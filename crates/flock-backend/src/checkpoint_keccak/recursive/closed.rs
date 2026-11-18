//! Recursive Keccak verification with committed boundaries and arithmetic port linkage.
use crate::checkpoint_keccak::{
    CommittedBatch, CommittedProof, Statement, recursive::PreparedCommittedVerifier,
};
use anyhow::{Result, ensure};
use old_binary_field::{BinaryChallenger, Poly64 as F, Poly192 as E};
use old_binary_pcs::whir::BinaryWhirDomain;
use old_challenger::HashChallenger;
use old_keccak::Keccak256Hash;
use old_merkle_tree::{MerkleCap, MerkleTreeMmcs};
use old_multilinear_util::point::Point;
use old_sumcheck::{
    OpeningBatch, OpeningProtocol, TableShape, TableSpec, ring_switch::bits::BitTensor,
};
use old_symmetric::{CompressionFunctionFromHasher, SerializingHasher};
use old_whir::{
    FoldingFactor, ProtocolParameters, SecurityAssumption, WhirConfig,
    pcs::proof::{PcsProof, WhirProof},
};
use p3_circuit::{
    Circuit, CircuitBuilder, CircuitConstructionLimits, ExprId,
    ops::{ByteHash, binary_encoding::NativeBinaryEncoding, bytes_to_limbs},
};
use p3_recursion::{BinaryTower128Challenger, pcs::binary::BinaryPolyDeferredWhirTraceVerifier};

mod linked;
pub use linked::PreparedLinkedCheckpoint;

type Ch = BinaryChallenger<F, HashChallenger<u8, Keccak256Hash, 32>>;
type Mmcs = MerkleTreeMmcs<
    F,
    u8,
    SerializingHasher<Keccak256Hash>,
    CompressionFunctionFromHasher<Keccak256Hash, 2, 32>,
    2,
    32,
>;
type Opening = (Vec<E>, Vec<BitTensor<E, F>>, WhirProof<F, E, Mmcs>);

pub struct PreparedCheckpoint {
    seed: [u8; 32],
    native: CommittedBatch,
    pcs: BoundaryPcs,
    pub circuit: Circuit<F>,
}

pub(crate) struct BoundaryPcs {
    pub(crate) log_batch: usize,
    cap_height: usize,
    config: WhirConfig<E, F, Ch>,
    mmcs: Mmcs,
    pub(crate) verifier: BinaryPolyDeferredWhirTraceVerifier,
}

impl PreparedCheckpoint {
    pub fn new(log_batch: usize, context: &[u8]) -> Result<Self> {
        let native = CommittedBatch::for_recursion(log_batch)?;
        let seed = native.transcript_seed(context);
        let pcs = BoundaryPcs::new(log_batch, 1, native.recursive_pcs_seed())?;
        let reduction = PreparedCommittedVerifier::new(log_batch)?;
        let mut b = builder()?;
        let cap = pcs.allocate_cap(&mut b, true);
        let proof = reduction.allocate(&mut b)?;
        let opening = pcs.verifier.allocate_native_targets(&mut b)?;
        let ch = pcs.challenger(&mut b, &seed, &cap)?;
        let claims = reduction.verify_reduction(&mut b, ch, &proof)?;
        let (values, _) = pcs.verifier.verify_at_native(
            &mut b,
            claims.challenger.clone(),
            &cap,
            &claims.points,
            &opening,
        )?;
        ensure!(
            values.len() == 2
                && values
                    .iter()
                    .all(|v| v.current().len() == 1 && v.next().is_empty()),
            "incorrect Keccak boundary routing"
        );
        claims.authenticate(&mut b, &values[0].current()[0], &values[1].current()[0]);
        Ok(Self {
            seed,
            native,
            pcs,
            circuit: b.build()?,
        })
    }

    pub fn public_inputs(&self, statement: &Statement) -> Result<Vec<F>> {
        self.pcs.public_inputs(statement)
    }

    /// Imports proof messages and PCS paths; acceptance is enforced by the circuit.
    pub fn private_inputs(&self, statement: &Statement, proof: &CommittedProof) -> Result<Vec<F>> {
        let mut ch = self.pcs.native_challenger(statement, &self.seed)?;
        let input = self.native.recursive_input(proof, &mut ch)?;
        let mut private = input.private_values;
        private.extend(self.pcs.private_inputs(
            statement,
            &input.points,
            &input.opening,
            &mut ch,
        )?);
        Ok(private)
    }
}

impl BoundaryPcs {
    pub(crate) fn new(log_batch: usize, openings: usize, ring_seed: Vec<F>) -> Result<Self> {
        let config = WhirConfig::new_with_domain(
            log_batch + 6,
            ProtocolParameters {
                security_level: 152,
                pow_bits: 16,
                round_log_inv_rates: vec![],
                folding_factor: FoldingFactor::Constant(crate::WHIR_FOLD),
                soundness_type: SecurityAssumption::JohnsonBound,
                starting_log_inv_rate: crate::WHIR_LOG_INV_RATE,
            },
            &BinaryWhirDomain::<F>::default(),
        )?;
        let cap_height = crate::WHIR_CAP_HEIGHT;
        let mmcs = Mmcs::new(
            SerializingHasher::new(Keccak256Hash),
            CompressionFunctionFromHasher::new(Keccak256Hash),
            cap_height,
        );
        let shape = TableShape::new(log_batch + 11, 1);
        let protocol = OpeningProtocol::new(
            (0..2)
                .map(|_| TableSpec::new(shape, vec![OpeningBatch::new(vec![0], vec![]); openings]))
                .collect(),
        );
        let verifier = BinaryPolyDeferredWhirTraceVerifier::new(
            &config,
            protocol,
            ByteHash::Keccak256,
            cap_height,
            ring_seed,
        )?;
        Ok(Self {
            log_batch,
            cap_height,
            config,
            mmcs,
            verifier,
        })
    }

    pub(crate) fn allocate_cap(&self, b: &mut CircuitBuilder<F>, public: bool) -> Vec<Vec<ExprId>> {
        (0..1 << self.cap_height)
            .map(|_| {
                (if public {
                    b.alloc_public_input_array::<16>("Keccak boundary commitment")
                } else {
                    b.alloc_private_input_array::<16>("Keccak boundary commitment")
                })
                .to_vec()
            })
            .collect()
    }

    pub(crate) fn challenger(
        &self,
        b: &mut CircuitBuilder<F>,
        seed: &[u8; 32],
        cap: &[Vec<ExprId>],
    ) -> Result<BinaryTower128Challenger> {
        let initial: Vec<_> = seed
            .iter()
            .map(|&v| b.define_const(F::new(u64::from(v))))
            .collect();
        let mut ch = BinaryTower128Challenger::with_initial_bytes_with_host::<
            NativeBinaryEncoding,
            F,
        >(b, ByteHash::Keccak256, &initial)?;
        self.verifier.observe_commitment_native(b, &mut ch, cap)?;
        Ok(ch)
    }

    pub(crate) fn public_inputs(&self, statement: &Statement) -> Result<Vec<F>> {
        ensure!(
            statement.log_batch as usize == self.log_batch,
            "incorrect Keccak batch size"
        );
        ensure!(
            statement.commitment.roots().len() == 1 << self.cap_height,
            "incorrect Keccak cap height"
        );
        Ok(statement
            .commitment
            .roots()
            .iter()
            .flat_map(|root| {
                bytes_to_limbs(root)
                    .into_iter()
                    .map(|w| F::new(u64::from(w)))
            })
            .collect())
    }

    pub(crate) fn native_challenger(&self, statement: &Statement, seed: &[u8; 32]) -> Result<Ch> {
        self.public_inputs(statement)?;
        let commitment = MerkleCap::<F, [u8; 32]>::new(statement.commitment.roots().to_vec());
        let mut ch = Ch::from_hasher(seed.to_vec(), Keccak256Hash);
        self.verifier
            .observe_native_commitment(&mut ch, &commitment)?;
        Ok(ch)
    }

    pub(crate) fn private_inputs(
        &self,
        statement: &Statement,
        points: &[Vec<E>],
        opening: &[u8],
        ch: &mut Ch,
    ) -> Result<Vec<F>> {
        let commitment = MerkleCap::<F, [u8; 32]>::new(statement.commitment.roots().to_vec());
        let points: Vec<_> = points.iter().cloned().map(Point::new).collect();
        let (values, tensors, whir): Opening = postcard::from_bytes(opening)?;
        let opening = PcsProof {
            evals: vec![],
            whir,
        };
        Ok(self.verifier.import_native(
            &self.config,
            &self.mmcs,
            &commitment,
            &points,
            &values,
            &tensors,
            &opening,
            ch,
        )?)
    }
}

pub(crate) fn builder() -> Result<CircuitBuilder<F>> {
    let mut b = CircuitBuilder::with_construction_limits(CircuitConstructionLimits {
        max_expression_nodes: 1 << 27,
        max_pending_connects: 1 << 26,
        max_non_primitive_calls: 1 << 21,
        max_non_primitive_slots: 1 << 29,
    })?;
    b.enable_native_keccak_f1600()?;
    Ok(b)
}
