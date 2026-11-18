//! Authenticated recursive Keccak batch verifier. Arithmetic port linkage is separate.
use anyhow::{Result, ensure};
use imt_flock_backend::checkpoint_keccak::{
    CommittedBatch, CommittedProof, Statement, recursive::PreparedCommittedVerifier,
};
use p3_binary_field::{BinaryChallenger, Poly64 as F, Poly192 as E};
use p3_binary_pcs::whir::{BinaryWhirDomain, recommended_cap_height};
use p3_challenger::HashChallenger;
use p3_circuit::{
    Circuit, CircuitBuilder, CircuitConstructionLimits,
    ops::{ByteHash, binary_encoding::NativeBinaryEncoding, bytes_to_limbs},
};
use p3_keccak::Keccak256Hash;
use p3_merkle_tree::{MerkleCap, MerkleTreeMmcs};
use p3_multilinear_util::point::Point;
use p3_recursion::{BinaryTower128Challenger, pcs::binary::BinaryPolyDeferredWhirTraceVerifier};
use p3_sumcheck::{
    OpeningBatch, OpeningProtocol, TableShape, TableSpec, ring_switch::bits::BitTensor,
};
use p3_symmetric::{CompressionFunctionFromHasher, SerializingHasher};
use p3_whir::{
    FoldingFactor, ProtocolParameters, SecurityAssumption, WhirConfig,
    pcs::proof::{PcsProof, WhirProof},
};

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
    log_batch: usize,
    cap_height: usize,
    seed: [u8; 32],
    native: CommittedBatch,
    config: WhirConfig<E, F, Ch>,
    mmcs: Mmcs,
    pcs: BinaryPolyDeferredWhirTraceVerifier,
    pub circuit: Circuit<F>,
}

impl PreparedCheckpoint {
    pub fn new(log_batch: usize, context: &[u8]) -> Result<Self> {
        let native = CommittedBatch::for_recursion(log_batch)?;
        let seed = native.transcript_seed(context);
        let config = WhirConfig::new_with_domain(
            log_batch + 6,
            ProtocolParameters {
                security_level: 152,
                pow_bits: 16,
                round_log_inv_rates: vec![],
                folding_factor: FoldingFactor::Constant(4),
                soundness_type: SecurityAssumption::JohnsonBound,
                starting_log_inv_rate: 1,
            },
            &BinaryWhirDomain::<F>::default(),
        )?;
        let cap_height = recommended_cap_height(&config);
        let mmcs = Mmcs::new(
            SerializingHasher::new(Keccak256Hash),
            CompressionFunctionFromHasher::new(Keccak256Hash),
            cap_height,
        );
        let shape = TableShape::new(log_batch + 11, 1);
        let protocol = OpeningProtocol::new(
            (0..2)
                .map(|_| TableSpec::new(shape, vec![OpeningBatch::new(vec![0], vec![])]))
                .collect(),
        );
        let pcs = BinaryPolyDeferredWhirTraceVerifier::new(
            &config,
            protocol,
            ByteHash::Keccak256,
            cap_height,
            native.recursive_pcs_seed(),
        )?;
        let reduction = PreparedCommittedVerifier::new(log_batch)?;
        let mut b = CircuitBuilder::<F>::with_construction_limits(CircuitConstructionLimits {
            max_expression_nodes: 1 << 27,
            max_pending_connects: 1 << 26,
            max_non_primitive_calls: 1 << 21,
            max_non_primitive_slots: 1 << 29,
        })?;
        b.enable_native_keccak_f1600()?;
        let cap: Vec<_> = (0..1 << cap_height)
            .map(|_| {
                b.alloc_public_input_array::<16>("Keccak boundary commitment")
                    .to_vec()
            })
            .collect();
        let proof = reduction.allocate(&mut b)?;
        let opening = pcs.allocate_native_targets(&mut b)?;
        let initial: Vec<_> = seed
            .iter()
            .map(|&v| b.define_const(F::new(u64::from(v))))
            .collect();
        let mut ch = BinaryTower128Challenger::with_initial_bytes_with_host::<
            NativeBinaryEncoding,
            F,
        >(&mut b, ByteHash::Keccak256, &initial)?;
        pcs.observe_commitment_native(&mut b, &mut ch, &cap)?;
        let claims = reduction.verify_reduction(&mut b, ch, &proof)?;
        let (values, _) = pcs.verify_at_native(
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
            log_batch,
            cap_height,
            seed,
            native,
            config,
            mmcs,
            pcs,
            circuit: b.build()?,
        })
    }

    pub fn public_inputs(&self, statement: &Statement) -> Result<Vec<F>> {
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
                    .map(|word| F::new(u64::from(word)))
            })
            .collect())
    }

    /// Imports proof messages and PCS paths; acceptance is enforced by the circuit.
    pub fn private_inputs(&self, statement: &Statement, proof: &CommittedProof) -> Result<Vec<F>> {
        self.public_inputs(statement)?;
        let commitment = MerkleCap::<F, [u8; 32]>::new(statement.commitment.roots().to_vec());
        let mut ch = Ch::from_hasher(self.seed.to_vec(), Keccak256Hash);
        self.pcs.observe_native_commitment(&mut ch, &commitment)?;
        let input = self.native.recursive_input(proof, &mut ch)?;
        let points = input.points.map(Point::new);
        let (values, tensors, whir): Opening = postcard::from_bytes(&input.opening)?;
        let opening = PcsProof {
            evals: vec![],
            whir,
        };
        let witness = self.pcs.import_native(
            &self.config,
            &self.mmcs,
            &commitment,
            &points,
            &values,
            &tensors,
            &opening,
            &mut ch,
        )?;
        let mut private = input.private_values;
        private.extend(witness);
        Ok(private)
    }
}
