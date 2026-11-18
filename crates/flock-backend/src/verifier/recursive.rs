use anyhow::{Result, ensure};
use old_air::BaseAir;
use old_binary_field::{BinaryChallenger, Poly64 as F, Poly192 as E};
use old_binary_pcs::whir::BinaryWhirDomain;
use old_bus::BusProof;
use old_challenger::HashChallenger;
use old_keccak::Keccak256Hash;
use old_merkle_tree::{MerkleCap, MerkleTreeMmcs};
use old_multilinear_util::point::Point;
use old_sumcheck::{
    OpeningBatch, OpeningProtocol, TableShape, TableSpec, generic_degree::GenericDegreeProof,
    ring_switch::bits::BitTensor,
};
use old_symmetric::{CompressionFunctionFromHasher, SerializingHasher};
use old_whir::{
    FoldingFactor, ProtocolParameters, SecurityAssumption, WhirConfig,
    pcs::proof::{PcsProof, WhirProof},
};
use p3_circuit::{CircuitBuilder, ExprId};
use p3_recursion::{
    BinaryTower128Challenger,
    pcs::binary::{BinaryPolyCoordinateOpeningPlan, BinaryPolyDeferredWhirTraceVerifier},
    verifier::{
        AuthenticatedCoordinateOpenings, BinaryPolyCoordinateWhirVerifier, CoordinatePcsParameters,
        CoordinateWhirTargets,
    },
};

use super::{Verifier, recursive_air};
use crate::{
    HashBackend, WHIR_CAP_HEIGHT, WHIR_FOLD, WHIR_LOG_INV_RATE,
    checkpoint::AggregateProof,
    checkpoint_keccak::{
        committed::{Opening, recursive_opening},
        recursive::deferred_seed,
    },
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
type Wire = (Vec<E>, Vec<BitTensor<E, F>>, WhirProof<F, E, Mmcs>);
type Reduction = (Option<BusProof<E>>, GenericDegreeProof<F, E>);

#[cfg(test)]
mod periodic_tests;
#[cfg(test)]
mod tests;

pub struct RecursiveArithmetic {
    verifier: BinaryPolyCoordinateWhirVerifier,
    configs: [WhirConfig<E, F, Ch>; 2],
    mmcs: Mmcs,
    public_counts: Vec<usize>,
}

impl Verifier {
    pub fn recursive_arithmetic(&self) -> Result<RecursiveArithmetic> {
        ensure!(
            self.data.backend == HashBackend::Checkpoint,
            "recursive arithmetic requires checkpoint backend"
        );
        let airs = recursive_air::convert(&self.data.airs)?;
        let heights: Vec<_> = self.data.airs.iter().map(|a| a.log_height).collect();
        let shapes: Vec<_> = airs
            .iter()
            .zip(&heights)
            .map(|(a, &h)| TableShape::new(h, a.width()))
            .collect();
        let pp_shapes: Vec<_> = airs
            .iter()
            .zip(&heights)
            .filter(|(a, _)| a.preprocessed_width() > 0)
            .map(|(a, &h)| TableShape::new(h, a.preprocessed_width()))
            .collect();
        let main = plan(&shapes, &self.data.main_coordinates)?;
        let pp = plan(&pp_shapes, &self.data.preprocessed_coordinates)?;
        let configs = [config(main.num_variables())?, config(pp.num_variables())?];
        let parameters =
            |i, plan: &BinaryPolyCoordinateOpeningPlan, widths| CoordinatePcsParameters {
                config: &configs[i],
                widths,
                cap_height: WHIR_CAP_HEIGHT,
                ring_seed: deferred_seed(plan.num_variables(), plan.ring_claim_count()),
            };
        let cap = self
            .data
            .key
            .preprocessed_commitment()
            .ok_or_else(|| anyhow::anyhow!("missing checkpoint preprocessing"))?;
        let verifier = BinaryPolyCoordinateWhirVerifier::new(
            &airs.iter().collect::<Vec<_>>(),
            &heights,
            parameters(0, &main, &self.data.main_coordinates),
            Some((
                parameters(1, &pp, &self.data.preprocessed_coordinates),
                MerkleCap::new(cap.roots().to_vec()),
            )),
        )?;
        Ok(RecursiveArithmetic {
            verifier,
            configs,
            mmcs: Mmcs::new(
                SerializingHasher::new(Keccak256Hash),
                CompressionFunctionFromHasher::new(Keccak256Hash),
                WHIR_CAP_HEIGHT,
            ),
            public_counts: airs.iter().map(|a| a.num_public_values()).collect(),
        })
    }
}

impl RecursiveArithmetic {
    pub fn allocate(&self, b: &mut CircuitBuilder<F>) -> Result<CoordinateWhirTargets> {
        Ok(self.verifier.allocate(b)?)
    }

    /// The enclosing circuit must bind the arithmetic transcript seed to its boundary commitment.
    pub fn verify(
        &self,
        b: &mut CircuitBuilder<F>,
        ch: BinaryTower128Challenger,
        public: &[ExprId],
        proof: &CoordinateWhirTargets,
    ) -> Result<AuthenticatedCoordinateOpenings> {
        let public = self.public(public)?;
        Ok(self.verifier.verify_native(b, ch, &public, proof)?)
    }

    pub fn private_inputs(&self, bytes: &[u8], public: &[F], seed: &[u8]) -> Result<Vec<F>> {
        let proof: AggregateProof = crate::proof_codec::decode(bytes)?;
        let proof = proof.arithmetic;
        ensure!(
            proof.lookup.is_none() && proof.indexed.is_none() && proof.circuits.is_empty(),
            "unsupported arithmetic proof parts"
        );
        let public = self.public(public)?;
        let (bus, sumcheck): Reduction =
            postcard::from_bytes(&postcard::to_allocvec(&(&proof.bus, &proof.sumcheck))?)?;
        let cap = MerkleCap::new(proof.commitment.roots().to_vec());
        let mut ch = Ch::from_hasher(seed.to_vec(), Keccak256Hash);
        let input =
            self.verifier
                .import_reduction(&cap, &public, bus.as_ref(), &sumcheck, &mut ch)?;
        let mut values = input.private_values;
        values.extend(import_opening(
            self.verifier.main_pcs(),
            &self.configs[0],
            &self.mmcs,
            &cap,
            &input.main_points,
            &proof.opening,
            &mut ch,
        )?);
        match (
            self.verifier.preprocessed_pcs(),
            input.preprocessed_points,
            proof.preprocessed_opening,
        ) {
            (Some((pcs, cap)), Some(points), Some(proof)) => values.extend(import_opening(
                pcs,
                &self.configs[1],
                &self.mmcs,
                cap,
                &points,
                &proof,
                &mut ch,
            )?),
            _ => anyhow::bail!("missing arithmetic preprocessing opening"),
        }
        Ok(values)
    }

    fn public<T: Clone>(&self, public: &[T]) -> Result<Vec<Vec<T>>> {
        ensure!(
            self.public_counts
                .iter()
                .all(|&n| n == 0 || n == public.len()),
            "incorrect recursive public count"
        );
        Ok(self
            .public_counts
            .iter()
            .map(|&n| public[..n].to_vec())
            .collect())
    }
}

fn plan(shapes: &[TableShape], widths: &[Vec<usize>]) -> Result<BinaryPolyCoordinateOpeningPlan> {
    let protocol = OpeningProtocol::new(
        shapes
            .iter()
            .map(|&s| TableSpec::new(s, vec![OpeningBatch::new((0..s.width()).collect(), vec![])]))
            .collect(),
    );
    Ok(BinaryPolyCoordinateOpeningPlan::new(&protocol, widths)?)
}

fn config(arity: usize) -> Result<WhirConfig<E, F, Ch>> {
    Ok(WhirConfig::new_with_domain(
        arity - 6,
        ProtocolParameters {
            security_level: 152,
            pow_bits: 16,
            round_log_inv_rates: vec![],
            folding_factor: FoldingFactor::Constant(WHIR_FOLD),
            soundness_type: SecurityAssumption::JohnsonBound,
            starting_log_inv_rate: WHIR_LOG_INV_RATE,
        },
        &BinaryWhirDomain::<F>::default(),
    )?)
}

fn import_opening(
    pcs: &BinaryPolyDeferredWhirTraceVerifier,
    config: &WhirConfig<E, F, Ch>,
    mmcs: &Mmcs,
    cap: &MerkleCap<F, [u8; 32]>,
    points: &[Point<E>],
    proof: &Opening,
    ch: &mut Ch,
) -> Result<Vec<F>> {
    let (values, tensors, whir): Wire = postcard::from_bytes(&recursive_opening(proof)?)?;
    Ok(pcs.import_native(
        config,
        mmcs,
        cap,
        points,
        &values,
        &tensors,
        &PcsProof {
            evals: vec![],
            whir,
        },
        ch,
    )?)
}
