//! Authenticate a linear functional of a uniformly masked vector with upstream
//! additive WHIR. This module is NON-HIDING by itself: callers must supply the
//! uniform mask combination, never a private trace or unmasked opening values.
//!
//! A public quadratic sumcheck reduces the functional to an ordinary MLE
//! opening. This avoids patching WHIR or inventing a new PCS for dense weights.

use anyhow::{Result, ensure};
use p3_binary_field::BinaryChallenger;
use p3_binary_pcs::whir::BinaryWhirDomain;
use p3_challenger::{CanObserve, CanSample, HashChallenger};
use p3_commit::MultilinearPcs;
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing, RawDataSerializable};
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_multilinear_util::{point::Point, poly::Poly};
use p3_sumcheck::layout::{Layout, PrefixProver, Table};
use p3_sumcheck::strategy::{Basis, VariableOrder};
use p3_sumcheck::{OpeningBatch, OpeningProtocol, PrescribedPointPcs, TableShape, TableSpec};
use p3_symmetric::{CompressionFunctionFromHasher, MerkleCap, SerializingHasher};
use p3_whir::pcs::{WhirProverData, proof::PcsProof};
use p3_whir::{FoldingFactor, ProtocolParameters, SecurityAssumption, WhirConfig, WhirProver};
use serde::{Deserialize, Serialize};

use super::{E, F, hash::DomainHash, parameters::Parameters, transcript::Transcript};
use crate::binary::security::union_bits;

// Shared by the complete masked-child verifier and its component tests.
pub(super) mod recursive;

const LEAF_DOMAIN: &[u8] = b"imt-veil-whir-v1/leaf\0";
const NODE_DOMAIN: &[u8] = b"imt-veil-whir-v1/node\0";
const TRANSCRIPT_DOMAIN: &[u8] = b"imt-veil-whir-v1/transcript\0";
const SEAL_TAG: &[u8; 8] = b"IMTVPC03";

type Tree = MerkleTreeMmcs<
    F,
    u8,
    SerializingHasher<DomainHash>,
    CompressionFunctionFromHasher<DomainHash, 2, 32>,
    2,
    32,
>;
type Challenger = BinaryChallenger<F, HashChallenger<u8, DomainHash, 32>>;
type LayoutType = PrefixProver<F, E>;
type Pcs = WhirProver<E, F, BinaryWhirDomain<F>, Tree, Challenger, LayoutType>;
type ProverData = WhirProverData<F, E, Tree, LayoutType>;

/// A verifier-derived functional. Compact implementations bind their complete
/// descriptor and evaluate its MLE without allocating a dense verifier table.
pub(super) trait BlendFunctional {
    fn length(&self) -> usize;
    fn dense(&self) -> Result<Vec<E>>;
    fn evaluate(&self, point: &[E]) -> Result<E>;
    fn bind(&self, transcript: &mut Transcript) -> Result<()>;
}

impl BlendFunctional for Vec<E> {
    fn length(&self) -> usize {
        self.len()
    }
    fn dense(&self) -> Result<Vec<E>> {
        Ok(self.clone())
    }
    fn evaluate(&self, point: &[E]) -> Result<E> {
        Ok(Poly::new(self.as_slice()).eval_ext::<F>(&Point::new(point.to_vec())))
    }
    fn bind(&self, transcript: &mut Transcript) -> Result<()> {
        transcript.fields(b"blend-functional-weights", self);
        Ok(())
    }
}

pub(super) struct BlendSecurity {
    pub conditional_bits: f64,
    pub log2_max_candidates: f64,
}

/// Consumed by one opening. No private polynomial or prover data is serialized.
pub(super) struct CommittedBlend {
    pub root: [u8; 32],
    values: Poly<E>,
    data: ProverData,
    pcs: Pcs,
    protocol: OpeningProtocol,
}

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct BlendOpening {
    rounds: Vec<[E; 2]>,
    value: E,
    pcs: PcsProof<F, E, Tree>,
}

impl CommittedBlend {
    pub fn new(values: Vec<E>, parameters: &Parameters) -> Result<Self> {
        let (pcs, protocol, _) = backend(values.len(), parameters)?;
        // A Table holds one contiguous row per coordinate polynomial.
        let mut coordinates = Vec::with_capacity(3 * values.len());
        for i in 0..3 {
            for value in &values {
                let base: &[F] = value.as_basis_coefficients_slice();
                coordinates.push(base[i]);
            }
        }
        let table = Table::new(RowMajorMatrix::new(coordinates, values.len()));
        let witness = LayoutType::new_witness(vec![table], 2);
        // Upstream commit only hashes the table and observes the root. It draws
        // no challenges. Opening reconstructs the commitment phase below.
        let (commitment, data) = pcs
            .commit(witness, &mut challenger(&[0; 32]))
            .map_err(|e| anyhow::anyhow!("blend commitment failed: {e:?}"))?;
        ensure!(commitment.roots().len() == 1, "unexpected WHIR cap");
        Ok(Self {
            root: commitment[0],
            values: Poly::new(values),
            data,
            pcs,
            protocol,
        })
    }

    pub fn prove<W: BlendFunctional + ?Sized>(
        mut self,
        weights: &W,
        sum: E,
        transcript: &mut Transcript,
    ) -> Result<BlendOpening> {
        bind(transcript, &self.root, weights, sum)?;
        ensure!(
            weights.length() == self.values.num_evals(),
            "wrong blend functional length"
        );
        let mut weight = Poly::new(weights.dense()?);
        let mut rounds = Vec::with_capacity(self.values.num_variables());
        let mut point = Vec::with_capacity(self.values.num_variables());
        for _ in 0..self.values.num_variables() {
            let coefficients = VariableOrder::Prefix
                .sumcheck_coefficients(self.values.as_slice(), weight.as_slice());
            let message = [coefficients.c_a, coefficients.c_inf];
            transcript.fields(b"blend-sumcheck-round", &message);
            let r = transcript.challenge(b"blend-sumcheck-challenge")?;
            rounds.push(message);
            point.push(r);
            VariableOrder::Prefix.fix_var(&mut self.values, r);
            VariableOrder::Prefix.fix_var(&mut weight, r);
        }
        let value = self.values.as_slice()[0];
        transcript.fields(b"blend-sumcheck-terminal", &[value]);
        let mut challenger = challenger(&transcript.fingerprint());
        self.pcs
            .observe_commitment(&MerkleCap::new(vec![self.root]), &mut challenger);
        let pcs = self
            .pcs
            .open_at(
                self.data,
                &self.protocol,
                &[Point::new(point)],
                &mut challenger,
            )
            .map_err(|e| anyhow::anyhow!("blend WHIR opening failed: {e:?}"))?;
        let proof = BlendOpening { rounds, value, pcs };
        transcript.bytes(b"blend-whir-seal-v3", &seal(&mut challenger));
        Ok(proof)
    }
}

impl BlendOpening {
    pub(super) fn round_messages(&self) -> (&[[E; 2]], E) {
        (&self.rounds, self.value)
    }

    /// Check the functional sumcheck through the terminal equality. The PCS
    /// must still authenticate the returned point and this opening's value.
    pub(super) fn reduce<W: BlendFunctional + ?Sized>(
        &self,
        root: &[u8; 32],
        weights: &W,
        sum: E,
        transcript: &mut Transcript,
    ) -> Result<Point<E>> {
        ensure!(
            self.rounds.len() == weights.length().ilog2() as usize,
            "wrong blend sumcheck round count"
        );
        bind(transcript, root, weights, sum)?;
        let mut claim = sum;
        let mut point = Vec::with_capacity(self.rounds.len());
        for &[c0, cinf] in &self.rounds {
            transcript.fields(b"blend-sumcheck-round", &[c0, cinf]);
            let r = transcript.challenge(b"blend-sumcheck-challenge")?;
            claim = Basis::Evaluation.reduce_claim(c0, cinf, r, claim);
            point.push(r);
        }
        let point = Point::new(point);
        let weight = weights.evaluate(point.as_slice())?;
        ensure!(
            claim == self.value * weight,
            "blend functional sumcheck failed"
        );
        transcript.fields(b"blend-sumcheck-terminal", &[self.value]);
        Ok(point)
    }

    pub fn verify<W: BlendFunctional + ?Sized>(
        &self,
        root: &[u8; 32],
        weights: &W,
        sum: E,
        parameters: &Parameters,
        transcript: &mut Transcript,
    ) -> Result<()> {
        let (pcs, protocol, _) = backend(weights.length(), parameters)?;
        let point = self.reduce(root, weights, sum, transcript)?;
        let mut challenger = challenger(&transcript.fingerprint());
        let cap = MerkleCap::new(vec![*root]);
        pcs.observe_commitment(&cap, &mut challenger);
        let seal = self.verify_opening(&pcs, &protocol, point, &cap, challenger)?;
        transcript.bytes(b"blend-whir-seal-v3", &seal);
        Ok(())
    }

    pub(super) fn opening_advice(
        &self,
        root: &[u8; 32],
        cp: &super::child::checkpoint::StackedBlendCheckpoint,
        parameters: &Parameters,
    ) -> Result<(Vec<F>, [u8; 32])> {
        ensure!(
            (8..=22).contains(&cp.point.len()),
            "unexpected coordinate opening arity"
        );
        let length = 1 << cp.point.len();
        let prepared = recursive::PreparedWhir::new(length, parameters)?;
        let private = prepared.import(&cp.seed, root, &cp.point, &self.pcs)?;
        let (pcs, protocol, _) = backend(length, parameters)?;
        let mut ch = challenger(&cp.seed);
        let cap = MerkleCap::new(vec![*root]);
        pcs.observe_commitment(&cap, &mut ch);
        Ok((
            private,
            self.verify_opening(&pcs, &protocol, Point::new(cp.point.clone()), &cap, ch)?,
        ))
    }

    fn verify_opening(
        &self,
        pcs: &Pcs,
        protocol: &OpeningProtocol,
        point: Point<E>,
        cap: &MerkleCap<F, [u8; 32]>,
        mut challenger: Challenger,
    ) -> Result<[u8; 32]> {
        let evals = pcs
            .verify_at(cap, &self.pcs, protocol, &[point], &mut challenger)
            .map_err(|e| anyhow::anyhow!("invalid blend WHIR proof: {e:?}"))?;
        ensure!(
            evals.len() == 1 && evals[0].current().len() == 3 && evals[0].next().is_empty(),
            "wrong blend opening shape"
        );
        let reconstructed: E = evals[0]
            .current()
            .iter()
            .enumerate()
            .map(|(i, &v)| {
                v * E::new(std::array::from_fn(
                    |j| if i == j { F::ONE } else { F::ZERO },
                ))
            })
            .sum();
        ensure!(
            reconstructed == self.value,
            "WHIR opening does not authenticate sumcheck terminal"
        );
        Ok(seal(&mut challenger))
    }
}

pub(super) fn security_budget(length: usize, parameters: &Parameters) -> Result<BlendSecurity> {
    Ok(backend(length, parameters)?.2)
}

fn backend(
    length: usize,
    parameters: &Parameters,
) -> Result<(Pcs, OpeningProtocol, BlendSecurity)> {
    parameters.validate()?;
    ensure!(
        length.is_power_of_two() && (256..=1 << 22).contains(&length),
        "invalid blend polynomial size"
    );
    let variables = length.ilog2() as usize;
    let domain = BinaryWhirDomain::<F>::default();
    let config = WhirConfig::new_with_domain(
        variables + 2,
        ProtocolParameters {
            security_level: parameters.query_bits,
            pow_bits: 16,
            round_log_inv_rates: vec![],
            folding_factor: FoldingFactor::Constant(2),
            soundness_type: SecurityAssumption::JohnsonBound,
            starting_log_inv_rate: parameters.log_inv_rate,
        },
        &domain,
    )
    .map_err(|e| anyhow::anyhow!("invalid blend WHIR configuration: {e:?}"))?;
    ensure!(
        config.max_pow_bits() <= 16,
        "blend WHIR exceeds grinding ceiling"
    );
    let tree = tree();
    let pcs = Pcs::new(config, domain, tree);
    let protocol = OpeningProtocol::new(vec![TableSpec::new(
        TableShape::new(variables, 3),
        vec![OpeningBatch::new(vec![0, 1, 2], vec![])],
    )]);
    let report = pcs
        .prescribed_security(&protocol)
        .ok_or_else(|| anyhow::anyhow!("missing blend WHIR security report"))?;
    // The extra reduction must be charged over the PCS's whole candidate list,
    // before the reduction challenges. This is an interactive algebraic bound.
    let reduction = 191.0 - ((2 * variables) as f64).log2() - report.log2_max_candidates;
    let bits = union_bits(&[report.error().bits(), reduction])?;
    ensure!(
        bits >= parameters.min_algebraic_bits as f64,
        "blend algebraic bound {bits:.3} below required {}",
        parameters.min_algebraic_bits
    );
    Ok((
        pcs,
        protocol,
        BlendSecurity {
            conditional_bits: bits,
            log2_max_candidates: report.log2_max_candidates,
        },
    ))
}

fn bind<W: BlendFunctional + ?Sized>(
    transcript: &mut Transcript,
    root: &[u8; 32],
    weights: &W,
    sum: E,
) -> Result<()> {
    ensure!(
        weights.length().is_power_of_two(),
        "invalid functional size"
    );
    transcript.bytes(b"blend-whir-commitment", root);
    weights.bind(transcript)?;
    transcript.fields(b"blend-functional-sum", &[sum]);
    Ok(())
}

fn tree() -> Tree {
    Tree::new(
        SerializingHasher::new(DomainHash(LEAF_DOMAIN)),
        CompressionFunctionFromHasher::new(DomainHash(NODE_DOMAIN)),
        0,
    )
}

fn challenger(seed: &[u8; 32]) -> Challenger {
    Challenger::from_hasher(seed.to_vec(), DomainHash(TRANSCRIPT_DOMAIN))
}

/// Continue the verified PCS transcript with a distinct closing tag. The
/// surrounding protocol binds the actual WHIR message/challenge schedule,
/// independently of its transport encoding. Merkle paths remain checked by
/// WHIR; they are not substituted by this seal or by a native Boolean hint.
fn seal(challenger: &mut Challenger) -> [u8; 32] {
    challenger.observe(F::new(u64::from_le_bytes(*SEAL_TAG)));
    let samples: [F; 4] = std::array::from_fn(|_| challenger.sample());
    samples
        .into_iter()
        .flat_map(RawDataSerializable::into_bytes)
        .collect::<Vec<_>>()
        .try_into()
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::CommittedBlend;
    use crate::binary::veil::{E, parameters::Parameters, transcript::Transcript};
    use anyhow::Result;
    use p3_field::PrimeCharacteristicRing;
    use rand::{RngExt, SeedableRng, rngs::StdRng};

    #[test]
    fn whir_authenticates_the_actual_linear_functional() -> Result<()> {
        let parameters = Parameters::default();
        let mut rng = StdRng::seed_from_u64(951);
        let values: Vec<E> = (0..256).map(|_| rng.random()).collect();
        let weights: Vec<E> = (0..256).map(|_| rng.random()).collect();
        let sum: E = values.iter().zip(&weights).map(|(&a, &b)| a * b).sum();
        for claimed in [sum, sum + E::ONE] {
            let committed = CommittedBlend::new(values.clone(), &parameters)?;
            let root = committed.root;
            // The prover deliberately performs no native dot-product precheck.
            let proof = committed.prove(&weights, claimed, &mut Transcript::new(b"whir-test"))?;
            let verified = proof.verify(
                &root,
                &weights,
                claimed,
                &parameters,
                &mut Transcript::new(b"whir-test"),
            );
            assert_eq!(verified.is_ok(), claimed == sum);
            let mut wrong_root = root;
            wrong_root[0] ^= 1;
            assert!(
                proof
                    .verify(
                        &wrong_root,
                        &weights,
                        claimed,
                        &parameters,
                        &mut Transcript::new(b"whir-test")
                    )
                    .is_err()
            );
        }
        Ok(())
    }
}
