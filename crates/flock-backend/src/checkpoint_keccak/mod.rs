//! Experimental Keccak GKR reduction over Poly64/Poly192.
//!
//! The raw reduction requires a caller to bind the batch's input/output
//! commitments before sampling the initial claim and authenticate the returned
//! input opening. `CommittedBatch` supplies that authentication with the existing
//! additive-WHIR PCS. The aggregate's linked variant also authenticates the
//! native arithmetic ports against those boundaries.
//! The reference prover recomputes round checkpoints instead of committing every
//! nonlinear wire. It reuses Plonky3's cubic sumcheck and Keccak transcript.
mod closing;
pub(crate) mod committed;
mod linear;
pub mod linked;
pub(crate) mod ports;
pub mod recursive;
mod rounds;
#[cfg(test)]
mod tests;

use anyhow::{Result, ensure};
use p3_binary_field::{Poly192 as E, TowerLevel};
use p3_challenger::{FieldChallenger, GrindingChallenger};
use p3_field::BasedVectorSpace;
use p3_maybe_rayon::prelude::*;
use p3_multilinear_util::point::Point;
use p3_sumcheck::generic_degree::{GenericDegreeProof, RoundProver};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};

use crate::{F, keccak::RC};
use rounds::ChiSumcheck;

pub use committed::{CommittedBatch, CommittedProof, Statement};

pub const BITS: usize = 1600;
const POSITION_LOG: usize = 11;
const POSITIONS: usize = 1 << POSITION_LOG;
const ROUNDS: usize = 24;
const MAX_BATCH_LOG: usize = 24;
const DOMAIN: &str = "imt-experimental-keccak-gkr-v1";
const RECURSIVE_DOMAIN: &[u8] = b"imt-experimental-keccak-gkr-fixed-v2";

#[derive(Clone, Copy)]
enum Transcript {
    PostcardV1,
    FixedV2,
}

pub type State = [u64; 25];

/// A bit-weighted claim on a batch of permutation states. Instance coordinates
/// use Plonky3's MSB-first multilinear convention; bits are lane-major, LSB-first.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Claim {
    pub instance: Vec<E>,
    pub weights: Vec<E>,
    pub value: E,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Proof {
    layers: Vec<LayerProof>,
}

#[derive(Clone, Serialize, Deserialize)]
struct LayerProof {
    sumcheck: GenericDegreeProof<F, E>,
    values: [E; 3],
}

/// Conditional algebraic error numerator over |Poly192|, excluding PCS,
/// initial output-claim batching, Fiat–Shamir and hash assumptions.
pub fn algebraic_error_degree(log_batch: usize) -> Result<usize> {
    ensure!(log_batch <= MAX_BATCH_LOG, "oversized Keccak GKR batch");
    Ok(ROUNDS * (3 * (log_batch + POSITION_LOG) + 2))
}

/// Reduce a caller-authenticated output claim to an input claim.
/// No original client witness is involved: these are the aggregator's Keccak calls.
pub fn prove<C>(inputs: &[State], output: &Claim, challenger: &mut C) -> Result<(Proof, Claim)>
where
    C: FieldChallenger<F> + GrindingChallenger<Witness = F>,
{
    prove_using(inputs, output, challenger, Transcript::PostcardV1)
}

fn prove_using<C>(
    inputs: &[State],
    output: &Claim,
    challenger: &mut C,
    transcript: Transcript,
) -> Result<(Proof, Claim)>
where
    C: FieldChallenger<F> + GrindingChallenger<Witness = F>,
{
    ensure!(
        inputs.len().is_power_of_two(),
        "Keccak GKR needs a power-of-two batch"
    );
    let log_batch = inputs.len().trailing_zeros() as usize;
    validate(output, log_batch)?;
    bind(output, log_batch, challenger, transcript)?;
    let mut claim = output.clone();
    let mut layers = Vec::with_capacity(ROUNDS);
    for round in (0..ROUNDS).rev() {
        challenger.observe(F::from_repr(round as u64));
        let before_chi = inputs
            .par_iter()
            .map(|input| {
                let mut state = *input;
                for previous in 0..round {
                    state = linear::finish_round(&linear::forward(&state), previous);
                }
                linear::forward(&state)
            })
            .collect();
        let equality = Point::new(claim.instance.as_slice()).equality_weights_msb();
        let mut sumcheck = ChiSumcheck::new(before_chi, equality, claim.weights.clone());
        let (proof, point) = sumcheck.prove::<F, C>(
            challenger,
            log_batch + POSITION_LOG,
            3,
            0,
            remove_iota(&claim, round),
        );
        let values = sumcheck.terminal();
        let beta = bind_values(values, challenger);
        claim = previous_claim(point.as_slice(), values, beta, log_batch);
        layers.push(LayerProof {
            sumcheck: proof,
            values,
        });
    }
    Ok((Proof { layers }, claim))
}

/// Verify only the reduction. Acceptance additionally requires authenticating
/// the returned input claim against the input commitment fixed before `output`.
pub fn verify<C>(
    proof: &Proof,
    output: &Claim,
    log_batch: usize,
    challenger: &mut C,
) -> Result<Claim>
where
    C: FieldChallenger<F> + GrindingChallenger<Witness = F>,
{
    verify_using(proof, output, log_batch, challenger, Transcript::PostcardV1)
}

fn verify_using<C>(
    proof: &Proof,
    output: &Claim,
    log_batch: usize,
    challenger: &mut C,
    transcript: Transcript,
) -> Result<Claim>
where
    C: FieldChallenger<F> + GrindingChallenger<Witness = F>,
{
    validate(output, log_batch)?;
    ensure!(
        proof.layers.len() == ROUNDS,
        "incorrect Keccak GKR layer count"
    );
    bind(output, log_batch, challenger, transcript)?;
    let mut claim = output.clone();
    for (round, layer) in (0..ROUNDS).rev().zip(&proof.layers) {
        challenger.observe(F::from_repr(round as u64));
        ensure!(
            layer.sumcheck.claimed_sum == remove_iota(&claim, round),
            "incorrect Keccak layer sum"
        );
        let (point, terminal) =
            layer
                .sumcheck
                .verify(challenger, log_batch + POSITION_LOG, 3, 0)?;
        let eq = Point::eval_eq(&claim.instance, &point.as_slice()[..log_batch]);
        let position = Point::new(&point.as_slice()[log_batch..]).equality_weights_msb();
        let weight = claim
            .weights
            .iter()
            .zip(&position)
            .map(|(&a, &b)| a * b)
            .sum::<E>();
        let [a, b, c] = layer.values;
        ensure!(
            terminal == eq * weight * (a + c + b * c),
            "incorrect Keccak layer endpoint"
        );
        let beta = bind_values(layer.values, challenger);
        claim = previous_claim(point.as_slice(), layer.values, beta, log_batch);
    }
    Ok(claim)
}

fn validate(claim: &Claim, log_batch: usize) -> Result<()> {
    algebraic_error_degree(log_batch)?;
    ensure!(
        claim.instance.len() == log_batch,
        "incorrect Keccak claim point"
    );
    ensure!(claim.weights.len() == BITS, "incorrect Keccak bit weights");
    Ok(())
}

fn bind<C: FieldChallenger<F>>(
    claim: &Claim,
    log_batch: usize,
    challenger: &mut C,
    transcript: Transcript,
) -> Result<()> {
    let digest = match transcript {
        Transcript::PostcardV1 => {
            Keccak256::digest(postcard::to_allocvec(&(DOMAIN, log_batch as u64, claim))?)
        }
        Transcript::FixedV2 => Keccak256::digest(RECURSIVE_DOMAIN),
    };
    for bytes in digest.as_chunks::<8>().0 {
        challenger.observe(F::from_repr(u64::from_le_bytes(*bytes)));
    }
    if matches!(transcript, Transcript::FixedV2) {
        challenger.observe(F::from_repr(log_batch as u64));
        for value in claim
            .instance
            .iter()
            .chain(&claim.weights)
            .chain([&claim.value])
        {
            challenger.observe_slice(value.as_basis_coefficients_slice());
        }
    }
    Ok(())
}

fn bind_values<C: FieldChallenger<F>>(values: [E; 3], challenger: &mut C) -> E {
    for value in values {
        challenger.observe_slice(value.as_basis_coefficients_slice());
    }
    challenger.sample_algebra_element()
}

fn remove_iota(claim: &Claim, round: usize) -> E {
    claim.value
        + (0..64)
            .filter(|bit| (RC[round] >> bit) & 1 != 0)
            .map(|bit| claim.weights[bit])
            .sum::<E>()
}

fn previous_claim(point: &[E], values: [E; 3], beta: E, log_batch: usize) -> Claim {
    let position = Point::new(&point[log_batch..]).equality_weights_msb();
    let square = beta * beta;
    let weights = (0..BITS)
        .map(|j| {
            position[j]
                + beta * position[linear::shift(j, 4)]
                + square * position[linear::shift(j, 3)]
        })
        .collect::<Vec<_>>();
    Claim {
        instance: point[..log_batch].to_vec(),
        weights: linear::transpose(&weights),
        value: values[0] + beta * values[1] + square * values[2],
    }
}
