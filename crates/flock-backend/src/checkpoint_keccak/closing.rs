//! Reduce the final arbitrary bit functional to one ordinary PCS opening.
use anyhow::{Result, ensure};
use p3_field::PrimeCharacteristicRing;
use p3_maybe_rayon::prelude::*;
use p3_multilinear_util::{point::Point, poly::Poly};
use p3_sumcheck::generic_degree::{GenericDegreeProof, RoundPolyInterpolator, RoundProver};

use super::{BITS, Claim, E, F, POSITIONS, State};
use crate::config::Challenger;

pub(super) type Proof = GenericDegreeProof<F, E>;

pub(super) struct Closing {
    pub point: Point<E>,
    pub weight: E,
    pub product: E,
}

struct DotProduct {
    weights: Poly<E>,
    input: Poly<E>,
}

pub(super) fn prove(inputs: &[State], claim: &Claim, ch: &mut Challenger) -> (Proof, Point<E>) {
    let mut folded = fold_states(inputs, &claim.instance);
    folded.resize(POSITIONS, E::ZERO);
    let mut weights = claim.weights.clone();
    weights.resize(POSITIONS, E::ZERO);
    let (proof, point) = prove_functional(weights, folded, claim.value, ch);
    (proof, full_point(claim, point))
}

pub(super) fn fold_states(inputs: &[State], point: &[E]) -> Vec<E> {
    let equality = Point::new(point).equality_weights_msb();
    inputs
        .par_chunks(256)
        .zip(equality.par_chunks(256))
        .map(|(states, eq)| {
            let mut values = E::zero_vec(BITS);
            for (state, &weight) in states.iter().zip(eq) {
                for (lane, &word) in state.iter().enumerate() {
                    let mut bits = word;
                    while bits != 0 {
                        values[lane * 64 + bits.trailing_zeros() as usize] += weight;
                        bits &= bits - 1;
                    }
                }
            }
            values
        })
        .reduce(
            || E::zero_vec(BITS),
            |mut a, b| {
                for (a, b) in a.iter_mut().zip(b) {
                    *a += b;
                }
                a
            },
        )
}

pub(super) fn prove_functional(
    weights: Vec<E>,
    input: Vec<E>,
    value: E,
    ch: &mut Challenger,
) -> (Proof, Point<E>) {
    assert!(weights.len().is_power_of_two() && weights.len() == input.len());
    let log = weights.len().trailing_zeros() as usize;
    let mut prover = DotProduct {
        weights: Poly::new(weights),
        input: Poly::new(input),
    };
    prover.prove::<F, Challenger>(ch, log, 2, 0, value)
}

pub(super) fn verify(proof: &Proof, claim: &Claim, ch: &mut Challenger) -> Result<Closing> {
    let mut closing = verify_functional(proof, &claim.weights, claim.value, ch)?;
    closing.point = full_point(claim, closing.point);
    Ok(closing)
}

pub(super) fn verify_functional(
    proof: &Proof,
    weights: &[E],
    value: E,
    ch: &mut Challenger,
) -> Result<Closing> {
    ensure!(
        proof.claimed_sum == value,
        "incorrect Keccak input functional"
    );
    ensure!(
        !weights.is_empty() && weights.len() <= 2 * POSITIONS,
        "invalid closing weights"
    );
    let log = weights.len().next_power_of_two().trailing_zeros() as usize;
    let (point, product) = proof.verify(ch, log, 2, 0)?;
    let weight = weights
        .iter()
        .zip(point.equality_weights_msb())
        .map(|(&weight, eq)| weight * eq)
        .sum();
    Ok(Closing {
        point,
        weight,
        product,
    })
}

fn full_point(claim: &Claim, point: Point<E>) -> Point<E> {
    let mut full = claim.instance.clone();
    full.extend_from_slice(point.as_slice());
    Point::new(full)
}

impl RoundProver<E> for DotProduct {
    fn fold(&mut self, challenge: E) {
        self.weights.fix_prefix_var_mut(challenge);
        self.input.fix_prefix_var_mut(challenge);
    }

    fn round_poly(&self) -> Vec<E> {
        let half = self.weights.num_evals() / 2;
        (0..2)
            .map(|index| {
                let node: E = RoundPolyInterpolator::transmitted_node(index);
                let line = |poly: &Poly<E>, i: usize| {
                    poly.as_slice()[i] + node * (poly.as_slice()[i + half] - poly.as_slice()[i])
                };
                (0..half)
                    .map(|i| line(&self.weights, i) * line(&self.input, i))
                    .sum()
            })
            .collect()
    }
}
