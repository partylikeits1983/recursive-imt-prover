//! Reduce the final arbitrary bit functional to one ordinary PCS opening.
use anyhow::{Result, ensure};
use p3_field::PrimeCharacteristicRing;
use p3_maybe_rayon::prelude::*;
use p3_multilinear_util::{point::Point, poly::Poly};
use p3_sumcheck::generic_degree::{GenericDegreeProof, RoundPolyInterpolator, RoundProver};

use super::{BITS, Claim, E, F, POSITION_LOG, POSITIONS, State};
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
    let equality = Point::new(claim.instance.as_slice()).equality_weights_msb();
    let mut folded = inputs
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
        );
    folded.resize(POSITIONS, E::ZERO);
    let mut weights = claim.weights.clone();
    weights.resize(POSITIONS, E::ZERO);
    let mut prover = DotProduct {
        weights: Poly::new(weights),
        input: Poly::new(folded),
    };
    let (proof, point) = prover.prove::<F, Challenger>(ch, POSITION_LOG, 2, 0, claim.value);
    (proof, full_point(claim, point))
}

pub(super) fn verify(proof: &Proof, claim: &Claim, ch: &mut Challenger) -> Result<Closing> {
    ensure!(
        proof.claimed_sum == claim.value,
        "incorrect Keccak input functional"
    );
    let (point, product) = proof.verify(ch, POSITION_LOG, 2, 0)?;
    let weight = claim
        .weights
        .iter()
        .zip(point.equality_weights_msb())
        .map(|(&weight, eq)| weight * eq)
        .sum();
    Ok(Closing {
        point: full_point(claim, point),
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
