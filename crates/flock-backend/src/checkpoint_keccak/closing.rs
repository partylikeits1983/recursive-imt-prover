//! Reduce the final arbitrary bit functional to one ordinary PCS opening.
use anyhow::{Result, ensure};
use p3_challenger::{FieldChallenger, GrindingChallenger};
use p3_field::PrimeCharacteristicRing;
use p3_maybe_rayon::prelude::*;
use p3_multilinear_util::{point::Point, poly::Poly};
use p3_sumcheck::generic_degree::{GenericDegreeProof, RoundPolyInterpolator, RoundProver};

use super::{
    BITS, Claim, E, F, POSITIONS, State,
    bits::{byte_table, transpose8},
};
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

pub(super) fn prove(inputs: &[State], claim: &Claim, ch: &mut Challenger) -> (Proof, Point<E>, E) {
    let mut folded = fold_states(inputs, &claim.instance);
    folded.resize(POSITIONS, E::ZERO);
    let mut weights = claim.weights.clone();
    weights.resize(POSITIONS, E::ZERO);
    let (proof, point, value) = prove_functional(weights, folded, claim.value, ch);
    (proof, full_point(claim, point), value)
}

pub(super) fn fold_states(inputs: &[State], point: &[E]) -> Vec<E> {
    let equality = Point::new(point).equality_weights_msb();
    inputs
        .par_chunks(256)
        .zip(equality.par_chunks(256))
        .map(|(states, eq)| {
            let mut values = E::zero_vec(BITS);
            // Padded batches often have whole chunks of equal states.
            let first = &states[0];
            if states.iter().all(|state| state == first) {
                add_state(&mut values, first, eq.iter().copied().sum());
                return values;
            }
            let (groups, tail) = states.as_chunks::<8>();
            let (weights, remaining) = eq.as_chunks::<8>();
            for (group, weights) in groups.iter().zip(weights) {
                let lookup = byte_table(weights);
                for (lane, target) in values.as_chunks_mut::<64>().0.iter_mut().enumerate() {
                    let words: [u64; 8] = core::array::from_fn(|i| group[i][lane]);
                    if words == [0; 8] {
                        continue;
                    }
                    for (byte, target) in target.as_chunks_mut::<8>().0.iter_mut().enumerate() {
                        let masks = transpose8(u64::from_le_bytes(
                            words.map(|word| (word >> (8 * byte)) as u8),
                        ))
                        .to_le_bytes();
                        for (v, index) in target.iter_mut().zip(masks) {
                            *v += lookup[usize::from(index)];
                        }
                    }
                }
            }
            for (state, &weight) in tail.iter().zip(remaining) {
                add_state(&mut values, state, weight);
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

fn add_state(values: &mut [E], state: &State, weight: E) {
    for (lane, &word) in state.iter().enumerate() {
        let mut bits = word;
        while bits != 0 {
            values[lane * 64 + bits.trailing_zeros() as usize] += weight;
            bits &= bits - 1;
        }
    }
}

pub(super) fn prove_functional(
    weights: Vec<E>,
    input: Vec<E>,
    value: E,
    ch: &mut Challenger,
) -> (Proof, Point<E>, E) {
    assert!(weights.len().is_power_of_two() && weights.len() == input.len());
    let log = weights.len().trailing_zeros() as usize;
    let mut prover = DotProduct {
        weights: Poly::new(weights),
        input: Poly::new(input),
    };
    let (proof, point) = prover.prove::<F, Challenger>(ch, log, 2, 0, value);
    // The sumcheck has already computed this evaluation. The PCS still
    // authenticates it; retaining it just avoids another full-table pass.
    (proof, point, prover.input.as_slice()[0])
}

pub(super) fn evaluate_folded(values: &[E], point: &[E]) -> E {
    assert!(values.len() <= 1 << point.len());
    values
        .iter()
        .zip(Point::new(point).equality_weights_msb())
        .map(|(&value, weight)| value * weight)
        .sum()
}

pub(super) fn verify<C>(proof: &Proof, claim: &Claim, ch: &mut C) -> Result<Closing>
where
    C: FieldChallenger<F> + GrindingChallenger<Witness = F>,
{
    let mut closing = verify_functional(proof, &claim.weights, claim.value, ch)?;
    closing.point = full_point(claim, closing.point);
    Ok(closing)
}

pub(super) fn verify_functional<C>(
    proof: &Proof,
    weights: &[E],
    value: E,
    ch: &mut C,
) -> Result<Closing>
where
    C: FieldChallenger<F> + GrindingChallenger<Witness = F>,
{
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

#[cfg(test)]
mod benchmarks {
    use super::*;
    use p3_challenger::FieldChallenger;
    use std::time::Instant;

    #[test]
    #[ignore = "release timing of the two boundary-folding algorithms"]
    fn compare_boundary_folding() {
        let mut states = super::super::tests::inputs(1 << 16);
        states[47182..].fill([0; 25]);
        let mut ch = crate::config::challenger(b"boundary-fold-benchmark");
        let point: Vec<E> = (0..16).map(|_| ch.sample_algebra_element()).collect();
        let direct = || {
            let equality = Point::new(point.as_slice()).equality_weights_msb();
            states
                .par_chunks(256)
                .zip(equality.par_chunks(256))
                .map(|(states, weights)| {
                    let mut values = E::zero_vec(BITS);
                    for (s, &w) in states.iter().zip(weights) {
                        add_state(&mut values, s, w);
                    }
                    values
                })
                .reduce(
                    || E::zero_vec(BITS),
                    |mut left, right| {
                        for (l, r) in left.iter_mut().zip(right) {
                            *l += r;
                        }
                        left
                    },
                )
        };
        let reference = direct();
        for i in 0..8 {
            for packed in [i % 2 == 1, i % 2 == 0] {
                let start = Instant::now();
                let folded = if packed {
                    fold_states(&states, &point)
                } else {
                    direct()
                };
                let elapsed = start.elapsed();
                assert_eq!(folded, reference);
                println!(
                    "boundary-fold {}",
                    serde_json::json!({"packed":packed,"seconds":elapsed.as_secs_f64()})
                );
            }
        }
    }
}
