//! The product has degree at most 46 before projection. Bind its coefficients
//! before drawing the Poly192 evaluation point used by the cubic sumcheck.
use anyhow::{Result, ensure};
use p3_binary_field::TowerLevel;
use p3_challenger::{FieldChallenger, GrindingChallenger};
use p3_field::PrimeCharacteristicRing;
use p3_maybe_rayon::prelude::*;
use p3_multilinear_util::point::Point;
use p3_sumcheck::generic_degree::RoundProver;
use serde::{Deserialize, Serialize};

use super::super::bits::{byte_table, transpose8};
use super::super::{
    BITS, Claim, E, F, POSITION_LOG, State, bind_values, closing, linear, previous_claim,
    rounds::ChiSumcheck,
};
use super::maps::{EMBED, PROJECT};
use crate::{config::Challenger, keccak::RC};

const COEFFS: usize = 47;

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct Layer {
    pub(super) coefficients: Vec<E>,
    pub(super) sumcheck: closing::Proof,
    pub(super) values: [E; 3],
}

pub(super) struct PackedClaim {
    pub(super) claim: Claim,
    pub(super) lanes: [E; 16],
}

fn encode<T: PrimeCharacteristicRing + Copy + Send + Sync>(
    words: &[u16],
    basis: &[T; 16],
) -> Vec<T> {
    let low = byte_table(&basis[..8]);
    let high = byte_table(&basis[8..]);
    words
        .par_iter()
        .map(|&w| low[(w & 255) as usize] + high[(w >> 8) as usize])
        .collect()
}

fn pack(states: &[State], before_chi: impl Fn(usize, State) -> State + Sync) -> Vec<u16> {
    let mut packed = vec![0; states.len() / 16 * BITS];
    packed
        .par_chunks_exact_mut(BITS)
        .zip(states.par_chunks_exact(16))
        .enumerate()
        .for_each(|(block, (row, group))| {
            let group: [State; 16] = core::array::from_fn(|i| before_chi(block * 16 + i, group[i]));
            for lane in 0..25 {
                for byte in 0..8 {
                    let transpose = |start: usize| {
                        transpose8(u64::from_le_bytes(core::array::from_fn(|i| {
                            (group[start + i][lane] >> (byte * 8)) as u8
                        })))
                        .to_le_bytes()
                    };
                    let low = transpose(0);
                    let high = transpose(8);
                    for j in 0..8 {
                        row[lane * 64 + byte * 8 + j] = u16::from_le_bytes([low[j], high[j]]);
                    }
                }
            }
        });
    packed
}

/// Both RMFE images have degree at most 23. Their carry-less product
/// fits in 47 bits, so polynomial reduction modulo the Poly64 modulus is free to omit.
#[inline]
fn embedded_product(a: F, b: F) -> u64 {
    #[cfg(all(
        target_arch = "aarch64",
        target_feature = "aes",
        target_feature = "neon"
    ))]
    {
        // SAFETY: this branch is compiled only for targets that guarantee AES and NEON.
        unsafe { core::arch::aarch64::vmull_p64(a.to_repr(), b.to_repr()) as u64 }
    }
    #[cfg(not(all(
        target_arch = "aarch64",
        target_feature = "aes",
        target_feature = "neon"
    )))]
    {
        (a * b).to_repr()
    }
}

fn coefficients(words: &[u16], claim: &Claim) -> Vec<E> {
    let embeds = EMBED.map(|x| F::from_repr(x.into()));
    let ones: F = embeds.iter().copied().sum();
    let low = byte_table(&embeds[..8]);
    let high = byte_table(&embeds[8..]);
    let low_linear = low.map(|a| a * ones);
    let high_linear = high.map(|a| a * ones);
    let weights: Vec<_> = claim
        .weights
        .as_chunks::<8>()
        .0
        .iter()
        .map(|v| byte_table(v))
        .collect();
    let eq = Point::new(claim.instance.as_slice()).equality_weights_msb();
    words
        .par_chunks_exact(BITS)
        .zip(eq.par_iter())
        .map(|(row, &scale)| {
            // Keep the embedded row in worker-local storage. The unary term
            // ones*a is linear over the 16 input bits and comes from lookups.
            let embedded: [(F, F); BITS] = core::array::from_fn(|j| {
                let [lo, hi] = row[j].to_le_bytes().map(usize::from);
                (low[lo] + high[hi], low_linear[lo] + high_linear[hi])
            });
            let mut sums = [E::ZERO; COEFFS];
            for (block, lookup) in weights.iter().enumerate() {
                let start = block * 8;
                let products: [u64; 8] = core::array::from_fn(|i| {
                    let j = start + i;
                    let b = embedded[linear::shift(j, 1)].0;
                    let c = embedded[linear::shift(j, 2)].0;
                    embedded[j].1.to_repr() ^ embedded_product(ones + b, c)
                });
                for (byte, chunk) in sums.chunks_mut(8).enumerate() {
                    let columns = transpose8(u64::from_le_bytes(
                        products.map(|p| (p >> (byte * 8)) as u8),
                    ))
                    .to_le_bytes();
                    for (sum, key) in chunk.iter_mut().zip(columns) {
                        *sum += lookup[key as usize];
                    }
                }
            }
            sums.map(|v| v * scale)
        })
        .reduce(
            || [E::ZERO; COEFFS],
            |a, b| core::array::from_fn(|i| a[i] + b[i]),
        )
        .to_vec()
}

fn challenge(coeff: &[E], ch: &mut impl FieldChallenger<F>) -> (E, [E; 16]) {
    ch.observe_algebra_slice(coeff);
    let t: E = ch.sample_algebra_element();
    let mut powers = [E::ONE; 24];
    for i in 1..24 {
        powers[i] = powers[i - 1] * t;
    }
    let lanes = EMBED.map(|mask| {
        powers
            .iter()
            .enumerate()
            .filter(|(i, _)| (mask >> i) & 1 == 1)
            .map(|(_, &v)| v)
            .sum()
    });
    let value = coeff.iter().rev().fold(E::ZERO, |acc, &c| acc * t + c);
    (value, lanes)
}

fn project(coeff: &[E], lanes: &[E; 16]) -> E {
    PROJECT
        .iter()
        .zip(lanes)
        .map(|(&mask, &lane)| {
            lane * coeff
                .iter()
                .enumerate()
                .filter(|(i, _)| (mask >> i) & 1 == 1)
                .map(|(_, &v)| v)
                .sum::<E>()
        })
        .sum()
}

pub(super) fn prove(
    states: &[State],
    before_chi: impl Fn(usize, State) -> State + Sync,
    current: &PackedClaim,
    ch: &mut Challenger,
) -> (Layer, PackedClaim) {
    let words = pack(states, before_chi);
    let coeff = coefficients(&words, &current.claim);
    let (value, lanes) = challenge(&coeff, ch);
    let instance = &current.claim.instance;
    let mut sumcheck = ChiSumcheck::encoded(
        encode(&words, &lanes),
        instance,
        current.claim.weights.clone(),
        lanes.iter().copied().sum(),
    );
    let (proof, point) = sumcheck.prove::<F, _>(ch, instance.len() + POSITION_LOG, 3, 0, value);
    let values = sumcheck.terminal();
    let claim = previous_claim(
        point.as_slice(),
        values,
        bind_values(values, ch),
        instance.len(),
    );
    (
        Layer {
            coefficients: coeff,
            sumcheck: proof,
            values,
        },
        PackedClaim { claim, lanes },
    )
}

pub(super) fn verify(
    layer: &Layer,
    current: &PackedClaim,
    round_constant: E,
    ch: &mut (impl FieldChallenger<F> + GrindingChallenger<Witness = F>),
) -> Result<PackedClaim> {
    verify_parts(
        &layer.coefficients,
        &layer.sumcheck,
        layer.values,
        current,
        round_constant,
        ch,
    )
}

pub(super) fn verify_parts(
    coefficients: &[E],
    sumcheck: &closing::Proof,
    values: [E; 3],
    current: &PackedClaim,
    round_constant: E,
    ch: &mut (impl FieldChallenger<F> + GrindingChallenger<Witness = F>),
) -> Result<PackedClaim> {
    ensure!(
        coefficients.len() == COEFFS,
        "incorrect packed product degree"
    );
    ensure!(
        project(coefficients, &current.lanes) + round_constant == current.claim.value,
        "incorrect projected chi claim"
    );
    let (value, lanes) = challenge(coefficients, ch);
    ensure!(
        sumcheck.claimed_sum == value,
        "incorrect packed polynomial evaluation"
    );
    let instance = &current.claim.instance;
    let (point, terminal) = sumcheck.verify(ch, instance.len() + POSITION_LOG, 3, 0)?;
    let (next, position) = point.as_slice().split_at(instance.len());
    let [a, b, c] = values;
    let k: E = lanes.iter().copied().sum();
    ensure!(
        terminal
            == Point::eval_eq(instance, next)
                * closing::evaluate_folded(&current.claim.weights, position)
                * (k * (a + c) + b * c),
        "incorrect packed chi endpoint"
    );
    let claim = previous_claim(
        point.as_slice(),
        values,
        bind_values(values, ch),
        instance.len(),
    );
    Ok(PackedClaim { claim, lanes })
}

pub(super) fn iota(claim: &PackedClaim, round: usize) -> E {
    claim.lanes.iter().copied().sum::<E>()
        * (0..64)
            .filter(|bit| RC[round] >> bit & 1 != 0)
            .map(|bit| claim.claim.weights[bit])
            .sum::<E>()
}

impl Layer {
    pub(super) fn scalar_count(&self) -> usize {
        self.coefficients.len()
            + self.values.len()
            + 1
            + self
                .sumcheck
                .round_polys
                .iter()
                .map(Vec::len)
                .sum::<usize>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn all_basis_products() {
        for (i, &a) in EMBED.iter().enumerate() {
            for (j, &b) in EMBED.iter().enumerate() {
                let (a, b) = (F::from_repr(a.into()), F::from_repr(b.into()));
                let p = embedded_product(a, b);
                assert_eq!(p, (a * b).to_repr());
                for (k, &mask) in PROJECT.iter().enumerate() {
                    assert_eq!((p & mask).count_ones() % 2, u32::from(i == j && j == k));
                }
            }
        }
        for bit in 0..64 {
            assert_eq!(transpose8(1 << bit), 1 << ((bit % 8) * 8 + bit / 8));
        }
    }
}
