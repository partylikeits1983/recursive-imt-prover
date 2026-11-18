//! Keccak's linear layer and its transpose on bit weights.
use p3_binary_field::Poly192;

use super::{BITS, State};
use crate::keccak::{RC, RHO};

/// Theta, rho and pi, before the nonlinear chi step.
pub(super) fn forward(input: &State) -> State {
    let columns: [u64; 5] =
        core::array::from_fn(|x| (0..5).fold(0, |value, y| value ^ input[x + 5 * y]));
    let mut output = [0; 25];
    for x in 0..5 {
        let delta = columns[(x + 4) % 5] ^ columns[(x + 1) % 5].rotate_left(1);
        for y in 0..5 {
            output[y + 5 * ((2 * x + 3 * y) % 5)] =
                (input[x + 5 * y] ^ delta).rotate_left(RHO[x + 5 * y] as u32);
        }
    }
    output
}

pub(super) fn finish_round(before_chi: &State, round: usize) -> State {
    let mut output = core::array::from_fn(|lane| {
        let (x, y) = (lane % 5, lane / 5);
        before_chi[lane] ^ ((!before_chi[(x + 1) % 5 + 5 * y]) & before_chi[(x + 2) % 5 + 5 * y])
    });
    output[0] ^= RC[round];
    output
}

/// Move position `j` by `offset` lanes in its five-lane chi row.
pub(super) const fn shift(j: usize, offset: usize) -> usize {
    let lane = j / 64;
    ((lane % 5 + offset) % 5 + 5 * (lane / 5)) * 64 + j % 64
}

/// Exact transpose: <weights, forward(input)> = <transpose(weights), input>.
pub(super) fn transpose(weights: &[Poly192]) -> Vec<Poly192> {
    transpose_with(weights, |a, b| *a + *b)
}

pub(super) fn transpose_with<T: Clone>(weights: &[T], mut add: impl FnMut(&T, &T) -> T) -> Vec<T> {
    assert_eq!(weights.len(), BITS);
    let mut theta = weights.to_vec();
    for x in 0..5 {
        for y in 0..5 {
            let source = x + 5 * y;
            let destination = y + 5 * ((2 * x + 3 * y) % 5);
            for bit in 0..64 {
                theta[source * 64 + bit] =
                    weights[destination * 64 + (bit + RHO[source]) % 64].clone();
            }
        }
    }
    let columns: Vec<_> = (0..320)
        .map(|index| {
            let (x, bit) = (index / 64, index % 64);
            (1..5).fold(theta[x * 64 + bit].clone(), |sum, y| {
                add(&sum, &theta[(x + 5 * y) * 64 + bit])
            })
        })
        .collect();
    (0..BITS)
        .map(|j| {
            let (x, bit) = ((j / 64) % 5, j % 64);
            let value = add(&theta[j], &columns[((x + 1) % 5) * 64 + bit]);
            add(&value, &columns[((x + 4) % 5) * 64 + (bit + 1) % 64])
        })
        .collect()
}
