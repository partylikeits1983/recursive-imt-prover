//! Factored evaluation of the transposed Keccak linear layer after chi batching.
use super::{BITS, CF, CircuitBuilder, NativePoly192Target as T, equality_weights, linear};
use crate::keccak::RHO;

pub(in crate::checkpoint_keccak) enum Weights {
    Dense(Vec<T>),
    LinearChi {
        lanes: Vec<T>,
        bits: Vec<T>,
        point: Vec<T>,
    },
}

impl Weights {
    pub fn linear_chi(b: &mut CircuitBuilder<CF>, position: &[T], beta: &T, square: &T) -> Self {
        let lanes = equality_weights(b, &position[..5]);
        let lanes = (0..25)
            .map(|lane| {
                let second = b.native_poly192_mul(beta, &lanes[linear::shift(lane * 64, 4) / 64]);
                let third = b.native_poly192_mul(square, &lanes[linear::shift(lane * 64, 3) / 64]);
                let sum = b.native_poly192_add(&lanes[lane], &second);
                b.native_poly192_add(&sum, &third)
            })
            .collect();
        Self::LinearChi {
            lanes,
            bits: equality_weights(b, &position[5..]),
            point: position[5..].to_vec(),
        }
    }

    pub fn iota(&self, b: &mut CircuitBuilder<CF>, rc: u64) -> T {
        let selected = |bit: usize| (rc >> bit) & 1 != 0;
        match self {
            Self::Dense(values) => sum(
                b,
                &(0..64)
                    .filter(|&bit| selected(bit))
                    .map(|bit| values[bit].clone())
                    .collect::<Vec<_>>(),
            ),
            Self::LinearChi { lanes, bits, .. } => {
                let mut total = b.native_poly192_constant([0; 3]);
                for (source, delta) in core::iter::once((0, 0))
                    .chain((0..5).map(|y| (1 + 5 * y, 0)))
                    .chain((0..5).map(|y| (4 + 5 * y, 1)))
                {
                    let selected: Vec<_> = (0..64)
                        .filter(|&bit| selected(bit))
                        .map(|bit| bits[(bit + RHO[source] + delta) % 64].clone())
                        .collect();
                    let bit_sum = sum(b, &selected);
                    let product = b.native_poly192_mul(&lanes[pi(source)], &bit_sum);
                    total = b.native_poly192_add(&total, &product);
                }
                total
            }
        }
    }

    pub fn evaluate(&self, b: &mut CircuitBuilder<CF>, position: &[T]) -> T {
        let mut value = b.native_poly192_constant([0; 3]);
        match self {
            Self::Dense(weights) => {
                for (w, p) in weights.iter().zip(equality_weights(b, position)) {
                    let product = b.native_poly192_mul(w, &p);
                    value = b.native_poly192_add(&value, &product);
                }
            }
            Self::LinearChi { lanes, point, .. } => {
                let target = equality_weights(b, &position[..5]);
                let columns: Vec<_> = (0..5)
                    .map(|x| {
                        sum(
                            b,
                            &(0..5)
                                .map(|y| target[x + 5 * y].clone())
                                .collect::<Vec<_>>(),
                        )
                    })
                    .collect();
                let rotations = correlations(b, &position[5..], point);
                for source in 0..25 {
                    let x = source % 5;
                    let own = b.native_poly192_add(&target[source], &columns[(x + 4) % 5]);
                    let first = b.native_poly192_mul(&own, &rotations[RHO[source]]);
                    let second = b.native_poly192_mul(
                        &columns[(x + 1) % 5],
                        &rotations[(RHO[source] + 1) % 64],
                    );
                    let term = b.native_poly192_add(&first, &second);
                    let product = b.native_poly192_mul(&lanes[pi(source)], &term);
                    value = b.native_poly192_add(&value, &product);
                }
            }
        }
        value
    }

    pub fn expand(self, b: &mut CircuitBuilder<CF>) -> Vec<T> {
        match self {
            Self::Dense(weights) => weights,
            Self::LinearChi { lanes, bits, .. } => {
                let weights: Vec<_> = (0..BITS)
                    .map(|j| b.native_poly192_mul(&lanes[j / 64], &bits[j % 64]))
                    .collect();
                linear::transpose_with(&weights, |a, c| b.native_poly192_add(a, c))
            }
        }
    }
}

const fn pi(lane: usize) -> usize {
    let (x, y) = (lane % 5, lane / 5);
    y + 5 * ((2 * x + 3 * y) % 5)
}

fn sum(b: &mut CircuitBuilder<CF>, values: &[T]) -> T {
    values
        .iter()
        .fold(b.native_poly192_constant([0; 3]), |sum, value| {
            b.native_poly192_add(&sum, value)
        })
}

/// All sums eq(a, z) * eq(c, z + k mod 64), using two carry states per bit.
fn correlations(b: &mut CircuitBuilder<CF>, a: &[T], c: &[T]) -> Vec<T> {
    assert_eq!(a.len(), 6);
    assert_eq!(c.len(), 6);
    let zero = b.native_poly192_constant([0; 3]);
    let one = b.native_poly192_constant([1, 0, 0]);
    let mut states = vec![(one.clone(), zero.clone())];
    for (bit, (a, c)) in a.iter().rev().zip(c.iter().rev()).enumerate() {
        let cross = b.native_poly192_mul(a, c);
        let low_high = b.native_poly192_add(c, &cross);
        let high_low = b.native_poly192_add(a, &cross);
        let difference = b.native_poly192_add(a, c);
        let diagonal = b.native_poly192_add(&one, &difference);
        let size = states.len();
        if bit == 5 {
            let mut values = vec![zero.clone(); 2 * size];
            for (k, (low, high)) in states.iter().enumerate() {
                let total = b.native_poly192_add(low, high);
                let same = b.native_poly192_mul(&total, &diagonal);
                values[k] = b.native_poly192_add(high, &same);
                values[k + size] = b.native_poly192_add(low, &same);
            }
            return values;
        }
        let mut next = vec![(zero.clone(), zero.clone()); 2 * size];
        for (k, (low, high)) in states.iter().enumerate() {
            let l_same = b.native_poly192_mul(low, &diagonal);
            let h_same = b.native_poly192_mul(high, &diagonal);
            let l_up = b.native_poly192_mul(low, &low_high);
            let h_up = b.native_poly192_mul(high, &low_high);
            let l_down = b.native_poly192_mul(low, &high_low);
            let h_down = b.native_poly192_mul(high, &high_low);
            next[k] = (b.native_poly192_add(&l_same, &h_up), h_down);
            next[k + size] = (l_up, b.native_poly192_add(&l_down, &h_same));
        }
        states = next;
    }
    unreachable!()
}
