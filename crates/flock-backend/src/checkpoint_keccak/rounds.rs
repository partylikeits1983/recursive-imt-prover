//! Reference cubic sumcheck: instance variables first, then bit positions.
use p3_binary_field::Poly192 as E;
use p3_field::{ExtensionField, Field, PackedFieldExtension, PackedValue, PrimeCharacteristicRing};
use p3_maybe_rayon::prelude::*;
use p3_multilinear_util::poly::Poly;
use p3_sumcheck::generic_degree::{RoundPolyInterpolator, RoundProver};

use super::{BITS, POSITIONS, State, linear::shift};
use crate::F;

type PackedE = <E as ExtensionField<F>>::ExtensionPacking;
const PACKING_WIDTH: usize = <F as Field>::Packing::WIDTH;

pub(super) struct ChiSumcheck {
    stage: Stage,
    weights: Weights,
}

struct Weights {
    values: Vec<E>,
    nibbles: Vec<[E; 16]>,
}

enum Stage {
    Instances {
        columns: Columns,
        equality: Poly<E>,
        count: usize,
    },
    Positions {
        columns: [Poly<E>; 3],
        weights: Poly<E>,
        scale: E,
    },
}

enum Columns {
    Bits {
        states: Vec<State>,
        first: Option<E>,
    },
    Folded(Vec<E>),
}

impl Weights {
    fn new(values: Vec<E>) -> Self {
        let nibbles = values.as_chunks::<4>().0.iter().map(subset_sums).collect();
        Self { values, nibbles }
    }

    fn lane_sum(&self, lane: usize, mut mask: u64) -> E {
        let mut value = E::ZERO;
        for table in &self.nibbles[16 * lane..16 * (lane + 1)] {
            value += table[(mask & 15) as usize];
            mask >>= 4;
        }
        value
    }
}

impl Columns {
    /// Coefficients of sum_j w[j] * chi(low[j] + t * delta[j]).
    /// Expanding once avoids evaluating the quadratic at three field nodes.
    fn chi_coefficients(&self, i: usize, half: usize, weights: &Weights) -> [E; 3] {
        let mut coefficients = [E::ZERO; 3];
        if let Self::Bits { states, first } = self {
            if let Some(r) = first {
                let mut sums = [[E::ZERO; 3]; 3];
                for lane in 0..25 {
                    let low: [u64; 3] =
                        core::array::from_fn(|k| states[i][shift(lane * 64, k) / 64]);
                    let high: [u64; 3] =
                        core::array::from_fn(|k| states[i + half][shift(lane * 64, k) / 64]);
                    let dlow: [u64; 3] = core::array::from_fn(|k| {
                        low[k] ^ states[i + 2 * half][shift(lane * 64, k) / 64]
                    });
                    let dhigh: [u64; 3] = core::array::from_fn(|k| {
                        high[k] ^ states[i + 3 * half][shift(lane * 64, k) / 64]
                    });
                    let [a, b, c] = low;
                    let [ar, br, cr] = dlow;
                    let [at, bt, ct] = core::array::from_fn(|k| low[k] ^ high[k]);
                    let [art, brt, crt] = core::array::from_fn(|k| dlow[k] ^ dhigh[k]);
                    // Coefficients in the new round variable, each quadratic in r.
                    let masks = [
                        [a ^ c ^ (b & c), ar ^ cr ^ (b & cr) ^ (br & c), br & cr],
                        [
                            at ^ ct ^ (b & ct) ^ (bt & c),
                            art ^ crt ^ (b & crt) ^ (br & ct) ^ (bt & cr) ^ (brt & c),
                            (br & crt) ^ (brt & cr),
                        ],
                        [bt & ct, (bt & crt) ^ (brt & ct), brt & crt],
                    ];
                    for (sums, masks) in sums.iter_mut().zip(masks) {
                        for (sum, mask) in sums.iter_mut().zip(masks) {
                            *sum += weights.lane_sum(lane, mask);
                        }
                    }
                }
                return sums.map(|[a, b, c]| a + *r * (b + *r * c));
            }
            let low = &states[i];
            let high = &states[i + half];
            for lane in 0..25 {
                let next = shift(lane * 64, 1) / 64;
                let after = shift(lane * 64, 2) / 64;
                let a = low[lane];
                let b = low[next];
                let c = low[after];
                let da = a ^ high[lane];
                let db = b ^ high[next];
                let dc = c ^ high[after];
                let masks = [a ^ c ^ (b & c), da ^ dc ^ (b & dc) ^ (db & c), db & dc];
                for (sum, mask) in coefficients.iter_mut().zip(masks) {
                    *sum += weights.lane_sum(lane, mask);
                }
            }
            return coefficients;
        }
        let Self::Folded(values) = self else {
            unreachable!()
        };
        let low = &values[i * BITS..(i + 1) * BITS];
        let high = &values[(i + half) * BITS..(i + half + 1) * BITS];
        let load = |row: &[E], j| {
            <PackedE as PackedFieldExtension<F, E>>::from_ext_slice(&row[j..j + PACKING_WIDTH])
        };
        let mut sums = [PackedE::ZERO.mul_unreduced(PackedE::ZERO); 3];
        for j in (0..BITS).step_by(PACKING_WIDTH) {
            let a: [PackedE; 3] = core::array::from_fn(|k| load(low, shift(j, k)));
            let d: [PackedE; 3] = core::array::from_fn(|k| load(high, shift(j, k)) + a[k]);
            let w = load(&weights.values, j);
            sums[0] += w.mul_unreduced(a[0] + a[2] + a[1] * a[2]);
            sums[1] += w.mul_unreduced(d[0] + d[2] + a[1] * d[2] + d[1] * a[2]);
            sums[2] += (w * d[1]).mul_unreduced(d[2]);
        }
        sums.map(|sum| {
            let reduced = sum.reduce();
            (0..PACKING_WIDTH)
                .map(|lane| <PackedE as PackedFieldExtension<F, E>>::extract(&reduced, lane))
                .sum()
        })
    }

    fn at(&self, instance: usize, position: usize) -> E {
        match self {
            Self::Bits { states, first } => {
                let bit =
                    |i: usize| E::from_bool((states[i][position / 64] >> (position % 64)) & 1 != 0);
                let low = bit(instance);
                first.map_or(low, |r| low + r * (bit(instance + states.len() / 2) + low))
            }
            Self::Folded(values) => values[instance * BITS + position],
        }
    }

    fn fold(&mut self, half: usize, challenge: E) {
        if let Self::Folded(values) = self {
            let (low, high) = values.split_at_mut(half * BITS);
            let r = PackedE::from(challenge);
            low.par_chunks_exact_mut(PACKING_WIDTH)
                .zip(high.par_chunks_exact(PACKING_WIDTH))
                .for_each(|(a, b)| {
                    let low = <PackedE as PackedFieldExtension<F, E>>::from_ext_slice(a);
                    let high = <PackedE as PackedFieldExtension<F, E>>::from_ext_slice(b);
                    <PackedE as PackedFieldExtension<F, E>>::to_ext_slice(
                        &(low + (high + low) * r),
                        a,
                    );
                });
            values.truncate(half * BITS);
            values.shrink_to_fit();
            return;
        }
        let Self::Bits { states, first } = self else {
            unreachable!()
        };
        let Some(r) = *first else {
            *first = Some(challenge);
            return;
        };
        let lookup = subset_sums(&[
            (E::ONE + r) * (E::ONE + challenge),
            (E::ONE + r) * challenge,
            r * (E::ONE + challenge),
            r * challenge,
        ]);
        let mut values = E::zero_vec(half * BITS);
        values
            .par_chunks_mut(BITS)
            .enumerate()
            .for_each(|(i, row)| {
                for (j, value) in row.iter_mut().enumerate() {
                    let index = (0..4).fold(0, |index, k| {
                        index | ((((states[i + k * half][j / 64] >> (j % 64)) & 1) as usize) << k)
                    });
                    *value = lookup[index];
                }
            });
        *self = Self::Folded(values);
    }
}

impl ChiSumcheck {
    pub fn new(states: Vec<State>, equality: Vec<E>, weights: Vec<E>) -> Self {
        assert_eq!(weights.len(), BITS);
        assert_eq!(states.len(), equality.len());
        let count = states.len();
        let mut state = Self {
            stage: Stage::Instances {
                columns: Columns::Bits {
                    states,
                    first: None,
                },
                equality: Poly::new(equality),
                count,
            },
            weights: Weights::new(weights),
        };
        state.enter_positions();
        state
    }

    fn enter_positions(&mut self) {
        let Stage::Instances {
            columns,
            equality,
            count: 1,
        } = &self.stage
        else {
            return;
        };
        let values = core::array::from_fn(|offset| {
            Poly::new(
                (0..POSITIONS)
                    .map(|j| {
                        if j < BITS {
                            columns.at(0, shift(j, offset))
                        } else {
                            E::ZERO
                        }
                    })
                    .collect(),
            )
        });
        let mut weights = self.weights.values.clone();
        weights.resize(POSITIONS, E::ZERO);
        self.stage = Stage::Positions {
            columns: values,
            weights: Poly::new(weights),
            scale: equality.as_slice()[0],
        };
    }

    pub fn terminal(&self) -> [E; 3] {
        let Stage::Positions { columns, .. } = &self.stage else {
            unreachable!()
        };
        core::array::from_fn(|i| columns[i].as_constant().unwrap())
    }
}

fn subset_sums(values: &[E; 4]) -> [E; 16] {
    let mut table = [E::ZERO; 16];
    for mask in 1usize..16 {
        table[mask] = table[mask & (mask - 1)] + values[mask.trailing_zeros() as usize];
    }
    table
}

impl RoundProver<E> for ChiSumcheck {
    fn fold(&mut self, challenge: E) {
        match &mut self.stage {
            Stage::Instances {
                columns,
                equality,
                count,
            } => {
                *count /= 2;
                columns.fold(*count, challenge);
                equality.fix_prefix_var_mut(challenge);
            }
            Stage::Positions {
                columns, weights, ..
            } => {
                for column in columns {
                    column.fix_prefix_var_mut(challenge);
                }
                weights.fix_prefix_var_mut(challenge);
            }
        }
        self.enter_positions();
    }

    fn round_poly(&self) -> Vec<E> {
        let nodes: [E; 3] = core::array::from_fn(RoundPolyInterpolator::transmitted_node);
        match &self.stage {
            Stage::Instances {
                columns,
                equality,
                count,
            } => {
                let half = count / 2;
                let sums = (0..half)
                    .into_par_iter()
                    .map(|i| {
                        let [a, b, c] = columns.chi_coefficients(i, half, &self.weights);
                        let low = equality.as_slice()[i];
                        let delta = equality.as_slice()[i + half] - low;
                        nodes.map(|node| (low + delta * node) * (a + node * (b + node * c)))
                    })
                    .reduce(
                        || [E::ZERO; 3],
                        |a, b| core::array::from_fn(|k| a[k] + b[k]),
                    );
                sums.to_vec()
            }
            Stage::Positions {
                columns,
                weights,
                scale,
            } => {
                let half = weights.num_evals() / 2;
                nodes
                    .into_iter()
                    .map(|node| {
                        let line = |p: &Poly<E>, i: usize| {
                            let low = p.as_slice()[i];
                            low + (p.as_slice()[i + half] - low) * node
                        };
                        *scale
                            * (0..half)
                                .map(|i| {
                                    let b = columns.each_ref().map(|p| line(p, i));
                                    line(weights, i) * (b[0] + b[2] + b[1] * b[2])
                                })
                                .sum::<E>()
                    })
                    .collect()
            }
        }
    }
}
