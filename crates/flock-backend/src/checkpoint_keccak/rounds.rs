//! Reference cubic sumcheck: instance variables first, then bit positions.
use p3_binary_field::Poly192 as E;
use p3_field::PrimeCharacteristicRing;
use p3_maybe_rayon::prelude::*;
use p3_multilinear_util::poly::Poly;
use p3_sumcheck::generic_degree::{RoundPolyInterpolator, RoundProver};

use super::{BITS, POSITIONS, State, linear::shift};

pub(super) struct ChiSumcheck {
    stage: Stage,
    weights: Vec<E>,
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
    Bits(Vec<State>),
    Folded(Vec<E>),
}

impl Columns {
    /// Coefficients of sum_j w[j] * chi(low[j] + t * delta[j]).
    /// Expanding once avoids evaluating the quadratic at three field nodes.
    fn chi_coefficients(&self, i: usize, half: usize, weights: &[E]) -> [E; 3] {
        let mut coefficients = [E::ZERO; 3];
        if let Self::Bits(states) = self {
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
                for (sum, mut mask) in coefficients.iter_mut().zip(masks) {
                    while mask != 0 {
                        *sum += weights[lane * 64 + mask.trailing_zeros() as usize];
                        mask &= mask - 1;
                    }
                }
            }
            return coefficients;
        }
        for (j, &weight) in weights.iter().enumerate() {
            let low: [E; 3] = core::array::from_fn(|k| self.at(i, shift(j, k)));
            let delta: [E; 3] = core::array::from_fn(|k| self.at(i + half, shift(j, k)) - low[k]);
            coefficients[0] += weight * (low[0] + low[2] + low[1] * low[2]);
            coefficients[1] +=
                weight * (delta[0] + delta[2] + low[1] * delta[2] + delta[1] * low[2]);
            coefficients[2] += weight * delta[1] * delta[2];
        }
        coefficients
    }

    fn at(&self, instance: usize, position: usize) -> E {
        match self {
            Self::Bits(states) => {
                E::from_bool((states[instance][position / 64] >> (position % 64)) & 1 != 0)
            }
            Self::Folded(values) => values[instance * BITS + position],
        }
    }

    fn fold(&mut self, half: usize, challenge: E) {
        if let Self::Folded(values) = self {
            let (low, high) = values.split_at_mut(half * BITS);
            low.par_iter_mut().zip(high.par_iter()).for_each(|(a, &b)| {
                *a += (b - *a) * challenge;
            });
            values.truncate(half * BITS);
            values.shrink_to_fit();
            return;
        }
        let Self::Bits(states) = self else {
            unreachable!()
        };
        let lookup = [E::ZERO, challenge, E::ONE - challenge, E::ONE];
        let mut values = E::zero_vec(half * BITS);
        values
            .par_chunks_mut(BITS)
            .enumerate()
            .for_each(|(i, row)| {
                for (j, value) in row.iter_mut().enumerate() {
                    let low = ((states[i][j / 64] >> (j % 64)) & 1) as usize;
                    let high = ((states[i + half][j / 64] >> (j % 64)) & 1) as usize;
                    *value = lookup[2 * low + high];
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
                columns: Columns::Bits(states),
                equality: Poly::new(equality),
                count,
            },
            weights,
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
        let mut weights = self.weights.clone();
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
