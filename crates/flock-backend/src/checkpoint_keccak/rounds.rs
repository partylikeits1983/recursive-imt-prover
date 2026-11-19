//! Reference cubic sumcheck: instance variables first, then bit positions.
use p3_binary_field::Poly192 as E;
use p3_field::{ExtensionField, Field, PackedFieldExtension, PackedValue, PrimeCharacteristicRing};
use p3_maybe_rayon::prelude::*;
use p3_multilinear_util::{point::Point, poly::Poly};
use p3_sumcheck::generic_degree::{RoundPolyInterpolator, RoundProver};

use super::{BITS, POSITIONS, State, linear::shift};
use crate::F;

type PackedE = <E as ExtensionField<F>>::ExtensionPacking;
const PACKING_WIDTH: usize = <F as Field>::Packing::WIDTH;

pub(super) struct ChiSumcheck<'a> {
    stage: Stage,
    weights: Weights,
    point: &'a [E],
}

struct Weights {
    values: Vec<E>,
    bytes: Vec<[E; 256]>,
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
    FourBits(Box<FourBitColumns>),
    Folded(Vec<E>),
}

// After two folds every entry is a subset sum of the same four challenge
// weights. Its four-bit index adds by XOR even for degenerate challenges.
struct FourBitColumns {
    indices: Vec<u8>,
    values: [E; 16],
    products: [E; 256],
}

impl FourBitColumns {
    fn chi_endpoint_and_quadratic(&self, i: usize, other: usize, weights: &[E]) -> [E; 2] {
        let low = &self.indices[i * BITS..(i + 1) * BITS];
        let high = &self.indices[other * BITS..(other + 1) * BITS];
        // Group bit weights by their field value before multiplying. The low
        // endpoint contributes a + c + b*c and the quadratic term db*dc.
        let mut linear = [E::ZERO; 16];
        let mut product = [E::ZERO; 256];
        let mut quadratic = [E::ZERO; 256];
        for lane in 0..25 {
            let j = lane * 64;
            let next = shift(j, 1);
            let after = shift(j, 2);
            for bit in 0..64 {
                let a = low[j + bit];
                let b = low[next + bit];
                let c = low[after + bit];
                let db = b ^ high[next + bit];
                let dc = c ^ high[after + bit];
                let weight = weights[j + bit];
                linear[(a ^ c) as usize] += weight;
                product[(b << 4 | c) as usize] += weight;
                quadratic[(db << 4 | dc) as usize] += weight;
            }
        }
        [
            E::dot_product(&linear, &self.values) + E::dot_product(&product, &self.products),
            E::dot_product(&quadratic, &self.products),
        ]
    }

    fn fold(&self, half: usize, challenge: E) -> Vec<E> {
        let low = self.values.map(|v| (E::ONE + challenge) * v);
        let high = self.values.map(|v| challenge * v);
        let lookup: [E; 256] = core::array::from_fn(|i| low[i & 15] + high[i >> 4]);
        let (left, right) = self.indices.split_at(half * BITS);
        left.par_iter()
            .zip(right.par_iter())
            .map(|(&a, &b)| lookup[(a | b << 4) as usize])
            .collect()
    }
}

impl Weights {
    fn new(values: Vec<E>) -> Self {
        let bytes = values.as_chunks::<8>().0.iter().map(subset_sums).collect();
        Self { values, bytes }
    }

    fn lane_sum(&self, lane: usize, mut mask: u64) -> E {
        let mut value = E::ZERO;
        for table in &self.bytes[8 * lane..8 * (lane + 1)] {
            value += table[(mask & 255) as usize];
            mask >>= 8;
        }
        value
    }
}

impl Columns {
    /// Constant and quadratic coefficients of the weighted chi polynomial along a pair.
    /// Starting at either endpoint gives the same quadratic term in characteristic two.
    fn chi_endpoint_and_quadratic(
        &self,
        i: usize,
        other: usize,
        half: usize,
        weights: &Weights,
    ) -> [E; 2] {
        let mut coefficients = [E::ZERO; 2];
        if let Self::Bits { states, first } = self {
            if let Some(r) = first {
                let mut sums = [[E::ZERO; 3]; 2];
                for lane in 0..25 {
                    let low: [u64; 3] =
                        core::array::from_fn(|k| states[i][shift(lane * 64, k) / 64]);
                    let high: [u64; 3] =
                        core::array::from_fn(|k| states[other][shift(lane * 64, k) / 64]);
                    let dlow: [u64; 3] = core::array::from_fn(|k| {
                        low[k] ^ states[i + 2 * half][shift(lane * 64, k) / 64]
                    });
                    let dhigh: [u64; 3] = core::array::from_fn(|k| {
                        high[k] ^ states[other + 2 * half][shift(lane * 64, k) / 64]
                    });
                    let [a, b, c] = low;
                    let [ar, br, cr] = dlow;
                    let bt = low[1] ^ high[1];
                    let ct = low[2] ^ high[2];
                    let brt = dlow[1] ^ dhigh[1];
                    let crt = dlow[2] ^ dhigh[2];
                    // Coefficients in the new round variable, each quadratic in r.
                    let masks = [
                        [a ^ c ^ (b & c), ar ^ cr ^ (b & cr) ^ (br & c), br & cr],
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
            let high = &states[other];
            for lane in 0..25 {
                let next = shift(lane * 64, 1) / 64;
                let after = shift(lane * 64, 2) / 64;
                let a = low[lane];
                let b = low[next];
                let c = low[after];
                let db = b ^ high[next];
                let dc = c ^ high[after];
                let masks = [a ^ c ^ (b & c), db & dc];
                for (sum, mask) in coefficients.iter_mut().zip(masks) {
                    *sum += weights.lane_sum(lane, mask);
                }
            }
            return coefficients;
        }
        if let Self::FourBits(columns) = self {
            return columns.chi_endpoint_and_quadratic(i, other, &weights.values);
        }
        let Self::Folded(values) = self else {
            unreachable!()
        };
        let low = &values[i * BITS..(i + 1) * BITS];
        let high = &values[other * BITS..(other + 1) * BITS];
        let load = |row: &[E], j| {
            <PackedE as PackedFieldExtension<F, E>>::from_ext_slice(&row[j..j + PACKING_WIDTH])
        };
        let mut sums = [PackedE::ZERO.mul_unreduced(PackedE::ZERO); 2];
        for j in (0..BITS).step_by(PACKING_WIDTH) {
            let [a, b, c] = core::array::from_fn(|k| load(low, shift(j, k)));
            let y = load(high, shift(j, 1));
            let z = load(high, shift(j, 2));
            let w = load(&weights.values, j);
            sums[0] += w.mul_unreduced(a + c + b * c);
            sums[1] += (w * (b + y)).mul_unreduced(c + z);
        }
        sums.map(|sum| {
            let reduced = sum.reduce();
            (0..PACKING_WIDTH)
                .map(|lane| <PackedE as PackedFieldExtension<F, E>>::extract(&reduced, lane))
                .sum::<E>()
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
            Self::FourBits(columns) => {
                columns.values[columns.indices[instance * BITS + position] as usize]
            }
            Self::Folded(values) => values[instance * BITS + position],
        }
    }

    fn fold(&mut self, half: usize, challenge: E) {
        if let Self::FourBits(columns) = self {
            *self = Self::Folded(columns.fold(half, challenge));
            return;
        }
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
        let lookup: [E; 16] = subset_sums(&[
            (E::ONE + r) * (E::ONE + challenge),
            (E::ONE + r) * challenge,
            r * (E::ONE + challenge),
            r * challenge,
        ]);
        let mut indices = vec![0u8; half * BITS];
        indices
            .par_chunks_mut(BITS)
            .enumerate()
            .for_each(|(i, row)| {
                for (j, value) in row.iter_mut().enumerate() {
                    let index = (0..4).fold(0, |index, k| {
                        index | ((((states[i + k * half][j / 64] >> (j % 64)) & 1) as usize) << k)
                    });
                    *value = index as u8;
                }
            });
        *self = Self::FourBits(Box::new(FourBitColumns {
            indices,
            values: lookup,
            products: core::array::from_fn(|i| lookup[i >> 4] * lookup[i & 15]),
        }));
    }
}

impl<'a> ChiSumcheck<'a> {
    pub fn new(states: Vec<State>, point: &'a [E], weights: Vec<E>) -> Self {
        let equality = Point::new(point).equality_weights_msb();
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
            point,
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

fn subset_sums<const N: usize, const M: usize>(values: &[E; N]) -> [E; M] {
    assert_eq!(M, 1 << N);
    let mut table = [E::ZERO; M];
    for mask in 1usize..M {
        table[mask] = table[mask & (mask - 1)] + values[mask.trailing_zeros() as usize];
    }
    table
}

impl RoundProver<E> for ChiSumcheck<'_> {
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

    const USES_RUNNING_SUM: bool = true;

    fn round_poly(&self) -> Vec<E> {
        self.evals(None)
    }

    fn round_poly_with_sum(&self, sum: E) -> Vec<E> {
        self.evals(Some(sum))
    }
}

impl ChiSumcheck<'_> {
    fn evals(&self, sum: Option<E>) -> Vec<E> {
        let nodes: [E; 3] = core::array::from_fn(RoundPolyInterpolator::transmitted_node);
        match &self.stage {
            Stage::Instances {
                columns,
                equality,
                count,
            } => {
                let half = count / 2;
                let r = self.point[self.point.len() - count.ilog2() as usize];
                let weights = &self.weights;
                let eq = equality.as_slice();
                // Pull the current equality factor e(t) = 1 + r + t out of
                // the sum. Adding the paired weights leaves the suffix weight
                // (including the scale accumulated from previous folds).
                let weight = |i: usize| eq[i] + eq[i + half];
                let [low, quadratic] = (0..half)
                    .into_par_iter()
                    .map(|i| {
                        columns
                            .chi_endpoint_and_quadratic(i, i + half, half, weights)
                            .map(|v| v * weight(i))
                    })
                    .reduce(|| [E::ZERO; 2], |a, b| [a[0] + b[0], a[1] + b[1]]);
                // For the remaining quadratic q, S = (1+r)q(0) + r*q(1).
                // A zero target coordinate or an unclaimed round needs a direct q(1).
                let high = if let Some((sum, inverse)) = sum.zip(r.try_inverse()) {
                    (sum + (E::ONE + r) * low) * inverse
                } else {
                    (0..half)
                        .into_par_iter()
                        .map(|i| {
                            columns.chi_endpoint_and_quadratic(i + half, i, half, weights)[0]
                                * weight(i)
                        })
                        .sum()
                };
                let linear = high + low + quadratic;
                nodes
                    .map(|t| (E::ONE + r + t) * (low + t * (linear + t * quadratic)))
                    .to_vec()
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
