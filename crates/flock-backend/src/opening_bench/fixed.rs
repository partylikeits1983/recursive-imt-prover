//! Profile two exact ways to evaluate the fixed wiring at a verifier challenge.
use p3_air::BaseAir;
use p3_matrix::dense::RowMajorMatrix;
use serde::Serialize;
use std::collections::{HashMap, HashSet};

use crate::{F, Prepared};

#[derive(Default, Serialize)]
pub struct FixedColumnProfile {
    pub columns: usize,
    pub cells: usize,
    pub constant_columns: usize,
    pub affine_columns: usize,
    pub remaining_nonzero_entries: usize,
    pub remaining_value_groups: usize,
    pub remaining_nonempty_blocks: usize,
    pub shared_interpolation_nodes: usize,
    pub shared_word_scales: usize,
    pub shared_extension_products: usize,
}

// In characteristic two a whole subtable can be translated by XORing a constant.
// Store the value at index zero separately and intern its remaining polynomial.
#[derive(Clone, Copy)]
struct Subtable {
    constant: u64,
    residual: usize,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct Interpolation {
    left: usize,
    right: usize,
    delta: u64,
}

struct SharedColumns {
    levels: Vec<HashMap<Interpolation, usize>>,
    nodes: usize,
}

impl SharedColumns {
    fn new(height: usize) -> Self {
        assert!(height.is_power_of_two());
        Self {
            levels: (0..height.ilog2()).map(|_| HashMap::new()).collect(),
            nodes: 0,
        }
    }

    fn add(&mut self, column: &[u64], work: &mut Vec<Subtable>) -> Subtable {
        work.clear();
        work.extend(column.iter().map(|&constant| Subtable {
            constant,
            residual: 0,
        }));
        for level in &mut self.levels {
            let pairs = work.len() / 2;
            for i in 0..pairs {
                let (left, right) = (work[2 * i], work[2 * i + 1]);
                let delta = left.constant ^ right.constant;
                // left + x * (left + right + delta), after removing the low constant.
                let residual = if left.residual == right.residual && delta == 0 {
                    left.residual
                } else {
                    *level
                        .entry(Interpolation {
                            left: left.residual,
                            right: right.residual,
                            delta,
                        })
                        .or_insert_with(|| {
                            self.nodes += 1;
                            self.nodes
                        })
                };
                work[i] = Subtable {
                    constant: left.constant,
                    residual,
                };
            }
            work.truncate(pairs);
        }
        work[0]
    }

    fn count_products(self, profile: &mut FixedColumnProfile) {
        profile.shared_interpolation_nodes += self.nodes;
        for level in self.levels {
            let mut words = HashSet::new();
            let mut products = HashSet::new();
            for node in level.into_keys() {
                if node.left == node.right {
                    if node.delta > 1 {
                        words.insert(node.delta);
                    }
                } else {
                    // Exchanging the branches preserves the challenge product.
                    products.insert((
                        node.left.min(node.right),
                        node.left.max(node.right),
                        node.delta,
                    ));
                }
            }
            profile.shared_word_scales += words.len();
            profile.shared_extension_products += products.len();
        }
    }
}

impl FixedColumnProfile {
    fn add(&mut self, table: &RowMajorMatrix<F>) {
        let height = table.values.len() / table.width;
        let mut column = Vec::with_capacity(height);
        let mut groups = HashSet::new();
        let mut shared = SharedColumns::new(height);
        let mut work = Vec::with_capacity(height);
        for i in 0..table.width {
            self.columns += 1;
            self.cells += height;
            column.clear();
            column.extend(
                table
                    .values
                    .chunks_exact(table.width)
                    .map(|r| r[i].to_bits()),
            );
            let first = column[0];
            if column.iter().all(|&value| value == first) {
                self.constant_columns += 1;
                continue;
            }
            shared.add(&column, &mut work);
            // Crossing each coordinate changes an affine Boolean function by a fixed word.
            if (0..height.ilog2()).all(|bit| {
                let stride = 1 << bit;
                let delta = first ^ column[stride];
                column.chunks_exact(stride * 2).all(|block| {
                    block[..stride]
                        .iter()
                        .zip(&block[stride..])
                        .all(|(&lo, &hi)| lo ^ hi == delta)
                })
            }) {
                self.affine_columns += 1;
                continue;
            }
            // One scaling per distinct nonzero word per 2^14-row block.
            for block in column.chunks(1 << 14) {
                groups.clear();
                for &value in block {
                    if value != 0 {
                        self.remaining_nonzero_entries += 1;
                        groups.insert(value);
                    }
                }
                self.remaining_value_groups += groups.len();
                self.remaining_nonempty_blocks += usize::from(!groups.is_empty());
            }
        }
        shared.count_products(self);
    }
}

impl Prepared {
    pub fn fixed_column_profile(&self) -> FixedColumnProfile {
        let mut profile = FixedColumnProfile::default();
        for air in &self.airs {
            if let Some(table) = air.preprocessed_trace() {
                profile.add(&table);
            }
        }
        profile
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_binary_field::Poly192;
    use p3_field::PrimeCharacteristicRing;

    #[test]
    fn separates_affine_words_from_nonlinear_fixed_wiring() {
        let values = (0..8u64)
            .flat_map(|i| [9, 7 ^ i, (i & 1) & (i >> 1)].map(F::new))
            .collect();
        let mut profile = FixedColumnProfile::default();
        profile.add(&RowMajorMatrix::new(values, 3));
        assert_eq!(profile.cells, 24);
        assert_eq!(profile.constant_columns, 1);
        assert_eq!(profile.affine_columns, 1);
        assert_eq!(profile.remaining_nonzero_entries, 2);
        assert_eq!(profile.remaining_value_groups, 1);
        assert_eq!(profile.remaining_nonempty_blocks, 1);
    }

    #[test]
    fn shared_interpolation_preserves_each_columns_extension_evaluation() {
        let columns = [[1, 0, 4, 15, 0, 1, 10, 7], [11, 10, 14, 5, 2, 3, 8, 5]];
        let point = [2u64, 7, 19].map(|i| Poly192::new([F::new(i), F::new(i + 1), F::new(i + 2)]));
        let mut shared = SharedColumns::new(8);
        let mut work = Vec::new();
        let roots = columns.map(|column| shared.add(&column, &mut work));
        let mut values = vec![Poly192::ZERO; shared.nodes + 1];
        for (level, x) in shared.levels.iter().zip(point) {
            for (node, &id) in level {
                let low = values[node.left];
                values[id] =
                    low + x * (low + values[node.right] + Poly192::from(F::new(node.delta)));
            }
        }
        for (root, column) in roots.into_iter().zip(columns) {
            let mut dense = column.map(|v| Poly192::from(F::new(v))).to_vec();
            for x in point {
                dense = dense
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|v| v[0] + x * (v[0] + v[1]))
                    .collect();
            }
            assert_eq!(
                values[root.residual] + Poly192::from(F::new(root.constant)),
                dense[0]
            );
        }
        let mut profile = FixedColumnProfile::default();
        shared.count_products(&mut profile);
        assert!(profile.shared_extension_products > 0);
        assert!(profile.shared_interpolation_nodes < 2 * 7);
    }
}
