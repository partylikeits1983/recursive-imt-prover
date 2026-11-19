use old_binary_field::{Poly64 as OldF, Poly192 as OldE, TowerLevel as OldTowerLevel};
use p3_air::check_all_constraints;
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use std::sync::Arc;

use super::{END, Gate, LOG_HEIGHT, MIDDLES, PREFIX, Products, WIDTH};
use crate::{
    F,
    air::{Chip, convert},
};

type Row = [OldF; 14];

fn fixture(middle: &[Gate]) -> (Vec<Row>, Vec<u32>) {
    let mut counts = vec![0; 17];
    let rows = PREFIX
        .iter()
        .chain(middle)
        .chain(&END)
        .map(|&(kind, slots)| {
            let mut row = [OldF::from_repr(0); 14];
            for (cell, id) in row.iter_mut().zip(slots) {
                *cell = OldF::from_repr(id as u64);
                if id != 0 {
                    counts[id] += 1;
                }
            }
            row[5] = OldF::from_repr(u64::from(kind == 12));
            row[kind] = OldF::from_repr(1);
            row
        })
        .collect();
    (rows, counts)
}

#[test]
fn contraction_preserves_the_cubic_product_and_all_external_uses() {
    let mut trace = F::zero_vec(WIDTH << LOG_HEIGHT);
    let mut products = Vec::new();
    for (i, middle) in MIDDLES.into_iter().enumerate() {
        let (gates, counts) = fixture(middle);
        let mut removed = vec![false; gates.len()];
        let mut uses = vec![0u32; counts.len()];
        let shard = Products::extract(&gates, &counts, &[64; 17], &mut removed, &mut uses).unwrap();
        assert!(removed.iter().all(|&v| v));
        assert_eq!(shard.rows, [[1, 2, 3, 4, 5, 6, 7, 8, 9]]);
        for (label, (&old, &eliminated)) in counts.iter().zip(&uses).enumerate() {
            assert_eq!(old - eliminated, u32::from((1..=9).contains(&label)));
        }
        let mut v = [OldF::from_repr(0); 17];
        for (j, x) in v[1..7].iter_mut().enumerate() {
            *x = OldF::from_repr(
                0x9e3779b97f4a7c15u64
                    .wrapping_mul((i * 6 + j + 1) as u64)
                    .rotate_left(j as u32),
            );
        }
        for row in gates {
            let [a, b, c, acc, out] = std::array::from_fn(|k| row[k].to_repr() as usize);
            v[out] = if row[8].to_repr() == 1 {
                v[a] * v[b]
            } else if row[10].to_repr() == 1 {
                v[a] * v[b] + v[c]
            } else if row[11].to_repr() == 1 {
                v[acc] * v[b] + v[c] - v[a]
            } else {
                v[a] + v[c]
            };
        }
        let product =
            OldE::new(v[1..4].try_into().unwrap()) * OldE::new(v[4..7].try_into().unwrap());
        assert_eq!(product.coefficients().as_slice(), &v[7..10]);
        trace[WIDTH * i..WIDTH * (i + 1)]
            .copy_from_slice(&<[OldF; 9]>::try_from(&v[1..10]).unwrap().map(convert));
        products.extend(shard.rows);
    }
    let air = Chip::products(Arc::new(Products { rows: products }));
    let mut trace = RowMajorMatrix::new(trace, WIDTH);
    assert!(check_all_constraints(&air, &trace, &[], Some(1)).is_ok());
    for output in 6..9 {
        trace.values[output] += F::ONE;
        assert!(!check_all_constraints(&air, &trace, &[], Some(1)).is_ok());
        trace.values[output] += F::ONE;
    }
}

#[test]
fn nonisolated_or_different_gates_remain_in_the_original_air() {
    for middle in MIDDLES {
        for mutation in 0..6 {
            let (mut gates, mut counts) = fixture(middle);
            let mut widths = [64; 17];
            let mut removed = vec![false; gates.len()];
            match mutation {
                0 => counts[11] += 1,
                1 => gates[2][0] = OldF::from_repr(1),
                2 => widths[16] = 16,
                3 => removed[3] = true,
                4 => gates[1][12] = OldF::from_repr(1),
                _ => gates[4][5] += OldF::from_repr(1),
            }
            let original = removed.clone();
            let mut uses = [0; 17];
            let shard =
                Products::extract(&gates, &counts, &widths, &mut removed, &mut uses).unwrap();
            assert!(shard.rows.is_empty());
            assert_eq!(removed, original);
            assert_eq!(uses, [0; 17]);
        }
    }
}
