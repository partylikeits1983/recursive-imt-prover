//! Evaluate the sixteen initial columns without allocating a full field table.
use ark_ff::{AdditiveGroup, Field};
use rayon::prelude::*;
use whir::algebra::{eq_weights, fields::Field192 as F};
const COLS: usize = 16;

pub fn powers(z: F, n: usize) -> Vec<F> {
    let mut p = F::ONE;
    (0..n)
        .map(|_| {
            let v = p;
            p *= z;
            v
        })
        .collect()
}

fn readings(table: &[u8], outer: &[F], inner: &[F]) -> [F; COLS] {
    let count = outer.len() * inner.len();
    assert_eq!(table.len(), COLS * count);
    // Multiplication by a nibble is a lookup in sixteen multiples of the inner weight.
    let lut: Vec<[F; 16]> = inner
        .iter()
        .map(|&x| {
            let mut s = F::ZERO;
            std::array::from_fn(|_| {
                let v = s;
                s += x;
                v
            })
        })
        .collect();
    (0..outer.len())
        .into_par_iter()
        .fold(
            || [F::ZERO; COLS],
            |mut acc, i| {
                let start = i * inner.len();
                for (c, out) in acc.iter_mut().enumerate() {
                    let cells = &table[c * count + start..c * count + start + inner.len()];
                    let value: F = cells.iter().zip(&lut).map(|(&d, w)| w[d as usize]).sum();
                    *out += value * outer[i];
                }
                acc
            },
        )
        .reduce(
            || [F::ZERO; COLS],
            |a, b| std::array::from_fn(|i| a[i] + b[i]),
        )
}

pub fn multilinear_columns(table: &[u8], point: &[F]) -> [F; COLS] {
    let split = point.len() / 2;
    readings(
        table,
        &eq_weights(&point[..split]),
        &eq_weights(&point[split..]),
    )
}
pub fn univariate_columns(table: &[u8], z: F) -> [F; COLS] {
    let count = table.len() / COLS;
    let inner = 1 << (count.ilog2() / 2);
    readings(
        table,
        &powers(z.pow([inner as u64]), count / inner),
        &powers(z, inner),
    )
}
