//! Initial four WHIR folds without allocating the 2^28-entry field covector.
//! The initial evaluation forms and the out-of-domain form factor across the first sixteen columns and the row suffix.
use ark_ff::{AdditiveGroup, Field};
use rayon::prelude::*;
use sha3::Keccak256;
use spongefish::instantiations::Hash as Sponge;
use whir::{
    algebra::{eq_weights, fields::Field192 as F},
    protocols::sumcheck,
    transcript::{ProverState, VerifierMessage},
};
const COLS: usize = 16;

use super::digit_columns::{powers, univariate_columns};
pub fn value(cols: &[F; COLS], point: &[F]) -> F {
    cols.iter()
        .zip(eq_weights(point))
        .map(|(v, w)| *v * w)
        .sum()
}
pub struct Folded {
    pub challenges: Vec<F>,
    pub vector: Vec<F>,
    pub weight: Vec<F>,
    pub sum: F,
}

// Fold a sixteen-element pair under the same challenge, in big-endian bit order.
fn fold_pair(left: &mut Vec<F>, right: &mut Vec<F>, r: F) {
    for values in [left, right] {
        let half = values.len() / 2;
        for j in 0..half {
            let low = values[j];
            values[j] = low + (values[j + half] - low) * r;
        }
        values.truncate(half);
    }
}
fn coefficients(left: &[F], right: &[F]) -> (F, F) {
    let n = left.len() / 2;
    let mut c0 = F::ZERO;
    let mut c2 = F::ZERO;
    for j in 0..n {
        c0 += left[j] * right[j];
        c2 += (left[j + n] - left[j]) * (right[j + n] - right[j]);
    }
    (c0, c2)
}

pub fn prove(
    p: &mut ProverState<Sponge<Keccak256>>,
    table: &[u8],
    points: &[Vec<F>],
    columns: &[[F; COLS]],
    cfg: &sumcheck::Config<F>,
) -> Folded {
    assert_eq!(cfg.num_rounds(), 4);
    assert!((1..=3).contains(&points.len()) && points.len() == columns.len());
    let n = points[0].len();
    let split = 4 + (n - 4) / 2;
    let inner = 1 << (n - split);
    let count = table.len() / COLS;
    let z: F = p.verifier_message();
    let ocols = univariate_columns(table, z);
    let mut ow = powers(z.pow([count as u64]), COLS);
    let ood: F = ocols.iter().zip(&ow).map(|(v, w)| *v * w).sum();
    p.prover_message(&ood);
    let mix: F = p.verifier_message();
    let mut terms = Vec::with_capacity(points.len() + 1);
    let mut coeff = F::ONE;
    let mut sum = F::ZERO;
    for (point, col) in points.iter().zip(columns) {
        let mut ew = eq_weights(&point[..4]);
        ew.iter_mut().for_each(|w| *w *= coeff);
        sum += coeff * value(col, &point[..4]);
        terms.push((col.to_vec(), ew));
        coeff *= mix;
    }
    ow.iter_mut().for_each(|w| *w *= coeff);
    sum += coeff * ood;
    terms.push((ocols.to_vec(), ow));
    let mut challenges = Vec::with_capacity(4);
    for _ in 0..4 {
        let (c0, c2) = terms
            .iter()
            .map(|(v, w)| coefficients(v, w))
            .fold((F::ZERO, F::ZERO), |(a, b), (c, d)| (a + c, b + d));
        p.prover_messages(&[c0, c2]);
        cfg.round_pow().prove(p);
        let r: F = p.verifier_message();
        let c1 = sum - c0 - c0 - c2;
        sum = c0 + r * (c1 + r * c2);
        for (v, w) in &mut terms {
            fold_pair(v, w, r);
        }
        challenges.push(r);
    }
    let cw = eq_weights(&challenges);
    let lut: Vec<[F; 16]> = cw
        .iter()
        .map(|&x| std::array::from_fn(|d| x * F::from(d as u8)))
        .collect();
    let vector: Vec<_> = (0..count)
        .into_par_iter()
        .map(|j| {
            (0..COLS)
                .map(|i| lut[i][table[i * count + j] as usize])
                .sum::<F>()
        })
        .collect();
    let mut suffixes = points
        .iter()
        .zip(&terms)
        .map(|(point, (_, w))| {
            (
                w[0],
                eq_weights(&point[4..split]),
                eq_weights(&point[split..]),
            )
        })
        .collect::<Vec<_>>();
    suffixes.push((
        terms.last().unwrap().1[0],
        powers(z.pow([inner as u64]), count / inner),
        powers(z, inner),
    ));
    let weight: Vec<_> = (0..count)
        .into_par_iter()
        .map(|i| {
            suffixes
                .iter()
                .map(|(w, high, low)| *w * high[i / inner] * low[i % inner])
                .sum()
        })
        .collect();
    assert_eq!(
        sum,
        vector.par_iter().zip(&weight).map(|(a, b)| *a * b).sum()
    );
    Folded {
        challenges,
        vector,
        weight,
        sum,
    }
}
