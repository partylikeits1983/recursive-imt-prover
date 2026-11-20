//! Authenticate the 47 coefficients of a packed chi product and its random evaluation.
use super::maps;
use crate::checkpoint_keccak::recursive::{connect, observe, sample};
use anyhow::{Result, ensure};
use old_binary_field::Poly64 as CF;
use p3_circuit::{CircuitBuilder, ops::NativePoly192Target as T};
use p3_recursion::BinaryTower128Challenger as Ch;

type Builder = CircuitBuilder<CF>;

pub(in crate::checkpoint_keccak) fn sum(b: &mut Builder, values: impl IntoIterator<Item = T>) -> T {
    values
        .into_iter()
        .fold(b.native_poly192_constant([0; 3]), |a, v| {
            b.native_poly192_add(&a, &v)
        })
}

pub(in crate::checkpoint_keccak) fn dot(b: &mut Builder, a: &[T], c: &[T]) -> T {
    assert_eq!(a.len(), c.len());
    let mut total = b.native_poly192_constant([0; 3]);
    for (a, c) in a.iter().zip(c) {
        let v = b.native_poly192_mul(a, c);
        total = b.native_poly192_add(&total, &v);
    }
    total
}

pub(in crate::checkpoint_keccak) fn product(
    b: &mut Builder,
    ch: &mut Ch,
    coeff: &[T],
    lanes: &[T],
    expected: &T,
) -> Result<(T, Vec<T>)> {
    ensure!(
        coeff.len() == 47 && lanes.len() == 16,
        "incorrect packed product shape"
    );
    let projected = maps::PROJECT.map(|mask| {
        sum(
            b,
            coeff
                .iter()
                .enumerate()
                .filter(|(k, _)| mask >> k & 1 != 0)
                .map(|(_, v)| v.clone()),
        )
    });
    let projected = dot(b, lanes, &projected);
    connect(b, &projected, expected);
    for c in coeff {
        observe(b, ch, c)?;
    }
    let t = sample(b, ch)?;
    let mut powers = vec![b.native_poly192_constant([1, 0, 0])];
    for i in 1..24 {
        powers.push(b.native_poly192_mul(&powers[i - 1], &t));
    }
    let lanes = maps::EMBED
        .iter()
        .map(|mask| {
            sum(
                b,
                powers
                    .iter()
                    .enumerate()
                    .filter(|(k, _)| mask >> k & 1 != 0)
                    .map(|(_, v)| v.clone()),
            )
        })
        .collect();
    let initial = coeff
        .iter()
        .rev()
        .fold(b.native_poly192_constant([0; 3]), |acc, c| {
            let prod = b.native_poly192_mul(&acc, &t);
            b.native_poly192_add(&prod, c)
        });
    Ok((initial, lanes))
}
