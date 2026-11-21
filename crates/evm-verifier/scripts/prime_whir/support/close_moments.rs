use super::{nibble_gate, sc};
use sc::{wire, words, Factors};
use sha3::{Digest, Keccak256};
use std::{fs, path::Path};
use whir::algebra::{eq_weights, fields::Field192 as F};

pub fn close(table: &[u8], upper: sc::Outcome<3>, r: usize, out: &Path) -> usize {
    let seed: [u8; 32] = Keccak256::new()
        .chain_update(upper.seed)
        .chain_update(wire(&upper.values))
        .finalize()
        .into();
    let beta: [F; 3] = std::array::from_fn(|i| sc::coin(&seed, 7, i));
    let sum = upper.values.iter().zip(&beta).map(|(v, b)| *v * b).sum();
    let weights = Factors {
        rows: eq_weights(&upper.point[..r])
            .into_iter()
            .map(|w| [w])
            .collect(),
        cols: eq_weights(&upper.point[r..])
            .into_iter()
            .map(|w| [w])
            .collect(),
    };
    let lower = sc::prove(
        table,
        (0..16u8).map(|d| [F::from(d)]).collect(),
        weights,
        seed,
        sum,
        1,
        |[d]| {
            [nibble_gate::moments(d)
                .into_iter()
                .zip(&beta)
                .map(|(v, b)| v * b)
                .sum()]
        },
    );
    let mut proof = upper.scalars;
    proof.extend(upper.values);
    proof.extend(lower.scalars);
    proof.extend(lower.values);
    let size = proof.len() * 24;
    let context = Keccak256::new()
        .chain_update(b"recursive-imt/nibble-mle/v1")
        .chain_update(lower.seed)
        .finalize();
    let mut public = context.to_vec();
    public.extend(words(&lower.point));
    fs::write(out.join("digits.bin"), wire(&proof)).unwrap();
    fs::write(out.join("opening-point.bin"), public).unwrap();
    fs::write(out.join("digit-value.bin"), words(&lower.values)).unwrap();
    size
}
