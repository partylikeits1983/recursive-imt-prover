//! Bind the 240 public leaf digests to the sponge boundaries and to the input
//! digits used by the native WHIR folds. The permutation relation opens the same table.
#[path = "support/close_moments.rs"]
mod close_moments;
#[path = "support/nibble_gate.rs"]
mod nibble_gate;
#[path = "support/digit_sumcheck.rs"]
mod sc;
use ark_ff::{AdditiveGroup, Field};
use sha3::{Digest, Keccak256};
use std::{env, fs, path::Path};
use whir::algebra::{eq_weights, fields::Field192 as F};

const ACTIVE: usize = 169;
const PAIRED: usize = 71;
const ROW_BITS: usize = 10;
const WIDTH: usize = 4096;

fn powers(x: F, count: usize) -> Vec<F> {
    (0..count)
        .scan(F::ONE, |p, _| {
            let z = *p;
            *p *= x;
            Some(z)
        })
        .collect()
}

// The ninth checkpoint occupies spare lanes among the first four checkpoints.
fn output_column(nibble: usize) -> usize {
    let lane = nibble / 16;
    ((lane / 7) * 32 + 25 + lane % 7) * 16 + nibble % 16
}

fn main() {
    let args: Vec<_> = env::args().collect();
    assert_eq!(
        args.len(),
        3,
        "native_row_ports witness-directory proof-directory"
    );
    let dir = Path::new(&args[1]);
    let out = Path::new(&args[2]);
    fs::create_dir_all(out).unwrap();
    let digits = fs::read(dir.join("table.bin")).unwrap();
    let root = fs::read(dir.join("cap/root.bin")).unwrap();
    let digests = fs::read(dir.join("digests.bin")).unwrap();
    assert_eq!(
        (digits.len(), root.len(), digests.len()),
        (1 << 22, 32, 240 * 32)
    );
    let seed: [u8; 32] = Keccak256::new()
        .chain_update(b"recursive-imt/native-row-sponge-ports/v1")
        .chain_update(&root)
        .chain_update(Keccak256::digest(&digests))
        .finalize()
        .into();
    let coin = |i| sc::coin(&seed, 0, i);
    let row = powers(coin(0), ACTIVE);
    let slot = powers(coin(1), 3);
    let digit = powers(coin(2), 400);
    let bit = powers(coin(3), 4);
    let digest_row = powers(coin(4), 240);
    let digest_byte = powers(coin(5), 32);
    let digest_mix = coin(6);
    let range_mix = coin(7);
    let range_point: Vec<_> = (0..22).map(|i| sc::coin(&seed, 1, i)).collect();
    let mut rows = vec![[F::ZERO; 6]; 1 << ROW_BITS];
    let mut cols = vec![[F::ZERO; 6]; WIDTH];

    // I + 2*carry - previousOutput - message = padding, bit by bit.
    // Byte 135 of each final rate block has its high bit set.
    let mut sum = F::ZERO;
    let mut digest_index = 0;
    for (r, &weight) in row.iter().enumerate() {
        let paired = r < PAIRED;
        rows[512 + 2 * r][if paired { 3 } else { 4 }] = weight;
        for s in 0..3 {
            let w = weight * slot[s];
            let perm = &mut rows[3 * r + s];
            perm[0] = w;
            if s == 0 || (s == 1 && !paired) {
                perm[1] = -weight * slot[s + 1];
                continue;
            }
            perm[2] = digest_mix * digest_row[digest_index];
            let len = match (paired, s) {
                (true, 1) => 120,
                (true, 2) => 128,
                (false, 2) => 112,
                _ => unreachable!(),
            };
            sum += w * (digit[2 * len] + bit[3] * digit[271]);
            let bytes = &digests[32 * digest_index..32 * (digest_index + 1)];
            sum += perm[2]
                * bytes
                    .iter()
                    .zip(&digest_byte)
                    .map(|(&b, w)| F::from(b) * w)
                    .sum::<F>();
            digest_index += 1;
        }
    }
    assert_eq!(digest_index, 240);
    for (k, &w) in digit.iter().enumerate() {
        cols[k][0] = w;
        cols[output_column(k)][1] = w;
        if k < 64 {
            cols[output_column(k)][2] =
                digest_byte[k / 2] * F::from(if k % 2 == 0 { 1u8 } else { 16 });
        }
    }
    for (column, paired) in [(3, true), (4, false)] {
        let ends = if paired {
            [272, 512, 768]
        } else {
            [272, 544, 768]
        };
        let mut start = 0;
        for (s, end) in ends.into_iter().enumerate() {
            for k in start..end {
                cols[1152 + k][column] = -slot[s] * digit[k - start];
            }
            if s == 1 || (s == 2 && !paired) {
                for k in 0..272 {
                    cols[2048 + (s - 1) * 512 + k][column] = F::from(2u8) * slot[s] * digit[k];
                }
            }
            start = end;
        }
    }
    for (r, w) in rows.iter_mut().zip(eq_weights(&range_point[..ROW_BITS])) {
        r[5] = w;
    }
    for (c, w) in cols.iter_mut().zip(eq_weights(&range_point[ROW_BITS..])) {
        c[5] = range_mix * w;
    }
    let gate = nibble_gate::Gate::with_weights(&bit, &[F::ZERO; 4]);
    let upper = sc::prove(
        &digits,
        (0..16u8)
            .map(|d| nibble_gate::moments(F::from(d)))
            .collect(),
        sc::Factors { rows, cols },
        seed,
        sum,
        0,
        |m| {
            let [b, _, range, d] = gate.values(m);
            [b, b, d, b, b, range]
        },
    );
    let bytes = close_moments::close(&digits, upper, ROW_BITS, out);
    println!(
        "Reduced 507 sponge inputs, 240 digests and 169 fold-row preimages to one 22-variable opening ({bytes} sumcheck bytes)"
    );
}
