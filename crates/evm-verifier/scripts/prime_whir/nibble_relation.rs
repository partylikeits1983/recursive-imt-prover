//! Bind both endpoints of the projected Keccak GKR to the same four-bit table.
//! Arguments are the terminal bundle, cap directory, native rounds.bin, row bits and output directory.
#[path = "support/digits.rs"]
mod digits;
#[path = "support/nibble_gate.rs"]
mod nibble_gate;
#[path = "support/digit_sumcheck.rs"]
mod sc;
#[allow(dead_code)]
#[path = "support/segments.rs"]
mod segments;

use ark_ff::{AdditiveGroup, PrimeField};
#[path = "support/close_moments.rs"]
mod close_moments;
use sc::{coin, wire, words, Factors};
use sha3::{Digest, Keccak256};
use std::{env, fs, path::Path, time::Instant};
use whir::algebra::{eq_weights, fields::Field192 as F};
fn parse(data: &[u8]) -> Vec<F> {
    let v: Vec<_> = data
        .chunks_exact(24)
        .map(F::from_be_bytes_mod_order)
        .collect();
    assert_eq!(wire(&v), data);
    v
}
fn coins(seed: &[u8; 32], family: u8, n: usize) -> Vec<F> {
    (0..n).map(|i| coin(seed, family, i)).collect()
}
struct Terms {
    input: Vec<F>,
    output: Vec<F>,
    bi: Vec<F>,
    bo: Vec<F>,
    range: Vec<F>,
    known: Vec<F>,
    rm: F,
    km: F,
}
impl Terms {
    fn weights(&self, r: usize) -> Factors<4> {
        let last = 21670 >> (16 - r);
        let nrows = 1 << r;
        let ir = eq_weights(&self.input[..r]);
        let or = eq_weights(&self.output[..r]);
        let rr = eq_weights(&self.range[..r]);
        let kr = eq_weights(&self.known[..r]);
        let rows = (0..nrows)
            .map(|i| {
                [
                    ir[i],
                    or[i],
                    rr[i] * self.rm,
                    if i % (nrows / 2) >= last {
                        kr[i] * self.km
                    } else {
                        F::ZERO
                    },
                ]
            })
            .collect();
        let si = eq_weights(&self.input[r..r + 3]);
        let so = eq_weights(&self.output[r..r + 3]);
        let pi = eq_weights(&self.input[r + 3..r + 7]);
        let po = eq_weights(&self.output[r + 3..r + 7]);
        let kl = eq_weights(&self.known[r + 3..r + 8]);
        let kp = eq_weights(&self.known[r + 8..]);
        let rc = eq_weights(&self.range[r..]);
        let mut cols = vec![[F::ZERO; 4]; 4096];
        for (i, w) in cols.iter_mut().enumerate() {
            w[2] = rc[i];
        }
        for s in 0..8 {
            for l in 0..25 {
                for j in 0..16 {
                    cols[16 * digits::slot(s, l) + j][0] = si[s] * self.bi[l] * pi[j];
                    cols[16 * digits::slot(s + 1, l) + j][1] = so[s] * self.bo[l] * po[j];
                    if s == 0 {
                        cols[16 * l + j][3] = kl[l] * kp[j];
                    }
                }
            }
        }
        Factors { rows, cols }
    }
    fn known_value(&self, node: &[u8], r: usize) -> F {
        let msg = [
            b"IMT-AGG-NODE-V2".as_slice(),
            &node[32..64],
            &[32],
            &node[64..96],
            &[32],
        ]
        .concat();
        assert_eq!(&Keccak256::digest(&msg)[..], &node[..32]);
        let mut data = [0u8; 200];
        data[..msg.len()].copy_from_slice(&msg);
        data[msg.len()] = 1;
        data[135] = 128;
        let l = eq_weights(&self.known[r + 3..r + 8]);
        let p = eq_weights(&self.known[r + 8..]);
        let v: F = data
            .iter()
            .enumerate()
            .map(|(i, &d)| {
                l[i / 8] * (p[2 * (i % 8)] * F::from(d & 15) + p[2 * (i % 8) + 1] * F::from(d >> 4))
            })
            .sum();
        self.km * v * eq_weights(&self.known[1..r])[21670 >> (16 - r)]
    }
}
fn main() {
    let args: Vec<_> = env::args().collect();
    assert_eq!(args.len(), 6);
    let bundle = Path::new(&args[1]);
    let cap = Path::new(&args[2]);
    let gkr = &args[3];
    let r: usize = args[4].parse().unwrap();
    assert!(matches!(r, 7 | 9 | 14 | 16));
    let out = Path::new(&args[5]);
    fs::create_dir_all(out).unwrap();
    let n = r + 12;
    let b = r + 9;
    let root = fs::read(cap.join("root.bin")).unwrap();
    let mut node = Vec::new();
    let native = matches!(r, 9 | 14);
    let ctx: [u8; 32] = if native {
        assert!(bundle.is_file());
        Keccak256::new()
            .chain_update(if r == 9 { b"recursive-imt/native-row-keccak/v1".as_slice() } else { b"recursive-imt/native-trace-keccak/v1".as_slice() })
            .chain_update(&root)
            .finalize()
            .into()
    } else {
        node = fs::read(cap.join("node.bin")).unwrap();
        let key = fs::read(cap.join("key.bin")).unwrap();
        assert_eq!(
            hex::encode(&key),
            "494900e0fa468212ed93087501b2ca91a608331d9a12070b6cc05133943e7405"
        );
        Keccak256::new()
            .chain_update(b"recursive-imt/keccak-nibbles192/v1")
            .chain_update(key)
            .chain_update(&node)
            .chain_update([r as u8])
            .chain_update(&root)
            .finalize()
            .into()
    };
    let public = fs::read(format!("{gkr}.public")).unwrap();
    assert_eq!(&public[..32], ctx);
    let output = parse(&public[32..]);
    let input = parse(&fs::read(format!("{gkr}.result")).unwrap());
    assert_eq!(output.len(), b + 25);
    assert_eq!(input.len(), b + 25);
    let opoint = coins(&ctx, 0, b);
    assert_eq!(opoint, output[..b]);
    let seed: [u8; 32] = Keccak256::new()
        .chain_update(ctx)
        .chain_update(words(&output[b..]))
        .chain_update(words(&input))
        .finalize()
        .into();
    let t = Terms {
        input: input[..b].to_vec(),
        output: opoint,
        bi: coins(&seed, 1, 25),
        bo: coins(&seed, 2, 25),
        range: coins(&seed, 3, n),
        known: coins(&seed, 4, n),
        rm: coin(&seed, 5, 0),
        km: if native { F::ZERO } else { coin(&seed, 5, 1) },
    };
    let mut sum = if native {
        F::ZERO
    } else {
        t.known_value(&node, r)
    };
    for j in 0..25 {
        sum += t.bi[j] * input[b + j] + t.bo[j] * output[b + j];
    }
    let table = digits::table(bundle, r, 4);
    let gate = nibble_gate::Gate::new(&t.input[b - 2..], &t.output[b - 2..]);
    let start = Instant::now();
    let upper = sc::prove(
        &table,
        (0..16u8)
            .map(|d| nibble_gate::moments(F::from(d)))
            .collect(),
        t.weights(r),
        seed,
        sum,
        0,
        |m| gate.values(m),
    );
    println!(
        "Checked digit range and both checkpoint endpoints in {:.2?}",
        start.elapsed()
    );
    let size = close_moments::close(&table, upper, r, out);
    if r == 9 {
        // The 512 permutations occupy the low half of the joint 22-variable polynomial.
        let path = out.join("opening-point.bin");
        let mut point = fs::read(&path).unwrap();
        point.splice(32..32, [0u8; 32]);
        fs::write(path, point).unwrap();
    }
    println!(
        "Both sumchecks to one committed scalar, {} bytes in {:.2?}",
        size,
        start.elapsed()
    );
}
