//! One WHIR opening for both sides of the Keccak reduction and the digit range check.
#[path = "support/digits.rs"]
mod digits;
#[path = "support/node.rs"]
mod node;
use digits::slot;
#[allow(dead_code)]
#[path = "support/segments.rs"]
mod segments;

use ark_ff::{AdditiveGroup, BigInteger, Field, PrimeField};
use rayon::prelude::*;
use sha3::{Digest, Keccak256};
use spongefish::instantiations::Hash;
use std::{env, fs, path::Path, time::Instant};
use whir::{
    algebra::{embedding::Identity, fields::Field256 as F, linear_form::MultilinearExtension},
    bits::Bits,
    buffer::{Buffer, BufferMath},
    hash::KECCAK,
    parameters::ProtocolParameters,
    protocols::{
        irs_commit::Evaluations,
        params::DecodingRegime,
        whir::{Config, Witness},
    },
    transcript::{codecs::Empty, DomainSeparator, ProverState, VerifierMessage, VerifierState},
};

const ROW_BITS: usize = 9;
const ROWS: usize = 1 << ROW_BITS;
const WIDTH: usize = 8 * 32 * 32;
const N: usize = ROW_BITS + 13;
const B: usize = ROW_BITS + 9;
const LAST: usize = 21670 >> (16 - ROW_BITS);

fn wire(xs: &[F]) -> Vec<u8> {
    xs.iter()
        .flat_map(|x| x.into_bigint().to_bytes_be())
        .collect()
}
fn scalars(raw: &[u8]) -> Vec<F> {
    let out: Vec<_> = raw
        .chunks_exact(32)
        .map(F::from_be_bytes_mod_order)
        .collect();
    assert_eq!(wire(&out), raw);
    out
}
fn coin(seed: &[u8], family: u8, i: usize) -> F {
    let h = Keccak256::new()
        .chain_update(b"recursive-imt/digit-coin/v1")
        .chain_update(seed)
        .chain_update([family, i as u8]);
    F::from_be_bytes_mod_order(
        &[
            h.clone().chain_update([0]).finalize(),
            h.chain_update([1]).finalize(),
        ]
        .concat(),
    )
}
fn coins(seed: &[u8], family: u8, n: usize) -> Vec<F> {
    (0..n).map(|i| coin(seed, family, i)).collect()
}
fn eq(x: &[F]) -> Vec<F> {
    let mut a = vec![F::ONE];
    for &r in x {
        a = a
            .into_iter()
            .flat_map(|v| {
                let h = v * r;
                [v - h, h]
            })
            .collect();
    }
    a
}
fn output_values(table: &[u8], point: &[F]) -> Vec<F> {
    let rows = eq(&point[..ROW_BITS]);
    let seg = eq(&point[ROW_BITS..ROW_BITS + 3]);
    let pair = eq(&point[ROW_BITS + 3..B - 1]);
    let bit = point[B - 1];
    let bits = [F::ZERO, F::ONE - bit, bit, F::ONE];
    (0..25usize)
        .into_par_iter()
        .map(|lane| {
            let mut sum = F::ZERO;
            for (i, row) in table.chunks_exact(WIDTH).enumerate() {
                for (s, &w) in seg.iter().enumerate() {
                    let col = 32 * slot(s + 1, lane);
                    let v: F = pair
                        .iter()
                        .zip(&row[col..col + 32])
                        .map(|(w, &d)| *w * bits[d as usize])
                        .sum();
                    sum += rows[i] * w * v;
                }
            }
            sum
        })
        .collect()
}
struct Terms {
    input: Vec<F>,
    output: Vec<F>,
    range: Vec<F>,
    known: Vec<F>,
    input_lanes: Vec<F>,
    output_lanes: Vec<F>,
    range_mix: F,
    known_mix: F,
}
impl Terms {
    fn new(seed: &[u8], input: &[F], output: &[F]) -> Self {
        Self {
            input: input.to_vec(),
            output: output.to_vec(),
            range: coins(seed, 3, N),
            known: coins(seed, 4, N),
            input_lanes: coins(seed, 1, 25),
            output_lanes: coins(seed, 2, 25),
            range_mix: coin(seed, 5, 0),
            known_mix: coin(seed, 5, 1),
        }
    }
    fn expected_known(&self, node: &[u8]) -> F {
        let x = &self.known;
        let e = eq(&x[1..ROW_BITS])[LAST];
        let lanes = eq(&x[ROW_BITS + 3..ROW_BITS + 8]);
        let pairs = eq(&x[ROW_BITS + 8..]);
        let mut block = [0u8; 200];
        let msg = [
            b"IMT-AGG-NODE-V2".as_slice(),
            &node[32..64],
            &[32],
            &node[64..],
            &[32],
        ]
        .concat();
        assert_eq!(&Keccak256::digest(&msg)[..], &node[..32]);
        block[..msg.len()].copy_from_slice(&msg);
        block[msg.len()] = 1;
        block[135] = 128;
        let mut v = F::ZERO;
        for l in 0..25 {
            for j in 0..32 {
                v += lanes[l] * pairs[j] * F::from((block[8 * l + j / 4] >> (2 * (j % 4))) & 3);
            }
        }
        e * self.known_mix * v
    }
    fn terms(&self, table: &[u8]) -> Vec<Cell> {
        let ir = eq(&self.input[..ROW_BITS]);
        let or = eq(&self.output[..ROW_BITS]);
        let rr = eq(&self.range[..ROW_BITS]);
        let kr = eq(&self.known[..ROW_BITS]);
        let is = eq(&self.input[ROW_BITS..ROW_BITS + 3]);
        let os = eq(&self.output[ROW_BITS..ROW_BITS + 3]);
        let ip = eq(&self.input[ROW_BITS + 3..B - 1]);
        let op = eq(&self.output[ROW_BITS + 3..B - 1]);
        let kl = eq(&self.known[ROW_BITS + 3..ROW_BITS + 8]);
        let kp = eq(&self.known[ROW_BITS + 8..]);
        let rc = eq(&self.range[ROW_BITS..]);
        let mut ic = vec![F::ZERO; WIDTH];
        let mut oc = ic.clone();
        let mut kc = ic.clone();
        for s in 0..8 {
            for l in 0..25 {
                for j in 0..32 {
                    ic[slot(s, l) * 32 + j] = is[s] * self.input_lanes[l] * ip[j];
                    oc[slot(s + 1, l) * 32 + j] = os[s] * self.output_lanes[l] * op[j];
                    if s == 0 {
                        kc[32 * l + j] = kl[l] * kp[j] * self.known_mix;
                    }
                }
            }
        }
        // H_r(d) = (r/2)*d + (1-3r/2)*low_bit(d), for d in {0,1,2,3}.
        let half = F::from(2u8).inverse().unwrap();
        let ih = self.input[B - 1] * half;
        let oh = self.output[B - 1] * half;
        let il = F::ONE - F::from(3u8) * ih;
        let ol = F::ONE - F::from(3u8) * oh;
        table
            .par_chunks_exact(WIDTH)
            .enumerate()
            .flat_map_iter(|(i, row)| {
                let k = if i % (ROWS / 2) >= LAST {
                    kr[i]
                } else {
                    F::ZERO
                };
                let (ic, oc, kc, rc) = (&ic, &oc, &kc, &rc);
                let (ir, or, rr) = (ir[i], or[i], rr[i] * self.range_mix);
                row.iter().copied().enumerate().map(move |(j, d)| {
                    let a = ir * ic[j];
                    let b = or * oc[j];
                    Cell {
                        d: F::from(d),
                        linear: a * ih + b * oh + k * kc[j],
                        low: a * il + b * ol,
                        range: rr * rc[j],
                    }
                })
            })
            .collect()
    }
}
#[derive(Clone, Copy)]
struct Cell {
    d: F,
    linear: F,
    low: F,
    range: F,
}
impl Cell {
    fn diff(self, a: Self) -> Self {
        Self {
            d: self.d - a.d,
            linear: self.linear - a.linear,
            low: self.low - a.low,
            range: self.range - a.range,
        }
    }
    fn step(&mut self, b: Self) {
        self.d += b.d;
        self.linear += b.linear;
        self.low += b.low;
        self.range += b.range;
    }
    fn fold(self, b: Self, x: F) -> Self {
        let t = b.diff(self);
        Self {
            d: self.d + x * t.d,
            linear: self.linear + x * t.linear,
            low: self.low + x * t.low,
            range: self.range + x * t.range,
        }
    }
    fn value(self, third: F) -> F {
        let d = self.d;
        let f = d * (d - F::ONE);
        // low_bit(d)=d-d(d-1)+(2/3)d(d-1)(d-2).
        let cube = f * (d - F::from(2u8));
        let low = d - f + (third + third) * cube;
        self.linear * d + self.low * low + self.range * cube * (d - F::from(3u8))
    }
}
fn interpolation(values: &[F; 6], x: F) -> F {
    let mut v = F::ZERO;
    for (i, &y) in values.iter().enumerate() {
        let mut num = F::ONE;
        let mut den = F::ONE;
        for j in 0..6 {
            if i != j {
                num *= x - F::from(j as u64);
                den *= F::from(i as u64) - F::from(j as u64);
            }
        }
        v += y * num * den.inverse().unwrap();
    }
    v
}
fn sumcheck(mut cells: Vec<Cell>, mut sum: F, mut seed: [u8; 32]) -> (Vec<F>, Vec<F>, F, [u8; 32]) {
    let third = F::from(3u8).inverse().unwrap();
    let mut transcript = Vec::new();
    let mut point = Vec::new();
    for k in 0..N {
        let mid = cells.len() / 2;
        let (lo, hi) = cells.split_at_mut(mid);
        let vals = lo
            .par_iter()
            .zip(hi.par_iter())
            .fold(
                || [F::ZERO; 6],
                |mut acc, (&a, &b)| {
                    let step = b.diff(a);
                    let mut line = a;
                    for x in &mut acc {
                        *x += line.value(third);
                        line.step(step);
                    }
                    acc
                },
            )
            .reduce(|| [F::ZERO; 6], |a, b| std::array::from_fn(|j| a[j] + b[j]));
        assert_eq!(vals[0] + vals[1], sum, "digit equation failed at round {k}");
        let msg = [vals[0], vals[2], vals[3], vals[4], vals[5]];
        seed = Keccak256::new()
            .chain_update(seed)
            .chain_update([k as u8])
            .chain_update(wire(&msg))
            .finalize()
            .into();
        let r = coin(&seed, 6, k);
        point.push(r);
        transcript.extend(msg);
        sum = interpolation(&vals, r);
        lo.par_iter_mut()
            .zip(hi.par_iter())
            .for_each(|(a, &b)| *a = a.fold(b, r));
        cells.truncate(mid);
    }
    assert_eq!(cells[0].value(third), sum);
    (transcript, point, cells[0].d, seed)
}
fn main() {
    let args: Vec<_> = env::args().collect();
    assert_eq!(args.len(), 4);
    let bundle = Path::new(&args[1]);
    let out = Path::new(&args[2]);
    fs::create_dir_all(out).unwrap();
    let mode = &args[3];
    assert!(mode == "prepare" || mode == "close");
    let digits = digits::table(bundle, ROW_BITS, 2);
    let cfg = Config::<Identity<F>>::new(
        1 << N,
        &ProtocolParameters {
            security_level: 135,
            pow_bits: 16,
            initial_folding_factor: 3,
            folding_factor: 3,
            decoding_regime: DecodingRegime::Johnson,
            starting_log_inv_rate: 5,
            batch_size: 1,
            hash_id: KECCAK,
        },
    );
    assert!(cfg.check_max_pow_bits(Bits::new(16.0)) && cfg.security_level(1, 1) + 1e-8 >= 135.0);
    let vector = Buffer::from(
        digits
            .iter()
            .copied()
            .map(F::from)
            .collect::<Vec<_>>()
            .as_slice(),
    );
    let pre = DomainSeparator::protocol(&cfg)
        .session(&"recursive-imt/precommit/v1")
        .instance(&Empty);
    let mut prestate = ProverState::new(&pre, Hash::<Keccak256>::default());
    let irs = cfg.initial_committer.commit(&mut prestate, &[&vector]);
    let root: [u8; 32] = prestate.proof().narg_string.try_into().unwrap();
    let (node, key) = node::node_statement(bundle);
    let ctx: [u8; 32] = Keccak256::new()
        .chain_update(b"recursive-imt/keccak-digits/v1")
        .chain_update(key)
        .chain_update(&node)
        .chain_update([ROW_BITS as u8])
        .chain_update(root)
        .finalize()
        .into();
    let opoint = coins(&ctx, 0, B);
    let outputs = output_values(&digits, &opoint);
    if mode == "prepare" {
        for (name, bytes) in [
            ("node", node),
            ("root", root.to_vec()),
            ("digit-instance", ctx.to_vec()),
            ("output-result", wire(&[opoint, outputs].concat())),
        ] {
            fs::write(out.join(format!("{name}.bin")), bytes).unwrap();
        }
        return;
    }
    assert_eq!(fs::read(out.join("root.bin")).unwrap(), root);
    let raw = fs::read(out.join("rounds.bin.result")).unwrap();
    let input = scalars(&raw);
    assert_eq!(input.len(), B + 25);
    let seed: [u8; 32] = Keccak256::new()
        .chain_update(ctx)
        .chain_update(wire(&outputs))
        .chain_update(&raw)
        .finalize()
        .into();
    let terms = Terms::new(&seed, &input[..B], &opoint);
    let mut sum = terms.expected_known(&node);
    for l in 0..25 {
        sum += terms.input_lanes[l] * input[B + l] + terms.output_lanes[l] * outputs[l];
    }
    let start = Instant::now();
    let (mut proof, point, value, final_seed) = sumcheck(terms.terms(&digits), sum, seed);
    proof.push(value);
    println!(
        "range and both bit evaluations {:.2?}, {} field words",
        start.elapsed(),
        proof.len()
    );
    fs::write(out.join("digits.bin"), wire(&proof)).unwrap();
    let closing = Keccak256::new()
        .chain_update(b"recursive-imt/keccak-digit-opening/v1")
        .chain_update(final_seed)
        .finalize();
    let instance: [u8; 32] = Keccak256::new()
        .chain_update(closing)
        .chain_update(wire(&point))
        .chain_update(wire(&[value]))
        .finalize()
        .into();
    let domain = DomainSeparator::protocol(&cfg)
        .session(&"recursive-imt/prime-whir-opening/v1")
        .instance(&instance);
    let mut p = ProverState::new(&domain, Hash::<Keccak256>::default());
    p.prover_message(&whir::hash::Hash(root));
    let zs: Vec<F> = p.verifier_message_vec(cfg.initial_out_domain_samples);
    let oods: Vec<_> = zs
        .iter()
        .map(|z| vector.mixed_univariate_evaluate(cfg.embedding(), *z))
        .collect();
    p.prover_messages(&oods);
    let w = Witness {
        irs,
        out_of_domain: Evaluations {
            points: zs,
            matrix: Buffer::from(oods.as_slice()),
        },
    };
    let form = MultilinearExtension::new(point);
    let _ = cfg.prove(
        &mut p,
        &[&vector],
        vec![&w],
        vec![Box::new(form.clone())],
        Buffer::from(&[value][..]),
    );
    let result = p.proof();
    let mut v = VerifierState::new(&domain, &result, Hash::<Keccak256>::default());
    let c = cfg.receive_commitment(&mut v).unwrap();
    cfg.verify(&mut v, &[&c], &[value])
        .unwrap()
        .verify([&form as _])
        .unwrap();
    v.check_eof().unwrap();
    fs::write(out.join("proof.bin"), result.narg_string).unwrap();
    fs::write(out.join("hints.bin"), result.hints).unwrap();
}
