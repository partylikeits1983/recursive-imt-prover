//! Prove all five groups of native binary WHIR row folds over the 192-bit prime.
#[path = "support/close_moments.rs"]
mod close_moments;
#[path = "support/nibble_gate.rs"]
mod nibble_gate;
#[path = "support/digit_sumcheck.rs"]
mod sc;
use ark_ff::{AdditiveGroup, Field, PrimeField};
use sha3::{Digest, Keccak256};
use spongefish::instantiations::Hash;
use std::{env, fs, path::Path, time::Instant};
use whir::{
    algebra::{
        embedding::Identity,
        eq_weights,
        fields::Field192 as F,
        linear_form::{Evaluate, MultilinearExtension},
    },
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
const STAGES: [usize; 5] = [71, 35, 26, 20, 17];
fn powers(x: F, n: usize) -> Vec<F> {
    (0..n)
        .scan(F::ONE, |a, _| {
            let v = *a;
            *a *= x;
            Some(v)
        })
        .collect()
}
fn word(b: &[u8]) -> u64 {
    u64::from_le_bytes(b.try_into().unwrap())
}
fn fp(x: u64, p: &[F]) -> F {
    p.iter()
        .enumerate()
        .filter_map(|(i, &v)| ((x >> i) & 1 != 0).then_some(v))
        .sum()
}
fn main() {
    let arg = env::args().nth(1).unwrap();
    let out = Path::new(&arg);
    let get = |name: &str| fs::read(out.join(name)).unwrap();
    let digits = get("table.bin");
    let rows = get("rows.bin");
    let values = get("values.bin");
    let draws = get("draws.bin");
    let weights = get("weights.bin");
    assert_eq!(
        (
            digits.len(),
            rows.len(),
            values.len(),
            draws.len(),
            weights.len()
        ),
        (1 << 19, 169 * 384, 169 * 24, 22 * 24, 112 * 24)
    );
    let now = Instant::now();
    let cfg = Config::<Identity<F>>::new(
        digits.len(),
        &ProtocolParameters {
            security_level: 135,
            pow_bits: 16,
            initial_folding_factor: 4,
            folding_factor: 5,
            decoding_regime: DecodingRegime::Johnson,
            starting_log_inv_rate: 5,
            batch_size: 1,
            hash_id: KECCAK,
        },
    );
    assert!(cfg.check_max_pow_bits(Bits::new(16.)) && cfg.security_level(1, 1) + 1e-8 >= 135.);
    let fields: Vec<F> = digits.iter().map(|&d| F::from(d)).collect();
    let vector = Buffer::from(fields.as_slice());
    let shared = env::args().nth(2);
    let digests = env::args().nth(3).map(|file| fs::read(file).unwrap());
    if let Some(bytes) = &digests {
        assert!(shared.is_some() && bytes.len() == 240 * 32);
    }
    let (root, irs) = if let Some(file) = &shared {
        (fs::read(file).unwrap().try_into().unwrap(), None)
    } else {
        let pre = DomainSeparator::protocol(&cfg)
            .session(&"recursive-imt/precommit/v1")
            .instance(&Empty);
        let mut state = ProverState::new(&pre, Hash::<Keccak256>::default());
        let irs = cfg.initial_committer.commit(&mut state, &[&vector]);
        let root: [u8; 32] = state.proof().narg_string.try_into().unwrap();
        (root, Some(irs))
    };
    fs::write(out.join("root.bin"), root).unwrap();
    let domain = if digests.is_some() {
        "recursive-imt/native-row-fold-digests/v1"
    } else if shared.is_some() {
        "recursive-imt/native-whir-fold-hash-trace/v1"
    } else {
        "recursive-imt/native-whir-fold-rows/v1"
    };
    let seed: [u8; 32] = Keccak256::new()
        .chain_update(domain.as_bytes())
        .chain_update(root)
        .chain_update(Keccak256::digest(&draws))
        .chain_update(Keccak256::digest(digests.as_ref().unwrap_or(&rows)))
        .chain_update(Keccak256::digest(&values))
        .finalize()
        .into();
    let coin = |f, i| sc::coin(&seed, f, i);
    let t = coin(0, 0);
    let tp = powers(t, 128);
    let eta: [F; 3] = std::array::from_fn(|i| coin(1, i));
    let ar = powers(coin(2, 0), 256);
    let bc = powers(coin(2, 1), 51);
    let port = coin(2, 2);
    let range = coin(2, 3);
    let eq = |family, n| eq_weights(&(0..n).map(|i| coin(family, i)).collect::<Vec<_>>());
    let row_eq = eq(3, 8);
    let range_row = eq(4, 8);
    let range_col = eq(5, 11);
    let mut factors = sc::Factors {
        rows: vec![[F::ZERO; 9]; 256],
        cols: vec![[F::ZERO; 9]; 2048],
    };
    for (i, row) in factors.rows.iter_mut().enumerate() {
        let mut start = 0;
        for (s, count) in STAGES.into_iter().enumerate() {
            if (start..start + count).contains(&i) {
                row[s] = row_eq[i];
            }
            start += count;
        }
        row[5] = row_eq[i];
        row[6] = row_eq[i];
        row[7] = ar[i];
        row[8] = range_row[i];
    }
    let mut coefficients = [[F::ZERO; 48]; 5];
    let mut ws = weights.chunks_exact(24);
    for (s, out) in coefficients.iter_mut().enumerate() {
        for j in 0..if s == 0 { 48 } else { 16 } {
            let w = ws.next().unwrap();
            let [a, b, c] = std::array::from_fn(|k| fp(word(&w[8 * k..8 * k + 8]), &tp[..64]));
            let [h, m, n] = eta;
            let e = [
                h * a + m * b + n * c,
                h * c + m * (a + c) + n * b,
                h * b + m * (b + c) + n * (a + c),
            ];
            if s == 0 {
                out[j] = e[0]
            } else {
                out[3 * j..3 * j + 3].copy_from_slice(&e)
            }
        }
    }
    let modulus = F::ONE + t + tp[3] + tp[4] + tp[64];
    let sixteen = powers(F::from(16u8), 16);
    let port_start = if digests.is_some() { 1920 } else { 1152 };
    for (i, col) in factors.cols.iter_mut().enumerate() {
        if i < 1152 {
            let slab = i / 128;
            col[6] = -F::from(2u8) * eta[slab / 3] * sixteen[slab % 3] * tp[i % 128];
        } else if i < 1920 {
            let w = (i - 1152) / 16;
            for s in 0..5 {
                col[s] = coefficients[s][w] * tp[4 * (i % 16)];
            }
        } else if i < 2016 {
            let w = (i - 1920) / 16;
            col[5] = -eta[w % 3] * tp[4 * (i % 16)] * if w < 3 { F::ONE } else { modulus };
        }
        if (port_start..1968).contains(&i) {
            col[7] = port * bc[(i - port_start) / 16] * sixteen[i % 16];
        }
        col[8] = range * range_col[i];
    }
    let mut public_sum = F::ZERO;
    for (i, (row, val)) in rows
        .chunks_exact(384)
        .zip(values.chunks_exact(24))
        .enumerate()
    {
        let public_row = if digests.is_some() { &[][..] } else { row };
        let cell: F = public_row
            .chunks_exact(8)
            .chain(val.chunks_exact(8))
            .zip(&bc)
            .map(|(w, &b)| F::from(word(w)) * b)
            .sum();
        public_sum += ar[i] * cell;
    }
    let sum = port * public_sum - F::from(6u8) * eta.iter().sum::<F>() * tp.iter().sum::<F>();
    let g = nibble_gate::Gate::with_weights(&tp[..4], &[F::ZERO; 4]);
    let upper = sc::prove(
        &digits,
        (0..16u8)
            .map(|x| nibble_gate::moments(F::from(x)))
            .collect(),
        factors,
        seed,
        sum,
        0,
        |m| {
            let [bits, _, v, d] = g.values(m);
            [bits, bits, bits, bits, bits, bits, d, d, v]
        },
    );
    close_moments::close(&digits, upper, 8, out);
    let statement = [get("opening-point.bin"), get("digit-value.bin")].concat();
    let point = statement[32..statement.len() - 32]
        .chunks_exact(32)
        .map(F::from_be_bytes_mod_order)
        .collect::<Vec<_>>();
    let value = F::from_be_bytes_mod_order(&statement[statement.len() - 32..]);
    let form = MultilinearExtension::new(point.clone());
    assert_eq!(form.evaluate(&Identity::new(), &fields), value);
    if shared.is_some() {
        if digests.is_some() {
            let mut restricted = vec![F::ONE];
            restricted.extend_from_slice(&point[..8]);
            restricted.extend([F::ZERO; 2]);
            restricted.extend_from_slice(&point[8..]);
            fs::write(out.join("opening-point.bin"), [&statement[..32], &sc::words(&restricted)].concat()).unwrap();
            println!("Reduced 169 folds to the source digits in the 22-variable row sponge commitment");
            return;
        }
        let mut restricted = vec![F::ZERO];
        restricted.extend_from_slice(&point[..13]);
        restricted.extend([F::ONE, F::ZERO, F::ZERO, F::ONE, F::ONE, F::ONE]);
        restricted.extend_from_slice(&point[13..]);
        let public = [&statement[..32], &sc::words(&restricted)].concat();
        fs::write(out.join("opening-point.bin"), public).unwrap();
        println!("Reduced all native row folds to one opening on the 26-variable shared table");
        return;
    }
    let instance: [u8; 32] = Keccak256::digest(&statement).into();
    let ds = DomainSeparator::protocol(&cfg)
        .session(&"recursive-imt/prime-whir-opening/v1")
        .instance(&instance);
    let mut p = ProverState::new(&ds, Hash::<Keccak256>::default());
    p.prover_message(&whir::hash::Hash(root));
    let zs: Vec<F> = p.verifier_message_vec(cfg.initial_out_domain_samples);
    let oods: Vec<F> = zs
        .iter()
        .map(|&z| vector.mixed_univariate_evaluate(cfg.embedding(), z))
        .collect();
    p.prover_messages(&oods);
    let witness = Witness {
        irs: irs.unwrap(),
        out_of_domain: Evaluations {
            points: zs,
            matrix: Buffer::from(oods.as_slice()),
        },
    };
    let _ = cfg.prove(
        &mut p,
        &[&vector],
        vec![&witness],
        vec![Box::new(form.clone())],
        Buffer::from(vec![value]),
    );
    let proof = p.proof();
    let mut check = VerifierState::new(&ds, &proof, Hash::<Keccak256>::default());
    let commitment = cfg.receive_commitment(&mut check).unwrap();
    cfg.verify(&mut check, &[&commitment], &[value])
        .unwrap()
        .verify([&form as _])
        .unwrap();
    check.check_eof().unwrap();
    for (n, b) in [
        ("statement.bin", statement),
        ("proof.bin", proof.narg_string),
        ("hints.bin", proof.hints),
    ] {
        fs::write(out.join(n), b).unwrap();
    }
    println!("Verified 169 native binary WHIR row folds against a single 19-variable prime-field opening in {:.2?}",now.elapsed());
}
