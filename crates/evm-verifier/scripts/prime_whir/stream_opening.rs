//! Open one real checkpoint digit evaluation with bounded-memory WHIR commitments.
//! A caller may supply its own static 32-byte context and point words after the output path.
#[path = "support/digit_columns.rs"]
mod digit_columns;
#[path = "support/digits.rs"]
mod digits;
#[allow(dead_code)]
#[path = "stream_digits.rs"]
mod initial;
#[path = "support/nibble_folds.rs"]
mod nibble_folds;
#[allow(dead_code)]
#[path = "support/segments.rs"]
mod segments;
#[path = "support/stream_code.rs"]
mod stream_code;
use ark_ff::{BigInteger, Field, PrimeField};
use sha3::{Digest, Keccak256};
use spongefish::instantiations::Hash as Sponge;
use std::{env, fs, path::Path, time::Instant};
use whir::{
    algebra::{
        embedding::Identity,
        eq_weights,
        fields::Field192 as F,
        linear_form::{LinearForm, MultilinearExtension},
        ntt::{self, NttEngine},
    },
    bits::Bits,
    buffer::{Buffer, BufferMath, BufferOps},
    hash::{Hash, KECCAK},
    parameters::ProtocolParameters,
    protocols::{
        challenge_indices::challenge_indices, irs_commit, params::DecodingRegime, whir::Config,
    },
    transcript::{DomainSeparator, ProverState, VerifierMessage, VerifierState},
};
type Transcript = ProverState<Sponge<Keccak256>>;
fn public(path: Option<&String>, dir: &Path, arity: usize) -> ([u8; 32], Vec<F>) {
    if let Some(path) = path {
        let data = fs::read(path).unwrap();
        assert_eq!(data.len(), 32 * (arity + 1));
        let coords = data[32..]
            .chunks_exact(32)
            .map(|v| {
                assert!(v[..8].iter().all(|b| *b == 0));
                let x = F::from_be_bytes_mod_order(v);
                assert_eq!(x.into_bigint().to_bytes_be(), &v[8..]);
                x
            })
            .collect();
        return (data[..32].try_into().unwrap(), coords);
    }
    let context: [u8; 32] = if arity == 19 {
        Keccak256::digest(b"recursive-imt/field192-opening-control/v1").into()
    } else {
        Keccak256::new()
            .chain_update(b"recursive-imt/streamed-opening-control/v1")
            .chain_update(fs::read(dir.join("key.bin")).unwrap())
            .chain_update(fs::read(dir.join("node.bin")).unwrap())
            .chain_update(fs::read(dir.join("root.bin")).unwrap())
            .finalize()
            .into()
    };
    let point = (0..arity)
        .map(|i| {
            F::from_be_bytes_mod_order(
                &Keccak256::new()
                    .chain_update(context)
                    .chain_update([i as u8])
                    .finalize(),
            )
        })
        .collect();
    (context, point)
}
enum Oracle {
    Initial,
    Folded(stream_code::Code, Buffer<F>),
}
struct Initial<'a> {
    digits: &'a [u8],
    dir: &'a Path,
    engine: NttEngine<F>,
    omega: F,
}
fn open(
    p: &mut Transcript,
    code: &irs_commit::Config<Identity<F>>,
    w: &Oracle,
    first: &Initial<'_>,
    folds: &[F],
) -> (Vec<F>, Vec<F>) {
    let ix = challenge_indices(p, code.codeword_length(), code.in_domain_samples(), false);
    let hints = match w {
        Oracle::Initial => {
            initial::opening(first.digits, &first.engine, first.omega, first.dir, &ix)
        }
        Oracle::Folded(c, coeff) => c.opening(coeff.to_slice(), &ix),
    };
    let n = code.num_cols() * ix.len();
    assert_eq!(
        u64::from_le_bytes(hints[..8].try_into().unwrap()) as usize,
        n
    );
    let payload = &hints[8..8 + 24 * n];
    let rows: Vec<_> = payload
        .chunks_exact(24)
        .map(F::from_le_bytes_mod_order)
        .collect();
    p.prover_hint_ark(&rows);
    let rest = &hints[8 + 24 * n..];
    assert_eq!(rest.len() % 32, 0);
    for h in rest.chunks_exact(32) {
        p.prover_hint(&Hash(h.try_into().unwrap()));
    }
    let weights = eq_weights(folds);
    assert_eq!(weights.len(), code.num_cols());
    let values = rows
        .chunks_exact(weights.len())
        .map(|row| row.iter().zip(&weights).map(|(x, w)| *x * w).sum())
        .collect();
    (code.evaluation_points(&ix), values)
}
fn main() {
    let args: Vec<_> = env::args().collect();
    assert!((5..=8).contains(&args.len()));
    let input = Path::new(&args[1]);
    let dir = Path::new(&args[2]);
    let row_bits: usize = args[3].parse().unwrap();
    assert!(matches!(row_bits, 7 | 10 | 14 | 16));
    let out = Path::new(&args[4]);
    fs::create_dir_all(out).unwrap();
    let root: [u8; 32] = fs::read(dir.join("root.bin")).unwrap().try_into().unwrap();
    let table = digits::table(input, row_bits, 4);
    let cfg = Config::<Identity<F>>::new(
        table.len(),
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
    assert!(cfg.check_max_pow_bits(Bits::new(16.0)) && cfg.security_level(1, 1) + 1e-8 >= 135.0);
    let n = row_bits + 12;
    let (first_context, first_point) = public(args.get(5), dir, n);
    let mut points = vec![first_point];
    let context = match args.get(6..).unwrap_or_default() {
        [] => first_context,
        extra => {
            let domain = match (row_bits, extra.len()) {
                (14, 1) => b"recursive-imt/native-trace-openings/v1".as_slice(),
                (10, 2) => b"recursive-imt/native-row-openings/v1".as_slice(),
                _ => panic!("unsupported joint opening geometry"),
            };
            assert!(cfg.security_level(1, 1 + extra.len()) + 1e-8 >= 135.);
            let mut hash = Keccak256::new().chain_update(domain).chain_update(first_context);
            for path in extra {
                let (context, point) = public(Some(path), dir, n);
                hash.update(context);
                points.push(point);
            }
            hash.finalize().into()
        }
    };
    let t = Instant::now();
    let mut statement = context.to_vec();
    let mut cols = Vec::new();
    let mut values = Vec::new();
    for point in &points {
        let col = digit_columns::multilinear_columns(&table, &point[4..]);
        let value = nibble_folds::value(&col, &point[..4]);
        for x in point.iter().chain([&value]) {
            statement.extend([0; 8]);
            statement.extend(x.into_bigint().to_bytes_be());
        }
        cols.push(col);
        values.push(value);
    }
    let instance: [u8; 32] = Keccak256::digest(&statement).into();
    let domain = DomainSeparator::protocol(&cfg)
        .session(&"recursive-imt/prime-whir-opening/v1")
        .instance(&instance);
    let mut p = ProverState::new(&domain, Sponge::<Keccak256>::default());
    p.prover_message(&Hash(root));
    let folded = nibble_folds::prove(&mut p, &table, &points, &cols, &cfg.initial_sumcheck);
    println!(
        "Initial four folds and dense opening value in {:.2?}",
        t.elapsed()
    );
    let mut a = Buffer::from(folded.vector);
    let mut b = Buffer::from(folded.weight);
    let mut sum = folded.sum;
    let mut folds = folded.challenges;
    let rows = table.len() / 16;
    let first = Initial {
        digits: &table,
        dir,
        engine: NttEngine::new(rows, ntt::generator::<F>(rows)),
        omega: ntt::generator::<F>(32 * rows),
    };
    let mut prev = Oracle::Initial;
    let mut prev_cfg = &cfg.initial_committer;
    for (i, round) in cfg.round_configs.iter().enumerate() {
        let start = Instant::now();
        let code = stream_code::Code::commit(&round.irs_committer, a.to_slice());
        p.prover_message(&Hash(code.root));
        assert_eq!(round.out_domain_samples, 1);
        let z: F = p.verifier_message();
        let ood = a.mixed_univariate_evaluate(&Identity::new(), z);
        p.prover_message(&ood);
        println!("Committed WHIR stage {} in {:.2?}", i + 1, start.elapsed());
        round.pow.prove(&mut p);
        let (in_points, in_values) = open(&mut p, prev_cfg, &prev, &first, &folds);
        let mut points = vec![z];
        points.extend(in_points);
        let mix: F = p.verifier_message();
        let mut coeff = F::ONE;
        let scalars: Vec<_> = points
            .iter()
            .map(|_| {
                let v = coeff;
                coeff *= mix;
                v
            })
            .collect();
        sum += ood
            + in_values
                .iter()
                .zip(&scalars[1..])
                .map(|(v, w)| *v * w)
                .sum::<F>();
        b.accumulate_geometric(&points, &Buffer::from(scalars), a.len());
        let next = a.clone();
        prev = Oracle::Folded(code, a);
        prev_cfg = &round.irs_committer;
        let (folded, opening) =
            round
                .sumcheck
                .prove(&mut p, &Identity::new(), next, &mut b, &mut sum, &[]);
        a = folded;
        folds = opening.round_challenges;
        println!("Finished stage {} after {:.2?} total", i + 1, t.elapsed());
    }
    p.prover_messages(a.to_slice());
    cfg.final_pow.prove(&mut p);
    let (last_points, last_values) = open(&mut p, prev_cfg, &prev, &first, &folds);
    for (z, y) in last_points.into_iter().zip(last_values) {
        assert_eq!(a.mixed_univariate_evaluate(&Identity::new(), z), y);
    }
    let _ = cfg
        .final_sumcheck
        .prove(&mut p, &Identity::new(), a, &mut b, &mut sum, &[]);
    let proof = p.proof();
    let mut v = VerifierState::new(&domain, &proof, Sponge::<Keccak256>::default());
    let c = cfg.receive_commitment(&mut v).unwrap();
    let forms: Vec<_> = points.into_iter().map(MultilinearExtension::new).collect();
    cfg.verify(&mut v, &[&c], &values)
        .unwrap()
        .verify(forms.iter().map(|f| f as &dyn LinearForm<F>))
        .unwrap();
    v.check_eof().unwrap();
    println!("Reference verified the {}-variable opening: {} transcript and {} hint bytes, {:.2?} elapsed",n,proof.narg_string.len(),proof.hints.len(),t.elapsed());
    fs::write(out.join("proof.bin"), proof.narg_string).unwrap();
    fs::write(out.join("hints.bin"), proof.hints).unwrap();
    fs::write(out.join("statement.bin"), statement).unwrap();
}
