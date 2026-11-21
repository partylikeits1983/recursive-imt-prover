use ark_ff::{BigInteger, PrimeField};
use gkr::scalar::Fr;
use gkr::{
    keccacheck_og::{prover::prove, verifier::verify},
    reference::keccak_round,
};
use sha3::{Digest, Keccak256};
use std::{env, fs, time::Instant};

fn main() {
    let args: Vec<_> = env::args().collect();
    let table = fs::read(&args[1]).unwrap();
    let permutations: usize = args[2].parse().unwrap();
    let native_trace = args.get(5).is_some_and(|mode| mode == "--native-trace");
    let source_rows = if native_trace { permutations } else { 65536 };
    assert_eq!(table.len(), source_rows * 600);
    if native_trace {
        assert!(matches!(permutations, 512 | 16384));
    }
    assert!(permutations.is_power_of_two() && permutations <= 65536);
    let nibbles = native_trace || args.get(5).is_some_and(|mode| mode == "--nibbles192");
    let digits = nibbles || args.get(5).is_some_and(|mode| mode == "--digits");
    let segments = 8 * permutations;
    let mut inputs = Vec::with_capacity(segments * 25);
    let mut outputs = vec![0; segments * 25];
    for row in 0..permutations {
        let stride = source_rows / permutations;
        // The digit-table sample includes the fixed final hash row in both child roles.
        let index = if digits && !native_trace && row % (permutations / 2) == 21670 / stride {
            row / (permutations / 2) * 32768 + 21670
        } else {
            row * stride
        };
        let checkpoints = &table[600 * index..600 * (index + 1)];
        let state_at = |offset: usize| {
            std::array::from_fn(|lane| {
                let j = offset + 8 * lane;
                u64::from_le_bytes(checkpoints[j..j + 8].try_into().unwrap())
            })
        };
        let mut state: [u64; 25] = state_at(0);
        let mut standard = state;
        keccak::f1600(&mut standard);
        assert_eq!(standard, state_at(400));
        for s in 0..8 {
            inputs.extend(state);
            for step in 0..3 {
                state = keccak_round(&state, 3 * s + step).iota.try_into().unwrap();
            }
            if s == 3 {
                assert_eq!(state, state_at(200));
            }
            for (lane, v) in state.iter().enumerate() {
                outputs[lane * segments + row * 8 + s] = *v;
            }
        }
        assert_eq!(state, standard);
    }
    // Direct-bit control: both complete endpoint vectors fix the instance before any challenge.
    let mut statement = Keccak256::new()
        .chain_update(b"recursive-imt/segment-gkr-io/v1")
        .chain_update((segments as u64).to_be_bytes());
    for &word in inputs.iter().chain(&outputs) {
        statement.update(word.to_le_bytes());
    }
    let digest: [u8; 32] = statement.finalize().into();
    let mut seed = gkr::transcript::Sponge::new();
    for half in digest.chunks_exact(16) {
        seed.absorb(Fr::from_be_bytes_mod_order(half));
    }
    let n = segments.ilog2() as usize;
    let r = (0..n).map(|_| seed.squeeze()).collect::<Vec<_>>();
    if let Some(source) = args.get(4) {
        let input: Vec<_> = (0..25)
            .flat_map(|lane| inputs[lane..].iter().step_by(25).copied())
            .collect();
        let (context, point, lanes) = if source == "sample" {
            let point: Vec<_> = (0..n + 6).map(|_| seed.squeeze()).collect();
            let lanes = gkr::projected::readings(&outputs, &point);
            (digest, point, lanes)
        } else if nibbles {
            assert_eq!(Fr::MODULUS_BIT_SIZE, 192);
            let bundle = std::path::Path::new(source);
            let root = fs::read(bundle.join("root.bin")).unwrap();
            assert_eq!(root.len(), 32);
            let instance: [u8; 32] = if native_trace {
                Keccak256::new()
                    .chain_update(if permutations == 512 { b"recursive-imt/native-row-keccak/v1".as_slice() } else { b"recursive-imt/native-trace-keccak/v1".as_slice() })
                    .chain_update(root)
                    .finalize()
                    .into()
            } else {
                let node = fs::read(bundle.join("node.bin")).unwrap();
                let key = fs::read(bundle.join("key.bin")).unwrap();
                assert_eq!((node.len(), key.len()), (96, 32));
                Keccak256::new()
                    .chain_update(b"recursive-imt/keccak-nibbles192/v1")
                    .chain_update(key)
                    .chain_update(node)
                    .chain_update([permutations.ilog2() as u8])
                    .chain_update(root)
                    .finalize()
                    .into()
            };
            let point: Vec<Fr> = (0..n + 6)
                .map(|i| {
                    let hash = Keccak256::new()
                        .chain_update(b"recursive-imt/digit-coin/v1")
                        .chain_update(instance)
                        .chain_update([0, i as u8]);
                    Fr::from_be_bytes_mod_order(
                        &[
                            hash.clone().chain_update([0]).finalize(),
                            hash.chain_update([1]).finalize(),
                        ]
                        .concat(),
                    )
                })
                .collect();
            let lanes = gkr::projected::readings(&outputs, &point);
            (instance, point, lanes)
        } else {
            let bundle = std::path::Path::new(source);
            let h: [u8; 32] = if digits {
                fs::read(bundle.join("digit-instance.bin"))
                    .unwrap()
                    .try_into()
                    .unwrap()
            } else {
                assert_eq!(permutations, 65536);
                Keccak256::new()
                    .chain_update(b"recursive-imt/segment-rounds/v1")
                    .chain_update(fs::read(bundle.join("node.bin")).unwrap())
                    .chain_update(fs::read(bundle.join("root.bin")).unwrap())
                    .chain_update(fs::read(bundle.join("readings.bin")).unwrap())
                    .finalize()
                    .into()
            };
            let result = fs::read(bundle.join("output-result.bin")).unwrap();
            let point_len = n + 6;
            assert_eq!(result.len(), (point_len + 25) * 32);
            let scalars: Vec<_> = result
                .chunks_exact(32)
                .map(Fr::from_be_bytes_mod_order)
                .collect();
            assert_eq!(
                gkr::projected::readings(&outputs, &scalars[..point_len]),
                scalars[point_len..]
            );
            (
                h,
                scalars[..point_len].to_vec(),
                scalars[point_len..].to_vec(),
            )
        };
        let start = Instant::now();
        let proof = gkr::projected::prove_bits(&input, &context, &point, &lanes);
        let proving = start.elapsed();
        let (r, b) = gkr::projected::verify_bits(&input, &context, &point, &lanes, &proof);
        assert_eq!(proof.len(), 3 * (18 * (n + 6) + 161));
        let encode = |v: &[Fr]| {
            v.iter()
                .flat_map(|x| x.into_bigint().to_bytes_be())
                .collect::<Vec<_>>()
        };
        let path = &args[3];
        fs::write(path, encode(&proof)).unwrap();
        fs::write(
            format!("{path}.public"),
            [context.to_vec(), encode(&point), encode(&lanes)].concat(),
        )
        .unwrap();
        fs::write(format!("{path}.result"), [encode(&r), encode(&b)].concat()).unwrap();
        println!(
            "{permutations} permutations, {} projected GKR scalars, proving {proving:.2?}",
            proof.len()
        );
        return;
    }
    let start = Instant::now();
    let (proof, input, output) = prove(&inputs, r.clone());
    let proving = start.elapsed();
    assert_eq!(output, outputs);
    for i in 0..segments {
        for j in 0..25 {
            assert_eq!(input[j * segments + i], inputs[25 * i + j]);
        }
    }
    let start = Instant::now();
    let (point, bits) = verify(n + 6, &outputs, &input, &proof, r.clone());
    let verification = start.elapsed();
    let encoded: Vec<u8> = proof
        .iter()
        .flat_map(|v| v.into_bigint().to_bytes_be())
        .collect();
    println!(
        "{permutations} permutations, {segments} segments, {} scalars, {} bytes, {} nonzero bytes, proving {proving:.3?}, direct verification {verification:.3?}",
        proof.len(),
        encoded.len(),
        encoded.iter().filter(|&&b| b != 0).count()
    );
    if let Some(path) = args.get(3) {
        use gkr::sumcheck::util::{eval_mle, to_field_vec};
        let words = outputs
            .chunks_exact(segments)
            .map(|lane| eval_mle(&to_field_vec(lane), &r));
        let mut application = digest.to_vec();
        for value in words {
            application.extend(value.into_bigint().to_bytes_be());
        }
        let result: Vec<u8> = point
            .iter()
            .chain(&bits)
            .flat_map(|v| v.into_bigint().to_bytes_be())
            .collect();
        fs::write(format!("{path}.public"), application).unwrap();
        fs::write(format!("{path}.result"), result).unwrap();
        fs::write(path, encoded).unwrap();
    }
}
