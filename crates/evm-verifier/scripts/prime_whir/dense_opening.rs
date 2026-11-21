//! Run against worldfnd/whir fe86de76 with the default (coset-major) RS encoder.
#[path = "support/segments.rs"]
mod segments;
#[path = "support/node.rs"]
mod node;
use node::node_statement;

use std::{
    env, fs,
    path::{Path, PathBuf},
    time::Instant,
};

use ark_ff::{BigInteger, PrimeField};
use ark_std::rand::{rngs::StdRng, Rng, SeedableRng};
use sha3::{Digest, Keccak256};
use spongefish::instantiations::Hash;
use whir::{
    algebra::{
        embedding::Identity,
        fields::Field256 as F,
        linear_form::{Evaluate, LinearForm, MultilinearExtension},
        ntt,
    },
    bits::Bits,
    buffer::{Buffer, BufferMath, BufferOps},
    hash::KECCAK,
    parameters::ProtocolParameters,
    protocols::{params::DecodingRegime, whir::Config},
    transcript::{codecs::Empty, DomainSeparator, ProverState, VerifierMessage, VerifierState},
};

/// Each 64-field row has one 16-field region for each of the three native checkpoints.
/// Two little-endian lanes fit injectively in a scalar, with zero-padding at the end of each state.
fn checkpoint_table(bundle: &Path, ports: bool) -> (Vec<F>, Vec<u8>) {
    let data = fs::read(bundle.join("keccak-checkpoints.bin")).unwrap();
    const STATE_BYTES: usize = 25 * 8;
    assert_eq!(data.len(), (1 << 16) * 3 * STATE_BYTES);
    let report: serde_json::Value =
        serde_json::from_slice(&fs::read(bundle.join("report.json")).unwrap()).unwrap();
    let statement = hex::decode(report["summary"]["statement"].as_str().unwrap()).unwrap();
    assert_eq!(statement.len(), 33);
    assert_eq!(statement[32], 64);
    let key: serde_json::Value =
        serde_json::from_slice(&fs::read(bundle.join("trusted.json")).unwrap()).unwrap();
    let digest: Vec<u8> = serde_json::from_value(key["verifier_digest"].clone()).unwrap();
    assert_eq!(digest.len(), 32);
    let mut hash = Keccak256::new();
    hash.update(b"recursive-imt/terminal-keccak-checkpoints/v1");
    hash.update(digest);
    hash.update(statement);
    let mut vector = vec![F::from(0u64); 1 << 22];
    for (target, row) in vector
        .chunks_exact_mut(64)
        .zip(data.chunks_exact(3 * STATE_BYTES))
    {
        for (region, state) in target
            .chunks_exact_mut(16)
            .zip(row.chunks_exact(STATE_BYTES))
        {
            for (slot, lanes) in region.iter_mut().zip(state.chunks(16)) {
                *slot = F::from_le_bytes_mod_order(lanes);
            }
        }
        if ports {
            // Keep all input lanes and both digest words together in the first subcube.
            target.swap(13, 32);
            target.swap(14, 33);
        }
    }
    (vector, hash.finalize().to_vec())
}

fn node_ports(node: &[u8], key: [u8; 32], root: &[u8]) -> (Vec<F>, Vec<u8>) {
    let context = Keccak256::new()
        .chain_update(b"recursive-imt/terminal-node-ports/v1")
        .chain_update(key)
        .chain_update(&node[..32])
        .chain_update([64])
        .chain_update(&node[32..])
        .finalize()
        .to_vec();
    let challenge = |i: u8| {
        let prefix = Keccak256::new()
            .chain_update(b"recursive-imt/terminal-node-query/v1")
            .chain_update(&context)
            .chain_update(root)
            .chain_update([i]);
        let wide = [
            prefix.clone().chain_update([0]).finalize(),
            prefix.chain_update([1]).finalize(),
        ]
        .concat();
        F::from_be_bytes_mod_order(&wide)
    };
    let mut point = vec![F::from(0u64); 22];
    point[0] = challenge(0);
    for (bit, coord) in point[1..16].iter_mut().rev().enumerate() {
        *coord = F::from((21670u64 >> bit) & 1);
    }
    for (i, coord) in point[18..].iter_mut().enumerate() {
        *coord = challenge(1 + i as u8);
    }
    (point, context)
}

fn main() {
    let mut args = env::args().skip(1);
    let out = PathBuf::from(args.next().expect("output directory"));
    let seed: u64 = args.next().as_deref().unwrap_or("42").parse().unwrap();
    let terminal = args.next().map(PathBuf::from);
    let mode = args.next();
    let ports = mode.as_deref() == Some("--node-ports");
    let lower_rate = mode.as_deref() == Some("--segment-output-rate32");
    let output_bits = lower_rate || mode.as_deref() == Some("--segment-output");
    let segmented = mode.as_deref() == Some("--segments") || output_bits;
    assert!(mode.is_none() || ((ports || segmented) && terminal.is_some()));
    assert!(args.next().is_none());
    fs::create_dir_all(&out).unwrap();
    let params = Config::<Identity<F>>::new(
        1 << 22,
        &ProtocolParameters {
            security_level: 135,
            pow_bits: 16,
            initial_folding_factor: 3,
            folding_factor: 3,
            decoding_regime: DecodingRegime::Johnson,
            starting_log_inv_rate: if lower_rate { 5 } else { 4 },
            batch_size: 1,
            hash_id: KECCAK,
        },
    );
    assert!(params.check_max_pow_bits(Bits::new(16.0)));
    let security_bits = params.security_level(1, 1);
    assert!(
        security_bits + 1e-8 >= 135.0,
        "WHIR profile missed its local target"
    );
    println!("WHIR round-by-round bound {security_bits:.2} bits");
    let mut rng = StdRng::seed_from_u64(seed);
    let (vector, mut public) = match &terminal {
        Some(bundle) if segmented => (
            segments::table(&fs::read(bundle.join("keccak-checkpoints.bin")).unwrap()),
            Vec::new(),
        ),
        Some(bundle) => checkpoint_table(bundle, ports),
        None => (
            (0..1 << 22).map(|_| rng.gen()).collect(),
            Keccak256::digest(b"recursive-imt/opening-benchmark").to_vec(),
        ),
    };
    let start = Instant::now();
    let vector = Buffer::from(vector.as_slice());
    // The IRS root is independent of WHIR's OOD challenge. Commit once, then bind the
    // external statement and reuse the reference commitment witness in the opening.
    let prefix = DomainSeparator::protocol(&params)
        .session(&"recursive-imt/precommit/v1")
        .instance(&Empty);
    let mut precommit = ProverState::new(&prefix, Hash::<Keccak256>::default());
    let irs = params.initial_committer.commit(&mut precommit, &[&vector]);
    let root: [u8; 32] = precommit.proof().narg_string.try_into().unwrap();
    fs::write(out.join("root.bin"), root).unwrap();
    let node = terminal
        .as_ref()
        .filter(|_| ports || segmented)
        .map(|bundle| {
            let (node, key) = node_statement(bundle);
            fs::write(out.join("node.bin"), &node).unwrap();
            (node, key)
        });
    let (prover_form, verifier_form, value): (Box<dyn LinearForm<F>>, Box<dyn LinearForm<F>>, F) =
        if segmented {
            let (form, expected, context, readings) =
                segments::SegmentForm::claim(vector.to_slice(), &node.as_ref().unwrap().0, &root);
            let actual = form.evaluate(params.embedding(), vector.to_slice());
            assert_eq!(
                actual, expected,
                "segment table disagrees with native public rows"
            );
            fs::write(out.join("readings.bin"), &readings).unwrap();
            public = context;
            public.extend(root);
            public.extend(readings);
            (Box::new(form.clone()), Box::new(form), actual)
        } else {
            let point = if let Some((node, key)) = node {
                let (coords, context) = node_ports(&node, key, &root);
                public = context;
                coords
            } else {
                (0..22).map(|_| rng.gen()).collect()
            };
            let form = MultilinearExtension::new(point.clone());
            let actual = form.evaluate(params.embedding(), vector.to_slice());
            for x in point {
                public.extend(x.into_bigint().to_bytes_be());
            }
            (Box::new(form.clone()), Box::new(form), actual)
        };
    public.extend(value.into_bigint().to_bytes_be());
    if output_bits {
        let start = Instant::now();
        let (bridge, result) = segments::output_bits(vector.to_slice(), &public);
        println!("packed output bit reduction {:.2?}", start.elapsed());
        fs::write(out.join("output-bits.bin"), bridge).unwrap();
        fs::write(out.join("output-result.bin"), result).unwrap();
    }
    let instance: [u8; 32] = Keccak256::digest(&public).into();
    let ds = DomainSeparator::protocol(&params)
        .session(&"recursive-imt/prime-whir-opening/v1")
        .instance(&instance);
    println!(
        "protocol {} session {}",
        hex::encode(ds.protocol_id),
        hex::encode(ds.session_id)
    );
    for (commit, pow) in std::iter::once(&params.initial_committer)
        .chain(params.round_configs.iter().map(|r| &r.irs_committer))
        .zip(
            params
                .round_configs
                .iter()
                .map(|r| &r.pow)
                .chain([&params.final_pow]),
        )
    {
        assert_eq!(pow.hash_id, KECCAK);
        println!(
            "rows {} queries {} threshold {} generator {} at1 {}",
            commit.codeword_length(),
            commit.in_domain_samples(),
            pow.threshold,
            ntt::generator::<F>(commit.codeword_length()),
            commit.evaluation_points(&[1])[0]
        );
    }
    let mut prover = ProverState::new(&ds, Hash::<Keccak256>::default());
    prover.prover_message(&whir::hash::Hash(root));
    let points: Vec<F> = prover.verifier_message_vec(params.initial_out_domain_samples);
    let ood: Vec<F> = points
        .iter()
        .map(|&z| vector.mixed_univariate_evaluate(params.embedding(), z))
        .collect();
    prover.prover_messages(&ood);
    let witness = whir::protocols::whir::Witness {
        irs,
        out_of_domain: whir::protocols::irs_commit::Evaluations {
            points,
            matrix: Buffer::from(ood.as_slice()),
        },
    };
    let _ = params.prove(
        &mut prover,
        &[&vector],
        vec![&witness],
        vec![prover_form],
        Buffer::from(&[value][..]),
    );
    let proof = prover.proof();
    println!("commit and prove {:.2?}", start.elapsed());
    let mut verifier = VerifierState::new(&ds, &proof, Hash::<Keccak256>::default());
    let commitment = params.receive_commitment(&mut verifier).unwrap();
    let claim = params
        .verify(&mut verifier, &[&commitment], &[value])
        .unwrap();
    claim.verify([verifier_form.as_ref()]).unwrap();
    verifier.check_eof().unwrap();
    fs::write(out.join("public.bin"), public).unwrap();
    fs::write(out.join("proof.bin"), proof.narg_string).unwrap();
    fs::write(out.join("hints.bin"), proof.hints).unwrap();
}
