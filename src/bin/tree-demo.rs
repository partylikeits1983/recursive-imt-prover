use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::Instant,
};

use anyhow::{Result, ensure};
use clap::Parser;
use imt_flock_backend::{
    HashBackend, MAX_VERIFIER_BYTES, WHIR_FOLD, WHIR_LOG_INV_RATE, verifier_key_digest,
};
use mimalloc::MiMalloc;
use rayon::ThreadPoolBuilder;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use recursive_imt_prover::{
    benchmark::{environment, ms, peak_rss, statistics},
    binary::{
        IMT_DEPTH, MAX_CHILDREN,
        aggregation_tree::{
            cyclic::{CyclicVerifier, PROTOCOL, PreparedCyclicMerge},
            merge::TreeProof,
        },
        cli::fixtures,
        engine::Settings,
        relation::AggregatePublic,
        veil::{
            aggregate::{MaskedChildInput, PreparedMaskedAggregate, StatementFormat},
            child::{MaskedMembershipProof, PreparedMembership},
            parameters::Parameters,
        },
    },
    files::{read_bounded, read_json, write_json},
};

#[global_allocator]
static ALLOCATOR: MiMalloc = MiMalloc;

#[derive(Parser)]
#[command(about = "Depth-32 masked children and one merge circuit/key reused across the tree")]
struct Args {
    #[arg(long, default_value_t = 64)]
    batch_size: usize,
    #[arg(long, default_value_t = 4)]
    threads: usize,
    #[arg(long, default_value = "run/cyclic-tree")]
    out: PathBuf,
    #[arg(long)]
    verify: bool,
    #[arg(long, conflicts_with = "verify")]
    setup_only: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Trusted {
    protocol: String,
    identity: String,
    verifier_digest: [u8; 32],
}

fn main() -> Result<()> {
    let args = Args::parse();
    ensure!(
        (1..=64).contains(&args.threads),
        "threads must be in 1..=64"
    );
    ThreadPoolBuilder::new()
        .num_threads(args.threads)
        .build_global()?;
    if args.verify {
        return verify_files(&args.out);
    }
    ensure!(
        args.batch_size.is_power_of_two() && (4..=MAX_CHILDREN).contains(&args.batch_size),
        "tree batch size must be 4, 8, 16, 32 or 64"
    );
    ensure!(!args.out.exists(), "output directory must be fresh");
    fs::create_dir_all(&args.out)?;
    let start = Instant::now();
    let parameters = Parameters::default();
    let child = PreparedMembership::new(IMT_DEPTH, parameters.clone())?;
    let child_setup_ms = ms(start);
    let settings = Settings {
        depth: IMT_DEPTH,
        batch_size: 2,
        log_inv_rate: WHIR_LOG_INV_RATE,
        fold: WHIR_FOLD,
        max_codeword_cells: 1 << 29,
        ..Settings::default()
    };
    eprintln!("Preparing first aggregation...");
    let t = Instant::now();
    let first = PreparedMaskedAggregate::with_format(
        &settings,
        parameters.clone(),
        HashBackend::Checkpoint,
        StatementFormat::CyclicPair,
    )?;
    let first_setup_ms = ms(t);
    let first_key = first.export_verifier_key()?;
    let first_identity = first.identity();
    eprintln!("Preparing the reusable merge circuit once...");
    let t = Instant::now();
    let merge = PreparedCyclicMerge::new(first.cyclic_verifier()?)?;
    let merge_setup_ms = ms(t);
    let key = merge.export_verifier_key()?;
    let trusted = Trusted {
        protocol: PROTOCOL.to_owned(),
        identity: merge.identity(),
        verifier_digest: verifier_key_digest(&key),
    };
    let verifier = CyclicVerifier::from_bytes(&key, &trusted.verifier_digest, &trusted.identity)?;
    let mut report = json!({
        "protocol": PROTOCOL, "environment": environment(), "depth": IMT_DEPTH,
        "batch_size": args.batch_size, "field": "Poly64/Poly192", "hash": "Keccak-256", "bound": "Johnson",
        "child_parameters": parameters, "child_identity": child.identity(),
        "first_verifier_digest": verifier_key_digest(&first_key), "merge_verifier_digest": trusted.verifier_digest,
        "circuit_constructions": {"child":1, "first_aggregation":1, "merge":1},
        "setup_ms": {"child":child_setup_ms, "first_aggregation":first_setup_ms, "merge":merge_setup_ms},
        "geometry": {"first_aggregation":first.geometry(), "merge":merge.geometry()},
        "children": [], "first_aggregates": [], "merge_levels": [],
        "validation_work": {"extra_first_aggregates":1},
        "same_key_recursion": false, "acceptance_pass": false,
        "full_zk_established": false, "end_to_end_security_bits": null
    });
    write_json(&args.out.join("report.json"), &report)?;
    if args.setup_only {
        println!(
            "{}",
            json!({"setup_only":true,"report":args.out.join("report.json")})
        );
        return Ok(());
    }
    let t = Instant::now();
    let notes = fixtures(IMT_DEPTH, args.batch_size)?;
    report["fixture_ms"] = json!(ms(t));
    let mut inputs = Vec::new();
    let mut child_metrics = Vec::new();
    for (i, (public, witness)) in notes.into_iter().enumerate() {
        let t = Instant::now();
        let trace = child.witness(&public, &witness)?;
        drop(witness);
        let witness_ms = ms(t);
        let t = Instant::now();
        let proof = child.prove_trace(&public, trace)?;
        let prove_ms = ms(t);
        let bytes = proof.to_bytes()?;
        let t = Instant::now();
        let proof = MaskedMembershipProof::from_bytes(&bytes)?;
        child.verify(&public, &proof)?;
        let verify_ms = ms(t);
        eprintln!(
            "Child {}/{}: prove {prove_ms:.1} ms, verify {verify_ms:.1} ms",
            i + 1,
            args.batch_size
        );
        child_metrics.push(json!({"witness_ms":witness_ms,"prove_ms":prove_ms,"decode_verify_ms":verify_ms,"proof_bytes":bytes.len()}));
        inputs.push(MaskedChildInput { public, proof });
    }
    drop(child);
    let expected = AggregatePublic {
        children: inputs.iter().map(|c| c.public.clone()).collect(),
    };
    report["children"] = json!(child_metrics);
    write_json(&args.out.join("report.json"), &report)?;

    let t = Instant::now();
    let mut malformed = inputs[..2].to_vec();
    malformed[0].public.root[0] ^= 1;
    ensure!(
        first
            .prove_for_merge(&malformed, merge.authority())
            .is_err(),
        "invalid child statement accepted"
    );
    let mut bytes = inputs[0].proof.to_bytes()?;
    bytes[8] ^= 1; // Oracle commitment immediately after the version header.
    malformed = inputs[..2].to_vec();
    malformed[0].proof = MaskedMembershipProof::from_bytes(&bytes)?;
    ensure!(
        first
            .prove_for_merge(&malformed, merge.authority())
            .is_err(),
        "invalid child proof accepted"
    );
    eprintln!("Preparing a foreign-authority proof for rejection testing...");
    let mut foreign = merge.authority().clone();
    foreign.identity[0] ^= 1;
    let (public, proof, _) = first.prove_for_merge(&inputs[..2], &foreign)?;
    let foreign_pair = TreeProof { public, proof };
    let mut validation_ms = ms(t);
    let mut layer = Vec::new();
    let mut first_metrics = Vec::new();
    for (i, pair) in inputs.as_chunks::<2>().0.iter().enumerate() {
        let (public, proof, metrics) = first.prove_for_merge(pair, merge.authority())?;
        eprintln!(
            "First aggregate {}/{}: {:.1} ms, {} bytes",
            i + 1,
            args.batch_size / 2,
            metrics.aggregation_wall_ms,
            proof.len()
        );
        first_metrics.push(json!(metrics));
        layer.push(TreeProof { public, proof });
        report["first_aggregates"] = json!(first_metrics);
        write_json(&args.out.join("report.json"), &report)?;
    }
    drop(first);
    drop(inputs);
    let t = Instant::now();
    ensure!(
        CyclicVerifier::from_bytes(
            &first_key,
            &verifier_key_digest(&first_key),
            &first_identity
        )
        .is_err(),
        "first authority accepted as merge authority"
    );
    ensure!(
        verifier.verify(&layer[0].proof, &layer[0].public).is_err(),
        "first proof accepted as a merge proof"
    );
    let valid_pair = TreeProof {
        public: layer[0].public.clone(),
        proof: layer[0].proof.clone(),
    };
    ensure!(
        merge.prove(&[foreign_pair, valid_pair]).is_err(),
        "foreign carried authority accepted"
    );
    validation_ms += ms(t);

    let mut levels = Vec::new();
    let mut merge_times = Vec::new();
    while layer.len() > 1 {
        ensure!(
            merge.export_verifier_key()? == key,
            "merge key changed between levels"
        );
        let count = layer.len() / 2;
        let mut next = Vec::new();
        let mut nodes = Vec::new();
        let mut pairs = layer.into_iter();
        while let Some(left) = pairs.next() {
            let right = pairs
                .next()
                .ok_or_else(|| anyhow::anyhow!("incomplete merge pair"))?;
            let (proof, metrics) = merge.prove(&[left, right])?;
            verifier.verify(&proof.proof, &proof.public)?;
            eprintln!(
                "Merge level {}, node {count_done}/{count}, {} leaves: {:.1} ms, {} bytes",
                levels.len() + 1,
                proof.public.children.len(),
                metrics.aggregation_wall_ms,
                proof.proof.len(),
                count_done = next.len() + 1
            );
            merge_times.push(metrics.aggregation_wall_ms);
            nodes.push(json!({"children":proof.public.children.len(),"metrics":metrics}));
            next.push(proof);
        }
        levels.push(json!({"verifier_digest":verifier_key_digest(&merge.export_verifier_key()?),"nodes":nodes}));
        report["merge_levels"] = json!(levels);
        write_json(&args.out.join("report.json"), &report)?;
        layer = next;
    }
    let proof = layer.pop().unwrap();
    ensure!(
        proof.public == expected,
        "final statement differs from the ordered children"
    );
    let t = Instant::now();
    let negative_checks = negative_checks(&verifier, &proof)?;
    validation_ms += ms(t);
    fs::write(args.out.join("aggregate.proof"), &proof.proof)?;
    fs::write(args.out.join("verifier.key"), &key)?;
    write_json(&args.out.join("statement.json"), &proof.public)?;
    write_json(&args.out.join("trusted.json"), &trusted)?;
    drop(merge);
    drop(verifier);
    let t = Instant::now();
    let output = Command::new(std::env::current_exe()?)
        .args(["--verify", "--threads", &args.threads.to_string(), "--out"])
        .arg(&args.out)
        .output()?;
    let wall_ms = ms(t);
    ensure!(
        output.status.success(),
        "fresh verifier failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    report["fresh_verifier"] = serde_json::from_slice::<Value>(&output.stdout)?;
    report["fresh_verifier_wall_ms"] = json!(wall_ms);
    report["negative_checks"] = json!(negative_checks);
    report["invalid_child_statement_rejected"] = json!(true);
    report["invalid_child_proof_rejected"] = json!(true);
    report["foreign_authority_rejected"] = json!(true);
    report["same_key_recursion"] = json!(levels.len() >= 2);
    report["acceptance_pass"] = json!(args.batch_size == 64 && levels.len() == 5);
    report["run_wall_ms"] = json!(ms(start));
    report["validation_overhead_ms"] = json!(validation_ms);
    report["critical_path_ms"] = json!(ms(start) - validation_ms);
    report["peak_rss_bytes"] = json!(peak_rss());
    report["merge_times_ms"] = json!(statistics(merge_times));
    write_json(&args.out.join("report.json"), &report)?;
    println!(
        "{}",
        json!({"children":args.batch_size,"merge_levels":levels.len(),"proof_bytes":proof.proof.len(),"same_key_recursion":report["same_key_recursion"],"acceptance_pass":report["acceptance_pass"],"report":args.out.join("report.json")})
    );
    Ok(())
}

fn verify_files(directory: &Path) -> Result<()> {
    let start = Instant::now();
    let trusted: Trusted = read_json(&directory.join("trusted.json"))?;
    ensure!(trusted.protocol == PROTOCOL, "incorrect cyclic protocol");
    let key = read_bounded(&directory.join("verifier.key"), MAX_VERIFIER_BYTES)?;
    let verifier = CyclicVerifier::from_bytes(&key, &trusted.verifier_digest, &trusted.identity)?;
    let public: AggregatePublic = read_json(&directory.join("statement.json"))?;
    let proof = read_bounded(&directory.join("aggregate.proof"), 16 << 20)?;
    let setup_ms = ms(start);
    let t = Instant::now();
    verifier.verify(&proof, &public)?;
    println!(
        "{}",
        json!({"verified":true,"children":public.children.len(),"setup_ms":setup_ms,"verify_ms":ms(t),"peak_rss_bytes":peak_rss()})
    );
    Ok(())
}

fn negative_checks(verifier: &CyclicVerifier, proof: &TreeProof) -> Result<Vec<&'static str>> {
    let mut checked = Vec::new();
    for case in [
        "root",
        "nullifier hash",
        "order",
        "remove",
        "insert",
        "half",
    ] {
        let mut public = proof.public.clone();
        match case {
            "root" => public.children[0].root[0] ^= 1,
            "nullifier hash" => public.children[0].nullifier_hash[0] ^= 1,
            "order" => public.children.swap(0, 1),
            "remove" => {
                public.children.pop();
            }
            "insert" => public.children.push(public.children[0].clone()),
            "half" => public.children.truncate(public.children.len() / 2),
            _ => unreachable!(),
        }
        ensure!(
            verifier.verify(&proof.proof, &public).is_err(),
            "accepted modified {case}"
        );
        checked.push(case);
    }
    let mut corrupted = proof.proof.clone();
    let middle = corrupted.len() / 2;
    corrupted[middle] ^= 1;
    ensure!(
        verifier.verify(&corrupted, &proof.public).is_err(),
        "accepted corrupted proof"
    );
    checked.push("corrupted proof");
    ensure!(
        verifier
            .verify(&proof.proof[..proof.proof.len() - 1], &proof.public)
            .is_err(),
        "accepted truncated proof"
    );
    checked.push("truncated proof");
    let mut extended = proof.proof.clone();
    extended.push(0);
    ensure!(
        verifier.verify(&extended, &proof.public).is_err(),
        "accepted trailing proof bytes"
    );
    checked.push("trailing proof bytes");
    Ok(checked)
}
