#[path = "tree-demo/progress.rs"]
mod progress;
#[path = "tree-demo/storage.rs"]
mod storage;

use std::{
    fs,
    io::{self, IsTerminal},
    num::NonZeroUsize,
    path::{Path, PathBuf},
    process::Command,
    thread::available_parallelism,
    time::Instant,
};

use anyhow::{Result, ensure};
use clap::Parser;
use imt_flock_backend::{
    HashBackend, MAX_VERIFIER_BYTES, WHIR_FOLD, WHIR_LOG_INV_RATE, compact_aggregate_proof,
    verifier_key_digest,
};
use mimalloc::MiMalloc;
use rayon::{ThreadPoolBuilder, prelude::*};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use recursive_imt_prover::{
    benchmark::{environment, ms, peak_rss, statistics},
    binary::{
        IMT_DEPTH, MAX_CHILDREN,
        aggregation_tree::{
            TreeProof,
            cyclic::{CyclicVerifier, PROTOCOL, PreparedCyclicMerge},
        },
        cli::fixtures,
        engine::Settings,
        relation::AggregatePublic,
        veil::{
            aggregate::{AggregationMetrics, PreparedMaskedAggregate, StatementFormat},
            child::{MaskedMembershipProof, PreparedMembership},
            parameters::Parameters,
        },
    },
    files::{read_bounded, read_json, write_json},
};

use progress::TreeProgress;
use storage::{StoredProof, scratch_directory};

#[global_allocator]
static ALLOCATOR: MiMalloc = MiMalloc;

#[derive(Parser)]
#[command(
    name = "cargo prove",
    bin_name = "cargo prove",
    about = "Prove a tree of independent child proofs and verify its root. Temporary proofs are written to disk and cleaned up.",
    after_help = "Examples:\n  cargo prove -j 3                Prove 64 children, up to three at a time\n  cargo prove -n 8 -j 3           Prove a smaller eight-child tree\n  cargo prove --parallel-nodes 2  Prove two aggregate pairs in parallel"
)]
struct Args {
    /// Number of child proofs (4, 8, 16, 32 or 64).
    #[arg(short = 'n', long, default_value_t = MAX_CHILDREN)]
    batch_size: usize,
    /// Total CPU worker threads shared by all proofs.
    #[arg(long, default_value_t = available_parallelism().map_or(1, usize::from).min(64))]
    threads: usize,
    /// Maximum number of child proofs to prove in parallel.
    #[arg(short = 'j', long, default_value = "2")]
    parallel_children: NonZeroUsize,
    /// Maximum number of aggregate pairs to prove in parallel at each level.
    #[arg(long, default_value_t = 1)]
    parallel_nodes: usize,
    /// Directory for --keep or --verify. Temporary demos use an isolated directory under run/.
    #[arg(short, long)]
    out: Option<PathBuf>,
    /// Keep the final proof, statement, verifier key and report in a fresh --out directory.
    #[arg(long, requires = "out", conflicts_with = "verify")]
    keep: bool,
    /// Also print the machine-readable summary when stdout is a terminal.
    #[arg(long)]
    json: bool,
    /// Verify a saved proof from --out.
    #[arg(long)]
    verify: bool,
    /// Prepare the circuits and exit before generating proofs.
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
        return verify_files(args.out.as_deref().unwrap_or(Path::new("run/cyclic-tree")));
    }
    ensure!(
        args.batch_size.is_power_of_two() && (4..=MAX_CHILDREN).contains(&args.batch_size),
        "tree batch size must be 4, 8, 16, 32 or 64"
    );
    ensure!(
        args.parallel_nodes > 0,
        "parallel node count must be positive"
    );
    let destination = args.out.as_deref().filter(|_| args.keep);
    if let Some(path) = destination {
        ensure!(!path.exists(), "--keep requires a fresh output directory");
    }
    // Kept runs stage beside the destination so publishing the verified bundle is one rename.
    let parent = match destination {
        Some(path) => path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new(".")),
        None => Path::new("run"),
    };
    let scratch = scratch_directory(parent)?;
    let out = scratch.path();
    let report_path = destination.map(|dir| dir.join("report.json"));
    let parallel_children = args
        .parallel_children
        .get()
        .min(args.threads)
        .min(args.batch_size);
    eprintln!("Preparing circuits…");
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
        "batch_size": args.batch_size, "parallel_children":parallel_children, "parallel_nodes":args.parallel_nodes, "field": "Poly64/Poly192", "hash": "Keccak-256", "bound": "Johnson",
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
    write_json(&out.join("report.json"), &report)?;
    if args.setup_only {
        finish_run(scratch, destination)?;
        println!(
            "{}",
            json!({"setup_only":true,"report":report_path,"setup_ms":report["setup_ms"]})
        );
        return Ok(());
    }
    let node_dir = out.join("nodes");
    fs::create_dir(&node_dir)?;
    let t = Instant::now();
    let notes = fixtures(IMT_DEPTH, args.batch_size)?;
    report["fixture_ms"] = json!(ms(t));
    let expected = AggregatePublic {
        children: notes.iter().map(|(public, _)| public.clone()).collect(),
    };
    let progress = TreeProgress::new(args.batch_size);
    let child_start = Instant::now();
    let results = notes
        .into_par_iter()
        .enumerate()
        .by_uniform_blocks(parallel_children)
        .map(|(i, (public, witness))| {
            progress.track(0, i, || {
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
                let metrics = json!({
                    "witness_ms": witness_ms,
                    "prove_ms": prove_ms,
                    "decode_verify_ms": verify_ms,
                    "proof_bytes": bytes.len(),
                });
                Ok((
                    StoredProof::write(&node_dir, 0, i, public, &bytes)?,
                    metrics,
                ))
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let (inputs, child_metrics): (Vec<_>, Vec<_>) = results.into_iter().unzip();
    let child_wall_ms = ms(child_start);
    report["child_stage_wall_ms"] = json!(child_wall_ms);
    drop(child);
    report["children"] = json!(child_metrics);
    write_json(&out.join("report.json"), &report)?;

    let t = Instant::now();
    progress.message("Checking child and authority rejection");
    let original = [inputs[0].load()?, inputs[1].load()?];
    let mut malformed = original.clone();
    malformed[0].public.root[0] ^= 1;
    ensure!(
        first
            .prove_for_merge(&malformed, merge.authority())
            .is_err(),
        "invalid child statement accepted"
    );
    let mut bytes = original[0].proof.to_bytes()?;
    bytes[8] ^= 1; // Oracle commitment immediately after the version header.
    malformed = original.clone();
    malformed[0].proof = MaskedMembershipProof::from_bytes(&bytes)?;
    ensure!(
        first
            .prove_for_merge(&malformed, merge.authority())
            .is_err(),
        "invalid child proof accepted"
    );
    let mut foreign = merge.authority().clone();
    foreign.identity[0] ^= 1;
    let (public, proof, _) = first.prove_for_merge(&original, &foreign)?;
    drop(original);
    drop(malformed);
    let foreign_pair = TreeProof { public, proof };
    let mut validation_ms = ms(t);
    let mut first_metrics = Vec::new();
    let validation_before_aggregation_ms = validation_ms;
    let first_start = Instant::now();
    let mut layer = prove_pairs(
        &inputs,
        args.parallel_nodes,
        &progress,
        &node_dir,
        1,
        |pair| {
            let (public, proof, metrics) =
                first.prove_for_merge(&[pair[0].load()?, pair[1].load()?], merge.authority())?;
            Ok((TreeProof { public, proof }, metrics))
        },
        |_, metrics| {
            first_metrics.push(json!(metrics));
            report["first_aggregates"] = json!(first_metrics);
            write_json(&out.join("report.json"), &report)
        },
    )?;
    let first_wall_ms = ms(first_start);
    report["first_aggregation_wall_ms"] = json!(first_wall_ms);
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
    let valid_pair = layer[0].load()?;
    ensure!(
        verifier
            .verify(&valid_pair.proof, &valid_pair.public)
            .is_err(),
        "first proof accepted as a merge proof"
    );
    progress.message("Checking merge authority");
    ensure!(
        merge.prove(&[foreign_pair, valid_pair]).is_err(),
        "foreign carried authority accepted"
    );
    validation_ms += ms(t);

    let mut levels = Vec::new();
    let mut merge_level_wall_ms = Vec::new();
    let mut merge_times = Vec::new();
    while layer.len() > 1 {
        ensure!(
            merge.export_verifier_key()? == key,
            "merge key changed between levels"
        );
        let mut nodes = Vec::new();
        let started = Instant::now();
        let next = prove_pairs(
            &layer,
            args.parallel_nodes,
            &progress,
            &node_dir,
            levels.len() + 2,
            |pair| {
                let (proof, metrics) = merge.prove(&[pair[0].load()?, pair[1].load()?])?;
                verifier.verify(&proof.proof, &proof.public)?;
                Ok((proof, metrics))
            },
            |proof, metrics| {
                merge_times.push(metrics.aggregation_wall_ms);
                nodes.push(json!({"children":proof.public.children.len(),"metrics":metrics}));
                Ok(())
            },
        )?;
        let digest = verifier_key_digest(&merge.export_verifier_key()?);
        let level_ms = ms(started);
        merge_level_wall_ms.push(level_ms);
        levels.push(json!({"verifier_digest":digest, "wall_ms":level_ms, "nodes":nodes}));
        report["merge_levels"] = json!(levels);
        write_json(&out.join("report.json"), &report)?;
        layer = next;
    }
    let mut proof = layer.pop().unwrap().load()?;
    fs::remove_dir_all(node_dir)?;
    progress.message("Encoding and checking the final proof");
    let encoding_start = Instant::now();
    report["final_uncompressed_proof_bytes"] = json!(proof.proof.len());
    proof.proof = compact_aggregate_proof(&proof.proof)?;
    report["final_encoding_ms"] = json!(ms(encoding_start));
    report["final_proof_bytes"] = json!(proof.proof.len());
    ensure!(
        proof.public == expected,
        "final statement differs from the ordered children"
    );
    let t = Instant::now();
    let negative_checks = negative_checks(&verifier, &proof)?;
    validation_ms += ms(t);
    fs::write(out.join("aggregate.proof"), &proof.proof)?;
    fs::write(out.join("verifier.key"), &key)?;
    write_json(&out.join("statement.json"), &proof.public)?;
    write_json(&out.join("trusted.json"), &trusted)?;
    drop(merge);
    drop(verifier);
    let t = Instant::now();
    progress.message("Verifying the root in a fresh process");
    let output = Command::new(std::env::current_exe()?)
        .args(["--verify", "--threads", &args.threads.to_string(), "--out"])
        .arg(out)
        .output()?;
    let wall_ms = ms(t);
    // Both prepared keys and decoded children were ready at first_start. Leave
    // the two rejection-test intervals out of the receipt-to-verification time.
    let aggregation_to_verification_ms =
        ms(first_start) - (validation_ms - validation_before_aggregation_ms);
    ensure!(
        output.status.success(),
        "fresh verifier failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    report["fresh_verifier"] = serde_json::from_slice::<Value>(&output.stdout)?;
    report["fresh_verifier_wall_ms"] = json!(wall_ms);
    report["prepared_aggregation_to_fresh_verification_ms"] = json!(aggregation_to_verification_ms);
    report["negative_checks"] = json!(negative_checks);
    report["invalid_child_statement_rejected"] = json!(true);
    report["invalid_child_proof_rejected"] = json!(true);
    report["foreign_authority_rejected"] = json!(true);
    report["same_key_recursion"] = json!(levels.len() >= 2);
    report["acceptance_pass"] = json!(args.batch_size == 64 && levels.len() == 5);
    let run_ms = ms(start);
    report["run_wall_ms"] = json!(run_ms);
    report["validation_overhead_ms"] = json!(validation_ms);
    report["critical_path_ms"] = json!(run_ms - validation_ms);
    report["peak_rss_bytes"] = json!(peak_rss());
    report["merge_times_ms"] = json!(statistics(merge_times));
    write_json(&out.join("report.json"), &report)?;
    finish_run(scratch, destination)?;
    progress.finish();
    let merge_timings = merge_level_wall_ms
        .iter()
        .map(|time| format!("{:.2} s", time / 1000.0))
        .collect::<Vec<_>>()
        .join(", ");
    eprintln!("\nWall time");
    eprintln!(
        "  Setup       {:.2} s",
        (child_setup_ms + first_setup_ms + merge_setup_ms) / 1000.0
    );
    eprintln!(
        "  Children    {:.2} s  (up to {parallel_children} at once)",
        child_wall_ms / 1000.0
    );
    eprintln!(
        "  Aggregation {:.2} s  (ready children to verified root)",
        aggregation_to_verification_ms / 1000.0
    );
    eprintln!(
        "    Pairs {:.2} s  ·  Merge levels {merge_timings}  ·  Verify {wall_ms:.0} ms",
        first_wall_ms / 1000.0
    );
    eprintln!(
        "  Total       {:.2} s  (includes {:.2} s of rejection checks)",
        run_ms / 1000.0,
        validation_ms / 1000.0
    );
    if args.json || !io::stdout().is_terminal() {
        println!(
            "{}",
            json!({"children":args.batch_size,"merge_levels":levels.len(),"proof_bytes":proof.proof.len(),"same_key_recursion":report["same_key_recursion"],"acceptance_pass":report["acceptance_pass"],"report":report_path, "parallel_children":parallel_children, "child_stage_wall_ms":child_wall_ms, "aggregation_to_verification_ms":aggregation_to_verification_ms,"run_wall_ms":run_ms})
        );
    } else if let Some(path) = report_path {
        eprintln!("  Report      {}", path.display());
    }
    Ok(())
}

fn finish_run(scratch: tempfile::TempDir, destination: Option<&Path>) -> Result<()> {
    if let Some(path) = destination {
        fs::rename(scratch.path(), path)?;
    } else {
        scratch.close()?;
    }
    Ok(())
}

fn prove_pairs<T: Sync>(
    inputs: &[T],
    limit: usize,
    progress: &TreeProgress,
    node_dir: &Path,
    level: usize,
    prove: impl Fn(&[T; 2]) -> Result<(TreeProof, AggregationMetrics)> + Sync,
    mut record: impl FnMut(&StoredProof<AggregatePublic>, AggregationMetrics) -> Result<()>,
) -> Result<Vec<StoredProof<AggregatePublic>>> {
    let (pairs, tail) = inputs.as_chunks::<2>();
    ensure!(tail.is_empty(), "incomplete aggregate pair");
    let mut output = Vec::with_capacity(pairs.len());
    for group in pairs.chunks(limit) {
        let base = output.len();
        let nodes = group
            .par_iter()
            .enumerate()
            .map(|(i, pair)| {
                progress.track(level, base + i, || {
                    let (proof, metrics) = prove(pair)?;
                    Ok((
                        StoredProof::write(node_dir, level, base + i, proof.public, &proof.proof)?,
                        metrics,
                    ))
                })
            })
            .collect::<Result<Vec<_>>>()?;
        for (proof, metrics) in nodes {
            record(&proof, metrics)?;
            output.push(proof);
        }
    }
    Ok(output)
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
