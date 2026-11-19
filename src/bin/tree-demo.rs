#[path = "tree-demo/progress.rs"]
mod progress;
#[path = "tree-demo/resources.rs"]
mod resources;
#[path = "tree-demo/schedule.rs"]
mod schedule;
#[path = "tree-demo/storage.rs"]
mod storage;

use std::{
    fs,
    io::{self, IsTerminal},
    num::NonZeroUsize,
    path::{Path, PathBuf},
    process::Command,
    sync::Arc,
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
use rayon::ThreadPoolBuilder;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use recursive_imt_prover::{
    benchmark::{environment, ms, statistics},
    binary::{
        IMT_DEPTH, MAX_CHILDREN,
        aggregation_tree::{
            TreeProof,
            cyclic::{CyclicVerifier, PROTOCOL, PreparedCyclicMerge},
        },
        cli::fixtures,
        engine::Settings,
        relation::{AggregatePublic, ClientPublic},
        veil::{
            aggregate::{
                AggregationMetrics, MaskedChildInput, PreparedMaskedAggregate, StatementFormat,
            },
            child::{MaskedMembershipProof, PreparedMembership},
            parameters::Parameters,
        },
    },
    files::{read_bounded, read_json, write_json},
};

use progress::TreeProgress;
use resources::{ProcessMonitor, print_machine};
use schedule::{Input, Limits};
use storage::{StoredProof, scratch_directory};

#[global_allocator]
static ALLOCATOR: MiMalloc = MiMalloc;

#[derive(Parser)]
#[command(
    name = "cargo prove",
    bin_name = "cargo prove",
    about = "Prove a tree of independent child proofs and verify its root. Temporary proofs are written to disk and cleaned up.",
    after_help = "Examples:\n  cargo prove -j 3                     Prove a 64-child tree, up to three proofs at once across levels\n  cargo prove -n 8 -j 3                Prove a smaller eight-child tree\n  cargo prove -j 3 --parallel-nodes 1  Allow one aggregate within the three-proof budget"
)]
struct Args {
    /// Number of child proofs (4, 8, 16, 32 or 64).
    #[arg(short = 'n', long, default_value_t = MAX_CHILDREN)]
    batch_size: usize,
    /// Total CPU worker threads shared by all proofs.
    #[arg(long, default_value_t = available_parallelism().map_or(1, usize::from).min(64))]
    threads: usize,
    /// Total concurrent proofs across all levels.
    #[arg(short = 'j', long, default_value = "2")]
    jobs: NonZeroUsize,
    /// Limit child proofs within the shared --jobs budget.
    #[arg(long)]
    parallel_children: Option<NonZeroUsize>,
    /// Limit aggregate proofs across all levels within the shared --jobs budget.
    #[arg(long)]
    parallel_nodes: Option<NonZeroUsize>,
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

impl Args {
    fn proof_limits(&self) -> Limits {
        let jobs = self.jobs.get().min(self.threads);
        let limit = |setting: Option<NonZeroUsize>, width: usize| {
            setting.map_or(jobs, NonZeroUsize::get).min(jobs).min(width)
        };
        Limits {
            jobs,
            leaves: limit(self.parallel_children, self.batch_size),
            aggregates: limit(self.parallel_nodes, self.batch_size - 1),
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Trusted {
    protocol: String,
    identity: String,
    verifier_digest: [u8; 32],
}

#[derive(Serialize)]
struct ChildMetrics {
    witness_ms: f64,
    prove_ms: f64,
    decode_verify_ms: f64,
    proof_bytes: usize,
}

enum Proof {
    Leaf(StoredProof<ClientPublic>, ChildMetrics),
    Aggregate(StoredProof<AggregatePublic>, AggregationMetrics),
}

struct NodeMetrics {
    index: usize,
    started: Instant,
    finished: Instant,
    proof_ms: f64,
    report: Value,
}

fn level_wall_ms(nodes: &[NodeMetrics]) -> f64 {
    let started = nodes.iter().map(|node| node.started).min().unwrap();
    let finished = nodes.iter().map(|node| node.finished).max().unwrap();
    finished.duration_since(started).as_secs_f64() * 1000.0
}

fn node_reports(nodes: &[NodeMetrics]) -> Vec<&Value> {
    nodes.iter().map(|node| &node.report).collect()
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
        return verify_files(
            args.out.as_deref().unwrap_or(Path::new("run/cyclic-tree")),
            ProcessMonitor::start(|_| {}),
        );
    }
    ensure!(
        args.batch_size.is_power_of_two() && (4..=MAX_CHILDREN).contains(&args.batch_size),
        "tree batch size must be 4, 8, 16, 32 or 64"
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
    let limits = args.proof_limits();
    eprintln!("Preparing circuits…");
    let environment = environment();
    print_machine(&environment, args.threads);
    let progress = Arc::new(TreeProgress::new(args.batch_size));
    let display = Arc::clone(&progress);
    let monitor = ProcessMonitor::start(move |peaks| display.update_peaks(peaks));
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
        "protocol": PROTOCOL, "environment": environment, "depth": IMT_DEPTH,
        "batch_size": args.batch_size, "jobs": limits.jobs, "parallel_children": limits.leaves, "parallel_nodes": limits.aggregates,
        "field": "Poly64/Poly192", "hash": "Keccak-256", "bound": "Johnson",
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
    if args.setup_only {
        let peaks = monitor.finish();
        peaks.record(&mut report);
        write_json(&out.join("report.json"), &report)?;
        finish_run(scratch, destination)?;
        let mut summary =
            json!({"setup_only":true,"report":report_path,"setup_ms":report["setup_ms"]});
        peaks.record(&mut summary);
        peaks.print();
        println!("{summary}");
        return Ok(());
    }
    write_json(&out.join("report.json"), &report)?;
    let node_dir = out.join("nodes");
    fs::create_dir(&node_dir)?;
    let t = Instant::now();
    let notes = fixtures(IMT_DEPTH, args.batch_size)?;
    report["fixture_ms"] = json!(ms(t));
    let expected = AggregatePublic {
        children: notes.iter().map(|(public, _)| public.clone()).collect(),
    };
    let mut timings: Vec<Vec<NodeMetrics>> =
        (0..=args.batch_size.ilog2()).map(|_| Vec::new()).collect();
    let mut sample_leaves = [None, None];
    let mut sample_pair = None;
    progress.show();
    let tree_start = Instant::now();
    let root = schedule::run(
        notes,
        limits,
        |node, input| {
            progress.track(node.level, node.index, || match input {
                Input::Leaf((public, witness)) => {
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
                    let metrics = ChildMetrics {
                        witness_ms,
                        prove_ms,
                        decode_verify_ms: ms(t),
                        proof_bytes: bytes.len(),
                    };
                    let stored = StoredProof::write(&node_dir, 0, node.index, public, &bytes)?;
                    Ok(Proof::Leaf(stored, metrics))
                }
                Input::Pair([Proof::Leaf(left, _), Proof::Leaf(right, _)]) => {
                    let (public, proof, metrics) =
                        first.prove_for_merge(&[left.load()?, right.load()?], merge.authority())?;
                    let stored = StoredProof::write(&node_dir, 1, node.index, public, &proof)?;
                    Ok(Proof::Aggregate(stored, metrics))
                }
                Input::Pair([Proof::Aggregate(left, _), Proof::Aggregate(right, _)]) => {
                    let (proof, metrics) = merge.prove(&[left.load()?, right.load()?])?;
                    verifier.verify(&proof.proof, &proof.public)?;
                    let stored = StoredProof::write(
                        &node_dir,
                        node.level,
                        node.index,
                        proof.public,
                        &proof.proof,
                    )?;
                    Ok(Proof::Aggregate(stored, metrics))
                }
                Input::Pair(_) => unreachable!("tree siblings use the same proof type"),
            })
        },
        |node, proof, started, finished| {
            let (proof_ms, mut metrics) = match proof {
                Proof::Leaf(proof, metrics) => {
                    if node.index < sample_leaves.len() {
                        sample_leaves[node.index] = Some(proof.clone());
                    }
                    (metrics.witness_ms + metrics.prove_ms, json!(metrics))
                }
                Proof::Aggregate(proof, metrics) => {
                    let details = if node.level == 1 {
                        if node.index == 0 {
                            sample_pair = Some(proof.clone());
                        }
                        json!(metrics)
                    } else {
                        json!({"children": proof.public.children.len(), "metrics": metrics})
                    };
                    (metrics.aggregation_wall_ms, details)
                }
            };
            metrics["started_ms"] =
                json!(started.duration_since(tree_start).as_secs_f64() * 1000.0);
            metrics["finished_ms"] =
                json!(finished.duration_since(tree_start).as_secs_f64() * 1000.0);
            timings[node.level].push(NodeMetrics {
                index: node.index,
                started,
                finished,
                proof_ms,
                report: metrics,
            });
        },
    )?;
    let tree_wall_ms = ms(tree_start);
    drop(child);
    for level in &mut timings {
        level.sort_unstable_by_key(|node| node.index);
    }
    let last_leaf = timings[0].iter().map(|node| node.finished).max().unwrap();
    let child_wall_ms = level_wall_ms(&timings[0]);
    let first_wall_ms = level_wall_ms(&timings[1]);
    let client_count = timings[0].len();
    let client_average_ms =
        timings[0].iter().map(|node| node.proof_ms).sum::<f64>() / client_count as f64;
    let aggregate_count = timings[1..].iter().map(Vec::len).sum::<usize>();
    let aggregate_average_ms = timings[1..]
        .iter()
        .flatten()
        .map(|node| node.proof_ms)
        .sum::<f64>()
        / aggregate_count as f64;
    let merge_times = timings[2..]
        .iter()
        .flatten()
        .map(|node| node.proof_ms)
        .collect();
    report["proof_tree_wall_ms"] = json!(tree_wall_ms);
    report["child_stage_wall_ms"] = json!(child_wall_ms);
    report["first_aggregation_wall_ms"] = json!(first_wall_ms);
    report["children"] = json!(node_reports(&timings[0]));
    report["first_aggregates"] = json!(node_reports(&timings[1]));
    let merge_level_wall_ms: Vec<_> = timings[2..]
        .iter()
        .map(|nodes| level_wall_ms(nodes))
        .collect();
    let levels: Vec<_> = timings[2..].iter().zip(&merge_level_wall_ms).map(|(nodes, wall_ms)| {
        json!({"verifier_digest": trusted.verifier_digest, "wall_ms": wall_ms, "nodes": node_reports(nodes)})
    }).collect();
    report["merge_levels"] = json!(levels);
    write_json(&out.join("report.json"), &report)?;

    let t = Instant::now();
    progress.message("Checking child and authority rejection");
    let [left, right] = sample_leaves.map(Option::unwrap);
    check_authorities(
        &first,
        &merge,
        &verifier,
        &first_key,
        [left.load()?, right.load()?],
        sample_pair.unwrap().load()?,
    )?;
    let mut validation_ms = ms(t);
    drop(first);
    ensure!(
        merge.export_verifier_key()? == key,
        "merge key changed between levels"
    );
    let Proof::Aggregate(root, _) = root else {
        unreachable!("a tree with at least four leaves has an aggregate root");
    };
    let mut proof = root.load()?;
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
    // Rejection checks run after the proof tree completes, outside the scheduler.
    let aggregation_to_verification_ms = ms(last_leaf) - validation_ms;
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
    let peaks = monitor.finish();
    peaks.record(&mut report);
    report["average_proof_ms"] =
        json!({"client":client_average_ms,"aggregation":aggregate_average_ms});
    report["merge_times_ms"] = json!(statistics(merge_times));
    write_json(&out.join("report.json"), &report)?;
    finish_run(scratch, destination)?;
    progress.finish(peaks);
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
        "  Proof tree  {:.2} s  (up to {} proofs across levels)",
        tree_wall_ms / 1000.0,
        limits.jobs,
    );
    eprintln!(
        "    Leaves {:.2} s  ·  Pairs {:.2} s  ·  Merges {merge_timings}  (spans can overlap)",
        child_wall_ms / 1000.0,
        first_wall_ms / 1000.0,
    );
    eprintln!(
        "  All leaves ready to verified root {:.2} s  (fresh verifier {wall_ms:.0} ms)",
        aggregation_to_verification_ms / 1000.0,
    );
    eprintln!(
        "  Total       {:.2} s  (includes {:.2} s of rejection checks)",
        run_ms / 1000.0,
        validation_ms / 1000.0
    );
    eprintln!("\nAverage time per proof");
    eprintln!(
        "  Client      {:.2} s  ({client_count} leaf proofs, witness + proving)",
        client_average_ms / 1000.0
    );
    eprintln!(
        "  Aggregation {:.2} s  ({aggregate_count} proofs across all pairs and merges)",
        aggregate_average_ms / 1000.0
    );
    peaks.print();
    if args.json || !io::stdout().is_terminal() {
        let mut summary = json!({
            "children": args.batch_size, "merge_levels": levels.len(), "proof_bytes": proof.proof.len(),
            "same_key_recursion": report["same_key_recursion"], "acceptance_pass": report["acceptance_pass"],
            "report": report_path, "jobs": limits.jobs,
            "parallel_children": limits.leaves, "parallel_nodes": limits.aggregates,
            "proof_tree_wall_ms": tree_wall_ms,
            "child_stage_wall_ms": child_wall_ms, "aggregation_to_verification_ms": aggregation_to_verification_ms,
            "run_wall_ms": run_ms, "average_proof_ms": report["average_proof_ms"]
        });
        peaks.record(&mut summary);
        println!("{summary}");
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

fn check_authorities(
    first: &PreparedMaskedAggregate,
    merge: &PreparedCyclicMerge,
    verifier: &CyclicVerifier,
    first_key: &[u8],
    original: [MaskedChildInput; 2],
    valid_pair: TreeProof,
) -> Result<()> {
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
    malformed[0].proof = MaskedMembershipProof::from_bytes(&bytes)?;
    ensure!(
        first
            .prove_for_merge(&malformed, merge.authority())
            .is_err(),
        "invalid child proof accepted"
    );
    drop(malformed);
    let mut foreign = merge.authority().clone();
    foreign.identity[0] ^= 1;
    let (public, proof, _) = first.prove_for_merge(&original, &foreign)?;
    let foreign_pair = TreeProof { public, proof };
    ensure!(
        CyclicVerifier::from_bytes(
            first_key,
            &verifier_key_digest(first_key),
            &first.identity()
        )
        .is_err(),
        "first authority accepted as merge authority"
    );
    ensure!(
        verifier
            .verify(&valid_pair.proof, &valid_pair.public)
            .is_err(),
        "first proof accepted as a merge proof"
    );
    ensure!(
        merge.prove(&[foreign_pair, valid_pair]).is_err(),
        "foreign carried authority accepted"
    );
    Ok(())
}

fn verify_files(directory: &Path, monitor: ProcessMonitor) -> Result<()> {
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
    let mut summary = json!({"verified":true,"children":public.children.len(),"setup_ms":setup_ms,"verify_ms":ms(t)});
    let peaks = monitor.finish();
    peaks.record(&mut summary);
    peaks.print();
    println!("{summary}");
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

#[cfg(test)]
mod tests {
    use super::{Args, Limits, Parser};

    #[test]
    fn proof_limits_share_one_budget() {
        let limits = |extra: &[&str]| {
            Args::parse_from(
                ["prove", "--threads", "8"]
                    .into_iter()
                    .chain(extra.iter().copied()),
            )
            .proof_limits()
        };
        let expected = |jobs, leaves, aggregates| Limits {
            jobs,
            leaves,
            aggregates,
        };
        assert_eq!(limits(&[]), expected(2, 2, 2));
        assert_eq!(limits(&["-j", "3"]), expected(3, 3, 3));
        assert_eq!(
            limits(&["-j", "3", "--parallel-nodes", "1"]),
            expected(3, 3, 1)
        );
        assert_eq!(
            limits(&["-j", "3", "--parallel-children", "1"]),
            expected(3, 1, 3)
        );
        assert_eq!(
            limits(&["-j", "3", "--parallel-nodes", "7"]),
            expected(3, 3, 3)
        );
        assert_eq!(limits(&["--jobs", "12"]), expected(8, 8, 8));
        assert_eq!(limits(&["-n", "4", "-j", "8"]), expected(8, 4, 3));
    }
}
