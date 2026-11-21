//! Prove the final 64-leaf root from two saved cyclic subtrees.
use std::{
    fs,
    path::{Path, PathBuf},
    time::Instant,
};

use anyhow::{Result, ensure};
use clap::Parser;
use imt_flock_backend::{MAX_VERIFIER_BYTES, compact_aggregate_proof, verifier_key_digest};
use mimalloc::MiMalloc;
use recursive_imt_prover::{
    benchmark::ms,
    binary::aggregation_tree::{
        RootVerifier, TreeProof, TreeStatement,
        cyclic::{self, TrustedVerifier},
        terminal::{MidpointProfile, PreparedTerminalMerge},
    },
    files::{read_bounded, read_json, write_json},
};
use serde_json::json;

#[global_allocator]
static ALLOCATOR: MiMalloc = MiMalloc;

#[derive(Parser)]
struct Args {
    left: PathBuf,
    right: PathBuf,
    #[arg(long)]
    child_key: PathBuf,
    /// Independently trusted metadata for the cyclic child verifier.
    #[arg(long)]
    child_trusted: PathBuf,
    /// A fresh directory for the verified terminal bundle.
    #[arg(long)]
    out: PathBuf,
    /// Commit the witness in the 32-word rows used by the paired opening.
    #[arg(long)]
    wide_witness: bool,
    /// Discharge witness and trusted wiring claims in one joint WHIR opening.
    #[arg(long, conflicts_with = "wide_witness")]
    shared_opening: bool,
    /// Use the 26-variable shared terminal profile with four-variable later folds.
    #[arg(long, conflicts_with_all = ["wide_witness", "shared_opening"])]
    four_variable_folds: bool,
    /// Verify both 12-round Keccak segments against one committed midpoint.
    #[arg(long, conflicts_with_all = ["wide_witness", "shared_opening", "four_variable_folds"])]
    midpoint: bool,
    /// Trusted midpoint terminal policy (default: strong). Comparison is for benchmarking.
    #[arg(long, value_enum, requires = "midpoint")]
    security_profile: Option<MidpointProfile>,
    /// Export padded Keccak input/midpoint/output lanes alongside the verified root.
    #[cfg(feature = "opening-bench")]
    #[arg(long, requires = "midpoint")]
    save_keccak_checkpoints: bool,
    /// Also replay the verified proof's bit readings in one paired WHIR opening.
    #[cfg(feature = "opening-bench")]
    #[arg(long, conflicts_with_all = ["shared_opening", "four_variable_folds", "midpoint"])]
    compare_paired_opening: bool,
    /// Reduce all current bit readings by sumcheck before the shared opening.
    #[cfg(feature = "opening-bench")]
    #[arg(long, requires = "compare_paired_opening")]
    reduce_readings: bool,
}

fn load_child(path: &Path) -> Result<TreeProof> {
    Ok(TreeProof {
        public: read_json(&path.join("statement.json"))?,
        proof: read_bounded(&path.join("aggregate.proof"), 16 << 20)?,
    })
}

fn main() -> Result<()> {
    let args = Args::parse();
    ensure!(
        !args.out.try_exists()?,
        "terminal output directory already exists"
    );
    let child_key = read_bounded(&args.child_key, MAX_VERIFIER_BYTES)?;
    let child_trust: TrustedVerifier = read_json(&args.child_trusted)?;
    ensure!(
        child_trust.protocol == cyclic::PROTOCOL,
        "incorrect child protocol"
    );
    let children = [load_child(&args.left)?, load_child(&args.right)?];
    let statement = TreeStatement::merge(
        &TreeStatement::from_public(&children[0].public)?,
        &TreeStatement::from_public(&children[1].public)?,
    )?;
    ensure!(
        usize::from(statement.count) == recursive_imt_prover::binary::MAX_CHILDREN,
        "expected two 32-leaf subtrees"
    );
    let start = Instant::now();
    let digest = &child_trust.verifier_digest;
    let identity = &child_trust.identity;
    let merge = if args.midpoint {
        PreparedTerminalMerge::with_midpoint_profile(
            &child_key,
            digest,
            identity,
            args.security_profile.unwrap_or_default(),
        )
    } else {
        let prepare = if args.four_variable_folds {
            PreparedTerminalMerge::with_four_variable_folds
        } else if args.shared_opening {
            PreparedTerminalMerge::with_shared_opening
        } else if args.wide_witness {
            PreparedTerminalMerge::with_wide_witness
        } else {
            PreparedTerminalMerge::new
        };
        prepare(&child_key, digest, identity)
    }?;
    let setup_ms = ms(start);
    let key = merge.export_verifier_key()?;
    let trust = TrustedVerifier {
        protocol: merge.protocol().to_owned(),
        identity: merge.identity(),
        verifier_digest: verifier_key_digest(&key),
    };
    #[cfg(feature = "opening-bench")]
    let (result, comparison) = if args.compare_paired_opening {
        let (result, captured) =
            imt_flock_backend::terminal_opening::record(|| merge.prove(&children))?;
        (result, Some((captured, merge.wiring_root()?)))
    } else {
        (merge.prove(&children)?, None)
    };
    #[cfg(not(feature = "opening-bench"))]
    let result = merge.prove(&children)?;
    let (root, metrics) = result;
    ensure!(
        TreeStatement::from_public(&root.public)? == statement,
        "incorrect ordered terminal root"
    );
    let geometry = serde_json::to_value(merge.geometry())?;

    let parent = args
        .out
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(parent)?;
    let staging = tempfile::Builder::new()
        .prefix(".terminal-merge-")
        .tempdir_in(parent)?;
    let dir = staging.path();
    #[cfg(feature = "opening-bench")]
    if args.save_keccak_checkpoints {
        let file = fs::File::create(dir.join("keccak-checkpoints.bin"))?;
        merge.write_keccak_checkpoints(&children, std::io::BufWriter::new(file))?;
    }
    drop(merge);
    let proof = compact_aggregate_proof(&root.proof)?;
    let RootVerifier::Terminal(verifier) = RootVerifier::from_trusted(&key, &trust)? else {
        anyhow::bail!("expected terminal verifier");
    };
    let bound = verifier.verify_statement_with_bound(&proof, &statement)?;
    fs::write(dir.join("aggregate.proof"), &proof)?;
    fs::write(dir.join("verifier.key"), &key)?;
    write_json(&dir.join("statement.json"), &root.public)?;
    write_json(&dir.join("trusted.json"), &trust)?;
    let sizes = json!({"proof_bytes": proof.len(), "raw_proof_bytes": root.proof.len(), "zero_bytes": proof.iter().filter(|&&b| b == 0).count()});
    let summary = json!({"protocol": trust.protocol, "terminal_conditional_algebraic_bits": bound, "statement": hex::encode(statement.bytes()), "setup_ms": setup_ms, "metrics": metrics, "sizes": sizes, "threads": rayon::current_num_threads()});
    write_json(
        &dir.join("report.json"),
        &json!({"summary": summary, "child_verifier_digest": child_trust.verifier_digest, "geometry": geometry}),
    )?;
    #[cfg(feature = "opening-bench")]
    if let Some((captured, wiring_root)) = comparison {
        let comparison = imt_flock_backend::terminal_opening::compare_recorded(
            captured,
            wiring_root,
            args.reduce_readings,
        )?;
        fs::write(dir.join("shared-opening.proof"), &comparison.opening_bytes)?;
        if let Some(trace) = &comparison.batch_trace {
            write_json(&dir.join("bit-batch-trace.json"), trace)?;
        }
        write_json(&dir.join("opening-comparison.json"), &comparison)?;
    }
    fs::rename(dir, &args.out)?;
    println!("{summary}");
    Ok(())
}
