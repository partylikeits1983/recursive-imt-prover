//! Replay a recursive merge on two saved tree-demo aggregates.
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::Parser;
use imt_flock_backend::{HashBackend, WHIR_FOLD, WHIR_LOG_INV_RATE};
use mimalloc::MiMalloc;
use recursive_imt_prover::{
    binary::{
        IMT_DEPTH,
        aggregation_tree::{TreeProof, cyclic::PreparedCyclicMerge},
        engine::Settings,
        veil::{
            aggregate::{PreparedMaskedAggregate, StatementFormat},
            child,
            parameters::Parameters,
        },
    },
    files::{read_bounded, read_json},
};
use serde_json::json;
use sha3::{Digest, Keccak256};

#[global_allocator]
static ALLOCATOR: MiMalloc = MiMalloc;

#[derive(Parser)]
struct Args {
    /// Directory containing aggregate.proof and statement.json for the left subtree.
    #[cfg_attr(
        feature = "opening-bench",
        arg(required_unless_present = "profile_fixed_columns")
    )]
    #[cfg_attr(not(feature = "opening-bench"), arg(required = true))]
    left: Option<PathBuf>,
    /// Directory for the right subtree, with the same number of leaves.
    #[cfg_attr(
        feature = "opening-bench",
        arg(required_unless_present = "profile_fixed_columns")
    )]
    #[cfg_attr(not(feature = "opening-bench"), arg(required = true))]
    right: Option<PathBuf>,
    #[arg(long, default_value = "3", value_parser = clap::value_parser!(u32).range(1..))]
    repetitions: u32,
    /// Use the child verifier authority for packed masked leaves.
    #[arg(long)]
    packed_lanes: bool,
    #[cfg(feature = "opening-bench")]
    #[arg(long)]
    compare_openings: bool,
    /// Profile fixed preprocessing using the same production merge setup.
    #[cfg(feature = "opening-bench")]
    #[arg(long, conflicts_with = "compare_openings")]
    profile_fixed_columns: bool,
}

fn read_tree(path: &Path) -> Result<TreeProof> {
    Ok(TreeProof {
        proof: read_bounded(&path.join("aggregate.proof"), 16 << 20)?,
        public: read_json(&path.join("statement.json"))?,
    })
}

fn prepare_merge(child_protocol: &str) -> Result<PreparedCyclicMerge> {
    let settings = Settings {
        depth: IMT_DEPTH,
        batch_size: 2,
        log_inv_rate: WHIR_LOG_INV_RATE,
        fold: WHIR_FOLD,
        max_codeword_cells: 1 << 29,
        ..Settings::default()
    };
    let first = PreparedMaskedAggregate::with_child_protocol(
        &settings,
        Parameters::default(),
        HashBackend::Checkpoint,
        StatementFormat::CyclicPair,
        child_protocol,
    )?;
    let first_verifier = first.cyclic_verifier()?;
    drop(first);
    PreparedCyclicMerge::new(first_verifier)
}

fn main() -> Result<()> {
    let args = Args::parse();
    let child_protocol = if args.packed_lanes {
        child::PACKED_PROTOCOL
    } else {
        child::PROTOCOL
    };
    #[cfg(feature = "opening-bench")]
    if args.profile_fixed_columns {
        println!(
            "{}",
            serde_json::to_string_pretty(&prepare_merge(child_protocol)?.fixed_column_profile())?
        );
        return Ok(());
    }
    let children = [
        read_tree(args.left.as_deref().context("missing left subtree")?)?,
        read_tree(args.right.as_deref().context("missing right subtree")?)?,
    ];
    let merge = prepare_merge(child_protocol)?;
    #[cfg(feature = "opening-bench")]
    if args.compare_openings {
        let mut merge = merge;
        println!(
            "{}",
            serde_json::to_string_pretty(&merge.compare_openings(&children, args.repetitions)?)?
        );
        return Ok(());
    }
    for _ in 0..args.repetitions {
        let (parent, metrics) = merge.prove(&children)?;
        let compact = imt_flock_backend::compact_aggregate_proof(&parent.proof)?;
        println!(
            "{}",
            json!({
                "metrics": metrics,
                "compressed_bytes": compact.len(),
                "zero_bytes": compact.iter().filter(|&&byte| byte == 0).count(),
                "threads": rayon::current_num_threads(),
                "proof_keccak256": hex::encode(Keccak256::digest(&parent.proof)),
            })
        );
    }
    Ok(())
}
