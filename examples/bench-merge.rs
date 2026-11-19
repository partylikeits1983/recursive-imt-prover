//! Replay a recursive merge on two saved tree-demo aggregates.
use std::path::{Path, PathBuf};

use anyhow::Result;
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
            parameters::Parameters,
        },
    },
    files::{read_bounded, read_json},
};
use serde_json::json;

#[global_allocator]
static ALLOCATOR: MiMalloc = MiMalloc;

#[derive(Parser)]
struct Args {
    /// Directory containing aggregate.proof and statement.json for the left subtree.
    left: PathBuf,
    /// Directory for the right subtree, with the same number of leaves.
    right: PathBuf,
    #[arg(long, default_value = "3", value_parser = clap::value_parser!(u32).range(1..))]
    repetitions: u32,
}

fn read_tree(path: &Path) -> Result<TreeProof> {
    Ok(TreeProof {
        proof: read_bounded(&path.join("aggregate.proof"), 16 << 20)?,
        public: read_json(&path.join("statement.json"))?,
    })
}

fn main() -> Result<()> {
    let args = Args::parse();
    let children = [read_tree(&args.left)?, read_tree(&args.right)?];
    let settings = Settings {
        depth: IMT_DEPTH,
        batch_size: 2,
        log_inv_rate: WHIR_LOG_INV_RATE,
        fold: WHIR_FOLD,
        max_codeword_cells: 1 << 29,
        ..Settings::default()
    };
    let first = PreparedMaskedAggregate::with_format(
        &settings,
        Parameters::default(),
        HashBackend::Blake3,
        StatementFormat::CyclicPair,
    )?;
    let first_verifier = first.cyclic_verifier()?;
    drop(first);
    let merge = PreparedCyclicMerge::new(first_verifier)?;
    for _ in 0..args.repetitions {
        let (parent, metrics) = merge.prove(&children)?;
        println!(
            "{}",
            json!({
                "metrics": metrics,
                "threads": rayon::current_num_threads(),
                "proof_blake3": blake3::hash(&parent.proof).to_hex().to_string(),
            })
        );
    }
    Ok(())
}
