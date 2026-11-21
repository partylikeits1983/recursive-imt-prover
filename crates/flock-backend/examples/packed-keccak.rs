//! Compare the same authenticated Keccak statement with different kernels and PCS layouts.
use anyhow::{Result, ensure};
use clap::Parser;
use imt_flock_backend::checkpoint_keccak::{
    State,
    packed::{Batch, Kernel, Openings, Proof, Schedule, Statement},
};
use serde_json::json;
use std::{env, fs, path::PathBuf, time::Instant};

#[derive(Parser)]
struct Args {
    log: usize,
    schedule: String,
    kernel: String,
    mode: String,
    repeats: usize,
    #[arg(long)]
    recursive: bool,
    #[arg(long, default_value_t = imt_flock_backend::WHIR_LOG_INV_RATE)]
    log_inv_rate: usize,
    /// Little-endian Keccak states (25 u64s each). Remaining slots start at zero.
    #[arg(long)]
    inputs: Option<PathBuf>,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let log = args.log;
    ensure!(
        !args.recursive || cfg!(feature = "opening-bench"),
        "--recursive requires --features opening-bench"
    );
    let schedule = match args.schedule.as_str() {
        "one" => Schedule::OneRound,
        "full" => Schedule::Full,
        "mid" => Schedule::Midpoint,
        _ => anyhow::bail!("unknown schedule"),
    };
    let kernel = match args.kernel.as_str() {
        "scalar" => Kernel::Scalar,
        "packed" => Kernel::Packed16,
        _ => anyhow::bail!("unknown kernel"),
    };
    let mode = match args.mode.as_str() {
        "separate" => Openings::Separate,
        "joint" => Openings::Joint,
        _ => anyhow::bail!("unknown opening mode"),
    };
    let repeats = args.repeats;
    ensure!(repeats > 0, "need at least one repeat");
    let batch = Batch::with_rate(log, schedule, kernel, mode, args.log_inv_rate)?;
    let (inputs, active): (Vec<State>, usize) = if let Some(path) = args.inputs {
        let bytes = fs::read(path)?;
        let (rows, tail) = bytes.as_chunks::<200>();
        ensure!(
            tail.is_empty() && !rows.is_empty() && rows.len() <= 1 << log,
            "invalid Keccak state file"
        );
        let mut v: Vec<_> = rows
            .iter()
            .map(|row| {
                core::array::from_fn(|j| {
                    u64::from_le_bytes(row[8 * j..8 * j + 8].try_into().unwrap())
                })
            })
            .collect();
        v.resize(1 << log, [0; 25]);
        (v, rows.len())
    } else {
        let v = (0..1 << log)
            .map(|i| {
                core::array::from_fn(|j| {
                    ((i * 25 + j + 1) as u64)
                        .wrapping_mul(0x9e3779b97f4a7c15)
                        .rotate_left((j * 11) as u32)
                })
            })
            .collect();
        (v, 1 << log)
    };
    for _ in 0..repeats {
        let start = Instant::now();
        let (statement, proof, t) = batch.prove(&inputs, b"packed-keccak-benchmark")?;
        let prove_s = start.elapsed().as_secs_f64();
        let root = postcard::to_allocvec(&statement)?;
        let bytes = postcard::to_allocvec(&proof)?;
        let start = Instant::now();
        let statement: Statement = postcard::from_bytes(&root)?;
        let proof: Proof = postcard::from_bytes(&bytes)?;
        batch.verify(&statement, &proof, b"packed-keccak-benchmark")?;
        let verify_s = start.elapsed().as_secs_f64();
        #[cfg(feature = "opening-bench")]
        let circuit = if args.recursive {
            Some(batch.recursive_cost(&statement, &proof, b"packed-keccak-benchmark")?)
        } else {
            None
        };
        #[cfg(not(feature = "opening-bench"))]
        let circuit: Option<()> = None;
        println!(
            "{}",
            json!({
                "log_n": log, "active": active, "log_inv_rate": args.log_inv_rate,
                "schedule": args.schedule,
                "kernel": args.kernel,
                "pcs": args.mode,
                "threads": env::var("RAYON_NUM_THREADS").ok(),
                "conditional_algebraic_bits": batch.conditional_algebraic_bits,
                "prove_s": prove_s,
                "witness_commit_s": t.commit.as_secs_f64(),
                "reduce_s": t.reduction.as_secs_f64(),
                "open_s": t.opening.as_secs_f64(),
                "decode_verify_s": verify_s,
                "recursive_circuit": circuit,
                "non_pcs_scalars": proof.reduction_scalars(),
                "statement_bytes": root.len(),
                "proof_bytes": bytes.len()
            })
        );
    }
    Ok(())
}
