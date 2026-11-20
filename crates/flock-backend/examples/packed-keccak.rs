//! Compare the same authenticated Keccak statement with different kernels and PCS layouts.
use anyhow::{Result, ensure};
use imt_flock_backend::checkpoint_keccak::{
    State,
    packed::{Batch, Kernel, Openings, Proof, Schedule, Statement},
};
use serde_json::json;
use std::{env, time::Instant};

fn main() -> Result<()> {
    let args: Vec<_> = env::args().skip(1).collect();
    let recursive = args.last().is_some_and(|v| v == "--recursive");
    ensure!(
        !recursive || cfg!(feature = "opening-bench"),
        "--recursive requires --features opening-bench"
    );
    ensure!(
        args.len() == 5 + usize::from(recursive),
        "usage: packed-keccak LOG_N one|full|mid scalar|packed separate|joint REPEATS [--recursive]"
    );
    let log: usize = args[0].parse()?;
    let schedule = match args[1].as_str() {
        "one" => Schedule::OneRound,
        "full" => Schedule::Full,
        "mid" => Schedule::Midpoint,
        _ => anyhow::bail!("unknown schedule"),
    };
    let kernel = match args[2].as_str() {
        "scalar" => Kernel::Scalar,
        "packed" => Kernel::Packed16,
        _ => anyhow::bail!("unknown kernel"),
    };
    let mode = match args[3].as_str() {
        "separate" => Openings::Separate,
        "joint" => Openings::Joint,
        _ => anyhow::bail!("unknown opening mode"),
    };
    let repeats: usize = args[4].parse()?;
    ensure!(repeats > 0, "need at least one repeat");
    let batch = Batch::new(log, schedule, kernel, mode)?;
    let inputs: Vec<State> = (0..1 << log)
        .map(|i| {
            core::array::from_fn(|j| {
                ((i * 25 + j + 1) as u64)
                    .wrapping_mul(0x9e3779b97f4a7c15)
                    .rotate_left((j * 11) as u32)
            })
        })
        .collect();
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
        let circuit = if recursive {
            Some(batch.recursive_cost(&statement, &proof, b"packed-keccak-benchmark")?)
        } else {
            None
        };
        #[cfg(not(feature = "opening-bench"))]
        let circuit: Option<()> = None;
        println!(
            "{}",
            json!({
                "log_n": log,
                "schedule": args[1],
                "kernel": args[2],
                "pcs": args[3],
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
