//! Non-hiding committed Keccak component benchmark; not aggregate integration.
use std::{env, fs, path::Path, process::Command, time::Instant};

use anyhow::{Result, ensure};
use imt_flock_backend::checkpoint_keccak::{CommittedBatch, CommittedProof, State, Statement};
use serde::Serialize;
use serde_json::{Value, json};

const CONTEXT: &[u8] = b"checkpoint-keccak-component-benchmark-v1";
const MAX_ARTIFACT_BYTES: u64 = 16 << 20;

#[derive(Serialize)]
struct Sample {
    phase: &'static str,
    prove_ms: f64,
    decode_verify_ms: f64,
    proof_bytes: usize,
    statement_bytes: usize,
}

fn main() -> Result<()> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    if args.first().is_some_and(|v| v == "--verify") {
        ensure!(
            args.len() == 2,
            "usage: checkpoint-keccak --verify directory"
        );
        return fresh_verify(Path::new(&args[1]));
    }
    ensure!(
        args.len() <= 3,
        "usage: checkpoint-keccak [power-of-two count] [samples] [fresh output directory]"
    );
    let count: usize = args.first().map_or(Ok(256), |v| v.parse())?;
    let samples: usize = args.get(1).map_or(Ok(3), |v| v.parse())?;
    ensure!(
        count.is_power_of_two() && count <= 1 << 20,
        "invalid batch count"
    );
    ensure!((1..=20).contains(&samples), "invalid sample count");
    let directory = args.get(2).map(Path::new);
    if let Some(path) = directory {
        fs::create_dir(path)?;
    }
    let start = Instant::now();
    let inputs = (0..count)
        .map(|i| {
            core::array::from_fn(|j| {
                ((i * 25 + j + 1) as u64)
                    .wrapping_mul(0x9e3779b97f4a7c15)
                    .rotate_left((j * 11) as u32)
            })
        })
        .collect::<Vec<State>>();
    let witness_ms = ms(start);
    let start = Instant::now();
    let scheme = CommittedBatch::new(count.trailing_zeros() as usize)?;
    let setup_ms = ms(start);
    let mut measurements = Vec::new();
    for i in 0..samples {
        let start = Instant::now();
        let (statement, proof) = scheme.prove(&inputs, CONTEXT)?;
        let prove_ms = ms(start);
        let bytes = postcard::to_allocvec(&proof)?;
        let statement_bytes = postcard::to_allocvec(&statement)?;
        let start = Instant::now();
        let restored: CommittedProof = postcard::from_bytes(&bytes)?;
        scheme.verify(&statement, &restored, CONTEXT)?;
        let decode_verify_ms = ms(start);
        if i == 0
            && let Some(path) = directory
        {
            fs::write(path.join("statement.bin"), &statement_bytes)?;
            fs::write(path.join("proof.bin"), &bytes)?;
        }
        eprintln!(
            "Keccak batch {count}, sample {}: prove {prove_ms:.1} ms, verify {decode_verify_ms:.1} ms",
            i + 1
        );
        measurements.push(Sample {
            phase: if i == 0 { "cold-first-proof" } else { "warm" },
            prove_ms,
            decode_verify_ms,
            proof_bytes: bytes.len(),
            statement_bytes: statement_bytes.len(),
        });
    }
    let fresh = if let Some(path) = directory {
        let start = Instant::now();
        let output = Command::new(env::current_exe()?)
            .arg("--verify")
            .arg(path)
            .output()?;
        ensure!(
            output.status.success(),
            "fresh component verification failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        Some(
            json!({ "process_wall_ms": ms(start), "verifier": serde_json::from_slice::<Value>(&output.stdout)? }),
        )
    } else {
        None
    };
    let report = json!({
        "protocol": "experimental-committed-checkpoint-keccak-v1",
        "field": "Poly64/Poly192", "hash": "Keccak-256", "pcs": "additive-WHIR",
        "johnson_query_target_bits": 152, "pow_bits_ceiling": 16,
        "batch_size": count, "witness_ms": witness_ms, "setup_ms": setup_ms,
        "conditional_algebraic_bits": scheme.conditional_algebraic_bits,
        "pcs_authenticated": true, "aggregate_integrated": false,
        "zero_knowledge": false, "end_to_end_security_bits": null, "acceptance_pass": false,
        "verification_scope": "Both boundary tables authenticated by one PCS commitment. Verifier receives the commitment and proof, no original states. This standalone command does not exercise aggregate port linkage.",
        "threads_requested": env::var("RAYON_NUM_THREADS").ok(),
        "samples": measurements, "fresh_process": fresh,
    });
    let json = serde_json::to_string_pretty(&report)?;
    if let Some(path) = directory {
        fs::write(path.join("report.json"), &json)?;
    }
    println!("{json}");
    Ok(())
}

fn fresh_verify(path: &Path) -> Result<()> {
    let start = Instant::now();
    let statement: Statement = postcard::from_bytes(&read(path, "statement.bin")?)?;
    ensure!(statement.log_batch <= 20, "oversized component batch");
    let proof: CommittedProof = postcard::from_bytes(&read(path, "proof.bin")?)?;
    let scheme = CommittedBatch::new(statement.log_batch as usize)?;
    let setup_decode_ms = ms(start);
    let start = Instant::now();
    scheme.verify(&statement, &proof, CONTEXT)?;
    println!(
        "{}",
        json!({ "valid": true, "setup_decode_ms": setup_decode_ms, "verify_ms": ms(start) })
    );
    Ok(())
}

fn read(path: &Path, name: &str) -> Result<Vec<u8>> {
    let file = path.join(name);
    ensure!(
        fs::metadata(&file)?.len() <= MAX_ARTIFACT_BYTES,
        "oversized component artifact"
    );
    Ok(fs::read(file)?)
}

fn ms(start: Instant) -> f64 {
    start.elapsed().as_secs_f64() * 1000.0
}
