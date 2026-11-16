use anyhow::{Result, ensure};
use clap::Parser;
use recursive_imt_poc::{client, codec};
use std::{io::Read, path::PathBuf, time::Instant};
#[derive(Parser)]
struct Args {
    #[arg(long)]
    key: PathBuf,
    #[arg(long)]
    depth: u8,
    #[arg(long)]
    out: PathBuf,
}
fn main() -> Result<()> {
    let a = Args::parse();
    let start = Instant::now();
    let mut key: client::ProvingKey = codec::read(&a.key, 1)?;
    key.prepare_for_proving()
        .map_err(|e| anyhow::anyhow!("prepare key: {e:?}"))?;
    let key_load_ms = start.elapsed().as_secs_f64() * 1000.;
    let mut input = Vec::new();
    std::io::stdin().take(65537).read_to_end(&mut input)?;
    ensure!(input.len() <= 65536, "witness too large");
    let witness: client::ClientWitness = serde_json::from_slice(&input)?;
    let statement = client::statement(&witness)?;
    let start = Instant::now();
    let assignment = client::assignment(a.depth, &statement, &witness)?;
    let witness_ms = start.elapsed().as_secs_f64() * 1000.;
    let start = Instant::now();
    let proof = key
        .prove(assignment, statement.fields())
        .map_err(|e| anyhow::anyhow!("prove: {e:?}"))?;
    let prove_ms = start.elapsed().as_secs_f64() * 1000.;
    codec::write(&a.out, 3, &proof)?;
    std::fs::write(
        a.out.with_extension("statement.json"),
        serde_json::to_vec_pretty(&statement)?,
    )?;
    let metrics = serde_json::json!({"key_load_prepare_ms":key_load_ms,"witness_ms":witness_ms,"prove_ms":prove_ms,"proof_bytes":std::fs::metadata(&a.out)?.len(),"randomness":"OS-seeded rand::rng, full ZK"});
    std::fs::write(
        a.out.with_extension("metrics.json"),
        serde_json::to_vec_pretty(&metrics)?,
    )?;
    println!("{metrics}");
    Ok(())
}
