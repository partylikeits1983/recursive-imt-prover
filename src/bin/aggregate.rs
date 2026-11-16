//! Aggregator loads only public information, keys and child proofs.
use anyhow::{Result, ensure};
use clap::Parser;
use recursive_imt_poc::{client, codec, outer, statement::BatchStatement, tree::AppendWitness};
use std::{path::PathBuf, time::Instant};
#[derive(Parser)]
struct Args {
    #[arg(long)]
    directory: PathBuf,
    #[arg(long)]
    diagnostic_transition_only: bool,
}
fn main() -> Result<()> {
    let a = Args::parse();
    let d = &a.directory;
    let s: BatchStatement = serde_json::from_slice(&std::fs::read(d.join("statement.json"))?)?;
    let w: AppendWitness = serde_json::from_slice(&std::fs::read(d.join("append.json"))?)?;
    let mut vk: client::VerifyingKey = codec::read(&d.join("client-vk.bin"), 2)?;
    vk.authenticate()
        .map_err(|e| anyhow::anyhow!("authenticate: {e:?}"))?;
    let proof0: client::Proof = codec::read(&d.join("client0.bin"), 3)?;
    let proof1: client::Proof = codec::read(&d.join("client1.bin"), 3)?;
    let start = Instant::now();
    client::verify(&vk, &s.child(0), &proof0)?;
    client::verify(&vk, &s.child(1), &proof1)?;
    let verify_children_ms = start.elapsed().as_secs_f64() * 1000.;
    ensure!(
        codec::encode(3, &proof0)? != codec::encode(3, &proof1)?,
        "identical child proofs"
    );
    println!(
        "Two actual full-ZK SPARK client proofs verified NATIVELY ({verify_children_ms:.2} ms)."
    );
    if !a.diagnostic_transition_only {
        outer::prove_batch([&proof0, &proof1], &s, &w)?;
        unreachable!();
    }
    eprintln!(
        "DIAGNOSTIC ONLY: proving append/history relation; client authorization is NOT inside this proof. State will not be applied."
    );
    let start = Instant::now();
    let c = outer::build_transition(s.depth)?;
    let build_ms = start.elapsed().as_secs_f64() * 1000.;
    let start = Instant::now();
    let prepared = outer::prepare(&c)?;
    let prepare_ms = start.elapsed().as_secs_f64() * 1000.;
    let start = Instant::now();
    let proof = outer::prove_transition(&c, &prepared, &s, &w)?;
    let trace_and_prove_ms = start.elapsed().as_secs_f64() * 1000.;
    let start = Instant::now();
    prepared.verifier().verify(
        &proof,
        &s.fields()
            .into_iter()
            .map(outer::convert)
            .collect::<Vec<_>>(),
    )?;
    let verify_ms = start.elapsed().as_secs_f64() * 1000.;
    codec::write(&d.join("transition-diagnostic.bin"), 4, &proof)?;
    let report = serde_json::json!({"kind":"transition-only diagnostic, NOT recursion","verify_children_ms":verify_children_ms,"build_ms":build_ms,"prepare_ms":prepare_ms,"trace_and_prove_ms":trace_and_prove_ms,"verify_ms":verify_ms,"proof_bytes":std::fs::metadata(d.join("transition-diagnostic.bin"))?.len(),"statement_bytes":codec::encode(5,&s)?.len()});
    std::fs::write(
        d.join("outer-diagnostic-metrics.json"),
        serde_json::to_vec_pretty(&report)?,
    )?;
    println!("{report}");
    Ok(())
}
