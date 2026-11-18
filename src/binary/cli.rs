use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

use super::{IMT_DEPTH, MAX_CHILDREN};

use anyhow::{Result, ensure};
use clap::Parser;
use rand::{RngExt, SeedableRng, rngs::StdRng};
use serde::{Deserialize, Serialize};

use super::engine::{Geometry, PreparedAggregate, PreparedChild, ProofMetrics, Settings};
use super::relation::{AggregatePublic, ClientPublic, ClientWitness};
use super::security::BatchAssessment;
use super::tree::{Imt, commitment};
use crate::benchmark::{environment, ms, peak_rss, statistics};
use crate::files::{read_bounded, read_json, write_json};

#[derive(Parser)]
#[command(about = "Poly64 / Poly192 / Keccak / additive-WHIR NON-ZK research baseline")]
pub struct Args {
    #[arg(long, default_value_t = 2)]
    pub batch_size: usize,
    #[arg(long, default_value_t = IMT_DEPTH)]
    pub depth: usize,
    #[arg(long, default_value_t = 3)]
    pub samples: usize,
    #[arg(long, default_value_t = 152)]
    pub pcs_bits: usize,
    /// Maximum WHIR grinding bits; reported separately from the PCS target.
    #[arg(long, default_value_t = 16)]
    pub pow_bits: usize,
    #[arg(long, default_value_t = 127)]
    pub min_security_bits: usize,
    /// Separate floor for all non-hash terms under uniform transcript challenges.
    #[arg(long, default_value_t = 144)]
    pub min_algebraic_bits: usize,
    #[arg(long, default_value_t = 1 << 29)]
    pub max_codeword_cells: usize,
    #[arg(long, default_value = "run/binary")]
    pub out: PathBuf,
    /// Skip aggregation to measure native child throughput at large batch sizes.
    #[arg(long)]
    pub children_only: bool,
    /// Verify using only aggregate.proof, statement.json and trusted.json in --out.
    #[arg(long)]
    pub verify: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Trusted {
    protocol: String,
    settings: Settings,
    child_identity: String,
    aggregate_identity: String,
}

#[derive(Serialize, Deserialize)]
struct Sample {
    phase: String,
    fixture_ms: f64,
    children: Vec<ProofMetrics>,
    aggregation_wall_ms: Option<f64>,
    aggregate: Option<ProofMetrics>,
    aggregate_decode_verify_ms: Option<f64>,
    critical_path_ms: f64,
    throughput_children_per_second: f64,
    process_peak_rss_bytes: u64,
}

#[derive(Serialize, Deserialize)]
struct Report {
    privacy: String,
    mode: String,
    settings: Settings,
    environment: serde_json::Value,
    child_setup_ms: f64,
    aggregate_setup_ms: Option<f64>,
    child_geometry: Geometry,
    aggregate_geometry: Option<Geometry>,
    security: Option<BatchAssessment>,
    samples: Vec<Sample>,
    fresh_verifier: Option<serde_json::Value>,
    summary: serde_json::Value,
}

pub fn run(mut args: Args, demo: bool) -> Result<()> {
    if args.verify {
        return verify_files(&args.out);
    }
    if demo {
        args.samples = 1;
    }
    ensure!(
        (1..=20).contains(&args.samples),
        "samples must be in 1..=20"
    );
    ensure!(
        !args.out.exists(),
        "output directory exists; choose a fresh --out"
    );
    let settings = Settings {
        depth: args.depth,
        batch_size: args.batch_size,
        pcs_bits: args.pcs_bits,
        pow_bits: args.pow_bits,
        min_security_bits: args.min_security_bits,
        min_algebraic_bits: args.min_algebraic_bits,
        max_codeword_cells: args.max_codeword_cells,
        ..Default::default()
    };
    settings.validate()?;
    fs::create_dir_all(&args.out)?;
    eprintln!(
        "NON-ZK correctness baseline; Johnson PCS target {} bits (not composed security).",
        settings.pcs_bits
    );
    let start = Instant::now();
    let child = PreparedChild::new(&settings)?;
    let child_setup_ms = ms(start);
    eprintln!(
        "Child prepared: {} witnesses; security {:?} bits",
        child.inner.geometry.witnesses, child.inner.geometry.security_bits
    );
    // Keep a partial report even when aggregate construction hits a resource limit.
    let mut report = Report {
        privacy: "NON-ZK: child transcripts reveal witness-dependent data".into(),
        mode: if args.children_only {
            "children-only"
        } else {
            "fixed-aggregate"
        }
        .into(),
        settings: settings.clone(),
        environment: environment(),
        child_setup_ms,
        aggregate_setup_ms: None,
        child_geometry: child.inner.geometry.clone(),
        aggregate_geometry: None,
        security: None,
        samples: vec![],
        fresh_verifier: None,
        summary: serde_json::json!({}),
    };
    write_json(&args.out.join("report.json"), &report)?;
    let start = Instant::now();
    let mut aggregation_failure = None;
    let aggregate = if args.children_only {
        None
    } else {
        eprintln!(
            "Constructing fixed verifier for N={} children...",
            settings.batch_size
        );
        match PreparedAggregate::new(&child, &settings) {
            Ok(value) => Some(value),
            Err(error) => {
                write_json(
                    &args.out.join("failure.json"),
                    &serde_json::json!({"stage":"aggregate_setup", "error":format!("{error:#}"), "elapsed_ms":ms(start), "peak_rss_bytes":peak_rss()}),
                )?;
                eprintln!("Aggregation unavailable: {error:#}. Measuring native children instead.");
                aggregation_failure = Some(format!("{error:#}"));
                None
            }
        }
    };
    if let Some(aggregate) = &aggregate {
        report.aggregate_setup_ms = Some(ms(start));
        report.aggregate_geometry = Some(aggregate.inner.geometry.clone());
        report.security = Some(BatchAssessment::new(
            &child.inner.geometry.assessment,
            &aggregate.inner.geometry.assessment,
            settings.batch_size,
        )?);
        write_json(
            &args.out.join("trusted.json"),
            &Trusted {
                protocol: "binary-poly64-keccak-imt-nonzk-v2".into(),
                settings: settings.clone(),
                child_identity: child.inner.identity(),
                aggregate_identity: aggregate.inner.identity(),
            },
        )?;
        eprintln!(
            "Aggregate prepared: {} witnesses; security {:?} bits",
            aggregate.inner.geometry.witnesses, aggregate.inner.geometry.security_bits
        );
    }
    // Retain the checked outer geometry/security even if proving is interrupted.
    write_json(&args.out.join("report.json"), &report)?;
    for index in 0..args.samples {
        let start = Instant::now();
        let fixture_start = Instant::now();
        let inputs = fixtures(settings.depth, settings.batch_size)?;
        let fixture_ms = ms(fixture_start);
        let mut children = Vec::new();
        let mut metrics = Vec::new();
        for (i, (public, witness)) in inputs.into_iter().enumerate() {
            let (proof, measurement) = child.prove(public, &witness)?;
            eprintln!(
                "Sample {} child {}: witness {:.1} ms, prove {:.1} ms, verify {:.1} ms, {} bytes",
                index + 1,
                i + 1,
                measurement.witness_ms,
                measurement.prove_ms,
                measurement.verify_ms,
                measurement.proof_bytes
            );
            children.push(proof);
            metrics.push(measurement);
        }
        // ClientWitness values have been dropped. The aggregator API receives proof bytes and public claims only.
        let (aggregation_wall_ms, aggregate_metrics, aggregate_verify_ms) =
            if let Some(aggregate) = &aggregate {
                let agg_start = Instant::now();
                let (public, proof, metrics) = aggregate.prove(&children)?;
                let wall = ms(agg_start);
                drop(children);
                let verify_start = Instant::now();
                aggregate.verify(&proof, &public)?;
                let verify_ms = ms(verify_start);
                eprintln!(
                    "Aggregate: witness {:.1} ms, prove {:.1} ms, decode+verify {:.1} ms, {} bytes",
                    metrics.witness_ms,
                    metrics.prove_ms,
                    verify_ms,
                    proof.len()
                );
                write_json(&args.out.join("statement.json"), &public)?;
                fs::write(args.out.join("aggregate.proof"), proof)?;
                (Some(wall), Some(metrics), Some(verify_ms))
            } else {
                (None, None, None)
            };
        let latency = ms(start);
        report.samples.push(Sample {
            phase: if index == 0 {
                "cold-first-proof-after-setup"
            } else {
                "warm-reused-setup"
            }
            .into(),
            fixture_ms,
            children: metrics,
            aggregation_wall_ms,
            aggregate: aggregate_metrics,
            aggregate_decode_verify_ms: aggregate_verify_ms,
            critical_path_ms: latency,
            throughput_children_per_second: settings.batch_size as f64 * 1000.0 / latency,
            process_peak_rss_bytes: peak_rss(),
        });
        report.summary = summarize(&report.samples);
        write_json(&args.out.join("report.json"), &report)?;
    }
    // Release proving keys and circuit graphs before starting the independent verifier.
    drop(aggregate);
    drop(child);
    if !args.children_only && aggregation_failure.is_none() {
        let start = Instant::now();
        let output = Command::new(std::env::current_exe()?)
            .args(["--verify", "--out"])
            .arg(&args.out)
            .output()?;
        ensure!(
            output.status.success(),
            "fresh verifier failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let mut fresh: serde_json::Value = serde_json::from_slice(&output.stdout)?;
        fresh["process_wall_ms"] = serde_json::json!(ms(start));
        report.fresh_verifier = Some(fresh);
        write_json(&args.out.join("report.json"), &report)?;
    }
    if let Some(error) = aggregation_failure {
        anyhow::bail!(
            "Child benchmarks saved in {}; no aggregate produced: {error}",
            args.out.display()
        );
    }
    println!("NON-ZK baseline complete: {}", args.out.display());
    println!("{}", serde_json::to_string_pretty(&report.summary)?);
    Ok(())
}

pub fn fixtures(depth: usize, count: usize) -> Result<Vec<(ClientPublic, ClientWitness)>> {
    let mut rng = StdRng::from_rng(&mut rand::rng());
    let mut tree = Imt::new(depth)?;
    let capacity = 1u64 << depth;
    ensure!(
        count > 0 && count <= MAX_CHILDREN && 2 * count as u64 <= capacity,
        "tree cannot hold users and later appends"
    );
    for _ in 0..8.min(capacity - 2 * count as u64) {
        tree.append(rng.random())?;
    }
    let mut notes = Vec::new();
    for i in 0..count {
        let secret = rng.random();
        let nonce = rng.random();
        let amount = 100 * (i as u64 + 1);
        let leaf_index = tree.append(commitment(&secret, amount, &nonce))?;
        notes.push((secret, nonce, amount, leaf_index));
    }
    // Each proof uses a different later root, never its insertion root.
    let mut inputs = Vec::new();
    for (secret, nonce, amount, leaf_index) in notes {
        tree.append(rng.random())?;
        inputs.push((
            ClientPublic {
                root: tree.root(),
                amount,
            },
            ClientWitness {
                secret,
                nonce,
                leaf_index,
                merkle_path: tree.path(leaf_index)?,
            },
        ));
    }
    Ok(inputs)
}

fn verify_files(directory: &Path) -> Result<()> {
    let trusted: Trusted = read_json(&directory.join("trusted.json"))?;
    ensure!(
        trusted.protocol == "binary-poly64-keccak-imt-nonzk-v2",
        "unsupported trusted protocol"
    );
    let public: AggregatePublic = read_json(&directory.join("statement.json"))?;
    ensure!(
        public.children.len() == trusted.settings.batch_size,
        "incorrect statement count"
    );
    let proof_path = directory.join("aggregate.proof");
    let proof = read_bounded(&proof_path, 64 << 20)?;
    let start = Instant::now();
    let child = PreparedChild::new(&trusted.settings)?;
    ensure!(
        child.inner.identity() == trusted.child_identity,
        "child authority mismatch"
    );
    let aggregate = PreparedAggregate::new(&child, &trusted.settings)?;
    ensure!(
        aggregate.inner.identity() == trusted.aggregate_identity,
        "aggregate authority mismatch"
    );
    let setup_ms = ms(start);
    let start = Instant::now();
    aggregate.verify(&proof, &public)?;
    println!(
        "{}",
        serde_json::json!({"verified":true, "verifier_reconstruction_ms":setup_ms,
        "decode_verify_ms":ms(start), "process_peak_rss_bytes":peak_rss()})
    );
    Ok(())
}

fn summarize(samples: &[Sample]) -> serde_json::Value {
    let warm: Vec<_> = samples.iter().skip(1).collect();
    let values = |select: fn(&Sample) -> Option<f64>| {
        statistics(warm.iter().filter_map(|s| select(s)).collect())
    };
    serde_json::json!({"warm_samples":warm.len(), "warm_critical_path_ms":values(|s| Some(s.critical_path_ms)),
        "warm_aggregation_wall_ms":values(|s| s.aggregation_wall_ms),
        "warm_aggregate_prove_ms":values(|s| s.aggregate.as_ref().map(|p| p.prove_ms)),
        "warm_aggregate_verify_ms":values(|s| s.aggregate_decode_verify_ms),
        "warm_child_prove_ms":statistics(warm.iter().flat_map(|s| s.children.iter().map(|c| c.prove_ms)).collect()),
        "warm_child_verify_ms":statistics(warm.iter().flat_map(|s| s.children.iter().map(|c| c.verify_ms)).collect())})
}
