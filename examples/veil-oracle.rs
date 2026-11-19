//! Isolated benchmark of the private-oracle bridge, not an IMT child benchmark.
use std::{fs, path::PathBuf, process::Command, time::Instant};

use anyhow::{Result, ensure};
use clap::Parser;
use mimalloc::MiMalloc;
use rand::RngExt;
use recursive_imt_prover::{
    benchmark::{environment, ms, peak_rss, statistics},
    binary::veil::{
        E,
        parameters::Parameters,
        private_sumcheck::{PrivateSumcheckProof, PrivateSumcheckStatement},
    },
    files::{read_bounded, read_json, write_json},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[global_allocator]
static ALLOCATOR: MiMalloc = MiMalloc;

#[derive(Parser)]
#[command(
    about = "Experimental binary BLAKE3 VEIL/WHIR oracle bridge; no full-ZK or 128-bit certification"
)]
struct Args {
    #[arg(long, default_value_t = 8)]
    variables: usize,
    #[arg(long, default_value_t = 2)]
    points: usize,
    #[arg(long, default_value_t = 3)]
    samples: usize,
    #[arg(long)]
    out: PathBuf,
    #[arg(long)]
    verify: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Trusted {
    protocol: String,
    parameters: Parameters,
    variables: usize,
    points: usize,
}

fn main() -> Result<()> {
    let args = Args::parse();
    if args.verify {
        return verify(&args);
    }
    ensure!(
        (1..=14).contains(&args.variables),
        "benchmark variables must be in 1..=14"
    );
    ensure!((1..=2).contains(&args.points), "points must be 1 or 2");
    ensure!(
        (1..=20).contains(&args.samples),
        "samples must be in 1..=20"
    );
    ensure!(!args.out.exists(), "output directory must be fresh");
    fs::create_dir_all(&args.out)?;
    let trusted = Trusted {
        protocol: "experimental-binary-veil-oracle-v3".into(),
        parameters: Parameters::default(),
        variables: args.variables,
        points: args.points,
    };
    write_json(&args.out.join("trusted.json"), &trusted)?;
    let mut samples = Vec::new();
    for sample in 0..args.samples {
        let start = Instant::now();
        let mut rng = rand::rng();
        let left: Vec<E> = (0..1 << args.variables).map(|_| rng.random()).collect();
        let right: Vec<E> = (0..1 << args.variables).map(|_| rng.random()).collect();
        let witness_ms = ms(start);
        let start = Instant::now();
        let (statement, proof) =
            PrivateSumcheckStatement::prove(left, right, args.points, &trusted.parameters)?;
        let prove_ms = ms(start);
        let start = Instant::now();
        let bytes = proof.to_bytes()?;
        let encode_ms = ms(start);
        let start = Instant::now();
        statement.verify(
            &trusted.parameters,
            &PrivateSumcheckProof::from_bytes(&bytes)?,
        )?;
        let verify_ms = ms(start);
        eprintln!(
            "Sample {}: prove {:.3} ms, decode+verify {:.3} ms, {} bytes",
            sample + 1,
            prove_ms,
            verify_ms,
            bytes.len()
        );
        fs::write(args.out.join("oracle.proof"), &bytes)?;
        write_json(&args.out.join("statement.json"), &statement)?;
        samples.push(json!({"phase":if sample == 0 {"cold-first-proof"} else {"warm-process"}, "witness_ms":witness_ms,"prove_ms":prove_ms,"encode_ms":encode_ms,"decode_verify_ms":verify_ms,"proof_bytes":bytes.len(),"peak_rss_bytes":peak_rss()}));
    }
    let start = Instant::now();
    let result = Command::new(std::env::current_exe()?)
        .args(["--verify", "--out"])
        .arg(&args.out)
        .output()?;
    ensure!(
        result.status.success(),
        "fresh verifier failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    let mut fresh: Value = serde_json::from_slice(&result.stdout)?;
    fresh["process_wall_ms"] = json!(ms(start));
    let warm = if samples.len() > 1 {
        &samples[1..]
    } else {
        &samples[..]
    };
    let summary = json!({
        "prove_ms":statistics(warm.iter().map(|v|v["prove_ms"].as_f64().unwrap()).collect()),
        "decode_verify_ms":statistics(warm.iter().map(|v|v["decode_verify_ms"].as_f64().unwrap()).collect()),
    });
    write_json(
        &args.out.join("report.json"),
        &json!({"protocol":trusted.protocol,"variables":args.variables,"points":args.points,"parameters":trusted.parameters,
        "field":"Poly64/Poly192","hash":"BLAKE3","bound":"Johnson; oracle binding radius also capped at half distance",
        "acceptance_pass":false,"full_zk_established":false,"end_to_end_security_bits":null,"imt_child":false,"aggregate":false,
        "measurement_scope":"all oracle setup, commitments and masked proof generation included; setup rebuilt each sample; compilation excluded",
        "environment":environment(),"samples":samples,"summary":summary,"fresh_verifier":fresh}),
    )?;
    println!("{}", serde_json::to_string_pretty(&summary)?);
    Ok(())
}

fn verify(args: &Args) -> Result<()> {
    let trusted: Trusted = read_json(&args.out.join("trusted.json"))?;
    ensure!(
        trusted.protocol == "experimental-binary-veil-oracle-v3",
        "wrong oracle protocol"
    );
    let statement: PrivateSumcheckStatement = read_json(&args.out.join("statement.json"))?;
    ensure!(
        statement.variables == trusted.variables && statement.opening_points == trusted.points,
        "oracle statement differs from trusted shape"
    );
    let bytes = read_bounded(&args.out.join("oracle.proof"), 16 << 20)?;
    let start = Instant::now();
    statement.verify(
        &trusted.parameters,
        &PrivateSumcheckProof::from_bytes(&bytes)?,
    )?;
    println!("{}", json!({"verified":true,"decode_verify_ms":ms(start)}));
    Ok(())
}
