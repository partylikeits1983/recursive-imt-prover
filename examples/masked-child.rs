//! End-to-end experimental masked membership child, with a fresh verifier.
use std::{fs, path::PathBuf, process::Command, time::Instant};

use anyhow::{Result, ensure};
use clap::Parser;
use mimalloc::MiMalloc;
use rand::RngExt;
use recursive_imt_prover::{
    benchmark::{environment, ms, peak_rss, statistics},
    binary::{
        cli::fixtures,
        relation::{ClientPublic, ClientWitness},
        tree::commitment,
        veil::{
            child::{MaskedMembershipProof, PROTOCOL, PreparedMembership},
            parameters::Parameters,
        },
    },
    files::{read_bounded, read_json, write_json},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[global_allocator]
static ALLOCATOR: MiMalloc = MiMalloc;

#[derive(Parser)]
#[command(
    about = "Experimental masked binary Keccak IMT child; full ZK/security analysis outstanding"
)]
struct Args {
    #[arg(long, default_value_t = 16)]
    depth: usize,
    #[arg(long, default_value_t = 3)]
    samples: usize,
    #[arg(long)]
    out: PathBuf,
    #[arg(long)]
    verify: bool,
    #[arg(long)]
    inspect: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Trusted {
    protocol: String,
    depth: usize,
    parameters: Parameters,
    authority: [u8; 32],
}

fn main() -> Result<()> {
    let args = Args::parse();
    if args.verify {
        return verify(&args);
    }
    ensure!(
        (1..=20).contains(&args.samples),
        "samples must be in 1..=20"
    );
    ensure!(!args.out.exists(), "output directory must be fresh");
    let parameters = Parameters::default();
    let start = Instant::now();
    let prepared = PreparedMembership::new(args.depth, parameters.clone())?;
    let setup_ms = ms(start);
    let trusted = Trusted {
        protocol: PROTOCOL.into(),
        depth: args.depth,
        parameters,
        authority: prepared.identity(),
    };
    let mut report = json!({
        "protocol":trusted.protocol, "depth":args.depth, "field":"Poly64/Poly192", "hash":"Keccak-256",
        "bound":"Johnson; VEIL binding radius capped at half distance", "parameters":trusted.parameters,
        "acceptance_pass":false, "full_zk_established":false, "end_to_end_security_bits":null, "aggregate":false,
        "imt_child":true, "setup_ms":setup_ms, "trace_height":prepared.trace_height(), "trace_width":prepared.trace_width(),
        "masked_messages":prepared.masked_messages(), "verifier_products":prepared.verifier_products(),
        "oracle_columns":prepared.oracle_columns(), "stacking_factor":prepared.stacking_factor(),
        "retained_oracle_bytes":prepared.retained_oracle_bytes()?, "environment":environment(), "samples":[],
    });
    fs::create_dir_all(&args.out)?;
    write_json(&args.out.join("trusted.json"), &trusted)?;
    write_json(&args.out.join("report.json"), &report)?;
    eprintln!(
        "Depth {}: {} x {} trace, {} masked messages, {} verifier products",
        args.depth,
        prepared.trace_height(),
        prepared.trace_width(),
        prepared.masked_messages(),
        prepared.verifier_products()
    );
    if args.inspect {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }
    let mut samples = Vec::new();
    for sample in 0..args.samples {
        let start = Instant::now();
        let (public, witness) = if args.depth == 0 {
            let mut rng = rand::rng();
            let witness = ClientWitness {
                secret: rng.random(),
                nonce: rng.random(),
                leaf_index: 0,
                merkle_path: vec![],
            };
            let amount = 100;
            (
                ClientPublic {
                    root: commitment(&witness.secret, amount, &witness.nonce),
                    amount,
                },
                witness,
            )
        } else {
            fixtures(args.depth, 1)?.remove(0)
        };
        let fixture_ms = ms(start);
        let start = Instant::now();
        let trace = prepared.witness(&public, &witness)?;
        let witness_ms = ms(start);
        let start = Instant::now();
        let proof = prepared.prove_trace(&public, trace)?;
        let prove_ms = ms(start);
        let start = Instant::now();
        let bytes = proof.to_bytes()?;
        let encode_ms = ms(start);
        let start = Instant::now();
        prepared.verify(&public, &MaskedMembershipProof::from_bytes(&bytes)?)?;
        let verify_ms = ms(start);
        let (oracle_bytes, algebra_bytes) = proof.component_bytes()?;
        eprintln!(
            "Sample {}: prove {:.3} ms, decode+verify {:.3} ms, {} bytes",
            sample + 1,
            prove_ms,
            verify_ms,
            bytes.len()
        );
        fs::write(args.out.join("child.proof"), &bytes)?;
        write_json(&args.out.join("statement.json"), &public)?;
        samples.push(json!({"phase":if sample == 0 {"cold-first-proof"} else {"warm-process"}, "fixture_ms":fixture_ms, "witness_ms":witness_ms, "prove_ms":prove_ms, "encode_ms":encode_ms, "decode_verify_ms":verify_ms, "proof_bytes":bytes.len(), "oracle_bytes":oracle_bytes, "algebra_bytes":algebra_bytes, "peak_rss_bytes":peak_rss()}));
        report["samples"] = json!(samples);
        write_json(&args.out.join("report.json"), &report)?;
    }
    let start = Instant::now();
    let output = Command::new(std::env::current_exe()?)
        .args(["--verify", "--out"])
        .arg(&args.out)
        .output()?;
    ensure!(
        output.status.success(),
        "fresh child verifier failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let mut fresh: Value = serde_json::from_slice(&output.stdout)?;
    fresh["process_wall_ms"] = json!(ms(start));
    report["fresh_verifier"] = fresh;
    let warm = if samples.len() > 1 {
        &samples[1..]
    } else {
        &samples[..]
    };
    report["summary"] = json!({
        "prove_ms":statistics(warm.iter().map(|s|s["prove_ms"].as_f64().unwrap()).collect()),
        "decode_verify_ms":statistics(warm.iter().map(|s|s["decode_verify_ms"].as_f64().unwrap()).collect()),
    });
    write_json(&args.out.join("report.json"), &report)?;
    println!("{}", serde_json::to_string_pretty(&report["summary"])?);
    Ok(())
}

fn verify(args: &Args) -> Result<()> {
    let trusted: Trusted = read_json(&args.out.join("trusted.json"))?;
    ensure!(trusted.protocol == PROTOCOL, "wrong masked child protocol");
    let start = Instant::now();
    let prepared = PreparedMembership::new(trusted.depth, trusted.parameters)?;
    ensure!(
        prepared.identity() == trusted.authority,
        "masked child verifier identity mismatch"
    );
    let setup_ms = ms(start);
    let public: ClientPublic = read_json(&args.out.join("statement.json"))?;
    let bytes = read_bounded(&args.out.join("child.proof"), 64 << 20)?;
    let start = Instant::now();
    prepared.verify(&public, &MaskedMembershipProof::from_bytes(&bytes)?)?;
    println!(
        "{}",
        json!({"verified":true,"setup_ms":setup_ms,"decode_verify_ms":ms(start)})
    );
    Ok(())
}
