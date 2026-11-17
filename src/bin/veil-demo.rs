//! Direct VEIL inner-argument experiment, explicitly separate from aggregation.
use std::{fs, path::PathBuf, process::Command, time::Instant};

use anyhow::{Result, ensure};
use clap::Parser;
use mimalloc::MiMalloc;
use rand::RngExt;
use recursive_imt_prover::benchmark::{environment, ms, peak_rss, statistics};
use recursive_imt_prover::binary::{
    relation::{ClientPublic, ClientWitness},
    tree::{Imt, commitment, keccak},
    veil::{constraints::ExperimentalProof, keccak::KeccakMembership, parameters::Parameters},
};
use recursive_imt_prover::files::{read_bounded, read_json, write_json};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[global_allocator]
static ALLOCATOR: MiMalloc = MiMalloc;

#[derive(Parser)]
#[command(about = "Experimental direct VEIL argument; no aggregation or certified security claim")]
struct Args {
    /// Zero proves one note preimage; positive depths prove IMT membership.
    #[arg(long, default_value_t = 0)]
    depth: usize,
    #[arg(long, default_value_t = 1)]
    samples: usize,
    #[arg(long, default_value = "run/veil-preimage")]
    out: PathBuf,
    #[arg(long)]
    verify: bool,
    /// Construct and report the circuit without producing proofs.
    #[arg(long)]
    inspect: bool,
    /// Budget for retained commitments only; actual peak RAM is higher.
    #[arg(long, default_value_t = 2u64 << 30)]
    max_retained_bytes: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Trusted {
    protocol: String,
    depth: usize,
    parameters: Parameters,
    relation_keccak: String,
}

fn main() -> Result<()> {
    let args = Args::parse();
    if args.verify {
        return verify(&args);
    }
    ensure!(
        args.samples > 0 && args.samples <= 20,
        "samples must be in 1..=20"
    );
    ensure!(!args.out.exists(), "output directory must be fresh");
    fs::create_dir_all(&args.out)?;
    eprintln!(
        "Experimental binary VEIL: privacy/security analysis incomplete; no aggregate generated"
    );
    let parameters = Parameters::default();
    let start = Instant::now();
    let circuit = KeccakMembership::new(args.depth)?;
    let setup_ms = ms(start);
    let mask = parameters.diagnostic(circuit.relation.variables + 6, 1, false)?;
    let product = parameters.diagnostic(circuit.relation.products.len() + 2, 3, true)?;
    let retained = mask.retained_commitment_bytes + product.retained_commitment_bytes;
    let trusted = Trusted {
        protocol: "experimental-binary-veil-inner-v4".into(),
        depth: args.depth,
        relation_keccak: hex::encode(keccak(&postcard::to_allocvec(&circuit.relation)?)),
        parameters,
    };
    let mut report = json!({"protocol":trusted.protocol, "depth":args.depth,
    "status":"EXPERIMENTAL: ZK adaptation unreviewed; end-to-end security unassessed", "aggregate":false,
    "challenge_bits":192,"hash":"Keccak-256","coding_bound":"Johnson proximity bound with VEIL half-distance binding cap",
    "end_to_end_security_bits":null, "acceptance_pass":false,
    "inner_security":circuit.relation.security_diagnostic(&trusted.parameters)?,
    "setup_ms":setup_ms, "variables":circuit.relation.variables,
    "linear_constraints":circuit.relation.linear.len(), "product_constraints":circuit.relation.products.len(),
    "mask_code":mask, "product_code":product, "retained_commitment_bytes":retained,
    "samples":[], "environment": environment()});
    write_json(&args.out.join("trusted.json"), &trusted)?;
    write_json(&args.out.join("report.json"), &report)?;
    eprintln!(
        "{} variables, {} products, {:.2} GiB retained commitments (excludes scratch)",
        circuit.relation.variables,
        circuit.relation.products.len(),
        retained as f64 / (1u64 << 30) as f64
    );
    if args.inspect {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }
    ensure!(
        retained as u64 <= args.max_retained_bytes,
        "retained commitment requirement exceeds resource budget; geometry saved to report.json"
    );
    let mut samples = Vec::new();
    for sample in 0..args.samples {
        let start = Instant::now();
        let (public, witness) = fixture(args.depth)?;
        let values = circuit.witness(&public, &witness)?;
        let witness_ms = ms(start);
        let public_values = KeccakMembership::public_values(&public);
        let start = Instant::now();
        let proof = circuit
            .relation
            .prove(&trusted.parameters, &public_values, &values)?;
        let prove_ms = ms(start);
        drop(values);
        drop(witness);
        let start = Instant::now();
        let bytes = proof.to_bytes()?;
        let encode_ms = ms(start);
        let start = Instant::now();
        circuit.relation.verify(
            &trusted.parameters,
            &public_values,
            &ExperimentalProof::from_bytes(&bytes)?,
        )?;
        let verify_ms = ms(start);
        eprintln!(
            "Sample {}: witness {:.1} ms, prove {:.1} ms, decode+verify {:.1} ms, {} bytes",
            sample + 1,
            witness_ms,
            prove_ms,
            verify_ms,
            bytes.len()
        );
        fs::write(args.out.join("child.proof"), &bytes)?;
        write_json(&args.out.join("statement.json"), &public)?;
        samples.push(json!({"phase":if sample == 0 {"cold-first-proof-after-setup"} else {"warm-reused-setup"},
            "witness_ms":witness_ms,"prove_ms":prove_ms,"encode_ms":encode_ms,"decode_verify_ms":verify_ms,
            "proof_bytes":bytes.len(),"process_peak_rss_bytes":peak_rss()}));
        report["samples"] = json!(samples);
        write_json(&args.out.join("report.json"), &report)?;
    }
    drop(circuit);
    let start = Instant::now();
    let fresh = Command::new(std::env::current_exe()?)
        .args(["--verify", "--out"])
        .arg(&args.out)
        .output()?;
    ensure!(
        fresh.status.success(),
        "fresh verification failed: {}",
        String::from_utf8_lossy(&fresh.stderr)
    );
    let mut value: Value = serde_json::from_slice(&fresh.stdout)?;
    value["process_wall_ms"] = json!(ms(start));
    report["fresh_verifier"] = value;
    report["summary"] = summarize(&samples);
    write_json(&args.out.join("report.json"), &report)?;
    println!("{}", serde_json::to_string_pretty(&report["summary"])?);
    Ok(())
}

fn verify(args: &Args) -> Result<()> {
    let start = Instant::now();
    let trusted: Trusted = read_json(&args.out.join("trusted.json"))?;
    ensure!(
        trusted.protocol == "experimental-binary-veil-inner-v4",
        "wrong protocol"
    );
    trusted.parameters.validate()?;
    let circuit = KeccakMembership::new(trusted.depth)?;
    ensure!(
        hex::encode(keccak(&postcard::to_allocvec(&circuit.relation)?)) == trusted.relation_keccak,
        "wrong relation identity"
    );
    let setup_ms = ms(start);
    let public: ClientPublic = read_json(&args.out.join("statement.json"))?;
    let bytes = read_bounded(&args.out.join("child.proof"), 256 << 20)?;
    let start = Instant::now();
    circuit.relation.verify(
        &trusted.parameters,
        &KeccakMembership::public_values(&public),
        &ExperimentalProof::from_bytes(&bytes)?,
    )?;
    println!(
        "{}",
        json!({"verified":true,"setup_ms":setup_ms,"decode_verify_ms":ms(start)})
    );
    Ok(())
}

fn fixture(depth: usize) -> Result<(ClientPublic, ClientWitness)> {
    let mut rng = rand::rng();
    let mut witness = ClientWitness {
        secret: rng.random(),
        nonce: rng.random(),
        leaf_index: 0,
        merkle_path: vec![],
    };
    let amount = rng.random();
    let leaf = commitment(&witness.secret, amount, &witness.nonce);
    let root = if depth == 0 {
        leaf
    } else {
        let mut tree = Imt::new(depth)?;
        tree.append(rng.random())?;
        witness.leaf_index = tree.append(leaf)?;
        if depth > 1 {
            tree.append(rng.random())?;
        }
        witness.merkle_path = tree.path(witness.leaf_index)?;
        tree.root()
    };
    Ok((ClientPublic { root, amount }, witness))
}

fn summarize(samples: &[Value]) -> Value {
    let selected: Vec<_> = if samples.len() > 1 {
        samples[1..].iter().collect()
    } else {
        samples.iter().collect()
    };
    let mut result = json!({"phase":if samples.len() > 1 {"warm"} else {"cold-only"}});
    for key in ["prove_ms", "decode_verify_ms", "proof_bytes"] {
        result[key] = statistics(selected.iter().map(|s| s[key].as_f64().unwrap()).collect());
    }
    result
}
