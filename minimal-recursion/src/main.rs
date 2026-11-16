use anyhow::{Context, Result, ensure};
use clap::{Parser, Subcommand};
use minimal_recursion::{
    Leaf, Profile, Statement, aggregate, encode_proof, encode_verifier, prepare_aggregator, verify,
};
use p3_recursion::artifact::ArtifactLimits;
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    process::Command,
    time::Instant,
};

#[derive(Parser)]
#[command(about = "Two actual Plonky3 proofs -> one recursive Plonky3 proof (non-ZK)")]
struct Args {
    #[command(subcommand)]
    command: Action,
}
#[derive(Subcommand)]
enum Action {
    /// Run setup, proving and independent verification as fresh processes.
    Demo {
        #[arg(long)]
        out: PathBuf,
        #[arg(long, value_enum, default_value = "reference")]
        profile: Profile,
        #[arg(long, default_value_t = 3)]
        left: u32,
        #[arg(long, default_value_t = 5)]
        right: u32,
    },
    /// Provision fixed verifier artifacts using separate calibration statements.
    Setup {
        #[arg(long)]
        out: PathBuf,
        #[arg(long, value_enum, default_value = "reference")]
        profile: Profile,
    },
    /// Generate two distinct child proofs and aggregate them; persist ONE proof.
    Prove {
        #[arg(long)]
        trusted_dir: PathBuf,
        #[arg(long)]
        out: PathBuf,
        #[arg(long, default_value_t = 3)]
        left: u32,
        #[arg(long, default_value_t = 5)]
        right: u32,
    },
    /// Verify only the final proof against trusted authority and an expected statement.
    Verify {
        #[arg(long)]
        trusted_dir: PathBuf,
        #[arg(long)]
        statement: PathBuf,
        #[arg(long)]
        proof: PathBuf,
    },
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    version: u32,
    relation: String,
    profile: Profile,
}
const RELATION: &str = "two-ordered-koalabear-y=x^2+x-v1";

fn read(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let file = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= limit, "artifact exceeds size limit");
    Ok(bytes)
}
fn write(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    Ok(())
}
fn json(path: &Path, value: &impl Serialize) -> Result<()> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    write(path, &bytes)
}
fn new_dir(path: &Path) -> Result<()> {
    ensure!(!path.exists(), "output must be new: {}", path.display());
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent)?;
    }
    fs::create_dir(path)?;
    Ok(())
}
fn profile_notice(profile: Profile) {
    if profile == Profile::Smoke {
        eprintln!("LOW-SECURITY SMOKE PROFILE: four FRI queries, zero grinding; tests only.");
    }
}
fn setup(out: &Path, profile: Profile) -> Result<()> {
    new_dir(out)?;
    profile_notice(profile);
    let start = Instant::now();
    let leaf = Leaf::prepare(profile)?;
    let leaf_prepare_ms = start.elapsed().as_secs_f64() * 1e3;
    let fields = Statement::from_inputs(7, 11)?.child_fields()?;
    let start = Instant::now();
    let proofs = [leaf.prove(fields[0])?, leaf.prove(fields[1])?];
    let calibration_prove_ms = start.elapsed().as_secs_f64() * 1e3;
    eprintln!("Setup: preparing the fixed recursive verifier from calibration proofs...");
    let start = Instant::now();
    let owner = prepare_aggregator(profile, leaf.verifier(), [&proofs[0], &proofs[1]], &fields)?;
    let outer_prepare_ms = start.elapsed().as_secs_f64() * 1e3;
    write(
        &out.join("leaf.verifier"),
        &encode_verifier(&leaf.verifier())?,
    )?;
    write(
        &out.join("outer.verifier"),
        &encode_verifier(&owner.verifier())?,
    )?;
    json(
        &out.join("manifest.json"),
        &Manifest {
            version: 1,
            relation: RELATION.into(),
            profile,
        },
    )?;
    json(
        &out.join("setup-metrics.json"),
        &serde_json::json!({
            "profile": profile,
            "rayon_threads": rayon::current_num_threads(),
            "leaf_prepare_ms": leaf_prepare_ms,
            "calibration_prove_ms": calibration_prove_ms,
            "outer_prepare_ms": outer_prepare_ms,
            "fri": {
                "suite": "KoalaBearD5Poseidon2BinaryFri",
                "log_blowup": profile.descriptor().log_blowup(),
                "num_queries": profile.descriptor().num_queries(),
                "query_pow_bits": profile.descriptor().query_pow_bits(),
                "commit_pow_bits": 0,
                "batch_pow_bits": 0,
                "log_final_poly_len": 0,
                "max_log_arity": 2,
                "input_cap_height": 0,
                "commit_cap_height": 0,
                "extension_degree": 5,
            },
        }),
    )?;
    println!(
        "Provisioned trusted verifier artifacts in {}",
        out.display()
    );
    Ok(())
}
fn prove(trusted: &Path, out: &Path, left: u32, right: u32) -> Result<()> {
    let statement = Statement::from_inputs(left, right)?;
    let manifest: Manifest = serde_json::from_slice(&read(&trusted.join("manifest.json"), 4096)?)?;
    ensure!(
        manifest.version == 1 && manifest.relation == RELATION,
        "wrong trusted manifest"
    );
    let profile = manifest.profile;
    profile_notice(profile);
    new_dir(out)?;
    let limits = ArtifactLimits::default();
    let leaf_pin = read(&trusted.join("leaf.verifier"), limits.max_verifier_bytes)?;
    let root_pin = read(&trusted.join("outer.verifier"), limits.max_verifier_bytes)?;
    let total_start = Instant::now();
    let start = Instant::now();
    let leaf = Leaf::prepare(profile)?;
    ensure!(
        encode_verifier(&leaf.verifier())? == leaf_pin,
        "leaf verifier differs from trusted setup"
    );
    let leaf_prepare_ms = start.elapsed().as_secs_f64() * 1e3;
    let fields = statement.child_fields()?;
    let mut proofs = Vec::new();
    let mut child_prove_ms = Vec::new();
    let mut child_bytes = Vec::new();
    for field in fields {
        let start = Instant::now();
        let proof = leaf.prove(field)?;
        child_prove_ms.push(start.elapsed().as_secs_f64() * 1e3);
        child_bytes.push(encode_proof(&leaf.verifier(), &proof)?.len());
        proofs.push(proof);
    }
    eprintln!("Generated two child proofs; preparing their recursive verifier...");
    let start = Instant::now();
    let owner = prepare_aggregator(profile, leaf.verifier(), [&proofs[0], &proofs[1]], &fields)?;
    let outer_verifier = owner.verifier();
    ensure!(
        encode_verifier(&outer_verifier)? == root_pin,
        "outer verifier differs from independently provisioned setup"
    );
    let outer_prepare_ms = start.elapsed().as_secs_f64() * 1e3;
    eprintln!("Proving the circuit that verifies both child proofs...");
    let start = Instant::now();
    let outer = aggregate(&owner, [&proofs[0], &proofs[1]], &fields)?;
    let outer_prove_ms = start.elapsed().as_secs_f64() * 1e3;
    let proof_bytes = encode_proof(&outer_verifier, &outer)?;
    let start = Instant::now();
    verify(&root_pin, &statement, &proof_bytes)?;
    let outer_verify_ms = start.elapsed().as_secs_f64() * 1e3;
    write(&out.join("outer.proof"), &proof_bytes)?;
    json(&out.join("statement.json"), &statement)?;
    let metrics = serde_json::json!({
        "profile": profile,
        "rayon_threads": rayon::current_num_threads(),
        "zero_knowledge": false,
        "children": 2,
        "leaf_prepare_ms": leaf_prepare_ms,
        "child_prove_ms": child_prove_ms,
        "outer_prepare_ms": outer_prepare_ms,
        "outer_prove_ms": outer_prove_ms,
        "outer_verify_ms": outer_verify_ms,
        "total_prove_process_ms": total_start.elapsed().as_secs_f64() * 1e3,
        "child_proof_bytes": child_bytes,
        "outer_proof_bytes": proof_bytes.len(),
        "outer_verifier_bytes": root_pin.len(),
        "statement_field_bytes": statement.bytes()?.len(),
        "measurements": "One run, not a statistical benchmark. Preparation is cold; outer_prove includes witness/trace generation. Verify includes artifact decoding.",
    });
    json(&out.join("metrics.json"), &metrics)?;
    println!("{}", serde_json::to_string_pretty(&metrics)?);
    Ok(())
}
fn verify_files(trusted: &Path, statement: &Path, proof: &Path) -> Result<()> {
    // Deliberately reads no child artifacts, prover data, or circuit witness.
    let limits = ArtifactLimits::default();
    let pin = read(&trusted.join("outer.verifier"), limits.max_verifier_bytes)?;
    let expected: Statement = serde_json::from_slice(&read(statement, 4096)?)?;
    let proof = read(proof, limits.max_proof_bytes)?;
    verify(&pin, &expected, &proof)?;
    println!("VERIFIED one outer proof for {:?}", expected.children);
    Ok(())
}
fn demo(out: &Path, profile: Profile, left: u32, right: u32) -> Result<()> {
    Statement::from_inputs(left, right)?;
    new_dir(out)?;
    let executable = std::env::current_exe()?;
    let trusted = out.join("trusted");
    let result = out.join("result");
    let name = match profile {
        Profile::Reference => "reference",
        Profile::Smoke => "smoke",
    };
    let status = Command::new(&executable)
        .arg("setup")
        .arg("--out")
        .arg(&trusted)
        .args(["--profile", name])
        .status()?;
    ensure!(status.success(), "setup process failed");
    let status = Command::new(&executable)
        .arg("prove")
        .arg("--trusted-dir")
        .arg(&trusted)
        .arg("--out")
        .arg(&result)
        .arg("--left")
        .arg(left.to_string())
        .arg("--right")
        .arg(right.to_string())
        .status()?;
    ensure!(status.success(), "proving process failed");
    let status = Command::new(&executable)
        .arg("verify")
        .arg("--trusted-dir")
        .arg(&trusted)
        .arg("--statement")
        .arg(result.join("statement.json"))
        .arg("--proof")
        .arg(result.join("outer.proof"))
        .status()?;
    ensure!(status.success(), "independent verifier process failed");
    println!("Complete: two child proofs -> one recursive proof -> fresh-process verification.");
    Ok(())
}
fn main() -> Result<()> {
    match Args::parse().command {
        Action::Demo {
            out,
            profile,
            left,
            right,
        } => demo(&out, profile, left, right),
        Action::Setup { out, profile } => setup(&out, profile),
        Action::Prove {
            trusted_dir,
            out,
            left,
            right,
        } => prove(&trusted_dir, &out, left, right),
        Action::Verify {
            trusted_dir,
            statement,
            proof,
        } => verify_files(&trusted_dir, &statement, &proof),
    }
}
