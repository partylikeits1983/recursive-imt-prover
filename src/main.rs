use anyhow::{Context, Result, ensure};
use clap::{Parser, Subcommand};
use minimal_recursion::{
    Leaf, Node, Profile, RELATION, Statement, aggregate, check_count, encode_proof,
    encode_verifier, hash, import_child, importer, verify,
};
use p3_recursion::artifact::ArtifactLimits;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    process::Command,
    time::Instant,
};

#[derive(Parser)]
#[command(about = "SHA3-256 preimage proofs -> N-to-one Plonky3 recursion (NON-ZK)")]
struct Args {
    #[command(subcommand)]
    command: Action,
}
#[derive(Subcommand)]
enum Action {
    /// Run setup, independent clients, aggregation and final verification as processes.
    Demo {
        #[arg(long)]
        out: PathBuf,
        #[arg(long, default_value_t = 2)]
        count: usize,
        #[arg(long, value_enum, default_value = "reference")]
        profile: Profile,
    },
    /// Independently provision the exact leaf/root verifier for a fixed batch size.
    Setup {
        #[arg(long)]
        out: PathBuf,
        #[arg(long, default_value_t = 2)]
        count: usize,
        #[arg(long, value_enum, default_value = "reference")]
        profile: Profile,
    },
    /// Generate one proof. Only this process reads/generates the preimage.
    Client {
        #[arg(long)]
        trusted_dir: PathBuf,
        #[arg(long)]
        out: PathBuf,
        /// Optional raw 32-byte witness file; otherwise draw fresh OS-seeded randomness.
        #[arg(long)]
        preimage_file: Option<PathBuf>,
    },
    /// Receives only proof artifacts and public digests; no preimages.
    Aggregate {
        #[arg(long)]
        trusted_dir: PathBuf,
        #[arg(long, required = true, num_args = 1..)]
        children: Vec<PathBuf>,
        #[arg(long)]
        out: PathBuf,
    },
    /// Reads only the trusted root verifier, expected digest list and ONE proof.
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
    count: usize,
    profile: Profile,
}
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
fn manifest(trusted: &Path) -> Result<Manifest> {
    let m: Manifest = serde_json::from_slice(&read(&trusted.join("manifest.json"), 4096)?)?;
    ensure!(
        m.version == 1 && m.relation == RELATION,
        "wrong trusted manifest"
    );
    check_count(m.count)?;
    Ok(m)
}
fn notice(profile: Profile) {
    eprintln!(
        "NON-ZK preimage proof prototype: private circuit inputs are not a secrecy guarantee."
    );
    if profile == Profile::Smoke {
        eprintln!("LOW-SECURITY SMOKE: four FRI queries, zero grinding; tests only.");
    }
}
fn setup(out: &Path, count: usize, profile: Profile) -> Result<()> {
    check_count(count)?;
    notice(profile);
    new_dir(out)?;
    let total = Instant::now();
    let start = Instant::now();
    let leaf = Leaf::prepare(profile)?;
    let leaf_prepare_ms = start.elapsed().as_secs_f64() * 1e3;
    let leaf_pin = encode_verifier(&leaf.verifier())?;
    // PUBLIC deterministic calibration witnesses, never used as actual client secrets.
    let start = Instant::now();
    let mut nodes = Vec::new();
    for i in 0..count {
        let preimage = [0xa0 + i as u8; 32];
        let digest = hash(&preimage);
        nodes.push(Node::Proved {
            proof: Box::new(leaf.prove(&preimage, digest)?),
            verifier: Box::new(leaf.verifier()),
            statement: digest.fields().to_vec(),
        });
    }
    let calibration_prove_ms = start.elapsed().as_secs_f64() * 1e3;
    eprintln!("Setup: preparing fixed aggregation of {count} SHA3 proofs...");
    let (root, aggregation) = aggregate(nodes, profile, None)?;
    let (root_pin, _) = root.encode()?;
    write(&out.join("leaf.verifier"), &leaf_pin)?;
    write(&out.join("outer.verifier"), &root_pin)?;
    json(
        &out.join("manifest.json"),
        &Manifest {
            version: 1,
            relation: RELATION.into(),
            count,
            profile,
        },
    )?;
    let d = profile.descriptor();
    json(
        &out.join("metrics.json"),
        &serde_json::json!({
            "profile":profile, "count":count, "rayon_threads":rayon::current_num_threads(),
            "leaf_prepare_ms":leaf_prepare_ms, "calibration_prove_ms":calibration_prove_ms,
            "aggregation":aggregation, "total_ms":total.elapsed().as_secs_f64()*1e3,
            "fri":{"extension_degree":5,"log_blowup":d.log_blowup(),"num_queries":d.num_queries(),"query_pow_bits":d.query_pow_bits(),"commit_pow_bits":0,"batch_pow_bits":0,"max_log_arity":2,"log_final_poly_len":0,"cap_height":0},
        }),
    )?;
    println!("Provisioned trusted verifier for {count} SHA3-256 preimage proofs");
    Ok(())
}
fn client(trusted: &Path, out: &Path, preimage_file: Option<&Path>) -> Result<()> {
    let m = manifest(trusted)?;
    notice(m.profile);
    new_dir(out)?;
    let limits = ArtifactLimits::default();
    let pin = read(&trusted.join("leaf.verifier"), limits.max_verifier_bytes)?;
    let start = Instant::now();
    let leaf = Leaf::prepare(m.profile)?;
    ensure!(
        encode_verifier(&leaf.verifier())? == pin,
        "leaf verifier does not match trusted setup"
    );
    let prepare_ms = start.elapsed().as_secs_f64() * 1e3;
    let mut preimage = [0u8; 32];
    if let Some(path) = preimage_file {
        preimage = read(path, 32)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("preimage must contain exactly 32 raw bytes"))?;
    } else {
        rand::rng().fill_bytes(&mut preimage);
    }
    let digest = hash(&preimage);
    let start = Instant::now();
    let proof = leaf.prove(&preimage, digest)?;
    let prove_ms = start.elapsed().as_secs_f64() * 1e3;
    let encoded = encode_proof(&leaf.verifier(), &proof)?;
    write(&out.join("child.proof"), &encoded)?;
    json(&out.join("statement.json"), &Statement::new(vec![digest])?)?;
    json(
        &out.join("metrics.json"),
        &serde_json::json!({"prepare_ms":prepare_ms,"prove_ms":prove_ms,"proof_bytes":encoded.len(),"profile":m.profile}),
    )?;
    println!("Produced one SHA3-256 proof");
    Ok(())
}
fn aggregate_files(trusted: &Path, children: &[PathBuf], out: &Path) -> Result<()> {
    let m = manifest(trusted)?;
    notice(m.profile);
    ensure!(
        children.len() == m.count,
        "child count differs from trusted batch size"
    );
    new_dir(out)?;
    let total = Instant::now();
    let limits = ArtifactLimits::default();
    let leaf_pin = read(&trusted.join("leaf.verifier"), limits.max_verifier_bytes)?;
    let root_pin = read(&trusted.join("outer.verifier"), limits.max_verifier_bytes)?;
    let importer = importer(m.profile, &leaf_pin)?;
    let mut nodes = Vec::new();
    let mut digests = Vec::new();
    let mut child_bytes = Vec::new();
    let start = Instant::now();
    for child in children {
        let s: Statement = serde_json::from_slice(&read(&child.join("statement.json"), 4096)?)?;
        s.fields()?;
        ensure!(s.digests.len() == 1, "expected one digest per child");
        let bytes = read(&child.join("child.proof"), limits.max_proof_bytes)?;
        child_bytes.push(bytes.len());
        digests.push(s.digests[0]);
        nodes.push(import_child(&importer, s.digests[0], &bytes)?);
    }
    let native_import_ms = start.elapsed().as_secs_f64() * 1e3;
    let statement = Statement::new(digests)?;
    eprintln!("Recursively aggregating {} child proofs...", m.count);
    let (root, aggregation) = aggregate(nodes, m.profile, Some(&root_pin))?;
    ensure!(
        root.statement() == statement.fields()?.as_slice(),
        "aggregation statement ordering mismatch"
    );
    let (_, proof) = root.encode()?;
    let start = Instant::now();
    verify(&root_pin, &statement, &proof)?;
    let verify_ms = start.elapsed().as_secs_f64() * 1e3;
    write(&out.join("outer.proof"), &proof)?;
    json(&out.join("statement.json"), &statement)?;
    let metrics = serde_json::json!({
        "profile":m.profile,"count":m.count,"zero_knowledge":false,"rayon_threads":rayon::current_num_threads(),
        "native_import_ms":native_import_ms,"aggregation":aggregation,"verify_ms":verify_ms,
        "total_ms":total.elapsed().as_secs_f64()*1e3,"child_proof_bytes":child_bytes,
        "outer_proof_bytes":proof.len(),"outer_verifier_bytes":root_pin.len(),"statement_field_bytes":statement.bytes()?.len(),
        "sample_count":1,"notes":"Preparation is cold. Prove times include trace generation. Verification includes artifact decoding. No compression or security-bit claim.",
    });
    json(&out.join("metrics.json"), &metrics)?;
    println!("{}", serde_json::to_string_pretty(&metrics)?);
    Ok(())
}
fn verify_files(trusted: &Path, statement: &Path, proof: &Path) -> Result<()> {
    let limits = ArtifactLimits::default();
    let pin = read(&trusted.join("outer.verifier"), limits.max_verifier_bytes)?;
    let expected: Statement = serde_json::from_slice(&read(statement, 4096)?)?;
    let proof = read(proof, limits.max_proof_bytes)?;
    verify(&pin, &expected, &proof)?;
    println!(
        "VERIFIED one outer proof for {} ordered SHA3-256 digests",
        expected.digests.len()
    );
    Ok(())
}
fn demo(out: &Path, count: usize, profile: Profile) -> Result<()> {
    check_count(count)?;
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
        .args(["--profile", name, "--count", &count.to_string()])
        .status()?;
    ensure!(status.success(), "setup process failed");
    let mut children = Vec::new();
    for i in 0..count {
        let child = out.join(format!("client-{i}"));
        let status = Command::new(&executable)
            .arg("client")
            .arg("--trusted-dir")
            .arg(&trusted)
            .arg("--out")
            .arg(&child)
            .status()?;
        ensure!(status.success(), "client process failed");
        children.push(child);
    }
    let status = Command::new(&executable)
        .arg("aggregate")
        .arg("--trusted-dir")
        .arg(&trusted)
        .arg("--out")
        .arg(&result)
        .arg("--children")
        .args(&children)
        .status()?;
    ensure!(status.success(), "aggregation process failed");
    // Retain only measurements; remove demo-owned child proofs before final verification.
    let child_metrics: Vec<serde_json::Value> = children
        .iter()
        .map(|p| {
            Ok(serde_json::from_slice(&read(
                &p.join("metrics.json"),
                4096,
            )?)?)
        })
        .collect::<Result<_>>()?;
    json(&out.join("client-metrics.json"), &child_metrics)?;
    for child in children {
        fs::remove_dir_all(child)?;
    }
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
    println!(
        "Complete: {count} independent SHA3 preimage proofs -> one recursive proof -> fresh verification without child files."
    );
    Ok(())
}
fn main() -> Result<()> {
    match Args::parse().command {
        Action::Demo {
            out,
            count,
            profile,
        } => demo(&out, count, profile),
        Action::Setup {
            out,
            count,
            profile,
        } => setup(&out, count, profile),
        Action::Client {
            trusted_dir,
            out,
            preimage_file,
        } => client(&trusted_dir, &out, preimage_file.as_deref()),
        Action::Aggregate {
            trusted_dir,
            children,
            out,
        } => aggregate_files(&trusted_dir, &children, &out),
        Action::Verify {
            trusted_dir,
            statement,
            proof,
        } => verify_files(&trusted_dir, &statement, &proof),
    }
}
