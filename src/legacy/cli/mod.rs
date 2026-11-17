mod benchmark;
mod demo;
mod io;
mod types;

use anyhow::{Result, ensure};
pub(crate) use benchmark::{BenchmarkOptions, benchmark};
pub(crate) use demo::{demo, fixtures};
use io::{
    INPUT_JSON_LIMIT, create_output_dir, read_bounded, read_json, read_manifest, write_json,
    write_new,
};
use p3_recursion::artifact::ArtifactLimits;
use recursive_imt_prover::legacy::tree::{ClientInput, calibration, check_depth};
use recursive_imt_prover::legacy::{
    Claim, Digest, FORMAT_VERSION, Leaf, MAX_CHILD_PROOF_BYTES, OUTER_PROTOCOL, Profile, RELATION,
    Statement, aggregate, check_count, import_child, importer, verify, verify_allowed,
};
use std::{
    path::{Path, PathBuf},
    time::Instant,
};
pub(crate) use types::TreeOptions;
use types::{BatchMetrics, ClientMetrics, FriMetrics, Manifest, SetupMetrics, WhirMetrics};

pub(crate) fn setup(out: &Path, count: usize, depth: u8, profile: Profile) -> Result<()> {
    check_count(count)?;
    check_depth(depth)?;
    notice(profile);
    create_output_dir(out)?;
    let total = Instant::now();
    let start = Instant::now();
    let leaf = Leaf::prepare(profile, depth)?;
    let leaf_prepare_ms = start.elapsed().as_secs_f64() * 1e3;
    let leaf_pin = leaf.verifier_bytes()?;
    let fixture = calibration(depth)?;
    let importer = importer(profile, &leaf_pin)?;
    let start = Instant::now();
    let mut nodes = Vec::new();
    for _ in 0..count {
        let proof = leaf.prove(&fixture.witness, fixture.claim())?;
        nodes.push(import_child(
            &importer,
            fixture.claim(),
            &leaf.encode_proof(&proof)?,
        )?);
    }
    let calibration_prove_ms = start.elapsed().as_secs_f64() * 1e3;
    eprintln!("Setup: preparing fixed aggregation of {count} SHA3 proofs...");
    let (root, aggregation) = aggregate(nodes, profile, None)?;
    let (root_pin, _) = root.encode()?;
    write_new(&out.join("leaf.verifier"), &leaf_pin)?;
    write_new(&out.join("outer.verifier"), &root_pin)?;
    write_json(
        &out.join("manifest.json"),
        &Manifest {
            version: FORMAT_VERSION,
            relation: RELATION.into(),
            count,
            depth,
            profile,
            outer_protocol: OUTER_PROTOCOL.into(),
        },
    )?;
    write_json(
        &out.join("metrics.json"),
        &SetupMetrics {
            profile,
            count,
            depth,
            hiding_min_height: profile.hiding_min_height(),
            rayon_threads: rayon::current_num_threads(),
            leaf_prepare_ms,
            calibration_prove_ms,
            aggregation,
            total_ms: total.elapsed().as_secs_f64() * 1e3,
            fri: FriMetrics::from(profile),
            outer: WhirMetrics::from(profile),
            child_security: leaf.verifier.johnson_security()?,
        },
    )?;
    println!("Provisioned trusted verifier for {count} SHA3-256 preimage proofs");
    Ok(())
}

pub(crate) fn client(trusted: &Path, out: &Path, witness_file: &Path) -> Result<()> {
    let manifest = read_manifest(trusted)?;
    notice(manifest.profile);
    create_output_dir(out)?;
    let limits = ArtifactLimits::default();
    let pin = read_bounded(&trusted.join("leaf.verifier"), limits.max_verifier_bytes)?;
    let start = Instant::now();
    let leaf = Leaf::prepare(manifest.profile, manifest.depth)?;
    ensure!(
        leaf.verifier_bytes()? == pin,
        "leaf verifier does not match trusted setup"
    );
    let prepare_ms = start.elapsed().as_secs_f64() * 1e3;
    let input: ClientInput = read_json(witness_file, INPUT_JSON_LIMIT)?;
    let claim = input.claim();
    let (proof, timings) = leaf.prove_timed(&input.witness, claim)?;
    let encoded = leaf.encode_proof(&proof)?;
    write_new(&out.join("child.proof"), &encoded)?;
    write_json(&out.join("statement.json"), &Statement::new([claim])?)?;
    write_json(
        &out.join("metrics.json"),
        &ClientMetrics {
            prepare_ms,
            timings,
            proof_bytes: encoded.len(),
            profile: manifest.profile,
        },
    )?;
    println!("Produced one ZK SHA3-256 IMT membership proof");
    Ok(())
}

pub(crate) fn aggregate_files(trusted: &Path, children: &[PathBuf], out: &Path) -> Result<()> {
    let manifest = read_manifest(trusted)?;
    notice(manifest.profile);
    ensure!(
        children.len() == manifest.count,
        "child count differs from trusted batch size"
    );
    create_output_dir(out)?;
    let total = Instant::now();
    let limits = ArtifactLimits::default();
    let leaf_pin = read_bounded(&trusted.join("leaf.verifier"), limits.max_verifier_bytes)?;
    let root_pin = read_bounded(&trusted.join("outer.verifier"), limits.max_verifier_bytes)?;
    let importer = importer(manifest.profile, &leaf_pin)?;
    let mut nodes = Vec::new();
    let mut claims = Vec::new();
    let mut child_bytes = Vec::new();
    let start = Instant::now();
    for child in children {
        let statement: Statement = read_json(&child.join("statement.json"), INPUT_JSON_LIMIT)?;
        statement.fields()?;
        ensure!(statement.roots.len() == 1, "expected one root per child");
        let bytes = read_bounded(
            &child.join("child.proof"),
            MAX_CHILD_PROOF_BYTES.min(limits.max_proof_bytes),
        )?;
        child_bytes.push(bytes.len());
        let claim = Claim {
            root: statement.roots[0],
            amount: statement.amounts[0],
        };
        claims.push(claim);
        nodes.push(import_child(&importer, claim, &bytes)?);
    }
    let native_import_ms = start.elapsed().as_secs_f64() * 1e3;
    let statement = Statement::new(claims)?;
    eprintln!("Recursively aggregating {} child proofs...", manifest.count);
    let (root, aggregation) = aggregate(nodes, manifest.profile, Some(&root_pin))?;
    ensure!(
        root.statement() == statement.fields()?.as_slice(),
        "aggregation statement ordering mismatch"
    );
    let (_, proof) = root.encode()?;
    let start = Instant::now();
    verify(&root_pin, &statement, &proof)?;
    let verify_ms = start.elapsed().as_secs_f64() * 1e3;
    write_new(&out.join("outer.proof"), &proof)?;
    write_json(&out.join("statement.json"), &statement)?;
    let metrics = BatchMetrics {
        profile: manifest.profile,
        count: manifest.count,
        children_zero_knowledge: true,
        outer_zero_knowledge: false,
        outer: WhirMetrics::from(manifest.profile),
        rayon_threads: rayon::current_num_threads(),
        native_import_ms,
        aggregation,
        verify_ms,
        total_ms: total.elapsed().as_secs_f64() * 1e3,
        child_proof_bytes: child_bytes,
        outer_proof_bytes: proof.len(),
        outer_verifier_bytes: root_pin.len(),
        statement_field_bytes: statement.bytes()?.len(),
        sample_count: 1,
        notes: "Preparation is cold. Prove times include trace generation. Verification includes artifact decoding. No compression or security-bit claim.".into(),
    };
    write_json(&out.join("metrics.json"), &metrics)?;
    println!("{}", serde_json::to_string_pretty(&metrics)?);
    Ok(())
}

pub(crate) fn verify_files(
    trusted: &Path,
    statement: &Path,
    proof: &Path,
    allowed_file: &Path,
) -> Result<()> {
    let limits = ArtifactLimits::default();
    let pin = read_bounded(&trusted.join("outer.verifier"), limits.max_verifier_bytes)?;
    let expected: Statement = read_json(statement, INPUT_JSON_LIMIT)?;
    let proof = read_bounded(proof, limits.max_proof_bytes)?;
    let allowed: Vec<Digest> = read_json(allowed_file, INPUT_JSON_LIMIT)?;
    verify_allowed(&pin, &expected, &proof, &allowed)?;
    println!(
        "VERIFIED one outer proof for {} ordered IMT membership roots",
        expected.roots.len()
    );
    Ok(())
}

fn notice(profile: Profile) {
    eprintln!(
        "Child proofs: hiding FRI + salted commitments. Outer: WHIR over already-ZK proofs, KoalaBear field."
    );
    if profile == Profile::Smoke {
        eprintln!("LOW-SECURITY SMOKE: four FRI queries, zero grinding; tests only.");
    }
}
