use std::{env, fs, path::PathBuf, process::Command};

use anyhow::{Result, ensure};
use recursive_imt_prover::{
    binary::{IMT_DEPTH, relation::AggregatePublic},
    files::{read_json, write_json},
};
use serde_json::Value;

#[cfg(unix)]
#[test]
fn interrupted_demo_cleans_its_files_and_can_rerun() -> Result<()> {
    use std::{
        io::{BufRead, BufReader},
        process::Stdio,
    };

    let root = tempfile::tempdir()?;
    let existing = root.path().join("run/tree-live");
    fs::create_dir_all(&existing)?;
    fs::write(existing.join("existing.txt"), b"keep")?;
    for _ in 0..2 {
        let mut child = Command::new(env!("CARGO_BIN_EXE_tree-demo"))
            .args(["-n", "4", "-j", "3", "--out", "run/tree-live"])
            .current_dir(root.path())
            .stderr(Stdio::piped())
            .spawn()?;
        let mut message = String::new();
        BufReader::new(child.stderr.take().unwrap()).read_line(&mut message)?;
        let interrupted = Command::new("kill")
            .arg("-INT")
            .arg(child.id().to_string())
            .status()?;
        let exit = child.wait()?;
        assert!(message.contains("Preparing circuits"));
        assert!(interrupted.success());
        assert_eq!(exit.code(), Some(130));
        assert_eq!(fs::read_dir(root.path().join("run"))?.count(), 1);
        assert_eq!(fs::read(existing.join("existing.txt"))?, b"keep");
    }
    Ok(())
}

#[test]
#[ignore = "64 real depth-32 child proofs and 63 aggregates; substantial time and memory"]
fn sixty_four_children_reuse_one_merge_key_and_verify_independently() -> Result<()> {
    let run = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("run");
    fs::create_dir_all(&run)?;
    let scratch = tempfile::Builder::new()
        .prefix("cyclic-64-test-")
        .tempdir_in(&run)?;
    let directory = scratch.path().join("verified");
    let executable = env!("CARGO_BIN_EXE_tree-demo");
    let threads = env::var("RAYON_NUM_THREADS").unwrap_or_else(|_| "4".to_owned());
    ensure!(
        Command::new(executable)
            .args([
                "--batch-size",
                "64",
                "--threads",
                &threads,
                "--keep",
                "--out"
            ])
            .arg(&directory)
            .status()?
            .success(),
        "cyclic tree run failed"
    );
    let report: Value = read_json(&directory.join("report.json"))?;
    assert_eq!(report["depth"], IMT_DEPTH);
    assert_eq!(report["children"].as_array().unwrap().len(), 64);
    assert_eq!(report["first_aggregates"].as_array().unwrap().len(), 32);
    assert_eq!(report["circuit_constructions"]["merge"], 1);
    assert_eq!(report["same_key_recursion"], true);
    assert_eq!(report["acceptance_pass"], true);
    assert_eq!(report["fresh_verifier"]["verified"], true);
    assert_eq!(report["invalid_child_statement_rejected"], true);
    assert_eq!(report["invalid_child_proof_rejected"], true);
    assert_eq!(report["foreign_authority_rejected"], true);
    assert_eq!(report["negative_checks"].as_array().unwrap().len(), 9);
    let levels = report["merge_levels"].as_array().unwrap();
    assert_eq!(levels.len(), 5);
    let timed_stages = report["first_aggregation_wall_ms"].as_f64().unwrap()
        + levels
            .iter()
            .map(|l| l["wall_ms"].as_f64().unwrap())
            .sum::<f64>()
        + report["fresh_verifier_wall_ms"].as_f64().unwrap();
    assert!(
        report["prepared_aggregation_to_fresh_verification_ms"]
            .as_f64()
            .unwrap()
            >= timed_stages
    );
    for (index, level) in levels.iter().enumerate() {
        assert_eq!(level["verifier_digest"], report["merge_verifier_digest"]);
        let nodes = level["nodes"].as_array().unwrap();
        assert_eq!(nodes.len(), 16 >> index);
        assert!(nodes.iter().all(|node| node["children"] == 4 << index));
    }
    let public: AggregatePublic = read_json(&directory.join("statement.json"))?;
    assert_eq!(public.children.len(), 64);
    for (index, statement) in public.children.iter().enumerate() {
        assert!(
            public.children[..index]
                .iter()
                .all(|earlier| earlier.nullifier_hash != statement.nullifier_hash)
        );
    }
    let stored = fs::metadata(directory.join("aggregate.proof"))?.len();
    assert_eq!(report["final_proof_bytes"], stored);
    assert!(stored < report["final_uncompressed_proof_bytes"].as_u64().unwrap());
    let independent = directory.join("independent");
    fs::create_dir(&independent)?;
    for name in [
        "aggregate.proof",
        "statement.json",
        "trusted.json",
        "verifier.key",
    ] {
        fs::copy(directory.join(name), independent.join(name))?;
    }
    let verify = || {
        Command::new(executable)
            .args(["--verify", "--threads", &threads, "--out"])
            .arg(&independent)
            .output()
    };
    let result = verify()?;
    ensure!(
        result.status.success(),
        "isolated final verification failed"
    );
    let verified: Value = serde_json::from_slice(&result.stdout)?;
    assert_eq!(verified["verified"], true);
    assert_eq!(verified["children"], 64);
    let mut altered = public.clone();
    altered.children[0].root[0] ^= 1;
    write_json(&independent.join("statement.json"), &altered)?;
    ensure!(
        !verify()?.status.success(),
        "fresh verifier accepted an altered root"
    );
    altered = public.clone();
    altered.children[0].nullifier_hash[0] ^= 1;
    write_json(&independent.join("statement.json"), &altered)?;
    ensure!(
        !verify()?.status.success(),
        "fresh verifier accepted an altered nullifier hash"
    );
    altered = public.clone();
    altered.children.swap(0, 1);
    write_json(&independent.join("statement.json"), &altered)?;
    ensure!(
        !verify()?.status.success(),
        "fresh verifier accepted swapped statements"
    );
    write_json(&independent.join("statement.json"), &public)?;
    eprintln!(
        "64-child same-key tree and isolated verification passed: {}",
        directory.display()
    );
    Ok(())
}
