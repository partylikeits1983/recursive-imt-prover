use std::{env, fs, path::PathBuf, process::Command};

use anyhow::{Result, ensure};
use recursive_imt_prover::{
    binary::{IMT_DEPTH, aggregation_tree::TreeStatement, relation::AggregatePublic},
    files::{read_json, write_json},
};
use serde_json::Value;

#[test]
#[ignore = "builds the pinned LeanVM adapter and generates real recursive proofs"]
fn fast_cli_verifies_a_saved_preimage_tree() -> Result<()> {
    let scratch = tempfile::tempdir()?;
    let dir = scratch.path().join("batch");
    let bin = env!("CARGO_BIN_EXE_tree-demo");
    let proved = Command::new(bin)
        .args(["-n", "4", "-j", "2", "--threads", "2", "--keep", "--out"])
        .arg(&dir)
        .output()?;
    ensure!(
        proved.status.success(),
        "{}",
        String::from_utf8_lossy(&proved.stderr)
    );
    let report: Value = read_json(&dir.join("report.json"))?;
    assert_eq!(report["jobs"], 2);
    assert_eq!(report["merge_count"], 3);
    assert_eq!(report["client_privacy"], "non-hiding");
    let expected = TreeStatement::from_public(&read_json(&dir.join("statement.json"))?)?;
    let mut bytes = expected.bytes();
    for accepted in [true, false] {
        let result = Command::new(bin)
            .args(["--verify", "--out"])
            .arg(&dir)
            .arg("--trusted")
            .arg(dir.join("trusted.json"))
            .arg("--expected-statement")
            .arg(hex::encode(bytes))
            .output()?;
        assert_eq!(result.status.success(), accepted);
        bytes[0] ^= 1;
    }
    Ok(())
}

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
        let mut stderr = BufReader::new(child.stderr.take().unwrap());
        let mut message = String::new();
        stderr.read_line(&mut message)?;
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
                "--backend",
                "masked",
                "-j",
                "3",
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
    assert_eq!(report["batch_size"], 64);
    let jobs = threads.parse::<usize>()?.min(3);
    assert_eq!(report["jobs"], jobs);
    assert_eq!(report["parallel_children"], jobs);
    assert_eq!(report["parallel_nodes"], jobs);
    assert_eq!(report["children"].as_array().unwrap().len(), 64);
    assert_eq!(report["first_aggregates"].as_array().unwrap().len(), 32);
    assert_eq!(report["circuit_constructions"]["merge"], 1);
    assert_eq!(report["same_key_recursion"], true);
    assert_eq!(report["acceptance_pass"], true);
    assert_eq!(report["fresh_verifier"]["verified"], true);
    assert_eq!(report["invalid_child_statement_rejected"], true);
    assert_eq!(report["invalid_child_proof_rejected"], true);
    assert_eq!(report["foreign_authority_rejected"], true);
    assert_eq!(report["negative_checks"].as_array().unwrap().len(), 10);
    let levels = report["merge_levels"].as_array().unwrap();
    assert_eq!(levels.len(), 5);
    let mut inputs = report["children"].as_array().unwrap();
    let last_leaf = inputs
        .iter()
        .map(|node| node["finished_ms"].as_f64().unwrap())
        .fold(0.0, f64::max);
    for parents in std::iter::once(report["first_aggregates"].as_array().unwrap()).chain(
        levels
            .iter()
            .map(|level| level["nodes"].as_array().unwrap()),
    ) {
        assert_eq!(inputs.len(), 2 * parents.len());
        for (pair, parent) in inputs.as_chunks::<2>().0.iter().zip(parents) {
            let started = parent["started_ms"].as_f64().unwrap();
            assert!(
                pair.iter()
                    .all(|node| node["finished_ms"].as_f64().unwrap() <= started)
            );
        }
        inputs = parents;
    }
    let root_finished = inputs[0]["finished_ms"].as_f64().unwrap();
    let rest_of_tree =
        root_finished - last_leaf + report["fresh_verifier_wall_ms"].as_f64().unwrap();
    assert!(
        report["prepared_aggregation_to_fresh_verification_ms"]
            .as_f64()
            .unwrap()
            >= rest_of_tree
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
                .all(|earlier| earlier.input_tag != statement.input_tag)
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
    let statement = TreeStatement::from_public(&public)?;
    assert_eq!(verified["statement"], hex::encode(statement.bytes()));
    // A relying party can have only the proof, key and its independently known statement.
    let compact = scratch.path().join("compact");
    fs::create_dir(&compact)?;
    for name in ["aggregate.proof", "verifier.key"] {
        fs::hard_link(directory.join(name), compact.join(name))?;
    }
    let check_compact = |expected: &TreeStatement| {
        Command::new(executable)
            .args(["--verify", "--threads", &threads, "--out"])
            .arg(&compact)
            .arg("--trusted")
            .arg(directory.join("trusted.json"))
            .arg("--expected-statement")
            .arg(hex::encode(expected.bytes()))
            .output()
    };
    assert!(check_compact(&statement)?.status.success());
    let mut wrong_digest = statement.clone();
    wrong_digest.digest[31] ^= 1;
    assert!(!check_compact(&wrong_digest)?.status.success());
    for count in [0, 2, 3, 32, 65] {
        assert!(
            !check_compact(&TreeStatement {
                count,
                ..statement.clone()
            })?
            .status
            .success()
        );
    }
    let mut altered = public.clone();
    altered.children[0].root[0] ^= 1;
    write_json(&independent.join("statement.json"), &altered)?;
    ensure!(
        !verify()?.status.success(),
        "fresh verifier accepted an altered root"
    );
    altered = public.clone();
    altered.children[0].input_tag[0] ^= 1;
    write_json(&independent.join("statement.json"), &altered)?;
    ensure!(
        !verify()?.status.success(),
        "fresh verifier accepted an altered input tag"
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
