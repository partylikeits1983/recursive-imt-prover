use recursive_imt_prover::legacy::Statement;
use serde_json::Value;
use std::{
    env::temp_dir,
    fs,
    path::{Path, PathBuf},
    process::{Command, Output, id},
    time::{SystemTime, UNIX_EPOCH},
};

const EXE: &str = env!("CARGO_BIN_EXE_recursive-imt-prover");

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = temp_dir().join(format!("recursive-imt-prover-{}-{nonce}", id()));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn depth_32_odd_batch_uses_later_roots_and_rejects_tampered_public_data() {
    let directory = TestDirectory::new();
    let out = directory.0.join("demo");
    let output = success(
        Command::new(EXE)
            .args([
                "demo",
                "--count",
                "3",
                "--historical",
                "--profile",
                "smoke",
                "--amounts",
                "7,100000,18446744073709551615",
                "--out",
            ])
            .arg(&out),
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("VERIFIED one outer proof for 3"));
    assert_private_files_removed(&out, 3);
    let history: Value =
        serde_json::from_slice(&fs::read(out.join("tree-history.json")).unwrap()).unwrap();
    assert_eq!(history["prefilled_leaves"], 128);
    assert_eq!(
        history["proof_leaf_counts"],
        serde_json::json!([139, 147, 155])
    );
    let manifest: Value =
        serde_json::from_slice(&fs::read(out.join("trusted/manifest.json")).unwrap()).unwrap();
    assert_eq!(manifest["depth"], 32);
    let path = out.join("result/statement.json");
    let statement: Statement = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    assert_eq!(statement.amounts, [7, 100000, u64::MAX]);
    assert_ne!(statement.roots[0], statement.roots[1]);
    for mutation in 0..3 {
        let mut bad = statement.clone();
        match mutation {
            0 => bad.roots[2].0[0] ^= 1,
            1 => bad.amounts[2] ^= 1,
            _ => bad.amounts.swap(0, 1),
        }
        fs::write(&path, serde_json::to_vec(&bad).unwrap()).unwrap();
        assert!(!verifier(&out).output().unwrap().status.success());
    }
    fs::write(&path, serde_json::to_vec(&statement).unwrap()).unwrap();
    success(&mut verifier(&out));
}

#[test]
fn benchmark_runs_configured_counts_and_samples() {
    let directory = TestDirectory::new();
    let out = directory.0.join("bench");
    let output = success(
        Command::new(EXE)
            .args([
                "benchmark",
                "--counts",
                "1,3",
                "--samples",
                "2",
                "--profile",
                "smoke",
                "--depth",
                "4",
                "--prefill",
                "2",
                "--append-after",
                "1",
                "--historical",
                "--out",
            ])
            .arg(&out),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Child 3: prove"));
    assert!(stdout.contains("Aggregate: prepare"));
    assert!(stdout.contains("aggregate verify"));
    assert!(stdout.contains("WHIR aggregation, KoalaBear, proven Johnson"));
    let report: Value =
        serde_json::from_slice(&fs::read(out.join("report.json")).unwrap()).unwrap();
    assert_eq!(report["profile"], "smoke");
    assert_eq!(report["samples_per_count"], 2);
    assert_eq!(report["tree"]["depth"], 4);
    assert_eq!(
        report["environment"]["source_sha3_256"]
            .as_str()
            .unwrap()
            .len(),
        64
    );
    for (index, count) in [1, 3].into_iter().enumerate() {
        let series = &report["series"][index];
        assert_eq!(series["count"], count);
        assert_eq!(
            series["setup"]["outer"]["protocol"],
            "koalabear-d4-whir-johnson-v1"
        );
        assert_eq!(series["samples"].as_array().unwrap().len(), 2);
        assert!(
            series["setup"]["child_security"]["model"]
                .as_str()
                .unwrap()
                .contains("Johnson")
        );
        for sample in series["samples"].as_array().unwrap() {
            assert_eq!(sample["clients"].as_array().unwrap().len(), count);
            for child in sample["clients"].as_array().unwrap() {
                for timing in ["trace_ms", "prove_ms", "verify_ms"] {
                    assert!(child[timing].as_f64().unwrap() >= 0.0);
                }
            }
        }
        assert!(
            series["summary"]["outer_proof_bytes"]["median"]
                .as_f64()
                .unwrap()
                > 0.0
        );
        for sample in 1..=2 {
            assert_private_files_removed(&out.join(format!("n-{count}/sample-{sample}")), count);
        }
    }
    assert_eq!(
        fs::read_to_string(out.join("children.csv"))
            .unwrap()
            .lines()
            .count(),
        9
    );
    assert_eq!(
        fs::read_to_string(out.join("summary.csv"))
            .unwrap()
            .lines()
            .count(),
        3
    );
}

#[test]
fn invalid_run_configuration_fails_before_creating_outputs() {
    let directory = TestDirectory::new();
    for (index, arguments) in [
        vec!["demo", "--count", "0"],
        vec!["demo", "--count", "2", "--amounts", "100"],
        vec!["demo", "--append-after", "0"],
        vec!["benchmark", "--samples", "0"],
        vec!["benchmark", "--counts", "2,2"],
    ]
    .iter()
    .enumerate()
    {
        let out = directory.0.join(index.to_string());
        let result = Command::new(EXE)
            .args(arguments)
            .arg("--out")
            .arg(&out)
            .output()
            .unwrap();
        assert!(!result.status.success());
        assert!(!out.exists());
    }
}

fn assert_private_files_removed(out: &Path, count: usize) {
    assert!(!out.join("private-inputs").exists());
    for index in 0..count {
        assert!(!out.join(format!("client-{index}")).exists());
    }
}

fn verifier(out: &Path) -> Command {
    let mut command = Command::new(EXE);
    command
        .arg("verify")
        .arg("--trusted-dir")
        .arg(out.join("trusted"))
        .arg("--statement")
        .arg(out.join("result/statement.json"))
        .arg("--proof")
        .arg(out.join("result/outer.proof"))
        .arg("--allowed-roots")
        .arg(out.join("allowed-roots.json"));
    command
}

fn success(command: &mut Command) -> Output {
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}
