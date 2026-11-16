use minimal_recursion::Statement;
use std::{
    fs,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

#[test]
fn fresh_process_verifies_without_child_files_and_rejects_changed_statement() {
    let dir = std::env::temp_dir().join(format!(
        "minimal-recursion-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let executable = env!("CARGO_BIN_EXE_minimal-recursion");
    let output = Command::new(executable)
        .args(["demo", "--profile", "smoke", "--out"])
        .arg(&dir)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("VERIFIED one outer proof"));
    let result = dir.join("result");
    let mut files: Vec<_> = fs::read_dir(&result)
        .unwrap()
        .map(|x| x.unwrap().file_name())
        .collect();
    files.sort();
    assert_eq!(files, ["metrics.json", "outer.proof", "statement.json"]);
    let statement_path = result.join("statement.json");
    let mut statement: Statement =
        serde_json::from_slice(&fs::read(&statement_path).unwrap()).unwrap();
    statement.children[1][1] += 1;
    fs::write(&statement_path, serde_json::to_vec(&statement).unwrap()).unwrap();
    let rejected = Command::new(executable)
        .arg("verify")
        .arg("--trusted-dir")
        .arg(dir.join("trusted"))
        .arg("--statement")
        .arg(&statement_path)
        .arg("--proof")
        .arg(result.join("outer.proof"))
        .output()
        .unwrap();
    assert!(!rejected.status.success());
    fs::remove_dir_all(dir).unwrap();
}
