use minimal_recursion::Statement;
use std::{
    fs,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};
#[test]
fn fresh_process_odd_batch_without_children_and_rejects_wrong_digest() {
    let dir = std::env::temp_dir().join(format!(
        "sha3-recursion-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let exe = env!("CARGO_BIN_EXE_minimal-recursion");
    let out = Command::new(exe)
        .args(["demo", "--count", "3", "--profile", "smoke", "--out"])
        .arg(&dir)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("VERIFIED one outer proof for 3"));
    for i in 0..3 {
        assert!(!dir.join(format!("client-{i}")).exists());
    }
    let path = dir.join("result/statement.json");
    let mut statement: Statement = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    statement.digests[2].0[0] ^= 1;
    fs::write(&path, serde_json::to_vec(&statement).unwrap()).unwrap();
    let out = Command::new(exe)
        .arg("verify")
        .arg("--trusted-dir")
        .arg(dir.join("trusted"))
        .arg("--statement")
        .arg(path)
        .arg("--proof")
        .arg(dir.join("result/outer.proof"))
        .output()
        .unwrap();
    assert!(!out.status.success());
    fs::remove_dir_all(dir).unwrap();
}
