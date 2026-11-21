//! Measure the default synthetic recursion workload and independently check its saved proof.
use anyhow::{Result, ensure};
use recursive_imt_prover::binary::{
    AggregatePublic, ClientPublic, IMT_DEPTH, MAX_CHILDREN,
    aggregation_tree::TreeStatement,
    tree::{Imt, keccak, preimage_leaf},
};
use std::{path::Path, process::Command};

// Use the application's sparse tree and batch encoding independently of the LeanVM driver.
fn expected_batch() -> Result<TreeStatement> {
    let mut tree = Imt::new(IMT_DEPTH)?;
    for i in 0..MAX_CHILDREN as u8 {
        let secret = keccak(&[b"imt-recursion-secret".as_slice(), &[i]].concat());
        tree.append(preimage_leaf(&secret))?;
    }
    let mut children = Vec::with_capacity(MAX_CHILDREN);
    for i in 0..MAX_CHILDREN as u8 {
        tree.append(keccak(&[b"imt-recursion-append".as_slice(), &[i]].concat()))?;
        children.push(ClientPublic::membership_root(tree.root()));
    }
    TreeStatement::from_public(&AggregatePublic { children })
}

fn main() -> Result<()> {
    // Cargo also invokes harness-free targets under `test --all-targets`.
    if !std::env::args().any(|a| a == "--bench") {
        return Ok(());
    }
    let repo = Path::new(env!("CARGO_MANIFEST_DIR"));
    let scratch = tempfile::tempdir()?;
    let work = scratch.path().join("leanvm");
    let target = scratch.path().join("target");
    let batch = scratch.path().join("batch");
    let built = Command::new("python3")
        .arg(repo.join("adapters/leanvm/recursion/prepare.py"))
        .arg("--work")
        .arg(&work)
        .env("CARGO_TARGET_DIR", &target)
        .status()?;
    ensure!(built.success(), "building the pinned LeanVM adapter failed");

    let binary = target
        .join("release")
        .join(format!("imt-recursion{}", std::env::consts::EXE_SUFFIX));
    let proved = Command::new(&binary)
        .args(["benchmark", "--out"])
        .arg(&batch)
        .status()?;
    ensure!(proved.success(), "LeanVM recursion benchmark failed");
    let expected = expected_batch()?;
    let verified = Command::new(binary)
        .arg("verify")
        .arg(batch.join("root.imt"))
        .arg(hex::encode(expected.digest))
        .arg(expected.count.to_string())
        .status()?;
    ensure!(
        verified.success(),
        "saved root failed independent IMT statement verification"
    );
    Ok(())
}
