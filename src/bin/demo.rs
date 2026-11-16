use anyhow::{Result, ensure};
use clap::Parser;
use recursive_imt_poc::{client, codec, fixtures};
use std::{
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::Instant,
};
#[derive(Parser)]
struct Args {
    #[arg(long, default_value_t = 8)]
    depth: u8,
    #[arg(long, default_value = "run/demo")]
    out: PathBuf,
    /// Run available milestones only, explicitly WITHOUT recursive authorization.
    #[arg(long)]
    diagnostic_transition_only: bool,
    #[arg(long)]
    historical_roots: bool,
}
fn binary(name: &str) -> Result<PathBuf> {
    let p = std::env::current_exe()?.with_file_name(name);
    ensure!(
        p.exists(),
        "build all workers first: cargo build --release --bins"
    );
    Ok(p)
}
fn worker(key: &Path, depth: u8, out: &Path, w: &client::ClientWitness) -> Result<()> {
    let mut child = Command::new(binary("client-worker")?)
        .args(["--key"])
        .arg(key)
        .args(["--depth", &depth.to_string(), "--out"])
        .arg(out)
        .stdin(Stdio::piped())
        .spawn()?;
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&serde_json::to_vec(w)?)?;
    ensure!(child.wait()?.success(), "client worker failed");
    Ok(())
}
fn main() -> Result<()> {
    let a = Args::parse();
    ensure!(
        !a.out.exists(),
        "output exists; choose a fresh --out directory"
    );
    std::fs::create_dir_all(&a.out)?;
    println!(
        "INCOMPLETE RESEARCH PROTOTYPE: full-ZK SPARK clients + transition diagnostics; recursive client verification missing."
    );
    let f = fixtures::pair(a.depth, a.historical_roots)?;
    let start = Instant::now();
    let c = client::build(a.depth, &f.clients[0], &f.witnesses[0])?;
    ensure!(c.satisfied(), "client relation unsatisfied");
    let build_ms = start.elapsed().as_secs_f64() * 1000.;
    let stats = serde_json::to_value(&c.stats)?;
    let start = Instant::now();
    let (pk, vk) = client::setup(c.shape)?;
    let setup_ms = start.elapsed().as_secs_f64() * 1000.;
    codec::write(&a.out.join("client-pk.bin"), 1, &pk)?;
    codec::write(&a.out.join("client-vk.bin"), 2, &vk)?;
    let setup = serde_json::json!({"build_ms":build_ms,"setup_ms":setup_ms,"dimensions":stats,"client_key_sha256":codec::id(2,&vk)?,"config":client::config()});
    std::fs::write(a.out.join("setup.json"), serde_json::to_vec_pretty(&setup)?)?;
    std::fs::write(
        a.out.join("state.json"),
        serde_json::to_vec_pretty(&f.state)?,
    )?;
    std::fs::write(
        a.out.join("statement.json"),
        serde_json::to_vec_pretty(&f.batch)?,
    )?;
    std::fs::write(
        a.out.join("append.json"),
        serde_json::to_vec_pretty(&f.append)?,
    )?;
    // Independent processes receive their own witness via stdin. No secret or
    // private spent-note path is written to disk. Aggregator receives no pipe.
    for i in 0..2 {
        worker(
            &a.out.join("client-pk.bin"),
            a.depth,
            &a.out.join(format!("client{i}.bin")),
            &f.witnesses[i],
        )?;
    }
    drop(f);
    drop(pk);
    drop(vk);
    let mut command = Command::new(binary("aggregate")?);
    command.arg("--directory").arg(&a.out);
    if a.diagnostic_transition_only {
        command.arg("--diagnostic-transition-only");
    }
    ensure!(
        command.status()?.success(),
        "stopped at missing recursive verifier (no outer authorization proof; state unchanged)"
    );
    let status = Command::new(binary("verify")?)
        .arg("--state")
        .arg(a.out.join("state.json"))
        .arg("--statement")
        .arg(a.out.join("statement.json"))
        .arg("--proof")
        .arg(a.out.join("transition-diagnostic.bin"))
        .arg("--diagnostic-transition-only")
        .status()?;
    ensure!(
        status.success(),
        "fresh-process transition diagnostic failed"
    );
    println!(
        "Available milestones completed; requested recursive PoC is NOT complete. State remains unchanged."
    );
    Ok(())
}
