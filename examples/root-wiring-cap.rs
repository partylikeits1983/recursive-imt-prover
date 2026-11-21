//! Export the depth-12 cap from deterministic terminal setup, independently of any proof.
use anyhow::{Result, ensure};
use clap::Parser;
use imt_flock_backend::{MAX_VERIFIER_BYTES, opening_trace::fixed_wiring_cap};
use recursive_imt_prover::{
    binary::aggregation_tree::{
        cyclic::{self, TrustedVerifier},
        terminal::PreparedTerminalMerge,
    },
    files::{read_bounded, read_json},
};
use std::{
    io::{self, Write},
    path::PathBuf,
};

#[derive(Parser)]
struct Args {
    #[arg(long)]
    child_key: PathBuf,
    #[arg(long)]
    child_trusted: PathBuf,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let trust: TrustedVerifier = read_json(&args.child_trusted)?;
    ensure!(
        trust.protocol == cyclic::PROTOCOL,
        "expected trusted cyclic child key"
    );
    let key = read_bounded(&args.child_key, MAX_VERIFIER_BYTES)?;
    let cap = fixed_wiring_cap(|| {
        let setup = PreparedTerminalMerge::with_shared_opening(
            &key,
            &trust.verifier_digest,
            &trust.identity,
        )?;
        setup.wiring_root()
    })?;
    ensure!(cap.len() == 4096, "incorrect fixed cap size");
    io::stdout().lock().write_all(cap.as_flattened())?;
    Ok(())
}
