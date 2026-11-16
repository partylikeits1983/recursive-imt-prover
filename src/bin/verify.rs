use anyhow::{Result, ensure};
use clap::Parser;
use recursive_imt_poc::{
    codec, outer,
    state::{TrustedState, verify_and_apply},
    statement::BatchStatement,
};
use std::path::PathBuf;
#[derive(Parser)]
struct Args {
    #[arg(long)]
    state: PathBuf,
    #[arg(long)]
    statement: PathBuf,
    #[arg(long)]
    proof: PathBuf,
    /// Verifies only the diagnostic transition relation. NEVER applies state.
    #[arg(long)]
    diagnostic_transition_only: bool,
}
fn main() -> Result<()> {
    let a = Args::parse();
    let mut state: TrustedState = serde_json::from_slice(&std::fs::read(&a.state)?)?;
    let s: BatchStatement = serde_json::from_slice(&std::fs::read(&a.statement)?)?;
    state.precheck(&s)?;
    ensure!(
        std::fs::metadata(&a.proof)?.len() <= codec::MAX_BYTES,
        "proof too large"
    );
    let bytes = std::fs::read(&a.proof)?;
    if a.diagnostic_transition_only {
        // Reconstruct ONLY the fixed circuit selected by trusted local state and
        // the compiled binary. Never derive the program/key from proof metadata.
        let c = outer::build_transition(state.depth)?;
        let prepared = outer::prepare(&c)?;
        let proof: outer::TransitionProof = codec::decode(4, &bytes)?;
        prepared.verifier().verify(
            &proof,
            &s.fields()
                .into_iter()
                .map(outer::convert)
                .collect::<Vec<_>>(),
        )?;
        println!(
            "Transition diagnostic verified in fresh process, without children. NO client authorization proven; state unchanged."
        );
        return Ok(());
    }
    verify_and_apply(&mut state, &s, &bytes)?;
    // No successful path exists in v0-incomplete; no file writes on failure.
    anyhow::bail!("unreachable: recursive verifier must be implemented before state persistence")
}
