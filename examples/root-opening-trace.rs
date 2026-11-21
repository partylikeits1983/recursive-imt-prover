//! Emit the Merkle openings checked by one successful native root verification.
use anyhow::{Result, ensure};
use clap::Parser;
use imt_flock_backend::{MAX_VERIFIER_BYTES, opening_trace};
use recursive_imt_prover::{
    binary::aggregation_tree::{RootVerifier, TreeStatement, cyclic::TrustedVerifier},
    files::{read_bounded, read_json},
};
use std::{io, path::PathBuf};

#[derive(Parser)]
struct Args {
    #[arg(long)]
    bundle: PathBuf,
    #[arg(long)]
    trusted: PathBuf,
    /// Compare conditional algebraic bounds on this trusted root geometry.
    #[arg(long)]
    security_sweep: bool,
    /// Find the smallest supported local WHIR budget meeting this composed terminal floor.
    #[arg(long, requires = "max_grinding_bits", value_parser = clap::value_parser!(u32).range(1..=192))]
    select_conditional_bits: Option<u32>,
    #[arg(long, requires = "select_conditional_bits", value_parser = clap::value_parser!(u32).range(16..=17))]
    max_grinding_bits: Option<u32>,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let trusted: TrustedVerifier = read_json(&args.trusted)?;
    let key = read_bounded(&args.bundle.join("verifier.key"), MAX_VERIFIER_BYTES)?;
    let verifier = RootVerifier::from_trusted(&key, &trusted)?;
    let wiring_root = match &verifier {
        RootVerifier::Terminal(v) => Some(hex::encode(v.wiring_root()?)),
        RootVerifier::Cyclic(_) => None,
    };
    let proof = read_bounded(&args.bundle.join("aggregate.proof"), 16 << 20)?;
    let public = read_json(&args.bundle.join("statement.json"))?;
    let statement = TreeStatement::from_public(&public)?;
    let search = args
        .select_conditional_bits
        .zip(args.max_grinding_bits)
        .map(|(conditional_bits, grind)| opening_trace::SecuritySearch {
            conditional_bits,
            max_grinding_bits: grind as usize,
        });
    let trace = opening_trace::capture_with_search(args.security_sweep, search, || {
        verifier.verify_statement(&proof, &statement)
    })?;
    ensure!(
        search.is_none() || trace.selected_parameters.is_some(),
        "parameter selection requires a shared terminal root"
    );
    if args.security_sweep {
        ensure!(
            trace
                .security_sweep
                .as_ref()
                .is_some_and(|rows| !rows.is_empty()),
            "a shared-opening terminal root is required for the security sweep"
        );
    }
    ensure!(
        !trace.openings.is_empty(),
        "no authenticated Merkle openings"
    );
    let body_cost = (trusted.protocol
        == recursive_imt_prover::binary::aggregation_tree::terminal::PROTOCOL)
        .then(|| imt_flock_backend::terminal_opening::terminal_body_cost(&proof))
        .transpose()?;
    serde_json::to_writer(
        io::stdout().lock(),
        &serde_json::json!({
            "protocol": trusted.protocol, "statement": hex::encode(statement.bytes()), "verifier_digest": hex::encode(trusted.verifier_digest), "trusted_wiring_root": wiring_root,
            "terminal_body_cost": body_cost, "openings": trace.openings, "linked_prefix": trace.linked_prefix, "linked_closing": trace.linked_closing,
            "shared_algebraic_bits": trace.shared_algebraic_bits, "security_sweep": trace.security_sweep, "selected_parameters": trace.selected_parameters, "arithmetic_prefix": trace.arithmetic_prefix,
            "shared_bit_batch": trace.shared_bit_batch, "chi_cubics": trace.chi_cubics, "chi_layers": trace.chi_layers
        }),
    )?;
    Ok(())
}
