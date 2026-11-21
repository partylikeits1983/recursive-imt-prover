//! Count the operations required to check one native root in the recursive circuit.
use std::{collections::BTreeMap, path::PathBuf};

use anyhow::{Result, ensure};
use clap::Parser;
use imt_flock_backend::{MAX_VERIFIER_BYTES, RecursiveAggregate, Verifier};
use p3_circuit::ops::Op;
use recursive_imt_prover::{
    binary::aggregation_tree::cyclic::{PROTOCOL, TrustedVerifier},
    files::{read_bounded, read_json},
};

#[derive(Parser)]
struct Args {
    #[arg(long)]
    key: PathBuf,
    #[arg(long)]
    trusted: PathBuf,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let trust: TrustedVerifier = read_json(&args.trusted)?;
    ensure!(trust.protocol == PROTOCOL, "incorrect cyclic protocol");
    let key = read_bounded(&args.key, MAX_VERIFIER_BYTES)?;
    let verifier = Verifier::from_bytes(
        &key,
        &trust.verifier_digest,
        &trust.identity,
        PROTOCOL.as_bytes(),
    )?;
    let circuit = RecursiveAggregate::new(verifier)?.circuit()?;
    let mut counts = BTreeMap::new();
    for op in &circuit.ops {
        let name = match op {
            Op::Const { .. } => "const".to_owned(),
            Op::Public { .. } => "public".to_owned(),
            Op::Hint { .. } => "hint".to_owned(),
            Op::Alu { kind, .. } => format!("{kind:?}"),
            Op::NonPrimitiveOpWithExecutor { executor, .. } => format!("{:?}", executor.op_type()),
        };
        *counts.entry(name).or_insert(0_usize) += 1;
    }
    println!(
        "{}",
        serde_json::json!({
            "verifier_key_digest": hex::encode(trust.verifier_digest),
            "operations": circuit.ops.len(),
            "by_operation": counts,
            "wires": circuit.witness_count,
            "private_field_elements": circuit.private_flat_len
        })
    );
    Ok(())
}
