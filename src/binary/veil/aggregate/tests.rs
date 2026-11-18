use std::{env, path::PathBuf, time::Instant};

use anyhow::Result;
use imt_flock_backend::RecursiveAggregate;

use crate::{
    benchmark::ms,
    binary::{
        aggregation_tree::{
            TreeStatement,
            files::{read_proof, read_verifier},
        },
        relation::F,
    },
};

#[test]
#[ignore = "requires saved depth-32 masked-demo --tree-pair checkpoint artifacts"]
fn real_tree_pair_verifies_recursively() -> Result<()> {
    let directory = PathBuf::from(env::var("IMT_AGGREGATE_INPUT")?);
    let input = read_proof(&directory)?;
    let (verifier, _) = read_verifier(&directory)?;
    verifier.verify(&input.proof, &input.public)?;
    let public = TreeStatement::from_public(&input.public)?.verifier_fields();
    let start = Instant::now();
    let recursive = RecursiveAggregate::new(verifier.outer)?;
    let circuit = recursive.circuit()?;
    let build_ms = ms(start);
    let start = Instant::now();
    let private = recursive.private_inputs(&input.proof, &public)?;
    let import_ms = ms(start);
    let start = Instant::now();
    let mut runner = circuit.runner();
    runner.set_public_inputs(&public)?;
    runner.set_private_inputs(&private)?;
    runner.run_witness()?;
    eprintln!(
        "Depth-32 aggregate verifier: {} witnesses, build {build_ms:.1} ms, import {import_ms:.1} ms, witness {:.1} ms",
        circuit.witness_count,
        ms(start)
    );
    let mut bad = public;
    bad[0] = F::new(bad[0].to_bits() ^ 1);
    let mut runner = circuit.runner();
    runner.set_public_inputs(&bad)?;
    runner.set_private_inputs(&private)?;
    assert!(runner.run_witness().is_err());
    Ok(())
}
