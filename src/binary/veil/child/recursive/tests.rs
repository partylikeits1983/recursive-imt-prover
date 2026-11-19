use std::time::Instant;

use anyhow::Result;
use mimalloc::MiMalloc;
use p3_field::PrimeCharacteristicRing;

use super::PreparedMaskedVerifier;
use crate::binary::{
    cli::fixtures,
    veil::{F, parameters::Parameters},
};

#[global_allocator]
static ALLOCATOR: MiMalloc = MiMalloc;

#[test]
#[ignore = "complete masked child verifier at depth 32"]
fn complete_masked_child_verifier_checks_real_proof_data() -> Result<()> {
    let prepared = PreparedMaskedVerifier::new(32, Parameters::default())?;
    let (public, witness) = fixtures(32, 1)?.remove(0);
    let proof = prepared.child.prove(&public, &witness)?;
    // The circuit witness importer has no access to `witness`.
    let private = prepared.import(&public, &proof)?;
    let start = Instant::now();
    let circuit = prepared.circuit()?;
    eprintln!(
        "complete masked verifier: build {:.3}s, {} witnesses",
        start.elapsed().as_secs_f64(),
        circuit.witness_count
    );
    let values = public.fields();
    let mut runner = circuit.runner();
    runner.set_public_inputs(&values)?;
    runner.set_private_inputs(&private)?;
    runner.run_witness()?;
    for i in [0, 31, 32, 63, 64, 95] {
        let mut changed = values.clone();
        changed[i] += F::ONE;
        let mut runner = circuit.runner();
        runner.set_public_inputs(&changed)?;
        runner.set_private_inputs(&private)?;
        assert!(runner.run_witness().is_err(), "public mutation {i}");
    }
    for i in [0, 3 * prepared.child.messages, private.len() - 1] {
        let mut changed = private.clone();
        changed[i] += F::ONE;
        let mut runner = circuit.runner();
        runner.set_public_inputs(&values)?;
        runner.set_private_inputs(&changed)?;
        assert!(runner.run_witness().is_err(), "proof mutation {i}");
    }
    Ok(())
}
