use anyhow::Result;
use p3_circuit::CircuitBuilder;
use p3_field::PrimeCharacteristicRing;

use super::{PUBLIC_COUNTS, connect_parts};
use crate::binary::{
    cli::fixtures,
    engine::{PreparedCircuit, Settings},
    veil::{F, child::recursive::PreparedMaskedVerifier, parameters::Parameters},
};

#[test]
fn every_bridge_between_verifier_parts_is_constrained() -> Result<()> {
    let mut b = CircuitBuilder::<F>::new();
    let root = b.alloc_public_input_array::<40>("statement");
    let parts = PUBLIC_COUNTS.map(|n| b.alloc_private_inputs(n, "part-statement"));
    connect_parts(&mut b, &root, &parts)?;
    let circuit = b.build()?;
    let public = vec![F::ZERO; 40];
    let private = vec![F::ZERO; PUBLIC_COUNTS.iter().sum()];
    let mut r = circuit.runner();
    r.set_public_inputs(&public)?;
    r.set_private_inputs(&private)?;
    r.run_witness()?;
    // Every public scalar is either the outer statement or a connected bridge;
    // no native verifier output is represented by a free acceptance Boolean.
    for i in 0..private.len() {
        let mut changed = private.clone();
        changed[i] = F::ONE;
        let mut r = circuit.runner();
        assert!(
            r.set_public_inputs(&public)
                .and_then(|()| r.set_private_inputs(&changed))
                .and_then(|()| r.run_witness())
                .is_err(),
            "unbound part field {i}"
        );
    }
    Ok(())
}

#[test]
#[ignore = "complete linked child verifier at depth 32"]
fn linked_parts_execute_actual_masked_child_and_reject_mutations() -> Result<()> {
    let prepared = PreparedMaskedVerifier::new(32, Parameters::default())?;
    let (public, witness) = fixtures(32, 1)?.remove(0);
    let proof = prepared.child.prove(&public, &witness)?;
    let inputs = prepared.import_parts(&public, &proof)?;
    for (part, input) in inputs.iter().enumerate() {
        let circuit = prepared.part_circuit(part)?;
        eprintln!("part {part}: {} witnesses", circuit.witness_count);
        let mut r = circuit.runner();
        r.set_public_inputs(&input.public)?;
        r.set_private_inputs(&input.private)?;
        r.run_witness()?;
        for i in [0, input.public.len() / 2, input.public.len() - 1] {
            let mut changed = input.public.clone();
            changed[i] += F::ONE;
            let mut r = circuit.runner();
            assert!(
                r.set_public_inputs(&changed)
                    .and_then(|()| r.set_private_inputs(&input.private))
                    .and_then(|()| r.run_witness())
                    .is_err(),
                "part {part} public {i}"
            );
        }
        for i in [0, input.private.len() - 1] {
            let mut changed = input.private.clone();
            changed[i] += F::ONE;
            let mut r = circuit.runner();
            assert!(
                r.set_public_inputs(&input.public)
                    .and_then(|()| r.set_private_inputs(&changed))
                    .and_then(|()| r.run_witness())
                    .is_err(),
                "part {part} private {i}"
            );
        }
    }
    Ok(())
}

fn actual_outer(part: usize) -> Result<()> {
    let prepared = PreparedMaskedVerifier::new(32, Parameters::default())?;
    let (public, witness) = fixtures(32, 1)?.remove(0);
    let proof = prepared.child.prove(&public, &witness)?;
    let inputs = prepared.import_parts(&public, &proof)?;
    let circuit = prepared.part_circuit(part)?;
    eprintln!("part {part}: {} witnesses", circuit.witness_count);
    let settings = Settings {
        packed_log_inv_rate: 1,
        ..Settings::default()
    };
    let prepared = PreparedCircuit::new(
        circuit,
        &settings,
        format!("imt-masked-verifier-part-v1/{part}").as_bytes(),
    )?;
    eprintln!(
        "part {part}: setup completed, {} initial codeword cells",
        prepared.geometry.initial_codeword_cells
    );
    let (proof, metrics) = prepared.prove(&inputs[part].public, &inputs[part].private)?;
    prepared.verify(&proof, &inputs[part].public)?;
    eprintln!(
        "part {part}: prove {:.3}ms, verify {:.3}ms, {} bytes",
        metrics.prove_ms,
        metrics.verify_ms,
        proof.len()
    );
    Ok(())
}

#[test]
#[ignore = "actual outer proof of the complete AIR/oracle/affine part"]
fn actual_outer_air_part() -> Result<()> {
    actual_outer(0)
}
#[test]
#[ignore = "actual outer proof of the product-vector part"]
fn actual_outer_product_part() -> Result<()> {
    actual_outer(1)
}
#[test]
#[ignore = "actual outer proof of the mask-vector part"]
fn actual_outer_mask_part() -> Result<()> {
    actual_outer(2)
}
