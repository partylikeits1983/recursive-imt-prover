use crate::support;

use p3_circuit::CircuitBuilder;
use p3_field::PrimeCharacteristicRing;
use p3_recursion::{PcsRecursionBackend, RecursionInput, VerifierCircuitResult};
use recursive_imt_prover::legacy::tree::ClientInput;
use recursive_imt_prover::legacy::{
    Backend, Child, E, ImtAir, Leaf, Profile, Statement, ZkConfig, aggregate, backend,
    import_child, importer, verify, verify_allowed,
};
use support::fixtures;

fn child(leaf: &Leaf, input: &ClientInput) -> Child {
    let proof = leaf.prove(&input.witness, input.claim()).unwrap();
    let importer = importer(Profile::Smoke, &leaf.verifier_bytes().unwrap()).unwrap();
    import_child(
        &importer,
        input.claim(),
        &leaf.encode_proof(&proof).unwrap(),
    )
    .unwrap()
}

#[test]
fn recursive_root_array_and_trusted_key_reuse() {
    let profile = Profile::Smoke;
    let leaf = Leaf::prepare(profile, 4).unwrap();
    for count in [1, 2, 3, 4, 8, 16] {
        let historical = fixtures(count, 4, true);
        let (root, _) = aggregate(
            historical.iter().map(|i| child(&leaf, i)).collect(),
            profile,
            None,
        )
        .unwrap();
        let (pin, encoded) = root.encode().unwrap();
        let statement = Statement::new(historical.iter().map(ClientInput::claim)).unwrap();
        assert_eq!(root.statement(), statement.fields().unwrap());
        verify_allowed(&pin, &statement, &encoded, &statement.roots).unwrap();
        assert!(verify_allowed(&pin, &statement, &encoded, &[]).is_err());
        if count > 1 {
            assert!(verify_allowed(&pin, &statement, &encoded, &statement.roots[1..]).is_err());
            let mut reordered = statement.clone();
            reordered.roots.swap(0, 1);
            assert!(verify(&pin, &reordered, &encoded).is_err());
            reordered.roots.pop();
            assert!(verify(&pin, &reordered, &encoded).is_err());
            let mut wrong_amounts = statement.clone();
            wrong_amounts.amounts.swap(0, 1);
            assert!(verify(&pin, &wrong_amounts, &encoded).is_err());
        }
        for i in 0..count {
            let mut bad = statement.clone();
            bad.roots[i].0[17] ^= 1;
            assert!(verify(&pin, &bad, &encoded).is_err());
            let mut bad = statement.clone();
            bad.amounts[i] ^= 1;
            assert!(verify(&pin, &bad, &encoded).is_err());
        }
        for i in [0, encoded.len() / 2, encoded.len() - 1] {
            let mut bad = encoded.clone();
            bad[i] ^= 1;
            assert!(verify(&pin, &statement, &bad).is_err());
        }
        // Reuse the trusted key with fresh notes and repeated current roots.
        let current = fixtures(count, 4, false);
        let (root, _) = aggregate(
            current.iter().map(|i| child(&leaf, i)).collect(),
            profile,
            Some(&pin),
        )
        .unwrap();
        let statement = Statement::new(current.iter().map(ClientInput::claim)).unwrap();
        let (new_pin, encoded) = root.encode().unwrap();
        assert_eq!(new_pin, pin);
        verify_allowed(&pin, &statement, &encoded, &[current[0].root]).unwrap();
    }
}

#[test]
fn malformed_hiding_proof_witness_bypasses_native_prefilter() {
    let profile = Profile::Smoke;
    let leaf = Leaf::prepare(profile, 4).unwrap();
    let input = fixtures(2, 4, false).pop().unwrap();
    let fields = input.claim().fields();
    let proof = leaf.prove(&input.witness, input.claim()).unwrap();
    let verifier = &leaf.verifier;
    let previous = RecursionInput::<ZkConfig, ImtAir>::UniStark {
        proof: &proof,
        air: &verifier.air,
        public_inputs: fields.to_vec(),
        preprocessed_commit: None,
    };
    let backend = backend();
    let mut builder = CircuitBuilder::new();
    <Backend as PcsRecursionBackend<ZkConfig, ImtAir, 4>>::prepare_circuit(
        &backend,
        &verifier.config,
        &mut builder,
    )
    .unwrap();
    let result = <Backend as PcsRecursionBackend<ZkConfig, ImtAir, 4>>::build_verifier_circuit(
        &backend,
        &previous,
        &verifier.config,
        &mut builder,
    )
    .unwrap();
    let circuit = builder.build().unwrap();
    let public = result.pack_public_inputs(&previous).unwrap();
    let private = result.pack_private_inputs(&previous).unwrap();
    let run = |public: &[E], private: &[E]| {
        let mut runner = circuit.runner();
        runner.set_public_inputs(public).unwrap();
        runner.set_private_inputs(private).unwrap();
        <Backend as PcsRecursionBackend<ZkConfig, ImtAir, 4>>::set_private_data_for_result(
            &backend,
            &verifier.config,
            &mut runner,
            &result,
            &previous,
        )
        .unwrap();
        runner.run()
    };
    assert!(run(&public, &private).is_ok());
    // Root limbs and main commitment limbs. Smoke has no grinding, so its
    // unused zero-bit PoW witness is not a meaningful rejection target.
    for i in [0, 15, 16, 23] {
        let mut bad = public.clone();
        bad[i] += E::ONE;
        assert!(run(&bad, &private).is_err(), "public index {i}");
    }
    for i in [0, private.len() / 2, private.len() - 1] {
        let mut bad = private.clone();
        bad[i] += E::ONE;
        assert!(run(&public, &bad).is_err(), "private index {i}");
    }
}
