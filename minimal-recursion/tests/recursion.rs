use minimal_recursion::*;
use p3_circuit::CircuitBuilder;
use p3_field::PrimeCharacteristicRing;
use p3_recursion::{
    BatchOnly, PcsRecursionBackend, RecursionInput, TrustedPcsRecursionBackend,
    VerifierCircuitResult,
};

#[test]
fn two_actual_children_one_proof_binding_and_prepared_reuse() {
    let profile = Profile::Smoke; // Explicitly low security; reference is run by the demo.
    let leaf = Leaf::prepare(profile).unwrap();
    let calibration = Statement::from_inputs(7, 11)
        .unwrap()
        .child_fields()
        .unwrap();
    let mut initial = [
        leaf.prove(calibration[0]).unwrap(),
        leaf.prove(calibration[1]).unwrap(),
    ];
    let owner = prepare_aggregator(
        profile,
        leaf.verifier(),
        [&initial[0], &initial[1]],
        &calibration,
    )
    .unwrap();
    let pin = encode_verifier(&owner.verifier()).unwrap();

    // Two pairs under exactly the same prepared circuit, different from setup.
    for (left, right) in [(3, 5), (17, 23)] {
        let statement = Statement::from_inputs(left, right).unwrap();
        let fields = statement.child_fields().unwrap();
        let children = [
            leaf.prove(fields[0]).unwrap(),
            leaf.prove(fields[1]).unwrap(),
        ];
        assert_ne!(
            encode_proof(&leaf.verifier(), &children[0]).unwrap(),
            encode_proof(&leaf.verifier(), &children[1]).unwrap()
        );
        let proof = aggregate(&owner, [&children[0], &children[1]], &fields).unwrap();
        let encoded = encode_proof(&owner.verifier(), &proof).unwrap();
        verify(&pin, &statement, &encoded).unwrap();
        // Every public field, order, and proof byte encoding is authenticated.
        for i in 0..4 {
            let mut bad = statement.clone();
            bad.children[i / 2][i % 2] += 1;
            assert!(verify(&pin, &bad, &encoded).is_err());
        }
        let mut swapped = statement.clone();
        swapped.children.swap(0, 1);
        assert!(verify(&pin, &swapped, &encoded).is_err());
        for index in [0, encoded.len() / 2, encoded.len() - 1] {
            let mut bad = encoded.clone();
            bad[index] ^= 1;
            assert!(verify(&pin, &statement, &bad).is_err());
        }
        assert!(verify(&pin, &statement, &encoded[..encoded.len() - 1]).is_err());
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(verify(&pin, &statement, &trailing).is_err());
        assert!(
            verify(
                &encode_verifier(&leaf.verifier()).unwrap(),
                &statement,
                &encoded
            )
            .is_err()
        );
        let mut wrong_child = fields;
        wrong_child[1][1] += F::ONE;
        assert!(aggregate(&owner, [&children[0], &children[1]], &wrong_child).is_err());
    }

    let different = Leaf::prepare_with_coefficient(profile, 2).unwrap();
    let alt_fields = [
        [F::from_u32(3), F::from_u32(15)],
        [F::from_u32(5), F::from_u32(35)],
    ];
    let alt = [
        different.prove(alt_fields[0]).unwrap(),
        different.prove(alt_fields[1]).unwrap(),
    ];
    different
        .verifier()
        .verify(&alt[0], &alt_fields[0])
        .unwrap();
    assert!(leaf.verifier().verify(&alt[0], &alt_fields[0]).is_err());
    assert!(aggregate(&owner, [&alt[0], &alt[1]], &alt_fields).is_err());
    let alt_owner = prepare_aggregator(
        profile,
        different.verifier(),
        [&alt[0], &alt[1]],
        &alt_fields,
    )
    .unwrap();
    let alt_outer = aggregate(&alt_owner, [&alt[0], &alt[1]], &alt_fields).unwrap();
    let alt_bytes = encode_proof(&alt_owner.verifier(), &alt_outer).unwrap();
    let alt_statement = Statement {
        version: 1,
        children: [[3, 15], [5, 35]],
    };
    verify(
        &encode_verifier(&alt_owner.verifier()).unwrap(),
        &alt_statement,
        &alt_bytes,
    )
    .unwrap();
    assert!(verify(&pin, &alt_statement, &alt_bytes).is_err());

    initial[0].proof.opened_values.instances[0]
        .base_opened_values
        .trace_local[0] += E::ONE;
    assert!(aggregate(&owner, [&initial[0], &initial[1]], &calibration).is_err());
}

#[test]
fn malformed_recursive_witness_rejected_without_native_prefilter() {
    let profile = Profile::Smoke;
    let config = profile.config().unwrap();
    let leaf = Leaf::prepare(profile).unwrap();
    let fields = child_statement(13).unwrap().map(F::from_u32);
    let proof = leaf.prove(fields).unwrap();
    let verifier = leaf.verifier();
    let previous = RecursionInput::<Config, BatchOnly>::BatchStark {
        proof: &proof,
        common_data: verifier.common_data(),
        table_public_inputs: verifier.table_public_values(&fields).unwrap(),
    };
    let backend = backend();
    let mut builder = CircuitBuilder::new();
    <Backend as PcsRecursionBackend<Config, BatchOnly, 5>>::prepare_circuit(
        &backend,
        &config,
        &mut builder,
    )
    .unwrap();
    let result = <Backend as TrustedPcsRecursionBackend<Config, BatchOnly, 5>>::build_trusted_batch_verifier_circuit(
        &backend, &verifier, &proof, &fields, &mut builder,
    ).unwrap();
    <Backend as TrustedPcsRecursionBackend<Config, BatchOnly, 5>>::constrain_trusted_preprocessing(
        &backend,
        &mut builder,
        &result,
        verifier
            .common_data()
            .preprocessed
            .as_ref()
            .map(|p| &p.commitment),
    )
    .unwrap();
    let circuit = builder.build().unwrap();
    let public = result.pack_public_inputs(&previous).unwrap();
    let private = result.pack_private_inputs(&previous).unwrap();
    let run = |public: &[E], private: &[E]| {
        let mut runner = circuit.runner();
        runner.set_public_inputs(public).unwrap();
        runner.set_private_inputs(private).unwrap();
        // Populate paths from the HONEST proof, then run the malformed algebraic
        // witness directly. No native verifier sees or prefilters these mutations.
        <Backend as TrustedPcsRecursionBackend<Config, BatchOnly, 5>>::set_private_data_for_trusted_batch(
            &backend, &verifier, &proof, &fields, &mut runner,
            <_ as VerifierCircuitResult<Config, BatchOnly>>::op_ids(&result),
        )
        .unwrap();
        runner.run()
    };
    assert!(run(&public, &private).is_ok());
    for index in [0, public.len() / 2, public.len() - 1] {
        let mut bad = public.clone();
        bad[index] += E::ONE;
        assert!(
            run(&bad, &private).is_err(),
            "unchecked public witness at {index}"
        );
    }
    for index in [0, private.len() / 2, private.len() - 1] {
        let mut bad = private.clone();
        bad[index] += E::ONE;
        assert!(
            run(&public, &bad).is_err(),
            "unchecked private witness at {index}"
        );
    }
}

#[test]
fn leaf_relation_and_canonical_statements() {
    let leaf = Leaf::prepare(Profile::Smoke).unwrap();
    assert!(leaf.prove([F::from_u32(3), F::from_u32(13)]).is_err());
    assert!(Statement::from_inputs(MODULUS, 5).is_err());
    let mut bad = Statement::from_inputs(3, 5).unwrap();
    bad.children[0][1] = MODULUS;
    assert!(bad.bytes().is_err());
    bad = Statement::from_inputs(3, 5).unwrap();
    bad.version = 2;
    assert!(bad.bytes().is_err());
    assert_eq!(
        Statement::from_inputs(3, 5).unwrap().children,
        [[3, 12], [5, 30]]
    );
}
