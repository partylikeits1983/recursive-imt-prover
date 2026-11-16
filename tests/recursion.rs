use minimal_recursion::*;
use p3_circuit::CircuitBuilder;
use p3_field::PrimeCharacteristicRing;
use p3_recursion::{
    BatchOnly, PcsRecursionBackend, RecursionInput, TrustedPcsRecursionBackend,
    VerifierCircuitResult,
};
use sha3::{Digest as _, Keccak256};

fn node(leaf: &Leaf, preimage: [u8; 32]) -> Node {
    let d = hash(&preimage);
    Node::Proved {
        proof: Box::new(leaf.prove(&preimage, d).unwrap()),
        verifier: Box::new(leaf.verifier()),
        statement: d.fields().to_vec(),
    }
}
#[test]
fn sha3_vectors_and_preimage_binding() {
    let leaf = Leaf::prepare(Profile::Smoke).unwrap();
    let vectors = [
        (
            [0; 32],
            "9e6291970cb44dd94008c79bcaf9d86f18b4b49ba5b2a04781db7199ed3b9e4e",
        ),
        (
            core::array::from_fn(|i| i as u8),
            "050a48733bd5c2756ba95c5828cc83ee16fabcd3c086885b7744f84a0f9e0d94",
        ),
        (
            [255; 32],
            "01ed9271b2e7bfdfffb130d403daf002de33317d3806b47aab95fa686efa1689",
        ),
    ];
    for (preimage, expected) in vectors {
        let d = hash(&preimage);
        assert_eq!(String::from(d), expected);
        let proof = leaf.prove(&preimage, d).unwrap();
        leaf.verifier().verify(&proof, &d.fields()).unwrap();
        let pin = encode_verifier(&leaf.verifier()).unwrap();
        let importer = importer(Profile::Smoke, &pin).unwrap();
        let encoded = encode_proof(&leaf.verifier(), &proof).unwrap();
        import_child(&importer, d, &encoded).unwrap();
        assert!(import_child(&importer, d, &encoded[..encoded.len() - 1]).is_err());
        let mut corrupted = encoded.clone();
        corrupted[encoded.len() / 2] ^= 1;
        assert!(import_child(&importer, d, &corrupted).is_err());
        let mut wrong = preimage;
        wrong[7] ^= 1;
        assert!(leaf.prove(&wrong, d).is_err());
        let mut bad = d;
        bad.0[31] ^= 1;
        assert!(import_child(&importer, bad, &encoded).is_err());
        assert!(leaf.prove(&preimage, bad).is_err());
        let mut runner = leaf.circuit.runner();
        runner.set_public_inputs(&d.fields().map(E::from)).unwrap();
        let mut inputs = Leaf::private_inputs(&preimage);
        inputs[0] = E::from_u32(65536);
        runner.set_private_inputs(&inputs).unwrap();
        assert!(runner.run().is_err());
    }
    // Identical dimensions but different padding / relation: Keccak is not SHA3.
    let foreign = Leaf::prepare_with_suffix(Profile::Smoke, 1).unwrap();
    let preimage = [42; 32];
    let keccak = Digest(Keccak256::digest(preimage).into());
    assert_ne!(hash(&preimage), keccak);
    let proof = foreign.prove(&preimage, keccak).unwrap();
    foreign.verifier().verify(&proof, &keccak.fields()).unwrap();
    assert!(leaf.verifier().verify(&proof, &keccak.fields()).is_err());
    assert!(leaf.prove(&preimage, keccak).is_err());
}
#[test]
fn actual_recursive_batches_and_trusted_root_reuse() {
    let profile = Profile::Smoke;
    let leaf = Leaf::prepare(profile).unwrap();
    for count in [1, 2, 3, 4, 8] {
        let initial = (0..count)
            .map(|i| node(&leaf, [0xa0 + i as u8; 32]))
            .collect();
        let (calibration, _) = aggregate(initial, profile, None).unwrap();
        let (pin, _) = calibration.encode().unwrap();
        drop(calibration);
        if count == 1 {
            let foreign = Leaf::prepare_with_suffix(profile, 1).unwrap();
            let preimage = [42; 32];
            let d = Digest(Keccak256::digest(preimage).into());
            let child = || Node::Proved {
                proof: Box::new(foreign.prove(&preimage, d).unwrap()),
                verifier: Box::new(foreign.verifier()),
                statement: d.fields().to_vec(),
            };
            // Even a natively valid, same-shape child cannot change root authority.
            assert!(aggregate(vec![child()], profile, Some(&pin)).is_err());
            let (root, _) = aggregate(vec![child()], profile, None).unwrap();
            let (foreign_pin, encoded) = root.encode().unwrap();
            let statement = Statement::new(vec![d]).unwrap();
            verify(&foreign_pin, &statement, &encoded).unwrap();
            assert!(verify(&pin, &statement, &encoded).is_err());
        }
        let secrets: Vec<_> = (0..count).map(|i| [i as u8 + 1; 32]).collect();
        let statement = Statement::new(secrets.iter().map(hash).collect()).unwrap();
        let nodes = secrets.iter().map(|&p| node(&leaf, p)).collect();
        let (root, metrics) = aggregate(nodes, profile, Some(&pin)).unwrap();
        assert_eq!(
            metrics.recursive_proofs,
            if count == 1 { 1 } else { count - 1 }
        );
        assert_eq!(root.statement(), statement.fields().unwrap());
        let (actual_pin, encoded) = root.encode().unwrap();
        assert_eq!(actual_pin, pin);
        verify(&pin, &statement, &encoded).unwrap();
        for i in 0..count {
            let mut bad = statement.clone();
            bad.digests[i].0[17] ^= 1;
            assert!(verify(&pin, &bad, &encoded).is_err());
        }
        if count > 1 {
            let mut bad = statement.clone();
            bad.digests.swap(0, 1);
            assert!(verify(&pin, &bad, &encoded).is_err());
            bad.digests.pop();
            assert!(verify(&pin, &bad, &encoded).is_err());
        }
        for index in [0, encoded.len() / 2, encoded.len() - 1] {
            let mut bad = encoded.clone();
            bad[index] ^= 1;
            assert!(verify(&pin, &statement, &bad).is_err());
        }
        assert!(verify(&pin, &statement, &encoded[..encoded.len() - 1]).is_err());
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(verify(&pin, &statement, &trailing).is_err());
    }
}
#[test]
fn malformed_recursive_witness_without_native_prefilter() {
    let profile = Profile::Smoke;
    let config = profile.config().unwrap();
    let leaf = Leaf::prepare(profile).unwrap();
    let preimage = [13; 32];
    let fields = hash(&preimage).fields();
    let proof = leaf.prove(&preimage, hash(&preimage)).unwrap();
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
    let result=<Backend as TrustedPcsRecursionBackend<Config,BatchOnly,5>>::build_trusted_batch_verifier_circuit(&backend,&verifier,&proof,&fields,&mut builder).unwrap();
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
        let mut r = circuit.runner();
        r.set_public_inputs(public).unwrap();
        r.set_private_inputs(private).unwrap();
        <Backend as TrustedPcsRecursionBackend<Config,BatchOnly,5>>::set_private_data_for_trusted_batch(&backend,&verifier,&proof,&fields,&mut r,<_ as VerifierCircuitResult<Config,BatchOnly>>::op_ids(&result)).unwrap();
        r.run()
    };
    assert!(run(&public, &private).is_ok());
    for i in [0, public.len() / 2, public.len() - 1] {
        let mut bad = public.clone();
        bad[i] += E::ONE;
        assert!(run(&bad, &private).is_err());
    }
    for i in [0, private.len() / 2, private.len() - 1] {
        let mut bad = private.clone();
        bad[i] += E::ONE;
        assert!(run(&public, &bad).is_err());
    }
}
#[test]
fn canonical_statement_and_batch_limits() {
    assert!(check_count(0).is_err());
    assert!(check_count(MAX_BATCH + 1).is_err());
    assert!(Digest::try_from("A".repeat(64)).is_err());
    assert!(Digest::try_from("00".repeat(31)).is_err());
    let mut s = Statement::new(vec![hash(&[0; 32])]).unwrap();
    assert_eq!(s.bytes().unwrap().len(), 64);
    s.version = 2;
    assert!(s.fields().is_err());
    s.version = 1;
    s.relation = "keccak256".into();
    assert!(s.fields().is_err());
}
