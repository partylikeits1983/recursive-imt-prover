use crate::support;

use p3_air::check_all_constraints;
use p3_field::PrimeCharacteristicRing;
use p3_keccak_air::input_limb;
use p3_matrix::dense::RowMajorMatrix;
use p3_recursion::builtin_config::{SuiteIdV1, WhirSecurityAssumptionV1};
use p3_uni_stark::StarkGenericConfig;
use recursive_imt_prover::legacy::{
    Digest, F, Leaf, MAX_BATCH, Profile, Statement, check_count, import_child, importer,
};
use support::fixtures;

#[test]
fn child_membership_constraints_and_canonical_encoding() {
    let depth = 4;
    let leaf = Leaf::prepare(Profile::Smoke, depth).unwrap();
    let input = fixtures(3, depth, false).pop().unwrap();
    let proof = leaf.prove(&input.witness, input.claim()).unwrap();
    let bytes = leaf.encode_proof(&proof).unwrap();
    let importer = importer(Profile::Smoke, &leaf.verifier_bytes().unwrap()).unwrap();
    import_child(&importer, input.claim(), &bytes).unwrap();
    for i in [0, bytes.len() / 2, bytes.len() - 1] {
        let mut bad = bytes.clone();
        bad[i] ^= 1;
        assert!(import_child(&importer, input.claim(), &bad).is_err());
    }
    assert!(import_child(&importer, input.claim(), &bytes[..bytes.len() - 1]).is_err());
    let mut bad = bytes.clone();
    bad.push(0);
    assert!(import_child(&importer, input.claim(), &bad).is_err());
    let mut wrong_claim = input.claim();
    wrong_claim.root.0[31] ^= 1;
    assert!(import_child(&importer, wrong_claim, &bytes).is_err());
    assert!(leaf.prove(&input.witness, wrong_claim).is_err());
    let mut witness = input.witness.clone();
    witness.note.secret.0[0] ^= 1;
    assert!(leaf.prove(&witness, input.claim()).is_err());
    witness = input.witness.clone();
    witness.note.nullifier.0[0] ^= 1;
    assert!(leaf.prove(&witness, input.claim()).is_err());
    witness = input.witness.clone();
    witness.note.amount ^= 1;
    assert!(leaf.prove(&witness, input.claim()).is_err());
    let mut wrong_amount = input.claim();
    wrong_amount.amount ^= 1;
    assert!(leaf.prove(&input.witness, wrong_amount).is_err());
    assert!(import_child(&importer, wrong_amount, &bytes).is_err());
    witness = input.witness.clone();
    witness.path[1].0[3] ^= 1;
    assert!(leaf.prove(&witness, input.claim()).is_err());
    witness = input.witness.clone();
    witness.index ^= 1;
    assert!(leaf.prove(&witness, input.claim()).is_err());
    witness.index = 1u64 << depth;
    assert!(leaf.prove(&witness, input.claim()).is_err());
    witness = input.witness.clone();
    witness.path.pop();
    assert!(leaf.prove(&witness, input.claim()).is_err());
    // Bypass host witness conversion and mutate the actual AIR trace directly.
    let air = &leaf.verifier.air;
    let trace = air.trace(&input.witness, Profile::Smoke).unwrap();
    let check = |t: &RowMajorMatrix<F>| {
        check_all_constraints(air, t, &input.claim().fields(), Some(1)).is_ok()
    };
    assert!(check(&trace));
    let mut wrong_public = input.claim().fields();
    wrong_public[16] += F::ONE;
    assert!(!check_all_constraints(air, &trace, &wrong_public, Some(1)).is_ok());
    for (row, col, value) in [
        (0, input_limb(0), F::from_u32(65536)),
        (24, air.direction_col(), F::TWO),
        (24, input_limb(17), F::from_u32(65536)),
        (24, air.stage_col(1), F::ZERO),
        (0, input_limb(16), F::ONE),
        (23, air.inverse_col(), F::ZERO),
    ] {
        let mut bad = trace.clone();
        bad.values[row * air.width() + col] = value;
        assert!(!check(&bad), "row {row}, col {col}");
    }
    let foreign = Leaf::prepare(Profile::Smoke, 5).unwrap();
    assert!(foreign.verifier.verify(&proof, input.claim()).is_err());
    let second = leaf.prove(&input.witness, input.claim()).unwrap();
    assert_ne!(bytes, leaf.encode_proof(&second).unwrap());
    let second_leaf = Leaf::prepare(Profile::Smoke, depth).unwrap();
    assert_eq!(
        leaf.verifier_bytes().unwrap(),
        second_leaf.verifier_bytes().unwrap()
    );
    second_leaf.verifier.verify(&proof, input.claim()).unwrap();
    assert!(check_count(0).is_err());
    assert!(check_count(MAX_BATCH + 1).is_err());
    assert!(Digest::try_from("A".repeat(64)).is_err());
    assert!(Digest::try_from("00".repeat(31)).is_err());
    let mut statement = Statement::new([input.claim()]).unwrap();
    statement.version = 1;
    assert!(statement.fields().is_err());
}

#[test]
fn child_air_handles_depth_boundaries_with_fixed_height_and_hiding_budget() {
    for depth in [1, 8, 16, 32] {
        let leaf = Leaf::prepare(Profile::Smoke, depth).unwrap();
        let input = fixtures(2, depth, false).pop().unwrap();
        let proof = leaf.prove(&input.witness, input.claim()).unwrap();
        assert_eq!(
            proof.degree_bits,
            leaf.verifier.air.height(Profile::Smoke).ilog2() as usize + 1
        );
        assert!(leaf.verifier.air.height(Profile::Smoke) >= Profile::Smoke.hiding_min_height());
        assert!(proof.commitments.random.is_some());
        assert!(proof.opened_values.random.is_some());
        assert_eq!(leaf.verifier.config.is_zk(), 1);
        leaf.verifier.verify(&proof, input.claim()).unwrap();
        let mut incomplete = proof;
        let random_commitment = incomplete.commitments.random.take();
        assert!(leaf.verifier.verify(&incomplete, input.claim()).is_err());
        incomplete.commitments.random = random_commitment;
        incomplete.opened_values.random = None;
        assert!(leaf.verifier.verify(&incomplete, input.claim()).is_err());
    }
}

#[test]
fn reference_uses_proven_johnson_analysis_and_full_child_hiding() {
    let leaf = Leaf::prepare(Profile::Reference, 32).unwrap();
    let descriptor = Profile::Reference.descriptor(true);
    assert_eq!(descriptor.log_blowup(), 2);
    assert_eq!(descriptor.num_queries(), 128);
    assert_eq!(descriptor.query_pow_bits(), 16);
    assert_eq!(descriptor.num_random_codewords(), 4);
    assert_eq!(descriptor.salt_elements(), 4);
    assert_eq!(leaf.verifier.config.is_zk(), 1);
    let security = leaf.verifier.johnson_security().unwrap();
    assert_eq!(security.committed_degree_bits, 11);
    assert_eq!(security.challenge_field_bits, 123);
    assert_eq!(security.johnson_radius, 0.5);
    assert!(security.analyzed_radius > 0.4);
    assert!(security.analyzed_radius < security.johnson_radius);
    assert!(security.round_by_round_bits > 0.0);
    assert!(security.round_by_round_bits < 123.0);
    assert!(
        security
            .terms
            .iter()
            .any(|term| term.name == security.binding_term)
    );
    println!("{}", serde_json::to_string_pretty(&security).unwrap());
}

#[test]
fn outer_uses_whir_without_weakening_child_hiding() {
    for profile in [Profile::Smoke, Profile::Reference] {
        let outer = profile.config().unwrap();
        assert_eq!(
            outer.descriptor().suite(),
            SuiteIdV1::KoalaBearD4Poseidon2Whir
        );
        assert_eq!(
            outer.descriptor().security_assumption_id(),
            WhirSecurityAssumptionV1::JohnsonBound.as_u16()
        );
        assert_eq!(outer.is_zk(), 0);
        assert_eq!(profile.zk_config().unwrap().is_zk(), 1);
    }
}
