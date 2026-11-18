use recursive_imt_prover::binary::{
    MAX_CHILDREN,
    engine::Settings,
    security::{AlgebraicAssessment, BatchAssessment, union_bits},
    veil::{constraints::Relation, parameters::Parameters},
};

#[test]
fn union_accounting_includes_every_child_and_never_certifies_missing_privacy() {
    assert_eq!(union_bits(&[144.0, 144.0]).unwrap(), 143.0);
    assert!(union_bits(&[]).is_err());
    assert!(union_bits(&[f64::NAN]).is_err());
    assert!(union_bits(&[f64::INFINITY]).is_err());
    let proof = AlgebraicAssessment {
        uniform_challenge_bits: 144.0,
        hash_collision_work_bits: 128.0,
        upstream_combined_bits: 127.99,
    };
    let batch = BatchAssessment::new(&proof, &proof, MAX_CHILDREN).unwrap();
    assert!(
        (batch.uniform_challenge_union_bits - (144.0 - (MAX_CHILDREN as f64 + 1.0).log2())).abs()
            < 1e-12
    );
    assert!(batch.meets_algebraic_128_budget);
    assert!(!batch.child_zk);
    assert!(!batch.end_to_end_128_established);
    assert!(BatchAssessment::new(&proof, &proof, 0).is_err());
    assert!(BatchAssessment::new(&proof, &proof, MAX_CHILDREN + 1).is_err());
    assert!(proof.require_algebraic(145).is_err());
    let weak = AlgebraicAssessment {
        uniform_challenge_bits: 128.0,
        ..proof
    };
    assert!(
        !BatchAssessment::new(&weak, &weak, 2)
            .unwrap()
            .meets_algebraic_128_budget
    );
    let settings = Settings::default();
    assert_eq!(settings.depth, 32);
    assert!(
        Settings {
            depth: 16,
            ..settings.clone()
        }
        .validate()
        .is_err()
    );
    assert!(
        Settings {
            batch_size: MAX_CHILDREN,
            ..settings.clone()
        }
        .validate()
        .is_ok()
    );
    assert!(
        Settings {
            batch_size: 128,
            ..settings.clone()
        }
        .validate()
        .is_err()
    );
    assert_eq!(settings.pcs_bits, 152);
    assert_eq!(settings.min_algebraic_bits, 144);
}

#[test]
fn veil_queries_respect_binding_radius_and_conditional_composition() {
    let parameters = Parameters::default();
    let base = parameters.diagnostic(78406, 1, false).unwrap();
    let product = parameters.diagnostic(78402, 3, true).unwrap();
    assert_eq!(base.opened_rows, 176);
    assert_eq!(product.opened_rows, 193);
    assert_eq!(base.binding_radius, 15.0 / 32.0);
    assert_eq!(product.binding_radius, 7.0 / 16.0);
    for diagnostic in [base, product] {
        assert!(diagnostic.binding_radius < diagnostic.johnson_radius);
        assert!(diagnostic.query_miss_bits >= 160.0);
        assert!(
            diagnostic.randomized_dimension >= diagnostic.message_symbols + diagnostic.opened_rows
        );
    }
    for rate in 2..=5 {
        let p = Parameters {
            log_inv_rate: rate,
            ..parameters.clone()
        };
        for product in [false, true] {
            let c = p
                .diagnostic(1000, if product { 3 } else { 1 }, product)
                .unwrap();
            assert!(c.query_miss_bits >= 160.0);
            assert!(c.binding_radius <= c.johnson_radius);
        }
    }
    // The old direct-WHIR counts do not support a 160-bit VEIL binding claim.
    assert!(-83.0 * (17.0f64 / 32.0).log2() < 128.0);
    assert!(-112.0 * (9.0f64 / 16.0).log2() < 128.0);
    let weak = Parameters {
        query_bits: 128,
        ..parameters
    };
    let empty = Relation {
        variables: 1,
        public_wires: vec![],
        linear: vec![],
        products: vec![],
    };
    assert!(empty.prove(&weak, &[], &[Default::default()]).is_err());
}
