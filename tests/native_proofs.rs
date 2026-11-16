//! Native differential evidence is deliberately separate from recursion coverage.
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use recursive_imt_poc::{client, codec, fixtures, gadgets::outer_sumcheck, tree::Tree};
use spartan_whir::{QuinticExtension as E, ZkMatrixClosingProof, engine::F};
fn copy(p: &client::Proof) -> client::Proof {
    codec::decode(3, &codec::encode(3, p).unwrap()).unwrap()
}
#[test]
fn actual_full_zk_spark_clients_and_component_mutations() {
    let f = fixtures::pair(8, false).unwrap();
    let c = client::build(8, &f.clients[0], &f.witnesses[0]).unwrap();
    let shape = c.shape.clone();
    let (pk, vk) = client::setup(c.shape).unwrap();
    let p0 = client::prove(&pk, 8, &f.clients[0], &f.witnesses[0]).unwrap();
    let p1 = client::prove(&pk, 8, &f.clients[1], &f.witnesses[1]).unwrap();
    client::verify(&vk, &f.clients[0], &p0).unwrap();
    client::verify(&vk, &f.clients[1], &p1).unwrap();
    assert_ne!(
        codec::encode(3, &p0).unwrap(),
        codec::encode(3, &p1).unwrap()
    );
    let rerandomized = client::prove(&pk, 8, &f.clients[0], &f.witnesses[0]).unwrap();
    client::verify(&vk, &f.clients[0], &rerandomized).unwrap();
    assert_ne!(
        codec::encode(3, &p0).unwrap(),
        codec::encode(3, &rerandomized).unwrap()
    );
    let mut restored: client::VerifyingKey =
        codec::decode(2, &codec::encode(2, &vk).unwrap()).unwrap();
    assert!(client::verify(&restored, &f.clients[0], &p0).is_err());
    restored.authenticate().unwrap();
    client::verify(&restored, &f.clients[0], &p0).unwrap();
    let mut wrong = f.clients[0].clone();
    wrong.new_commitment = f.clients[1].new_commitment;
    assert!(client::verify(&vk, &wrong, &p0).is_err());
    let mut bad = copy(&p0);
    bad.instance.public_inputs[0] += F::ONE;
    assert!(client::verify(&vk, &f.clients[0], &bad).is_err());
    bad = copy(&p0);
    bad.proof.outer_sumcheck.mu_tilde += E::ONE;
    assert!(client::verify(&vk, &f.clients[0], &bad).is_err());
    bad = copy(&p0);
    bad.proof.pcs_proof.base_case.blinded_message[0] += E::ONE;
    assert!(client::verify(&vk, &f.clients[0], &bad).is_err());
    bad = copy(&p0);
    bad.proof.pcs_proof.base_case.pow_witness += F::ONE;
    assert!(client::verify(&vk, &f.clients[0], &bad).is_err());
    bad = copy(&p0);
    bad.proof.matrix_closing = ZkMatrixClosingProof::DirectSparse;
    assert!(client::verify(&vk, &f.clients[0], &bad).is_err());
    bad = copy(&p0);
    if let ZkMatrixClosingProof::Spark(closing) = &mut bad.proof.matrix_closing {
        closing.spark_fixed_openings.evals.val_a_low += E::ONE;
    } else {
        panic!("expected SPARK");
    }
    assert!(client::verify(&vk, &f.clients[0], &bad).is_err());
    let bytes = codec::encode(3, &p0).unwrap();
    assert!(codec::decode::<client::Proof>(3, &bytes[..bytes.len() - 1]).is_err());
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(codec::decode::<client::Proof>(3, &trailing).is_err());
    let mut noncanonical = codec::encode(9, &vec![F::ONE]).unwrap();
    let n = noncanonical.len();
    noncanonical[n - 4..].copy_from_slice(&F::ORDER_U32.to_le_bytes());
    assert!(codec::decode::<Vec<F>>(9, &noncanonical).is_err());
    // Circuit component verification of an ACTUAL proof, bypassing native verification on mutations.
    let prefix = outer_sumcheck::test_prefix(&vk, &p0).unwrap();
    let g = outer_sumcheck::build(prefix.len(), p0.proof.outer_sumcheck.rounds.len()).unwrap();
    let input = outer_sumcheck::assignment(&prefix, &p0).unwrap();
    let mut r = g.runner();
    r.set_private_inputs(&input).unwrap();
    assert!(r.run().is_ok());
    for index in [
        prefix.len(),
        prefix.len() + 5,
        prefix.len() + 17,
        input.len() - 1,
    ] {
        let mut changed = input.clone();
        changed[index] += recursive_imt_poc::outer::convert(F::ONE);
        let mut r = g.runner();
        assert!(
            r.set_private_inputs(&changed)
                .and_then(|_| r.run())
                .is_err(),
            "component witness {index}"
        );
    }
    let pinned = outer_sumcheck::build_pinned_component(&vk).unwrap();
    let pin_input = outer_sumcheck::pinned_assignment(&vk, &p0).unwrap();
    let public: Vec<_> = f.clients[0]
        .fields()
        .into_iter()
        .map(recursive_imt_poc::outer::convert)
        .collect();
    let mut r = pinned.runner();
    r.set_public_inputs(&public).unwrap();
    r.set_private_inputs(&pin_input).unwrap();
    assert!(r.run().is_ok());
    let mut changed = public.clone();
    changed[24] += recursive_imt_poc::outer::convert(F::ONE);
    let mut r = pinned.runner();
    assert!(
        r.set_public_inputs(&changed)
            .and_then(|_| r.set_private_inputs(&pin_input))
            .and_then(|_| r.run())
            .is_err()
    );
    // Same-size different relation/key must not verify. Change a coefficient,
    // retaining dimensions and proof shape; no witness-supplied key selection.
    let mut other_shape = shape;
    other_shape.a.entries[0].val += F::ONE;
    let (_other_pk, other_vk) = client::setup(other_shape).unwrap();
    assert!(client::verify(&other_vk, &f.clients[0], &p0).is_err());
    // Reference-only rotation: no authorized TrustedState update is claimed.
    // Same client key proves replacement notes against two accepted reference roots.
    let mut tree: Tree = f.tree;
    tree.append(f.batch.new_commitments[0]).unwrap();
    let first_root = tree.root();
    let w0 = client::ClientWitness {
        old: f.witnesses[0].new.clone(),
        new: client::Note::random(),
        old_leaf_index: 2,
        old_authentication_path: tree.path(2).unwrap(),
    };
    tree.append(f.batch.new_commitments[1]).unwrap();
    let w1 = client::ClientWitness {
        old: f.witnesses[1].new.clone(),
        new: client::Note::random(),
        old_leaf_index: 3,
        old_authentication_path: tree.path(3).unwrap(),
    };
    for w in [w0, w1] {
        let s = client::statement(&w).unwrap();
        assert!([first_root, tree.root()].contains(&s.membership_root));
        let p = client::prove(&pk, 8, &s, &w).unwrap();
        client::verify(&vk, &s, &p).unwrap();
    }
}
