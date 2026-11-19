use std::fs;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::process::Command;

use p3_air::check_constraints;
use p3_binary_field::{BinaryField128, TowerLevel};
use p3_circuit::Circuit;
use p3_field::Field;
use p3_recursion::artifact::{CanonicalBinaryStatement, ExpectedVerifierArtifact};
use recursive_imt_prover::binary::cli::fixtures;
use recursive_imt_prover::binary::engine::{PreparedAggregate, PreparedChild, Settings};
use recursive_imt_prover::binary::relation::{
    ClientPublic, ClientWitness, F, PUBLIC_BYTES, membership_circuit, membership_circuit_over,
};
use recursive_imt_prover::binary::tree::{Imt, commitment, digest, nullifier_hash, parent};

const TEST_DEPTH: usize = 32;

fn settings() -> Settings {
    Settings {
        pcs_bits: 8,
        pow_bits: 0,
        min_security_bits: 1,
        min_algebraic_bits: 1,
        ..Default::default()
    }
}

fn accepts<F: Field>(circuit: &Circuit<F>, public: &[F], private: &[F]) -> bool {
    let mut runner = circuit.runner();
    runner
        .set_public_inputs(public)
        .and_then(|()| runner.set_private_inputs(private))
        .and_then(|()| runner.run_witness())
        .is_ok()
}

fn witness_fields(witness: &ClientWitness) -> Vec<F> {
    witness.fields(TEST_DEPTH).unwrap()
}

#[test]
fn blake3_digest_and_append_only_tree() {
    assert_eq!(
        hex::encode(digest(b"")),
        "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
    );
    let mut tree = Imt::new(TEST_DEPTH).unwrap();
    let note = commitment(&[1; 32], &[2; 32]);
    assert_ne!(note, commitment(&[2; 32], &[1; 32]));
    assert_eq!(
        note,
        digest(&[b"IMT-BLAKE3-LEAF2".as_slice(), &[1; 32], &[2; 32]].concat())
    );
    assert_eq!(
        nullifier_hash(&[2; 32]),
        digest(&[b"IMT-BLAKE3-NULL1".as_slice(), &[2; 32]].concat())
    );
    assert_ne!(nullifier_hash(&[2; 32]), digest(&[2; 32]));
    let index = tree.append(note).unwrap();
    tree.append([9; 32]).unwrap();
    let mut digest = note;
    for (level, sibling) in tree.path(index).unwrap().iter().enumerate() {
        digest = if (index >> level) & 1 == 0 {
            parent(&digest, sibling)
        } else {
            parent(sibling, &digest)
        };
    }
    assert_eq!(digest, tree.root());
    assert!(tree.path(2).is_err());
    assert!(Imt::new(33).is_err());
}

#[test]
fn membership_constraints_reject_every_private_and_public_mutation() {
    let circuit = membership_circuit(TEST_DEPTH).unwrap();
    let (public, witness) = fixtures(TEST_DEPTH, 1).unwrap().remove(0);
    let fields = public.fields();
    let private = witness_fields(&witness);
    assert!(accepts(&circuit, &fields, &private));
    let poly = membership_circuit_over::<BinaryField128>(TEST_DEPTH).unwrap();
    let poly_public: Vec<_> = fields
        .iter()
        .map(|f| BinaryField128::from_repr(u128::from(f.to_repr())))
        .collect();
    let poly_private: Vec<_> = private
        .iter()
        .map(|f| BinaryField128::from_repr(u128::from(f.to_repr())))
        .collect();
    assert!(accepts(&poly, &poly_public, &poly_private));
    let mut wrong_poly = poly_public.clone();
    wrong_poly[0] += BinaryField128::from_repr(1);
    assert!(!accepts(&poly, &wrong_poly, &poly_private));
    // Secret, nullifier, direction and sibling are independent constrained inputs.
    for position in [0, 32, 64, 65, private.len() - 1] {
        let mut wrong = private.clone();
        wrong[position] += F::from_repr(1);
        assert!(
            !accepts(&circuit, &fields, &wrong),
            "private position {position}"
        );
    }
    for position in [0, 31, 32, 63] {
        let mut wrong = fields.clone();
        wrong[position] += F::from_repr(1);
        assert!(
            !accepts(&circuit, &wrong, &private),
            "public position {position}"
        );
    }
    let mut noncanonical = fields.clone();
    noncanonical[32] = F::from_repr(256);
    assert!(!accepts(&circuit, &noncanonical, &private));
    let mut nonboolean = private.clone();
    nonboolean[64] = F::from_repr(2);
    assert!(!accepts(&circuit, &fields, &nonboolean));
    let mut outside = witness.clone();
    outside.leaf_index = u32::MAX;
    assert!(!accepts(&circuit, &fields, &witness_fields(&outside)));
    outside = witness.clone();
    outside.merkle_path.pop();
    assert!(outside.fields(TEST_DEPTH).is_err());
    for nullifier in [[0; 32], [255; 32]] {
        let mut tree = Imt::new(TEST_DEPTH).unwrap();
        let index = tree
            .append(commitment(&witness.secret_num, &nullifier))
            .unwrap();
        let mut updated = witness.clone();
        updated.nullifier = nullifier;
        updated.leaf_index = index;
        updated.merkle_path = tree.path(index).unwrap();
        assert!(accepts(
            &circuit,
            &ClientPublic {
                root: tree.root(),
                nullifier_hash: nullifier_hash(&nullifier),
            }
            .fields(),
            &witness_fields(&updated)
        ));
    }
}

#[test]
fn actual_child_and_aggregate_proofs_authenticate_order_and_authority() {
    let settings = settings();
    let child = PreparedChild::new(&settings).unwrap();
    // A strong outer setting cannot upgrade the security of a weak child.
    assert!(PreparedAggregate::new(&child, &Settings::default()).is_err());
    let mut children = Vec::new();
    for (public, witness) in fixtures(TEST_DEPTH, 2).unwrap() {
        let (proof, _) = child.prove(public, &witness).unwrap();
        child.verify(&proof).unwrap();
        children.push(proof);
    }
    assert_ne!(children[0].public.root, children[1].public.root);
    let aggregate = PreparedAggregate::new(&child, &settings).unwrap();
    // Bypass the aggregator's native precheck: the compiled verifier must itself
    // reject altered proof data and statements supplied as its private inputs.
    let shape = child.inner.authority.recursive_verifier().input_shape();
    let identity = child.inner.authority.canonical_verifier_bytes();
    let mut private = Vec::new();
    let fields: Vec<_> = children.iter().flat_map(|c| c.public.fields()).collect();
    for input in &children {
        let tables = child
            .inner
            .bus
            .public_values(&input.public.fields())
            .unwrap();
        let bytes = child.inner.authority.encode_statement(&tables).unwrap();
        let checked = child
            .inner
            .authority
            .decode_and_verify(
                identity,
                ExpectedVerifierArtifact::from_trusted_bytes(identity),
                &input.proof,
                CanonicalBinaryStatement::new(&bytes, PUBLIC_BYTES),
            )
            .unwrap();
        private.extend(
            checked
                .native_input()
                .private_native_values(&shape)
                .unwrap(),
        );
    }
    assert!(accepts(&aggregate.inner.circuit, &fields, &private));
    let mut bad_private = private.clone();
    bad_private[0] += F::from_repr(1);
    assert!(!accepts(&aggregate.inner.circuit, &fields, &bad_private));
    let mut bad_fields = fields.clone();
    bad_fields[32] += F::from_repr(1);
    assert!(!accepts(&aggregate.inner.circuit, &bad_fields, &private));
    let (public, proof, _) = aggregate.prove(&children).unwrap();
    aggregate.verify(&proof, &public).unwrap();
    let mut wrong = public.clone();
    wrong.children[0].nullifier_hash[0] ^= 1;
    assert!(aggregate.verify(&proof, &wrong).is_err());
    wrong = public.clone();
    wrong.children[1].root[0] ^= 1;
    assert!(aggregate.verify(&proof, &wrong).is_err());
    wrong = public.clone();
    wrong.children.swap(0, 1);
    assert!(aggregate.verify(&proof, &wrong).is_err());
    wrong = public.clone();
    wrong.children.pop();
    assert!(aggregate.verify(&proof, &wrong).is_err());
    wrong = public.clone();
    wrong.children.push(public.children[0].clone());
    assert!(aggregate.verify(&proof, &wrong).is_err());
    for position in [0, proof.len() / 2, proof.len() - 1] {
        let mut corrupt = proof.clone();
        corrupt[position] ^= 1;
        assert!(aggregate.verify(&corrupt, &public).is_err());
    }
    assert!(aggregate.prove(&children[..1]).is_err());
    let mut bad = children.clone();
    let middle = bad[0].proof.len() / 2;
    bad[0].proof[middle] ^= 1;
    assert!(aggregate.prove(&bad).is_err());
    bad = children.clone();
    bad[0].public.nullifier_hash[0] ^= 1;
    assert!(aggregate.prove(&bad).is_err());
    let foreign = PreparedChild::new(&Settings {
        log_inv_rate: 2,
        ..settings.clone()
    })
    .unwrap();
    assert!(foreign.verify(&children[0]).is_err());
    let repeated = vec![children[0].clone(), children[0].clone()];
    let (public, proof, _) = aggregate.prove(&repeated).unwrap();
    aggregate.verify(&proof, &public).unwrap();
}

#[test]
fn blake3_air_rejects_tampered_compression_trace() {
    let child = PreparedChild::new(&settings()).unwrap();
    let (public, witness) = fixtures(TEST_DEPTH, 1).unwrap().remove(0);
    let mut runner = child.inner.circuit.runner();
    runner.set_public_inputs(&public.fields()).unwrap();
    runner
        .set_private_inputs(&witness_fields(&witness))
        .unwrap();
    let witness = runner.run_witness().unwrap();
    let mut traces = child.inner.bus.traces(&witness).unwrap();
    let table = child.inner.bus.packed_table_index().unwrap();
    let air = &child.inner.bus.airs()[table];
    check_constraints(air, &traces[table], &[]);
    // A non-Boolean BLAKE3 input bit violates the AIR even though its native
    // host computation has already completed successfully.
    traces[table].values[0] = F::from_repr(2);
    assert!(
        catch_unwind(AssertUnwindSafe(|| check_constraints(
            air,
            &traces[table],
            &[]
        )))
        .is_err()
    );
}

#[test]
fn independent_process_needs_only_aggregate_statement_and_trust() {
    let directory = std::env::temp_dir().join(format!("binary-imt-process-{}", std::process::id()));
    assert!(!directory.exists());
    let output = Command::new(env!("CARGO_BIN_EXE_demo"))
        .args([
            "--pcs-bits",
            "8",
            "--pow-bits",
            "0",
            "--min-security-bits",
            "1",
            "--min-algebraic-bits",
            "1",
            "--out",
        ])
        .arg(&directory)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(directory.join("aggregate.proof").exists());
    assert!(!directory.join("children").exists());
    let mut trusted: serde_json::Value =
        serde_json::from_slice(&fs::read(directory.join("trusted.json")).unwrap()).unwrap();
    trusted["aggregate_identity"] = "00".into();
    fs::write(
        directory.join("trusted.json"),
        serde_json::to_vec(&trusted).unwrap(),
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_demo"))
        .args(["--verify", "--out"])
        .arg(&directory)
        .output()
        .unwrap();
    assert!(!output.status.success());
    fs::remove_dir_all(directory).unwrap();

    let limited = std::env::temp_dir().join(format!("binary-imt-limited-{}", std::process::id()));
    assert!(!limited.exists());
    let output = Command::new(env!("CARGO_BIN_EXE_bench"))
        .args([
            "--pcs-bits",
            "8",
            "--pow-bits",
            "0",
            "--min-security-bits",
            "1",
            "--min-algebraic-bits",
            "1",
            "--samples",
            "1",
            "--max-codeword-cells",
            // Permit the depth-32 child, but reject its larger outer circuit.
            "8388608",
            "--out",
        ])
        .arg(&limited)
        .output()
        .unwrap();
    assert!(!output.status.success());
    let report: serde_json::Value =
        serde_json::from_slice(&fs::read(limited.join("report.json")).unwrap()).unwrap();
    assert_eq!(
        report["samples"][0]["children"].as_array().unwrap().len(),
        2
    );
    assert!(report["samples"][0]["aggregate"].is_null());
    assert!(limited.join("failure.json").exists());
    assert!(!limited.join("aggregate.proof").exists());
    fs::remove_dir_all(limited).unwrap();
}
