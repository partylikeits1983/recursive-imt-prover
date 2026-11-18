use std::time::Instant;

use anyhow::Result;
use imt_flock_backend::{
    Prepared, Verifier,
    checkpoint_keccak::{
        State, Statement,
        linked::{BoundaryWitness, LinkedBatch, LinkedProof, PORTS, PortOpening},
        recursive::PreparedLinkedVerifier,
    },
    verifier_key_digest,
};
use p3_binary_field::{BinaryChallenger, Poly64 as F, Poly192 as E};
use p3_challenger::{FieldChallenger, HashChallenger};
use p3_circuit::{Circuit, CircuitBuilder, ops::bytes_to_limbs};
use p3_keccak::Keccak256Hash;
use recursive_imt_prover::binary::checkpoint::PreparedLinkedCheckpoint;

type Ch = BinaryChallenger<F, HashChallenger<u8, Keccak256Hash, 32>>;
const CONTEXT: &[u8] = b"recursive-linked-keccak-test";

fn states(log: usize) -> Vec<State> {
    (0..1 << log)
        .map(|i| core::array::from_fn(|j| ((25 * i + j) as u64).wrapping_mul(0x9e3779b97f4a7c15)))
        .collect()
}

fn fixture(log: usize, bad_port: Option<usize>) -> Result<(Statement, LinkedProof, PortOpening)> {
    let scheme = LinkedBatch::for_recursion(log, 0.0)?;
    let inputs = states(log);
    let pending = scheme.commit(BoundaryWitness::new(inputs.clone()), CONTEXT)?;
    let statement = pending.statement.clone();
    let mut ch = Ch::from_hasher(scheme.arithmetic_seed(CONTEXT, &statement)?, Keccak256Hash);
    let point: Vec<E> = (0..log).map(|_| ch.sample_algebra_element()).collect();
    let mut ports = BoundaryWitness::new(inputs).opening(&point)?;
    if let Some(index) = bad_port {
        let different = *ports
            .values
            .iter()
            .find(|&&v| v != ports.values[index])
            .expect("fixture has distinct port values");
        ports.values[index] = different;
    }
    let proof = scheme.prove(pending, &ports)?;
    Ok(postcard::from_bytes(&postcard::to_allocvec(&(
        statement, proof, ports,
    ))?)?)
}

fn accepts(circuit: &Circuit<F>, public: &[F], private: &[F]) -> bool {
    let mut runner = circuit.runner();
    runner
        .set_public_inputs(public)
        .and_then(|()| runner.set_private_inputs(private))
        .and_then(|()| runner.run_witness())
        .is_ok()
}

#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "recursive Keccak proofs; run with --release"
)]
fn recursive_port_link_authenticates_all_four_boundary_openings() -> Result<()> {
    for log in [0, 3] {
        let scheme = LinkedBatch::for_recursion(log, 0.0)?;
        let (statement, proof, ports) = fixture(log, None)?;
        scheme.verify(&statement, &proof, CONTEXT, &ports)?;
        assert!(
            LinkedBatch::new(log, 0.0)?
                .verify(&statement, &proof, CONTEXT, &ports)
                .is_err()
        );
        let start = Instant::now();
        let prepared = PreparedLinkedCheckpoint::new(log, 0.0, CONTEXT)?;
        eprintln!(
            "Linked Keccak log {log}: build {:.3}s, {} witnesses",
            start.elapsed().as_secs_f64(),
            prepared.circuit.witness_count
        );
        let public = prepared.public_inputs(&statement, &ports)?;
        let private = prepared.private_inputs(&statement, &proof, &ports)?;
        assert!(accepts(&prepared.circuit, &public, &private));
        let port_start = public.len() - 3 * PORTS;
        let mut public_indices = vec![0, port_start - 1];
        public_indices.extend([0, 99, 100, 199, 200, 215, 216, 231].map(|p| port_start + 3 * p));
        for index in public_indices {
            let mut bad = public.clone();
            bad[index] = F::new(bad[index].to_bits() ^ 1);
            assert!(
                !accepts(&prepared.circuit, &bad, &private),
                "public {index}"
            );
        }
        let link_start = 3 + 24 * 3 * (1 + 3 * (log + 11) + 3) + 3 * (1 + 2 * 11);
        let pcs_start = link_start + 3 * (1 + 2 * 12);
        for index in [
            link_start,
            link_start + 3,
            pcs_start,
            pcs_start + 3,
            pcs_start + 6,
            pcs_start + 9,
            private.len() - 1,
        ] {
            let mut bad = private.clone();
            bad[index] = F::new(bad[index].to_bits() ^ 1);
            assert!(!accepts(&prepared.circuit, &public, &bad), "proof {index}");
        }
        for port in [0, 100, 200, 216] {
            let (statement, proof, ports) = fixture(log, Some(port))?;
            assert!(scheme.verify(&statement, &proof, CONTEXT, &ports).is_err());
            let public = prepared.public_inputs(&statement, &ports)?;
            let private = prepared.private_inputs(&statement, &proof, &ports)?;
            assert!(
                !accepts(&prepared.circuit, &public, &private),
                "prover-supplied false port {port}"
            );
        }
        let foreign = PreparedLinkedCheckpoint::new(log, 0.0, b"other authority")?;
        assert!(foreign.private_inputs(&statement, &proof, &ports).is_err());
        let mut short = ports.clone();
        short.values.pop();
        assert!(prepared.public_inputs(&statement, &short).is_err());
    }
    Ok(())
}

#[test]
fn arithmetic_seed_binds_authority_shape_and_boundary_before_row_challenges() -> Result<()> {
    let scheme = LinkedBatch::for_recursion(3, 0.0)?;
    let statement = scheme
        .commit(BoundaryWitness::new(states(3)), CONTEXT)?
        .statement;
    let prepared = PreparedLinkedVerifier::new(3)?;
    for authority in [b"even".as_slice(), b"odd".as_slice()] {
        let mut b = CircuitBuilder::<F>::new();
        b.enable_native_keccak_f1600()?;
        let context: Vec<_> = (0..authority.len())
            .map(|_| b.alloc_public_input("authority byte"))
            .collect();
        let cap: Vec<_> = statement
            .commitment
            .roots()
            .iter()
            .map(|_| b.alloc_public_input_array::<16>("boundary cap").to_vec())
            .collect();
        let actual = prepared.arithmetic_seed(&mut b, &context, &cap)?;
        let expected = b.alloc_public_input_array::<32>("arithmetic seed");
        for (a, e) in actual.into_iter().zip(expected) {
            b.connect(a, e);
        }
        let circuit = b.build()?;
        let mut public: Vec<_> = authority.iter().map(|&v| F::new(u64::from(v))).collect();
        public.extend(
            statement
                .commitment
                .roots()
                .iter()
                .flat_map(|r| bytes_to_limbs(r).into_iter().map(|w| F::new(u64::from(w)))),
        );
        public.extend(
            scheme
                .arithmetic_seed(authority, &statement)?
                .into_iter()
                .map(|v| F::new(u64::from(v))),
        );
        assert!(accepts(&circuit, &public, &[]));
        for index in [0, authority.len(), public.len() - 1] {
            let mut bad = public.clone();
            bad[index] = F::new(bad[index].to_bits() ^ 1);
            assert!(!accepts(&circuit, &bad, &[]));
        }
    }
    Ok(())
}

#[test]
#[ignore = "actual outer proof of the linked Keccak verifier component"]
fn linked_checkpoint_has_an_actual_outer_proof() -> Result<()> {
    let (statement, proof, ports) = fixture(3, None)?;
    let recursive = PreparedLinkedCheckpoint::new(3, 0.0, CONTEXT)?;
    let public = recursive.public_inputs(&statement, &ports)?;
    let private = recursive.private_inputs(&statement, &proof, &ports)?;
    let outer = Prepared::new_checkpoint(recursive.circuit, CONTEXT)?;
    let (proof, metrics) = outer.prove(&public, &private)?;
    outer.verify(&proof, &public)?;
    let key = outer.export_verifier(CONTEXT)?;
    let verifier =
        Verifier::from_bytes(&key, &verifier_key_digest(&key), &outer.identity(), CONTEXT)?;
    verifier.verify(&proof, &public)?;
    let mut bad = public.clone();
    let last = bad.len() - 1;
    bad[last] = F::new(bad[last].to_bits() ^ 1);
    assert!(verifier.verify(&proof, &bad).is_err());
    let mut bad = proof;
    let last = bad.len() - 1;
    bad[last] ^= 1;
    assert!(verifier.verify(&bad, &public).is_err());
    eprintln!(
        "Linked checkpoint outer proof: {}",
        serde_json::to_string(&metrics)?
    );
    Ok(())
}
