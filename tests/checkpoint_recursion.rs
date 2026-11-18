use std::time::Instant;

use anyhow::Result;
use imt_flock_backend::{
    Prepared, Verifier,
    checkpoint_keccak::{CommittedBatch, CommittedProof, State, Statement},
    verifier_key_digest,
};
use p3_binary_field::Poly64 as F;
use p3_circuit::Circuit;
use recursive_imt_prover::binary::checkpoint::PreparedCheckpoint;

const CONTEXT: &[u8] = b"recursive-committed-keccak-test";

fn inputs(log: usize) -> Vec<State> {
    (0..1 << log)
        .map(|i| core::array::from_fn(|j| ((25 * i + j) as u64).wrapping_mul(0x9e3779b97f4a7c15)))
        .collect()
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
fn recursive_keccak_authenticates_both_boundaries_and_rejects_tampering() -> Result<()> {
    for log in [0, 3] {
        let scheme = CommittedBatch::for_recursion(log)?;
        let states = inputs(log);
        let (statement, proof) = scheme.prove(&states, CONTEXT)?;
        let (statement, proof): (Statement, CommittedProof) =
            postcard::from_bytes(&postcard::to_allocvec(&(statement, proof))?)?;
        scheme.verify(&statement, &proof, CONTEXT)?;
        assert!(
            CommittedBatch::new(log)?
                .verify(&statement, &proof, CONTEXT)
                .is_err()
        );
        let start = Instant::now();
        let prepared = PreparedCheckpoint::new(log, CONTEXT)?;
        eprintln!(
            "Closed Keccak log {log}: build {:.3}s, {} witnesses",
            start.elapsed().as_secs_f64(),
            prepared.circuit.witness_count
        );
        let public = prepared.public_inputs(&statement)?;
        let private = prepared.private_inputs(&statement, &proof)?;
        assert!(accepts(&prepared.circuit, &public, &private));
        for index in [0, public.len() / 2, public.len() - 1] {
            let mut bad = public.clone();
            bad[index] = F::new(bad[index].to_bits() ^ 1);
            assert!(!accepts(&prepared.circuit, &bad, &private), "cap {index}");
        }
        let closing_start = 3 + 24 * 3 * (1 + 3 * (log + 11) + 3);
        let pcs_start = closing_start + 3 * (1 + 2 * 11);
        // Tamper after import, bypassing the native verifier and importer.
        for index in [
            0,
            3,
            closing_start,
            closing_start + 3,
            pcs_start,
            pcs_start + 3,
            pcs_start + 6,
            pcs_start + 6 + 192,
            (pcs_start + private.len()) / 2,
            private.len() - 1,
        ] {
            let mut bad = private.clone();
            bad[index] = F::new(bad[index].to_bits() ^ 1);
            assert!(!accepts(&prepared.circuit, &public, &bad), "proof {index}");
        }
        let mut wrong_count = statement.clone();
        wrong_count.log_batch += 1;
        assert!(prepared.private_inputs(&wrong_count, &proof).is_err());
        let (_, old) = CommittedBatch::new(log)?.prove(&states, CONTEXT)?;
        assert!(prepared.private_inputs(&statement, &old).is_err());
        let (_, foreign) = scheme.prove(&states, b"another authority")?;
        assert!(prepared.private_inputs(&statement, &foreign).is_err());
        let (other_statement, _) = scheme.prove(&vec![[0; 25]; states.len()], CONTEXT)?;
        assert!(prepared.private_inputs(&other_statement, &proof).is_err());
    }
    Ok(())
}

#[test]
#[ignore = "actual outer proof of the authenticated checkpoint verifier"]
fn closed_checkpoint_has_an_actual_outer_proof() -> Result<()> {
    let (statement, proof) = CommittedBatch::for_recursion(3)?.prove(&inputs(3), CONTEXT)?;
    let recursive = PreparedCheckpoint::new(3, CONTEXT)?;
    let public = recursive.public_inputs(&statement)?;
    let private = recursive.private_inputs(&statement, &proof)?;
    let outer = Prepared::new_checkpoint(recursive.circuit, CONTEXT)?;
    let (proof, metrics) = outer.prove(&public, &private)?;
    outer.verify(&proof, &public)?;
    let key = outer.export_verifier(CONTEXT)?;
    let verifier =
        Verifier::from_bytes(&key, &verifier_key_digest(&key), &outer.identity(), CONTEXT)?;
    verifier.verify(&proof, &public)?;
    let mut corrupted = proof.clone();
    let last = corrupted.len() - 1;
    corrupted[last] ^= 1;
    assert!(verifier.verify(&corrupted, &public).is_err());
    let mut bad = public;
    bad[0] = F::new(bad[0].to_bits() ^ 1);
    assert!(verifier.verify(&proof, &bad).is_err());
    eprintln!(
        "Closed checkpoint outer proof: {}",
        serde_json::to_string(&metrics)?
    );
    Ok(())
}
