use imt_flock_backend::{Prepared, Verifier, verifier_key_digest};
use recursive_imt_prover::binary::{cli::fixtures, relation::membership_circuit};

#[test]
fn native_keccak_membership_via_flock() {
    let (public, witness) = fixtures(16, 1).unwrap().remove(0);
    let prepared = Prepared::new(
        membership_circuit(16).unwrap(),
        b"flock-membership-adapter-test",
    )
    .unwrap();
    eprintln!("{}", serde_json::to_string(&prepared.geometry).unwrap());
    let (proof, metrics) = prepared
        .prove(&public.fields(), &witness.fields(16).unwrap())
        .unwrap();
    eprintln!("{}", serde_json::to_string(&metrics).unwrap());
    prepared.verify(&proof, &public.fields()).unwrap();
    let binding = b"trusted-membership-test-config";
    let key = prepared.export_verifier(binding).unwrap();
    let digest = verifier_key_digest(&key);
    let cached = Verifier::from_bytes(&key, &digest, &prepared.identity(), binding).unwrap();
    cached.verify(&proof, &public.fields()).unwrap();
    let mut altered_key = key.clone();
    let midpoint = altered_key.len() / 2;
    altered_key[midpoint] ^= 1;
    assert!(Verifier::from_bytes(&altered_key, &digest, &prepared.identity(), binding).is_err());
    assert!(Verifier::from_bytes(&key, &[0; 32], &prepared.identity(), binding).is_err());
    assert!(Verifier::from_bytes(&key, &digest, "wrong-authority", binding).is_err());
    assert!(Verifier::from_bytes(&key, &digest, &prepared.identity(), b"wrong-config").is_err());
    let mut wrong = public.clone();
    wrong.amount ^= 1;
    assert!(prepared.verify(&proof, &wrong.fields()).is_err());
    assert!(cached.verify(&proof, &wrong.fields()).is_err());
    wrong = public.clone();
    wrong.root[0] ^= 1;
    assert!(prepared.verify(&proof, &wrong.fields()).is_err());
    assert!(cached.verify(&proof, &wrong.fields()).is_err());
    assert!(cached.verify(&proof, &[]).is_err());
    let other = Prepared::new(
        membership_circuit(16).unwrap(),
        b"other-verifying-authority",
    )
    .unwrap();
    assert!(other.verify(&proof, &public.fields()).is_err());
    let mut trailing = proof.clone();
    trailing.push(0);
    assert!(prepared.verify(&trailing, &public.fields()).is_err());
    assert!(cached.verify(&trailing, &public.fields()).is_err());
    assert!(
        prepared
            .verify(&proof[..proof.len() / 2], &public.fields())
            .is_err()
    );
    let mut corrupted = proof.clone();
    let middle = corrupted.len() / 2;
    corrupted[middle] ^= 1;
    assert!(prepared.verify(&corrupted, &public.fields()).is_err());
    assert!(cached.verify(&corrupted, &public.fields()).is_err());
}
