use imt_flock_backend::{HashBackend, Prepared, Verifier, verifier_key_digest};
use p3_field::PrimeCharacteristicRing;
use recursive_imt_prover::binary::{
    cli::fixtures,
    relation::{PUBLIC_BYTES, membership_circuit},
    veil::F,
};

#[test]
fn repeated_keccak_memberships_bind_distinct_witnesses_and_statements() {
    let children = fixtures(32, 2).unwrap();
    let public: Vec<_> = children.iter().flat_map(|(p, _)| p.fields()).collect();
    let private: Vec<_> = children
        .iter()
        .flat_map(|(_, w)| w.fields(32).unwrap())
        .collect();
    let prepared = Prepared::repeated(
        membership_circuit(32).unwrap(),
        2,
        b"flock-membership-adapter-test",
        HashBackend::Flock,
    )
    .unwrap();
    eprintln!("{}", serde_json::to_string(&prepared.geometry).unwrap());
    let (proof, metrics) = prepared.prove(&public, &private).unwrap();
    eprintln!("{}", serde_json::to_string(&metrics).unwrap());
    prepared.verify(&proof, &public).unwrap();
    let binding = b"trusted-membership-test-config";
    let key = prepared.export_verifier(binding).unwrap();
    let digest = verifier_key_digest(&key);
    let cached = Verifier::from_bytes(&key, &digest, &prepared.identity(), binding).unwrap();
    cached.verify(&proof, &public).unwrap();
    let mut altered_key = key.clone();
    let midpoint = altered_key.len() / 2;
    altered_key[midpoint] ^= 1;
    assert!(Verifier::from_bytes(&altered_key, &digest, &prepared.identity(), binding).is_err());
    assert!(Verifier::from_bytes(&key, &[0; 32], &prepared.identity(), binding).is_err());
    assert!(Verifier::from_bytes(&key, &digest, "wrong-authority", binding).is_err());
    assert!(Verifier::from_bytes(&key, &digest, &prepared.identity(), b"wrong-config").is_err());
    let mut wrong = public.clone();
    wrong[32] += F::ONE;
    assert!(prepared.verify(&proof, &wrong).is_err());
    assert!(cached.verify(&proof, &wrong).is_err());
    wrong = public.clone();
    wrong[PUBLIC_BYTES] += F::ONE;
    assert!(prepared.verify(&proof, &wrong).is_err());
    assert!(cached.verify(&proof, &wrong).is_err());
    let mut swapped = public.clone();
    let (first, second) = swapped.split_at_mut(PUBLIC_BYTES);
    first.swap_with_slice(second);
    assert!(cached.verify(&proof, &swapped).is_err());
    assert!(cached.verify(&proof, &[]).is_err());
    let other = Prepared::repeated(
        membership_circuit(32).unwrap(),
        2,
        b"other-verifying-authority",
        HashBackend::Flock,
    )
    .unwrap();
    assert!(other.verify(&proof, &public).is_err());
    let mut trailing = proof.clone();
    trailing.push(0);
    assert!(prepared.verify(&trailing, &public).is_err());
    assert!(cached.verify(&trailing, &public).is_err());
    assert!(prepared.verify(&proof[..proof.len() / 2], &public).is_err());
    let mut corrupted = proof.clone();
    let middle = corrupted.len() / 2;
    corrupted[middle] ^= 1;
    assert!(prepared.verify(&corrupted, &public).is_err());
    assert!(cached.verify(&corrupted, &public).is_err());
}
