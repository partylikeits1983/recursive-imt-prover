use old_binary_field::{Poly64 as OldF, TowerLevel as OldTowerLevel};
use p3_binary_field::Poly192;
use p3_circuit::{Circuit, CircuitBuilder};
use p3_field::PrimeCharacteristicRing;
use p3_keccak::KeccakF;
use p3_symmetric::Permutation;

use crate::{HashBackend, Prepared, Verifier, checkpoint::AggregateProof, verifier_key_digest};

fn circuit() -> Circuit<OldF> {
    let mut builder = CircuitBuilder::<OldF>::new();
    builder.enable_native_keccak_f1600().unwrap();
    for _ in 0..2 {
        let input = (0..100)
            .map(|_| builder.alloc_private_input("limb"))
            .collect::<Vec<_>>();
        let (output, swapped) = builder
            .add_native_keccak_f1600_with_swapped_digest(&input)
            .unwrap();
        for wire in output.into_iter().chain(swapped) {
            let public = builder.public_input();
            builder.connect(wire, public);
        }
    }
    builder.build().unwrap()
}

fn public(inputs: &[OldF]) -> Vec<OldF> {
    inputs
        .as_chunks::<100>()
        .0
        .iter()
        .flat_map(|limbs| {
            let state: [u64; 25] = core::array::from_fn(|lane| {
                (0..4).fold(0, |word, bit| {
                    word | (limbs[lane * 4 + bit].to_repr() << (bit * 16))
                })
            });
            let output = KeccakF.permute(state);
            (0..100)
                .map(|i| OldF::from_repr((output[i / 4] >> (16 * (i % 4))) & 0xffff))
                .chain((0..16).map(|i| {
                    OldF::from_repr(u64::from(
                        ((output[i / 4] >> (16 * (i % 4))) as u16).swap_bytes(),
                    ))
                }))
                .collect::<Vec<_>>()
        })
        .collect()
}

#[test]
fn checkpoint_aggregate_binds_real_arithmetic_ports_and_cached_authority() {
    let prepared = Prepared::new_checkpoint(circuit(), b"linked-circuit-test").unwrap();
    assert_eq!(prepared.geometry.hash_backend, HashBackend::Checkpoint);
    assert!(prepared.geometry.algebraic_bits >= 144.0);
    let private = (0..200)
        .map(|i| OldF::from_repr(((i + 1) * 317) as u64 & 0xffff))
        .collect::<Vec<_>>();
    let public = public(&private);
    let (bytes, _) = prepared.prove(&public, &private).unwrap();
    prepared.verify(&bytes, &public).unwrap();
    let key = prepared.export_verifier(b"test-config").unwrap();
    let digest = verifier_key_digest(&key);
    let cached = Verifier::from_bytes(&key, &digest, &prepared.identity(), b"test-config").unwrap();
    cached.verify(&bytes, &public).unwrap();
    for index in [0, 99, 100, 115, 116, public.len() - 1] {
        let mut changed = public.clone();
        changed[index] = OldF::from_repr(changed[index].to_repr() ^ 1);
        assert!(prepared.verify(&bytes, &changed).is_err());
        assert!(cached.verify(&bytes, &changed).is_err());
    }
    let mut changed: AggregateProof = postcard::from_bytes(&bytes).unwrap();
    changed.arithmetic.opening.values[0] += Poly192::ONE;
    assert!(
        cached
            .verify(&postcard::to_allocvec(&changed).unwrap(), &public)
            .is_err()
    );
    changed = postcard::from_bytes(&bytes).unwrap();
    changed.statement.log_batch += 1;
    assert!(
        cached
            .verify(&postcard::to_allocvec(&changed).unwrap(), &public)
            .is_err()
    );
    let mut other_private = private.clone();
    other_private[0] = OldF::from_repr(other_private[0].to_repr() ^ 1);
    let other_public = self::public(&other_private);
    let (other_bytes, _) = prepared.prove(&other_public, &other_private).unwrap();
    let other: AggregateProof = postcard::from_bytes(&other_bytes).unwrap();
    changed = postcard::from_bytes(&bytes).unwrap();
    changed.statement = other.statement;
    assert!(
        cached
            .verify(&postcard::to_allocvec(&changed).unwrap(), &public)
            .is_err()
    );
    changed = postcard::from_bytes(&bytes).unwrap();
    changed.keccak = other.keccak;
    assert!(
        cached
            .verify(&postcard::to_allocvec(&changed).unwrap(), &public)
            .is_err()
    );
    assert!(Verifier::from_bytes(&key, &digest, &prepared.identity(), b"wrong-config").is_err());
    assert!(Verifier::from_bytes(&key, &digest, "wrong-authority", b"test-config").is_err());
    let mut changed_key = key.clone();
    changed_key[0] ^= 1;
    assert!(
        Verifier::from_bytes(&changed_key, &digest, &prepared.identity(), b"test-config").is_err()
    );
}

#[test]
fn flock_backend_still_verifies_with_versioned_snapshot() {
    let prepared = Prepared::new(circuit(), b"flock-circuit-test").unwrap();
    let private = vec![OldF::from_repr(17); 200];
    let public = public(&private);
    let (bytes, _) = prepared.prove(&public, &private).unwrap();
    let key = prepared.export_verifier(b"test-config").unwrap();
    let cached = Verifier::from_bytes(
        &key,
        &verifier_key_digest(&key),
        &prepared.identity(),
        b"test-config",
    )
    .unwrap();
    cached.verify(&bytes, &public).unwrap();
}
