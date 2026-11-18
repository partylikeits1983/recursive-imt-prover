use anyhow::Result;
use old_binary_field::Poly64 as F;
use p3_circuit::{
    Circuit, CircuitBuilder,
    ops::{ByteHash, binary_encoding::NativeBinaryEncoding},
};
use p3_keccak::KeccakF;
use p3_recursion::BinaryTower128Challenger;
use p3_symmetric::Permutation;

use crate::{
    AUTHORITY_BYTES, HashBackend, Prepared, RecursiveAggregate, Verifier,
    checkpoint::AggregateProof, verifier_key_digest,
};

fn accepts(circuit: &Circuit<F>, public: &[F], private: &[F]) -> bool {
    let mut runner = circuit.runner();
    runner
        .set_public_inputs(public)
        .and_then(|()| runner.set_private_inputs(private))
        .and_then(|()| runner.run_witness())
        .is_ok()
}

fn fixture(seed: u64) -> Result<(Prepared, Vec<F>, Vec<F>)> {
    fixture_with_constant(seed, 0x1234)
}

fn fixture_with_constant(seed: u64, scale: u64) -> Result<(Prepared, Vec<F>, Vec<F>)> {
    let mut b = CircuitBuilder::<F>::new();
    b.enable_native_keccak_f1600()?;
    let mut private = Vec::new();
    let input: Vec<_> = (0..100)
        .map(|i| {
            private.push(F::new(i + 1 + seed));
            b.alloc_private_input("limb")
        })
        .collect();
    let (hash, _) = b.add_native_keccak_f1600_with_swapped_digest(&input)?;
    let mut public = Vec::new();
    for i in 1..40 {
        let value = b.mul(input[0], input[i]);
        let expected = b.alloc_public_input("product");
        b.connect(value, expected);
        public.push(private[0] * private[i]);
    }
    let constant = b.define_const(F::new(scale));
    let scaled = b.mul(input[1], constant);
    let expected = b.public_input();
    b.connect(scaled, expected);
    public.push(private[1] * F::new(scale));
    let expected = b.alloc_public_input("hash output");
    b.connect(hash[0], expected);
    let state = core::array::from_fn::<_, 25, _>(|lane| {
        (0..4).fold(0, |word, bit| {
            word | (private[4 * lane + bit].to_bits() << (16 * bit))
        })
    });
    public.push(F::new(KeccakF.permute(state)[0] & 0xffff));
    Ok((
        Prepared::new_checkpoint(b.build()?, b"recursive-arithmetic-test")?,
        public,
        private,
    ))
}

#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "recursive authority binding; run with --release"
)]
fn one_verifier_circuit_accepts_distinct_authenticated_preprocessing_keys() -> Result<()> {
    let (first, public, witness) = fixture_with_constant(0, 0x1234)?;
    let (proof, _) = first.prove(&public, &witness)?;
    let key = first.export_verifier(b"authority-test")?;
    let authority = Verifier::from_bytes(
        &key,
        &verifier_key_digest(&key),
        &first.identity(),
        b"authority-test",
    )?;
    authority.require_same_layout(&first)?;
    let key_fields = authority.recursive_authority()?.fields();
    let recursive = RecursiveAggregate::new(authority)?;
    let private = recursive.private_inputs(&proof, &public)?;
    let mut builder = CircuitBuilder::<F>::new();
    builder.enable_native_keccak_f1600()?;
    let statement = builder.alloc_public_inputs(public.len(), "statement");
    let targets = builder.alloc_public_input_array::<AUTHORITY_BYTES>("authenticated authority");
    recursive.verify_with_authority(&mut builder, &statement, &targets)?;
    let circuit = builder.build()?;
    let values = [public.clone(), key_fields.to_vec()].concat();
    assert!(accepts(&circuit, &values, &private));
    for index in [
        0,
        public.len() - 1,
        public.len(),
        public.len() + 31,
        public.len() + 32,
        values.len() - 1,
    ] {
        let mut changed = values.clone();
        changed[index] = F::new(changed[index].to_bits() ^ 1);
        assert!(!accepts(&circuit, &changed, &private), "field {index}");
    }
    let mut changed = values.clone();
    changed[public.len() + 32] = F::new(256);
    assert!(!accepts(&circuit, &changed, &private));

    let (mut second, public, witness) = fixture_with_constant(7, 0x1235)?;
    recursive.require_same_layout(&second)?;
    second.geometry.main_coordinate_widths[0][0] ^= 1;
    assert!(recursive.require_same_layout(&second).is_err());
    second.geometry.main_coordinate_widths[0][0] ^= 1;
    second.log_heights[0] += 1;
    assert!(recursive.require_same_layout(&second).is_err());
    second.log_heights[0] -= 1;
    let (proof, _) = second.prove(&public, &witness)?;
    let key = second.export_verifier(b"authority-test")?;
    let authority = Verifier::from_bytes(
        &key,
        &verifier_key_digest(&key),
        &second.identity(),
        b"authority-test",
    )?;
    let second_fields = authority.recursive_authority()?.fields();
    assert_ne!(&key_fields[..32], &second_fields[..32]);
    assert_ne!(&key_fields[32..], &second_fields[32..]);
    let second = RecursiveAggregate::new(authority)?;
    let private = second.private_inputs(&proof, &public)?;
    assert!(accepts(
        &circuit,
        &[public.clone(), second_fields.to_vec()].concat(),
        &private
    ));
    assert!(!accepts(
        &circuit,
        &[public, key_fields.to_vec()].concat(),
        &private
    ));
    Ok(())
}

#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "recursive arithmetic proof; run with --release"
)]
fn complete_arithmetic_verifier_constrains_bus_air_and_coordinate_pcs() -> Result<()> {
    let (source, public, private) = fixture(0)?;
    let (bytes, _) = source.prove(&public, &private)?;
    source.verify(&bytes, &public)?;
    let key = source.export_verifier(b"arithmetic-test")?;
    let authority = Verifier::from_bytes(
        &key,
        &verifier_key_digest(&key),
        &source.identity(),
        b"arithmetic-test",
    )?;
    let recursive = authority.recursive_arithmetic()?;
    let native: AggregateProof = crate::proof_codec::decode(&bytes)?;
    let seed = source
        .checkpoint
        .as_ref()
        .unwrap()
        .arithmetic_seed(&source.seed, &native.statement)?;
    let private = recursive.private_inputs(&bytes, &public, &seed)?;
    let mut b = CircuitBuilder::<F>::new();
    b.enable_native_keccak_f1600()?;
    let initial = b.alloc_public_input_array::<32>("arithmetic seed");
    let public_targets: Vec<_> = public
        .iter()
        .map(|_| b.alloc_public_input("statement"))
        .collect();
    let targets = recursive.allocate(&mut b)?;
    let ch = BinaryTower128Challenger::with_initial_bytes_with_host::<NativeBinaryEncoding, F>(
        &mut b,
        ByteHash::Keccak256,
        &initial,
    )?;
    let _ = recursive.verify(&mut b, ch, &public_targets, &targets)?;
    let circuit = b.build()?;
    eprintln!(
        "Complete arithmetic verifier: {} witnesses",
        circuit.witness_count
    );
    let public: Vec<_> = seed
        .iter()
        .map(|&v| F::new(u64::from(v)))
        .chain(public)
        .collect();
    assert!(accepts(&circuit, &public, &private));
    for index in [0, 32, public.len() - 2] {
        let mut bad = public.clone();
        bad[index] = F::new(bad[index].to_bits() ^ 1);
        assert!(!accepts(&circuit, &bad, &private), "public {index}");
    }
    for index in [0, 16, 19, private.len() / 2, private.len() - 1] {
        let mut bad = private.clone();
        bad[index] = F::new(bad[index].to_bits() ^ 1);
        assert!(!accepts(&circuit, &public, &bad), "private {index}");
    }
    Ok(())
}

#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "complete recursive aggregate verifier; run with --release"
)]
fn complete_aggregate_verifier_links_arithmetic_and_keccak() -> Result<()> {
    let (source, public, private) = fixture(0)?;
    let (bytes, _) = source.prove(&public, &private)?;
    let key = source.export_verifier(b"aggregate-test")?;
    let authority = Verifier::from_bytes(
        &key,
        &verifier_key_digest(&key),
        &source.identity(),
        b"aggregate-test",
    )?;
    let recursive = RecursiveAggregate::new(authority)?;
    let private = recursive.private_inputs(&bytes, &public)?;
    let circuit = recursive.circuit()?;
    eprintln!(
        "Complete aggregate verifier: {} witnesses",
        circuit.witness_count
    );
    assert!(accepts(&circuit, &public, &private));
    for index in [0, public.len() - 1] {
        let mut bad = public.clone();
        bad[index] = F::new(bad[index].to_bits() ^ 1);
        assert!(!accepts(&circuit, &bad, &private));
    }
    for index in [0, 16, 32, private.len() / 2, private.len() - 1] {
        let mut bad = private.clone();
        bad[index] = F::new(bad[index].to_bits() ^ 1);
        assert!(!accepts(&circuit, &public, &bad), "private {index}");
    }
    Ok(())
}

#[test]
#[ignore = "two real aggregate proofs inside an actual outer proof"]
fn two_aggregate_verifications_have_an_actual_outer_proof() -> Result<()> {
    let (source, first, witness) = fixture(0)?;
    let (a, _) = source.prove(&first, &witness)?;
    let (_, second, witness) = fixture(7)?;
    let (b, _) = source.prove(&second, &witness)?;
    let key = source.export_verifier(b"aggregate-test")?;
    let authority = Verifier::from_bytes(
        &key,
        &verifier_key_digest(&key),
        &source.identity(),
        b"aggregate-test",
    )?;
    let recursive = RecursiveAggregate::new(authority)?;
    let mut private = recursive.private_inputs(&a, &first)?;
    private.extend(recursive.private_inputs(&b, &second)?);
    let public = [first.clone(), second.clone()].concat();
    let outer = Prepared::repeated(
        recursive.circuit()?,
        2,
        b"two-aggregate-test",
        HashBackend::Checkpoint,
    )?;
    let (proof, metrics) = outer.prove(&public, &private)?;
    outer.verify(&proof, &public)?;
    let key = outer.export_verifier(b"outer-test")?;
    let verifier = Verifier::from_bytes(
        &key,
        &verifier_key_digest(&key),
        &outer.identity(),
        b"outer-test",
    )?;
    verifier.verify(&proof, &public)?;
    assert!(verifier.verify(&proof, &[second, first].concat()).is_err());
    let mut bad = proof;
    let middle = bad.len() / 2;
    bad[middle] ^= 1;
    assert!(verifier.verify(&bad, &public).is_err());
    eprintln!(
        "Two aggregate component proofs: {}",
        serde_json::to_string(&metrics)?
    );
    Ok(())
}
