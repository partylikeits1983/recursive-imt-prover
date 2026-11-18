use anyhow::Result;
use imt_flock_backend::{Prepared, Verifier, verifier_key_digest};
use p3_air::check_all_constraints;
use p3_circuit::{Circuit, CircuitBuilder};
use p3_circuit_prover::direct::DirectCircuitLimits;
use p3_circuit_prover::native_bus::{KeccakCommitment, NativeBusCircuit};

use super::{NODE_DOMAIN, STATEMENT_BYTES, TreeStatement, TreeTarget};
use crate::binary::{
    relation::{AggregatePublic, ClientPublic, F, PUBLIC_BYTES},
    tree::keccak,
};

fn public(count: usize) -> AggregatePublic {
    AggregatePublic {
        children: (0..count)
            .map(|i| ClientPublic {
                root: [i as u8; 32],
                amount: u64::MAX - i as u64,
            })
            .collect(),
    }
}

fn circuit(leaf: bool) -> Result<Circuit<F>> {
    let mut b = CircuitBuilder::new();
    b.enable_native_keccak_f1600()?;
    let expected = b.alloc_public_input_array::<STATEMENT_BYTES>("statement");
    let node = if leaf {
        let public = b.alloc_private_input_array::<PUBLIC_BYTES>("root-and-amount");
        TreeTarget::leaf(&mut b, public)?
    } else {
        let left = TreeTarget {
            digest: b.alloc_private_input_array::<32>("left-digest"),
            count: b.alloc_private_input("left-count"),
        };
        let right = TreeTarget {
            digest: b.alloc_private_input_array::<32>("right-digest"),
            count: b.alloc_private_input("right-count"),
        };
        TreeTarget::merge(&mut b, left, right)?
    };
    node.connect(&mut b, expected);
    Ok(b.build()?)
}

fn accepts(circuit: &Circuit<F>, public: &[F], private: &[F]) -> Result<bool> {
    let mut runner = circuit.runner();
    let Ok(witness) = runner
        .set_public_inputs(public)
        .and_then(|()| runner.set_private_inputs(private))
        .and_then(|()| runner.run_witness())
    else {
        return Ok(false);
    };
    let bus = NativeBusCircuit::with_compact_options(
        circuit,
        "tree-statement-test",
        4,
        DirectCircuitLimits::default(),
        KeccakCommitment::Bits,
    )?;
    let traces = bus.traces(&witness)?;
    let public = bus.public_values(public)?;
    Ok(bus
        .airs()
        .iter()
        .zip(&traces)
        .zip(&public)
        .all(|((air, trace), values)| check_all_constraints(air, trace, values, Some(1)).is_ok()))
}

#[test]
fn ordered_statement_binds_amount_root_and_count() -> Result<()> {
    let public = public(8);
    let expected = TreeStatement::from_public(&public)?;
    for i in 0..8 {
        let mut changed = public.clone();
        changed.children[i].amount ^= 1;
        assert_ne!(TreeStatement::from_public(&changed)?, expected);
        changed = public.clone();
        changed.children[i].root[31] ^= 1;
        assert_ne!(TreeStatement::from_public(&changed)?, expected);
    }
    let mut changed = public.clone();
    changed.children.swap(0, 1);
    assert_ne!(TreeStatement::from_public(&changed)?, expected);
    changed.children.pop();
    assert!(TreeStatement::from_public(&changed).is_err());
    changed.children.truncate(4);
    assert_ne!(TreeStatement::from_public(&changed)?, expected);
    changed.children = public.children.clone();
    changed.children.extend_from_within(..);
    assert_ne!(TreeStatement::from_public(&changed)?, expected);
    changed.children.clear();
    assert!(TreeStatement::from_public(&changed).is_err());
    changed.children = vec![public.children[0].clone(); 64];
    assert_eq!(TreeStatement::from_public(&changed)?.count, 64);
    changed.children.extend_from_within(..);
    assert!(TreeStatement::from_public(&changed).is_err());
    Ok(())
}

#[test]
fn leaf_constraints_bind_canonical_root_and_amount_bytes() -> Result<()> {
    let circuit = circuit(true)?;
    let public = &public(1).children[0];
    for amount in [0, 0x0102030405060708, u64::MAX] {
        let public = ClientPublic {
            amount,
            ..public.clone()
        };
        let leaf = TreeStatement::leaf(&public);
        let mut encoding = b"IMT-AGG-LEAF-V1".to_vec();
        encoding.extend(public.root);
        encoding.extend(amount.to_le_bytes());
        assert_eq!(leaf.digest, keccak(&encoding));
        assert!(accepts(&circuit, &leaf.fields(), &public.fields())?);
        for (index, delta) in [(0, 1), (32, 1), (39, 1), (32, 256)] {
            let mut private = public.fields();
            private[index] += F::new(delta);
            assert!(!accepts(&circuit, &leaf.fields(), &private)?);
        }
        let mut wrong_count = leaf.fields();
        wrong_count[32] = F::new(2);
        assert!(!accepts(&circuit, &wrong_count, &public.fields())?);
    }
    Ok(())
}

#[test]
fn one_merge_circuit_constrains_every_level_and_rejects_invalid_counts() -> Result<()> {
    let circuit = circuit(false)?;
    for count in [1, 2, 4, 8, 16, 32] {
        let left = TreeStatement::from_public(&public(count))?;
        let right = left.clone();
        let merged = TreeStatement::merge(&left, &right)?;
        let private: Vec<_> = left.fields().into_iter().chain(right.fields()).collect();
        assert_eq!(merged.count, 2 * count as u8);
        assert!(accepts(&circuit, &merged.fields(), &private)?);
        let mut wrong = merged.fields();
        wrong[32] = F::new(0); // Field addition would incorrectly give count XOR count = 0.
        assert!(!accepts(&circuit, &wrong, &private)?);
    }
    for count in [0, 3, 5, 7, 31, 33, 64, 128, 255] {
        let left = TreeStatement {
            digest: [1; 32],
            count,
        };
        let right = TreeStatement {
            digest: [2; 32],
            count,
        };
        assert!(TreeStatement::merge(&left, &right).is_err());
        // Supply the correct hash for an invalid count, bypassing the native guard.
        let mut message = NODE_DOMAIN.to_vec();
        message.extend(left.digest);
        message.push(count);
        message.extend(right.digest);
        message.push(count);
        let expected = TreeStatement {
            digest: keccak(&message),
            count: count.wrapping_mul(2),
        };
        let private: Vec<_> = left.fields().into_iter().chain(right.fields()).collect();
        assert!(
            !accepts(&circuit, &expected.fields(), &private)?,
            "count {count}"
        );
    }
    let left = TreeStatement::from_public(&public(2))?;
    let right = TreeStatement::from_public(&public(4))?;
    assert!(TreeStatement::merge(&left, &right).is_err());
    let expected = TreeStatement::merge(&left, &left)?;
    let private: Vec<_> = left.fields().into_iter().chain(right.fields()).collect();
    assert!(!accepts(&circuit, &expected.fields(), &private)?);
    Ok(())
}

#[test]
fn statement_hash_proofs_reuse_one_key_across_levels() -> Result<()> {
    // Only the statement hash relation is proved here, not child verification.
    let prepared = Prepared::new(circuit(false)?, b"tree-statement-hash-test")?;
    let binding = b"tree-statement-hash-test-v1";
    let key = prepared.export_verifier(binding)?;
    let verifier = Verifier::from_bytes(
        &key,
        &verifier_key_digest(&key),
        &prepared.identity(),
        binding,
    )?;
    for count in [2, 4] {
        let public = public(count);
        let middle = count / 2;
        let left = TreeStatement::from_public(&AggregatePublic {
            children: public.children[..middle].to_vec(),
        })?;
        let right = TreeStatement::from_public(&AggregatePublic {
            children: public.children[middle..].to_vec(),
        })?;
        let expected = TreeStatement::from_public(&public)?;
        let private: Vec<_> = left.fields().into_iter().chain(right.fields()).collect();
        let (proof, _) = prepared.prove(&expected.fields(), &private)?;
        verifier.verify(&proof, &expected.fields())?;
        let swapped = TreeStatement::merge(&right, &left)?;
        assert!(verifier.verify(&proof, &swapped.fields()).is_err());
        let mut wrong = expected.fields();
        wrong[32] = F::new(1);
        assert!(verifier.verify(&proof, &wrong).is_err());
    }
    Ok(())
}
