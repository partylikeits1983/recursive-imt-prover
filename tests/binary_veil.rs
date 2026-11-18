use anyhow::Result;
use p3_field::{Field, PrimeCharacteristicRing};
use rand::{RngExt, SeedableRng, rngs::StdRng};
use recursive_imt_prover::binary::veil::{
    E, F,
    code::BinaryCode,
    constraints::{ExperimentalProof, Linear, Relation},
    parameters::Parameters,
};
#[test]
fn additive_code_matches_interpolation_and_product() -> Result<()> {
    let mut rng = StdRng::seed_from_u64(123);
    for message_len in [1, 7, 32] {
        let code = BinaryCode::new(message_len, 5, 2)?;
        let a: Vec<E> = (0..code.input_len).map(|_| rng.random()).collect();
        let b: Vec<E> = (0..code.input_len).map(|_| rng.random()).collect();
        let ca = code.encode(&a)?;
        let cb = code.encode(&b)?;
        for i in [0, 1, 3, code.codeword_len - 1] {
            let row = code.generator_row(i)?;
            let expected: E = row.iter().zip(&a).map(|(&c, &x)| x * c).sum();
            assert_eq!(ca[i], expected, "generator row disagrees with NTT");
        }
        let pa = code.to_product(&a)?;
        let pb = code.to_product(&b)?;
        assert_eq!(&pa[..code.input_len], &a);
        let product: Vec<_> = pa.iter().zip(&pb).map(|(&a, &b)| a * b).collect();
        let encoded = code.encode_product(&product)?;
        for i in 0..code.codeword_len {
            assert_eq!(encoded[i], ca[i] * cb[i]);
        }
    }
    Ok(())
}

#[test]
fn query_padding_has_full_rank_and_hides_every_message() -> Result<()> {
    let code = BinaryCode::new(3, 3, 2)?;
    // Every triple of these query positions and every triple of padding columns.
    for a in 0..5 {
        for b in a + 1..6 {
            for c in b + 1..7 {
                let rows = [
                    code.generator_row(a)?,
                    code.generator_row(b)?,
                    code.generator_row(c)?,
                ];
                for i in code.message_len..code.input_len - 2 {
                    for j in i + 1..code.input_len - 1 {
                        for k in j + 1..code.input_len {
                            let m: Vec<Vec<F>> =
                                rows.iter().map(|r| vec![r[i], r[j], r[k]]).collect();
                            assert!(invertible(m));
                        }
                    }
                }
            }
        }
    }
    assert!(BinaryCode::new(usize::MAX, 1, 2).is_err());
    assert!(BinaryCode::new(1, 0, 2).is_err());
    Ok(())
}

fn invertible(mut matrix: Vec<Vec<F>>) -> bool {
    for i in 0..matrix.len() {
        let Some(pivot) = (i..matrix.len()).find(|&j| matrix[j][i] != F::ZERO) else {
            return false;
        };
        matrix.swap(i, pivot);
        let inverse = matrix[i][i].inverse();
        for value in &mut matrix[i] {
            *value *= inverse;
        }
        for j in i + 1..matrix.len() {
            let factor = matrix[j][i];
            let (before, after) = matrix.split_at_mut(j);
            for (target, &pivot) in after[0][i..].iter_mut().zip(&before[i][i..]) {
                *target += factor * pivot;
            }
        }
    }
    true
}

#[test]
fn multiplication_padding_is_bijective_in_characteristic_two() {
    let mut rng = StdRng::seed_from_u64(87);
    for _ in 0..100 {
        let mut rho: E = rng.random();
        while rho == E::ZERO || rho == E::ONE {
            rho = rng.random();
        }
        let a = rho.exp_u64(7);
        let b = a * rho;
        let desired: [E; 3] = rng.random();
        let r = (desired[0] + b) / (a + b);
        let s = ((r + E::ONE) * desired[1] + desired[2]) / a;
        let t = (desired[2] + r * desired[1]) / b;
        assert_eq!(a * r + b * (r + E::ONE), desired[0]);
        assert_eq!(a * s + b * t, desired[1]);
        assert_eq!(a * r * s + b * (r + E::ONE) * t, desired[2]);
    }
}

#[test]
fn private_algebraic_proof_roundtrip_and_statement_binding() -> Result<()> {
    let parameters = Parameters::default();
    let relation = Relation {
        variables: 3,
        public_wires: vec![2],
        linear: vec![],
        products: vec![[Linear::wire(0), Linear::wire(1), Linear::wire(2)]],
    };
    let a = E::from(F::new(7));
    let b = E::from(F::new(9));
    let public = [a * b];
    let witness = [a, b, a * b];
    let proof = relation.prove(&parameters, &public, &witness)?;
    let bytes = proof.to_bytes()?;
    relation.verify(
        &parameters,
        &public,
        &ExperimentalProof::from_bytes(&bytes)?,
    )?;
    assert!(
        relation
            .verify(&parameters, &[public[0] + E::ONE], &proof)
            .is_err()
    );
    assert!(relation.verify(&parameters, &[], &proof).is_err());
    assert!(
        relation
            .prove(&parameters, &public, &[a + E::ONE, b, a * b])
            .is_err()
    );
    let second = relation.prove(&parameters, &public, &witness)?;
    assert_ne!(bytes, second.to_bytes()?, "fresh randomness required");
    let mut wrong_relation = relation.clone();
    wrong_relation.products[0][0].constant = E::ONE;
    assert!(wrong_relation.verify(&parameters, &public, &proof).is_err());
    let mut wrong_parameters = parameters.clone();
    wrong_parameters.query_bits = 128;
    assert!(relation.verify(&wrong_parameters, &public, &proof).is_err());
    for i in [0, bytes.len() / 2, bytes.len() - 1] {
        let mut corrupt = bytes.clone();
        corrupt[i] ^= 0x80;
        if let Ok(proof) = ExperimentalProof::from_bytes(&corrupt) {
            assert!(relation.verify(&parameters, &public, &proof).is_err());
        }
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(ExperimentalProof::from_bytes(&trailing).is_err());
    assert!(ExperimentalProof::from_bytes(&bytes[..bytes.len() / 2]).is_err());
    Ok(())
}

#[test]
fn affine_constants_cannot_be_replaced_by_zero_witness() -> Result<()> {
    let parameters = Parameters::default();
    let relation = Relation {
        variables: 1,
        public_wires: vec![],
        linear: vec![Linear {
            constant: E::ONE,
            terms: vec![(0, E::ONE)],
        }],
        products: vec![],
    };
    let proof = relation.prove(&parameters, &[], &[E::ONE])?;
    relation.verify(&parameters, &[], &proof)?;
    assert!(relation.check(&parameters, &[], &[E::ZERO]).is_err());
    Ok(())
}
