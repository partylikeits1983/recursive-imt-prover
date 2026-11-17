use anyhow::Result;
use p3_field::PrimeCharacteristicRing;
use rand::{RngExt, SeedableRng, rngs::StdRng};
use recursive_imt_prover::binary::veil::{
    E,
    parameters::Parameters,
    sumcheck::{MaskedSumcheckProof, PublicSumcheck},
};

fn statement(length: usize) -> PublicSumcheck {
    let mut rng = StdRng::seed_from_u64(191 + length as u64);
    let left: Vec<E> = (0..length).map(|_| rng.random()).collect();
    let right: Vec<E> = (0..length).map(|_| rng.random()).collect();
    let claimed_sum = left.iter().zip(&right).map(|(&a, &b)| a * b).sum();
    PublicSumcheck {
        left,
        right,
        claimed_sum,
    }
}

#[test]
fn online_masked_sumcheck_roundtrip() -> Result<()> {
    let parameters = Parameters::default();
    for size in [2, 8, 64] {
        let statement = statement(size);
        let proof = statement.prove(&parameters)?;
        let bytes = proof.to_bytes()?;
        statement.verify(&parameters, &MaskedSumcheckProof::from_bytes(&bytes)?)?;
        let second = statement.prove(&parameters)?;
        assert_ne!(
            bytes,
            second.to_bytes()?,
            "fresh masks must change the proof"
        );
    }
    Ok(())
}

#[test]
fn online_proof_binds_complete_statement_and_parameters() -> Result<()> {
    let parameters = Parameters::default();
    let statement = statement(8);
    let proof = statement.prove(&parameters)?;
    for kind in 0..6 {
        let mut altered = statement.clone();
        match kind {
            0 => altered.claimed_sum += E::ONE,
            1 => altered.left[0] += E::ONE,
            2 => altered.right[0] += E::ONE,
            // The dot product is unchanged, but these are different oracles.
            3 => std::mem::swap(&mut altered.left, &mut altered.right),
            4 => {
                altered.left.reverse();
                altered.right.reverse();
            }
            5 => {
                altered.left.truncate(4);
                altered.right.truncate(4);
            }
            _ => unreachable!(),
        }
        assert!(
            altered.verify(&parameters, &proof).is_err(),
            "changed statement {kind}"
        );
    }
    let mut altered = parameters.clone();
    altered.query_bits += 1;
    assert!(statement.verify(&altered, &proof).is_err());
    altered = parameters.clone();
    altered.max_message_len /= 2;
    assert!(statement.verify(&altered, &proof).is_err());
    Ok(())
}

#[test]
fn malformed_sumcheck_statements_and_transport_fail_closed() -> Result<()> {
    let parameters = Parameters::default();
    let statement = statement(8);
    let proof = statement.prove(&parameters)?;
    for size in [0, 1, 3, 1 << 17] {
        let invalid = PublicSumcheck {
            left: vec![E::ZERO; size],
            right: vec![E::ZERO; size],
            claimed_sum: E::ZERO,
        };
        assert!(invalid.prove(&parameters).is_err());
        assert!(invalid.verify(&parameters, &proof).is_err());
    }
    let mut invalid = statement.clone();
    invalid.right.pop();
    assert!(invalid.verify(&parameters, &proof).is_err());
    invalid = statement.clone();
    invalid.claimed_sum += E::ONE;
    assert!(invalid.prove(&parameters).is_err());
    let mut too_small = parameters.clone();
    too_small.max_message_len = 8;
    assert!(statement.verify(&too_small, &proof).is_err());

    let bytes = proof.to_bytes()?;
    let mut old = bytes.clone();
    old[..8].copy_from_slice(b"IMTVSC01");
    assert!(MaskedSumcheckProof::from_bytes(&old).is_err());
    for i in [0, 8, bytes.len() / 2, bytes.len() - 1] {
        let mut corrupt = bytes.clone();
        corrupt[i] ^= 0x80;
        if let Ok(decoded) = MaskedSumcheckProof::from_bytes(&corrupt) {
            assert!(statement.verify(&parameters, &decoded).is_err());
        }
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(MaskedSumcheckProof::from_bytes(&trailing).is_err());
    assert!(MaskedSumcheckProof::from_bytes(&bytes[..bytes.len() / 2]).is_err());
    assert!(MaskedSumcheckProof::from_bytes(&vec![0; (1 << 20) + 1]).is_err());
    Ok(())
}
