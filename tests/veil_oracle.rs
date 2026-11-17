use anyhow::Result;
use p3_field::PrimeCharacteristicRing;
use rand::{RngExt, SeedableRng, rngs::StdRng};
use recursive_imt_prover::binary::veil::{
    E,
    parameters::Parameters,
    private_sumcheck::{PrivateSumcheckProof, PrivateSumcheckStatement},
};

#[test]
fn private_oracle_whir_roundtrip_and_statement_binding() -> Result<()> {
    let parameters = Parameters::default();
    let mut rng = StdRng::seed_from_u64(944);
    for (length, points) in [(8, 1), (8, 2), (256, 2)] {
        let left: Vec<E> = (0..length).map(|_| rng.random()).collect();
        let right: Vec<E> = (0..length).map(|_| rng.random()).collect();
        let (statement, proof) = PrivateSumcheckStatement::prove(left, right, points, &parameters)?;
        let bytes = proof.to_bytes()?;
        let mut old = bytes.clone();
        old[..8].copy_from_slice(b"IMTVPO01");
        assert!(PrivateSumcheckProof::from_bytes(&old).is_err());
        statement.verify(&parameters, &PrivateSumcheckProof::from_bytes(&bytes)?)?;
        for kind in 0..4 {
            let mut altered = statement.clone();
            match kind {
                0 => altered.claimed_sum += E::ONE,
                1 => altered.oracle_root[0] ^= 1,
                2 => altered.opening_points = 3 - points,
                3 => altered.variables += 1,
                _ => unreachable!(),
            }
            assert!(
                altered.verify(&parameters, &proof).is_err(),
                "statement mutation {kind}"
            );
        }
        for index in [0, 8, bytes.len() / 2, bytes.len() - 1] {
            let mut altered = bytes.clone();
            altered[index] ^= 0x80;
            if let Ok(proof) = PrivateSumcheckProof::from_bytes(&altered) {
                assert!(
                    statement.verify(&parameters, &proof).is_err(),
                    "proof mutation {index}"
                );
            }
        }
        let mut altered = parameters.clone();
        altered.query_bits += 1;
        assert!(statement.verify(&altered, &proof).is_err());
        let mut trailing = bytes;
        trailing.push(0);
        assert!(PrivateSumcheckProof::from_bytes(&trailing).is_err());
    }
    Ok(())
}
