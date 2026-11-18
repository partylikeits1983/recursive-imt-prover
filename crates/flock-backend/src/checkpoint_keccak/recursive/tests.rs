use std::time::Instant;

use anyhow::Result;
use p3_challenger::FieldChallenger;
use p3_circuit::{
    Circuit, CircuitConstructionLimits,
    ops::{ByteHash, bytes_to_limbs},
};
use p3_field::PrimeCharacteristicRing;
use p3_keccak::KeccakF;
use p3_multilinear_util::point::Point;
use p3_symmetric::Permutation;
use sha3::{Digest, Keccak256};

use super::super::{E, MAX_BATCH_LOG, RC, linear};
use super::{
    BITS, BinaryTower128Challenger, CF, CircuitBuilder, Claim, ClaimTarget, NativeBinaryEncoding,
    PreparedVerifier, Proof, State, connect, prove, sample, verify, weights::Weights,
};
use crate::config::challenger;
use crate::{Prepared, Verifier, verifier_key_digest};

const SEED: &[u8] = b"recursive-keccak-gkr-test";

fn fixture(log: usize) -> (Vec<State>, Claim) {
    let states: Vec<State> = (0..1 << log)
        .map(|i| core::array::from_fn(|j| ((25 * i + j) as u64).wrapping_mul(0x9e3779b97f4a7c15)))
        .collect();
    let mut ch = challenger(b"recursive-keccak-claim");
    let mut output = Claim {
        instance: (0..log).map(|_| ch.sample_algebra_element()).collect(),
        weights: (0..BITS).map(|_| ch.sample_algebra_element()).collect(),
        value: E::ZERO,
    };
    let after: Vec<_> = states.iter().map(|s| KeccakF.permute(*s)).collect();
    output.value = evaluate(&after, &output);
    (states, output)
}

fn evaluate(states: &[State], claim: &Claim) -> E {
    let eq = Point::new(claim.instance.as_slice()).equality_weights_msb();
    states
        .iter()
        .zip(eq)
        .map(|(state, eq)| {
            eq * (0..BITS)
                .filter(|j| (state[j / 64] >> (j % 64)) & 1 != 0)
                .map(|j| claim.weights[j])
                .sum::<E>()
        })
        .sum()
}

fn fields(claim: &Claim) -> Vec<CF> {
    claim
        .instance
        .iter()
        .chain(&claim.weights)
        .chain([&claim.value])
        .flat_map(|v| v.coefficients().map(|c| CF::new(c.to_bits())))
        .collect()
}

fn claim_target(b: &mut CircuitBuilder<CF>, log: usize, compact: bool) -> ClaimTarget {
    let mut field = || {
        let coefficients = if compact {
            b.alloc_private_input_array::<3>("Keccak claim")
        } else {
            b.alloc_public_input_array::<3>("Keccak claim")
        };
        b.native_poly192_from_coefficients(coefficients)
    };
    ClaimTarget {
        instance: (0..log).map(|_| field()).collect(),
        weights: (0..BITS).map(|_| field()).collect(),
        value: field(),
    }
}

fn verifier_circuit(prepared: &PreparedVerifier, compact: bool) -> Result<Circuit<CF>> {
    let mut b = CircuitBuilder::<CF>::with_construction_limits(CircuitConstructionLimits {
        max_expression_nodes: 1 << 27,
        max_pending_connects: 1 << 26,
        max_non_primitive_calls: 1 << 21,
        max_non_primitive_slots: 1 << 29,
    })?;
    b.enable_native_keccak_f1600()?;
    let output = claim_target(&mut b, prepared.log_batch, compact);
    let expected = claim_target(&mut b, prepared.log_batch, compact);
    let coefficients = if compact {
        b.alloc_private_input_array::<3>("transcript continuation")
    } else {
        b.alloc_public_input_array::<3>("transcript continuation")
    };
    let expected_tail = b.native_poly192_from_coefficients(coefficients);
    if compact {
        let mut words = Vec::new();
        for value in [&output, &expected]
            .into_iter()
            .flat_map(|claim| {
                claim
                    .instance
                    .iter()
                    .chain(&claim.weights)
                    .chain([&claim.value])
            })
            .chain([&expected_tail])
        {
            for &coefficient in value.coefficients() {
                words.extend(b.native_poly64_unchecked_words(coefficient, 4)?);
            }
        }
        let digest = b.native_keccak256_words(&words)?;
        let expected_digest = b.alloc_public_input_array::<16>("claim digest");
        for (a, e) in digest.into_iter().zip(expected_digest) {
            b.connect(a, e);
        }
    }
    let proof = prepared.allocate(&mut b)?;
    let seed: Vec<_> = SEED
        .iter()
        .map(|&v| b.define_const(CF::new(u64::from(v))))
        .collect();
    let ch = BinaryTower128Challenger::with_initial_bytes_with_host::<NativeBinaryEncoding, CF>(
        &mut b,
        ByteHash::Keccak256,
        &seed,
    )?;
    let mut reduced = prepared.verify_reduction(&mut b, ch, &output, &proof)?;
    for (actual, expected) in reduced
        .claim
        .instance
        .iter()
        .chain(&reduced.claim.weights)
        .chain([&reduced.claim.value])
        .zip(
            expected
                .instance
                .iter()
                .chain(&expected.weights)
                .chain([&expected.value]),
        )
    {
        connect(&mut b, actual, expected);
    }
    let tail = sample(&mut b, &mut reduced.challenger)?;
    connect(&mut b, &tail, &expected_tail);
    Ok(b.build()?)
}

fn accepts(circuit: &Circuit<CF>, public: &[CF], private: &[CF]) -> Result<bool> {
    let mut runner = circuit.runner();
    runner.set_public_inputs(public)?;
    runner.set_private_inputs(private)?;
    Ok(runner.run_witness().is_ok())
}

#[test]
fn factored_weights_match_dense_at_boolean_and_extension_points() -> Result<()> {
    let mut b = CircuitBuilder::<CF>::new();
    let point: Vec<_> = (0..23)
        .map(|_| {
            let coefficients = b.alloc_public_input_array::<3>("point or coefficient");
            b.native_poly192_from_coefficients(coefficients)
        })
        .collect();
    let beta = &point[11];
    let square = b.native_poly192_square(beta);
    let weights = Weights::linear_chi(&mut b, &point[..11], beta, &square);
    let value = weights.evaluate(&mut b, &point[12..]);
    let values: Vec<_> = core::iter::once(value)
        .chain(RC.iter().map(|&rc| weights.iota(&mut b, rc)))
        .collect();
    for actual in values {
        let coefficients = b.alloc_public_input_array::<3>("dense reference value");
        let expected = b.native_poly192_from_coefficients(coefficients);
        connect(&mut b, &actual, &expected);
    }
    let circuit = b.build()?;
    let mut ch = challenger(b"Keccak factored weight edge cases");
    for case in 0..8 {
        let point: Vec<E> = (0..23)
            .map(|i| match case {
                0 => E::ZERO,
                1 => E::ONE,
                2 => E::from_bool(i >= 12),
                3 => E::from_bool(i < 12),
                4 => E::from_bool(i % 2 != 0),
                _ if i == 11 && case < 7 => E::from_bool(case == 6),
                _ => ch.sample_algebra_element(),
            })
            .collect();
        let coefficients = Point::new(&point[..11]).equality_weights_msb();
        let beta = point[11];
        let weights: Vec<_> = (0..BITS)
            .map(|j| {
                coefficients[j]
                    + beta * coefficients[linear::shift(j, 4)]
                    + beta * beta * coefficients[linear::shift(j, 3)]
            })
            .collect();
        let weights = linear::transpose(&weights);
        let eq = Point::new(&point[12..]).equality_weights_msb();
        let value: E = weights.iter().zip(eq).map(|(&a, c)| a * c).sum();
        let expected: Vec<E> = core::iter::once(value)
            .chain(RC.iter().map(|&rc| {
                (0..64)
                    .filter(|bit| (rc >> bit) & 1 != 0)
                    .map(|bit| weights[bit])
                    .sum()
            }))
            .collect();
        let public: Vec<_> = point
            .iter()
            .chain(&expected)
            .flat_map(|v| v.coefficients().map(|c| CF::new(c.to_bits())))
            .collect();
        assert!(accepts(&circuit, &public, &[])?, "case {case}");
        let mut bad = public.clone();
        let last = bad.len() - 1;
        bad[last] = CF::new(bad[last].to_bits() ^ 1);
        assert!(!accepts(&circuit, &bad, &[])?, "forged reference {case}");
    }
    Ok(())
}

#[test]
fn fixed_transcript_binds_claim_shape_context_and_protocol() -> Result<()> {
    let (states, output) = fixture(3);
    let (proof, input) = prove(&states, &output, &mut challenger(SEED))?;
    assert_eq!(input.value, evaluate(&states, &input));
    assert_eq!(verify(&proof, &output, 3, &mut challenger(SEED))?, input);
    assert!(verify(&proof, &output, 2, &mut challenger(SEED)).is_err());
    assert!(verify(&proof, &output, 3, &mut challenger(b"foreign-context")).is_err());
    assert!(super::super::verify(&proof, &output, 3, &mut challenger(SEED)).is_err());
    let (old, _) = super::super::prove(&states, &output, &mut challenger(SEED))?;
    assert!(verify(&old, &output, 3, &mut challenger(SEED)).is_err());
    let prepared = PreparedVerifier::new(3)?;
    assert!(PreparedVerifier::new(MAX_BATCH_LOG + 1).is_err());
    for kind in 0..4 {
        let mut bad = proof.clone();
        match kind {
            0 => {
                bad.layers.pop();
            }
            1 => {
                bad.layers[0].sumcheck.round_polys.pop();
            }
            2 => {
                bad.layers[0].sumcheck.round_polys[0].push(E::ZERO);
            }
            _ => bad.layers[0]
                .sumcheck
                .pow_witnesses
                .push(super::super::F::ZERO),
        }
        assert!(prepared.private_values(&bad).is_err());
    }
    for kind in 0..3 {
        let mut bad = output.clone();
        match kind {
            0 => bad.instance[0] += E::ONE,
            1 => bad.weights[BITS - 1] += E::ONE,
            _ => bad.value += E::ONE,
        }
        assert!(verify(&proof, &bad, 3, &mut challenger(SEED)).is_err());
    }
    Ok(())
}

#[test]
#[ignore = "complete 24-round recursive Keccak verifier and an actual outer proof"]
fn circuit_replays_real_keccak_proofs_and_rejects_tampering() -> Result<()> {
    let log = 3;
    let prepared = PreparedVerifier::new(log)?;
    let (states, output) = fixture(log);
    let mut ch = challenger(SEED);
    let (proof, input) = prove(&states, &output, &mut ch)?;
    let bytes = postcard::to_allocvec(&proof)?;
    let decoded: Proof = postcard::from_bytes(&bytes)?;
    let tail: E = ch.sample_algebra_element();
    let mut public = fields(&output);
    public.extend(fields(&input));
    public.extend(tail.coefficients().map(|c| CF::new(c.to_bits())));
    let private = prepared.private_values(&decoded)?;
    let start = Instant::now();
    let circuit = verifier_circuit(&prepared, false)?;
    eprintln!(
        "Keccak GKR verifier: build {:.3}s, {} witnesses, {} private cells",
        start.elapsed().as_secs_f64(),
        circuit.witness_count,
        private.len()
    );
    assert!(accepts(&circuit, &public, &private)?);
    for index in [
        0,
        3 * log,
        3 * (log + BITS),
        public.len() / 2,
        public.len() - 1,
    ] {
        let mut bad = public.clone();
        bad[index] = CF::new(bad[index].to_bits() ^ 1);
        assert!(!accepts(&circuit, &bad, &private)?, "public {index}");
    }
    for index in [0, 3, private.len() / 2, private.len() - 1] {
        let mut bad = private.clone();
        bad[index] = CF::new(bad[index].to_bits() ^ 1);
        assert!(!accepts(&circuit, &public, &bad)?, "proof {index}");
    }
    // The diagnostic binds the full claim vector with a digest to stay below
    // the backend's public-input cap. Its PCS boundaries remain unclosed.
    let bytes: Vec<_> = public
        .iter()
        .flat_map(|v| v.to_bits().to_le_bytes())
        .collect();
    let digest = Keccak256::digest(&bytes);
    let outer_private: Vec<_> = public.iter().chain(&private).copied().collect();
    let public: Vec<_> = bytes_to_limbs(&digest)
        .into_iter()
        .map(|v| CF::new(u64::from(v)))
        .collect();
    let outer = Prepared::new_checkpoint(verifier_circuit(&prepared, true)?, SEED)?;
    let (encoded, metrics) = outer.prove(&public, &outer_private)?;
    outer.verify(&encoded, &public)?;
    let key = outer.export_verifier(SEED)?;
    let verifier = Verifier::from_bytes(&key, &verifier_key_digest(&key), &outer.identity(), SEED)?;
    verifier.verify(&encoded, &public)?;
    let mut bad = public.clone();
    bad[0] = CF::new(bad[0].to_bits() ^ 1);
    assert!(verifier.verify(&encoded, &bad).is_err());
    let mut corrupt = encoded;
    let middle = corrupt.len() / 2;
    corrupt[middle] ^= 1;
    assert!(verifier.verify(&corrupt, &public).is_err());
    eprintln!(
        "Keccak reduction outer proof: {}",
        serde_json::to_string(&metrics)?
    );
    Ok(())
}
