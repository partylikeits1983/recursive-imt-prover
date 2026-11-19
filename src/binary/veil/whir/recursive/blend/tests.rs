use anyhow::Result;
use p3_circuit::{Circuit, CircuitBuilder};
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};
use rand::{RngExt, SeedableRng, rngs::StdRng};

use super::PreparedBlend;
use crate::binary::engine::{PreparedCircuit, Settings};
use crate::binary::veil::{
    E, F,
    parameters::Parameters,
    transcript::Transcript,
    whir::{CommittedBlend, recursive::transcript::CircuitTranscript},
};

struct Fixture {
    circuit: Circuit<F>,
    public: Vec<F>,
    private: Vec<F>,
}

fn fixture(valid_claim: bool) -> Result<Fixture> {
    let mut rng = StdRng::seed_from_u64(0x66756e6374696f6e);
    let values: Vec<E> = (0..256).map(|_| rng.random()).collect();
    let weights: Vec<E> = (0..256).map(|_| rng.random()).collect();
    let sum = values.iter().zip(&weights).map(|(&a, &b)| a * b).sum::<E>()
        + if valid_claim { E::ZERO } else { E::ONE };
    let parameters = Parameters::default();
    let committed = CommittedBlend::new(values, &parameters)?;
    let root = committed.root;
    let start = Transcript::new(b"recursive-blend-test").fingerprint();
    let mut transcript = Transcript::new(b"recursive-blend-test");
    let proof = committed.prove(&weights, sum, &mut transcript)?;
    let end = transcript.fingerprint();
    let prepared = PreparedBlend::new(256, &parameters)?;
    let private = prepared.import(
        &proof,
        &root,
        &weights,
        sum,
        Transcript::new(b"recursive-blend-test"),
    )?;
    let mut builder = CircuitBuilder::<F>::new();
    builder.enable_native_blake3_compress()?;
    let start_target = builder.alloc_public_input_array::<32>("initial-state");
    let root_target = builder.alloc_public_input_array::<32>("blend-root");
    let weight_targets: Vec<_> = weights
        .iter()
        .map(|_| {
            let coefficients = builder.alloc_public_input_array::<3>("weight");
            builder.native_poly192_from_coefficients(coefficients)
        })
        .collect();
    let sum_target = builder.alloc_public_input_array::<3>("sum");
    let sum_target = builder.native_poly192_from_coefficients(sum_target);
    let end_target = builder.alloc_public_input_array::<32>("final-state");
    let targets = prepared.allocate(&mut builder)?;
    let transcript = prepared.verify(
        &mut builder,
        &root_target,
        &weight_targets,
        &sum_target,
        &targets,
        CircuitTranscript::from_state(start_target),
    )?;
    for (&actual, expected) in transcript.fingerprint().iter().zip(end_target) {
        builder.connect(actual, expected);
    }
    let mut public: Vec<F> = start
        .into_iter()
        .chain(root)
        .map(|v| F::new(u64::from(v)))
        .collect();
    for value in weights.iter().chain([&sum]) {
        public.extend_from_slice(value.as_basis_coefficients_slice());
    }
    public.extend(end.into_iter().map(|v| F::new(u64::from(v))));
    Ok(Fixture {
        circuit: builder.build()?,
        public,
        private,
    })
}

fn accepts(fixture: &Fixture, public: &[F], private: &[F]) -> bool {
    let mut runner = fixture.circuit.runner();
    runner
        .set_public_inputs(public)
        .and_then(|()| runner.set_private_inputs(private))
        .and_then(|()| runner.run_witness())
        .is_ok()
}

#[test]
fn recursive_blend_binds_transcript_sumcheck_and_pcs() -> Result<()> {
    let fixture = fixture(true)?;
    assert!(accepts(&fixture, &fixture.public, &fixture.private));
    for i in [0, 32, 64, 64 + 3 * 256, fixture.public.len() - 1] {
        let mut changed = fixture.public.clone();
        changed[i] += F::ONE;
        assert!(!accepts(&fixture, &changed, &fixture.private), "public {i}");
    }
    // Mutate both coefficients of every sumcheck round, its terminal value,
    // and the PCS witness, bypassing all native import checks.
    for i in (0..17)
        .map(|i| i * 3)
        .chain([51, fixture.private.len() - 1])
    {
        let mut changed = fixture.private.clone();
        changed[i] += F::ONE;
        assert!(!accepts(&fixture, &fixture.public, &changed), "proof {i}");
    }
    Ok(())
}

#[test]
fn recursive_blend_rejects_false_sum_with_valid_terminal_pcs() -> Result<()> {
    // The prover creates an actual WHIR proof at the transcript's point even
    // for the false sum. Only the in-circuit functional relation rejects it.
    let fixture = fixture(false)?;
    assert!(!accepts(&fixture, &fixture.public, &fixture.private));
    Ok(())
}

#[test]
#[ignore = "resource-intensive recursive proof; run explicitly in release mode"]
fn recursive_blend_has_an_actual_outer_proof() -> Result<()> {
    let fixture = fixture(true)?;
    let prepared = PreparedCircuit::new(
        fixture.circuit,
        &Settings::default(),
        b"imt-masked-blend-recursion-v1",
    )?;
    let (proof, metrics) = prepared.prove(&fixture.public, &fixture.private)?;
    prepared.verify(&proof, &fixture.public)?;
    let mut changed = fixture.public.clone();
    *changed.last_mut().unwrap() += F::ONE;
    assert!(prepared.verify(&proof, &changed).is_err());
    eprintln!(
        "masked blend outer: prove {:.3} ms, verify {:.3} ms, {} bytes, {} witnesses",
        metrics.prove_ms,
        metrics.verify_ms,
        proof.len(),
        prepared.geometry.witnesses,
    );
    Ok(())
}
