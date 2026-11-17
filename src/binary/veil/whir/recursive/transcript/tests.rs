use anyhow::Result;
use p3_air::check_constraints;
use p3_circuit::CircuitBuilder;
use p3_circuit_prover::direct::DirectCircuitLimits;
use p3_circuit_prover::native_bus::{KeccakCommitment, NativeBusCircuit};
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};
use rand::{RngExt, SeedableRng, rngs::StdRng};

use super::{CircuitTranscript, checked_challenge};
use crate::binary::veil::{E, F, transcript::Transcript};

#[test]
fn framed_transcript_matches_native_and_constrains_keccak() -> Result<()> {
    let mut rng = StdRng::seed_from_u64(0x7472616e736372);
    let fields: Vec<E> = (0..3).map(|_| rng.random()).collect();
    let mut reference = Transcript::new(b"recursive-transcript-test");
    let start = reference.fingerprint();
    reference.fields(b"field-message", &fields);
    let challenge = reference.challenge(b"challenge")?;
    reference.bytes(b"empty", &[]);
    let end = reference.fingerprint();

    let mut builder = CircuitBuilder::<F>::new();
    builder.enable_native_keccak_f1600()?;
    let start_target = builder.alloc_public_input_array::<32>("initial-state");
    let field_targets: Vec<_> = fields
        .iter()
        .map(|_| {
            let coefficients = builder.alloc_public_input_array::<3>("fields");
            builder.native_poly192_from_coefficients(coefficients)
        })
        .collect();
    let expected = builder.alloc_public_input_array::<3>("challenge");
    let end_target = builder.alloc_public_input_array::<32>("final-state");
    let mut transcript = CircuitTranscript::from_state(start_target);
    transcript.fields(&mut builder, b"field-message", &field_targets)?;
    let value = transcript.challenge(&mut builder, b"challenge")?;
    for (&actual, expected) in value.coefficients().iter().zip(expected) {
        builder.connect(actual, expected);
    }
    transcript.bytes(&mut builder, b"empty", &[])?;
    for (&actual, expected) in transcript.fingerprint().iter().zip(end_target) {
        builder.connect(actual, expected);
    }
    let circuit = builder.build()?;
    let mut public: Vec<F> = start.into_iter().map(|v| F::new(u64::from(v))).collect();
    for value in fields.iter().chain([&challenge]) {
        public.extend_from_slice(value.as_basis_coefficients_slice());
    }
    public.extend(end.into_iter().map(|v| F::new(u64::from(v))));
    let mut runner = circuit.runner();
    runner.set_public_inputs(&public)?;
    runner.set_private_inputs(&[])?;
    let witness = runner.run_witness()?;
    let bus = NativeBusCircuit::with_compact_options(
        &circuit,
        "framed-transcript-test",
        4,
        DirectCircuitLimits {
            max_witnesses: 1 << 20,
            max_operations: 1 << 20,
            max_trace_cells: 1 << 25,
        },
        KeccakCommitment::Bits,
    )?;
    let traces = bus.traces(&witness)?;
    let public_values = bus.public_values(&public)?;
    for ((air, trace), values) in bus.airs().iter().zip(&traces).zip(&public_values) {
        check_constraints(air, trace, values);
    }
    // Non-byte initial state and mutations of every message type must fail.
    for i in [0, 32, 41, public.len() - 1] {
        let mut changed = public.clone();
        changed[i] += F::new(256);
        let mut runner = circuit.runner();
        runner.set_public_inputs(&changed)?;
        runner.set_private_inputs(&[])?;
        assert!(runner.run_witness().is_err(), "mutation at {i}");
    }
    Ok(())
}

#[test]
fn single_draw_challenge_rejects_zero_and_one_and_checks_all_limbs() -> Result<()> {
    let mut builder = CircuitBuilder::<F>::new();
    let digest = builder.alloc_public_input_array::<32>("candidate");
    let _ = checked_challenge(&mut builder, &digest)?;
    let circuit = builder.build()?;
    for (a, b, c, accepted) in [
        (0, 0, 0, false),
        (1, 0, 0, false),
        (2, 0, 0, true),
        (0, 1, 0, true),
        (1, 0, 1, true),
    ] {
        let mut input = vec![F::ZERO; 32];
        input[0] = F::new(a);
        input[8] = F::new(b);
        input[16] = F::new(c);
        let mut runner = circuit.runner();
        runner.set_public_inputs(&input)?;
        runner.set_private_inputs(&[])?;
        assert_eq!(runner.run_witness().is_ok(), accepted);
    }
    Ok(())
}
