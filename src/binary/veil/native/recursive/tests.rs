use anyhow::Result;
use p3_circuit::CircuitBuilder;
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};
use p3_multi_stark::{rounds::AirDegrees, zerocheck::transcript::ZerocheckShape};
use p3_sumcheck::generic_degree::RoundPolyInterpolator;
use rand::{RngExt, SeedableRng, rngs::StdRng};

use super::weight_polynomials;
use crate::binary::veil::{
    E, F,
    compiler::{MaskedReader, recursive::CircuitReader},
    native::NativeAirProgram,
    parameters::Parameters,
    whir::recursive::transcript::CircuitTranscript,
};

#[test]
fn constant_interpolation_weights_match_upstream_at_nodes_and_random_points() {
    let mut rng = StdRng::seed_from_u64(196);
    for degree in 1..=17 {
        let polynomials = weight_polynomials(degree);
        let reference = RoundPolyInterpolator::<E>::new(degree);
        let message: Vec<E> = (0..degree).map(|_| rng.random()).collect();
        let claim: E = rng.random();
        let mut points: Vec<E> = (0..=degree).map(|i| E::from(F::new(i as u64))).collect();
        points.extend((0..8).map(|_| rng.random::<E>()));
        for point in points {
            let value: E = std::iter::once(&claim)
                .chain(&message)
                .zip(&polynomials)
                .map(|(&v, p)| v * p.iter().rev().fold(E::ZERO, |acc, &c| acc * point + c))
                .sum();
            assert_eq!(value, reference.eval(&message, claim, point));
        }
    }
}

#[test]
fn circuit_air_schedule_matches_native_replay_at_depth32() -> Result<()> {
    let mut rng = StdRng::seed_from_u64(20261117);
    let variables = 10;
    let program = NativeAirProgram::new(ZerocheckShape::new(
        &[AirDegrees {
            constraints: 3,
            interactions: 0,
        }],
        variables,
        0,
        0,
    ))?;
    let parameters = Parameters::default();
    let masked: Vec<E> = (0..program.message_count() + 6)
        .map(|_| rng.random())
        .collect();
    let mut reader = MaskedReader::new(
        &parameters,
        b"native-circuit-replay",
        program.message_count(),
        &[2; 32],
        &masked,
    )?;
    let start = reader.public_transcript().fingerprint();
    let replay = program.replay(&mut reader)?;
    let native = program.reduce(replay)?;
    let end = reader.public_transcript().fingerprint();
    let mut builder = CircuitBuilder::<F>::new();
    builder.enable_native_blake3_compress()?;
    let start_target = builder.alloc_public_input_array::<32>("initial-state");
    let values: Vec<_> = masked[..program.message_count()]
        .iter()
        .map(|_| {
            let coefficients = builder.alloc_private_input_array::<3>("masked-air-message");
            builder.native_poly192_from_coefficients(coefficients)
        })
        .collect();
    let mut reader = CircuitReader::new(CircuitTranscript::from_state(start_target), &values);
    let target = program.replay_circuit(&mut builder, &mut reader)?;
    assert_eq!(reader.position(), program.message_count());
    assert_eq!(target.claim.terms.len(), native.claim.terms.len());
    for ((a, _), (b, _)) in target.claim.terms.iter().zip(&native.claim.terms) {
        assert_eq!(a, b);
    }
    let mut public: Vec<F> = start.into_iter().map(|v| F::new(u64::from(v))).collect();
    let actual = std::iter::once(&target.alpha)
        .chain(&target.tau)
        .chain(&target.point)
        .chain([&target.claim.constant])
        .chain(target.claim.terms.iter().map(|(_, c)| c));
    let expected = std::iter::once(&native.alpha)
        .chain(&native.tau)
        .chain(&native.point)
        .chain([&native.claim.constant])
        .chain(native.claim.terms.iter().map(|(_, c)| c));
    for (actual, value) in actual.zip(expected) {
        let output = builder.alloc_public_input_array::<3>("air-reduction");
        public.extend_from_slice(value.as_basis_coefficients_slice());
        for (&a, b) in actual.coefficients().iter().zip(output) {
            builder.connect(a, b);
        }
    }
    let end_target = builder.alloc_public_input_array::<32>("final-state");
    public.extend(end.into_iter().map(|v| F::new(u64::from(v))));
    for (&a, b) in reader.transcript.fingerprint().iter().zip(end_target) {
        builder.connect(a, b);
    }
    let circuit = builder.build()?;
    let private: Vec<F> = masked[..program.message_count()]
        .iter()
        .flat_map(|v| v.as_basis_coefficients_slice().iter().copied())
        .collect();
    let mut runner = circuit.runner();
    runner.set_public_inputs(&public)?;
    runner.set_private_inputs(&private)?;
    runner.run_witness()?;
    for index in [0, private.len() / 2, private.len() - 1] {
        let mut changed = private.clone();
        changed[index] += F::ONE;
        let mut runner = circuit.runner();
        runner.set_public_inputs(&public)?;
        runner.set_private_inputs(&changed)?;
        assert!(runner.run_witness().is_err());
    }
    Ok(())
}
