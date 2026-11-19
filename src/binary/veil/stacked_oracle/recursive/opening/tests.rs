use anyhow::Result;
use p3_circuit::{Circuit, CircuitBuilder};
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};
use rand::{RngExt, SeedableRng, rngs::StdRng};

use super::PreparedStacked;
use crate::binary::engine::{PreparedCircuit, Settings};
use crate::binary::veil::{
    E, F,
    compiler::{MaskedProver, MaskedReader},
    constraints::Relation,
    native::OraclePoint,
    parameters::Parameters,
    stacked_oracle::{StackedOracle, StackedSpec},
    whir::recursive::transcript::CircuitTranscript,
};

struct Fixture {
    circuit: Circuit<F>,
    public: Vec<F>,
    private: Vec<F>,
    row_offset: usize,
}

fn fixture() -> Result<Fixture> {
    let spec = StackedSpec {
        variables: 3,
        columns: 5,
        log_stack: 2,
    };
    let parameters = Parameters::default();
    let mut rng = StdRng::seed_from_u64(0x6f7261636c65);
    let columns: Vec<Vec<E>> = (0..spec.columns)
        .map(|_| (0..1 << spec.variables).map(|_| rng.random()).collect())
        .collect();
    let point: Vec<E> = (0..spec.variables).map(|_| rng.random()).collect();
    let data = StackedOracle::new(spec.clone(), &columns, &parameters, &mut rng)?;
    let root = data.root();
    let binding = b"recursive-stacked-opening-test";
    let mut prover = MaskedProver::new(&parameters, binding, spec.messages(2)?, &mut rng)?;
    let start = prover.public_transcript().clone();
    let proof = data.open(
        &[OraclePoint::Current(&point), OraclePoint::Next(&point)],
        &mut prover,
    )?;
    let end = prover.public_transcript().fingerprint();
    let inner = prover.finish(
        |reader| {
            let claims = proof.verify(
                &spec,
                &root,
                &[OraclePoint::Current(&point), OraclePoint::Next(&point)],
                &parameters,
                reader,
            )?;
            Ok(Relation {
                variables: spec.messages(2)?,
                public_wires: vec![],
                linear: claims.consistency,
                products: vec![],
            })
        },
        &mut rng,
    )?;
    // Prepare the outer witness from public proof data only. `columns` and the
    // hidden mask values are neither arguments nor inputs to this verifier.
    let prepared = PreparedStacked::new(spec.clone(), &parameters)?;
    let masked = &inner.masked[..spec.messages(2)?];
    let private = prepared.import(&proof, &root, &point, masked, start.clone())?;
    let mut reader = MaskedReader::new(
        &parameters,
        binding,
        spec.messages(2)?,
        &inner.masks.root,
        &inner.masked,
    )?;
    let claims = proof.verify(
        &spec,
        &root,
        &[OraclePoint::Current(&point), OraclePoint::Next(&point)],
        &parameters,
        &mut reader,
    )?;
    let constants: Vec<_> = claims.consistency.iter().map(|c| c.constant).collect();
    let coefficients: Vec<_> = (0..spec.columns)
        .map(|i| {
            claims.consistency[0]
                .terms
                .iter()
                .find(|(j, _)| *j == i)
                .unwrap()
                .1
        })
        .collect();
    let mask_coefficient = claims.consistency[0]
        .terms
        .iter()
        .find(|(i, _)| *i == 2 * spec.columns)
        .unwrap()
        .1;

    let mut builder = CircuitBuilder::<F>::new();
    builder.enable_native_blake3_compress()?;
    let start_target = builder.alloc_public_input_array::<32>("initial-state");
    let root_target = builder.alloc_public_input_array::<32>("oracle-root");
    let mut public: Vec<F> = start
        .fingerprint()
        .into_iter()
        .chain(root)
        .map(|v| F::new(u64::from(v)))
        .collect();
    let point_target: Vec<_> = point
        .iter()
        .map(|v| {
            public.extend_from_slice(v.as_basis_coefficients_slice());
            let coefficients = builder.alloc_public_input_array::<3>("point");
            builder.native_poly192_from_coefficients(coefficients)
        })
        .collect();
    let targets = prepared.allocate(&mut builder)?;
    let result = prepared.verify(
        &mut builder,
        &root_target,
        &point_target,
        &targets,
        CircuitTranscript::from_state(start_target),
    )?;
    for (actual, value) in result
        .constants
        .iter()
        .chain(&result.coefficients)
        .chain([&result.mask_coefficient])
        .zip(
            constants
                .iter()
                .chain(&coefficients)
                .chain([&mask_coefficient]),
        )
    {
        let expected = builder.alloc_public_input_array::<3>("affine-obligation");
        public.extend_from_slice(value.as_basis_coefficients_slice());
        for (&actual, expected) in actual.coefficients().iter().zip(expected) {
            builder.connect(actual, expected);
        }
    }
    let end_target = builder.alloc_public_input_array::<32>("final-state");
    public.extend(end.into_iter().map(|v| F::new(u64::from(v))));
    for (&actual, expected) in result.transcript.fingerprint().iter().zip(end_target) {
        builder.connect(actual, expected);
    }
    Ok(Fixture {
        circuit: builder.build()?,
        public,
        private,
        row_offset: masked.len() * 3 + 32 + 6,
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
fn recursive_oracle_authenticates_salted_rows_and_affine_obligations() -> Result<()> {
    let fixture = fixture()?;
    assert!(accepts(&fixture, &fixture.public, &fixture.private));
    for i in [0, 32, 64, 73, 79, 94, fixture.public.len() - 1] {
        let mut changed = fixture.public.clone();
        changed[i] += F::ONE;
        assert!(
            !accepts(&fixture, &changed, &fixture.private),
            "public mutation {i}"
        );
    }
    for i in [
        0,
        36,
        68,
        fixture.row_offset,
        fixture.row_offset + 9,
        fixture.row_offset + 15,
        fixture.private.len() - 1,
    ] {
        let mut changed = fixture.private.clone();
        changed[i] += F::ONE;
        assert!(
            !accepts(&fixture, &fixture.public, &changed),
            "proof mutation {i}"
        );
    }
    Ok(())
}

#[test]
#[ignore = "resource-intensive complete public oracle-verification outer proof"]
fn recursive_oracle_has_an_actual_outer_proof() -> Result<()> {
    let fixture = fixture()?;
    let prepared = PreparedCircuit::new(
        fixture.circuit,
        &Settings::default(),
        b"imt-stacked-oracle-recursion-v3",
    )?;
    let (proof, metrics) = prepared.prove(&fixture.public, &fixture.private)?;
    prepared.verify(&proof, &fixture.public)?;
    let mut altered = fixture.public.clone();
    altered[32] += F::ONE;
    assert!(prepared.verify(&proof, &altered).is_err());
    eprintln!(
        "stacked oracle outer: prove {:.3} ms, verify {:.3} ms, {} bytes, {} witnesses",
        metrics.prove_ms,
        metrics.verify_ms,
        proof.len(),
        prepared.geometry.witnesses
    );
    Ok(())
}
