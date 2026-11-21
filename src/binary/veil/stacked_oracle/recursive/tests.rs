use anyhow::Result;
use p3_circuit::ops::NativePoly192Target;
use p3_circuit::{Circuit, CircuitBuilder};
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};
use rand::{RngExt, SeedableRng, rngs::StdRng};

use super::{FunctionalTarget, ViewTarget};
use crate::binary::engine::{PreparedCircuit, Settings};
use crate::binary::veil::{
    E, F,
    parameters::Parameters,
    stacked_oracle::{Functional, StackedSpec, View},
    transcript::Transcript,
    vector::dot,
    whir::{
        BlendFunctional, CommittedBlend,
        recursive::{blend::PreparedBlend, transcript::CircuitTranscript},
    },
};

struct Fixture {
    circuit: Circuit<F>,
    public: Vec<F>,
    private: Vec<F>,
}

fn public_field(
    builder: &mut CircuitBuilder<F>,
    public: &mut Vec<F>,
    value: E,
) -> NativePoly192Target {
    let cells = builder.alloc_public_input_array::<3>("functional-field");
    public.extend_from_slice(value.as_basis_coefficients_slice());
    builder.native_poly192_from_coefficients(cells)
}

fn fixture() -> Result<Fixture> {
    let parameters = Parameters::default();
    let spec = StackedSpec {
        variables: 3,
        columns: 5,
        log_stack: 2,
        domains: Default::default(),
    };
    let code = spec.code(&parameters)?;
    let mut rng = StdRng::seed_from_u64(0x737461636b6564);
    let point: Vec<E> = (0..spec.variables).map(|_| rng.random()).collect();
    let mut native = Transcript::new(b"compact-functional-test");
    let start = native.fingerprint();
    let indices = native.indices(code.queries, code.codeword_len);
    let functional = Functional {
        code: code.clone(),
        spec: spec.clone(),
        views: vec![
            View {
                point: point.clone(),
                next: false,
            },
            View { point, next: true },
        ],
        indices,
        theta: rng.random(),
        beta: rng.random(),
    };
    let values: Vec<E> = (0..code.input_len).map(|_| rng.random()).collect();
    let sum = dot(&values, &functional.dense()?);
    let committed = CommittedBlend::new(values, &parameters)?;
    let root = committed.root;
    let before = native.clone();
    let proof = committed.prove(&functional, sum, &mut native)?;
    let end = native.fingerprint();
    let prepared = PreparedBlend::new(code.input_len, &parameters)?;
    let private = prepared.import(&proof, &root, &functional, sum, before.clone())?;
    proof.verify(&root, &functional, sum, &parameters, &mut before.clone())?;

    let mut builder = CircuitBuilder::<F>::new();
    builder.enable_native_keccak_f1600()?;
    let mut public: Vec<F> = start
        .into_iter()
        .chain(root)
        .map(|v| F::new(u64::from(v)))
        .collect();
    let start_target = builder.alloc_public_input_array::<32>("initial-state");
    let root_target = builder.alloc_public_input_array::<32>("root");
    let views = functional
        .views
        .iter()
        .map(|v| ViewTarget {
            next: v.next,
            point: v
                .point
                .iter()
                .map(|&v| public_field(&mut builder, &mut public, v))
                .collect(),
        })
        .collect();
    let theta = public_field(&mut builder, &mut public, functional.theta);
    let beta = public_field(&mut builder, &mut public, functional.beta);
    let sum_target = public_field(&mut builder, &mut public, sum);
    let end_target = builder.alloc_public_input_array::<32>("final-state");
    public.extend(end.into_iter().map(|v| F::new(u64::from(v))));
    let mut transcript = CircuitTranscript::from_state(start_target);
    let queries = transcript.indices(&mut builder, code.queries, code.codeword_len)?;
    let functional_target = FunctionalTarget {
        spec,
        code,
        views,
        queries,
        theta,
        beta,
    };
    let targets = prepared.allocate(&mut builder)?;
    let transcript = prepared.verify(
        &mut builder,
        &root_target,
        &functional_target,
        &sum_target,
        &targets,
        transcript,
    )?;
    for (&actual, expected) in transcript.fingerprint().iter().zip(end_target) {
        builder.connect(actual, expected);
    }
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
fn compact_functional_checks_real_whir_and_derived_query_schedule() -> Result<()> {
    let fixture = fixture()?;
    assert!(accepts(&fixture, &fixture.public, &fixture.private));
    for i in [0, 32, 64, 73, 82, 85, 88, fixture.public.len() - 1] {
        let mut changed = fixture.public.clone();
        changed[i] += F::ONE;
        assert!(!accepts(&fixture, &changed, &fixture.private), "public {i}");
    }
    for i in [0, 3, fixture.private.len() / 2, fixture.private.len() - 1] {
        let mut changed = fixture.private.clone();
        changed[i] += F::ONE;
        assert!(!accepts(&fixture, &fixture.public, &changed), "proof {i}");
    }
    Ok(())
}

#[test]
#[ignore = "resource-intensive compact functional outer proof"]
fn compact_functional_has_an_actual_outer_proof() -> Result<()> {
    let fixture = fixture()?;
    let prepared = PreparedCircuit::new(
        fixture.circuit,
        &Settings::default(),
        b"imt-compact-functional-recursion-v3",
    )?;
    let (proof, metrics) = prepared.prove(&fixture.public, &fixture.private)?;
    prepared.verify(&proof, &fixture.public)?;
    let mut changed = fixture.public.clone();
    changed[64] += F::ONE;
    assert!(prepared.verify(&proof, &changed).is_err());
    eprintln!(
        "compact functional outer: prove {:.3} ms, verify {:.3} ms, {} bytes, {} witnesses",
        metrics.prove_ms,
        metrics.verify_ms,
        proof.len(),
        prepared.geometry.witnesses
    );
    Ok(())
}
