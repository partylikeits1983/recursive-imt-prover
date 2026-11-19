use anyhow::Result;
use p3_circuit::{Circuit, CircuitBuilder};
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};
use rand::{RngExt, SeedableRng, rngs::StdRng};

use super::PreparedVector;
use crate::binary::{
    engine::{PreparedCircuit, Settings},
    veil::{
        E, F, parameters::Parameters, transcript::Transcript, vector::CommittedVectors,
        whir::recursive::transcript::CircuitTranscript,
    },
};

struct Fixture {
    circuit: Circuit<F>,
    public: Vec<F>,
    private: Vec<F>,
}

fn fixture(length: usize, product: bool) -> Result<Fixture> {
    let parameters = Parameters::default();
    let code = parameters.code(length, product)?;
    let mut rng = StdRng::seed_from_u64(20261118);
    let a: Vec<E> = (0..length).map(|_| rng.random()).collect();
    let vectors = if product {
        let b: Vec<E> = (0..length).map(|_| rng.random()).collect();
        let c = a.iter().zip(&b).map(|(&a, &b)| a * b).collect();
        vec![a, b, c]
    } else {
        vec![a]
    };
    let weights: Vec<E> = (0..length).map(|_| rng.random()).collect();
    let data = CommittedVectors::new(&vectors, code.clone(), product, &mut rng)?;
    let mut transcript = Transcript::new(&postcard::to_allocvec(&(
        b"recursive-vector-test",
        &weights,
        product,
    ))?);
    let start = transcript.clone();
    let proof = data.prove(&weights, &parameters, &mut transcript)?;
    let end = transcript.fingerprint();
    proof.verify(
        &code,
        &weights,
        vectors.len(),
        product,
        &parameters,
        &mut start.clone(),
    )?;
    let prepared = PreparedVector::new(code, vectors.len(), product, &parameters)?;
    let private = prepared.import(&proof, &weights, &parameters, start.clone())?;
    let mut b = CircuitBuilder::<F>::new();
    b.enable_native_blake3_compress()?;
    let initial = b.alloc_public_input_array::<32>("initial-state");
    let mut public: Vec<_> = start
        .fingerprint()
        .into_iter()
        .map(|v| F::new(u64::from(v)))
        .collect();
    let weights_target: Vec<_> = weights
        .iter()
        .map(|v| {
            public.extend_from_slice(v.as_basis_coefficients_slice());
            let c = b.alloc_public_input_array::<3>("weight");
            b.native_poly192_from_coefficients(c)
        })
        .collect();
    let targets = prepared.allocate(&mut b)?;
    let end_target = prepared.verify(
        &mut b,
        &targets,
        &weights_target,
        CircuitTranscript::from_state(initial),
    )?;
    let expected = b.alloc_public_input_array::<32>("final-state");
    public.extend(end.into_iter().map(|v| F::new(u64::from(v))));
    for (&a, c) in end_target.fingerprint().iter().zip(expected) {
        b.connect(a, c);
    }
    Ok(Fixture {
        circuit: b.build()?,
        public,
        private,
    })
}

fn accepts(f: &Fixture, public: &[F], private: &[F]) -> bool {
    let mut r = f.circuit.runner();
    r.set_public_inputs(public)
        .and_then(|()| r.set_private_inputs(private))
        .and_then(|()| r.run_witness())
        .is_ok()
}

#[test]
fn recursive_vectors_check_dot_product_code_queries_and_salts() -> Result<()> {
    for product in [false, true] {
        let f = fixture(3, product)?;
        assert!(accepts(&f, &f.public, &f.private));
        for i in [0, 32, f.public.len() - 1] {
            let mut changed = f.public.clone();
            changed[i] += F::ONE;
            assert!(
                !accepts(&f, &changed, &f.private),
                "public mutation {i}, product={product}"
            );
        }
        for i in [0, 32, 35, 48, 80, 128, f.private.len() - 1] {
            let mut changed = f.private.clone();
            changed[i] += F::ONE;
            assert!(
                !accepts(&f, &f.public, &changed),
                "proof mutation {i}, product={product}"
            );
        }
    }
    Ok(())
}

#[test]
#[ignore = "actual recursive proof at full child inner-vector geometry"]
fn recursive_vectors_have_actual_outer_proofs_at_child_geometry() -> Result<()> {
    for (length, product) in [(5316, true), (8614, false)] {
        let f = fixture(length, product)?;
        let prepared = PreparedCircuit::new(
            f.circuit,
            &Settings::default(),
            b"imt-compact-vector-recursion-v1",
        )?;
        let (proof, metrics) = prepared.prove(&f.public, &f.private)?;
        prepared.verify(&proof, &f.public)?;
        eprintln!(
            "vector outer length={length} product={product}: prove {:.3} ms, verify {:.3} ms, {} bytes, {} witnesses",
            metrics.prove_ms,
            metrics.verify_ms,
            proof.len(),
            prepared.geometry.witnesses
        );
    }
    Ok(())
}
