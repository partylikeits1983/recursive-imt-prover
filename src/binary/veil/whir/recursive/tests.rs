use anyhow::Result;
use p3_air::check_constraints;
use p3_circuit::{Circuit, CircuitBuilder};
use p3_circuit_prover::direct::DirectCircuitLimits;
use p3_circuit_prover::native_bus::{KeccakCommitment, NativeBusCircuit};
use p3_commit::MultilinearPcs;
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};
use p3_multilinear_util::{point::Point, poly::Poly};
use p3_recursion::pcs::binary::BinaryWhirHashDomains;
use p3_sumcheck::PrescribedPointPcs;
use p3_symmetric::MerkleCap;
use rand::{RngExt, SeedableRng, rngs::StdRng};

use super::PreparedWhir;
use crate::binary::engine::{PreparedCircuit, Settings};
use crate::binary::veil::{
    E, F,
    parameters::Parameters,
    whir::{CommittedBlend, LEAF_DOMAIN, NODE_DOMAIN, challenger, seal},
};

struct Fixture {
    circuit: Circuit<F>,
    public: Vec<F>,
    private: Vec<F>,
}

fn fixture(length: usize) -> Result<Fixture> {
    fixture_with_domains(length, None)
}

fn fixture_with_domains(length: usize, domains: Option<BinaryWhirHashDomains>) -> Result<Fixture> {
    let parameters = Parameters::default();
    let mut rng = StdRng::seed_from_u64(0x72656375727365);
    let variables = length.ilog2() as usize;
    let values: Vec<E> = (0..length).map(|_| rng.random()).collect();
    let point: Vec<E> = (0..variables).map(|_| rng.random()).collect();
    let value = Poly::new(values.clone()).eval_ext::<F>(&Point::new(point.clone()));
    let committed = CommittedBlend::new(values, &parameters)?;
    let root = committed.root;
    let seed = [71u8; 32];
    let mut native = challenger(&seed);
    let cap = MerkleCap::new(vec![root]);
    committed.pcs.observe_commitment(&cap, &mut native);
    let proof = committed
        .pcs
        .open_at(
            committed.data,
            &committed.protocol,
            &[Point::new(point.clone())],
            &mut native,
        )
        .map_err(|e| anyhow::anyhow!("native PCS proof: {e:?}"))?;
    let seal = seal(&mut native);
    let mut prepared = PreparedWhir::new(length, &parameters)?;
    let private = prepared.import(&seed, &root, &point, &proof)?;
    if let Some(domains) = domains {
        prepared.domains = domains;
    }
    let mut builder = CircuitBuilder::<F>::new();
    builder.enable_native_keccak_f1600()?;
    let seed_target = builder.alloc_public_input_array::<32>("seed");
    let root_target = builder.alloc_public_input_array::<32>("root");
    let point_target: Vec<_> = (0..variables)
        .map(|_| {
            let coefficients = builder.alloc_public_input_array::<3>("point");
            builder.native_poly192_from_coefficients(coefficients)
        })
        .collect();
    let expected = builder.alloc_public_input_array::<3>("value");
    let expected_seal = builder.alloc_public_input_array::<32>("continuation-seal");
    let targets = prepared.allocate(&mut builder)?;
    let value_target = prepared.verify(
        &mut builder,
        &seed_target,
        &root_target,
        &point_target,
        &targets,
    )?;
    for (&actual, expected) in value_target.value.coefficients().iter().zip(expected) {
        builder.connect(actual, expected);
    }
    for (actual, expected) in value_target.seal.into_iter().zip(expected_seal) {
        builder.connect(actual, expected);
    }
    let mut public: Vec<F> = seed
        .into_iter()
        .chain(root)
        .map(|v| F::new(u64::from(v)))
        .collect();
    for v in point.iter().chain([&value]) {
        public.extend_from_slice(v.as_basis_coefficients_slice());
    }
    public.extend(seal.into_iter().map(|v| F::new(u64::from(v))));
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
fn prefixed_whir_circuit_checks_proof_and_public_opening() -> Result<()> {
    let fixture = fixture(256)?;
    assert!(accepts(&fixture, &fixture.public, &fixture.private));
    for i in [0, 32, 64, fixture.public.len() - 1] {
        let mut changed = fixture.public.clone();
        changed[i] += F::ONE;
        assert!(
            !accepts(&fixture, &changed, &fixture.private),
            "public mutation {i}"
        );
    }
    for i in [0, fixture.private.len() / 2, fixture.private.len() - 1] {
        let mut changed = fixture.private.clone();
        changed[i] += F::ONE;
        assert!(
            !accepts(&fixture, &fixture.public, &changed),
            "proof mutation {i}"
        );
    }
    // Check every generated native bus AIR, including the Keccak computation,
    // instead of treating the circuit runner's host hash as proof constraints.
    let mut runner = fixture.circuit.runner();
    runner.set_public_inputs(&fixture.public)?;
    runner.set_private_inputs(&fixture.private)?;
    let witness = runner.run_witness()?;
    let bus = NativeBusCircuit::with_compact_options(
        &fixture.circuit,
        "prefixed-whir-test",
        4,
        DirectCircuitLimits {
            max_witnesses: 1 << 23,
            max_operations: 1 << 23,
            max_trace_cells: 1 << 28,
        },
        KeccakCommitment::Bits,
    )?;
    let traces = bus.traces(&witness)?;
    let public = bus.public_values(&fixture.public)?;
    for ((air, trace), values) in bus.airs().iter().zip(&traces).zip(&public) {
        check_constraints(air, trace, values);
    }
    Ok(())
}

#[test]
fn prefixed_whir_rejects_different_hash_domains() -> Result<()> {
    for domains in [
        BinaryWhirHashDomains::new(NODE_DOMAIN, LEAF_DOMAIN)?,
        BinaryWhirHashDomains::new(b"different-leaf-domain", NODE_DOMAIN)?,
        BinaryWhirHashDomains::new(LEAF_DOMAIN, b"different-node-domain")?,
    ] {
        let fixture = fixture_with_domains(256, Some(domains))?;
        assert!(!accepts(&fixture, &fixture.public, &fixture.private));
    }
    assert!(BinaryWhirHashDomains::new(b"", NODE_DOMAIN).is_err());
    assert!(BinaryWhirHashDomains::new(LEAF_DOMAIN, LEAF_DOMAIN).is_err());
    assert!(BinaryWhirHashDomains::new(&[1; 257], NODE_DOMAIN).is_err());
    Ok(())
}

#[test]
#[ignore = "resource-intensive recursive proof; run explicitly in release mode"]
fn prefixed_whir_has_an_actual_outer_proof() -> Result<()> {
    let fixture = fixture(256)?;
    let prepared = PreparedCircuit::new(
        fixture.circuit,
        &Settings::default(),
        b"imt-prefixed-whir-recursion-v1",
    )?;
    let (proof, metrics) = prepared.prove(&fixture.public, &fixture.private)?;
    prepared.verify(&proof, &fixture.public)?;
    let mut changed = fixture.public.clone();
    changed[32] += F::ONE;
    assert!(prepared.verify(&proof, &changed).is_err());
    eprintln!(
        "prefixed WHIR outer: prove {:.3} ms, verify {:.3} ms, {} bytes, {} witnesses",
        metrics.prove_ms,
        metrics.verify_ms,
        proof.len(),
        prepared.geometry.witnesses
    );
    Ok(())
}

#[test]
#[ignore = "resource-intensive recursive proofs at both child geometries"]
fn prefixed_whir_outer_proofs_at_depth16_and_depth32_geometry() -> Result<()> {
    // A stacked child oracle uses 128 columns per stack and a coefficient
    // domain twice its message length. These are PCS components, not IMT proofs.
    for (depth, length) in [(16, 1 << 17), (32, 1 << 18)] {
        let fixture = fixture(length)?;
        let prepared = PreparedCircuit::new(
            fixture.circuit,
            &Settings::default(),
            b"imt-prefixed-whir-recursion-geometry-v1",
        )?;
        let (proof, metrics) = prepared.prove(&fixture.public, &fixture.private)?;
        prepared.verify(&proof, &fixture.public)?;
        eprintln!(
            "depth {depth} PCS component: prove {:.3} ms, verify {:.3} ms, {} bytes, {} witnesses",
            metrics.prove_ms,
            metrics.verify_ms,
            proof.len(),
            prepared.geometry.witnesses,
        );
    }
    Ok(())
}
