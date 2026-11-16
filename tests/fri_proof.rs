use p3_circuit::ops::Op;
use p3_field_outer::PrimeCharacteristicRing;
use p3_koala_bear_outer::KoalaBear as O;
use recursive_imt_poc::{codec, fixtures, outer};
#[test]
fn actual_transition_proof_fixed_authority_and_malicious_trace() {
    let f = fixtures::pair(4, true).unwrap();
    let c = outer::build_transition(4).unwrap();
    let prepared = outer::prepare(&c).unwrap();
    let verifier = prepared.verifier();
    let p = outer::prove_transition(&c, &prepared, &f.batch, &f.append).unwrap();
    let expected: Vec<_> = f.batch.fields().into_iter().map(outer::convert).collect();
    verifier.verify(&p, &expected).unwrap();
    for i in 0..expected.len() {
        let mut changed = expected.clone();
        changed[i] += O::ONE;
        assert!(verifier.verify(&p, &changed).is_err(), "public field {i}");
    }
    let mut corrupted: outer::TransitionProof =
        codec::decode(4, &codec::encode(4, &p).unwrap()).unwrap();
    corrupted.ext_degree = 2;
    assert!(verifier.verify(&corrupted, &expected).is_err());
    let mut corrupted: outer::TransitionProof =
        codec::decode(4, &codec::encode(4, &p).unwrap()).unwrap();
    corrupted.non_primitives[0].public_values[0] += O::ONE;
    assert!(verifier.verify(&corrupted, &expected).is_err());
    // Bypass runner and host preflight: corrupt a constraint trace directly.
    let mut runner = c.circuit.runner();
    runner.set_public_inputs(&expected).unwrap();
    runner
        .set_private_inputs(&outer::private_inputs(&f.batch, &f.append).unwrap())
        .unwrap();
    let mut traces = runner.run().unwrap();
    traces.alu_trace.values[100][3] += O::ONE;
    // Some upstream builds reject unsatisfied traces while proving; otherwise
    // the retained verifier must reject the resulting invalid argument.
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| prepared.prove(&traces)));
    if let Ok(Ok(bad)) = result {
        assert!(verifier.verify(&bad, &expected).is_err());
    }
    // Same shape, different compiled constant/program. No shape-only authority.
    let mut other = outer::TransitionCircuit {
        circuit: c.circuit.clone(),
        schema: c.schema.clone(),
        depth: 4,
    };
    let mut changed = 0;
    for op in &mut other.circuit.ops {
        if let Op::Const { val, .. } = op
            && (*val == O::from_u32(2026) || *val == O::from_u32(2027))
        {
            *val += O::ONE;
            changed += 1;
        }
    }
    assert_eq!(changed, 2);
    assert_eq!(other.circuit.ops.len(), c.circuit.ops.len());
    assert_eq!(other.circuit.witness_count, c.circuit.witness_count);
    let other_prepared = outer::prepare(&other).unwrap();
    let mut s = f.batch.clone();
    s.ctx.0[2] += 1;
    let q = outer::prove_transition(&other, &other_prepared, &s, &f.append).unwrap();
    let other_expected: Vec<_> = s.fields().into_iter().map(outer::convert).collect();
    other_prepared
        .verifier()
        .verify(&q, &other_expected)
        .unwrap();
    assert!(verifier.verify(&q, &other_expected).is_err());
}
