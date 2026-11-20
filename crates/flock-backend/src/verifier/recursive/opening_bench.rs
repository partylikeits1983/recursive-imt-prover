//! Run the measured WHIR proofs through the same native Poly192 circuit gadgets as a parent.
use super::{
    BinaryPolyCoordinateOpeningPlan, BinaryPolyDeferredWhirTraceVerifier, BinaryTower128Challenger,
    Ch, CircuitBuilder, CompressionFunctionFromHasher, E, F, Keccak256Hash, MerkleCap, Mmcs,
    Opening, OpeningBatch, OpeningProtocol, Point, Result, SerializingHasher, TableShape,
    TableSpec, WHIR_CAP_HEIGHT, config, deferred_seed, ensure, import_opening,
};
use crate::{
    checkpoint_keccak::{committed::Commitment, recursive::closed::builder},
    opening_bench::{CircuitCost, SEED},
};
use p3_circuit::ops::{
    ByteHash, NativePoly192Target, NpoTypeId, Op, binary_encoding::NativeBinaryEncoding,
    bytes_to_limbs,
};

pub(crate) struct CircuitInput {
    pub log_inv_rate: usize,
    pub root: Commitment,
    pub proof: Opening,
    pub protocol: p3_sumcheck::OpeningProtocol,
    pub widths: Vec<Vec<usize>>,
    pub points: Vec<p3_multilinear_util::point::Point<p3_binary_field::Poly192>>,
    pub opened: Vec<p3_sumcheck::OpeningEvals<p3_binary_field::Poly192>>,
}

fn old_value(x: p3_binary_field::Poly192) -> E {
    E::new(x.coefficients().map(|f| F::new(f.to_bits())))
}
fn public_value(b: &mut CircuitBuilder<F>, public: &mut Vec<F>, v: E) -> NativePoly192Target {
    public.extend(v.coefficients());
    let cells = b.alloc_public_input_array::<3>("opening coordinate");
    b.native_poly192_from_coefficients(cells)
}

use crate::checkpoint_keccak::{packed, recursive::Bridge};

pub(crate) fn check_circuit(inputs: Vec<CircuitInput>) -> Result<CircuitCost> {
    run_circuit(inputs, SEED, None)
}

pub(crate) fn check_component(
    input: CircuitInput,
    seed: &[u8],
    batch: &packed::Batch,
    proof: &packed::Proof,
) -> Result<CircuitCost> {
    run_circuit(vec![input], seed, Some((batch, proof)))
}

fn run_circuit(
    inputs: Vec<CircuitInput>,
    domain: &[u8],
    component: Option<(&packed::Batch, &packed::Proof)>,
) -> Result<CircuitCost> {
    let mut b = builder()?;
    let seed = domain
        .iter()
        .map(|&byte| b.define_const(F::new(byte.into())))
        .collect::<Vec<_>>();
    let mut ch = BinaryTower128Challenger::with_initial_bytes_with_host::<NativeBinaryEncoding, F>(
        &mut b,
        ByteHash::Keccak256,
        &seed,
    )?;
    let mut native = Ch::from_hasher(domain.to_vec(), Keccak256Hash);
    let mmcs = Mmcs::new(
        SerializingHasher::new(Keccak256Hash),
        CompressionFunctionFromHasher::new(Keccak256Hash),
        WHIR_CAP_HEIGHT,
    );
    let mut public = Vec::new();
    let mut private = Vec::new();
    let mut groups = Vec::new();
    for input in inputs {
        let shapes = input.protocol.table_shapes();
        let mut schedules = vec![vec![]; shapes.len()];
        for (table, batch) in input.protocol.iter_openings() {
            schedules[table].push(OpeningBatch::new(
                batch.current().to_vec(),
                batch.next().to_vec(),
            ));
        }
        let logical = OpeningProtocol::new(
            shapes
                .iter()
                .zip(schedules)
                .map(|(s, batches)| {
                    TableSpec::new(TableShape::new(s.num_variables(), s.width()), batches)
                })
                .collect(),
        );
        let plan =
            BinaryPolyCoordinateOpeningPlan::with_word_openings(&logical, &input.widths, true)?;
        let vars = plan.num_variables();
        let config = config(vars, input.log_inv_rate)?;
        let pcs = BinaryPolyDeferredWhirTraceVerifier::new(
            &config,
            plan.protocol().clone(),
            ByteHash::Keccak256,
            WHIR_CAP_HEIGHT,
            deferred_seed(vars, plan.ring_claim_count()),
        )?;
        let cap = MerkleCap::<F, [u8; 32]>::new(input.root.roots().to_vec());
        let roots = cap
            .roots()
            .iter()
            .map(|digest| {
                public.extend(
                    bytes_to_limbs(digest)
                        .into_iter()
                        .map(|word| F::new(word.into())),
                );
                b.alloc_public_input_array::<16>("parent opening commitment")
                    .to_vec()
            })
            .collect::<Vec<_>>();
        pcs.observe_commitment_native(&mut b, &mut ch, &roots)?;
        pcs.observe_native_commitment(&mut native, &cap)?;
        groups.push((input, plan, config, pcs, cap, roots));
    }
    for (input, plan, config, pcs, cap, roots) in groups {
        let (points, terminals) = if let Some((batch, proof)) = component {
            let (points, _) = batch.reduce(proof, &mut Bridge(&mut native))?;
            let (terminals, next) = batch.circuit_reduction(&mut b, &mut private, ch, proof)?;
            ch = next;
            (points, Some(terminals))
        } else {
            (input.points, None)
        };
        let logical: Vec<Vec<E>> = points
            .iter()
            .map(|p| p.as_slice().iter().copied().map(old_value).collect())
            .collect();
        let targets = terminals
            .as_ref()
            .map(|t| t.points.clone())
            .unwrap_or_else(|| {
                logical
                    .iter()
                    .map(|p| {
                        p.iter()
                            .map(|&v| public_value(&mut b, &mut public, v))
                            .collect()
                    })
                    .collect()
            });
        let targets = plan.opening_points(&targets, |v| b.native_poly192_constant([v, 0, 0]))?;
        let points = plan
            .opening_points(&logical, |v| E::from(F::new(v)))?
            .into_iter()
            .map(Point::new)
            .collect::<Vec<_>>();
        let proof = pcs.allocate_native_targets(&mut b)?;
        private.extend(import_opening(
            &pcs,
            &config,
            &mmcs,
            &cap,
            &points,
            &input.proof,
            &mut native,
        )?);
        let (opened, next) = pcs.verify_at_native(&mut b, ch, &roots, &targets, &proof)?;
        ch = next;
        let values = plan.recombine_native(&mut b, &opened)?;
        if let Some(terminals) = terminals {
            terminals.authenticate(&mut b, &values)?;
            continue;
        }
        ensure!(
            values.len() == input.opened.len(),
            "recursive opening schedule mismatch"
        );
        for (batch, expected) in values.iter().zip(input.opened) {
            ensure!(
                batch.current().len() == expected.current().len() && expected.next().is_empty(),
                "recursive opening width mismatch"
            );
            for (target, &value) in batch.current().iter().zip(expected.current()) {
                let expected = public_value(&mut b, &mut public, old_value(value));
                for (&left, &right) in target.coefficients().iter().zip(expected.coefficients()) {
                    b.connect(left, right);
                }
            }
        }
    }
    let circuit = b.build()?;
    let mut runner = circuit.runner();
    runner.set_public_inputs(&public)?;
    runner.set_private_inputs(&private)?;
    runner.run_witness()?;
    let last = public
        .last_mut()
        .ok_or_else(|| anyhow::anyhow!("empty opening statement"))?;
    *last = F::new(last.to_bits() ^ 1);
    let mut altered = circuit.runner();
    let accepted = altered
        .set_public_inputs(&public)
        .and_then(|()| altered.set_private_inputs(&private))
        .and_then(|()| altered.run_witness())
        .is_ok();
    ensure!(
        !accepted,
        "recursive verifier accepted an altered opening value"
    );
    let keccak = NpoTypeId::native_keccak_f1600();
    let keccak_permutations = circuit.ops.iter().filter(|op| {
        matches!(op, Op::NonPrimitiveOpWithExecutor { executor, .. } if executor.op_type() == &keccak)
    }).count();
    Ok(CircuitCost {
        witnesses: circuit.witness_count,
        operations: circuit.ops.len(),
        keccak_permutations,
    })
}
