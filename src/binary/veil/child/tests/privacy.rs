//! A fixed-transcript coupling of the stacked coefficient oracle, on two actual
//! preimage witnesses of the same public statement. All shifts below translate
//! existing independent pads, so each translation has an inverse.
use super::super::{ALIGNED_PREIMAGE_PROTOCOL, PreparedMembership};
use crate::binary::{
    ClientPublic, IMT_DEPTH,
    tree::{Imt, preimage_leaf},
    veil::{
        E, F,
        compiler::MaskedReader,
        membership_air::MembershipAir,
        native::OraclePoint,
        parameters::Parameters,
        vector::{dot, powers},
    },
};
use anyhow::Result;
use p3_air::check_constraints;
use p3_field::{Field, PrimeCharacteristicRing};

#[test]
#[ignore = "proves a depth-32 masked leaf and couples every stacked oracle column"]
fn different_preimages_under_one_root_preserve_opened_rows_and_entire_blend() -> Result<()> {
    let child = PreparedMembership::for_protocol(
        IMT_DEPTH,
        Parameters::default(),
        ALIGNED_PREIMAGE_PROTOCOL,
    )?;
    let mut tree = Imt::new(IMT_DEPTH)?;
    let preimages = [[0x41; 32], [0x42; 32]];
    for preimage in &preimages {
        tree.append(preimage_leaf(preimage))?;
    }
    let statement = ClientPublic::membership_root(tree.root());
    let trace = |i: usize| {
        child
            .air
            .preimage_trace(&preimages[i], i as u32, &tree.path(i as u32)?)
    };
    let left = trace(0)?;
    let right = trace(1)?;
    for t in [&left, &right] {
        check_constraints(&child.air, t, &MembershipAir::public_values(&statement));
    }
    assert!(
        left.values != right.values,
        "the witnesses must give distinct traces"
    );
    let proof = child.prove_trace(&statement, left.clone())?;
    child.verify(&statement, &proof)?;

    // Use this proof's actual batching coin and all its queried positions.
    let mut reader = MaskedReader::new(
        &child.parameters,
        &child.binding(&statement, &proof.oracle_root)?,
        child.messages,
        &proof.inner.masks.root,
        &proof.inner.masked,
    )?;
    let reduction = child.program.reduce(child.program.replay(&mut reader)?)?;
    let code = child.oracle.code(&child.parameters)?;
    let queries = proof.opening.read_queries(
        &child.oracle,
        &proof.oracle_root,
        &[
            OraclePoint::Current(&reduction.point),
            OraclePoint::Next(&reduction.point),
        ],
        &code,
        &mut reader,
    )?;
    assert_eq!(queries.indices.len(), 176);
    let mut positions = queries.indices.clone();
    positions.sort_unstable();
    positions.dedup();

    // Each coefficient tree column contains a consecutive stack of trace
    // columns. Use the prover's actual NTT to evaluate each trace difference.
    let left = left.transpose();
    let right = right.transpose();
    let stacks = child.oracle_columns() - 1;
    let count = positions.len();
    assert!(count <= code.message_offset());
    let mut matrix = Vec::with_capacity(count);
    for &pos in &positions {
        let mut row = code.generator_row(pos)?[..count].to_vec();
        row.resize(count + stacks, F::ZERO);
        matrix.push(row);
    }
    let mut deltas = Vec::new();
    for (j, (a, b)) in left
        .values
        .chunks(code.message_len)
        .zip(right.values.chunks(code.message_len))
        .enumerate()
    {
        let mut shift = E::zero_vec(code.input_len);
        for (v, (&a, &b)) in shift[code.message_offset()..]
            .iter_mut()
            .zip(a.iter().zip(b))
        {
            *v = E::from(a + b);
        }
        let encoded = code.encode(&shift)?;
        for (&pos, row) in positions.iter().zip(&mut matrix) {
            let [v, y, z] = encoded[pos].coefficients();
            assert_eq!((y, z), (F::ZERO, F::ZERO));
            row[count + j] = v;
        }
        deltas.push(shift);
    }
    assert_eq!(deltas.len(), stacks);
    assert!(
        matrix
            .iter()
            .any(|r| r[count..].iter().any(|&x| x != F::ZERO))
    );
    solve(&mut matrix, count);

    // The leading coefficients are random in the real prover. Add one shift
    // per padding coefficient to cancel the encoded difference at every query.
    let mut weighted = E::zero_vec(code.input_len);
    let mut factor = E::ONE;
    for (j, shift) in deltas.iter_mut().enumerate() {
        for (pad, row) in shift.iter_mut().zip(&matrix) {
            *pad = E::from(row[count + j]);
        }
        let encoded = code.encode(shift)?;
        assert!(queries.indices.iter().all(|&pos| encoded[pos] == E::ZERO));
        for (total, &change) in weighted.iter_mut().zip(shift.iter()) {
            *total += factor * change;
        }
        factor *= queries.alpha;
    }
    // The last column is uniformly random at every coefficient. Translate it
    // by the unique amount preserving the FULL polynomial passed to WHIR.
    let inverse = factor.inverse();
    let auxiliary: Vec<_> = weighted.iter().map(|&change| inverse * change).collect();
    assert!(
        weighted
            .iter()
            .zip(&auxiliary)
            .all(|(&w, &a)| w + factor * a == E::ZERO)
    );
    let encoded_aux = code.encode(&auxiliary)?;
    assert!(
        queries
            .indices
            .iter()
            .all(|&pos| encoded_aux[pos] == E::ZERO)
    );
    // Check both publicly disclosed blend evaluations against the actual
    // trace columns. The last, partially filled stack uses the same slot weights.
    let slots = powers(queries.theta, child.stacking_factor());
    let columns = powers(queries.alpha, stacks);
    let (_, published) = proof.opening.blend_messages();
    let views = [
        OraclePoint::Current(&reduction.point),
        OraclePoint::Next(&reduction.point),
    ];
    for (view, &claimed) in views.iter().zip(published) {
        let weights = view.weights();
        let trace_eval = |trace: &[F]| -> E {
            trace
                .chunks_exact(weights.len())
                .enumerate()
                .map(|(i, column)| {
                    let evaluated: E = column.iter().zip(&weights).map(|(&v, &w)| w * v).sum();
                    evaluated * slots[i % slots.len()] * columns[i / slots.len()]
                })
                .sum()
        };
        let old_aux_eval = (claimed + trace_eval(&left.values)) * inverse;
        let aux_delta: E = auxiliary[code.message_offset()..]
            .chunks_exact(weights.len())
            .zip(&slots)
            .map(|(column, &s)| s * dot(column, &weights))
            .sum();
        assert_eq!(
            trace_eval(&right.values) + factor * (old_aux_eval + aux_delta),
            claimed
        );
    }
    Ok(())
}

/// Solve all the right-hand sides together. Failure to find a pivot means the
/// low-degree masking coordinates cannot independently cover this set of rows.
fn solve(matrix: &mut [Vec<F>], variables: usize) {
    for i in 0..variables {
        let pivot = (i..variables)
            .find(|&j| matrix[j][i] != F::ZERO)
            .expect("full-rank prefix");
        matrix.swap(i, pivot);
        let inverse = matrix[i][i].inverse();
        for entry in &mut matrix[i][i..] {
            *entry *= inverse;
        }
        let pivot = matrix[i][i..].to_vec();
        for (j, row) in matrix.iter_mut().enumerate() {
            if i != j {
                let factor = row[i];
                for (entry, &p) in row[i..].iter_mut().zip(&pivot) {
                    *entry += factor * p;
                }
            }
        }
    }
}
