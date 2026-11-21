use anyhow::Result;
use p3_field::{Field, PrimeCharacteristicRing};
use p3_multilinear_util::{point::Point, poly::Poly};
use rand::{RngExt, SeedableRng, rngs::StdRng};

use super::{Functional, StackedOpening, StackedOracle, StackedSpec, View};
use crate::binary::veil::{
    E, F,
    code::BinaryCode,
    compiler::{MaskedProver, MaskedReader},
    constraints::Relation,
    native::OraclePoint,
    parameters::Parameters,
    vector::dot,
    whir::BlendFunctional,
};

#[test]
fn coefficient_generator_and_compact_functional_match_dense_evaluation() -> Result<()> {
    let mut rng = StdRng::seed_from_u64(0x636f656666);
    for variables in [0, 1, 4, 8] {
        let spec = StackedSpec {
            variables,
            columns: 5,
            log_stack: 2,
            domains: Default::default(),
        };
        let code = BinaryCode::coefficients(1 << (variables + 2), 5, 2)?;
        let input: Vec<E> = (0..code.input_len).map(|_| rng.random()).collect();
        let encoded = code.encode(&input)?;
        for index in [0, 1, 13, code.codeword_len - 1] {
            assert_eq!(
                encoded[index],
                input
                    .iter()
                    .zip(code.generator_row(index)?)
                    .map(|(&x, y)| x * y)
                    .sum::<E>()
            );
        }
        assert!(code.to_product(&input).is_err());
        let point: Vec<E> = (0..variables).map(|_| rng.random()).collect();
        let functional = Functional {
            code,
            spec,
            views: vec![
                View {
                    point: point.clone(),
                    next: false,
                },
                View { point, next: true },
            ],
            indices: vec![0, 3, 3, 7, 15],
            theta: rng.random(),
            beta: rng.random(),
        };
        let dense = functional.dense()?;
        for _ in 0..8 {
            let point: Vec<E> = (0..dense.len().ilog2()).map(|_| rng.random()).collect();
            let expected = Poly::new(dense.as_slice()).eval_ext::<F>(&Point::new(point.clone()));
            assert_eq!(expected, functional.evaluate(&point)?);
        }
    }
    Ok(())
}

#[test]
fn random_coefficient_prefix_hides_queried_rows_when_message_changes() -> Result<()> {
    let mut rng = StdRng::seed_from_u64(0x70726976616379);
    for message_len in [1, 4, 16] {
        let code = BinaryCode::coefficients(message_len, 5, 2)?;
        let before: Vec<E> = (0..code.input_len).map(|_| rng.random()).collect();
        let mut after = before.clone();
        for value in &mut after[code.message_offset()..] {
            *value = rng.random();
        }
        let queries = [0, 3, 3, 7, code.codeword_len - 1];
        let distinct = [queries[0], queries[1], queries[3], queries[4]];
        let n = distinct.len();
        let mut matrix = Vec::new();
        let mut rhs = Vec::new();
        for q in distinct {
            let row = code.generator_row(q)?;
            matrix.push(row[..n].to_vec());
            rhs.push(
                row.iter()
                    .zip(before.iter().zip(&after))
                    .map(|(&c, (&a, &b))| (a + b) * c)
                    .sum::<E>(),
            );
        }
        for i in 0..n {
            let pivot = (i..n)
                .find(|&j| matrix[j][i] != F::ZERO)
                .expect("prefix evaluation matrix is full rank");
            matrix.swap(i, pivot);
            rhs.swap(i, pivot);
            let inverse = matrix[i][i].inverse();
            for value in &mut matrix[i] {
                *value *= inverse;
            }
            rhs[i] *= inverse;
            for j in 0..n {
                if i == j {
                    continue;
                }
                let factor = matrix[j][i];
                let row = matrix[i].clone();
                for (target, value) in matrix[j].iter_mut().zip(row) {
                    *target += factor * value;
                }
                let value = rhs[i];
                rhs[j] += factor * value;
            }
        }
        for i in 0..n {
            after[i] += rhs[i];
        }
        let left = code.encode(&before)?;
        let right = code.encode(&after)?;
        for q in queries {
            assert_eq!(left[q], right[q]);
        }
        assert_ne!(
            &before[code.message_offset()..],
            &after[code.message_offset()..]
        );
    }
    Ok(())
}

fn replay(
    spec: &StackedSpec,
    opening: &StackedOpening,
    root: &[u8; 32],
    point: &[E],
    expected: &[Vec<E>],
    reader: &mut MaskedReader<'_>,
) -> Result<Relation> {
    let claims = opening.verify(
        spec,
        root,
        &[OraclePoint::Current(point), OraclePoint::Next(point)],
        &Parameters::default(),
        reader,
    )?;
    let mut linear = claims.consistency;
    for (values, expected) in claims.values.into_iter().zip(expected) {
        for (mut value, &expected) in values.into_iter().zip(expected) {
            value.constant += expected;
            linear.push(value);
        }
    }
    Ok(Relation {
        variables: spec.messages(2)?,
        public_wires: vec![],
        linear,
        products: vec![],
    })
}

#[test]
fn stacked_oracle_authenticates_original_column_order_and_successors() -> Result<()> {
    let parameters = Parameters::default();
    let mut rng = StdRng::seed_from_u64(927);
    let spec = StackedSpec {
        variables: 3,
        columns: 5,
        log_stack: 2,
        domains: Default::default(),
    };
    let columns: Vec<Vec<E>> = (0..spec.columns)
        .map(|_| (0..8).map(|_| rng.random()).collect())
        .collect();
    let point: Vec<E> = (0..3).map(|_| rng.random()).collect();
    let expected: Vec<Vec<E>> = [OraclePoint::Current(&point), OraclePoint::Next(&point)]
        .iter()
        .map(|p| columns.iter().map(|c| dot(c, &p.weights())).collect())
        .collect();
    let data = StackedOracle::new(spec.clone(), &columns, &parameters, &mut rng)?;
    let root = data.root();
    let binding = postcard::to_allocvec(&(b"stacked-test", root, &point, &expected))?;
    let mut ctx = MaskedProver::new(&parameters, &binding, spec.messages(2)?, &mut rng)?;
    let opening = data.open(
        &[OraclePoint::Current(&point), OraclePoint::Next(&point)],
        &mut ctx,
    )?;
    let inner = ctx.finish(
        |r| replay(&spec, &opening, &root, &point, &expected, r),
        &mut rng,
    )?;
    for kind in 0..5 {
        let mut expected = expected.clone();
        match kind {
            0 => (),
            1 => expected[0].swap(0, 4),   // different stack
            2 => expected[1].swap(0, 1),   // different slot
            3 => expected[1][4] += E::ONE, // short last stack
            _ => expected.swap(0, 1),
        }
        let mut reader = MaskedReader::new(
            &parameters,
            &binding,
            spec.messages(2)?,
            &inner.masks.root,
            &inner.masked,
        )?;
        let relation = replay(&spec, &opening, &root, &point, &expected, &mut reader)?;
        assert_eq!(
            reader.verify(&parameters, &inner, &relation).is_ok(),
            kind == 0
        );
    }
    // Changing trusted stacking also changes transcript identity and row width.
    let wrong = StackedSpec {
        log_stack: 1,
        ..spec.clone()
    };
    let mut reader = MaskedReader::new(
        &parameters,
        &binding,
        spec.messages(2)?,
        &inner.masks.root,
        &inner.masked,
    )?;
    assert!(replay(&wrong, &opening, &root, &point, &expected, &mut reader).is_err());
    // Prove a false claim while bypassing the native relation precheck. The
    // actual algebraic verifier, not a native boolean, must reject it.
    let data = StackedOracle::new(spec.clone(), &columns, &parameters, &mut rng)?;
    let root = data.root();
    let mut ctx = MaskedProver::new(&parameters, &binding, spec.messages(2)?, &mut rng)?;
    let opening = data.open(
        &[OraclePoint::Current(&point), OraclePoint::Next(&point)],
        &mut ctx,
    )?;
    let mut wrong = expected.clone();
    wrong[0][4] += E::ONE;
    let inner = ctx.finish_unchecked(
        |r| replay(&spec, &opening, &root, &point, &wrong, r),
        &mut rng,
    )?;
    let mut reader = MaskedReader::new(
        &parameters,
        &binding,
        spec.messages(2)?,
        &inner.masks.root,
        &inner.masked,
    )?;
    let relation = replay(&spec, &opening, &root, &point, &wrong, &mut reader)?;
    assert!(reader.verify(&parameters, &inner, &relation).is_err());
    Ok(())
}
