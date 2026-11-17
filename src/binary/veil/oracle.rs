//! Experimental VEIL oracle bridge: padded salted commitments, masked MLE
//! claims, and a uniform random combination authenticated by additive WHIR.
//! The complete adaptive-transcript ZK and ROM composition analysis is pending.

use anyhow::{Result, ensure};
use p3_field::PrimeCharacteristicRing;
use p3_multilinear_util::{point::Point, poly::Poly};
use p3_sumcheck::{constraints::statement::NextStatement, strategy::VariableOrder};
use rand::rngs::StdRng;
use serde::{Deserialize, Serialize};

use super::{
    E,
    code::BinaryCode,
    compiler::{MaskedProver, MaskedReader},
    constraints::Linear,
    native::OraclePoint,
    parameters::Parameters,
    transcript::Transcript,
    vector::{CommittedVectors, Opening, dot, powers, verify_openings},
    whir::{BlendOpening, CommittedBlend, security_budget},
};
use crate::binary::security::union_bits;

/// Trusted geometry. The caller's verifier fixes this, never the opening proof.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct OracleSpec {
    pub variables: usize,
    pub columns: usize,
}

/// Single-use private oracle. One opening can batch multiple prescribed points.
pub(super) struct CommittedOracle {
    spec: OracleSpec,
    parameters: Parameters,
    data: CommittedVectors,
}

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct OracleOpening {
    blend_root: [u8; 32],
    blend_evals: Vec<E>,
    rows: Vec<Opening>,
    whir: BlendOpening,
}

pub(super) struct OracleClaims {
    pub values: Vec<Vec<Linear>>,
    pub consistency: Vec<Linear>,
}

impl OraclePoint<'_> {
    fn point(&self) -> &[E] {
        match self {
            Self::Current(p) | Self::Next(p) => p,
        }
    }

    pub(super) fn weights(&self) -> Vec<E> {
        match self {
            Self::Current(point) => Poly::new_from_point(point, E::ONE).into_evals(),
            Self::Next(point) => {
                let mut next = NextStatement::initialize(point.len());
                next.add_evaluated_constraint(
                    Point::new(vec![]),
                    Point::new(point.to_vec()),
                    E::ZERO,
                    VariableOrder::Prefix,
                );
                let mut weights = Poly::new(vec![E::ZERO; 1 << point.len()]);
                let mut sum = E::ZERO;
                next.combine(&mut weights, &mut sum, E::ONE, 0);
                weights.into_evals()
            }
        }
    }
}

impl OracleSpec {
    pub fn code(&self, parameters: &Parameters) -> Result<BinaryCode> {
        ensure!(
            self.variables <= 20 && (1..=2048).contains(&self.columns),
            "invalid private oracle shape"
        );
        let code = parameters.code(1 << self.variables, false)?;
        ensure!(
            // The depth-32 fixed AIR has 1,626 columns and 1,024 rows.
            // Its padded encoding retains about 1.2 GiB of field cells;
            // this cap bounds retained cells, not temporary/peak allocations.
            code.codeword_len.saturating_mul(self.columns + 3) <= 1 << 26,
            "private oracle exceeds retained cell budget"
        );
        let coding = parameters.diagnostic(code.message_len, self.columns, false)?;
        let whir = security_budget(code.input_len, parameters)?;
        let bits = union_bits(&[
            coding.query_miss_bits,
            coding.linear_combination_gap_bits,
            191.0 - ((2 * self.columns) as f64).log2(),
            191.0 - ((code.queries + 2) as f64).log2() - whir.log2_max_candidates,
            whir.conditional_bits,
        ])?;
        ensure!(
            bits >= parameters.min_algebraic_bits as f64,
            "oracle algebraic bound {bits:.3} below required {}",
            parameters.min_algebraic_bits
        );
        Ok(code)
    }

    pub fn messages(&self, points: usize) -> Result<usize> {
        ensure!(
            (1..=2).contains(&points),
            "oracle needs one or two batched points"
        );
        Ok(points * (self.columns + 1))
    }

    fn bind(
        &self,
        root: &[u8; 32],
        points: &[OraclePoint<'_>],
        transcript: &mut Transcript,
    ) -> Result<()> {
        self.messages(points.len())?;
        ensure!(
            points.iter().all(|p| p.point().len() == self.variables),
            "wrong oracle point arity"
        );
        transcript.bytes(
            b"private-oracle-opening",
            &postcard::to_allocvec(&(
                self,
                root,
                points.iter().map(OraclePoint::point).collect::<Vec<_>>(),
            ))?,
        );
        // Keep the existing all-current transcript unchanged. Any successor
        // view has a distinct, explicitly bound ordered view schedule.
        if points.iter().any(|p| matches!(p, OraclePoint::Next(_))) {
            transcript.bytes(
                b"private-oracle-successor-views",
                &postcard::to_allocvec(
                    &points
                        .iter()
                        .map(|p| matches!(p, OraclePoint::Next(_)))
                        .collect::<Vec<_>>(),
                )?,
            );
        }
        Ok(())
    }
}

impl CommittedOracle {
    pub fn new(
        spec: OracleSpec,
        columns: &[Vec<E>],
        parameters: &Parameters,
        rng: &mut StdRng,
    ) -> Result<Self> {
        let code = spec.code(parameters)?;
        ensure!(columns.len() == spec.columns, "wrong oracle column count");
        let data = CommittedVectors::new(columns, code, false, rng)?;
        Ok(Self {
            spec,
            parameters: parameters.clone(),
            data,
        })
    }

    pub fn root(&self) -> [u8; 32] {
        self.data.root
    }

    pub fn open(self, points: &[OraclePoint<'_>], ctx: &mut MaskedProver) -> Result<OracleOpening> {
        let code = self.spec.code(&self.parameters)?;
        self.spec
            .bind(&self.data.root, points, ctx.public_transcript())?;
        let mut claims = Vec::with_capacity(self.spec.messages(points.len())?);
        for point in points {
            let weights = point.weights();
            for column in self.data.columns() {
                claims.push(dot(&column[..code.message_len], &weights));
            }
        }
        ctx.send(b"private-oracle-evaluations", &claims)?;
        let alpha = ctx.challenge(b"private-oracle-combination")?;
        let alpha_powers = powers(alpha, self.spec.columns + 1);
        let blend: Vec<E> = (0..code.input_len)
            .map(|i| {
                self.data
                    .columns()
                    .iter()
                    .zip(&alpha_powers)
                    .map(|(col, &a)| a * col[i])
                    .sum()
            })
            .collect();
        // Only the independent-mask combination enters the non-hiding backend.
        let committed = CommittedBlend::new(blend, &self.parameters)?;
        let blend_root = committed.root;
        let blend_evals: Vec<E> = claims
            .chunks_exact(self.spec.columns + 1)
            .map(|v| dot(v, &alpha_powers))
            .collect();
        let transcript = ctx.public_transcript();
        let indices = query_schedule(&code, &blend_root, &blend_evals, transcript);
        let rows = self.data.into_openings(&indices)?;
        let row_values = combine_rows(&rows, &alpha_powers);
        let (weights, sum) = functional(
            &code,
            points,
            &indices,
            &blend_evals,
            &row_values,
            transcript,
        )?;
        let whir = committed.prove(&weights, sum, transcript)?;
        Ok(OracleOpening {
            blend_root,
            blend_evals,
            rows,
            whir,
        })
    }
}

impl OracleOpening {
    pub fn verify(
        &self,
        spec: &OracleSpec,
        root: &[u8; 32],
        points: &[OraclePoint<'_>],
        parameters: &Parameters,
        ctx: &mut MaskedReader<'_>,
    ) -> Result<OracleClaims> {
        let code = spec.code(parameters)?;
        spec.bind(root, points, ctx.public_transcript())?;
        ensure!(
            self.blend_evals.len() == points.len(),
            "wrong blend evaluation count"
        );
        let messages = ctx.read(b"private-oracle-evaluations", spec.messages(points.len())?)?;
        let alpha = ctx.challenge(b"private-oracle-combination")?;
        let alpha_powers = powers(alpha, spec.columns + 1);
        let transcript = ctx.public_transcript();
        let indices = query_schedule(&code, &self.blend_root, &self.blend_evals, transcript);
        verify_openings(root, &code, spec.columns + 1, &indices, &self.rows)?;
        let row_values = combine_rows(&self.rows, &alpha_powers);
        let (weights, sum) = functional(
            &code,
            points,
            &indices,
            &self.blend_evals,
            &row_values,
            transcript,
        )?;
        self.whir
            .verify(&self.blend_root, &weights, sum, parameters, transcript)?;
        let mut values = Vec::with_capacity(points.len());
        let mut consistency = Vec::with_capacity(points.len());
        for (messages, &evaluation) in messages
            .chunks_exact(spec.columns + 1)
            .zip(&self.blend_evals)
        {
            let mut check = Linear::constant(evaluation);
            for (message, &a) in messages.iter().zip(&alpha_powers) {
                check
                    .terms
                    .extend(message.terms.iter().map(|&(i, c)| (i, c * a)));
            }
            consistency.push(check);
            values.push(messages[..spec.columns].to_vec());
        }
        Ok(OracleClaims {
            values,
            consistency,
        })
    }
}

fn query_schedule(
    code: &BinaryCode,
    root: &[u8; 32],
    evals: &[E],
    transcript: &mut Transcript,
) -> Vec<usize> {
    transcript.bytes(b"oracle-blend-commitment", root);
    transcript.fields(b"oracle-blend-evaluations", evals);
    transcript.indices(code.queries, code.codeword_len)
}

fn combine_rows(rows: &[Opening], alpha: &[E]) -> Vec<E> {
    rows.iter().map(|row| dot(&row.rows[0], alpha)).collect()
}

/// Batch MLE evaluations and the sampled codeword rows into one dense linear
/// functional. WHIR authenticates that functional via a public sumcheck.
fn functional(
    code: &BinaryCode,
    points: &[OraclePoint<'_>],
    indices: &[usize],
    evals: &[E],
    rows: &[E],
    transcript: &mut Transcript,
) -> Result<(Vec<E>, E)> {
    transcript.fields(b"oracle-blend-rows", rows);
    let beta = transcript.challenge(b"oracle-functional-batch")?;
    let mut weights = vec![E::ZERO; code.input_len];
    let mut sum = E::ZERO;
    let mut power = E::ONE;
    for (point, &claim) in points.iter().zip(evals) {
        let eq = point.weights();
        for (target, &weight) in weights.iter_mut().zip(&eq) {
            *target += power * weight;
        }
        sum += power * claim;
        power *= beta;
    }
    for (&index, &claim) in indices.iter().zip(rows) {
        for (target, weight) in weights.iter_mut().zip(code.generator_row(index)?) {
            *target += power * weight;
        }
        sum += power * claim;
        power *= beta;
    }
    Ok((weights, sum))
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use p3_field::PrimeCharacteristicRing;
    use p3_multilinear_util::{point::Point, poly::Poly};
    use rand::{RngExt, SeedableRng, rngs::StdRng};

    use super::{CommittedOracle, OracleOpening, OraclePoint, OracleSpec};
    use crate::binary::veil::{
        E, F,
        compiler::{MaskedProver, MaskedReader},
        constraints::{ExperimentalProof, Relation},
        parameters::Parameters,
        vector::dot,
    };

    fn replay(
        opening: &OracleOpening,
        root: &[u8; 32],
        point: &[E],
        expected: &[Vec<E>],
        reader: &mut MaskedReader<'_>,
    ) -> Result<Relation> {
        let spec = OracleSpec {
            variables: point.len(),
            columns: 2,
        };
        let views = [OraclePoint::Current(point), OraclePoint::Next(point)];
        let claims = opening.verify(&spec, root, &views, &Parameters::default(), reader)?;
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
    fn private_successor_openings_bind_the_repeat_last_view() -> Result<()> {
        let parameters = Parameters::default();
        let mut rng = StdRng::seed_from_u64(135);
        for variables in [0, 1, 5] {
            let point: Vec<E> = (0..variables).map(|_| rng.random()).collect();
            let columns: Vec<Vec<E>> = (0..2)
                .map(|_| (0..1 << variables).map(|_| rng.random()).collect())
                .collect();
            let eval_point = Point::new(point.clone());
            let current: Vec<E> = columns
                .iter()
                .map(|c| Poly::new(c.as_slice()).eval_ext::<F>(&eval_point))
                .collect();
            let next: Vec<E> = columns
                .iter()
                .map(|c| {
                    let shifted: Vec<E> =
                        (0..c.len()).map(|i| c[(i + 1).min(c.len() - 1)]).collect();
                    let expected = Poly::new(shifted).eval_ext::<F>(&eval_point);
                    assert_eq!(expected, dot(c, &OraclePoint::Next(&point).weights()));
                    expected
                })
                .collect();
            let expected = [current, next];
            let spec = OracleSpec {
                variables,
                columns: 2,
            };
            let data = CommittedOracle::new(spec.clone(), &columns, &parameters, &mut rng)?;
            let root = data.root();
            // The values are public ONLY in this test, so it can constrain the
            // hidden expressions independently of a downstream AIR evaluator.
            let binding = postcard::to_allocvec(&(b"successor-fixture", root, &point, &expected))?;
            let mut ctx = MaskedProver::new(&parameters, &binding, spec.messages(2)?, &mut rng)?;
            let opening = data.open(
                &[OraclePoint::Current(&point), OraclePoint::Next(&point)],
                &mut ctx,
            )?;
            let inner = ctx.finish(
                |reader| replay(&opening, &root, &point, &expected, reader),
                &mut rng,
            )?;
            let bytes = postcard::to_allocvec(&(inner, opening))?;
            let (inner, opening): (ExperimentalProof, OracleOpening) =
                postcard::from_bytes(&bytes)?;
            let mut reader = MaskedReader::new(
                &parameters,
                &binding,
                spec.messages(2)?,
                &inner.masks.root,
                &inner.masked,
            )?;
            let relation = replay(&opening, &root, &point, &expected, &mut reader)?;
            reader.verify(&parameters, &inner, &relation)?;

            let mut wrong = expected.clone();
            wrong[1][0] += E::ONE;
            let mut reader = MaskedReader::new(
                &parameters,
                &binding,
                spec.messages(2)?,
                &inner.masks.root,
                &inner.masked,
            )?;
            let relation = replay(&opening, &root, &point, &wrong, &mut reader)?;
            assert!(reader.verify(&parameters, &inner, &relation).is_err());
            for views in [
                [OraclePoint::Current(&point), OraclePoint::Current(&point)],
                [OraclePoint::Next(&point), OraclePoint::Current(&point)],
            ] {
                let mut reader = MaskedReader::new(
                    &parameters,
                    &binding,
                    spec.messages(2)?,
                    &inner.masks.root,
                    &inner.masked,
                )?;
                assert!(
                    opening
                        .verify(&spec, &root, &views, &parameters, &mut reader)
                        .is_err()
                );
            }
        }
        Ok(())
    }
}
