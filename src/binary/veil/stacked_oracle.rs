//! Experimental coefficient oracle with narrow, stacked trace commitments.
//!
//! Original column claims precede the slot challenge; auxiliary-mask claims
//! precede the column challenge. Only their uniformly masked combination enters
//! non-hiding WHIR. The full adaptive ZK/composition argument remains pending.
use anyhow::{Result, ensure};
use p3_field::PrimeCharacteristicRing;
use p3_multilinear_util::point::Point;
use rand::rngs::StdRng;
use serde::{Deserialize, Serialize};

use super::{
    E,
    air_algebra::{add, scale},
    code::BinaryCode,
    compiler::{MaskedProver, MaskedReader},
    constraints::Linear,
    native::OraclePoint,
    oracle::OracleClaims,
    parameters::Parameters,
    transcript::Transcript,
    vector::{CommittedVectors, Opening, dot, powers, verify_openings},
    whir::{BlendFunctional, BlendOpening, CommittedBlend, security_budget},
};
use crate::binary::security::union_bits;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct StackedSpec {
    pub variables: usize,
    pub columns: usize,
    pub log_stack: usize,
}

pub(super) struct StackedOracle {
    spec: StackedSpec,
    parameters: Parameters,
    data: CommittedVectors,
}

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct StackedOpening {
    blend_root: [u8; 32],
    blend_evals: Vec<E>,
    rows: Vec<Opening>,
    whir: BlendOpening,
}

#[derive(Clone)]
struct View {
    point: Vec<E>,
    next: bool,
}

/// Reconstructed from trusted geometry and replayed challenges, never decoded
/// from proof-controlled weight tables.
struct Functional {
    code: BinaryCode,
    spec: StackedSpec,
    views: Vec<View>,
    indices: Vec<usize>,
    theta: E,
    beta: E,
}

impl StackedSpec {
    fn stack(&self) -> usize {
        1 << self.log_stack
    }
    fn width(&self) -> usize {
        self.columns.div_ceil(self.stack())
    }
    pub fn messages(&self, points: usize) -> Result<usize> {
        ensure!(
            (1..=2).contains(&points),
            "expected one or two oracle views"
        );
        Ok(points * (self.columns + 1))
    }
    pub fn code(&self, parameters: &Parameters) -> Result<BinaryCode> {
        ensure!(
            self.variables <= 20 && self.log_stack <= 8 && (1..=2048).contains(&self.columns),
            "invalid stacked oracle shape"
        );
        let length = 1usize << (self.variables + self.log_stack);
        let geometry = parameters.code(length, false)?;
        let code = BinaryCode::coefficients(length, geometry.queries, parameters.log_inv_rate)?;
        ensure!(
            code.codeword_len.saturating_mul(self.width() + 3) <= 1 << 26,
            "stacked oracle exceeds retained cell budget"
        );
        let coding = parameters.diagnostic(length, self.width(), false)?;
        let whir = security_budget(code.input_len, parameters)?;
        let bits = union_bits(&[
            coding.query_miss_bits,
            coding.linear_combination_gap_bits,
            // Both slot and column batching, with at most two views. Charge
            // the original width conservatively, including short final stacks.
            191.0 - ((4 * (self.columns + self.stack())) as f64).log2(),
            191.0 - ((code.queries + 2) as f64).log2() - whir.log2_max_candidates,
            whir.conditional_bits,
        ])?;
        ensure!(
            bits >= parameters.min_algebraic_bits as f64,
            "stacked oracle algebraic bound {bits:.3} below required floor"
        );
        Ok(code)
    }
    pub fn retained_bytes(&self, parameters: &Parameters) -> Result<usize> {
        self.code(parameters)?;
        Ok(parameters
            .diagnostic(1 << (self.variables + self.log_stack), self.width(), false)?
            .retained_commitment_bytes)
    }
    fn bind(
        &self,
        root: &[u8; 32],
        points: &[OraclePoint<'_>],
        transcript: &mut Transcript,
    ) -> Result<Vec<View>> {
        self.messages(points.len())?;
        let views: Vec<_> = points
            .iter()
            .map(|p| match p {
                OraclePoint::Current(p) => View {
                    point: p.to_vec(),
                    next: false,
                },
                OraclePoint::Next(p) => View {
                    point: p.to_vec(),
                    next: true,
                },
            })
            .collect();
        ensure!(
            views.iter().all(|p| p.point.len() == self.variables),
            "wrong stacked point arity"
        );
        transcript.integers(
            b"stacked-coefficient-oracle-v2",
            &[self.variables, self.columns, self.log_stack],
        );
        transcript.bytes(b"stacked-oracle-root", root);
        bind_views(&views, transcript);
        Ok(views)
    }
}

impl StackedOracle {
    pub fn new(
        spec: StackedSpec,
        columns: &[Vec<E>],
        parameters: &Parameters,
        rng: &mut StdRng,
    ) -> Result<Self> {
        let code = spec.code(parameters)?;
        let height = 1 << spec.variables;
        ensure!(
            columns.len() == spec.columns && columns.iter().all(|c| c.len() == height),
            "wrong trace dimensions"
        );
        let mut stacked = vec![vec![E::ZERO; code.message_len]; spec.width()];
        for (i, column) in columns.iter().enumerate() {
            let offset = (i % spec.stack()) * height;
            stacked[i / spec.stack()][offset..offset + height].copy_from_slice(column);
        }
        // The final incomplete stack has zero unused slots. The same slot
        // functional then applies to every column. Independent padding and the
        // auxiliary column hide these known values along with the actual trace.
        let data = CommittedVectors::new(&stacked, code, false, rng)?;
        Ok(Self {
            spec,
            parameters: parameters.clone(),
            data,
        })
    }
    pub fn root(&self) -> [u8; 32] {
        self.data.root
    }
    pub fn open(
        self,
        points: &[OraclePoint<'_>],
        ctx: &mut MaskedProver,
    ) -> Result<StackedOpening> {
        let code = self.spec.code(&self.parameters)?;
        let views = self
            .spec
            .bind(&self.data.root, points, ctx.public_transcript())?;
        let height = 1 << self.spec.variables;
        let mut claims = Vec::with_capacity(points.len() * self.spec.columns);
        for point in points {
            let weights = point.weights();
            for i in 0..self.spec.columns {
                let offset = code.message_offset() + (i % self.spec.stack()) * height;
                claims.push(dot(
                    &self.data.columns()[i / self.spec.stack()][offset..offset + height],
                    &weights,
                ));
            }
        }
        ctx.send(b"stacked-column-evaluations", &claims)?;
        let theta = ctx.challenge(b"stacked-slot-combination")?;
        let slots = powers(theta, self.spec.stack());
        let mask = self.data.columns().last().unwrap();
        let mask_claims: Vec<E> = points
            .iter()
            .map(|point| {
                let weights = point.weights();
                slots
                    .iter()
                    .enumerate()
                    .map(|(slot, &factor)| {
                        let offset = code.message_offset() + slot * height;
                        factor * dot(&mask[offset..offset + height], &weights)
                    })
                    .sum()
            })
            .collect();
        ctx.send(b"stacked-mask-evaluations", &mask_claims)?;
        let alpha = ctx.challenge(b"stacked-column-combination")?;
        let factors = powers(alpha, self.spec.width() + 1);
        let blend: Vec<E> = (0..code.input_len)
            .map(|i| {
                self.data
                    .columns()
                    .iter()
                    .zip(&factors)
                    .map(|(c, &a)| c[i] * a)
                    .sum()
            })
            .collect();
        let committed = CommittedBlend::new(blend, &self.parameters)?;
        let blend_root = committed.root;
        let blend_evals: Vec<E> = claims
            .chunks_exact(self.spec.columns)
            .zip(mask_claims)
            .map(|(claims, mask)| {
                claims
                    .iter()
                    .enumerate()
                    .map(|(i, &v)| {
                        v * factors[i / self.spec.stack()] * slots[i % self.spec.stack()]
                    })
                    .sum::<E>()
                    + mask * factors[self.spec.width()]
            })
            .collect();
        let transcript = ctx.public_transcript();
        let indices = query_schedule(&code, &blend_root, &blend_evals, transcript);
        let rows = self.data.into_openings(&indices)?;
        let row_values: Vec<E> = rows.iter().map(|r| dot(&r.rows[0], &factors)).collect();
        let (functional, sum) = functional(
            code,
            &self.spec,
            views,
            indices,
            theta,
            &blend_evals,
            &row_values,
            transcript,
        )?;
        let whir = committed.prove(&functional, sum, transcript)?;
        Ok(StackedOpening {
            blend_root,
            blend_evals,
            rows,
            whir,
        })
    }
}

impl StackedOpening {
    pub fn verify(
        &self,
        spec: &StackedSpec,
        root: &[u8; 32],
        points: &[OraclePoint<'_>],
        parameters: &Parameters,
        ctx: &mut MaskedReader<'_>,
    ) -> Result<OracleClaims> {
        let code = spec.code(parameters)?;
        let views = spec.bind(root, points, ctx.public_transcript())?;
        ensure!(
            self.blend_evals.len() == points.len(),
            "wrong stacked blend evaluation count"
        );
        let values = ctx.read(b"stacked-column-evaluations", points.len() * spec.columns)?;
        let theta = ctx.challenge(b"stacked-slot-combination")?;
        let masks = ctx.read(b"stacked-mask-evaluations", points.len())?;
        let alpha = ctx.challenge(b"stacked-column-combination")?;
        let factors = powers(alpha, spec.width() + 1);
        let slots = powers(theta, spec.stack());
        let transcript = ctx.public_transcript();
        let indices = query_schedule(&code, &self.blend_root, &self.blend_evals, transcript);
        verify_openings(root, &code, spec.width() + 1, &indices, &self.rows)?;
        let row_values: Vec<E> = self
            .rows
            .iter()
            .map(|r| dot(&r.rows[0], &factors))
            .collect();
        let (functional, sum) = functional(
            code,
            spec,
            views,
            indices,
            theta,
            &self.blend_evals,
            &row_values,
            transcript,
        )?;
        self.whir
            .verify(&self.blend_root, &functional, sum, parameters, transcript)?;
        let mut consistency = Vec::new();
        for ((claims, mask), &evaluation) in values
            .chunks_exact(spec.columns)
            .zip(masks)
            .zip(&self.blend_evals)
        {
            let mut check = add(
                &Linear::constant(evaluation),
                &scale(&mask, factors[spec.width()]),
            );
            for (i, claim) in claims.iter().enumerate() {
                check = add(
                    &check,
                    &scale(claim, factors[i / spec.stack()] * slots[i % spec.stack()]),
                );
            }
            consistency.push(check);
        }
        Ok(OracleClaims {
            values: values
                .chunks_exact(spec.columns)
                .map(<[Linear]>::to_vec)
                .collect(),
            consistency,
        })
    }
}

impl BlendFunctional for Functional {
    fn length(&self) -> usize {
        self.code.input_len
    }
    fn bind(&self, transcript: &mut Transcript) -> Result<()> {
        transcript.integers(
            b"coefficient-functional-v2",
            &[
                self.spec.variables,
                self.spec.columns,
                self.spec.log_stack,
                self.code.input_len,
                self.code.codeword_len,
                self.code.queries,
            ],
        );
        bind_views(&self.views, transcript);
        transcript.integers(b"coefficient-functional-indices", &self.indices);
        transcript.fields(
            b"coefficient-functional-challenges",
            &[self.theta, self.beta],
        );
        Ok(())
    }
    fn dense(&self) -> Result<Vec<E>> {
        let mut result = vec![E::ZERO; self.length()];
        let slots = powers(self.theta, self.spec.stack());
        let height = 1 << self.spec.variables;
        let mut power = E::ONE;
        for view in &self.views {
            let point = if view.next {
                OraclePoint::Next(&view.point)
            } else {
                OraclePoint::Current(&view.point)
            };
            let weights = point.weights();
            for (slot, &factor) in slots.iter().enumerate() {
                let offset = self.code.message_offset() + slot * height;
                for (target, &weight) in result[offset..offset + height].iter_mut().zip(&weights) {
                    *target += power * factor * weight;
                }
            }
            power *= self.beta;
        }
        for &index in &self.indices {
            for (target, weight) in result.iter_mut().zip(self.code.generator_row(index)?) {
                *target += power * weight;
            }
            power *= self.beta;
        }
        Ok(result)
    }
    fn evaluate(&self, point: &[E]) -> Result<E> {
        ensure!(
            point.len() == self.length().ilog2() as usize,
            "wrong functional point arity"
        );
        let prefix = point.len() - self.spec.variables - self.spec.log_stack;
        let selector: E = point[..prefix].iter().copied().product();
        let slot_point = &point[prefix..prefix + self.spec.log_stack];
        let row_point = &point[prefix + self.spec.log_stack..];
        let mut slot = E::ONE;
        let mut theta = self.theta;
        for &coordinate in slot_point.iter().rev() {
            slot *= E::ONE + coordinate + coordinate * theta;
            theta = theta.square();
        }
        let mut sum = E::ZERO;
        let mut power = E::ONE;
        for view in &self.views {
            let row = if view.next {
                let (_, done, omega) = Point::eval_next(&view.point, row_point);
                done + omega
            } else {
                Point::eval_eq(&view.point, row_point)
            };
            sum += power * selector * slot * row;
            power *= self.beta;
        }
        for &index in &self.indices {
            let value: E = point
                .iter()
                .zip(self.code.coefficient_factors(index)?)
                .map(|(&s, t)| E::ONE + s + s * t)
                .product();
            sum += power * value;
            power *= self.beta;
        }
        Ok(sum)
    }
}

fn bind_views(views: &[View], transcript: &mut Transcript) {
    transcript.integers(b"stacked-oracle-view-count", &[views.len()]);
    for view in views {
        transcript.integers(
            b"stacked-oracle-view",
            &[usize::from(view.next), view.point.len()],
        );
        transcript.fields(b"stacked-oracle-point", &view.point);
    }
}

fn query_schedule(
    code: &BinaryCode,
    root: &[u8; 32],
    evals: &[E],
    transcript: &mut Transcript,
) -> Vec<usize> {
    transcript.bytes(b"stacked-blend-commitment", root);
    transcript.fields(b"stacked-blend-evaluations", evals);
    transcript.indices(code.queries, code.codeword_len)
}

#[allow(clippy::too_many_arguments)]
fn functional(
    code: BinaryCode,
    spec: &StackedSpec,
    views: Vec<View>,
    indices: Vec<usize>,
    theta: E,
    evals: &[E],
    rows: &[E],
    transcript: &mut Transcript,
) -> Result<(Functional, E)> {
    ensure!(
        views.len() == evals.len() && indices.len() == rows.len(),
        "wrong functional claims"
    );
    transcript.fields(b"stacked-blend-rows", rows);
    let beta = transcript.challenge(b"stacked-functional-batch")?;
    let factors = powers(beta, evals.len() + rows.len());
    let sum = evals
        .iter()
        .chain(rows)
        .zip(&factors)
        .map(|(&v, &f)| v * f)
        .sum();
    Ok((
        Functional {
            code,
            spec: spec.clone(),
            views,
            indices,
            theta,
            beta,
        },
        sum,
    ))
}

#[cfg(test)]
mod tests;

pub(super) mod recursive;
