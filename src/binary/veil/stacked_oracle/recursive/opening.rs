//! The full public oracle-verification phase, returning affine obligations for
//! the masked inner argument. The original private columns never enter here.
use anyhow::{Result, ensure};
use p3_circuit::ops::binary_encoding::NativeBinaryEncoding;
use p3_circuit::ops::binary_host::BinaryCircuitHost;
use p3_circuit::ops::{ByteHash, NativePoly192Target};
use p3_circuit::{CircuitBuilder, ExprId};
use p3_field::BasedVectorSpace;

use super::{FunctionalTarget, ViewTarget, bind_views};
use crate::binary::veil::{
    E, F,
    code::BinaryCode,
    hash::RowDomains,
    native::OraclePoint,
    parameters::Parameters,
    stacked_oracle::{StackedOpening, StackedSpec, functional, query_schedule},
    transcript::{Transcript, query_groups},
    vector::{dot, powers},
    whir::recursive::{
        blend::{BlendTargets, PreparedBlend},
        transcript::{CircuitTranscript, Query},
    },
};

pub(in crate::binary::veil) struct PreparedStacked {
    spec: StackedSpec,
    code: BinaryCode,
    blend: PreparedBlend,
}

pub(in crate::binary::veil) struct OpeningTargets {
    pub masked: Vec<NativePoly192Target>,
    blend_root: [ExprId; 32],
    blend_evals: Vec<NativePoly192Target>,
    rows: Vec<RowTargets>,
    whir: BlendTargets,
}

pub(in crate::binary::veil) struct RowTargets {
    pub values: Vec<NativePoly192Target>,
    pub salts: [NativePoly192Target; 2],
    pub path: Vec<[ExprId; 16]>,
}

/// For each view j, the constant plus the weighted hidden claims and mask
/// claim must equal zero. These are the hidden wire values, not the masked
/// messages in `OpeningTargets`.
pub(in crate::binary::veil) struct OracleRelations {
    pub constants: Vec<NativePoly192Target>,
    pub coefficients: Vec<NativePoly192Target>,
    pub mask_coefficient: NativePoly192Target,
    pub transcript: CircuitTranscript,
}

impl PreparedStacked {
    pub fn new(spec: StackedSpec, parameters: &Parameters) -> Result<Self> {
        let code = spec.code(parameters)?;
        let blend = PreparedBlend::new(code.input_len, parameters)?;
        Ok(Self { spec, code, blend })
    }

    pub fn allocate(&self, b: &mut CircuitBuilder<F>) -> Result<OpeningTargets> {
        let masked = (0..self.spec.messages(2)?).map(|_| field(b)).collect();
        let blend_root = b.alloc_private_input_array::<32>("blend-root");
        let blend_evals = (0..2).map(|_| field(b)).collect();
        let rows = (0..self.code.queries)
            .map(|_| RowTargets {
                values: (0..self.spec.width() + 1).map(|_| field(b)).collect(),
                salts: std::array::from_fn(|_| field(b)),
                path: (0..self.code.codeword_len.ilog2())
                    .map(|_| b.alloc_private_input_array::<16>("salted-oracle-path"))
                    .collect(),
            })
            .collect();
        Ok(OpeningTargets {
            masked,
            blend_root,
            blend_evals,
            rows,
            whir: self.blend.allocate(b)?,
        })
    }

    pub fn import(
        &self,
        proof: &StackedOpening,
        root: &[u8; 32],
        point: &[E],
        masked: &[E],
        mut transcript: Transcript,
    ) -> Result<Vec<F>> {
        ensure!(
            point.len() == self.spec.variables && masked.len() == self.spec.messages(2)?,
            "wrong oracle witness shape"
        );
        ensure!(
            proof.blend_evals.len() == 2 && proof.rows.len() == self.code.queries,
            "wrong oracle proof shape"
        );
        let views = self.spec.bind(
            root,
            &[OraclePoint::Current(point), OraclePoint::Next(point)],
            &mut transcript,
        )?;
        transcript.fields(
            b"stacked-column-evaluations",
            &masked[..2 * self.spec.columns],
        );
        let theta = transcript.challenge(b"stacked-slot-combination")?;
        transcript.fields(
            b"stacked-mask-evaluations",
            &masked[2 * self.spec.columns..],
        );
        let alpha = transcript.challenge(b"stacked-column-combination")?;
        let factors = powers(alpha, self.spec.width() + 1);
        let indices = query_schedule(
            &self.code,
            &proof.blend_root,
            &proof.blend_evals,
            &mut transcript,
        );
        let mut private = Vec::new();
        for value in masked {
            private.extend_from_slice(value.as_basis_coefficients_slice());
        }
        private.extend(proof.blend_root.into_iter().map(|v| F::new(u64::from(v))));
        for value in &proof.blend_evals {
            private.extend_from_slice(value.as_basis_coefficients_slice());
        }
        let mut row_values = Vec::new();
        for opening in &proof.rows {
            ensure!(
                opening.rows.len() == 1 && opening.rows[0].len() == self.spec.width() + 1,
                "wrong oracle row width"
            );
            ensure!(
                opening.path.0.len() == 1
                    && opening.path.0[0].len() == 2
                    && opening.path.1.len() == self.code.codeword_len.ilog2() as usize,
                "wrong oracle authentication shape"
            );
            for value in opening.rows[0].iter().chain(&opening.path.0[0]) {
                private.extend_from_slice(value.as_basis_coefficients_slice());
            }
            for digest in &opening.path.1 {
                private.extend(
                    digest
                        .as_chunks::<2>()
                        .0
                        .iter()
                        .map(|v| F::new(u64::from(u16::from_le_bytes(*v)))),
                );
            }
            row_values.push(dot(&opening.rows[0], &factors));
        }
        let (functional, sum) = functional(
            self.code.clone(),
            &self.spec,
            views,
            indices,
            theta,
            &proof.blend_evals,
            &row_values,
            &mut transcript,
        )?;
        private.extend(self.blend.import(
            &proof.whir,
            &proof.blend_root,
            &functional,
            sum,
            transcript,
        )?);
        Ok(private)
    }

    pub fn verify(
        &self,
        b: &mut CircuitBuilder<F>,
        root: &[ExprId; 32],
        point: &[NativePoly192Target],
        proof: &OpeningTargets,
        mut transcript: CircuitTranscript,
    ) -> Result<OracleRelations> {
        ensure!(
            point.len() == self.spec.variables && proof.masked.len() == self.spec.messages(2)?,
            "wrong circuit oracle shape"
        );
        let views = vec![
            ViewTarget {
                point: point.to_vec(),
                next: false,
            },
            ViewTarget {
                point: point.to_vec(),
                next: true,
            },
        ];
        transcript.integers(
            b,
            b"stacked-coefficient-oracle-v2",
            &[self.spec.variables, self.spec.columns, self.spec.log_stack],
        )?;
        transcript.bytes(b, b"stacked-oracle-root", root)?;
        bind_views(b, &views, &mut transcript)?;
        transcript.fields(
            b,
            b"stacked-column-evaluations",
            &proof.masked[..2 * self.spec.columns],
        )?;
        let theta = transcript.challenge(b, b"stacked-slot-combination")?;
        transcript.fields(
            b,
            b"stacked-mask-evaluations",
            &proof.masked[2 * self.spec.columns..],
        )?;
        let alpha = transcript.challenge(b, b"stacked-column-combination")?;
        let factors = circuit_powers(b, &alpha, self.spec.width() + 1);
        transcript.bytes(b, b"stacked-blend-commitment", &proof.blend_root)?;
        transcript.fields(b, b"stacked-blend-evaluations", &proof.blend_evals)?;
        let queries = transcript.indices(b, self.code.queries, self.code.codeword_len)?;
        let mut row_values = Vec::new();
        ensure!(
            proof.rows.len() == queries.len(),
            "wrong oracle query count"
        );
        authenticate_batch(
            b,
            root,
            &proof.rows,
            &queries,
            self.spec.width() + 1,
            self.spec.domains,
        )?;
        for row in &proof.rows {
            row_values.push(circuit_dot(b, &row.values, &factors)?);
        }
        transcript.fields(b, b"stacked-blend-rows", &row_values)?;
        let beta = transcript.challenge(b, b"stacked-functional-batch")?;
        let claims: Vec<_> = proof
            .blend_evals
            .iter()
            .chain(&row_values)
            .cloned()
            .collect();
        let weights = circuit_powers(b, &beta, claims.len());
        let sum = circuit_dot(b, &claims, &weights)?;
        let functional = FunctionalTarget {
            spec: self.spec.clone(),
            code: self.code.clone(),
            views,
            queries,
            theta: theta.clone(),
            beta,
        };
        let transcript = self.blend.verify(
            b,
            &proof.blend_root,
            &functional,
            &sum,
            &proof.whir,
            transcript,
        )?;
        let slots = circuit_powers(b, &theta, self.spec.stack());
        let coefficients = (0..self.spec.columns)
            .map(|i| {
                b.native_poly192_mul(
                    &factors[i / self.spec.stack()],
                    &slots[i % self.spec.stack()],
                )
            })
            .collect();
        Ok(OracleRelations {
            constants: proof.blend_evals.clone(),
            coefficients,
            mask_coefficient: factors[self.spec.width()].clone(),
            transcript,
        })
    }
}

pub(in crate::binary::veil) fn authenticate_batch(
    b: &mut CircuitBuilder<F>,
    root: &[ExprId; 32],
    rows: &[RowTargets],
    queries: &[Query],
    width: usize,
    domains: RowDomains,
) -> Result<()> {
    ensure!(
        !rows.is_empty() && rows.len() == queries.len(),
        "wrong authentication count"
    );
    let height = queries[0].bits.len();
    ensure!(
        rows.iter()
            .all(|r| r.path.len() == height && r.values.len() == width)
            && queries.iter().all(|q| q.bits.len() == height),
        "wrong authentication shape"
    );
    let root = NativeBinaryEncoding::words_from_bytes(b, root)?;
    for (range, depth) in query_groups(rows.len(), height) {
        let low = height - depth;
        if depth == 0 {
            authenticate(
                b,
                &root,
                &rows[range.start],
                &queries[range.start],
                low,
                domains,
            )?;
            continue;
        }
        let mut layer: Vec<_> = (0..range.len())
            .map(|s| rows[range.start + (s ^ 1)].path[low].to_vec())
            .collect();
        for (s, cap) in layer.iter().enumerate() {
            let query = &queries[range.start + s];
            // The high bits are trusted strata, not prover-selected routing.
            for (bit, &actual) in query.bits[low..].iter().enumerate() {
                let expected = b.define_const(F::new(((s >> bit) & 1) as u64));
                b.connect(actual, expected);
            }
            authenticate(b, cap, &rows[range.start + s], query, low, domains)?;
        }
        for k in 0..depth {
            for s in 0..range.len() {
                for (&actual, &expected) in rows[range.start + s].path[low + k]
                    .iter()
                    .zip(&layer[(s >> k) ^ 1])
                {
                    b.connect(actual, expected);
                }
            }
            layer = layer
                .as_chunks::<2>()
                .0
                .iter()
                .map(|pair| {
                    let mut words = constants(b, domains.tags().1);
                    words.extend(&pair[0]);
                    words.extend(&pair[1]);
                    Ok(NativeBinaryEncoding::hash_words(b, ByteHash::Keccak256, &words)?.to_vec())
                })
                .collect::<Result<_>>()?;
        }
        for (&actual, &expected) in layer[0].iter().zip(&root) {
            b.connect(actual, expected);
        }
    }
    Ok(())
}

fn authenticate(
    b: &mut CircuitBuilder<F>,
    root: &[ExprId],
    row: &RowTargets,
    query: &Query,
    height: usize,
    domains: RowDomains,
) -> Result<()> {
    ensure!(
        height <= row.path.len() && row.path.len() == query.bits.len() && root.len() == 16,
        "wrong salted opening dimensions"
    );
    let mut words = constants(b, domains.tags().0);
    for value in row.values.iter().chain(&row.salts) {
        for &coefficient in value.coefficients() {
            words.extend(b.native_poly64_unchecked_words(coefficient, 4)?);
        }
    }
    let mut digest = NativeBinaryEncoding::hash_words(b, ByteHash::Keccak256, &words)?;
    for (&bit, sibling) in query.bits.iter().zip(&row.path).take(height) {
        b.assert_bool(bit);
        let mut bytes = constants(b, domains.tags().1);
        bytes.extend(
            digest
                .iter()
                .zip(sibling)
                .map(|(&d, &s)| b.select(bit, s, d)),
        );
        bytes.extend(
            digest
                .iter()
                .zip(sibling)
                .map(|(&d, &s)| b.select(bit, d, s)),
        );
        digest = NativeBinaryEncoding::hash_words(b, ByteHash::Keccak256, &bytes)?;
    }
    for (actual, &expected) in digest.into_iter().zip(root) {
        b.connect(actual, expected);
    }
    Ok(())
}

pub(in crate::binary::veil) fn field(b: &mut CircuitBuilder<F>) -> NativePoly192Target {
    let coefficients = b.alloc_private_input_array::<3>("stacked-field");
    b.native_poly192_from_coefficients(coefficients)
}

pub(in crate::binary::veil) fn constants(b: &mut CircuitBuilder<F>, bytes: &[u8]) -> Vec<ExprId> {
    assert!(bytes.len().is_multiple_of(2));
    bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|&v| b.define_const(F::new(u64::from(u16::from_le_bytes(v)))))
        .collect()
}

pub(in crate::binary::veil) fn circuit_powers(
    b: &mut CircuitBuilder<F>,
    value: &NativePoly192Target,
    count: usize,
) -> Vec<NativePoly192Target> {
    let mut power = b.native_poly192_constant([1, 0, 0]);
    (0..count)
        .map(|_| {
            let result = power.clone();
            power = b.native_poly192_mul(&power, value);
            result
        })
        .collect()
}

pub(in crate::binary::veil) fn circuit_dot(
    b: &mut CircuitBuilder<F>,
    left: &[NativePoly192Target],
    right: &[NativePoly192Target],
) -> Result<NativePoly192Target> {
    ensure!(left.len() == right.len(), "wrong circuit dot shape");
    let mut result = b.native_poly192_constant([0; 3]);
    for (a, b_value) in left.iter().zip(right) {
        let term = b.native_poly192_mul(a, b_value);
        result = b.native_poly192_add(&result, &term);
    }
    Ok(result)
}

#[cfg(test)]
mod tests;
