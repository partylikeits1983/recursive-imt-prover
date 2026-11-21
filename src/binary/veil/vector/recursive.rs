//! Recursive verification of the VEIL vector argument. Only serialized proof
//! data is imported; neither hidden vectors nor their randomness are inputs.
use anyhow::{Result, ensure};
use p3_circuit::{CircuitBuilder, ExprId, ops::NativePoly192Target};
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};

use super::{VectorProof, functional::Functional, powers};
use crate::binary::veil::{
    E, F,
    code::BinaryCode,
    parameters::Parameters,
    stacked_oracle::recursive::opening::{
        RowTargets, authenticate_batch, circuit_dot, circuit_powers, field,
    },
    transcript::Transcript,
    whir::recursive::{
        blend::{BlendTargets, PreparedBlend},
        transcript::CircuitTranscript,
    },
};
use functional::FunctionalTarget;

mod functional;

pub(in crate::binary::veil) struct PreparedVector {
    code: BinaryCode,
    columns: usize,
    dot: PreparedBlend,
    product: Option<PreparedBlend>,
}

pub(in crate::binary::veil) struct VectorTargets {
    pub root: [ExprId; 32],
    pub claims: Vec<NativePoly192Target>,
    mask_dot: NativePoly192Target,
    product: Option<ProductTargets>,
    dot_root: [ExprId; 32],
    rows: Vec<RowTargets>,
    dot_opening: BlendTargets,
    product_opening: Option<BlendTargets>,
}

struct ProductTargets {
    gamma: NativePoly192Target,
    root: [ExprId; 32],
}

impl PreparedVector {
    pub fn new(
        code: BinaryCode,
        columns: usize,
        product: bool,
        parameters: &Parameters,
    ) -> Result<Self> {
        ensure!(
            columns > 0 && (!product || columns == 3),
            "wrong vector columns"
        );
        Ok(Self {
            dot: PreparedBlend::new(code.input_len, parameters)?,
            product: product
                .then(|| PreparedBlend::new(2 * code.input_len, parameters))
                .transpose()?,
            code,
            columns,
        })
    }

    pub fn allocate(&self, b: &mut CircuitBuilder<F>) -> Result<VectorTargets> {
        let root = b.alloc_private_input_array::<32>("vector-root");
        let claims = (0..self.columns).map(|_| field(b)).collect();
        let mask_dot = field(b);
        let product = self.product.as_ref().map(|_| ProductTargets {
            gamma: field(b),
            root: b.alloc_private_input_array::<32>("product-blend-root"),
        });
        let dot_root = b.alloc_private_input_array::<32>("dot-blend-root");
        let width = self.columns + 1 + usize::from(self.product.is_some());
        let rows = (0..self.code.queries)
            .map(|_| RowTargets {
                values: (0..width).map(|_| field(b)).collect(),
                salts: std::array::from_fn(|_| field(b)),
                path: (0..self.code.codeword_len.ilog2())
                    .map(|_| b.alloc_private_input_array::<16>("vector-path"))
                    .collect(),
            })
            .collect();
        let dot_opening = self.dot.allocate(b)?;
        let product_opening = self.product.as_ref().map(|p| p.allocate(b)).transpose()?;
        Ok(VectorTargets {
            root,
            claims,
            mask_dot,
            product,
            dot_root,
            rows,
            dot_opening,
            product_opening,
        })
    }

    pub fn import(
        &self,
        proof: &VectorProof,
        weights: &[E],
        parameters: &Parameters,
        mut transcript: Transcript,
    ) -> Result<Vec<F>> {
        ensure!(
            proof.dot.claims.len() == self.columns
                && proof.product.is_some() == self.product.is_some(),
            "wrong vector proof shape"
        );
        ensure!(
            weights.len() == self.code.message_len && proof.openings.len() == self.code.queries,
            "wrong vector query shape"
        );
        let mut private: Vec<_> = proof
            .root
            .into_iter()
            .map(|v| F::new(u64::from(v)))
            .collect();
        for value in proof.dot.claims.iter().chain([&proof.dot.mask_dot]) {
            private.extend_from_slice(value.as_basis_coefficients_slice());
        }
        transcript.bytes(b"vectors", &proof.root);
        let product = if let Some(product) = &proof.product {
            private.extend_from_slice(product.gamma.as_basis_coefficients_slice());
            private.extend(product.root.into_iter().map(|v| F::new(u64::from(v))));
            let z = transcript.challenge(b"product-test")?;
            transcript.fields(b"product-gamma", &[product.gamma]);
            let rho = transcript.challenge(b"product-mask")?;
            transcript.bytes(b"product-blend-commitment-v1", &product.root);
            Some((rho, powers(z, weights.len())))
        } else {
            None
        };
        transcript.fields(b"dot-claims", &proof.dot.claims);
        transcript.fields(b"dot-mask", &[proof.dot.mask_dot]);
        let rho = transcript.challenge(b"dot-blend")?;
        let expected = proof
            .dot
            .claims
            .iter()
            .rev()
            .fold(proof.dot.mask_dot, |sum, &v| v + rho * sum);
        private.extend(proof.dot.root.into_iter().map(|v| F::new(u64::from(v))));
        transcript.bytes(b"dot-blend-commitment-v1", &proof.dot.root);
        let indices = transcript.indices(self.code.queries, self.code.codeword_len);
        let width = self.columns + 1 + usize::from(self.product.is_some());
        for opening in &proof.openings {
            ensure!(
                opening.rows.len() == 1
                    && opening.rows[0].len() == width
                    && opening.path.0.len() == 1
                    && opening.path.0[0].len() == 2
                    && opening.path.1.len() == self.code.codeword_len.ilog2() as usize,
                "wrong vector authentication shape"
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
                        .map(|&v| F::new(u64::from(u16::from_le_bytes(v)))),
                );
            }
        }
        let values: Vec<_> = proof
            .openings
            .iter()
            .map(|o| {
                o.rows[0][..self.columns + 1]
                    .iter()
                    .rev()
                    .fold(E::ZERO, |sum, &v| v + rho * sum)
            })
            .collect();
        let (functional, sum) = Functional::new(
            &self.code,
            false,
            weights,
            &indices,
            &values,
            expected,
            &mut transcript,
        )?;
        private.extend(self.dot.import(
            &proof.dot.opening,
            &proof.dot.root,
            &functional,
            sum,
            transcript.clone(),
        )?);
        // Restore the public continuation for importing the next actual PCS.
        proof.dot.opening.verify(
            &proof.dot.root,
            &functional,
            sum,
            parameters,
            &mut transcript,
        )?;
        if let (Some(prepared), Some(proof_product), Some((rho, prefix))) =
            (&self.product, &proof.product, product)
        {
            let values: Vec<_> = proof
                .openings
                .iter()
                .map(|o| {
                    let r = &o.rows[0];
                    r[0] * r[1] + r[2] + rho * r[4]
                })
                .collect();
            let (functional, sum) = Functional::new(
                &self.code,
                true,
                &prefix,
                &indices,
                &values,
                rho * proof_product.gamma,
                &mut transcript,
            )?;
            private.extend(prepared.import(
                &proof_product.opening,
                &proof_product.root,
                &functional,
                sum,
                transcript,
            )?);
        }
        Ok(private)
    }

    pub fn verify(
        &self,
        b: &mut CircuitBuilder<F>,
        proof: &VectorTargets,
        weights: &[NativePoly192Target],
        mut transcript: CircuitTranscript,
    ) -> Result<CircuitTranscript> {
        ensure!(
            weights.len() == self.code.message_len
                && proof.claims.len() == self.columns
                && proof.product.is_some() == self.product.is_some(),
            "wrong vector circuit shape"
        );
        transcript.bytes(b, b"vectors", &proof.root)?;
        let product = if let Some(product) = &proof.product {
            let z = transcript.challenge(b, b"product-test")?;
            transcript.fields(b, b"product-gamma", std::slice::from_ref(&product.gamma))?;
            let rho = transcript.challenge(b, b"product-mask")?;
            transcript.bytes(b, b"product-blend-commitment-v1", &product.root)?;
            Some((rho, circuit_powers(b, &z, weights.len())))
        } else {
            None
        };
        transcript.fields(b, b"dot-claims", &proof.claims)?;
        transcript.fields(b, b"dot-mask", std::slice::from_ref(&proof.mask_dot))?;
        let rho = transcript.challenge(b, b"dot-blend")?;
        let factors = circuit_powers(b, &rho, self.columns + 1);
        let mut claims = proof.claims.clone();
        claims.push(proof.mask_dot.clone());
        let expected = circuit_dot(b, &claims, &factors)?;
        transcript.bytes(b, b"dot-blend-commitment-v1", &proof.dot_root)?;
        let queries = transcript.indices(b, self.code.queries, self.code.codeword_len)?;
        let width = self.columns + 1 + usize::from(self.product.is_some());
        let mut values = Vec::new();
        authenticate_batch(
            b,
            &proof.root,
            &proof.rows,
            &queries,
            width,
            crate::binary::veil::hash::RowDomains::Original,
        )?;
        for row in &proof.rows {
            values.push(circuit_dot(b, &row.values[..self.columns + 1], &factors)?);
        }
        let (beta, sum) = batch(b, &values, &expected, &mut transcript)?;
        let functional = FunctionalTarget {
            code: &self.code,
            product: false,
            prefix: weights,
            queries: &queries,
            beta,
        };
        transcript = self.dot.verify(
            b,
            &proof.dot_root,
            &functional,
            &sum,
            &proof.dot_opening,
            transcript,
        )?;
        if let (Some(prepared), Some(product), Some((rho, prefix)), Some(opening)) = (
            &self.product,
            &proof.product,
            product,
            &proof.product_opening,
        ) {
            let values: Vec<_> = proof
                .rows
                .iter()
                .map(|row| {
                    let r = &row.values;
                    let ab = b.native_poly192_mul(&r[0], &r[1]);
                    let c = b.native_poly192_add(&ab, &r[2]);
                    let mask = b.native_poly192_mul(&rho, &r[4]);
                    b.native_poly192_add(&c, &mask)
                })
                .collect();
            let expected = b.native_poly192_mul(&rho, &product.gamma);
            let (beta, sum) = batch(b, &values, &expected, &mut transcript)?;
            let functional = FunctionalTarget {
                code: &self.code,
                product: true,
                prefix: &prefix,
                queries: &queries,
                beta,
            };
            transcript =
                prepared.verify(b, &product.root, &functional, &sum, opening, transcript)?;
        }
        Ok(transcript)
    }
}

fn batch(
    b: &mut CircuitBuilder<F>,
    values: &[NativePoly192Target],
    expected: &NativePoly192Target,
    transcript: &mut CircuitTranscript,
) -> Result<(NativePoly192Target, NativePoly192Target)> {
    transcript.fields(b, b"vector-functional-rows-v1", values)?;
    let beta = transcript.challenge(b, b"vector-functional-batch-v1")?;
    let powers = circuit_powers(b, &beta, values.len());
    let sum = circuit_dot(b, values, &powers)?;
    let sum = b.native_poly192_mul(&beta, &sum);
    Ok((beta, b.native_poly192_add(expected, &sum)))
}

#[cfg(test)]
mod tests;
