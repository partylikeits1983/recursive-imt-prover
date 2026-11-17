//! Linear checks on public, uniformly masked interpolation blends. A WHIR
//! commitment authenticates their novel-basis coefficients; the functional
//! checks both the original prefix dot product and the salted-oracle queries.
//!
//! The prefix weights must be derived by the trusted enclosing verifier from
//! its already authenticated statement/transcript. The inner VEIL verifier
//! does this for both product-link powers and affine mask checks. They are not
//! independently supplied prover data and need not be hashed a second time.
use anyhow::{Result, ensure};
use p3_field::PrimeCharacteristicRing;
use p3_multilinear_util::{point::Point, poly::Poly};

use super::{dot, powers};
use crate::binary::veil::{E, code::BinaryCode, transcript::Transcript, whir::BlendFunctional};

pub(in crate::binary::veil) struct Functional {
    pub code: BinaryCode,
    pub product: bool,
    pub prefix: Vec<E>,
    pub indices: Vec<usize>,
    pub beta: E,
}

impl Functional {
    pub fn new(
        code: &BinaryCode,
        product: bool,
        prefix: &[E],
        indices: &[usize],
        values: &[E],
        expected: E,
        transcript: &mut Transcript,
    ) -> Result<(Self, E)> {
        ensure!(
            indices.len() == code.queries && values.len() == indices.len(),
            "wrong blend query count"
        );
        transcript.fields(b"vector-functional-rows-v1", values);
        let beta = transcript.challenge(b"vector-functional-batch-v1")?;
        let sum = expected + beta * dot(values, &powers(beta, values.len()));
        Ok((
            Self {
                code: code.clone(),
                product,
                prefix: prefix.to_vec(),
                indices: indices.to_vec(),
                beta,
            },
            sum,
        ))
    }
}

impl BlendFunctional for Functional {
    fn length(&self) -> usize {
        self.code.input_len << usize::from(self.product)
    }

    fn dense(&self) -> Result<Vec<E>> {
        let mut weights = self.code.blend_weights(&self.prefix, self.product)?;
        let mut power = self.beta;
        for &index in &self.indices {
            let mut row = vec![power];
            for factor in self.code.blend_factors(index, self.product)? {
                row = row.iter().flat_map(|&v| [v, v * factor]).collect();
            }
            for (weight, value) in weights.iter_mut().zip(row) {
                *weight += value;
            }
            power *= self.beta;
        }
        Ok(weights)
    }

    fn evaluate(&self, point: &[E]) -> Result<E> {
        ensure!(
            point.len() == self.length().ilog2() as usize,
            "wrong vector functional arity"
        );
        let weights = self.code.blend_weights(&self.prefix, self.product)?;
        let mut sum =
            Poly::new(weights).eval_ext::<crate::binary::veil::F>(&Point::new(point.to_vec()));
        let mut power = self.beta;
        for &index in &self.indices {
            let value: E = self
                .code
                .blend_factors(index, self.product)?
                .into_iter()
                .zip(point)
                .map(|(factor, &coordinate)| E::ONE + coordinate + coordinate * factor)
                .product();
            sum += power * value;
            power *= self.beta;
        }
        Ok(sum)
    }

    fn bind(&self, transcript: &mut Transcript) -> Result<()> {
        transcript.integers(
            b"vector-coefficient-functional-v1",
            &[
                self.code.message_len,
                self.code.input_len,
                self.code.codeword_len,
                self.code.queries,
                usize::from(self.product),
            ],
        );
        transcript.integers(b"vector-functional-indices", &self.indices);
        transcript.fields(b"vector-functional-beta", &[self.beta]);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use p3_field::PrimeCharacteristicRing;
    use rand::{RngExt, SeedableRng, rngs::StdRng};

    use super::{E, Functional, dot};
    use crate::binary::veil::{
        parameters::Parameters, transcript::Transcript, whir::BlendFunctional,
    };

    #[test]
    fn transposed_ntt_functional_matches_original_interpolation_checks() -> Result<()> {
        let mut rng = StdRng::seed_from_u64(0x6e74742d7472616e);
        let parameters = Parameters::default();
        for product in [false, true] {
            let code = parameters.code(13, product)?;
            let length = code.input_len << usize::from(product);
            let values: Vec<E> = (0..length).map(|_| rng.random()).collect();
            let prefix: Vec<E> = (0..code.message_len).map(|_| rng.random()).collect();
            let coefficients = code.blend_coefficients(&values, product)?;
            assert_eq!(
                dot(&prefix, &values[..prefix.len()]),
                dot(&coefficients, &code.blend_weights(&prefix, product)?)
            );
            let encoded = if product {
                code.encode_product(&values)?
            } else {
                code.encode(&values)?
            };
            let mut transcript = Transcript::new(b"transpose-ntt-functional");
            let indices = transcript.indices(code.queries, code.codeword_len);
            let queried: Vec<_> = indices.iter().map(|&i| encoded[i]).collect();
            let expected = dot(&prefix, &values[..prefix.len()]);
            let (functional, sum) = Functional::new(
                &code,
                product,
                &prefix,
                &indices,
                &queried,
                expected,
                &mut transcript,
            )?;
            assert_eq!(dot(&coefficients, &functional.dense()?), sum);
            let point: Vec<E> = (0..length.ilog2()).map(|_| rng.random()).collect();
            assert_eq!(
                functional.evaluate(&point)?,
                functional.dense()?.evaluate(&point)?
            );
            // The functional has genuine dependence on the authenticated row.
            let mut changed = queried;
            changed[0] += E::ONE;
            let (_, bad) = Functional::new(
                &code,
                product,
                &prefix,
                &indices,
                &changed,
                expected,
                &mut Transcript::new(b"transpose-ntt-functional"),
            )?;
            assert_ne!(bad, sum);
        }
        Ok(())
    }
}
