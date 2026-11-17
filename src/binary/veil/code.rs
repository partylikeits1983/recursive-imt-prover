//! Interpolation RS encoding on disjoint additive domains, using Plonky3 NTTs.
//!
//! The generator is a diagonally scaled Cauchy matrix. Any t distinct queried
//! coordinates have full rank on any t padding coordinates. This is the local
//! query-privacy property needed by VEIL; it is not a full protocol ZK theorem.

use anyhow::{Result, ensure};
use p3_binary_dft::{BasisNtt, domain_point, subspace_polynomial};
use p3_binary_field::TowerLevel;
use p3_field::{Field, PrimeCharacteristicRing};

use super::{E, F};

#[derive(Clone, Debug)]
pub struct BinaryCode {
    pub message_len: usize,
    pub queries: usize,
    pub input_len: usize,
    pub codeword_len: usize,
    input: BasisNtt<F>,
    output: BasisNtt<F>,
    product: BasisNtt<F>,
    coefficients: bool,
}

impl BinaryCode {
    pub fn new(message_len: usize, queries: usize, log_inv_rate: usize) -> Result<Self> {
        ensure!(
            message_len > 0 && queries > 0,
            "empty message or query budget"
        );
        ensure!((2..=5).contains(&log_inv_rate), "unsupported redundancy");
        let input_len = message_len
            .checked_add(queries)
            .and_then(usize::checked_next_power_of_two)
            .ok_or_else(|| anyhow::anyhow!("encoding length overflow"))?;
        let log_input = input_len.ilog2() as usize;
        let log_output = log_input + log_inv_rate;
        // Bound allocation before constructing plans or shifting a word.
        ensure!(log_output <= 24, "experimental encoding exceeds 2^24 cells");
        let basis: Vec<_> = (0..log_output).map(F::cantor_basis).collect();
        Ok(Self {
            message_len,
            queries,
            input_len,
            codeword_len: 1 << log_output,
            input: BasisNtt::new(&basis[..log_input], F::ZERO),
            output: BasisNtt::new(&basis, F::cantor_basis(log_output)),
            product: BasisNtt::new(&basis[..log_input + 1], F::ZERO),
            coefficients: false,
        })
    }

    /// Oracle-only encoding. Random low-degree coefficients precede the final
    /// aligned message block. Any q distinct evaluations have full rank on the
    /// first q coefficients, since novel polynomials have degrees 0..q-1.
    /// This encoding must not be used for the Hadamard product argument.
    pub fn coefficients(message_len: usize, queries: usize, log_inv_rate: usize) -> Result<Self> {
        ensure!(
            message_len.is_power_of_two(),
            "coefficient message must be a power of two"
        );
        let mut code = Self::new(message_len, queries, log_inv_rate)?;
        code.coefficients = true;
        Ok(code)
    }

    pub fn message_offset(&self) -> usize {
        if self.coefficients {
            self.input_len - self.message_len
        } else {
            0
        }
    }

    pub(super) fn is_interpolation(&self) -> bool {
        !self.coefficients
    }

    /// Factors of the novel-basis generator, in Prefix/MSB variable order.
    pub(super) fn coefficient_factors(&self, position: usize) -> Result<Vec<F>> {
        ensure!(self.coefficients, "expected coefficient encoding");
        let x = self.evaluation_point(position)?;
        Ok((0..self.input_len.ilog2() as usize)
            .rev()
            .map(|j| subspace_polynomial(j, x))
            .collect())
    }

    /// `padded` includes fresh independent randomness at *every* unused input
    /// position. This routine itself is deterministic and does not supply it.
    pub fn encode(&self, padded: &[E]) -> Result<Vec<E>> {
        ensure!(
            padded.len() == self.input_len,
            "incorrect padded input length"
        );
        let mut coefficients = padded.to_vec();
        if !self.coefficients {
            self.input
                .transform_algebra::<E, true>(&mut coefficients, 1);
        }
        coefficients.resize(self.codeword_len, E::ZERO);
        self.output
            .transform_algebra::<E, false>(&mut coefficients, 1);
        Ok(coefficients)
    }

    pub fn encode_product(&self, intermediate: &[E]) -> Result<Vec<E>> {
        ensure!(!self.coefficients, "coefficient code has no Hadamard API");
        ensure!(
            intermediate.len() == 2 * self.input_len,
            "incorrect product length"
        );
        let mut coefficients = intermediate.to_vec();
        self.product
            .transform_algebra::<E, true>(&mut coefficients, 1);
        coefficients.resize(self.codeword_len, E::ZERO);
        self.output
            .transform_algebra::<E, false>(&mut coefficients, 1);
        Ok(coefficients)
    }

    /// Extend a base-code message to the product-code interpolation domain.
    pub fn to_product(&self, padded: &[E]) -> Result<Vec<E>> {
        ensure!(!self.coefficients, "coefficient code has no Hadamard API");
        ensure!(
            padded.len() == self.input_len,
            "incorrect padded input length"
        );
        let mut coefficients = padded.to_vec();
        self.input
            .transform_algebra::<E, true>(&mut coefficients, 1);
        coefficients.resize(2 * self.input_len, E::ZERO);
        self.product
            .transform_algebra::<E, false>(&mut coefficients, 1);
        Ok(coefficients)
    }

    pub fn evaluation_point(&self, position: usize) -> Result<F> {
        ensure!(position < self.codeword_len, "query outside codeword");
        Ok(self.output.shift() + domain_point::<F>(position))
    }

    /// Convert interpolation values to the novel-basis coefficients committed
    /// by the compact public-blend PCS. This does not process private columns.
    pub(super) fn blend_coefficients(&self, values: &[E], product: bool) -> Result<Vec<E>> {
        let length = self.input_len << usize::from(product);
        ensure!(
            self.is_interpolation() && values.len() == length,
            "wrong interpolation blend shape"
        );
        let mut values = values.to_vec();
        self.blend_plan(product)
            .transform_algebra::<E, true>(&mut values, 1);
        Ok(values)
    }

    pub(super) fn blend_plan(&self, product: bool) -> &BasisNtt<F> {
        if product { &self.product } else { &self.input }
    }

    /// Transpose of the forward additive NTT: a dot product on interpolation
    /// values becomes a dot product on novel-basis coefficients.
    pub(super) fn blend_weights(&self, weights: &[E], product: bool) -> Result<Vec<E>> {
        let length = self.input_len << usize::from(product);
        ensure!(
            self.is_interpolation() && weights.len() == self.message_len,
            "wrong interpolation weights"
        );
        let mut values = weights.to_vec();
        values.resize(length, E::ZERO);
        for layer in (0..length.ilog2() as usize).rev() {
            let size = length >> layer;
            for (block, values) in values.chunks_exact_mut(size).enumerate() {
                let (lo, hi) = values.split_at_mut(size / 2);
                let twiddle = self.blend_plan(product).twiddle(layer, block);
                for (a, b) in lo.iter_mut().zip(hi) {
                    *a += *b;
                    *b += *a * twiddle;
                }
            }
        }
        Ok(values)
    }

    pub(super) fn blend_factors(&self, position: usize, product: bool) -> Result<Vec<F>> {
        let x = self.evaluation_point(position)?;
        let variables = self.input_len.ilog2() as usize + usize::from(product);
        Ok((0..variables)
            .rev()
            .map(|j| subspace_polynomial(j, x))
            .collect())
    }

    pub fn generator_row(&self, position: usize) -> Result<Vec<F>> {
        if self.coefficients {
            let mut row = vec![F::ONE];
            for factor in self.coefficient_factors(position)? {
                row = row.iter().flat_map(|&v| [v, v * factor]).collect();
            }
            return Ok(row);
        }
        let x = self.evaluation_point(position)?;
        // The Cantor-subspace vanishing polynomial has derivative one, also
        // after the isomorphism into Poly64's polynomial representation.
        let numerator = subspace_polynomial(self.input_len.ilog2() as usize, x);
        Ok((0..self.input_len)
            .map(|i| numerator * (x + domain_point::<F>(i)).inverse())
            .collect())
    }
}
