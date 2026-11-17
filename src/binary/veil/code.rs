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
        })
    }

    /// `padded` includes fresh independent randomness at *every* unused input
    /// position. This routine itself is deterministic and does not supply it.
    pub fn encode(&self, padded: &[E]) -> Result<Vec<E>> {
        ensure!(
            padded.len() == self.input_len,
            "incorrect padded input length"
        );
        let mut coefficients = padded.to_vec();
        self.input
            .transform_algebra::<E, true>(&mut coefficients, 1);
        coefficients.resize(self.codeword_len, E::ZERO);
        self.output
            .transform_algebra::<E, false>(&mut coefficients, 1);
        Ok(coefficients)
    }

    pub fn encode_product(&self, intermediate: &[E]) -> Result<Vec<E>> {
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

    pub fn generator_row(&self, position: usize) -> Result<Vec<F>> {
        let x = self.evaluation_point(position)?;
        // The Cantor-subspace vanishing polynomial has derivative one, also
        // after the isomorphism into Poly64's polynomial representation.
        let numerator = subspace_polynomial(self.input_len.ilog2() as usize, x);
        Ok((0..self.input_len)
            .map(|i| numerator * (x + domain_point::<F>(i)).inverse())
            .collect())
    }
}
