use anyhow::{Result, ensure};
use p3_security::SecurityAssumption;
use serde::{Deserialize, Serialize};

use super::code::BinaryCode;

/// Trusted parameters, never taken from a proof. The target applies to the
/// query-miss term only; it is NOT an end-to-end security certification.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Parameters {
    pub query_bits: usize,
    pub min_algebraic_bits: usize,
    pub log_inv_rate: usize,
    pub max_message_len: usize,
}

#[derive(Debug, Serialize)]
pub struct CodeDiagnostic {
    pub message_symbols: usize,
    pub randomized_dimension: usize,
    pub codeword_symbols: usize,
    pub opened_rows: usize,
    pub johnson_radius: f64,
    pub binding_radius: f64,
    pub query_miss_bits: f64,
    pub linear_combination_gap_bits: f64,
    pub product_combination_gap_bits: Option<f64>,
    pub retained_commitment_bytes: usize,
}

impl Default for Parameters {
    fn default() -> Self {
        Self {
            query_bits: 160,
            min_algebraic_bits: 144,
            log_inv_rate: 4,
            max_message_len: 1 << 21,
        }
    }
}

impl Parameters {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            (128..=192).contains(&self.query_bits),
            "query target must be at least 128 bits"
        );
        ensure!(
            (128..=160).contains(&self.min_algebraic_bits),
            "invalid inner algebraic floor"
        );
        ensure!(
            (2..=5).contains(&self.log_inv_rate),
            "unsupported code rate"
        );
        ensure!(
            (1..=1 << 21).contains(&self.max_message_len),
            "invalid message limit"
        );
        Ok(())
    }

    pub fn code(&self, message_len: usize, product: bool) -> Result<BinaryCode> {
        self.validate()?;
        ensure!(
            message_len <= self.max_message_len,
            "message exceeds trusted resource limit"
        );
        // The product has twice the dimension. Count ALL openings against its
        // lower rate, then reserve that many independent padding coordinates.
        let rate = self.log_inv_rate - usize::from(product);
        let queries = self.queries(rate);
        BinaryCode::new(message_len, queries, self.log_inv_rate)
    }

    /// VEIL's binding theorem also needs delta <= Delta/2. The WHIR
    /// Johnson query calculator alone does not satisfy that hypothesis.
    pub fn binding_radius(&self, log_inv_rate: usize) -> f64 {
        let johnson = 1.0 - 2.0f64.powf(SecurityAssumption::JohnsonBound.log_1_delta(log_inv_rate));
        let half_distance = (1.0 - 2.0f64.powi(-(log_inv_rate as i32))) / 2.0;
        johnson.min(half_distance)
    }

    fn queries(&self, log_inv_rate: usize) -> usize {
        let bits_per_query = -(1.0 - self.binding_radius(log_inv_rate)).log2();
        (self.query_bits as f64 / bits_per_query).ceil() as usize
    }

    /// Local coding diagnostics only. In particular the Hadamard, extraction,
    /// Fiat-Shamir, hash and composition terms are not covered by this report.
    pub fn diagnostic(
        &self,
        message_len: usize,
        columns: usize,
        product: bool,
    ) -> Result<CodeDiagnostic> {
        let code = self.code(message_len, product)?;
        let rate = self.log_inv_rate - usize::from(product);
        let degree = code.input_len.ilog2() as usize;
        let width = columns + 1 + usize::from(product);
        Ok(CodeDiagnostic {
            message_symbols: message_len,
            randomized_dimension: code.input_len,
            codeword_symbols: code.codeword_len,
            opened_rows: code.queries,
            johnson_radius: 1.0 - 2.0f64.powf(SecurityAssumption::JohnsonBound.log_1_delta(rate)),
            binding_radius: self.binding_radius(rate),
            query_miss_bits: -(code.queries as f64) * (1.0 - self.binding_radius(rate)).log2(),
            linear_combination_gap_bits: SecurityAssumption::JohnsonBound.prox_gaps_error(
                degree,
                self.log_inv_rate,
                192,
                columns + 1,
            ) - 1.0,
            // Separate proximity generator for the product code. Conditioning
            // on challenges outside {0,1} costs < 1 bit; charge a full bit.
            product_combination_gap_bits: product.then(|| {
                SecurityAssumption::JohnsonBound.prox_gaps_error(degree + 1, rate, 192, 2) - 1.0
            }),
            // Row data, two 192-bit salt columns, all binary-tree digests.
            // Excludes relation, padding, NTT scratch and allocator overhead.
            retained_commitment_bytes: code.codeword_len * (width + 2) * 24
                + (2 * code.codeword_len - 1) * 32,
        })
    }
}
