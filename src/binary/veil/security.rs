//! Conditional inner-IOP budget; excludes hashing, Fiat–Shamir and recursion.
use anyhow::{Result, ensure};
use serde::Serialize;

use super::{constraints::Relation, parameters::Parameters, whir::security_budget};
use crate::binary::security::union_bits;

#[derive(Debug, Serialize)]
pub struct InnerSecurityDiagnostic {
    pub model: &'static str,
    pub terms: Vec<(&'static str, f64)>,
    pub conditional_interactive_bits: f64,
    pub end_to_end_128_established: bool,
}

impl Relation {
    pub fn security_diagnostic(&self, parameters: &Parameters) -> Result<InnerSecurityDiagnostic> {
        let masks = parameters.diagnostic(self.variables + 6, 1, false)?;
        let products = parameters.diagnostic(self.products.len() + 2, 3, true)?;
        let products_len = (self.products.len() + 2) as f64;
        let linear_len = (self.linear.len() + self.public_wires.len() + 3) as f64;
        let mask_code = parameters.code(self.variables + 6, false)?;
        let product_code = parameters.code(self.products.len() + 2, true)?;
        let terms = vec![
            ("mask-code-proximity", masks.linear_combination_gap_bits),
            ("mask-code-query-miss", masks.query_miss_bits),
            (
                "product-base-code-proximity",
                products.linear_combination_gap_bits,
            ),
            (
                "product-square-code-proximity",
                products.product_combination_gap_bits.unwrap(),
            ),
            ("product-code-query-miss", products.query_miss_bits),
            ("hadamard-residual-batching", 191.0 - products_len.log2()),
            (
                "three-product-vector-links",
                191.0 - (3.0 * products_len).log2(),
            ),
            ("affine-and-public-batching", 191.0 - linear_len.log2()),
            (
                "mask-blend-whir",
                security_budget(mask_code.input_len, parameters)?.conditional_bits,
            ),
            (
                "product-dot-blend-whir",
                security_budget(product_code.input_len, parameters)?.conditional_bits,
            ),
            (
                "product-residual-blend-whir",
                security_budget(2 * product_code.input_len, parameters)?.conditional_bits,
            ),
            (
                "mask-functional-batching",
                191.0 - (mask_code.queries as f64).log2(),
            ),
            (
                "two-product-functional-batches",
                191.0 - (2.0 * product_code.queries as f64).log2(),
            ),
        ];
        Ok(InnerSecurityDiagnostic {
            model: "conditional inner IOP: binding radius capped at half distance; Johnson proximity bounds; uniform challenges",
            conditional_interactive_bits: union_bits(
                &terms.iter().map(|t| t.1).collect::<Vec<_>>(),
            )?,
            terms,
            end_to_end_128_established: false,
        })
    }

    pub(super) fn require_algebraic_budget(&self, parameters: &Parameters) -> Result<()> {
        let report = self.security_diagnostic(parameters)?;
        ensure!(
            report.conditional_interactive_bits >= parameters.min_algebraic_bits as f64,
            "inner algebraic model is {:.3} bits, below required {} bits",
            report.conditional_interactive_bits,
            parameters.min_algebraic_bits
        );
        Ok(())
    }
}
