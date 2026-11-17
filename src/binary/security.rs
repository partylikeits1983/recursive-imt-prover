//! Keep uniform-challenge error probabilities separate from hash work factors.
//! These diagnostics do not establish Fiat–Shamir knowledge soundness or ZK.
use super::MAX_CHILDREN;

use anyhow::{Result, ensure};
use p3_multi_stark::security::MultiStarkSecurityReport;
use serde::{Deserialize, Serialize};

const HASH_TERM: &str = "commitment-and-transcript-collision";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AlgebraicAssessment {
    pub uniform_challenge_bits: f64,
    pub hash_collision_work_bits: f64,
    pub upstream_combined_bits: f64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BatchAssessment {
    pub children: usize,
    pub uniform_challenge_union_bits: f64,
    pub hash_collision_work_bits: f64,
    pub meets_algebraic_128_budget: bool,
    pub child_zk: bool,
    pub end_to_end_128_established: bool,
}

impl AlgebraicAssessment {
    pub fn from_upstream(report: &MultiStarkSecurityReport) -> Result<Self> {
        ensure!(
            report.unassessed_components().is_empty(),
            "unassessed upstream security components"
        );
        let hash: Vec<_> = report
            .terms()
            .iter()
            .filter(|t| t.label == HASH_TERM)
            .collect();
        ensure!(hash.len() == 1, "missing or ambiguous hash collision cap");
        let algebraic = report
            .terms()
            .iter()
            .filter(|t| t.label != HASH_TERM)
            .map(|t| t.bits.bits())
            .collect::<Vec<_>>();
        let result = Self {
            uniform_challenge_bits: union_bits(&algebraic)?,
            hash_collision_work_bits: hash[0].bits.bits(),
            upstream_combined_bits: report
                .security_bits()
                .ok_or_else(|| anyhow::anyhow!("missing upstream security estimate"))?,
        };
        ensure!(
            result.hash_collision_work_bits.is_finite(),
            "invalid hash collision cap"
        );
        Ok(result)
    }

    pub fn require_algebraic(&self, bits: usize) -> Result<()> {
        ensure!(
            self.uniform_challenge_bits >= bits as f64,
            "uniform-challenge algebraic model is {:.3} bits, below required {bits} bits",
            self.uniform_challenge_bits
        );
        Ok(())
    }
}

impl BatchAssessment {
    pub fn new(
        child: &AlgebraicAssessment,
        outer: &AlgebraicAssessment,
        count: usize,
    ) -> Result<Self> {
        ensure!(
            (1..=MAX_CHILDREN).contains(&count),
            "unsupported security composition count"
        );
        let bits = union_bits(&[
            child.uniform_challenge_bits - (count as f64).log2(),
            outer.uniform_challenge_bits,
        ])?;
        Ok(Self {
            children: count,
            uniform_challenge_union_bits: bits,
            hash_collision_work_bits: child
                .hash_collision_work_bits
                .min(outer.hash_collision_work_bits),
            meets_algebraic_128_budget: bits >= 128.0,
            // This module assesses the native non-hiding format. It cannot certify
            // a VEIL child or supply the missing recursive composition theorem.
            child_zk: false,
            end_to_end_128_established: false,
        })
    }
}

/// -log2(sum(2^-bits)); stable even when the terms have very different sizes.
pub fn union_bits(terms: &[f64]) -> Result<f64> {
    ensure!(!terms.is_empty(), "empty soundness ledger");
    ensure!(
        terms.iter().all(|x| x.is_finite() && *x >= 0.0),
        "invalid soundness term"
    );
    let minimum = terms.iter().copied().fold(f64::INFINITY, f64::min);
    Ok(minimum
        - terms
            .iter()
            .map(|x| 2.0f64.powf(minimum - x))
            .sum::<f64>()
            .log2())
}
