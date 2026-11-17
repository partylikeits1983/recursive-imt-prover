//! Proven Johnson-regime analysis of the actual hiding child AIR.
use crate::legacy::client::LeafVerifier;
use crate::legacy::config::{E, EXTENSION_DEGREE, F};
use anyhow::{Context, Result, bail};
use p3_air::symbolic::AirLayout;
use p3_field::coset::TwoAdicMultiplicativeCoset;
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_security::fri::FriRegime;
use p3_security::grinding::GrindingSites;
use p3_security::proximity::alpha_ldr_m;
use p3_security::report::Regime;
use p3_security::shape::{InstanceShape, StarkAirParams};
use p3_security::stark::proven_security_report;
use p3_uni_stark::{OpeningShape, StarkSecurityParams};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SecurityTerm {
    pub name: String,
    pub bits: f64,
}

/// Per-child round-by-round model, not a bound for recursive composition.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChildSecurity {
    pub model: String,
    pub committed_degree_bits: usize,
    pub challenge_field_bits: usize,
    pub collision_resistance_bits: usize,
    pub constraints: usize,
    pub quotient_chunks: usize,
    pub batched_functions: usize,
    pub johnson_radius: f64,
    pub analyzed_radius: f64,
    pub proximity_m: usize,
    pub round_by_round_bits: f64,
    pub binding_term: String,
    pub terms: Vec<SecurityTerm>,
}

impl LeafVerifier {
    pub fn johnson_security(&self) -> Result<ChildSecurity> {
        let descriptor = self.profile.descriptor(true);
        let fri = FriRegime {
            log_blowup: descriptor.log_blowup() as usize,
            num_queries: descriptor.num_queries() as usize,
            log_final_poly_len: descriptor.log_final_poly_len() as usize,
            max_log_arity: descriptor.max_log_arity() as usize,
            commit_pow_bits: descriptor.commit_pow_bits() as usize,
            query_pow_bits: descriptor.query_pow_bits() as usize,
        };
        let base_bits = f64::from(F::ORDER_U32).log2();
        let field_bits = (base_bits * EXTENSION_DEGREE as f64).floor() as usize;
        // Poseidon2 commitments contain eight base-field elements; birthday cap.
        let collision_bits = (base_bits * 8.0 / 2.0).floor() as usize;
        let trace_bits = self.air.height(self.profile).ilog2() as usize;
        let domain = TwoAdicMultiplicativeCoset::<F>::new(F::ONE, trace_bits)
            .context("invalid child trace domain")?;
        // This AIR has no lookup/permutation columns. Only FRI query grinding
        // is enabled; it is already included in `fri`, never credited twice.
        let params = StarkSecurityParams::from_air::<F, E, _>(
            fri,
            &self.air,
            AirLayout::from_air::<F>(&self.air),
            domain,
            field_bits,
            collision_bits,
            2,
            OpeningShape::hiding(descriptor.num_random_codewords() as usize),
            GrindingSites::NONE,
        );
        let shape = StarkAirParams {
            num_constraints: params.num_constraints,
            max_constraint_degree: params.air_max_constraint_degree,
            num_quotient_chunks: params.num_quotient_chunks,
            max_combo: params.max_combo,
        };
        let instance = InstanceShape {
            // Hiding doubles the committed polynomial size.
            log_trace_length: trace_bits + 1,
            modulus_bits: field_bits,
            collision_resistance: collision_bits,
            num_batched_functions: params.num_batched_functions,
        };
        let report = proven_security_report(&fri, &shape, &instance, &[], &params.grinding);
        let johnson = report.ldr.context("no valid Johnson regime for child")?;
        let Regime::ListDecoding { m } = johnson.regime else {
            bail!("expected proven Johnson list-decoding analysis");
        };
        Ok(ChildSecurity {
            model: "p3-security proven Johnson / DKT26 (2026/2056), order-zero MCA".into(),
            committed_degree_bits: instance.log_trace_length,
            challenge_field_bits: field_bits,
            collision_resistance_bits: collision_bits,
            constraints: shape.num_constraints,
            quotient_chunks: shape.num_quotient_chunks,
            batched_functions: instance.num_batched_functions,
            johnson_radius: 1.0 - 2.0_f64.powf(-(fri.log_blowup as f64) / 2.0),
            analyzed_radius: 1.0 - alpha_ldr_m(fri.log_blowup, m),
            proximity_m: m,
            round_by_round_bits: johnson.security_bits(),
            binding_term: johnson.binding().label.into(),
            terms: johnson
                .terms()
                .iter()
                .map(|term| SecurityTerm {
                    name: term.label.into(),
                    bits: term.bits.bits(),
                })
                .collect(),
        })
    }
}
