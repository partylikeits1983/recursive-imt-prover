use clap::Args;
use recursive_imt_prover::legacy::scenario::ScenarioConfig;
use recursive_imt_prover::legacy::scenario::TreeHistory;
use recursive_imt_prover::legacy::{
    AggregationMetrics, ChildSecurity, ChildTimings, EXTENSION_DEGREE, OUTER_PROTOCOL, Profile,
};
use serde::{Deserialize, Serialize};

#[derive(Args)]
pub(crate) struct TreeOptions {
    #[arg(long, default_value_t = 32)]
    pub depth: u8,
    #[arg(long, default_value_t = 128)]
    pub prefill: usize,
    #[arg(long, default_value_t = 8)]
    pub append_after: usize,
    /// Give each user a distinct later root from the same tree.
    #[arg(long)]
    pub historical: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Manifest {
    pub version: u32,
    pub relation: String,
    pub count: usize,
    pub depth: u8,
    pub profile: Profile,
    pub outer_protocol: String,
}

#[derive(Deserialize, Serialize)]
pub(super) struct FriMetrics {
    pub extension_degree: usize,
    pub log_blowup: u32,
    pub num_queries: u32,
    pub query_pow_bits: u32,
    pub commit_pow_bits: u32,
    pub batch_pow_bits: u32,
    pub max_log_arity: u32,
    pub log_final_poly_len: u32,
    pub cap_height: u32,
}

#[derive(Deserialize, Serialize)]
pub(super) struct WhirMetrics {
    pub protocol: String,
    pub security_regime: String,
    pub security_target_per_term: u32,
    pub maximum_pow_bits: u32,
    pub starting_log_inv_rate: u32,
    pub folding_factor: u32,
}

#[derive(Deserialize, Serialize)]
pub(super) struct SetupMetrics {
    pub profile: Profile,
    pub count: usize,
    pub depth: u8,
    pub hiding_min_height: usize,
    pub rayon_threads: usize,
    pub leaf_prepare_ms: f64,
    pub calibration_prove_ms: f64,
    pub aggregation: AggregationMetrics,
    pub total_ms: f64,
    pub fri: FriMetrics,
    pub outer: WhirMetrics,
    pub child_security: ChildSecurity,
}

#[derive(Deserialize, Serialize)]
pub(super) struct ClientMetrics {
    pub prepare_ms: f64,
    #[serde(flatten)]
    pub timings: ChildTimings,
    pub proof_bytes: usize,
    pub profile: Profile,
}

#[derive(Deserialize, Serialize)]
pub(super) struct BatchMetrics {
    pub profile: Profile,
    pub count: usize,
    pub children_zero_knowledge: bool,
    pub outer_zero_knowledge: bool,
    pub outer: WhirMetrics,
    pub rayon_threads: usize,
    pub native_import_ms: f64,
    pub aggregation: AggregationMetrics,
    pub verify_ms: f64,
    pub total_ms: f64,
    pub child_proof_bytes: Vec<usize>,
    pub outer_proof_bytes: usize,
    pub outer_verifier_bytes: usize,
    pub statement_field_bytes: usize,
    pub sample_count: usize,
    pub notes: String,
}

#[derive(Deserialize, Serialize)]
pub(super) struct RunMetrics {
    pub fixture_ms: f64,
    pub client_wall_ms: f64,
    pub aggregate_wall_ms: f64,
    pub verify_wall_ms: f64,
    pub total_ms: f64,
    pub clients: Vec<ClientMetrics>,
    pub aggregation: BatchMetrics,
    pub tree: TreeHistory,
}

impl From<Profile> for FriMetrics {
    fn from(profile: Profile) -> Self {
        let descriptor = profile.descriptor(true);
        Self {
            extension_degree: EXTENSION_DEGREE,
            log_blowup: descriptor.log_blowup(),
            num_queries: descriptor.num_queries(),
            query_pow_bits: descriptor.query_pow_bits(),
            commit_pow_bits: descriptor.commit_pow_bits(),
            batch_pow_bits: 0,
            max_log_arity: descriptor.max_log_arity(),
            log_final_poly_len: descriptor.log_final_poly_len(),
            cap_height: descriptor.commit_cap_height(),
        }
    }
}

impl From<Profile> for WhirMetrics {
    fn from(profile: Profile) -> Self {
        let descriptor = profile.whir_descriptor();
        Self {
            protocol: OUTER_PROTOCOL.into(),
            security_regime: "proven-johnson".into(),
            security_target_per_term: descriptor.security_level(),
            maximum_pow_bits: descriptor.pow_bits(),
            starting_log_inv_rate: descriptor.starting_log_inv_rate(),
            folding_factor: descriptor.folding_factor(),
        }
    }
}

impl TreeOptions {
    pub fn config(&self) -> ScenarioConfig {
        ScenarioConfig {
            depth: self.depth,
            prefill: self.prefill,
            append_after: self.append_after,
            historical: self.historical,
        }
    }
}
