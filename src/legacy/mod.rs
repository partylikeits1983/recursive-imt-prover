//! Archived prime-field SHA3 PoC. Enable the `legacy-prime` feature to build it.
mod aggregation;
mod air;
mod backend;
mod client;
mod config;
mod note;
pub mod scenario;
mod security;
mod statement;
pub mod tree;
mod verification;

pub use aggregation::{AggregationMetrics, Aggregator, Node, aggregate, backend};
pub use air::ImtAir;
pub use backend::Backend;
pub use client::{
    Child, ChildTimings, Leaf, LeafVerifier, MAX_CHILD_PROOF_BYTES, import_child, importer,
};
pub use config::{
    Config, E, EXTENSION_DEGREE, F, OUTER_PROTOCOL, Profile, Proof, ZkConfig, ZkProof,
};
pub use security::{ChildSecurity, SecurityTerm};
pub use statement::{
    AMOUNT_LIMBS, CLAIM_FIELDS, Claim, DIGEST_BYTES, DIGEST_LIMBS, Digest, FORMAT_VERSION,
    MAX_BATCH, RELATION, Statement, check_count, field_bytes, hash,
};
pub use verification::{encode_proof, encode_verifier, verify, verify_allowed};

pub use note::{AMOUNT_BYTES, AMOUNT_OFFSET, NOTE_BYTES, Note, SECRET_BYTES};
