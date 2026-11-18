//! Native Poly64/Poly192/Keccak research baseline. Child proofs are NOT zero knowledge.
pub mod aggregation_tree;
pub mod cli;
pub mod engine;
pub mod relation;
pub mod security;
pub mod tree;
pub mod veil;

/// Fixed-batch research target. Recursive aggregation of aggregates is separate.
pub const MAX_CHILDREN: usize = 64;

pub use engine::{ChildInput, PreparedAggregate, PreparedChild, Settings};
pub use relation::{AggregatePublic, ClientPublic, ClientWitness};
