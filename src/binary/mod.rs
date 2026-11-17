//! Native Tower128/Keccak research baseline. Child proofs are NOT zero knowledge.
pub mod cli;
pub mod engine;
pub mod relation;
pub mod tree;
pub mod veil;

pub use engine::{ChildInput, PreparedAggregate, PreparedChild, Settings};
pub use relation::{AggregatePublic, ClientPublic, ClientWitness};
