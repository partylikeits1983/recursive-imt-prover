//! Depth-32 binary-field Keccak IMT proofs and recursive aggregation.
pub mod aggregation_tree;
pub mod checkpoint;
pub mod cli;
pub mod engine;
pub mod relation;
pub mod security;
pub mod tree;
pub mod veil;

pub const IMT_DEPTH: usize = 32;

pub const MAX_CHILDREN: usize = 64;

pub use engine::{ChildInput, PreparedAggregate, PreparedChild, Settings};
pub use relation::{AggregatePublic, ClientPublic, ClientWitness};
