//! Experimental binary masking and proof aggregation.
//! Joint privacy and end-to-end soundness remain unproved.

pub mod aggregate;
mod air_algebra;
pub mod child;
pub mod code;
mod compiler;
pub mod components;
pub mod constraints;
mod hash;
mod membership_air;
pub mod native;
mod oracle;
pub mod parameters;
pub mod private_sumcheck;
pub mod security;
mod stacked_oracle;
pub mod sumcheck;
mod transcript;
mod vector;
mod whir;

pub type F = p3_binary_field::Poly64;
pub type E = p3_binary_field::Poly192;
