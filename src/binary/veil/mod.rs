//! Experimental characteristic-two port of VEIL's inner algebraic argument.
//!
//! This is not the native MultiStark/WHIR child backend. The code and transcript
//! changes need a complete simulation and composition analysis before the
//! application may claim full ZK or 128-bit end-to-end security.

pub mod aggregate;
mod air_algebra;
pub mod child;
pub mod code;
mod compiler;
pub mod components;
pub mod constraints;
mod hash;
pub mod keccak;
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
