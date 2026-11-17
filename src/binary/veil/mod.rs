//! Experimental characteristic-two port of VEIL's inner algebraic argument.
//!
//! This is not the native MultiStark/WHIR child backend. The code and transcript
//! changes need a complete simulation and composition analysis before the
//! application may claim full ZK or 128-bit end-to-end security.

pub mod code;
pub mod constraints;
pub mod keccak;
pub mod parameters;
mod transcript;
mod vector;

pub type F = p3_binary_field::Poly64;
pub type E = p3_binary_field::Poly192;
