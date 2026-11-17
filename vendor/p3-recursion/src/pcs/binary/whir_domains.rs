//! Trusted Keccak domain prefixes for binary WHIR's byte commitments.
use alloc::vec::Vec;
use core::hash::Hash;

use p3_circuit::ops::ByteHash;
use p3_circuit::ops::binary_host::BinaryCircuitHost;
use p3_circuit::{CircuitBuilder, CircuitBuilderError, ExprId};
use p3_field::Field;

use super::whir_plan::invalid;
use crate::verifier::VerificationError;

#[derive(Clone, Debug)]
pub struct BinaryWhirHashDomains {
    leaf: Vec<u8>,
    node: Vec<u8>,
}

impl BinaryWhirHashDomains {
    pub fn new(leaf: &[u8], node: &[u8]) -> Result<Self, VerificationError> {
        if leaf.is_empty()
            || node.is_empty()
            || leaf == node
            || leaf.len() > 256
            || node.len() > 256
        {
            return Err(invalid(
                "expected distinct nonempty bounded Merkle hash prefixes",
            ));
        }
        Ok(Self {
            leaf: leaf.to_vec(),
            node: node.to_vec(),
        })
    }
    pub(super) fn leaf(&self) -> &[u8] {
        &self.leaf
    }
    pub(super) fn node(&self) -> &[u8] {
        &self.node
    }
}

pub(super) fn hash_prefixed<H, F>(
    b: &mut CircuitBuilder<F>,
    hash: ByteHash,
    prefix: &[u8],
    words: &[ExprId],
) -> Result<Vec<ExprId>, CircuitBuilderError>
where
    F: Field + Eq + Hash,
    H: BinaryCircuitHost<F>,
{
    if prefix.len().is_multiple_of(2) {
        let mut input = prefix
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| H::encode_u16(u16::from_le_bytes(*pair)).map(|value| b.define_const(value)))
            .collect::<Result<Vec<_>, _>>()?;
        input.extend_from_slice(words);
        H::hash_words(b, hash, &input)
    } else {
        let mut input = prefix
            .iter()
            .map(|&byte| H::encode_u16(u16::from(byte)).map(|value| b.define_const(value)))
            .collect::<Result<Vec<_>, _>>()?;
        input.extend(H::bytes_from_words(b, words)?);
        let digest = H::hash_bytes(b, hash, &input)?;
        H::words_from_bytes(b, &digest)
    }
}

pub(super) fn compress_prefixed<H, F>(
    b: &mut CircuitBuilder<F>,
    hash: ByteHash,
    prefix: &[u8],
    left: &[ExprId],
    right: &[ExprId],
) -> Result<Vec<ExprId>, CircuitBuilderError>
where
    F: Field + Eq + Hash,
    H: BinaryCircuitHost<F>,
{
    let mut input = left.to_vec();
    input.extend_from_slice(right);
    hash_prefixed::<H, F>(b, hash, prefix, &input)
}
