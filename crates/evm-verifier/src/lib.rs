//! Calldata for the Solidity verifier's `verifyForRoot` entry point.
//! The terminal program represents its application root as eight KoalaBear field elements.

use anyhow::{Result, ensure};

const MODULUS: u32 = 2_130_706_433;
const WORD: usize = 32;
const ROOT_WORDS: usize = 8;
const VERIFY_FOR_ROOT: [u8; 4] = [0x3a, 0xa4, 0xec, 0x0d];

/// Encodes an independently supplied public root and a terminal exporter's `abi.encode(Proof)`.
/// The contract decodes the proof and checks its root and cryptographic contents.
pub fn verify_calldata(expected_root: [u32; ROOT_WORDS], proof_abi: &[u8]) -> Result<Vec<u8>> {
    // A dynamic tuple encoded as a single top-level argument starts one word into its encoding.
    let mut tuple_offset = [0; WORD];
    tuple_offset[WORD - 1] = WORD as u8;
    // Two byte-string offsets, eight root words, two array offsets and three scalar fields.
    let tuple = proof_abi
        .strip_prefix(&tuple_offset)
        .filter(|body| body.len() >= 15 * WORD && body.len().is_multiple_of(WORD))
        .ok_or_else(|| anyhow::anyhow!("expected abi.encode(Proof) for the grouped terminal"))?;
    ensure!(
        expected_root.iter().all(|&value| value < MODULUS),
        "expected root contains a noncanonical KoalaBear element"
    );

    let head_size = (ROOT_WORDS + 1) * WORD;
    let mut calldata = Vec::with_capacity(4 + head_size + tuple.len());
    calldata.extend_from_slice(&VERIFY_FOR_ROOT);
    for value in expected_root {
        let mut word = [0; WORD];
        word[WORD - 4..].copy_from_slice(&value.to_be_bytes());
        calldata.extend_from_slice(&word);
    }
    tuple_offset[WORD - 2..].copy_from_slice(&(head_size as u16).to_be_bytes());
    calldata.extend_from_slice(&tuple_offset);
    calldata.extend_from_slice(tuple);
    Ok(calldata)
}

#[cfg(test)]
mod tests {
    use super::{MODULUS, WORD, verify_calldata};

    const PROOF: &[u8] = include_bytes!("../tests/fixtures/terminal-proof.abi");

    #[test]
    fn encodes_the_callers_root_separately_from_the_proof() {
        let root = [1, 2, 3, 4, 5, 6, 7, MODULUS - 1];
        let call = verify_calldata(root, PROOF).unwrap();
        assert_eq!(call.len(), 99_300);
        assert_eq!(&call[..4], &[0x3a, 0xa4, 0xec, 0x0d]);
        let (head, tuple) = call[4..].split_at(9 * WORD);
        for (word, value) in head.as_chunks::<WORD>().0.iter().zip(root) {
            assert_eq!(&word[..28], &[0; 28]);
            assert_eq!(word[28..], value.to_be_bytes());
        }
        assert_eq!(&head[8 * WORD..9 * WORD - 2], &[0; 30]);
        assert_eq!(&head[9 * WORD - 2..], &[1, 32]);
        assert_eq!(tuple, &PROOF[WORD..]);
    }

    #[test]
    fn rejects_invalid_roots_and_proof_framing() {
        assert!(verify_calldata([MODULUS; 8], PROOF).is_err());
        for malformed in [&b"IMTPRF02"[..], &PROOF[..WORD], &PROOF[..PROOF.len() - 1]] {
            assert!(verify_calldata([0; 8], malformed).is_err());
        }
    }
}
