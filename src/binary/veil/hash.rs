//! Distinct Keccak domains for commitments and Fiat–Shamir.
use p3_keccak::Keccak256Hash;
use p3_symmetric::CryptographicHasher;

// Even byte lengths permit native Keccak word inputs without changing byte
// order. These v3 domains deliberately invalidate earlier experimental proofs.
pub(super) const LEAF_DOMAIN: &[u8] = b"imt-veil-v3/leaf\0\0";
pub(super) const NODE_DOMAIN: &[u8] = b"imt-veil-v3/node\0\0";
pub(super) const TRANSCRIPT_DOMAIN: &[u8] = b"imt-veil-v3/transcript\0\0";

/// Merkle preimages for the stacked coefficient oracle. The trusted client
/// protocol selects the domain pair, independently of proof bytes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) enum RowDomains {
    #[default]
    Original,
    Aligned,
}

impl RowDomains {
    pub fn tags(self) -> (&'static [u8], &'static [u8]) {
        match self {
            Self::Original => (LEAF_DOMAIN, NODE_DOMAIN),
            Self::Aligned => (b"imt-veil-v4/leaf", b"imt-veil-v4/node"),
        }
    }
}

#[derive(Clone, Copy)]
pub(super) struct DomainHash(pub &'static [u8]);

impl CryptographicHasher<u8, [u8; 32]> for DomainHash {
    const LANES: usize = <Keccak256Hash as CryptographicHasher<u8, [u8; 32]>>::LANES;

    fn hash_iter<I: IntoIterator<Item = u8>>(&self, input: I) -> [u8; 32] {
        Keccak256Hash.hash_iter(self.0.iter().copied().chain(input))
    }

    fn hash_many(&self, input: &[u8], out: &mut [[u8; 32]]) {
        if out.is_empty() {
            return;
        }
        assert!(input.len().is_multiple_of(out.len()), "ragged hash batch");
        let width = input.len() / out.len();
        let mut framed = Vec::with_capacity(input.len() + self.0.len() * out.len());
        for i in 0..out.len() {
            framed.extend_from_slice(self.0);
            framed.extend_from_slice(&input[i * width..(i + 1) * width]);
        }
        // Retain upstream's vectorized Keccak implementation after framing.
        Keccak256Hash.hash_many(&framed, out);
    }
}

#[cfg(test)]
mod tests {
    use super::{CryptographicHasher, DomainHash, LEAF_DOMAIN, NODE_DOMAIN, TRANSCRIPT_DOMAIN};
    use sha3::{Digest, Keccak256};

    #[test]
    fn hash_roles_have_distinct_domains() {
        let input = [0x42; 64];
        let hashes = [LEAF_DOMAIN, NODE_DOMAIN, TRANSCRIPT_DOMAIN]
            .map(|domain| DomainHash(domain).hash_slice(&input));
        assert_ne!(hashes[0], hashes[1]);
        assert_ne!(hashes[1], hashes[2]);
        assert_ne!(hashes[0], hashes[2]);
    }

    #[test]
    fn batched_domains_match_scalar_keccak_at_block_boundaries() {
        for tag in [LEAF_DOMAIN, NODE_DOMAIN, TRANSCRIPT_DOMAIN] {
            let hasher = DomainHash(tag);
            for width in [0, 1, 64, 96, 136 - tag.len(), 137 - tag.len(), 168] {
                let input: Vec<_> = (0..5 * width).map(|i| i as u8).collect();
                let mut output = [[0; 32]; 5];
                hasher.hash_many(&input, &mut output);
                for (i, digest) in output.iter().enumerate() {
                    let message = &input[i * width..(i + 1) * width];
                    let mut reference = Keccak256::new();
                    reference.update(tag);
                    reference.update(message);
                    let expected: [u8; 32] = reference.finalize().into();
                    assert_eq!(*digest, expected);
                    assert_eq!(*digest, hasher.hash_slice(message));
                }
            }
        }
    }
}
