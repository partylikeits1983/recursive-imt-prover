//! Distinct BLAKE3 domains for commitments and Fiat–Shamir.
use p3_blake3::Blake3;
use p3_symmetric::CryptographicHasher;

// Even byte lengths permit native BLAKE3 word inputs without changing byte
// order. These v3 domains deliberately invalidate earlier experimental proofs.
pub(super) const LEAF_DOMAIN: &[u8] = b"imt-veil-v3/leaf\0\0";
pub(super) const NODE_DOMAIN: &[u8] = b"imt-veil-v3/node\0\0";
pub(super) const TRANSCRIPT_DOMAIN: &[u8] = b"imt-veil-v3/transcript\0\0";

#[derive(Clone, Copy)]
pub(super) struct DomainHash(pub &'static [u8]);

impl CryptographicHasher<u8, [u8; 32]> for DomainHash {
    const LANES: usize = <Blake3 as CryptographicHasher<u8, [u8; 32]>>::LANES;

    fn hash_iter<I: IntoIterator<Item = u8>>(&self, input: I) -> [u8; 32] {
        Blake3.hash_iter(self.0.iter().copied().chain(input))
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
        // Retain upstream's vectorized BLAKE3 implementation after framing.
        Blake3.hash_many(&framed, out);
    }
}

#[cfg(test)]
mod tests {
    use super::{CryptographicHasher, DomainHash, LEAF_DOMAIN, NODE_DOMAIN, TRANSCRIPT_DOMAIN};

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
    fn batched_domains_match_scalar_blake3_at_block_boundaries() {
        for tag in [LEAF_DOMAIN, NODE_DOMAIN, TRANSCRIPT_DOMAIN] {
            let hasher = DomainHash(tag);
            for width in [
                0,
                1,
                64,
                96,
                64 - tag.len(),
                65 - tag.len(),
                1024 - tag.len(),
                1025 - tag.len(),
                168,
            ] {
                let input: Vec<_> = (0..5 * width).map(|i| i as u8).collect();
                let mut output = [[0; 32]; 5];
                hasher.hash_many(&input, &mut output);
                for (i, digest) in output.iter().enumerate() {
                    let message = &input[i * width..(i + 1) * width];
                    let mut reference = blake3::Hasher::new();
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
