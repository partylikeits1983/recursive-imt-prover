//! Reproducible synthetic witness shared by the two independent benchmark implementations.
use sha3::{Digest, Keccak256};

pub fn hash(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Keccak256::new();
    for part in parts {
        h.update(part);
    }
    h.finalize().into()
}

pub const QUANTITY: u64 = 0xfedcba9876543210;
pub const INDEX: u32 = 0xa5b6c79d;

pub fn record_fields() -> [[u8; 32]; 4] {
    [1, 2, 3, 4].map(|b| hash(&[&[b]]))
}

pub fn siblings() -> [[u8; 32]; 32] {
    std::array::from_fn(|level| hash(&[b"benchmark sibling", &[level as u8]]))
}
