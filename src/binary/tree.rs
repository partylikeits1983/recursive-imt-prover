use std::collections::BTreeMap;

use anyhow::{Result, ensure};
use sha3::{Digest, Keccak256};

pub const RECORD_DOMAIN: &[u8; 16] = b"IMT-RECORD-OPEN1";
pub const NODE_DOMAIN: &[u8; 16] = b"IMT-KECCAK-NODE1";
pub const TAG_DOMAIN: &[u8; 16] = b"IMT-RECORD-USED1";
pub type Hash = [u8; 32];

/// Sparse storage of a fixed-depth append-only tree. Empty leaves are zero bytes.
pub struct Imt {
    depth: usize,
    count: u64,
    empty: Vec<Hash>,
    nodes: BTreeMap<(usize, u64), Hash>,
}

pub fn keccak(bytes: &[u8]) -> Hash {
    Keccak256::digest(bytes).into()
}

pub fn commitment(label: &Hash, nonce: &Hash, quantity: u64) -> Hash {
    let mut bytes = Vec::with_capacity(88);
    bytes.extend_from_slice(RECORD_DOMAIN);
    bytes.extend_from_slice(label);
    bytes.extend_from_slice(nonce);
    bytes.extend_from_slice(&quantity.to_le_bytes());
    keccak(&bytes)
}

pub fn input_tag(nonce: &Hash) -> Hash {
    let mut bytes = Vec::with_capacity(48);
    bytes.extend_from_slice(TAG_DOMAIN);
    bytes.extend_from_slice(nonce);
    keccak(&bytes)
}

pub fn parent(left: &Hash, right: &Hash) -> Hash {
    let mut bytes = Vec::with_capacity(80);
    bytes.extend_from_slice(NODE_DOMAIN);
    bytes.extend_from_slice(left);
    bytes.extend_from_slice(right);
    keccak(&bytes)
}

impl Imt {
    pub fn new(depth: usize) -> Result<Self> {
        ensure!((1..=32).contains(&depth), "depth must be in 1..=32");
        let mut empty = vec![[0; 32]];
        for i in 0..depth {
            empty.push(parent(&empty[i], &empty[i]));
        }
        Ok(Self {
            depth,
            count: 0,
            empty,
            nodes: BTreeMap::new(),
        })
    }

    pub fn append(&mut self, leaf: Hash) -> Result<u32> {
        ensure!(self.count < 1u64 << self.depth, "tree is full");
        let index = self.count;
        self.count += 1;
        self.nodes.insert((0, index), leaf);
        let mut cursor = index;
        for level in 0..self.depth {
            cursor >>= 1;
            let digest = parent(&self.at(level, 2 * cursor), &self.at(level, 2 * cursor + 1));
            self.nodes.insert((level + 1, cursor), digest);
        }
        Ok(index as u32)
    }

    pub fn root(&self) -> Hash {
        self.at(self.depth, 0)
    }

    pub fn path(&self, index: u32) -> Result<Vec<Hash>> {
        ensure!(u64::from(index) < self.count, "leaf has not been appended");
        Ok((0..self.depth)
            .map(|level| self.at(level, (u64::from(index) >> level) ^ 1))
            .collect())
    }

    fn at(&self, level: usize, index: u64) -> Hash {
        self.nodes
            .get(&(level, index))
            .copied()
            .unwrap_or(self.empty[level])
    }
}
