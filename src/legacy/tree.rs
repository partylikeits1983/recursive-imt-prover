//! Sparse, fixed-depth, append-only binary incremental Merkle tree.
use crate::legacy::note::Note;
use crate::legacy::statement::{Claim, DIGEST_BYTES, Digest};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use sha3::{Digest as _, Sha3_256};
use std::collections::BTreeMap;

pub const EMPTY: Digest = Digest([0; DIGEST_BYTES]);
pub const NODE_TAG: [u8; 2] = *b"IM";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Witness {
    pub note: Note,
    pub index: u64,
    /// Siblings from leaf to root. Index bits are consumed least-significant first.
    pub path: Vec<Digest>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientInput {
    pub root: Digest,
    pub amount: u64,
    pub witness: Witness,
}

pub struct Tree {
    depth: u8,
    leaf_count: u64,
    defaults: Vec<Digest>,
    nodes: BTreeMap<(u8, u64), Digest>,
}

impl Witness {
    pub fn root(&self) -> Result<Digest> {
        check_depth(u8::try_from(self.path.len())?)?;
        ensure!(
            self.index < (1u64 << self.path.len()),
            "index outside tree capacity"
        );
        let mut node = self.note.commitment();
        ensure!(node != EMPTY, "reserved empty leaf");
        for (i, &sibling) in self.path.iter().enumerate() {
            node = if (self.index >> i) & 1 == 0 {
                hash_node(node, sibling)
            } else {
                hash_node(sibling, node)
            };
        }
        Ok(node)
    }
}

impl ClientInput {
    pub fn claim(&self) -> Claim {
        Claim {
            root: self.root,
            amount: self.amount,
        }
    }
}

impl Tree {
    pub fn new(depth: u8) -> Result<Self> {
        check_depth(depth)?;
        let mut defaults = vec![EMPTY];
        for i in 0..depth as usize {
            defaults.push(hash_node(defaults[i], defaults[i]));
        }
        Ok(Self {
            depth,
            leaf_count: 0,
            defaults,
            nodes: BTreeMap::new(),
        })
    }

    fn node(&self, level: u8, index: u64) -> Digest {
        self.nodes
            .get(&(level, index))
            .copied()
            .unwrap_or(self.defaults[level as usize])
    }

    pub fn root(&self) -> Digest {
        self.node(self.depth, 0)
    }

    pub fn len(&self) -> u64 {
        self.leaf_count
    }

    pub fn is_empty(&self) -> bool {
        self.leaf_count == 0
    }

    pub fn append(&mut self, commitment: Digest) -> Result<u64> {
        ensure!(commitment != EMPTY, "reserved empty leaf");
        ensure!(self.leaf_count < (1u64 << self.depth), "tree full");
        let index = self.leaf_count;
        let mut node_index = index;
        self.nodes.insert((0, node_index), commitment);
        for level in 0..self.depth {
            let parent = hash_node(
                self.node(level, node_index & !1),
                self.node(level, node_index | 1),
            );
            node_index >>= 1;
            self.nodes.insert((level + 1, node_index), parent);
        }
        self.leaf_count += 1;
        Ok(index)
    }

    pub fn path(&self, index: u64) -> Result<Vec<Digest>> {
        ensure!(index < self.leaf_count, "leaf not inserted");
        Ok((0..self.depth)
            .map(|level| self.node(level, (index >> level) ^ 1))
            .collect())
    }
}

pub fn check_depth(depth: u8) -> Result<()> {
    ensure!((1..=32).contains(&depth), "tree depth must be 1..=32");
    Ok(())
}

pub fn hash_node(left: Digest, right: Digest) -> Digest {
    let mut hasher = Sha3_256::new();
    hasher.update(NODE_TAG);
    hasher.update(left.0);
    hasher.update(right.0);
    Digest(hasher.finalize().into())
}

/// Explicitly PUBLIC fixture for relation preparation, never an actual secret.
pub fn calibration(depth: u8) -> Result<ClientInput> {
    let note = Note {
        secret: Digest([0xa5; 32]),
        nullifier: Digest([0x5a; 32]),
        amount: 100,
    };
    let mut tree = Tree::new(depth)?;
    let index = tree.append(note.commitment())?;
    Ok(ClientInput {
        root: tree.root(),
        amount: note.amount,
        witness: Witness {
            note,
            index,
            path: tree.path(index)?,
        },
    })
}
