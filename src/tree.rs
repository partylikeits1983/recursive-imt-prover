use crate::primitives::{Digest, EMPTY, check_depth, node};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
/// Sparse node map: (height above leaves, subtree index). Space O(leaves * depth).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Tree {
    pub depth: u8,
    pub count: u64,
    nodes: BTreeMap<(u8, u64), Digest>,
    defaults: Vec<Digest>,
}
impl Tree {
    pub fn new(depth: u8) -> Result<Self> {
        check_depth(depth)?;
        let mut defaults = vec![EMPTY];
        for i in 0..depth as usize {
            defaults.push(node(defaults[i], defaults[i]));
        }
        Ok(Self {
            depth,
            count: 0,
            nodes: BTreeMap::new(),
            defaults,
        })
    }
    fn at(&self, h: u8, i: u64) -> Digest {
        self.nodes
            .get(&(h, i))
            .copied()
            .unwrap_or(self.defaults[h as usize])
    }
    pub fn root(&self) -> Digest {
        self.at(self.depth, 0)
    }
    pub fn path(&self, index: u64) -> Result<Vec<Digest>> {
        ensure!(index < 1u64 << self.depth, "index outside tree");
        Ok((0..self.depth)
            .map(|h| self.at(h, (index >> h) ^ 1))
            .collect())
    }
    pub fn append(&mut self, cm: Digest) -> Result<Vec<Digest>> {
        ensure!(cm != EMPTY, "reserved empty commitment");
        ensure!(self.count < 1u64 << self.depth, "tree full");
        let path = self.path(self.count)?;
        let mut i = self.count;
        let mut v = cm;
        self.nodes.insert((0, i), v);
        for h in 0..self.depth {
            v = if i & 1 == 0 {
                node(v, self.at(h, i ^ 1))
            } else {
                node(self.at(h, i ^ 1), v)
            };
            i >>= 1;
            self.nodes.insert((h + 1, i), v);
        }
        self.count += 1;
        Ok(path)
    }
    pub fn stored_nodes(&self) -> usize {
        self.nodes.len()
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppendWitness {
    pub paths: [Vec<Digest>; 2],
}
