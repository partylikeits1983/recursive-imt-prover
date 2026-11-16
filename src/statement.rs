use crate::primitives::{Digest, F};
use p3_field::PrimeCharacteristicRing;
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientStatement {
    pub ctx: Digest,
    pub membership_root: Digest,
    pub nullifier: Digest,
    pub new_commitment: Digest,
}
impl ClientStatement {
    pub fn fields(&self) -> Vec<F> {
        [
            self.ctx,
            self.membership_root,
            self.nullifier,
            self.new_commitment,
        ]
        .into_iter()
        .flat_map(Digest::fields)
        .collect()
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BatchStatement {
    pub version: u32,
    pub depth: u8,
    pub ctx: Digest,
    pub old_root: Digest,
    pub old_leaf_count: u64,
    pub allowed_roots: [Digest; 4],
    pub child_roots: [Digest; 2],
    pub nullifiers: [Digest; 2],
    pub new_commitments: [Digest; 2],
    pub new_root: Digest,
    pub new_leaf_count: u64,
}
impl BatchStatement {
    /// Version, depth, ctx, old root, count (3 LE 16-bit limbs), history,
    /// child roots, nullifiers, outputs, new root, new count (3 limbs).
    pub fn fields(&self) -> Vec<F> {
        let mut v = vec![F::from_u32(self.version), F::from_u8(self.depth)];
        v.extend(self.ctx.fields());
        v.extend(self.old_root.fields());
        v.extend(count_fields(self.old_leaf_count));
        for d in self
            .allowed_roots
            .iter()
            .chain(&self.child_roots)
            .chain(&self.nullifiers)
            .chain(&self.new_commitments)
            .chain([&self.new_root])
        {
            v.extend(d.fields());
        }
        v.extend(count_fields(self.new_leaf_count));
        v
    }
    pub fn child(&self, i: usize) -> ClientStatement {
        ClientStatement {
            ctx: self.ctx,
            membership_root: self.child_roots[i],
            nullifier: self.nullifiers[i],
            new_commitment: self.new_commitments[i],
        }
    }
    pub fn validate_encoding(&self) -> anyhow::Result<()> {
        anyhow::ensure!(self.version == 1, "unsupported statement version");
        crate::primitives::check_depth(self.depth)?;
        anyhow::ensure!(
            self.old_leaf_count <= 1u64 << self.depth && self.new_leaf_count <= 1u64 << self.depth,
            "count out of range"
        );
        Ok(())
    }
}
pub fn count_fields(n: u64) -> [F; 3] {
    core::array::from_fn(|i| F::from_u16((n >> (16 * i)) as u16))
}
pub const BATCH_FIELDS: usize = 112;
