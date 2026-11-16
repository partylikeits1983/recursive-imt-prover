//! Application state is never authorized by the partial transition circuit.
use crate::{
    primitives::{CTX, Digest},
    statement::BatchStatement,
};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedState {
    pub version: u32,
    pub depth: u8,
    pub ctx: Digest,
    pub current_root: Digest,
    pub next_leaf_index: u64,
    pub allowed_roots: [Digest; 4],
    pub spent_nullifiers: BTreeSet<Digest>,
    pub trusted_outer_verifier: String,
}
impl TrustedState {
    pub fn genesis(depth: u8, root: Digest, count: u64) -> Self {
        Self {
            version: 1,
            depth,
            ctx: CTX,
            current_root: root,
            next_leaf_index: count,
            allowed_roots: [root; 4],
            spent_nullifiers: BTreeSet::new(),
            trusted_outer_verifier: "UNAVAILABLE-full-client-verifier-missing".into(),
        }
    }
    pub fn precheck(&self, s: &BatchStatement) -> Result<()> {
        s.validate_encoding()?;
        ensure!(
            self.version == 1
                && s.depth == self.depth
                && s.ctx == self.ctx
                && s.old_root == self.current_root
                && s.old_leaf_count == self.next_leaf_index
                && s.allowed_roots == self.allowed_roots,
            "statement does not match trusted state"
        );
        ensure!(s.nullifiers[0] != s.nullifiers[1], "duplicate nullifier");
        ensure!(
            s.nullifiers
                .iter()
                .all(|nf| !self.spent_nullifiers.contains(nf)),
            "spent nullifier"
        );
        ensure!(
            s.child_roots.iter().all(|r| self.allowed_roots.contains(r)),
            "root not allowed"
        );
        ensure!(
            s.old_leaf_count.checked_add(2) == Some(s.new_leaf_count),
            "wrong count transition"
        );
        Ok(())
    }
}
pub fn verify_and_apply(state: &mut TrustedState, s: &BatchStatement, _proof: &[u8]) -> Result<()> {
    state.precheck(s)?;
    // There is deliberately no success/commit path until the recursive verifier
    // exists. Transition-only FRI proofs are not sufficient authorization.
    anyhow::bail!(
        "INCOMPLETE: trusted recursive authorization verifier unavailable; state unchanged"
    )
}
