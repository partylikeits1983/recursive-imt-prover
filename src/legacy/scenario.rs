use crate::legacy::note::Note;
use crate::legacy::statement::check_count;
use crate::legacy::tree::{ClientInput, Tree, Witness, check_depth};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub struct ScenarioConfig {
    pub depth: u8,
    pub prefill: usize,
    pub append_after: usize,
    pub historical: bool,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TreeHistory {
    pub prefilled_leaves: usize,
    pub user_leaves: usize,
    pub appended_after_users: usize,
    pub final_leaf_count: u64,
    pub proof_leaf_counts: Vec<u64>,
}

pub struct Scenario {
    pub inputs: Vec<ClientInput>,
    pub history: TreeHistory,
}

impl ScenarioConfig {
    pub fn validate(self, count: usize) -> Result<()> {
        check_count(count)?;
        check_depth(self.depth)?;
        ensure!(
            self.append_after > 0,
            "append-after must be positive to use a later root"
        );
        let later = self
            .append_after
            .checked_mul(if self.historical { count } else { 1 })
            .context("scenario leaf count overflow")?;
        let total = self
            .prefill
            .checked_add(count)
            .and_then(|n| n.checked_add(later))
            .context("scenario leaf count overflow")?;
        ensure!(
            u64::try_from(total)? <= (1u64 << self.depth),
            "scenario exceeds tree capacity"
        );
        Ok(())
    }
}

pub fn populate(notes: Vec<Note>, config: ScenarioConfig) -> Result<Scenario> {
    config.validate(notes.len())?;
    let count = notes.len();
    let mut tree = Tree::new(config.depth)?;
    append_unrelated(&mut tree, config.prefill)?;
    let mut inputs = Vec::with_capacity(count);
    let mut insertion_roots = Vec::with_capacity(count);
    for note in notes {
        let index = tree.append(note.commitment())?;
        insertion_roots.push(tree.root());
        inputs.push(ClientInput {
            root: tree.root(),
            amount: note.amount,
            witness: Witness {
                note,
                index,
                path: Vec::new(),
            },
        });
    }
    let mut proof_leaf_counts = Vec::with_capacity(count);
    if !config.historical {
        append_unrelated(&mut tree, config.append_after)?;
    }
    for (input, insertion_root) in inputs.iter_mut().zip(insertion_roots) {
        if config.historical {
            append_unrelated(&mut tree, config.append_after)?;
        }
        input.root = tree.root();
        input.witness.path = tree.path(input.witness.index)?;
        ensure!(
            input.root != insertion_root,
            "proof must use a root after the user's append"
        );
        proof_leaf_counts.push(tree.len());
    }
    Ok(Scenario {
        inputs,
        history: TreeHistory {
            prefilled_leaves: config.prefill,
            user_leaves: count,
            appended_after_users: config.append_after * if config.historical { count } else { 1 },
            final_leaf_count: tree.len(),
            proof_leaf_counts,
        },
    })
}

fn append_unrelated(tree: &mut Tree, count: usize) -> Result<()> {
    for _ in 0..count {
        tree.append(Note::random(0).commitment())?;
    }
    Ok(())
}
