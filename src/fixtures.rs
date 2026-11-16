//! Random diagnostic fixture generation. No deterministic proving randomness.
use crate::{
    client::{self, ClientWitness, Note},
    primitives::CTX,
    state::TrustedState,
    statement::{BatchStatement, ClientStatement},
    tree::{AppendWitness, Tree},
};
use anyhow::Result;
pub struct Fixture {
    pub tree: Tree,
    pub witnesses: [ClientWitness; 2],
    pub clients: [ClientStatement; 2],
    pub batch: BatchStatement,
    pub append: AppendWitness,
    pub state: TrustedState,
}
pub fn pair(depth: u8, historical: bool) -> Result<Fixture> {
    let notes = [Note::random(), Note::random()];
    let mut tree = Tree::new(depth)?;
    let root0 = tree.root();
    tree.append(notes[0].commitment())?;
    let root1 = tree.root();
    tree.append(notes[1].commitment())?;
    let root2 = tree.root();
    let w0 = ClientWitness {
        old: notes[0].clone(),
        new: Note::random(),
        old_leaf_index: 0,
        old_authentication_path: tree.path(0)?,
    };
    if historical {
        tree.append(Note::random().commitment())?;
    }
    let w1 = ClientWitness {
        old: notes[1].clone(),
        new: Note::random(),
        old_leaf_index: 1,
        old_authentication_path: tree.path(1)?,
    };
    let clients = [client::statement(&w0)?, client::statement(&w1)?];
    let mut state = TrustedState::genesis(depth, tree.root(), tree.count);
    if historical {
        state.allowed_roots = [tree.root(), root2, root1, root0];
    }
    let mut next = tree.clone();
    let path0 = next.append(clients[0].new_commitment)?;
    let path1 = next.append(clients[1].new_commitment)?;
    let batch = BatchStatement {
        version: 1,
        depth,
        ctx: CTX,
        old_root: tree.root(),
        old_leaf_count: tree.count,
        allowed_roots: state.allowed_roots,
        child_roots: clients.each_ref().map(|x| x.membership_root),
        nullifiers: clients.each_ref().map(|x| x.nullifier),
        new_commitments: clients.each_ref().map(|x| x.new_commitment),
        new_root: next.root(),
        new_leaf_count: next.count,
    };
    Ok(Fixture {
        tree,
        witnesses: [w0, w1],
        clients,
        batch,
        append: AppendWitness {
            paths: [path0, path1],
        },
        state,
    })
}
