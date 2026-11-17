use recursive_imt_prover::legacy::tree::{ClientInput, Tree, Witness};
use recursive_imt_prover::legacy::{Digest, Note};

// Explicitly deterministic, PUBLIC test fixtures, never actual client secrets.
pub fn fixtures(count: usize, depth: u8, historical: bool) -> Vec<ClientInput> {
    let mut tree = Tree::new(depth).unwrap();
    let mut inputs = Vec::new();
    for i in 0..count {
        let note = Note {
            secret: Digest([i as u8 + 1; 32]),
            nullifier: Digest([i as u8 + 17; 32]),
            amount: (i as u64 + 1) * 100,
        };
        let index = tree.append(note.commitment()).unwrap();
        inputs.push(ClientInput {
            root: tree.root(),
            amount: note.amount,
            witness: Witness {
                note,
                index,
                path: tree.path(index).unwrap(),
            },
        });
    }
    if !historical {
        for input in &mut inputs {
            input.root = tree.root();
            input.witness.path = tree.path(input.witness.index).unwrap();
        }
    }
    inputs
}
