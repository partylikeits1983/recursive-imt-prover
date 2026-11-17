use recursive_imt_prover::legacy::tree::{EMPTY, Tree, Witness, hash_node};
use recursive_imt_prover::legacy::{Digest, Note, hash};

#[test]
fn tree_matches_dense_reference_and_rejects_overflow() {
    let mut tree = Tree::new(4).unwrap();
    let mut dense = vec![EMPTY; 16];
    for i in 0..16 {
        let secret = [i as u8; 32];
        let note = Note {
            secret: Digest(secret),
            nullifier: Digest([0x42; 32]),
            amount: i as u64,
        };
        dense[i] = note.commitment();
        tree.append(dense[i]).unwrap();
        let mut level = dense.clone();
        while level.len() > 1 {
            level = level
                .as_chunks::<2>()
                .0
                .iter()
                .map(|p| hash_node(p[0], p[1]))
                .collect();
        }
        assert_eq!(tree.root(), level[0]);
        let witness = Witness {
            note,
            index: i as u64,
            path: tree.path(i as u64).unwrap(),
        };
        assert_eq!(witness.root().unwrap(), tree.root());
    }
    let root = tree.root();
    assert!(tree.append(hash(&[98; 32])).is_err());
    assert_eq!(tree.root(), root);
    assert_eq!(tree.len(), 16);
    let mut large = Tree::new(32).unwrap();
    assert!(large.append(EMPTY).is_err());
    large.append(hash(&[7; 32])).unwrap();
    assert_eq!(large.path(0).unwrap().len(), 32);
    assert!(Tree::new(0).is_err());
    assert!(Tree::new(33).is_err());
    assert_eq!(
        String::from(hash(&[0; 32])),
        "9e6291970cb44dd94008c79bcaf9d86f18b4b49ba5b2a04781db7199ed3b9e4e"
    );
}
