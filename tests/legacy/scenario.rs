use recursive_imt_prover::legacy::scenario::{ScenarioConfig, populate};
use recursive_imt_prover::legacy::tree::{Tree, Witness};
use recursive_imt_prover::legacy::{Claim, Digest, Leaf, Note, Profile};

#[test]
fn populated_depth_32_tree_uses_roots_after_all_users_appended() {
    for historical in [false, true] {
        let notes: Vec<_> = [100, 200].into_iter().map(Note::random).collect();
        let config = ScenarioConfig {
            depth: 32,
            prefill: 128,
            append_after: 8,
            historical,
        };
        let scenario = populate(notes, config).unwrap();
        assert_eq!(scenario.history.prefilled_leaves, 128);
        assert_eq!(
            scenario.history.final_leaf_count,
            if historical { 146 } else { 138 }
        );
        for (index, input) in scenario.inputs.iter().enumerate() {
            assert_eq!(input.witness.index, 128 + index as u64);
            assert_eq!(input.witness.path.len(), 32);
            assert!(scenario.history.proof_leaf_counts[index] > 130);
            assert_eq!(input.witness.root().unwrap(), input.root);
            assert_eq!(input.witness.note.amount, input.amount);
        }
        assert_eq!(
            scenario.inputs[0].root == scenario.inputs[1].root,
            !historical
        );
    }
}

#[test]
fn amount_binds_all_64_bits_without_field_modulus_aliases() {
    let leaf = Leaf::prepare(Profile::Smoke, 4).unwrap();
    for amount in [0, 1, 2_130_706_433, u32::MAX as u64, u64::MAX] {
        let note = Note {
            secret: Digest([1; 32]),
            nullifier: Digest([2; 32]),
            amount,
        };
        let mut tree = Tree::new(4).unwrap();
        let index = tree.append(note.commitment()).unwrap();
        let witness = Witness {
            note,
            index,
            path: tree.path(index).unwrap(),
        };
        let claim = Claim {
            root: tree.root(),
            amount,
        };
        let proof = leaf.prove(&witness, claim).unwrap();
        leaf.verifier.verify(&proof, claim).unwrap();
        let wrong = Claim {
            amount: amount.wrapping_add(2_130_706_433),
            ..claim
        };
        assert!(leaf.verifier.verify(&proof, wrong).is_err());
    }
}

#[test]
fn scenarios_reject_capacity_overflow_and_missing_later_appends() {
    let base = ScenarioConfig {
        depth: 4,
        prefill: 1,
        append_after: 1,
        historical: false,
    };
    assert!(base.validate(2).is_ok());
    assert!(
        ScenarioConfig {
            append_after: 0,
            ..base
        }
        .validate(2)
        .is_err()
    );
    assert!(
        ScenarioConfig {
            prefill: usize::MAX,
            ..base
        }
        .validate(2)
        .is_err()
    );
    assert!(
        ScenarioConfig {
            prefill: 15,
            ..base
        }
        .validate(2)
        .is_err()
    );
    assert!(
        ScenarioConfig {
            append_after: 8,
            historical: true,
            ..base
        }
        .validate(2)
        .is_err()
    );
}
