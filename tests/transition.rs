use p3_field_outer::PrimeCharacteristicRing;
use p3_koala_bear_outer::KoalaBear as O;
use recursive_imt_poc::{fixtures, outer, statement::BatchStatement, tree::AppendWitness};
fn accepts(c: &outer::TransitionCircuit, s: &BatchStatement, w: &AppendWitness) -> bool {
    let mut r = c.circuit.runner();
    r.set_public_inputs(
        &s.fields()
            .into_iter()
            .map(outer::convert)
            .collect::<Vec<_>>(),
    )
    .and_then(|_| r.set_private_inputs(&outer::private_inputs(s, w).unwrap()))
    .and_then(|_| r.run())
    .is_ok()
}
#[test]
fn fixed_circuit_history_append_and_adversarial_assignments() {
    let c = outer::build_transition(4).unwrap();
    for historical in [false, true] {
        let f = fixtures::pair(4, historical).unwrap();
        assert!(accepts(&c, &f.batch, &f.append));
        let s = &f.batch;
        let w = &f.append;
        let mut bad = s.clone();
        bad.new_root.0[0] += 1;
        assert!(!accepts(&c, &bad, w));
        bad = s.clone();
        bad.old_root.0[0] += 1;
        assert!(!accepts(&c, &bad, w));
        bad = s.clone();
        bad.old_leaf_count += 1;
        bad.new_leaf_count += 1;
        assert!(!accepts(&c, &bad, w));
        bad = s.clone();
        bad.new_leaf_count += 1;
        assert!(!accepts(&c, &bad, w));
        bad = s.clone();
        bad.child_roots[0].0[0] += 1;
        assert!(!accepts(&c, &bad, w));
        bad = s.clone();
        bad.nullifiers[1] = bad.nullifiers[0];
        assert!(!accepts(&c, &bad, w));
        bad = s.clone();
        bad.new_commitments[0] = recursive_imt_poc::primitives::EMPTY;
        assert!(!accepts(&c, &bad, w));
        let mut bw = w.clone();
        bw.paths[1] = f.tree.path(s.old_leaf_count + 1).unwrap();
        assert!(!accepts(&c, s, &bw));
        bw = w.clone();
        bw.paths[0][0].0[0] += 1;
        assert!(!accepts(&c, s, &bw));
        // Bypass every precheck. Supply malformed selector and count BIT values.
        for i in [0, 4, 32, 33, 64] {
            let mut private = outer::private_inputs(s, w).unwrap();
            private[i] = O::from_u32(2);
            let mut r = c.circuit.runner();
            let a = r.set_public_inputs(
                &s.fields()
                    .into_iter()
                    .map(outer::convert)
                    .collect::<Vec<_>>(),
            );
            let reject = a
                .and_then(|_| r.set_private_inputs(&private))
                .and_then(|_| r.run())
                .is_err();
            assert!(reject, "private index {i}");
        }
        for n in [
            16,
            17,
            (1u64 << 32) - 1,
            1u64 << 32,
            recursive_imt_poc::primitives::MODULUS as u64,
        ] {
            bad = s.clone();
            bad.old_leaf_count = n;
            bad.new_leaf_count = n + 2;
            assert!(!accepts(&c, &bad, w));
        }
    }
}
#[test]
fn state_rejects_untrusted_history_replay_and_never_applies_partial_proofs() {
    use recursive_imt_poc::state::verify_and_apply;
    let f = fixtures::pair(4, false).unwrap();
    let original = f.state;
    let mut state = original.clone();
    assert!(verify_and_apply(&mut state, &f.batch, b"anything").is_err());
    assert_eq!(state, original);
    let mut s = f.batch.clone();
    s.allowed_roots[0] = s.new_root;
    s.child_roots[0] = s.new_root;
    assert!(state.precheck(&s).is_err());
    state.spent_nullifiers.insert(f.batch.nullifiers[0]);
    assert!(state.precheck(&f.batch).is_err());
    state = original.clone();
    state.current_root = f.batch.new_root;
    state.next_leaf_index = f.batch.new_leaf_count;
    assert!(state.precheck(&f.batch).is_err());
    let _ = original;
}
#[test]
fn depth32_last_two_slots_and_u64_boundary_do_not_wrap_in_field() {
    use recursive_imt_poc::{
        client::Note,
        primitives::{CTX, Digest, EMPTY, node, root_from_path},
    };
    // Compressed reference prefix: all preceding leaves hold the same nonempty
    // reference commitment. Only the final two slots are empty. No 2^32 allocation.
    let leaf = Note::random().commitment();
    let mut filled = vec![leaf];
    for i in 0..32 {
        filled.push(node(filled[i], filled[i]));
    }
    let n = (1u64 << 32) - 2;
    let mut path0 = vec![EMPTY];
    path0.extend_from_slice(&filled[1..32]);
    let cm = [Note::random().commitment(), Note::random().commitment()];
    let mut path1 = path0.clone();
    path1[0] = cm[0];
    let old = root_from_path(EMPTY, n, &path0).unwrap();
    let middle = root_from_path(cm[0], n, &path0).unwrap();
    assert_eq!(middle, root_from_path(EMPTY, n + 1, &path1).unwrap());
    let new = root_from_path(cm[1], n + 1, &path1).unwrap();
    let s = BatchStatement {
        version: 1,
        depth: 32,
        ctx: CTX,
        old_root: old,
        old_leaf_count: n,
        allowed_roots: [old; 4],
        child_roots: [old; 2],
        nullifiers: [Digest([1; 8]), Digest([2; 8])],
        new_commitments: cm,
        new_root: new,
        new_leaf_count: 1u64 << 32,
    };
    let w = AppendWitness {
        paths: [path0, path1],
    };
    let c = outer::build_transition(32).unwrap();
    assert!(accepts(&c, &s, &w));
    let mut bad = s.clone();
    bad.old_leaf_count += 1;
    bad.new_leaf_count += 1;
    assert!(!accepts(&c, &bad, &w));
    bad = s.clone();
    bad.new_leaf_count = 0;
    assert!(!accepts(&c, &bad, &w));
    bad = s;
    bad.old_leaf_count += 1u64 << 48;
    assert!(bad.validate_encoding().is_err());
}
