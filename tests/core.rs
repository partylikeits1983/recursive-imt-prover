use p3_field::PrimeCharacteristicRing;
use recursive_imt_poc::{
    client::{self, ClientWitness, Note},
    primitives::*,
    tree::Tree,
};
fn fixture(
    depth: u8,
) -> (
    client::ClientWitness,
    recursive_imt_poc::statement::ClientStatement,
) {
    let old = Note::random();
    let new = Note::random();
    let mut tree = Tree::new(depth).unwrap();
    tree.append(old.commitment()).unwrap();
    let w = ClientWitness {
        old,
        new,
        old_leaf_index: 0,
        old_authentication_path: tree.path(0).unwrap(),
    };
    let s = client::statement(&w).unwrap();
    (w, s)
}
#[test]
fn client_constraints_reject_mutations_without_preflight() {
    let (w, s) = fixture(4);
    let mut c = client::build(4, &s, &w).unwrap();
    assert!(c.satisfied());
    assert_eq!(c.witness, client::assignment(4, &s, &w).unwrap());
    for i in 0..32 {
        c.public_inputs[i] += F::ONE;
        assert!(!c.satisfied(), "public {i}");
        c.public_inputs[i] -= F::ONE;
    }
    for i in [0, 8, 16, 24, 40, 100, 500] {
        c.witness.w[i] += F::ONE;
        assert!(!c.satisfied(), "witness {i}");
        c.witness.w[i] -= F::ONE;
    }
    let mut bad = w.clone();
    bad.old_leaf_index = 1 << 32;
    assert!(!client::build(4, &s, &bad).unwrap().satisfied());
    bad = w.clone();
    bad.old_leaf_index = 1;
    assert!(!client::build(4, &s, &bad).unwrap().satisfied());
    bad = w.clone();
    bad.old_authentication_path[0].0[0] += 1;
    assert!(!client::build(4, &s, &bad).unwrap().satisfied());
    bad = w.clone();
    bad.old = Note::random();
    assert!(!client::build(4, &s, &bad).unwrap().satisfied());
    bad = w.clone();
    bad.new = Note::random();
    assert!(!client::build(4, &s, &bad).unwrap().satisfied());
    let (w2, s2) = fixture(4);
    assert_eq!(c.shape, client::build(4, &s2, &w2).unwrap().shape);
}
#[test]
fn native_r1cs_poseidon_and_encoding() {
    use recursive_imt_poc::r1cs::Builder;
    for len in [0, 1, 8, 16, 17, 24, 32, 48] {
        let x: Vec<_> = (0..len).map(F::from_usize).collect();
        let mut b = Builder::new(vec![], true);
        let inputs: Vec<_> = x.iter().map(|&v| b.private(v)).collect();
        let out = b.hash(NOTE, &inputs);
        assert_eq!(
            out.iter().map(|x| b.value(x)).collect::<Vec<_>>(),
            hash(NOTE, &x).fields()
        );
        assert!(b.finish().satisfied());
    }
    assert_ne!(hash(NOTE, &[F::ONE]), hash(NULLIFIER, &[F::ONE]));
    assert_ne!(hash(NOTE, &[F::ONE]), hash(NOTE, &[F::ONE, F::ZERO]));
    assert!(serde_json::from_str::<Digest>("[2130706433,0,0,0,0,0,0,0]").is_err());
}
#[test]
fn sparse_depth32_and_independent_dense_reference() {
    for depth in [4, 8] {
        let mut t = Tree::new(depth).unwrap();
        let mut leaves = vec![EMPTY; 1 << depth];
        for item in leaves.iter_mut().take(5) {
            let cm = Note::random().commitment();
            *item = cm;
            t.append(cm).unwrap();
        }
        while leaves.len() > 1 {
            leaves = leaves
                .as_chunks::<2>()
                .0
                .iter()
                .map(|c| node(c[0], c[1]))
                .collect();
        }
        assert_eq!(t.root(), leaves[0]);
    }
    let mut t = Tree::new(32).unwrap();
    for _ in 0..5 {
        t.append(Note::random().commitment()).unwrap();
    }
    assert!(t.stored_nodes() < 200);
    assert_eq!(t.path((1 << 32) - 1).unwrap().len(), 32);
}
#[test]
fn nullifier_stable_across_root_and_replacement() {
    let (mut w, s) = fixture(4);
    w.new = Note::random();
    w.old_authentication_path[1] = Note::random().commitment();
    let s2 = client::statement(&w).unwrap();
    assert_eq!(s.nullifier, s2.nullifier);
    assert_ne!(s.membership_root, s2.membership_root);
    assert_ne!(s.new_commitment, s2.new_commitment);
}
#[test]
fn published_vectors_and_defaults_are_fixed() {
    let vectors: serde_json::Value =
        serde_json::from_str(include_str!("../artifacts/hash-vectors.json")).unwrap();
    for v in vectors["vectors"].as_array().unwrap() {
        let input: Vec<F> = v["input"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| F::from_u64(x.as_u64().unwrap()))
            .collect();
        let expected: Digest = serde_json::from_value(v["output"].clone()).unwrap();
        assert_eq!(hash(v["domain"].as_u64().unwrap() as u32, &input), expected);
    }
    let defaults: Vec<Digest> =
        serde_json::from_value(vectors["default_subtrees"].clone()).unwrap();
    for d in [4, 8, 16, 32] {
        assert_eq!(Tree::new(d).unwrap().root(), defaults[d as usize]);
    }
}
