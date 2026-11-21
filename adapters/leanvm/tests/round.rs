use lean_vm_core::cpu::{Proof, execute, prove, verify};
use primitives::field::F128;
use sha3::{Digest, Keccak256};

fn native_rounds() -> [[u64; 15]; 4] {
    include_str!("../../../crates/flock-backend/tests/fixtures/native-root-whir-rounds.txt")
        .lines()
        .filter(|line| !line.starts_with('#'))
        .map(|line| {
            line.split_whitespace()
                .map(|limb| u64::from_str_radix(limb, 16).unwrap())
                .collect::<Vec<_>>()
                .try_into()
                .unwrap()
        })
        .collect::<Vec<_>>()
        .try_into()
        .unwrap()
}

#[test]
fn proves_four_rounds_captured_from_the_native_root_verifier() {
    let ast = zkdsl_compiler::parse(include_str!("../whir_rounds.py")).unwrap();
    let program = zkdsl_compiler::compile(&ast).into();
    let rounds = native_rounds();
    for pair in rounds.windows(2) {
        assert_eq!(pair[0][12..15], pair[1][..3]);
    }

    // Commit to the native trace, including the expected result of *each* round.
    // LeanVM receives only the initial claim and the two messages and challenge per round.
    let mut hash = Keccak256::new().chain_update(b"IMT-RDE1");
    for limb in &rounds[0][..3] {
        hash.update(limb.to_le_bytes());
    }
    let mut digest = hash.finalize();
    for round in &rounds {
        let mut hash = Keccak256::new().chain_update(digest);
        for limb in &round[3..] {
            hash.update(limb.to_le_bytes());
        }
        digest = hash.finalize();
    }
    let words: [u64; 4] =
        std::array::from_fn(|i| u64::from_le_bytes(digest[8 * i..8 * (i + 1)].try_into().unwrap()));
    let public = [F128::new(words[0], words[1]), F128::new(words[2], words[3])];
    let base_words = |limbs: &[u64]| limbs.iter().map(|&x| F128::new(x, 0)).collect();
    let mut advice = [
        ("initial".to_owned(), vec![base_words(&rounds[0][..3])]),
        (
            "round".to_owned(),
            rounds.iter().map(|r| base_words(&r[3..12])).collect(),
        ),
    ];
    for log_inv_rate in lean_vm_core::pcs::MIN_LOG_INV_RATE..=lean_vm_core::pcs::MAX_LOG_INV_RATE {
        let (proof, stats) = prove(&program, &advice, public, log_inv_rate).unwrap();
        let bytes = proof.to_bytes();
        let decoded = Proof::from_bytes(&bytes).unwrap();
        verify(&program, &public, &decoded).unwrap();
        let zero_bytes = bytes.iter().filter(|&&byte| byte == 0).count();
        eprintln!(
            "log inverse rate {log_inv_rate}: {} guest cycles, {} proof bytes ({} zero bytes)",
            stats.cycles,
            bytes.len(),
            zero_bytes
        );

        let mut wrong_digest = public;
        wrong_digest[1] += F128::ONE;
        assert!(verify(&program, &wrong_digest, &decoded).is_err());
        let mut changed = bytes;
        *changed.last_mut().unwrap() ^= 1;
        assert!(Proof::from_bytes(&changed).is_none_or(|p| verify(&program, &public, &p).is_err()));
    }

    advice[1].1[0][6] += F128::ONE;
    assert!(execute(&program, &advice, public).is_err());
    // An unchecked high limb could be shifted between the two inputs to pack()
    // while preserving the packed 128-bit word.
    advice[1].1[0][6] += F128::ONE;
    advice[1].1[0][0] += F128::Y;
    advice[1].1[0][1] += F128::ONE;
    assert!(execute(&program, &advice, public).is_err());
}
