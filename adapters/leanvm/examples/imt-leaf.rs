//! Benchmark the native depth-32 statement on the pinned LeanVM implementation.
use lean_vm_core::cpu::{Proof, execute, prove, verify};
use primitives::field::F128;
#[path = "support/imt.rs"]
mod fixture;
use fixture::{INDEX, QUANTITY, hash};
use std::time::Instant;

fn cells(bytes: &[u8; 32]) -> [F128; 2] {
    let words: [u64; 4] =
        std::array::from_fn(|i| u64::from_le_bytes(bytes[8 * i..8 * i + 8].try_into().unwrap()));
    [F128::new(words[0], words[1]), F128::new(words[2], words[3])]
}

fn main() {
    parallel::set_num_threads(5);
    let preimage = match std::env::args().nth(1).as_deref() {
        None => false,
        Some("--preimage") => true,
        _ => panic!("usage: imt-leaf [--preimage]"),
    };
    let guest = if preimage {
        include_str!("../imt_preimage.py")
    } else {
        include_str!("../imt_leaf.py")
    };
    let ast = zkdsl_compiler::parse(guest).unwrap();
    let program = zkdsl_compiler::compile(&ast).into();
    let [label, nonce, next_label, next_nonce] = fixture::record_fields();
    let record =
        |l: &[u8; 32], n: &[u8; 32]| hash(&[b"IMT-RECORD-OPEN1", l, n, &QUANTITY.to_le_bytes()]);
    let mut root = if preimage {
        hash(&[b"IMT-PREIMAGE-V01", &label])
    } else {
        record(&label, &nonce)
    };
    let tag = hash(&[b"IMT-RECORD-USED1", &nonce]);
    let output = record(&next_label, &next_nonce);
    let mut path = vec![];
    for (level, sibling) in fixture::siblings().into_iter().enumerate() {
        let right = (INDEX >> level) & 1 == 1;
        let [a, b] = cells(&sibling);
        path.push(vec![a, b, F128::new(u64::from(right), 0)]);
        let (left, right) = if right {
            (&sibling, &root)
        } else {
            (&root, &sibling)
        };
        root = hash(&[b"IMT-KECCAK-NODE1", left, right]);
    }
    let digest = if preimage {
        root
    } else {
        hash(&[b"IMT-AGG-LEAF-V3", &root, &tag, &output])
    };
    print!(
        "{}=",
        if preimage {
            "public_root"
        } else {
            "ordered_leaf_digest"
        }
    );
    for b in digest {
        print!("{b:02x}");
    }
    println!();
    let public = cells(&digest);
    let (input_name, fields) = if preimage {
        ("preimage", cells(&label).to_vec())
    } else {
        (
            "record",
            [label, nonce, next_label, next_nonce]
                .iter()
                .flat_map(cells)
                .chain([F128::new(QUANTITY, 0)])
                .collect(),
        )
    };
    let mut advice = [
        (input_name.to_owned(), vec![fields]),
        ("path".to_owned(), path),
    ];
    execute(&program, &advice, public).unwrap();
    for sample in 0..5 {
        for log_inv_rate in if sample % 2 == 0 {
            [1, 2, 4]
        } else {
            [4, 2, 1]
        } {
            let start = Instant::now();
            let (proof, stats) = prove(&program, &advice, public, log_inv_rate).unwrap();
            let prove_s = start.elapsed().as_secs_f64();
            let bytes = proof.to_bytes();
            let decoded = Proof::from_bytes(&bytes).unwrap();
            let start = Instant::now();
            verify(&program, &public, &decoded).unwrap();
            let verify_s = start.elapsed().as_secs_f64();
            let mut wrong = public;
            wrong[1] += F128::ONE;
            assert!(verify(&program, &wrong, &decoded).is_err());
            println!(
                "sample={sample} log_inv_rate={log_inv_rate} cycles={} keccak={} committed_words={} bytes={} prove_s={prove_s:.4} verify_s={verify_s:.4}",
                stats.cycles,
                stats.table_heights[5],
                stats.total_committed,
                bytes.len()
            );
        }
    }
    if !preimage {
        advice[0].1[0][8] += F128::Y;
        assert!(execute(&program, &advice, public).is_err());
        advice[0].1[0][8] += F128::Y;
    }
    advice[0].1[0][0] += F128::ONE;
    assert!(execute(&program, &advice, public).is_err());
    advice[0].1[0][0] += F128::ONE;
    advice[1].1[19][0] += F128::ONE;
    assert!(execute(&program, &advice, public).is_err());
    advice[1].1[19][0] += F128::ONE;
    advice[1].1[8][2] = F128::new(3, 0);
    assert!(execute(&program, &advice, public).is_err());
}
