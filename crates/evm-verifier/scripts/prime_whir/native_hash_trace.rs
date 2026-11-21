//! Construct the single-native-verifier Keccak witness, including WHIR row preimages.
#[allow(dead_code)]
#[path = "support/segments.rs"]
mod segments;
use sha3::{Digest, Keccak256};
use std::{collections::HashMap, env, fs, path::Path};

const ROWS: usize = 1 << 14;
const WIDTH: usize = 4096;
#[path = "support/checkpoint_digits.rs"]
mod checkpoint_digits;
use checkpoint_digits::checkpoint;
fn main() {
    let args: Vec<_> = env::args().collect();
    assert_eq!(
        args.len(),
        4,
        "native_hash_trace hash-trace.json fold-witness-directory output-directory"
    );
    let records: Vec<(String, u64, String, String)> =
        serde_json::from_slice(&fs::read(&args[1]).unwrap()).unwrap();
    let folds = Path::new(&args[2]);
    let out = Path::new(&args[3]);
    fs::create_dir_all(out).unwrap();
    let mut table = vec![0; ROWS * WIDTH];
    let mut reference = Vec::with_capacity(ROWS * 600);
    let mut blocks = Vec::new();
    let mut spans = Vec::new();
    let mut index = HashMap::new();
    let mut perms = 0usize;
    for (i, (_, _, data, hash)) in records.iter().enumerate() {
        let msg = hex::decode(data.strip_prefix("0x").unwrap()).unwrap();
        let expected: [u8; 32] = Keccak256::digest(&msg).into();
        assert_eq!(
            hex::encode(expected),
            format!("{hash:0>64}"),
            "incorrect captured digest at opcode {i}"
        );
        index.entry(msg.clone()).or_insert(i);
        spans.extend((perms as u32).to_le_bytes());
        spans.extend(u32::try_from(msg.len()).unwrap().to_le_bytes());
        let mut padded = msg;
        padded.push(1);
        padded.resize(padded.len().div_ceil(136) * 136, 0);
        *padded.last_mut().unwrap() |= 128;
        let mut state = [0; 200];
        for block in padded.chunks_exact(136) {
            assert!(
                perms < ROWS,
                "native hash workload exceeded the pinned geometry"
            );
            for j in 0..136 {
                state[j] ^= block[j];
            }
            let (mid, end) = checkpoint(&state, &mut table[perms * WIDTH..(perms + 1) * WIDTH]);
            reference.extend(state);
            reference.extend(mid);
            reference.extend(end);
            blocks.extend(block);
            state = end;
            perms += 1;
        }
        assert_eq!(state[..32], expected, "sponge reconstruction failed at {i}");
    }
    let mut empty = vec![0; WIDTH];
    let (mid, end) = checkpoint(&[0; 200], &mut empty);
    for row in table[perms * WIDTH..].chunks_exact_mut(WIDTH) {
        row.copy_from_slice(&empty);
        reference.extend([0; 200]);
        reference.extend(mid);
        reference.extend(end);
    }
    let mut ports = Vec::new();
    let sources = fs::read(folds.join("rows.bin")).unwrap();
    assert_eq!(sources.len(), 169 * 384);
    for (i, row) in sources.chunks_exact(384).enumerate() {
        let slices = if i < 71 {
            vec![&row[..256], &row[256..]]
        } else {
            vec![row]
        };
        for src in slices {
            let id = index
                .get(src)
                .expect("WHIR row missing from actual hash inputs");
            ports.extend((*id as u32).to_le_bytes());
        }
    }
    // Restrict the 26-coordinate table to row MSB zero, segment 4, lanes 28..31.
    // These four lanes are outside every Keccak input and output reading.
    let digits = fs::read(folds.join("table.bin")).unwrap();
    assert_eq!(digits.len(), 1 << 19);
    for (i, s) in digits.chunks_exact(64).enumerate() {
        let start = i * WIDTH + (4 * 32 + 28) * 16;
        assert!(table[start..start + 64].iter().all(|&d| d == 0));
        table[start..start + 64].copy_from_slice(s);
    }
    for (file, buf) in [
        ("keccak-checkpoints.bin", reference),
        ("sponge-blocks.bin", blocks),
        ("hash-spans.bin", spans),
        ("fold-hash-ports.bin", ports),
        ("table.bin", table),
    ] {
        fs::write(out.join(file), buf).unwrap();
    }
    println!("Checked {} complete Keccak hashes and {perms} Keccak-f permutations. Located all 240 authenticated WHIR row preimages. Combined the two witnesses into a single 2^26 digit table.",records.len());
}
