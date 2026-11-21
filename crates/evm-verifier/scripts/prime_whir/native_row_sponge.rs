//! Build the committed Keccak and fold witness directly from the native authenticated rows.
#[path = "support/checkpoint_digits.rs"]
mod checkpoint_digits;
#[allow(dead_code)]
#[path = "support/segments.rs"]
mod segments;
use checkpoint_digits::checkpoint;
use sha3::{Digest, Keccak256};
use std::{env, fs, path::Path};

fn main() {
    let args: Vec<_> = env::args().collect();
    assert_eq!(
        args.len(),
        3,
        "native_row_sponge fold-directory output-directory"
    );
    let rows = fs::read(Path::new(&args[1]).join("rows.bin")).unwrap();
    let folds = fs::read(Path::new(&args[1]).join("table.bin")).unwrap();
    assert_eq!((rows.len(), folds.len()), (169 * 384, 1 << 19));
    let out = Path::new(&args[2]);
    fs::create_dir_all(out).unwrap();
    let mut table = vec![0u8; 1 << 22];
    let (states, aux) = table.split_at_mut(1 << 21);
    let mut reference = Vec::with_capacity(512 * 600);
    let mut digests = Vec::with_capacity(240 * 32);
    for (r, digits) in folds.chunks_exact(2048).enumerate() {
        aux[8192 * r..8192 * r + 2048].copy_from_slice(digits);
    }
    for (r, row) in rows.chunks_exact(384).enumerate() {
        let messages = if r < 71 {
            vec![&row[..256], &row[256..]]
        } else {
            vec![row]
        };
        let mut slot = 0;
        for msg in messages {
            let mut padded = msg.to_vec();
            padded.push(1);
            padded.resize(padded.len().div_ceil(136) * 136, 0);
            *padded.last_mut().unwrap() |= 128;
            let mut state = [0u8; 200];
            for (n, block) in padded.chunks_exact(136).enumerate() {
                for (j, &m) in block.iter().enumerate() {
                    if n != 0 {
                        let c = state[j] & m;
                        let i = 8192 * r + 2048 + (slot - 1) * 512 + j * 2;
                        aux[i] = c & 15;
                        aux[i + 1] = c >> 4;
                    }
                    state[j] ^= m;
                }
                let start = (r * 3 + slot) * 4096;
                let (mid, end) = checkpoint(&state, &mut states[start..start + 4096]);
                reference.extend(state);
                reference.extend(mid);
                reference.extend(end);
                state = end;
                slot += 1;
            }
            assert_eq!(state[..32], Keccak256::digest(msg)[..]);
            digests.extend(&state[..32]);
        }
        assert_eq!(slot, 3);
    }
    for padding in states[507 * 4096..].chunks_exact_mut(4096) {
        let (mid, end) = checkpoint(&[0; 200], padding);
        reference.extend([0; 200]);
        reference.extend(mid);
        reference.extend(end);
    }
    fs::write(out.join("hash-digits.bin"), &states[..]).unwrap();
    fs::write(out.join("digests.bin"), digests).unwrap();
    fs::write(out.join("keccak-checkpoints.bin"), reference).unwrap();
    fs::write(out.join("table.bin"), table).unwrap();
    println!("Reconstructed 240 digests from 507 Keccak-f permutations and 169 native fold rows");
}
