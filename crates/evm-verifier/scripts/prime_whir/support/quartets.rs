//! Optional four-leaf index for the initial WHIR tree. Exact evaluations of
//! the original nibble coefficients replace re-encoding a complete coset.
use super::{digit_columns, parents, Digest32, COLS, RATE};
use ark_ff::{Field, PrimeField};
use sha3::{Digest, Keccak256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::{Read, Seek, SeekFrom},
};
use whir::algebra::fields::Field192 as F;

pub fn subtree(
    mut nodes: Vec<Digest32>,
    group: usize,
    mut size: usize,
    total: usize,
    wanted: &BTreeSet<usize>,
    siblings: &mut BTreeMap<usize, Digest32>,
) -> Digest32 {
    let mut offset = 2 * (total - size);
    while nodes.len() > 1 {
        let first = offset + group * nodes.len();
        for pos in wanted.range(first..first + nodes.len()) {
            siblings.insert(*pos, nodes[*pos - first]);
        }
        nodes = parents(&nodes);
        offset += size;
        size /= 2;
    }
    nodes[0]
}
pub fn open_block(
    table: &[u8],
    omega: F,
    block: usize,
    indices: &[usize],
    index: &mut File,
    caps: &[Digest32],
    wanted: &BTreeSet<usize>,
    siblings: &mut BTreeMap<usize, Digest32>,
    opened: &mut BTreeMap<usize, [u8; 24 * COLS]>,
) {
    let rows = table.len() / COLS;
    let total = RATE * rows;
    let local = (block * 1024) % rows;
    let mut cached = [[0u8; 32]; 256];
    index
        .seek(SeekFrom::Start((local / 4 * 32) as u64))
        .unwrap();
    index.read_exact(cached.as_flattened_mut()).unwrap();
    let groups: BTreeSet<_> = indices
        .iter()
        .filter(|i| *i / 1024 == block)
        .map(|i| i / 4)
        .collect();
    for group in groups {
        let mut leaves = Vec::with_capacity(4);
        for i in 4 * group..4 * group + 4 {
            let exponent = i / rows + RATE * (i % rows);
            let row = digit_columns::univariate_columns(table, omega.pow([exponent as u64]));
            let mut bytes = [0u8; 24 * COLS];
            for (out, x) in bytes.chunks_exact_mut(24).zip(row) {
                for (b, limb) in out.chunks_exact_mut(8).zip(x.into_bigint().as_ref()) {
                    b.copy_from_slice(&limb.to_le_bytes());
                }
            }
            leaves.push(Keccak256::digest(bytes).into());
            if indices.contains(&i) {
                opened.insert(i, bytes);
            }
        }
        assert_eq!(
            subtree(leaves, group, total, total, wanted, siblings),
            cached[group % 256]
        );
    }
    assert_eq!(
        subtree(cached.to_vec(), block, total / 4, total, wanted, siblings),
        caps[block]
    );
}
