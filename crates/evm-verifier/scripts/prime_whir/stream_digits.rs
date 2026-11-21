//! Coset-major WHIR initial commitment for 192-bit, four-bit checkpoint digits.
//! Only one coset and its Merkle leaves are resident. The cap retains one digest per
//! 1024 RS rows, ordered exactly as the reference Merkle tree.
#[allow(dead_code)]
#[path = "support/digit_columns.rs"]
mod digit_columns;
#[path = "support/digits.rs"]
mod digits;
#[path = "support/node.rs"]
mod node;
#[path = "support/quartets.rs"]
mod quartets;
#[allow(dead_code)]
#[path = "support/segments.rs"]
mod segments;

use ark_ff::{AdditiveGroup, Field, PrimeField};
use rayon::prelude::*;
use sha3::{Digest, Keccak256};
use spongefish::instantiations::Hash;
use std::{
    collections::{BTreeMap, BTreeSet},
    env, fs,
    path::Path,
    time::Instant,
};
use whir::{
    algebra::{
        embedding::Identity,
        fields::Field192 as F,
        ntt::{self, NttEngine},
    },
    bits::Bits,
    buffer::{Buffer, BufferOps},
    hash::KECCAK,
    parameters::ProtocolParameters,
    protocols::{merkle_tree, params::DecodingRegime, whir::Config},
    transcript::{codecs::Empty, DomainSeparator, ProverState},
};

const COLS: usize = 16;
const RATE: usize = 32;
type Digest32 = [u8; 32];

fn parents(hashes: &[Digest32]) -> Vec<Digest32> {
    hashes
        .par_chunks_exact(2)
        .map(|pair| {
            Keccak256::new()
                .chain_update(pair[0])
                .chain_update(pair[1])
                .finalize()
                .into()
        })
        .collect()
}
fn reduce(mut hashes: Vec<Digest32>, limit: usize) -> Vec<Digest32> {
    while hashes.len() > limit {
        hashes = parents(&hashes);
    }
    hashes
}
fn encode_row(matrix: &[F], rows: usize, index: usize) -> [u8; 24 * COLS] {
    let mut data = [0; 24 * COLS];
    for (c, encoded) in data.chunks_exact_mut(24).enumerate() {
        let value = matrix[c * rows + index].into_bigint();
        for (out, limb) in encoded.chunks_exact_mut(8).zip(value.as_ref()) {
            out.copy_from_slice(&limb.to_le_bytes());
        }
    }
    data
}
fn encode_coset(table: &[u8], engine: &NttEngine<F>, step: F, matrix: &mut [F]) {
    let rows = table.len() / COLS;
    let small: [F; 16] = std::array::from_fn(|i| F::from(i as u8));
    matrix
        .par_chunks_mut(4096)
        .enumerate()
        .for_each(|(block, dest)| {
            let i = 4096 * block;
            let digits = &table[i..i + dest.len()];
            if step == F::ONE {
                for (v, &d) in dest.iter_mut().zip(digits) {
                    *v = small[d as usize];
                }
            } else {
                let mut t = step.pow([(i % rows) as u64]);
                for (v, &d) in dest.iter_mut().zip(digits) {
                    *v = t * small[d as usize];
                    t *= step;
                }
            }
        });
    engine.ntt_batch(matrix, rows);
}

fn cap(matrix: &[F], rows: usize, index: Option<&Path>) -> Vec<Digest32> {
    let leaves = (0..rows)
        .into_par_iter()
        .map(|i| Keccak256::digest(encode_row(matrix, rows, i)).into())
        .collect();
    let quartets = reduce(leaves, rows / 4);
    if let Some(path) = index {
        let tmp = path.with_extension(format!("tmp-{}", std::process::id()));
        fs::write(&tmp, quartets.as_flattened()).unwrap();
        fs::rename(tmp, path).unwrap();
    }
    reduce(quartets, (rows / 1024).max(1))
}
// Collect one native opening in transcript order. Re-encode only the cosets containing a
// requested row. Inside each coset, reconstruct only the requested 1,024-leaf subtrees.
pub(crate) fn opening(
    table: &[u8],
    engine: &NttEngine<F>,
    omega: F,
    out: &Path,
    indices: &[usize],
) -> Vec<u8> {
    let rows = table.len() / COLS;
    let total = RATE * rows;
    assert!(!indices.is_empty() && indices.iter().all(|&i| i < total));
    let indices_needed =
        merkle_tree::opening_sibling_indices(total, total.ilog2() as usize, indices);
    let wanted: BTreeSet<_> = indices_needed.iter().copied().collect();
    let mut siblings = BTreeMap::new();
    let mut opened = BTreeMap::new();
    let mut caps = Vec::with_capacity(total / 1024);
    for c in 0..RATE {
        let data = fs::read(out.join(format!("coset-{c:02}.cap"))).unwrap();
        assert_eq!(data.len(), 32 * (rows / 1024));
        caps.extend(
            data.chunks_exact(32)
                .map(|b| <Digest32>::try_from(b).unwrap()),
        );
    }
    let needed: BTreeSet<_> = indices.iter().map(|i| i / rows).collect();
    let mut matrix = Vec::new();
    for c in needed {
        let blocks: BTreeSet<_> = indices
            .iter()
            .filter(|i| *i / rows == c)
            .map(|i| i / 1024)
            .collect();
        let path = out.join(format!("coset-{c:02}.quartets"));
        if path.exists() {
            let mut cache = fs::File::open(path).unwrap();
            assert_eq!(cache.metadata().unwrap().len(), (rows / 4 * 32) as u64);
            for block in blocks {
                quartets::open_block(
                    table,
                    omega,
                    block,
                    indices,
                    &mut cache,
                    &caps,
                    &wanted,
                    &mut siblings,
                    &mut opened,
                );
            }
            continue;
        }
        matrix.resize(table.len(), F::ZERO);
        encode_coset(table, engine, omega.pow([c as u64]), &mut matrix);
        for &index in indices.iter().filter(|&&i| i / rows == c) {
            opened.insert(index, encode_row(&matrix, rows, index % rows));
        }
        for block in blocks {
            let start = (block * 1024) % rows;
            let nodes: Vec<Digest32> = (start..start + 1024)
                .into_par_iter()
                .map(|i| Keccak256::digest(encode_row(&matrix, rows, i)).into())
                .collect();
            assert_eq!(
                quartets::subtree(nodes, block, total, total, &wanted, &mut siblings),
                caps[block]
            );
        }
    }
    drop(matrix);
    let mut offset = 2 * (total - caps.len());
    while caps.len() > 1 {
        for pos in wanted.range(offset..offset + caps.len()) {
            siblings.insert(*pos, caps[*pos - offset]);
        }
        offset += caps.len();
        caps = parents(&caps);
    }
    assert_eq!(caps[0].as_slice(), fs::read(out.join("root.bin")).unwrap());
    let mut hints = ((indices.len() * COLS) as u64).to_le_bytes().to_vec();
    for index in indices {
        hints.extend(opened.get(index).unwrap());
    }
    for pos in indices_needed {
        hints.extend(siblings.get(&pos).unwrap());
    }
    hints
}
fn main() {
    let args: Vec<_> = env::args().collect();
    assert!((4..=6).contains(&args.len()));
    let row_bits: usize = args[2].parse().unwrap();
    assert!((6..=16).contains(&row_bits));
    let output = Path::new(&args[3]);
    fs::create_dir_all(output).unwrap();
    let flags = &args[4..];
    assert!(flags.iter().all(
        |s| matches!(s.as_str(), "--check-dense" | "--cache-quartets")
            || s.starts_with("--indices=")
            || s.starts_with("--index-cosets=")
    ));
    let reference = flags.iter().any(|s| s == "--check-dense");
    let cache_quartets = flags.iter().any(|s| s == "--cache-quartets");
    assert!(!reference || row_bits <= 10);
    let source = Path::new(&args[1]);
    if source.is_dir() {
        let (node, key) = node::node_statement(source);
        fs::write(output.join("node.bin"), node).unwrap();
        fs::write(output.join("key.bin"), key).unwrap();
    }
    let table = digits::table(source, row_bits, 4);
    let rows = table.len() / COLS;
    let cfg = Config::<Identity<F>>::new(
        table.len(),
        &ProtocolParameters {
            security_level: 135,
            pow_bits: 16,
            initial_folding_factor: 4,
            folding_factor: 5,
            decoding_regime: DecodingRegime::Johnson,
            starting_log_inv_rate: 5,
            batch_size: 1,
            hash_id: KECCAK,
        },
    );
    assert!(cfg.check_max_pow_bits(Bits::new(16.0)) && cfg.security_level(1, 1) + 1e-8 >= 135.0);
    assert_eq!(cfg.initial_committer.codeword_length(), rows * RATE);
    assert_eq!(cfg.initial_committer.num_cols(), COLS);
    let omega = ntt::generator::<F>(rows * RATE);
    let engine = NttEngine::new(rows, ntt::generator::<F>(rows));
    if let Some(list) = args.get(4).and_then(|s| s.strip_prefix("--indices=")) {
        let indices: Vec<usize> = list.split(',').map(|s| s.parse().unwrap()).collect();
        let hints = opening(&table, &engine, omega, output, &indices);
        fs::write(output.join("opening-hints.bin"), hints).unwrap();
        println!(
            "Opened {} rows from {} cosets",
            indices.len(),
            indices
                .iter()
                .map(|i| i / rows)
                .collect::<BTreeSet<_>>()
                .len()
        );
        return;
    }
    if let Some(cs) = flags.iter().find_map(|s| s.strip_prefix("--index-cosets=")) {
        let mut matrix = vec![F::ZERO; table.len()];
        for c in cs.split(',').map(|s| s.parse::<usize>().unwrap()) {
            assert!(c < RATE);
            encode_coset(&table, &engine, omega.pow([c as u64]), &mut matrix);
            let roots = cap(
                &matrix,
                rows,
                Some(&output.join(format!("coset-{c:02}.quartets"))),
            );
            assert_eq!(
                roots.as_flattened(),
                fs::read(output.join(format!("coset-{c:02}.cap"))).unwrap()
            );
        }
        return;
    }
    let start = Instant::now();
    let mut roots = Vec::new();
    let mut matrix = vec![F::ZERO; table.len()];
    for c in 0..RATE {
        let now = Instant::now();
        encode_coset(&table, &engine, omega.pow([c as u64]), &mut matrix);
        let index = output.join(format!("coset-{c:02}.quartets"));
        let cap = cap(&matrix, rows, cache_quartets.then_some(index.as_path()));
        fs::write(output.join(format!("coset-{c:02}.cap")), cap.as_flattened()).unwrap();
        roots.push(reduce(cap, 1)[0]);
        println!("coset {}/{RATE} {:.2?}", c + 1, now.elapsed());
    }
    drop(matrix);
    let root = reduce(roots, 1)[0];
    fs::write(output.join("root.bin"), root).unwrap();
    if reference {
        let ds = DomainSeparator::protocol(&cfg)
            .session(&"recursive-imt/precommit/v1")
            .instance(&Empty);
        let mut state = ProverState::new(&ds, Hash::<Keccak256>::default());
        let vector = Buffer::from(table.iter().copied().map(F::from).collect::<Vec<_>>());
        let witness = cfg.initial_committer.commit(&mut state, &[&vector]);
        assert_eq!(root.as_slice(), state.proof().narg_string);
        let ix = [
            rows * 31,
            rows + 1,
            0,
            1,
            rows + 1,
            rows * 31 + 1023,
            1024,
            rows * RATE - 1,
        ];
        let flat: Vec<F> = ix
            .iter()
            .flat_map(|&i| {
                witness.matrix.to_slice()[i * COLS..(i + 1) * COLS]
                    .iter()
                    .copied()
            })
            .collect();
        let mut paths = ProverState::new(&ds, Hash::<Keccak256>::default());
        paths.prover_hint_ark(&flat);
        merkle_tree::Config::with_hash(KECCAK, rows * RATE).open(
            &mut paths,
            &witness.matrix_witness,
            &ix,
        );
        assert_eq!(
            opening(&table, &engine, omega, output, &ix),
            paths.proof().hints
        );
        println!("Dense reference root and all opening bytes match for repeated, adjacent and distant rows");
    }
    println!(
        "{} permutations, {} digits, root {} in {:.2?}",
        1 << row_bits,
        table.len(),
        hex::encode(root),
        start.elapsed()
    );
}
