//! WHIR continuation commitments. Each temporary shard covers one complete coset
//! or 1,024 leaves, whichever is larger. The saved cap uses 32 bytes per 1,024 leaves.
use ark_ff::{AdditiveGroup, Field, PrimeField};
use rayon::prelude::*;
use sha3::{Digest, Keccak256};
use std::collections::{BTreeMap, BTreeSet};
use whir::{
    algebra::{
        embedding::Identity,
        fields::Field192 as F,
        ntt::{self, NttEngine},
    },
    protocols::{irs_commit, merkle_tree},
};

type Digest32 = [u8; 32];
const BLOCK: usize = 1024;
const COLS: usize = 32;
pub fn parent(a: Digest32, b: Digest32) -> Digest32 {
    Keccak256::new()
        .chain_update(a)
        .chain_update(b)
        .finalize()
        .into()
}
fn root(hashes: &mut [Digest32]) -> Digest32 {
    let mut n = hashes.len();
    while n > 1 {
        for i in 0..n / 2 {
            hashes[i] = parent(hashes[2 * i], hashes[2 * i + 1]);
        }
        n /= 2;
    }
    hashes[0]
}
fn row(matrix: &[F], rows: usize, i: usize) -> [u8; 24 * COLS] {
    let mut buf = [0; 24 * COLS];
    for (c, b) in buf.chunks_exact_mut(24).enumerate() {
        let v = matrix[c * rows + i].into_bigint();
        for (dest, k) in b.chunks_exact_mut(8).zip(v.as_ref()) {
            dest.copy_from_slice(&k.to_le_bytes());
        }
    }
    buf
}
pub struct Code {
    rows: usize,
    total: usize,
    omega: F,
    engine: NttEngine<F>,
    caps: Vec<Digest32>,
    pub root: Digest32,
}
impl Code {
    fn shard_rows(&self) -> usize {
        self.rows.max(BLOCK)
    }
    // Encode one coset in column-major order, using the exact pinned NTT.
    fn matrix(&self, coeff: &[F], c: usize, tmp: &mut Vec<F>) {
        let step = self.omega.pow([c as u64]);
        let mut t = F::ONE;
        let twiddles: Vec<_> = (0..self.rows)
            .map(|_| {
                let x = t;
                t *= step;
                x
            })
            .collect();
        tmp.resize(coeff.len(), F::ZERO);
        for (col, values) in tmp
            .chunks_exact_mut(self.rows)
            .zip(coeff.chunks_exact(self.rows))
        {
            for ((v, &a), &w) in col.iter_mut().zip(values).zip(&twiddles) {
                *v = a * w;
            }
        }
        self.engine.ntt_batch(tmp, self.rows);
    }
    // Supply contiguous groups of at most a single coset; only requested subtrees are hashed on reopening.
    fn shard(
        &self,
        coeff: &[F],
        shard: usize,
        queries: Option<&[usize]>,
    ) -> (
        Vec<(usize, Vec<Digest32>)>,
        BTreeMap<usize, [u8; 24 * COLS]>,
    ) {
        let width = self.shard_rows();
        let first = shard * width;
        let blocks = width / BLOCK;
        let wanted: BTreeSet<_> = queries.into_iter().flatten().map(|i| i / BLOCK).collect();
        let mut roots = Vec::new();
        let mut opened = BTreeMap::new();
        let mut tmp = Vec::new();
        let mut leaves = Vec::with_capacity(BLOCK);
        for coset in first / self.rows..(first + width) / self.rows {
            self.matrix(coeff, coset, &mut tmp);
            for i in 0..self.rows {
                let idx = coset * self.rows + i;
                let b = idx / BLOCK;
                if queries.is_some() && !wanted.contains(&b) {
                    continue;
                }
                let bytes = row(&tmp, self.rows, i);
                if queries.is_some_and(|q| q.contains(&idx)) {
                    opened.insert(idx, bytes);
                }
                leaves.push(Keccak256::digest(bytes).into());
                if leaves.len() == BLOCK {
                    if queries.is_some() {
                        roots.push((b, std::mem::take(&mut leaves)));
                    } else {
                        let h = root(&mut leaves);
                        roots.push((b, vec![h]));
                        leaves.clear();
                    }
                }
            }
        }
        assert_eq!(roots.len(), queries.map_or(blocks, |_| wanted.len()));
        (roots, opened)
    }
    pub fn commit(cfg: &irs_commit::Config<Identity<F>>, coeff: &[F]) -> Self {
        let rows = cfg.message_length();
        let total = cfg.codeword_length();
        assert_eq!(cfg.num_cols(), COLS);
        assert_eq!(coeff.len(), rows * COLS);
        assert!(total >= BLOCK && rows.is_power_of_two() && total.is_power_of_two());
        let mut code = Self {
            rows,
            total,
            omega: ntt::generator::<F>(total),
            engine: NttEngine::new(rows, ntt::generator::<F>(rows)),
            caps: Vec::new(),
            root: [0; 32],
        };
        let shards = total / code.shard_rows();
        let per_shard = code.shard_rows() / BLOCK;
        let mut caps = vec![[0; 32]; total / BLOCK];
        caps.par_chunks_exact_mut(per_shard)
            .enumerate()
            .for_each(|(s, dst)| {
                for (b, hashes) in code.shard(coeff, s, None).0 {
                    dst[b % per_shard] = hashes[0];
                }
            });
        assert_eq!(caps.len(), shards * per_shard);
        code.root = root(&mut caps.clone());
        code.caps = caps;
        code
    }
    pub fn opening(&self, coeff: &[F], indices: &[usize]) -> Vec<u8> {
        assert!(indices.iter().all(|i| *i < self.total));
        let order =
            merkle_tree::opening_sibling_indices(self.total, self.total.ilog2() as usize, indices);
        let wanted: BTreeSet<_> = order.iter().copied().collect();
        let mut requests = BTreeMap::<usize, Vec<usize>>::new();
        for i in indices {
            requests.entry(*i / self.shard_rows()).or_default().push(*i);
        }
        let mut hashes = BTreeMap::new();
        let mut rows = BTreeMap::new();
        for (s, ix) in requests {
            let (blocks, open) = self.shard(coeff, s, Some(&ix));
            rows.extend(open);
            for (b, mut leaves) in blocks {
                let mut n = BLOCK;
                let mut size = self.total;
                let mut offset = 0;
                while n > 1 {
                    let base = offset + b * n;
                    for pos in wanted.range(base..base + n) {
                        hashes.insert(*pos, leaves[*pos - base]);
                    }
                    for i in 0..n / 2 {
                        leaves[i] = parent(leaves[2 * i], leaves[2 * i + 1]);
                    }
                    n /= 2;
                    offset += size;
                    size /= 2;
                }
                assert_eq!(leaves[0], self.caps[b]);
            }
        }
        let mut caps = self.caps.clone();
        let mut n = caps.len();
        let mut offset = 2 * (self.total - n);
        while n > 1 {
            for pos in wanted.range(offset..offset + n) {
                hashes.insert(*pos, caps[*pos - offset]);
            }
            for i in 0..n / 2 {
                caps[i] = parent(caps[2 * i], caps[2 * i + 1]);
            }
            offset += n;
            n /= 2;
        }
        assert_eq!(caps[0], self.root);
        let mut result = ((indices.len() * COLS) as u64).to_le_bytes().to_vec();
        for i in indices {
            result.extend(rows.get(i).unwrap());
        }
        for i in order {
            result.extend(hashes.get(&i).unwrap());
        }
        result
    }
}
