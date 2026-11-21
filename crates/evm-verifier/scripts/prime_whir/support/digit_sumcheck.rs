//! Degree-five sumcheck over a row-by-column factored public weight.
//! The first two folds store compact digit-pair indices. Later folds use field scalars.
use ark_ff::{AdditiveGroup, BigInteger, Field, PrimeField};
use rayon::prelude::*;
use sha3::{Digest, Keccak256};
use whir::algebra::fields::Field192 as F;
pub fn wire(xs: &[F]) -> Vec<u8> {
    xs.iter()
        .flat_map(|x| x.into_bigint().to_bytes_be())
        .collect()
}
pub fn words(xs: &[F]) -> Vec<u8> {
    xs.iter()
        .flat_map(|x| [vec![0; 8], x.into_bigint().to_bytes_be()].concat())
        .collect()
}
pub fn coin(seed: &[u8; 32], family: u8, i: usize) -> F {
    let h = Keccak256::new()
        .chain_update(b"recursive-imt/digit-coin/v1")
        .chain_update(seed)
        .chain_update([family, i as u8]);
    F::from_be_bytes_mod_order(
        &[
            h.clone().chain_update([0]).finalize(),
            h.chain_update([1]).finalize(),
        ]
        .concat(),
    )
}
pub struct Factors<const L: usize> {
    pub rows: Vec<[F; L]>,
    pub cols: Vec<[F; L]>,
}
fn blend<const K: usize>(a: [F; K], b: [F; K], r: F) -> [F; K] {
    std::array::from_fn(|j| a[j] + r * (b[j] - a[j]))
}
fn fold_dense<const K: usize>(v: &mut Vec<[F; K]>, r: F) {
    let n = v.len() / 2;
    let (lo, hi) = v.split_at_mut(n);
    lo.par_iter_mut()
        .zip(hi)
        .for_each(|(a, b)| *a = blend(*a, *b, r));
    v.truncate(n);
}
impl<const L: usize> Factors<L> {
    fn get(&self, i: usize) -> [F; L] {
        let a = self.rows[i / self.cols.len()];
        let b = self.cols[i % self.cols.len()];
        std::array::from_fn(|k| a[k] * b[k])
    }
    fn fold(&mut self, r: F) {
        if self.rows.len() > 1 {
            fold_dense(&mut self.rows, r)
        } else {
            fold_dense(&mut self.cols, r)
        }
    }
}
enum Layer<const K: usize> {
    Byte(Vec<u8>, Vec<[F; K]>),
    Short(Vec<u16>, Vec<[F; K]>),
    Dense(Vec<[F; K]>),
}
impl<const K: usize> Layer<K> {
    fn len(&self) -> usize {
        match self {
            Self::Byte(a, _) => a.len(),
            Self::Short(a, _) => a.len(),
            Self::Dense(a) => a.len(),
        }
    }
    fn get(&self, i: usize) -> [F; K] {
        match self {
            Self::Byte(a, d) => d[a[i] as usize],
            Self::Short(a, d) => d[a[i] as usize],
            Self::Dense(a) => a[i],
        }
    }
    fn fold(self, r: F) -> Self {
        let n = self.len() / 2;
        match self {
            Self::Byte(a, d) => {
                let m = d.len();
                let dict = (0..m * m)
                    .into_par_iter()
                    .map(|i| blend(d[i % m], d[i / m], r))
                    .collect();
                if m == 16 {
                    Self::Byte(
                        (0..n)
                            .into_par_iter()
                            .map(|i| a[i] | (a[i + n] << 4))
                            .collect(),
                        dict,
                    )
                } else {
                    assert_eq!(m, 256);
                    Self::Short(
                        (0..n)
                            .into_par_iter()
                            .map(|i| a[i] as u16 | ((a[i + n] as u16) << 8))
                            .collect(),
                        dict,
                    )
                }
            }
            Self::Short(a, d) => Self::Dense(
                (0..n)
                    .into_par_iter()
                    .map(|i| blend(d[a[i] as usize], d[a[i + n] as usize], r))
                    .collect(),
            ),
            Self::Dense(mut v) => {
                fold_dense(&mut v, r);
                Self::Dense(v)
            }
        }
    }
}
fn values<const K: usize, const L: usize>(
    mut a: [F; K],
    b: [F; K],
    gate: impl Fn([F; K]) -> [F; L],
) -> [[F; L]; 6] {
    let diff: [F; K] = std::array::from_fn(|i| b[i] - a[i]);
    std::array::from_fn(|_| {
        let result = gate(a);
        for (x, y) in a.iter_mut().zip(diff) {
            *x += y;
        }
        result
    })
}
fn polynomial<const K: usize, const L: usize>(
    v: &Layer<K>,
    w: &Factors<L>,
    gate: &(impl Fn([F; K]) -> [F; L] + Sync),
) -> [F; 6] {
    let n = v.len() / 2;
    let table = if let Layer::Byte(_, dict) = v {
        let m = dict.len();
        Some(
            (0..m * m)
                .into_par_iter()
                .map(|i| values(dict[i % m], dict[i / m], gate))
                .collect::<Vec<_>>(),
        )
    } else {
        None
    };
    (0..n)
        .into_par_iter()
        .fold(
            || [F::ZERO; 6],
            |mut acc, i| {
                let mut weight = w.get(i);
                let hi = w.get(i + n);
                let step: [F; L] = std::array::from_fn(|k| hi[k] - weight[k]);
                let direct;
                let gates = if let (Some(lookup), Layer::Byte(ids, dict)) = (&table, v) {
                    &lookup[ids[i] as usize + dict.len() * ids[i + n] as usize]
                } else {
                    direct = values(v.get(i), v.get(i + n), gate);
                    &direct
                };
                for (sum, g) in acc.iter_mut().zip(gates) {
                    for k in 0..L {
                        *sum += weight[k] * g[k];
                        weight[k] += step[k];
                    }
                }
                acc
            },
        )
        .reduce(|| [F::ZERO; 6], |a, b| std::array::from_fn(|i| a[i] + b[i]))
}
fn at(y: &[F; 6], x: F) -> F {
    (0..6)
        .map(|i| {
            let mut a = y[i];
            let mut b = F::ONE;
            for j in 0..6 {
                if i != j {
                    a *= x - F::from(j as u8);
                    b *= F::from(i as u8) - F::from(j as u8);
                }
            }
            a / b
        })
        .sum()
}
pub struct Outcome<const K: usize> {
    pub seed: [u8; 32],
    pub point: Vec<F>,
    pub scalars: Vec<F>,
    pub values: [F; K],
}
pub fn prove<const K: usize, const L: usize>(
    digits: &[u8],
    dict: Vec<[F; K]>,
    mut weights: Factors<L>,
    mut seed: [u8; 32],
    mut sum: F,
    stage: u8,
    gate: impl Fn([F; K]) -> [F; L] + Sync,
) -> Outcome<K> {
    assert_eq!(dict.len(), 16);
    assert_eq!(digits.len(), weights.rows.len() * weights.cols.len());
    let mut v = Layer::Byte(digits.to_vec(), dict);
    let mut scalars = Vec::new();
    let mut point = Vec::new();
    while v.len() > 1 {
        let k = point.len();
        let y = polynomial(&v, &weights, &gate);
        assert_eq!(
            y[0] + y[1],
            sum,
            "incorrect stage {stage} digit identity at round {k}"
        );
        let msg = [y[0], y[2], y[3], y[4], y[5]];
        seed = Keccak256::new()
            .chain_update(seed)
            .chain_update([stage, k as u8])
            .chain_update(wire(&msg))
            .finalize()
            .into();
        let r = coin(&seed, 6, k);
        sum = at(&y, r);
        scalars.extend(msg);
        point.push(r);
        weights.fold(r);
        v = v.fold(r);
    }
    let values = v.get(0);
    let w = weights.get(0);
    assert_eq!(
        sum,
        w.into_iter().zip(gate(values)).map(|(a, b)| a * b).sum()
    );
    Outcome {
        seed,
        point,
        scalars,
        values,
    }
}
