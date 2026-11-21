//! First four sumcheck coordinates over packed Boolean witness columns. A column
//! only expands to prime-field values after its length has fallen by sixteen.
use crate::scalar::Fr;
use crate::sumcheck::util::calculate_evaluations_over_boolean_hypercube_for_eq as eq_table;
use crate::transcript::Prover;
use ark_ff::{AdditiveGroup, Field};
use rayon::prelude::*;

const PREFIX: usize = 4;
const SAMPLES: usize = 6;

#[derive(Clone, Copy)]
pub enum Basis {
    Bit,
    Sign,
    Complement,
}
use Basis::*;
#[derive(Clone, Copy)]
pub struct Factor(pub usize, pub Basis);
pub struct Term {
    pub factors: Vec<Factor>,
    pub first: Fr,
    pub second: Fr,
}
pub struct Tail {
    pub polys: Vec<Vec<Fr>>,
    pub eq: Vec<Fr>,
    pub other: Vec<Fr>,
    pub point: Vec<Fr>,
    pub sum: Fr,
}

fn reverse_low(v: usize, n: usize) -> usize {
    if n == 0 {
        0
    } else {
        v.reverse_bits() >> (usize::BITS as usize - n)
    }
}
fn pack(words: &[u64], rotation: u32) -> Vec<u16> {
    let stride = words.len() / 16;
    let mut out = vec![0; stride * 64];
    out.par_chunks_mut(64).enumerate().for_each(|(i, block)| {
        for j in 0..16 {
            let w = words[j * stride + i].rotate_left(rotation);
            let k = reverse_low(j, 4);
            for (bit, x) in block.iter_mut().enumerate() {
                *x |= (((w >> bit) & 1) as u16) << k;
            }
        }
    });
    out
}

// Subset sums of the Boolean equality weights, indexed by the sixteen raw bits.
fn subsets(point: &[Fr]) -> Vec<Fr> {
    let weights = eq_table(point);
    let mut out = vec![Fr::ZERO; 1 << weights.len()];
    for i in 1..out.len() {
        let bit = i.trailing_zeros() as usize;
        out[i] = out[i & (i - 1)] + weights[reverse_low(bit, point.len())];
    }
    out
}
type Samples = [Fr; SAMPLES];
struct Lookup {
    entries: [Vec<Samples>; 3],
    key_bits: usize,
    mask: usize,
}
impl Lookup {
    fn new(point: &[Fr], degree: usize) -> Self {
        let subset = subsets(point);
        let key_bits = 2 << point.len();
        let half = subset.len() - 1;
        let count = 1 << key_bits;
        let mut entries: [Vec<Samples>; 3] = std::array::from_fn(|_| Vec::with_capacity(count));
        for key in 0..count {
            let a = subset[key & half];
            let b = subset[key >> (key_bits / 2)];
            let mut v = [Fr::ZERO; SAMPLES];
            v[0] = a;
            for (i, el) in v.iter_mut().enumerate().take(degree).skip(1) {
                *el = a + Fr::from((i + 1) as u64) * (b - a);
            }
            entries[0].push(v);
            entries[1].push(v.map(|a| Fr::ONE - a.double()));
            entries[2].push(v.map(|a| Fr::ONE - a));
        }
        Lookup {
            entries,
            key_bits,
            mask: count - 1,
        }
    }
    fn basis(&self, basis: Basis) -> &[Samples] {
        &self.entries[match basis {
            Bit => 0,
            Sign => 1,
            Complement => 2,
        }]
    }
}

fn eq_pair(a: Fr, b: Fr) -> Fr {
    a * b + (Fr::ONE - a) * (Fr::ONE - b)
}

struct FixedWeights {
    suffix: Vec<Fr>,
    point: Vec<Fr>,
    fixed: Fr,
}
impl FixedWeights {
    fn new(point: &[Fr], rotate: bool) -> Self {
        let mut suffix = eq_table(&point[PREFIX..]);
        if rotate {
            for word in suffix.chunks_exact_mut(64) {
                word.rotate_left(1);
            }
        }
        Self {
            suffix,
            point: point.to_vec(),
            fixed: Fr::ONE,
        }
    }
    fn block(&self, h: usize, index: usize) -> Fr {
        let mut v = self.fixed;
        for j in h + 1..PREFIX {
            let a = self.point[j];
            v *= if index >> (PREFIX - 1 - j) & 1 == 1 {
                a
            } else {
                Fr::ONE - a
            };
        }
        v
    }
}

/// Accumulate one product of bit, sign or complement columns. At the first
/// coordinates the restricted bits take few values; sum the equality weights in
/// buckets before multiplying by the product. Larger alphabets use direct sums.
fn term_samples(
    term: &Term,
    packed: &[Vec<u16>],
    lut: &Lookup,
    first: &FixedWeights,
    second: Option<&FixedWeights>,
    h: usize,
    degree: usize,
) -> Samples {
    let count = term.factors.len();
    let factor_cols: Vec<_> = term.factors.iter().map(|f| &packed[f.0]).collect();
    let tables: Vec<_> = term.factors.iter().map(|f| lut.basis(f.1)).collect();
    let use_second = second.is_some() && term.second != Fr::ZERO;
    let size = lut.key_bits * count;
    let mut result = [Fr::ZERO; SAMPLES];
    for block in 0..1 << (PREFIX - h - 1) {
        let shift = reverse_low(block, PREFIX - h - 1) * lut.key_bits;
        let mut sums = [Fr::ZERO; SAMPLES];
        let mut sums2 = [Fr::ZERO; SAMPLES];
        if size <= 16 {
            let mut bins = vec![Fr::ZERO; 1 << size];
            let mut bins2 = if use_second {
                vec![Fr::ZERO; 1 << size]
            } else {
                Vec::new()
            };
            for i in 0..first.suffix.len() {
                let mut key = 0;
                for col in &factor_cols {
                    key = (key << lut.key_bits) | ((usize::from(col[i]) >> shift) & lut.mask);
                }
                bins[key] += first.suffix[i];
                if use_second {
                    bins2[key] += second.unwrap().suffix[i];
                }
            }
            for (key, weight) in bins.iter().enumerate() {
                let mut k = key;
                let mut product = [Fr::ONE; SAMPLES];
                for table in tables.iter().rev() {
                    let vs = &table[k & lut.mask];
                    k >>= lut.key_bits;
                    for t in 0..degree {
                        product[t] *= vs[t];
                    }
                }
                for t in 0..degree {
                    sums[t] += product[t] * weight;
                    if use_second {
                        sums2[t] += product[t] * bins2[key];
                    }
                }
            }
        } else {
            for i in 0..first.suffix.len() {
                let mut product = tables[0][(usize::from(factor_cols[0][i]) >> shift) & lut.mask];
                for j in 1..count {
                    let vs = &tables[j][(usize::from(factor_cols[j][i]) >> shift) & lut.mask];
                    for t in 0..degree {
                        product[t] *= vs[t];
                    }
                }
                for t in 0..degree {
                    sums[t] += product[t] * first.suffix[i];
                    if use_second {
                        sums2[t] += product[t] * second.unwrap().suffix[i];
                    }
                }
            }
        }
        let a = first.block(h, block) * term.first;
        let b = if use_second {
            second.unwrap().block(h, block) * term.second
        } else {
            Fr::ZERO
        };
        for t in 0..degree {
            let x = Fr::from(if t == 0 { 0 } else { t as u64 + 1 });
            result[t] += a * eq_pair(first.point[h], x) * sums[t];
            if use_second {
                result[t] += b * eq_pair(second.unwrap().point[h], x) * sums2[t];
            }
        }
    }
    result
}

// Interpolate the small sumcheck polynomial at the consecutive integers; its
// evaluation at one is derived from the incoming claim.
fn interpolate(samples: &Samples, degree: usize, sum: Fr) -> Vec<Fr> {
    let mut delta = vec![samples[0], sum - samples[0]];
    delta.extend_from_slice(&samples[1..degree]);
    let mut coefficients = vec![Fr::ZERO; degree + 1];
    let mut basis = vec![Fr::ONE];
    for k in 0..=degree {
        for (c, b) in coefficients.iter_mut().zip(&basis) {
            *c += delta[0] * b;
        }
        if k == degree {
            break;
        }
        for j in 0..degree - k {
            delta[j] = delta[j + 1] - delta[j];
        }
        let inverse = Fr::from((k + 1) as u64).inverse().unwrap();
        let root = Fr::from(k as u64);
        let mut next = vec![Fr::ZERO; basis.len() + 1];
        for (i, &b) in basis.iter().enumerate() {
            next[i] -= root * b * inverse;
            next[i + 1] += b * inverse;
        }
        basis = next;
    }
    coefficients
}

pub fn reduce(
    p: &mut Prover,
    words: Vec<(&[u64], u32)>,
    terms: Vec<Term>,
    alpha: &[Fr],
    other: Option<(&[Fr], bool)>,
    degree: usize,
    mut sum: Fr,
) -> Tail {
    assert!(alpha.len() >= PREFIX + 6 && degree <= SAMPLES);
    let packed: Vec<_> = words.par_iter().map(|(w, r)| pack(w, *r)).collect();
    let mut first = FixedWeights::new(alpha, false);
    let mut second = other.map(|(a, rot)| FixedWeights::new(a, rot));
    let mut point = Vec::with_capacity(PREFIX);
    for h in 0..PREFIX {
        let lut = Lookup::new(&point, degree);
        let vals = terms
            .par_iter()
            .map(|t| term_samples(t, &packed, &lut, &first, second.as_ref(), h, degree))
            .reduce(
                || [Fr::ZERO; SAMPLES],
                |a, b| std::array::from_fn(|i| a[i] + b[i]),
            );
        let coeff = interpolate(&vals, degree, sum);
        for &c in &coeff[1..] {
            p.write(c);
        }
        let r = p.read();
        sum = coeff.iter().rev().fold(Fr::ZERO, |v, &c| c + r * v);
        first.fixed *= eq_pair(alpha[h], r);
        if let Some(w) = &mut second {
            w.fixed *= eq_pair(w.point[h], r);
        }
        point.push(r);
    }
    let lut = subsets(&point);
    let polys = packed
        .into_par_iter()
        .map(|col| col.into_iter().map(|w| lut[w as usize]).collect())
        .collect();
    let scale = |w: FixedWeights| w.suffix.into_par_iter().map(|v| v * w.fixed).collect();
    Tail {
        polys,
        eq: scale(first),
        other: second.map(scale).unwrap_or_default(),
        point,
        sum,
    }
}

use crate::{
    reference::apply_pi,
    sumcheck::{
        chi::{ChiProof, prove_sumcheck_chi},
        theta::{ThetaProof, prove_sumcheck_theta},
        theta_a::{ThetaAProof, prove_sumcheck_theta_a},
        theta_c::{ThetaCProof, prove_sumcheck_theta_c},
        theta_d::{ThetaDProof, prove_sumcheck_theta_d},
    },
};

fn columns(data: &[u64], n: usize) -> Vec<(&[u64], u32)> {
    data.chunks_exact(1 << (n - 6))
        .map(|col| (col, 0))
        .collect()
}
fn term(factors: Vec<Factor>, first: Fr) -> Term {
    Term {
        factors,
        first,
        second: Fr::ZERO,
    }
}
fn signs(polys: &mut [Vec<Fr>]) {
    polys.par_iter_mut().for_each(|p| {
        for c in p {
            *c = Fr::ONE - c.double();
        }
    });
}

pub fn chi(p: &mut Prover, n: usize, r: &[Fr], b: &[Fr], rho: &[u64], sum: Fr) -> ChiProof {
    let mut pi = rho.to_vec();
    apply_pi(rho, &mut pi);
    let mut terms = Vec::with_capacity(50);
    for j in 0..25 {
        let base = j - j % 5;
        terms.push(term(vec![Factor(j, Bit)], b[j]));
        terms.push(term(
            vec![
                Factor(j, Sign),
                Factor(base + (j + 1) % 5, Complement),
                Factor(base + (j + 2) % 5, Bit),
            ],
            b[j],
        ));
    }
    let mut t = reduce(p, columns(&pi, n), terms, r, None, 4, sum);
    let mut proof = prove_sumcheck_chi(p, n - PREFIX, b, &mut t.eq, &mut t.polys, t.sum);
    t.point.append(&mut proof.r);
    proof.r = t.point;
    proof
}

pub fn theta(
    p: &mut Prover,
    n: usize,
    r: &[Fr],
    b: &[Fr],
    d: &[u64],
    a: &[u64],
    sum: Fr,
) -> ThetaProof {
    let mut source = columns(a, n);
    source.extend(columns(d, n));
    let terms = (0..25)
        .map(|j| term(vec![Factor(j, Sign), Factor(25 + j % 5, Sign)], b[j]))
        .collect();
    let mut t = reduce(p, source, terms, r, None, 3, sum);
    signs(&mut t.polys);
    let mut ds = t.polys.split_off(25);
    let mut ai: Vec<_> = (0..5)
        .into_par_iter()
        .map(|x| {
            let mut out = vec![Fr::ZERO; t.eq.len()];
            for y in 0..5 {
                let j = 5 * y + x;
                for (v, &a) in out.iter_mut().zip(&t.polys[j]) {
                    *v += a * b[j];
                }
            }
            out
        })
        .collect();
    drop(t.polys);
    let mut proof = prove_sumcheck_theta(p, n - PREFIX, &mut t.eq, &mut ds, &mut ai, t.sum);
    t.point.append(&mut proof.r);
    proof.r = t.point;
    proof
}

pub fn theta_d(p: &mut Prover, n: usize, r: &[Fr], b: &[Fr], c: &[u64], sum: Fr) -> ThetaDProof {
    let mut source = columns(c, n);
    source.extend(columns(c, n).into_iter().map(|(lane, _)| (lane, 1)));
    let terms = (0..5)
        .map(|j| {
            term(
                vec![Factor((j + 4) % 5, Sign), Factor(5 + (j + 1) % 5, Sign)],
                b[j],
            )
        })
        .collect();
    let mut t = reduce(p, source, terms, r, None, 3, sum);
    signs(&mut t.polys);
    let mut rot = t.polys.split_off(5);
    let mut proof =
        prove_sumcheck_theta_d(p, n - PREFIX, b, &mut t.eq, &mut t.polys, &mut rot, t.sum);
    t.point.append(&mut proof.r);
    proof.r = t.point;
    proof
}

pub fn theta_c(
    p: &mut Prover,
    n: usize,
    r: &[Fr],
    b: &[Fr],
    rot_b: &[Fr],
    a: &[u64],
    sum: Fr,
) -> ThetaCProof {
    let terms = (0..5)
        .map(|x| Term {
            factors: (0..5).map(|y| Factor(5 * y + x, Sign)).collect(),
            first: b[x],
            second: rot_b[x],
        })
        .collect();
    let mut t = reduce(p, columns(a, n), terms, r, Some((r, true)), 6, sum);
    signs(&mut t.polys);
    let mut proof = prove_sumcheck_theta_c(
        p,
        n - PREFIX,
        b,
        rot_b,
        &mut t.eq,
        &mut t.other,
        &mut t.polys,
        t.sum,
    );
    t.point.append(&mut proof.r);
    proof.r = t.point;
    proof
}

pub fn theta_a(
    p: &mut Prover,
    n: usize,
    r1: &[Fr],
    r2: &[Fr],
    b1: &[Fr],
    b2: &[Fr],
    a: &[u64],
    sum: Fr,
) -> ThetaAProof {
    let terms = (0..25)
        .map(|j| Term {
            factors: vec![Factor(j, Sign)],
            first: b1[j],
            second: b2[j],
        })
        .collect();
    let mut t = reduce(p, columns(a, n), terms, r1, Some((r2, false)), 2, sum);
    signs(&mut t.polys);
    let mut proof = prove_sumcheck_theta_a(
        p,
        n - PREFIX,
        b1,
        b2,
        &mut t.eq,
        &mut t.other,
        &mut t.polys,
        t.sum,
    );
    t.point.append(&mut proof.r);
    proof.r = t.point;
    proof
}
