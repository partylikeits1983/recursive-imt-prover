//! Reduce k current Boolean readings to one before the bit ring switch.
//! For B(z) the bit polynomial, sum over the cube B(z) * Σ alpha^i eq(p_i,z).
//! Each round has individual degree two. The last six coordinates (bits in a
//! packed word) are bound first, then the high coordinates in natural order.
use anyhow::{Result, ensure};
use p3_binary_field::Poly192 as E;
use p3_challenger::{CanObserve, FieldChallenger};
use p3_field::PrimeCharacteristicRing;
use p3_maybe_rayon::prelude::*;
use p3_multilinear_util::{point::Point, poly::Poly};
use serde::{Deserialize, Serialize};

use crate::{F, config::Challenger};

#[derive(Serialize, Deserialize)]
pub(super) struct BatchProof {
    pub(super) rounds: Vec<[E; 2]>,
    pub(super) value: E,
}

pub(super) struct Claims<'a> {
    pub(super) points: &'a [Point<E>],
    pub(super) values: &'a [E],
    pub(super) variables: usize,
}

impl Claims<'_> {
    fn bind(&self, ch: &mut Challenger) -> Result<(Vec<E>, E)> {
        ensure!(
            (7..=32).contains(&self.variables)
                && !self.points.is_empty()
                && self.points.len() == self.values.len()
                && self
                    .points
                    .iter()
                    .all(|p| p.num_variables() == self.variables),
            "invalid bit batching statement"
        );
        // Fixed encoding and lengths delimit every transcript item.
        for word in b"imt-boolean-reading-sumcheck-v01".as_chunks::<8>().0 {
            ch.observe(F::new(u64::from_le_bytes(*word)));
        }
        ch.observe(F::new(self.variables as u64));
        ch.observe(F::new(self.points.len() as u64));
        for (p, v) in self.points.iter().zip(self.values) {
            ch.observe_algebra_slice(p.as_slice());
            ch.observe_algebra_element(*v);
        }
        let alpha: E = ch.sample_algebra_element();
        let powers: Vec<_> = alpha.powers().take(self.points.len()).collect();
        let sum = self.values.iter().zip(&powers).map(|(&v, &w)| v * w).sum();
        Ok((powers, sum))
    }

    pub(super) fn verify(&self, proof: &BatchProof, ch: &mut Challenger) -> Result<Point<E>> {
        ensure!(
            proof.rounds.len() == self.variables,
            "wrong bit batching round count"
        );
        let (weights, mut running) = self.bind(ch)?;
        let mut draws = vec![];
        for &message in &proof.rounds {
            let r = draw(ch, message);
            running = evaluate(running, message, r);
            draws.push(r);
        }
        let point = Point::new([&draws[6..], &draws[..6]].concat());
        let weight: E = self
            .points
            .iter()
            .zip(weights)
            .map(|(p, w)| w * Point::eval_eq(p.as_slice(), point.as_slice()))
            .sum();
        ensure!(
            running == weight * proof.value,
            "incorrect batched bit endpoint"
        );
        ch.observe_algebra_element(proof.value);
        Ok(point)
    }
}

fn draw(ch: &mut Challenger, message: [E; 2]) -> E {
    ch.observe_algebra_slice(&message);
    ch.sample_algebra_element()
}
fn evaluate(sum: E, [zero, inf]: [E; 2], r: E) -> E {
    zero + r * (sum + (E::ONE + r) * inf)
}

struct Product {
    f: Vec<E>,
    g: Vec<E>,
}
impl Product {
    fn message(&self) -> [E; 2] {
        let (a, b) = self.f.split_at(self.f.len() / 2);
        let (x, y) = self.g.split_at(self.g.len() / 2);
        let at = |i: usize| [a[i] * x[i], (a[i] + b[i]) * (x[i] + y[i])];
        let add = |[a, b]: [E; 2], [c, d]: [E; 2]| [a + c, b + d];
        if a.len() < 1024 {
            (0..a.len()).map(at).fold([E::ZERO; 2], add)
        } else {
            (0..a.len())
                .into_par_iter()
                .map(at)
                .reduce(|| [E::ZERO; 2], add)
        }
    }
    fn fold(&mut self, r: E) {
        for v in [&mut self.f, &mut self.g] {
            let half = v.len() / 2;
            let (lo, hi) = v.split_at_mut(half);
            let update = |(a, b): (&mut E, &E)| *a += r * (*a + *b);
            if half < 1024 {
                lo.iter_mut().zip(hi.iter()).for_each(update);
            } else {
                lo.par_iter_mut().zip(hi.par_iter()).for_each(update);
            }
            v.truncate(half);
        }
    }
}

// Expand an equality weight onto its support. Selector coordinates fixed to
// zero or one skip a whole branch, including the two pinned commitment faces.
fn add_eq(out: &mut [E], p: &[E], scale: E) {
    if p.is_empty() {
        out[0] += scale;
        return;
    }
    if scale == E::ZERO {
        return;
    }
    let mid = out.len() / 2;
    let (low, high) = out.split_at_mut(mid);
    if p[0] == E::ZERO {
        add_eq(low, &p[1..], scale);
        return;
    }
    if p[0] == E::ONE {
        add_eq(high, &p[1..], scale);
        return;
    }
    if p.len() <= 12 {
        let terms = Poly::new_from_point_over::<F>(p, scale);
        for (o, t) in out.iter_mut().zip(terms.as_slice()) {
            *o += *t;
        }
        return;
    }
    let right = scale * p[0];
    join(
        || add_eq(low, &p[1..], scale + right),
        || add_eq(high, &p[1..], right),
    );
}

/// planes[i][b] is B(p_i.high, b). It is used only by the prover and implicit
/// in the low sumcheck messages. The verifier recomputes the final public
/// weight and requires a separate authenticated bit PCS reading at the endpoint.
pub(super) fn prove(
    claims: &Claims<'_>,
    words: &[F],
    planes: &[Vec<E>],
    ch: &mut Challenger,
) -> Result<(BatchProof, Point<E>)> {
    let (powers, mut running) = claims.bind(ch)?;
    let n = claims.variables - 6;
    ensure!(
        words.len() == 1 << n
            && planes.len() == powers.len()
            && planes.iter().all(|v| v.len() == 64),
        "wrong bit prover hint shape"
    );
    let mut low: Vec<_> = planes
        .iter()
        .zip(claims.points)
        .zip(&powers)
        .map(|((planes, p), &scale)| Product {
            f: planes.clone(),
            g: Poly::new_from_point(&p.as_slice()[n..], scale).into_evals(),
        })
        .collect();
    let mut rounds = vec![];
    let mut low_point = vec![];
    for _ in 0..6 {
        let msg = low
            .iter()
            .map(Product::message)
            .fold([E::ZERO; 2], |[a, b], [c, d]| [a + c, b + d]);
        let r = draw(ch, msg);
        running = evaluate(running, msg, r);
        rounds.push(msg);
        low_point.push(r);
        for p in &mut low {
            p.fold(r);
        }
    }
    let eq = Poly::new_from_point(&low_point, E::ONE);
    let mut lut = [[E::ZERO; 256]; 8];
    for (byte, table) in lut.iter_mut().enumerate() {
        for i in 1..256usize {
            table[i] = table[i & (i - 1)] + eq.as_slice()[8 * byte + i.trailing_zeros() as usize];
        }
    }
    let f = words
        .par_iter()
        .map(|word| {
            word.to_bits()
                .to_le_bytes()
                .into_iter()
                .enumerate()
                .fold(E::ZERO, |v, (j, b)| v + lut[j][b as usize])
        })
        .collect();
    let mut g = E::zero_vec(words.len());
    for (p, low) in claims.points.iter().zip(low) {
        add_eq(&mut g, &p.as_slice()[..n], low.g[0]);
    }
    let mut high = Product { f, g };
    let mut point = vec![];
    for _ in 0..n {
        let msg = high.message();
        let r = draw(ch, msg);
        running = evaluate(running, msg, r);
        rounds.push(msg);
        point.push(r);
        high.fold(r);
    }
    ensure!(
        running == high.f[0] * high.g[0],
        "inconsistent private bit evaluation"
    );
    let value = high.f[0];
    ch.observe_algebra_element(value);
    point.extend(low_point);
    Ok((BatchProof { rounds, value }, Point::new(point)))
}
