//! A nibble has three moment openings, for d, d^3 and d^4. Every monomial through
//! degree sixteen is a product of at most four of these moments on the Boolean cube.
use ark_ff::{AdditiveGroup, Field};
use whir::algebra::fields::Field192 as F;

pub type Moment = [F; 3];
pub fn moments(d: F) -> Moment {
    let d2 = d * d;
    [d, d * d2, d2 * d2]
}
fn monomials([a, b, c]: Moment) -> [F; 17] {
    let a2 = a * a;
    let b2 = b * b;
    let c2 = c * c;
    let c3 = c * c2;
    [
        F::ONE,
        a,
        a2,
        b,
        c,
        a * c,
        b2,
        b * c,
        c2,
        a * c2,
        b2 * c,
        b * c2,
        c3,
        a * c3,
        b2 * c2,
        b * c3,
        c2 * c2,
    ]
}
fn multiply_linear(p: &[F; 17], r: F) -> [F; 17] {
    std::array::from_fn(|i| {
        if i == 0 {
            -r * p[0]
        } else {
            p[i - 1] - r * p[i]
        }
    })
}
fn bit_polynomial(weights: &[F]) -> [F; 17] {
    let mut h = [F::ZERO; 17];
    for k in 0..16u8 {
        let value: F = (0..4)
            .filter(|i| (k >> i) & 1 == 1)
            .map(|i| weights[i as usize])
            .sum();
        if value == F::ZERO {
            continue;
        }
        let mut basis = [F::ZERO; 17];
        basis[0] = F::ONE;
        let mut den = F::ONE;
        for j in 0..16u8 {
            if j != k {
                basis = multiply_linear(&basis, F::from(j));
                den *= F::from(k) - F::from(j);
            }
        }
        let scale = value / den;
        for (y, b) in h.iter_mut().zip(basis) {
            *y += scale * b;
        }
    }
    h
}
pub struct Gate {
    coeff: [[F; 17]; 3],
}
impl Gate {
    pub fn new(input: &[F], output: &[F]) -> Self {
        Self::with_weights(
            &whir::algebra::eq_weights(input),
            &whir::algebra::eq_weights(output),
        )
    }
    pub fn with_weights(input: &[F], output: &[F]) -> Self {
        let mut v = [F::ZERO; 17];
        v[0] = F::ONE;
        for j in 0..16u8 {
            v = multiply_linear(&v, F::from(j));
        }
        Self {
            coeff: [bit_polynomial(input), bit_polynomial(output), v],
        }
    }
    pub fn values(&self, m: Moment) -> [F; 4] {
        let basis = monomials(m);
        let terms = self
            .coeff
            .each_ref()
            .map(|coeff| coeff.iter().zip(&basis).map(|(x, y)| *x * y).sum());
        [terms[0], terms[1], terms[2], m[0]]
    }
}
