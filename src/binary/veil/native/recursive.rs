//! Constrain the same trusted upstream AIR transcript schedule and affine
//! reduction used by the native masked child verifier.
use anyhow::{Result, ensure};
use p3_circuit::CircuitBuilder;
use p3_circuit::ops::NativePoly192Target;
use p3_field::{Field, PrimeCharacteristicRing};
use p3_sumcheck::generic_degree::RoundPolyInterpolator;

use super::{NativeAirProgram, Operation};
use crate::binary::veil::{
    E, F,
    compiler::recursive::{CircuitReader, LinearTarget, constant},
};

pub(in crate::binary::veil) struct AirReductionTarget {
    pub alpha: NativePoly192Target,
    pub tau: Vec<NativePoly192Target>,
    pub point: Vec<NativePoly192Target>,
    pub claim: LinearTarget,
}

impl NativeAirProgram {
    pub(in crate::binary::veil) fn replay_circuit(
        &self,
        b: &mut CircuitBuilder<F>,
        reader: &mut CircuitReader<'_>,
    ) -> Result<AirReductionTarget> {
        let mut messages = Vec::new();
        let mut challenges = Vec::new();
        for operation in &self.operations {
            match *operation {
                Operation::Public(value) => {
                    let value = constant(b, E::from(value));
                    reader.transcript.fields(b, b"native-public", &[value])?;
                }
                Operation::Message(count) => {
                    messages.push(reader.read(b, b"native-message", count)?)
                }
                Operation::Challenge => challenges.push(reader.challenge(b, b"native-challenge")?),
            }
        }
        ensure!(
            messages.len() == self.rounds && challenges.len() == 2 + 2 * self.rounds,
            "wrong AIR circuit schedule"
        );
        let weights = self.round_weight_polynomials();
        let mut claim = LinearTarget::constant(constant(b, E::ZERO));
        let point = challenges[2 + self.rounds..].to_vec();
        for (message, r) in messages.iter().zip(&point) {
            let weight = evaluate(b, &weights[0], r);
            claim = claim.scale(b, &weight);
            for (value, polynomial) in message.iter().zip(&weights[1..]) {
                let weight = evaluate(b, polynomial, r);
                let term = value.scale(b, &weight);
                claim = claim.add(b, &term);
            }
        }
        Ok(AirReductionTarget {
            alpha: challenges[0].clone(),
            tau: challenges[2..2 + self.rounds].to_vec(),
            point,
            claim,
        })
    }
}

impl NativeAirProgram {
    /// Polynomial coefficients for the previous claim and each transmitted round value.
    /// The order is the same as in the native verifier's affine reduction.
    pub fn round_weight_polynomials(&self) -> Vec<Vec<E>> {
        weight_polynomials(self.degree)
    }
}

/// Recover the pinned interpolator's degree-d polynomials at setup time.
/// All inversions involve distinct trusted constants. Circuit evaluation is
/// polynomial, so challenges equal to interpolation nodes also work exactly.
fn weight_polynomials(degree: usize) -> Vec<Vec<E>> {
    let interpolator = RoundPolyInterpolator::<E>::new(degree);
    let nodes: Vec<E> = (0..=degree).map(|i| E::from(F::new(i as u64))).collect();
    let mut lagrange = Vec::new();
    for (i, &x) in nodes.iter().enumerate() {
        let mut poly = vec![E::ONE];
        let mut denominator = E::ONE;
        for (j, &y) in nodes.iter().enumerate() {
            if i == j {
                continue;
            }
            let mut next = vec![E::ZERO; poly.len() + 1];
            for (k, &c) in poly.iter().enumerate() {
                next[k] += c * y;
                next[k + 1] += c;
            }
            poly = next;
            denominator *= x + y;
        }
        for c in &mut poly {
            *c *= denominator.inverse();
        }
        lagrange.push(poly);
    }
    (0..=degree)
        .map(|source| {
            let mut message = vec![E::ZERO; degree];
            let claim = if source == 0 {
                E::ONE
            } else {
                message[source - 1] = E::ONE;
                E::ZERO
            };
            let mut result = vec![E::ZERO; degree + 1];
            for (&node, poly) in nodes.iter().zip(&lagrange) {
                let value = interpolator.eval(&message, claim, node);
                for (target, &c) in result.iter_mut().zip(poly) {
                    *target += c * value;
                }
            }
            result
        })
        .collect()
}

fn evaluate(
    b: &mut CircuitBuilder<F>,
    coefficients: &[E],
    point: &NativePoly192Target,
) -> NativePoly192Target {
    let mut result = constant(b, E::ZERO);
    for &coefficient in coefficients.iter().rev() {
        let scaled = b.native_poly192_mul(&result, point);
        let coefficient = constant(b, coefficient);
        result = b.native_poly192_add(&scaled, &coefficient);
    }
    result
}

#[cfg(test)]
mod tests;
