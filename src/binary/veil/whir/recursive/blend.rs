//! Constrain the functional sumcheck and its actual WHIR terminal opening.
//! The verified WHIR continuation is sealed into the enclosing transcript.
use anyhow::{Result, ensure};
use p3_circuit::ops::NativePoly192Target;
use p3_circuit::{CircuitBuilder, ExprId};
use p3_field::BasedVectorSpace;

use super::{PreparedWhir, Targets, transcript::CircuitTranscript};
use crate::binary::veil::{
    E, F,
    parameters::Parameters,
    transcript::Transcript,
    whir::{BlendFunctional, BlendOpening, bind},
};

pub(in crate::binary::veil) struct PreparedBlend {
    whir: PreparedWhir,
    length: usize,
}

pub(in crate::binary::veil) struct BlendTargets {
    rounds: Vec<[NativePoly192Target; 2]>,
    value: NativePoly192Target,
    pcs: Targets,
}

pub(in crate::binary::veil) trait CircuitFunctional {
    fn length(&self) -> usize;
    fn bind(
        &self,
        builder: &mut CircuitBuilder<F>,
        transcript: &mut CircuitTranscript,
    ) -> Result<()>;
    fn evaluate(
        &self,
        builder: &mut CircuitBuilder<F>,
        point: &[NativePoly192Target],
    ) -> Result<NativePoly192Target>;
}

impl PreparedBlend {
    pub fn new(length: usize, parameters: &Parameters) -> Result<Self> {
        Ok(Self {
            whir: PreparedWhir::new(length, parameters)?,
            length,
        })
    }

    pub fn allocate(&self, builder: &mut CircuitBuilder<F>) -> Result<BlendTargets> {
        let rounds = (0..self.length.ilog2())
            .map(|_| std::array::from_fn(|_| allocate_field(builder)))
            .collect();
        Ok(BlendTargets {
            rounds,
            value: allocate_field(builder),
            pcs: self.whir.allocate(builder)?,
        })
    }

    pub fn import<W: BlendFunctional + ?Sized>(
        &self,
        proof: &BlendOpening,
        root: &[u8; 32],
        weights: &W,
        sum: E,
        mut transcript: Transcript,
    ) -> Result<Vec<F>> {
        ensure!(weights.length() == self.length, "wrong functional length");
        ensure!(
            proof.rounds.len() == self.length.ilog2() as usize,
            "wrong sumcheck round count"
        );
        bind(&mut transcript, root, weights, sum)?;
        let mut private = Vec::new();
        let mut point = Vec::with_capacity(proof.rounds.len());
        for round in &proof.rounds {
            for value in round {
                private.extend_from_slice(value.as_basis_coefficients_slice());
            }
            transcript.fields(b"blend-sumcheck-round", round);
            point.push(transcript.challenge(b"blend-sumcheck-challenge")?);
        }
        private.extend_from_slice(proof.value.as_basis_coefficients_slice());
        transcript.fields(b"blend-sumcheck-terminal", &[proof.value]);
        private.extend(
            self.whir
                .import(&transcript.fingerprint(), root, &point, &proof.pcs)?,
        );
        Ok(private)
    }

    pub fn verify<W: CircuitFunctional + ?Sized>(
        &self,
        builder: &mut CircuitBuilder<F>,
        root: &[ExprId; 32],
        weights: &W,
        sum: &NativePoly192Target,
        proof: &BlendTargets,
        mut transcript: CircuitTranscript,
    ) -> Result<CircuitTranscript> {
        ensure!(weights.length() == self.length, "wrong functional length");
        ensure!(
            proof.rounds.len() == self.length.ilog2() as usize,
            "wrong sumcheck round count"
        );
        transcript.bytes(builder, b"blend-whir-commitment", root)?;
        weights.bind(builder, &mut transcript)?;
        transcript.fields(builder, b"blend-functional-sum", std::slice::from_ref(sum))?;
        let mut claim = sum.clone();
        let mut point = Vec::with_capacity(proof.rounds.len());
        for [c0, cinf] in &proof.rounds {
            transcript.fields(
                builder,
                b"blend-sumcheck-round",
                &[c0.clone(), cinf.clone()],
            )?;
            let r = transcript.challenge(builder, b"blend-sumcheck-challenge")?;
            // Evaluation-basis identity in characteristic two:
            // h(r) = h(0) + r*C + r(r+1)*h(infinity).
            let r_squared = builder.native_poly192_square(&r);
            let r_product = builder.native_poly192_add(&r_squared, &r);
            let quadratic = builder.native_poly192_mul(&r_product, cinf);
            let linear = builder.native_poly192_mul(&r, &claim);
            let subtotal = builder.native_poly192_add(c0, &linear);
            claim = builder.native_poly192_add(&subtotal, &quadratic);
            point.push(r);
        }
        let weight = weights.evaluate(builder, &point)?;
        let terminal = builder.native_poly192_mul(&proof.value, &weight);
        connect(builder, &claim, &terminal);
        transcript.fields(
            builder,
            b"blend-sumcheck-terminal",
            std::slice::from_ref(&proof.value),
        )?;
        let value =
            self.whir
                .verify(builder, transcript.fingerprint(), root, &point, &proof.pcs)?;
        connect(builder, &proof.value, &value.value);
        transcript.bytes(builder, b"blend-whir-seal-v3", &value.seal)?;
        Ok(transcript)
    }
}

impl CircuitFunctional for Vec<NativePoly192Target> {
    fn length(&self) -> usize {
        self.len()
    }

    fn bind(
        &self,
        builder: &mut CircuitBuilder<F>,
        transcript: &mut CircuitTranscript,
    ) -> Result<()> {
        transcript.fields(builder, b"blend-functional-weights", self)
    }

    fn evaluate(
        &self,
        builder: &mut CircuitBuilder<F>,
        point: &[NativePoly192Target],
    ) -> Result<NativePoly192Target> {
        ensure!(
            self.len().is_power_of_two() && self.len().ilog2() as usize == point.len(),
            "wrong functional point arity"
        );
        let mut values = self.clone();
        for r in point {
            let half = values.len() / 2;
            for i in 0..half {
                let delta = builder.native_poly192_add(&values[i], &values[i + half]);
                let increment = builder.native_poly192_mul(&delta, r);
                values[i] = builder.native_poly192_add(&values[i], &increment);
            }
            values.truncate(half);
        }
        Ok(values[0].clone())
    }
}

fn allocate_field(builder: &mut CircuitBuilder<F>) -> NativePoly192Target {
    let coefficients = std::array::from_fn(|_| builder.alloc_private_input("blend-field"));
    builder.native_poly192_from_coefficients(coefficients)
}

fn connect(
    builder: &mut CircuitBuilder<F>,
    actual: &NativePoly192Target,
    expected: &NativePoly192Target,
) {
    for (&a, &b) in actual.coefficients().iter().zip(expected.coefficients()) {
        builder.connect(a, b);
    }
}

#[cfg(test)]
mod tests;
