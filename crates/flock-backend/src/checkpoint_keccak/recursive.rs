//! Fixed-width Keccak GKR replay. Callers must authenticate both PCS boundaries.
use anyhow::{Result, ensure};
use old_binary_field::Poly64 as CF;
use p3_challenger::{FieldChallenger, GrindingChallenger};
use p3_circuit::ops::binary_encoding::NativeBinaryEncoding;
use p3_circuit::{CircuitBuilder, ExprId, ops::NativePoly192Target};
use p3_recursion::{
    BinaryTower128Challenger,
    pcs::binary::{BinaryPolyGenericSumcheckProofTargets, BinaryPolyGenericSumcheckVerifier},
};
use sha3::{Digest, Keccak256};

use super::{
    BITS, Claim, F, POSITION_LOG, Proof, RC, RECURSIVE_DOMAIN, ROUNDS, State, Transcript,
    algebraic_error_degree, linear, prove_using, verify_using,
};

mod weights;
use weights::Weights;

#[derive(Clone)]
pub struct ClaimTarget {
    pub instance: Vec<NativePoly192Target>,
    pub weights: Vec<NativePoly192Target>,
    pub value: NativePoly192Target,
}

pub struct ProofTargets {
    layers: Vec<LayerTargets>,
}

struct LayerTargets {
    sumcheck: BinaryPolyGenericSumcheckProofTargets<NativePoly192Target, ExprId>,
    values: [NativePoly192Target; 3],
}

pub struct Reduction {
    pub claim: ClaimTarget,
    pub challenger: BinaryTower128Challenger,
}

pub struct PreparedVerifier {
    log_batch: usize,
    sumcheck: BinaryPolyGenericSumcheckVerifier,
}

/// Use the recursive transcript; existing v1 aggregate proofs are unchanged.
pub fn prove<C>(inputs: &[State], output: &Claim, ch: &mut C) -> Result<(Proof, Claim)>
where
    C: FieldChallenger<F> + GrindingChallenger<Witness = F>,
{
    prove_using(inputs, output, ch, Transcript::FixedV2)
}

pub fn verify<C>(proof: &Proof, output: &Claim, log_batch: usize, ch: &mut C) -> Result<Claim>
where
    C: FieldChallenger<F> + GrindingChallenger<Witness = F>,
{
    verify_using(proof, output, log_batch, ch, Transcript::FixedV2)
}

impl PreparedVerifier {
    pub fn new(log_batch: usize) -> Result<Self> {
        algebraic_error_degree(log_batch)?;
        Ok(Self {
            log_batch,
            sumcheck: BinaryPolyGenericSumcheckVerifier::new(log_batch + POSITION_LOG, 3, 0)?,
        })
    }

    pub fn allocate(&self, b: &mut CircuitBuilder<CF>) -> Result<ProofTargets> {
        let mut layers = Vec::with_capacity(ROUNDS);
        for _ in 0..ROUNDS {
            let sumcheck = self.sumcheck.input_shape().allocate_native_targets(b)?;
            let values = core::array::from_fn(|_| {
                let coefficients = b.alloc_private_input_array::<3>("Keccak GKR endpoint");
                b.native_poly192_from_coefficients(coefficients)
            });
            layers.push(LayerTargets { sumcheck, values });
        }
        b.check_construction_limits()?;
        Ok(ProofTargets { layers })
    }

    /// Shape-check and import proof messages, without trusting a native verifier.
    pub fn private_values(&self, proof: &Proof) -> Result<Vec<CF>> {
        ensure!(
            proof.layers.len() == ROUNDS,
            "incorrect Keccak GKR layer count"
        );
        let mut values = Vec::new();
        for layer in &proof.layers {
            let p = &layer.sumcheck;
            ensure!(
                p.round_polys.len() == self.log_batch + POSITION_LOG
                    && p.round_polys.iter().all(|p| p.len() == 3)
                    && p.pow_witnesses.is_empty(),
                "incorrect Keccak GKR sumcheck shape"
            );
            for value in core::iter::once(&p.claimed_sum)
                .chain(p.round_polys.iter().flatten())
                .chain(&layer.values)
            {
                values.extend(value.coefficients().map(|c| CF::new(c.to_bits())));
            }
        }
        Ok(values)
    }

    pub fn verify_reduction(
        &self,
        b: &mut CircuitBuilder<CF>,
        mut ch: BinaryTower128Challenger,
        output: &ClaimTarget,
        proof: &ProofTargets,
    ) -> Result<Reduction> {
        ensure!(
            output.instance.len() == self.log_batch,
            "incorrect Keccak claim point"
        );
        ensure!(output.weights.len() == BITS, "incorrect Keccak bit weights");
        ensure!(
            proof.layers.len() == ROUNDS,
            "incorrect Keccak GKR layer count"
        );
        let digest = Keccak256::digest(RECURSIVE_DOMAIN);
        for bytes in digest.as_chunks::<8>().0 {
            let seed = b.define_const(CF::new(u64::from_le_bytes(*bytes)));
            observe_base(b, &mut ch, seed)?;
        }
        let log = b.define_const(CF::new(self.log_batch as u64));
        observe_base(b, &mut ch, log)?;
        for value in output
            .instance
            .iter()
            .chain(&output.weights)
            .chain([&output.value])
        {
            observe(b, &mut ch, value)?;
        }
        let one = b.native_poly192_constant([1, 0, 0]);
        let mut instance = output.instance.clone();
        let mut value = output.value.clone();
        let mut weights = Weights::Dense(output.weights.clone());
        for (round, layer) in (0..ROUNDS).rev().zip(&proof.layers) {
            let round_value = b.define_const(CF::new(round as u64));
            observe_base(b, &mut ch, round_value)?;
            let iota = weights.iota(b, RC[round]);
            let expected = b.native_poly192_add(&value, &iota);
            let reduced =
                self.sumcheck
                    .verify_reduction_native(b, ch, &expected, &layer.sumcheck)?;
            ch = reduced.challenger;
            let (next_instance, position) = reduced.point.split_at(self.log_batch);
            let mut eq = one.clone();
            for (a, c) in instance.iter().zip(next_instance) {
                let sum = b.native_poly192_add(a, c);
                let factor = b.native_poly192_add(&one, &sum);
                eq = b.native_poly192_mul(&eq, &factor);
            }
            let weight = weights.evaluate(b, position);
            let [a, c, d] = &layer.values;
            let product = b.native_poly192_mul(c, d);
            let sum = b.native_poly192_add(a, d);
            let chi = b.native_poly192_add(&sum, &product);
            let scale = b.native_poly192_mul(&eq, &weight);
            let terminal = b.native_poly192_mul(&scale, &chi);
            connect(b, &terminal, &reduced.claim);
            for value in &layer.values {
                observe(b, &mut ch, value)?;
            }
            let beta = sample(b, &mut ch)?;
            let square = b.native_poly192_square(&beta);
            weights = Weights::linear_chi(b, position, &beta, &square);
            let second = b.native_poly192_mul(&beta, c);
            let third = b.native_poly192_mul(&square, d);
            let sum = b.native_poly192_add(a, &second);
            value = b.native_poly192_add(&sum, &third);
            instance = next_instance.to_vec();
            b.check_construction_limits()?;
        }
        Ok(Reduction {
            claim: ClaimTarget {
                instance,
                weights: weights.expand(b),
                value,
            },
            challenger: ch,
        })
    }
}

fn equality_weights(
    b: &mut CircuitBuilder<CF>,
    point: &[NativePoly192Target],
) -> Vec<NativePoly192Target> {
    let one = b.native_poly192_constant([1, 0, 0]);
    let mut weights = vec![one.clone()];
    for r in point {
        let complement = b.native_poly192_add(&one, r);
        weights = weights
            .iter()
            .flat_map(|w| {
                [
                    b.native_poly192_mul(w, &complement),
                    b.native_poly192_mul(w, r),
                ]
            })
            .collect();
    }
    weights
}

fn connect(b: &mut CircuitBuilder<CF>, a: &NativePoly192Target, c: &NativePoly192Target) {
    for (&a, &c) in a.coefficients().iter().zip(c.coefficients()) {
        b.connect(a, c);
    }
}

fn observe_base(
    b: &mut CircuitBuilder<CF>,
    ch: &mut BinaryTower128Challenger,
    value: ExprId,
) -> Result<()> {
    let words = b.native_poly64_unchecked_words(value, 4)?;
    ch.observe_words_with_host::<NativeBinaryEncoding, CF>(b, &words)?;
    Ok(())
}

fn observe(
    b: &mut CircuitBuilder<CF>,
    ch: &mut BinaryTower128Challenger,
    value: &NativePoly192Target,
) -> Result<()> {
    for &coefficient in value.coefficients() {
        observe_base(b, ch, coefficient)?;
    }
    Ok(())
}

fn sample(
    b: &mut CircuitBuilder<CF>,
    ch: &mut BinaryTower128Challenger,
) -> Result<NativePoly192Target> {
    let words = ch.sample_words_with_host::<NativeBinaryEncoding, CF>(b, 12)?;
    let mut coefficients = [ExprId::ZERO; 3];
    for (coefficient, words) in coefficients.iter_mut().zip(words.as_chunks::<4>().0) {
        *coefficient = b.native_poly64_from_unchecked_words(*words)?;
    }
    Ok(b.native_poly192_from_coefficients(coefficients))
}

#[cfg(test)]
mod tests;
