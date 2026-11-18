//! Preserve raw Poly64 transcript coordinates across the two pinned Plonky3 versions.
use old_binary_field::Poly64;
use p3_challenger::{CanObserve, CanSample, CanSampleBits, FieldChallenger, GrindingChallenger};

use p3_sumcheck::ring_switch::bits::transcript::{BitRingSwitchClaimsShape, BitRingSwitchShape};

use crate::F;
use crate::checkpoint_keccak::E;

pub(crate) struct Bridge<'a, C>(pub &'a mut C);
struct Seed(Vec<F>);

impl<C: old_challenger::CanObserve<Poly64>> CanObserve<F> for Bridge<'_, C> {
    fn observe(&mut self, value: F) {
        self.0.observe(Poly64::new(value.to_bits()));
    }
}

impl<C: old_challenger::CanSample<Poly64>> CanSample<F> for Bridge<'_, C> {
    fn sample(&mut self) -> F {
        F::new(self.0.sample().to_bits())
    }
}

impl<C: old_challenger::CanSampleBits<usize>> CanSampleBits<usize> for Bridge<'_, C> {
    fn sample_bits(&mut self, bits: usize) -> usize {
        self.0.sample_bits(bits)
    }
}

impl<C: old_challenger::FieldChallenger<Poly64>> FieldChallenger<F> for Bridge<'_, C> {}

impl<C: old_challenger::GrindingChallenger<Witness = Poly64>> GrindingChallenger for Bridge<'_, C> {
    type Witness = F;

    fn grind(&mut self, bits: usize) -> F {
        F::new(self.0.grind(bits).to_bits())
    }

    fn check_witness(&mut self, bits: usize, witness: F) -> bool {
        self.0.check_witness(bits, Poly64::new(witness.to_bits()))
    }
}

impl CanObserve<F> for Seed {
    fn observe(&mut self, value: F) {
        self.0.push(value);
    }
}

pub(crate) fn deferred_seed(variables: usize, claims: usize) -> Vec<Poly64> {
    let shape = BitRingSwitchClaimsShape {
        claims: vec![BitRingSwitchShape::new(variables); claims],
        deferred: true,
    };
    let mut seed = Seed(Vec::new());
    shape.domain_separator::<F, E>().seed(&mut seed);
    seed.0
        .into_iter()
        .map(|v| Poly64::new(v.to_bits()))
        .collect()
}
