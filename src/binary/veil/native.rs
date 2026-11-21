//! Transcript boundary for the pinned native AIR prover. This does not make an
//! ordinary `ZerocheckProof` safe to publish: its round polynomials and openings
//! remain private. The caller must compile the verifier and authenticate every
//! terminal claim with the hiding oracle adapter.
//!
//! The public upstream drivers describe the exact base-field interaction stream.
//! We retain public framing, group private observations into Poly192 messages,
//! and split each masked-transcript challenge back into its three Poly64 limbs.
//! Unexpected framing, limb counts, grinding or bit sampling fail closed.

use std::{cell::RefCell, rc::Rc};

use anyhow::{Result, ensure};
use p3_challenger::{CanObserve, CanSample, CanSampleBits, FieldChallenger, GrindingChallenger};
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};
use p3_multi_stark::zerocheck::transcript::{ZerocheckProverTranscript, ZerocheckShape};
use p3_sumcheck::generic_degree::{GenericDegreeShape, ProverTranscript, RoundPolyInterpolator};
use serde::Serialize;

use super::{E, F, constraints::Linear};

#[cfg(test)]
mod tests;

pub(super) mod recursive;

/// A trusted program generated from verifier geometry, never from proof bytes.
pub struct NativeAirProgram {
    operations: Vec<Operation>,
    messages: usize,
    rounds: usize,
    degree: usize,
}

#[derive(Clone, Debug, Serialize)]
pub enum Operation {
    Public(F),
    Message(usize),
    Challenge,
}

/// Implementations must commit their masks before the first call to `message`.
/// The callbacks receive whole extension elements, not separately masked limbs.
pub trait NativeProverContext: Sync {
    fn public(&mut self, value: F) -> Result<()>;
    fn message(&mut self, values: &[E]) -> Result<()>;
    fn challenge(&mut self) -> Result<E>;
}

/// Same public transcript schedule, with opaque hidden values supplied by the
/// compiler's reader. This interface performs no native accept/reject shortcut.
pub trait NativeVerifierContext {
    type Hidden;
    fn public(&mut self, value: F) -> Result<()>;
    fn message(&mut self, count: usize) -> Result<Vec<Self::Hidden>>;
    fn challenge(&mut self) -> Result<E>;
}

pub struct NativeReplay<T> {
    pub messages: Vec<Vec<T>>,
    pub challenges: Vec<E>,
}

/// Affine reduced claim. A caller must constrain it to the AIR evaluated at
/// `point`, weighted by eq(`tau`, `point`), and authenticate all private inputs
/// of that evaluation. Returning this reduction alone proves no AIR statement.
pub struct NativeAirReduction {
    pub alpha: E,
    pub beta: E,
    pub tau: Vec<E>,
    pub point: Vec<E>,
    pub claim: Linear,
}

/// A view of the same committed column. `Next` uses MultiStark's repeat-last
/// successor convention, rather than a cyclic shift or a second commitment.
pub enum OraclePoint<'a> {
    Current(&'a [E]),
    Next(&'a [E]),
}

/// Borrow one committed-mask context for the duration of the actual upstream
/// AIR prover. The upstream prover retains ordinary private arithmetic values.
pub struct NativeProver<'a, C> {
    program: &'a NativeAirProgram,
    context: &'a mut C,
    cursor: usize,
    limbs: Vec<F>,
    sampled: [F; 3],
    sample_cursor: usize,
}

#[derive(Default)]
struct Recording {
    operations: Vec<Operation>,
    message_limbs: usize,
    challenge_limbs: usize,
}

struct Recorder(Rc<RefCell<Recording>>);

impl NativeAirProgram {
    /// Only the ordinary AIR reduction is enabled here. Product buses, lookup
    /// reductions and PoW require their own explicit interaction descriptions.
    pub fn new(shape: ZerocheckShape) -> Result<Self> {
        ensure!(
            (1..=24).contains(&shape.log_height)
                && !shape.air_degrees.is_empty()
                && shape.air_degrees.len() <= 64
                && shape.lookup_point_len == 0
                && shape.bus_degree.is_none()
                && shape.pow_bits == 0
                && shape
                    .air_degrees
                    .iter()
                    .all(|d| d.interactions == 0 && (1..=16).contains(&d.constraints)),
            "unsupported masked native AIR transcript shape"
        );
        let degree = shape
            .air_degrees
            .iter()
            .map(|d| d.constraints)
            .max()
            .unwrap()
            + 1;
        let rounds = shape.log_height;
        let recording = Rc::new(RefCell::new(Recording::default()));
        let mut recorder = Recorder(Rc::clone(&recording));
        let mut driver = ZerocheckProverTranscript::<_, F, E>::new(&mut recorder, shape);
        let _ = driver.challenges(&[]);
        driver.constraint_sumcheck(|recorder| {
            let mut sumcheck = ProverTranscript::<_, F, E>::new(
                recorder,
                GenericDegreeShape::new(rounds, degree, 0),
                E::ZERO,
            );
            for _ in 0..rounds {
                // The pinned driver absorbs exactly these degree extension
                // elements, then draws one extension challenge. No data-dependent
                // classification or inspection of the prover's values is used.
                recording.borrow_mut().begin_message(degree);
                let _ = sumcheck.round(&vec![E::ZERO; degree]);
                recording.borrow().boundary();
            }
            sumcheck.finish();
        });
        driver.finish();
        let recording = recording.borrow();
        recording.boundary();
        Ok(Self {
            operations: recording.operations.clone(),
            messages: rounds * degree,
            rounds,
            degree,
        })
    }

    /// Fixed sequence of public observations, masked messages and verifier coins.
    pub fn operations(&self) -> &[Operation] {
        &self.operations
    }

    pub fn message_count(&self) -> usize {
        self.messages
    }

    /// Include this trusted program in the compiler's initial statement binding.
    pub fn binding(&self) -> Result<Vec<u8>> {
        Ok(postcard::to_allocvec(&(
            b"binary-masked-native-air-v1",
            &self.operations,
        ))?)
    }

    pub fn prover<'a, C: NativeProverContext>(&'a self, context: &'a mut C) -> NativeProver<'a, C> {
        NativeProver {
            program: self,
            context,
            cursor: 0,
            limbs: vec![],
            sampled: [F::ZERO; 3],
            sample_cursor: 0,
        }
    }

    pub fn replay<C: NativeVerifierContext>(
        &self,
        context: &mut C,
    ) -> Result<NativeReplay<C::Hidden>> {
        let mut messages = vec![];
        let mut challenges = vec![];
        for operation in &self.operations {
            match *operation {
                Operation::Public(value) => context.public(value)?,
                Operation::Message(count) => {
                    let values = context.message(count)?;
                    ensure!(
                        values.len() == count,
                        "native replay returned wrong message width"
                    );
                    messages.push(values);
                }
                Operation::Challenge => {
                    let r = context.challenge()?;
                    ensure!(
                        r != E::ZERO && r != E::ONE,
                        "native challenge must exclude zero and one"
                    );
                    challenges.push(r);
                }
            }
        }
        Ok(NativeReplay {
            messages,
            challenges,
        })
    }

    /// Reuse the pinned interpolator's exact characteristic-two convention:
    /// transmitted nodes are 0, 2, ..., degree, and node 1 is reconstructed
    /// from the previous sum. No integer embedding of 2 or division by 2.
    pub fn reduce(&self, replay: NativeReplay<Linear>) -> Result<NativeAirReduction> {
        ensure!(
            replay.messages.len() == self.rounds
                && replay.messages.iter().all(|m| m.len() == self.degree)
                && replay.challenges.len() == 2 + 2 * self.rounds,
            "unexpected native AIR replay shape"
        );
        let interpolator = RoundPolyInterpolator::<E>::new(self.degree);
        let mut claim = Linear::constant(E::ZERO);
        let challenges = replay.challenges;
        let point = &challenges[2 + self.rounds..];
        for (message, &r) in replay.messages.iter().zip(point) {
            let mut basis = vec![E::ZERO; self.degree];
            let claim_weight = interpolator.eval(&basis, E::ONE, r);
            claim.constant *= claim_weight;
            for (_, c) in &mut claim.terms {
                *c *= claim_weight;
            }
            for (i, evaluation) in message.iter().enumerate() {
                basis[i] = E::ONE;
                let weight = interpolator.eval(&basis, E::ZERO, r);
                basis[i] = E::ZERO;
                claim.constant += weight * evaluation.constant;
                claim
                    .terms
                    .extend(evaluation.terms.iter().map(|&(j, c)| (j, weight * c)));
            }
        }
        Ok(NativeAirReduction {
            alpha: challenges[0],
            beta: challenges[1],
            tau: challenges[2..2 + self.rounds].to_vec(),
            point: point.to_vec(),
            claim,
        })
    }
}

impl Recording {
    fn boundary(&self) {
        assert_eq!(self.message_limbs, 0, "upstream message width changed");
        assert_eq!(self.challenge_limbs, 0, "upstream challenge width changed");
    }

    fn begin_message(&mut self, count: usize) {
        self.boundary();
        self.operations.push(Operation::Message(count));
        self.message_limbs = 3 * count;
    }
}

impl CanObserve<F> for Recorder {
    fn observe(&mut self, value: F) {
        let mut record = self.0.borrow_mut();
        assert_eq!(
            record.challenge_limbs, 0,
            "observation splits extension challenge"
        );
        if record.message_limbs > 0 {
            // Dummy round values are zero. A changed upstream driver inserting
            // framing here is unsupported and must not silently become a mask.
            assert_eq!(value, F::ZERO, "unexpected framing inside native round");
            record.message_limbs -= 1;
        } else {
            record.operations.push(Operation::Public(value));
        }
    }
}

impl CanSample<F> for Recorder {
    fn sample(&mut self) -> F {
        let mut record = self.0.borrow_mut();
        assert_eq!(
            record.message_limbs, 0,
            "challenge precedes complete native message"
        );
        if record.challenge_limbs == 0 {
            record.operations.push(Operation::Challenge);
        }
        record.challenge_limbs = (record.challenge_limbs + 1) % 3;
        F::ONE // Three coefficients give a nonzero, non-one extension element.
    }
}

impl CanSampleBits<usize> for Recorder {
    fn sample_bits(&mut self, _: usize) -> usize {
        panic!("bit sampling is outside the masked native AIR schedule")
    }
}

impl GrindingChallenger for Recorder {
    type Witness = F;
    fn grind(&mut self, _: usize) -> F {
        panic!("grinding is outside the masked native AIR schedule")
    }
}

impl<C> NativeProver<'_, C> {
    pub fn finish(self) -> Result<()> {
        ensure!(
            self.cursor == self.program.operations.len()
                && self.limbs.is_empty()
                && self.sample_cursor == 0,
            "incomplete native AIR transcript"
        );
        Ok(())
    }
}

impl<C: NativeProverContext> CanObserve<F> for NativeProver<'_, C> {
    fn observe(&mut self, value: F) {
        assert_eq!(
            self.sample_cursor, 0,
            "observation splits extension challenge"
        );
        match self.program.operations.get(self.cursor) {
            Some(Operation::Public(expected)) => {
                assert_eq!(value, *expected, "native AIR public framing changed");
                self.context
                    .public(value)
                    .expect("native public observation failed");
                self.cursor += 1;
            }
            Some(Operation::Message(count)) => {
                self.limbs.push(value);
                if self.limbs.len() == count * 3 {
                    let values: Vec<E> = self
                        .limbs
                        .as_chunks::<3>()
                        .0
                        .iter()
                        .map(|limbs| E::from_basis_coefficients_slice(limbs).unwrap())
                        .collect();
                    self.context
                        .message(&values)
                        .expect("native masked message failed");
                    self.limbs.clear();
                    self.cursor += 1;
                }
            }
            _ => panic!("unexpected native AIR observation"),
        }
    }
}

impl<C: NativeProverContext> CanSample<F> for NativeProver<'_, C> {
    fn sample(&mut self) -> F {
        assert!(
            self.limbs.is_empty(),
            "challenge precedes complete native message"
        );
        assert!(
            matches!(
                self.program.operations.get(self.cursor),
                Some(Operation::Challenge)
            ),
            "unexpected native AIR challenge"
        );
        if self.sample_cursor == 0 {
            let r = self.context.challenge().expect("native challenge failed");
            assert!(
                r != E::ZERO && r != E::ONE,
                "native challenge must exclude zero and one"
            );
            self.sampled
                .copy_from_slice(r.as_basis_coefficients_slice());
        }
        let result = self.sampled[self.sample_cursor];
        self.sample_cursor = (self.sample_cursor + 1) % 3;
        if self.sample_cursor == 0 {
            self.cursor += 1;
        }
        result
    }
}

impl<C: NativeProverContext> CanSampleBits<usize> for NativeProver<'_, C> {
    fn sample_bits(&mut self, _: usize) -> usize {
        panic!("bit sampling is outside the masked native AIR schedule")
    }
}

impl<C: NativeProverContext> FieldChallenger<F> for NativeProver<'_, C> {}

impl<C: NativeProverContext> GrindingChallenger for NativeProver<'_, C> {
    type Witness = F;
    fn grind(&mut self, _: usize) -> F {
        panic!("grinding is outside the masked native AIR schedule")
    }
}
