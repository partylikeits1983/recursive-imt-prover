//! Feature-scoped recording of the inputs to native bit openings. Commitments,
//! proofs and verifier calls all use the original backend.
use std::cell::RefCell;

use anyhow::ensure;
use p3_binary_field::{PackedGf2, Poly192 as E, Underlier};
use p3_binary_pcs::{
    BitOpening, BitReadings, BooleanBackend, BooleanMultilinearPcs, PackedWords, WeightedClaim,
    WeightedOpening,
};
use p3_multilinear_util::point::Point;
use p3_sumcheck::{FoldedColumn, PrescribedOpeningSecurity, layout::Table};

use crate::{
    F,
    config::{Challenger, NativeBits},
};

pub struct CaptureBits(pub(crate) NativeBits);
pub(super) struct Member {
    pub(super) table: Table<F>,
    pub(super) openings: Vec<BitOpening<E>>,
    pub(super) readings: Vec<BitReadings<E>>,
    /// Private prover hints, the 64 bit-plane evaluations at each high point.
    pub(super) planes: Vec<Vec<E>>,
    pub(super) weighted: Vec<WeightedClaim<E>>,
}
#[derive(Default)]
pub struct Recorded(pub(super) Vec<Member>);

thread_local! {
    static RECORDING: RefCell<Option<Recorded>> = const { RefCell::new(None) };
}

pub fn record<T>(prove: impl FnOnce() -> anyhow::Result<T>) -> anyhow::Result<(T, Recorded)> {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            RECORDING.take();
        }
    }
    ensure!(
        RECORDING.with_borrow(Option::is_none),
        "nested bit opening recording"
    );
    RECORDING.set(Some(Recorded::default()));
    let _reset = Reset;
    Ok((prove()?, RECORDING.take().expect("recording active")))
}

impl BooleanBackend<E> for CaptureBits {
    type Val = F;
    type Commitment = <NativeBits as BooleanBackend<E>>::Commitment;
    type ProverData = <NativeBits as BooleanBackend<E>>::ProverData;
    type Proof = <NativeBits as BooleanBackend<E>>::Proof;
    type Error = <NativeBits as BooleanBackend<E>>::Error;
    fn num_variables(&self) -> usize {
        self.0.num_variables()
    }
}

impl BooleanMultilinearPcs<E, Challenger> for CaptureBits {
    fn observe_commitment(&self, cap: &Self::Commitment, ch: &mut Challenger) {
        self.0.observe_commitment(cap, ch);
    }
    fn packed_words(words: usize) -> Option<PackedWords<F>> {
        NativeBits::packed_words(words)
    }
    fn commit_bits<U: Underlier>(
        &self,
        bits: &[PackedGf2<U>],
        ch: &mut Challenger,
    ) -> Result<(Self::Commitment, Self::ProverData), Self::Error> {
        self.0.commit_bits(bits, ch)
    }
    fn commit_packed(
        &self,
        words: PackedWords<F>,
        ch: &mut Challenger,
    ) -> Result<(Self::Commitment, Self::ProverData), Self::Error> {
        self.0.commit_packed(words, ch)
    }

    fn open_weighted_readings(
        &self,
        data: Self::ProverData,
        openings: &[BitOpening<E>],
        weighted: &[WeightedOpening<E>],
        folded: &[Option<&FoldedColumn<E>>],
        ch: &mut Challenger,
    ) -> Result<(Vec<BitReadings<E>>, Vec<E>, Self::Proof), Self::Error> {
        let table = RECORDING.with_borrow(|r| r.as_ref().map(|_| data.table(0).clone()));
        let (readings, values, proof) = self
            .0
            .open_weighted_readings(data, openings, weighted, folded, ch)?;
        if let Some(table) = table {
            RECORDING.with_borrow_mut(|r| {
                r.as_mut().expect("recording active").0.push(Member {
                    table,
                    planes: proof
                        .elements()
                        .iter()
                        .map(|claim| claim.tensor.columns())
                        .collect(),
                    openings: openings.to_vec(),
                    readings: readings.clone(),
                    weighted: weighted
                        .iter()
                        .cloned()
                        .zip(values.iter().copied())
                        .map(|(opening, value)| WeightedClaim { opening, value })
                        .collect(),
                })
            });
        }
        Ok((readings, values, proof))
    }
    fn verify_weighted_readings(
        &self,
        cap: &Self::Commitment,
        openings: &[BitOpening<E>],
        readings: &[BitReadings<E>],
        weighted: &[WeightedClaim<E>],
        proof: &Self::Proof,
        ch: &mut Challenger,
    ) -> Result<(), Self::Error> {
        self.0
            .verify_weighted_readings(cap, openings, readings, weighted, proof, ch)
    }
    fn readings_security(&self, claims: usize, next: bool) -> Option<PrescribedOpeningSecurity> {
        self.0.readings_security(claims, next)
    }
    fn open_at_points(
        &self,
        data: Self::ProverData,
        points: &[Point<E>],
        ch: &mut Challenger,
    ) -> Result<(Vec<E>, Self::Proof), Self::Error> {
        self.0.open_at_points(data, points, ch)
    }
    fn verify_at_points(
        &self,
        cap: &Self::Commitment,
        points: &[Point<E>],
        values: &[E],
        proof: &Self::Proof,
        ch: &mut Challenger,
    ) -> Result<(), Self::Error> {
        self.0.verify_at_points(cap, points, values, proof, ch)
    }
}
