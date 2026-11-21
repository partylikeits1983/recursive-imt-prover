//! Request-local accumulation of the two faces of the terminal PCS. This is
//! private to the joint protocol. No public verification result is returned
//! until the outer verifier authenticates both pending sets against their roots.
use super::{Cap, Challenger, E, F};
use crate::config::NativeBits;
use anyhow::{Result, ensure};
use p3_binary_field::{PackedGf2, Underlier};
use p3_binary_pcs::{
    BitOpening, BitReadings, BooleanBackend, BooleanMultilinearPcs, PackedWords, WeightedClaim,
    WeightedOpening,
};
use p3_multilinear_util::point::Point;
use p3_sumcheck::{
    FoldedColumn, PrescribedOpeningSecurity,
    layout::Table,
    ring_switch::bits::{BitPacking, BitRingSwitch},
};
use std::sync::Mutex;

pub(super) struct Pending {
    pub points: Vec<Point<E>>,
    pub values: Vec<E>,
    pub witness: Option<(Table<F>, Vec<Vec<E>>)>,
    pub verified_cap: Option<Cap>,
}
pub(super) struct Side {
    inner: NativeBits,
    security: PrescribedOpeningSecurity,
    joint_variables: usize,
    pending: Mutex<Option<Pending>>,
}

impl Side {
    pub(super) fn new(
        inner: NativeBits,
        security: PrescribedOpeningSecurity,
        joint_variables: usize,
    ) -> Self {
        Self {
            inner,
            security,
            joint_variables,
            pending: Mutex::default(),
        }
    }

    pub(super) fn evidence(&self, count: usize) -> Option<PrescribedOpeningSecurity> {
        let mut security = self.security.clone();
        security.candidates()?;
        for (name, degree) in [
            ("joint reading powers", count),
            ("joint quadratic sumcheck", 2 * self.joint_variables),
        ] {
            security.charge_reduction(p3_security::SecurityTerm::new(
                name,
                p3_security::ErrorBits::from_numerator(192, degree as u128),
            ));
        }
        Some(security)
    }

    pub(super) fn take(&self) -> Result<Pending> {
        self.pending
            .lock()
            .expect("opening lock")
            .take()
            .ok_or_else(|| anyhow::anyhow!("missing terminal opening"))
    }

    fn record(
        &self,
        openings: &[BitOpening<E>],
        values: Vec<E>,
        witness: Option<(Table<F>, Vec<Vec<E>>)>,
        cap: Option<&Cap>,
    ) -> Result<()> {
        ensure!(
            !openings.is_empty()
                && openings.len() == values.len()
                && openings.iter().all(|o| o.current
                    && !o.next
                    && o.point.num_variables() == self.inner.num_variables()),
            "unsupported terminal reading"
        );
        let mut pending = self.pending.lock().expect("opening lock");
        ensure!(pending.is_none(), "duplicate terminal opening");
        *pending = Some(Pending {
            points: openings.iter().map(|o| o.point.clone()).collect(),
            values,
            witness,
            verified_cap: cap.cloned(),
        });
        Ok(())
    }
}

// Shared by the config's mixed trace PCS and the local finalizer.
pub(super) struct Face(pub std::sync::Arc<Side>);
impl BooleanBackend<E> for Face {
    type Val = F;
    type Commitment = Cap;
    type ProverData = <NativeBits as BooleanBackend<E>>::ProverData;
    type Proof = ();
    type Error = anyhow::Error;
    fn num_variables(&self) -> usize {
        self.0.inner.num_variables()
    }
}
impl BooleanMultilinearPcs<E, Challenger> for Face {
    fn observe_commitment(&self, cap: &Cap, ch: &mut Challenger) {
        self.0.inner.observe_commitment(cap, ch);
    }
    fn packed_words(words: usize) -> Option<PackedWords<F>> {
        NativeBits::packed_words(words)
    }
    fn commit_bits<U: Underlier>(
        &self,
        bits: &[PackedGf2<U>],
        ch: &mut Challenger,
    ) -> Result<(Cap, Self::ProverData)> {
        Ok(self.0.inner.commit_bits(bits, ch)?)
    }
    fn commit_packed(
        &self,
        words: PackedWords<F>,
        ch: &mut Challenger,
    ) -> Result<(Cap, Self::ProverData)> {
        Ok(self.0.inner.commit_packed(words, ch)?)
    }

    fn open_weighted_readings(
        &self,
        data: Self::ProverData,
        openings: &[BitOpening<E>],
        weighted: &[WeightedOpening<E>],
        folded: &[Option<&FoldedColumn<E>>],
        _ch: &mut Challenger,
    ) -> Result<(Vec<BitReadings<E>>, Vec<E>, ())> {
        ensure!(
            weighted.is_empty() && folded.is_empty(),
            "unsupported weighted terminal opening"
        );
        let table = data.table(0).clone();
        drop(data);
        let packing = BitPacking::from_packed(table.poly(0))?;
        let mut values = Vec::with_capacity(openings.len());
        let mut planes = Vec::with_capacity(openings.len());
        for o in openings {
            let switch = BitRingSwitch::<F, E>::new(&o.point)?;
            let tensor = switch.tensor(&packing)?;
            values.push(switch.incoming_claim(&tensor));
            planes.push(tensor.columns());
        }
        let readings = values
            .iter()
            .map(|&v| BitReadings {
                current: Some(v),
                next: None,
            })
            .collect();
        self.0
            .record(openings, values, Some((table, planes)), None)?;
        Ok((readings, vec![], ()))
    }

    fn verify_weighted_readings(
        &self,
        cap: &Cap,
        openings: &[BitOpening<E>],
        readings: &[BitReadings<E>],
        weighted: &[WeightedClaim<E>],
        _: &(),
        _: &mut Challenger,
    ) -> Result<()> {
        ensure!(
            weighted.is_empty() && cap.num_roots() == 1,
            "unsupported terminal opening"
        );
        let values = readings
            .iter()
            .map(|r| {
                ensure!(r.next.is_none(), "unexpected terminal successor");
                r.current
                    .ok_or_else(|| anyhow::anyhow!("missing current terminal value"))
            })
            .collect::<Result<_>>()?;
        self.0.record(openings, values, None, Some(cap))
    }
    fn readings_security(&self, count: usize, next: bool) -> Option<PrescribedOpeningSecurity> {
        if next {
            return None;
        }
        self.0.evidence(count)
    }
    fn open_at_points(
        &self,
        _: Self::ProverData,
        _: &[Point<E>],
        _: &mut Challenger,
    ) -> Result<(Vec<E>, ())> {
        anyhow::bail!("unsupported direct terminal opening")
    }
    fn verify_at_points(
        &self,
        _: &Cap,
        _: &[Point<E>],
        _: &[E],
        _: &(),
        _: &mut Challenger,
    ) -> Result<()> {
        anyhow::bail!("unsupported direct terminal opening")
    }
}
