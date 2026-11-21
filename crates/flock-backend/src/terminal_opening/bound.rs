//! One authenticated opening for the two commitments fixed by the root transcript.
use super::{Cap, E, F, FIRST, PairedOpening, PairedTree, batch};
use anyhow::{Result, ensure};
use p3_binary_pcs::{
    BooleanMultilinearPcs,
    whir::{BooleanWhirOpening, BooleanWhirPcs},
};
use p3_field::PrimeCharacteristicRing;
use p3_multilinear_util::point::Point;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub(super) struct SharedProof {
    reduction: batch::BatchProof,
    opening: BooleanWhirOpening<F, E, PairedTree>,
}

pub(super) struct Readings {
    points: Vec<Point<E>>,
    values: Vec<E>,
    variables: usize,
}

impl Readings {
    /// The caller supplies points derived during verification of the main and
    /// preprocessing tables. Their role selectors are fixed here.
    pub fn new(variables: usize, faces: [(&[Point<E>], &[E]); 2]) -> Result<Self> {
        ensure!(
            (FIRST + 1..=26).contains(&variables),
            "unsupported joint arity"
        );
        let split = variables - FIRST;
        let mut points = Vec::new();
        let mut values = Vec::new();
        for ((positions, readings), selectors) in
            faces.into_iter().zip([&[E::ZERO][..], &[E::ONE, E::ZERO]])
        {
            ensure!(
                !positions.is_empty() && positions.len() == readings.len(),
                "invalid joint claim count"
            );
            for p in positions {
                ensure!(
                    p.num_variables() + selectors.len() == variables + 6,
                    "incorrect joint bit arity"
                );
                let (row, col) = p.as_slice().split_at(split);
                points.push(Point::new([row, selectors, col].concat()));
            }
            values.extend_from_slice(readings);
        }
        Ok(Self {
            points,
            values,
            variables: variables + 6,
        })
    }
    fn claims(&self) -> batch::Claims<'_> {
        batch::Claims {
            points: &self.points,
            values: &self.values,
            variables: self.variables,
        }
    }
}

impl PairedOpening {
    pub(super) fn prove_readings(
        self,
        words: Vec<F>,
        expected_roots: [[u8; 32]; 2],
        readings: &Readings,
        planes: &[Vec<E>],
        seed: &[u8],
    ) -> Result<SharedProof> {
        ensure!(
            self.variables + 6 == readings.variables,
            "joint arity mismatch"
        );
        let mut ch = crate::config::challenger(seed);
        // Both roots were already fixed by setup and by the root's arithmetic
        // transcript. Sampling here lets us release the two dense sumcheck
        // tables before allocating the encoded first oracle and its Merkle trees.
        self.observe(expected_roots, &mut ch)?;
        let (reduction, point) = batch::prove(&readings.claims(), &words, planes, &mut ch)?;
        let pair = self.commit_words(words, &mut crate::config::challenger(seed))?;
        ensure!(
            pair.roots == expected_roots,
            "joint roots differ from the root-proof commitments"
        );
        let bits = BooleanWhirPcs::new(self.pcs, readings.variables)?;
        let (values, opening) = bits.open_at_points(pair.data, &[point], &mut ch)?;
        ensure!(values == [reduction.value], "incorrect joint reading");
        Ok(SharedProof { reduction, opening })
    }

    pub(super) fn verify_readings(
        self,
        expected_roots: [[u8; 32]; 2],
        readings: &Readings,
        proof: &SharedProof,
        seed: &[u8],
    ) -> Result<()> {
        ensure!(
            self.variables + 6 == readings.variables,
            "joint arity mismatch"
        );
        let mut challenger = crate::config::challenger(seed);
        let ch = &mut challenger;
        self.observe(expected_roots, ch)?;
        #[cfg(feature = "opening-bench")]
        let whir_config = (*self.pcs).clone();
        let bits = BooleanWhirPcs::new(self.pcs, readings.variables)?;
        let point = readings.claims().verify(&proof.reduction, ch)?;
        #[cfg(feature = "opening-bench")]
        let ring_challenger = ch.clone();
        bits.verify_at_points(
            &Cap::new(expected_roots.to_vec()),
            std::slice::from_ref(&point),
            &[proof.reduction.value],
            &proof.opening,
            ch,
        )?;
        #[cfg(feature = "opening-bench")]
        crate::opening_trace::record_bit_batch(|| {
            let mut trace = super::BatchTrace::new(
                seed,
                &expected_roots,
                &readings.claims(),
                &proof.reduction,
                &point,
            );
            trace.ring_switch = Some(super::replay::RingSwitchTrace::from_verified(
                &point,
                proof.reduction.value,
                &proof.opening,
                ring_challenger,
                &whir_config,
            ));
            trace
        });
        Ok(())
    }
}
