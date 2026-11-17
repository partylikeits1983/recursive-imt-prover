//! Symbolic affine obligations over hidden VEIL wires, with circuit-derived
//! coefficients. Hidden wire values are never requested from the aggregator.
use anyhow::{Result, ensure};
use p3_binary_field::TowerLevel;
use p3_circuit::CircuitBuilder;
use p3_circuit::ops::NativePoly192Target;
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};

use crate::binary::veil::{E, F, whir::recursive::transcript::CircuitTranscript};

#[derive(Clone)]
pub(in crate::binary::veil) struct LinearTarget {
    pub constant: NativePoly192Target,
    pub terms: Vec<(usize, NativePoly192Target)>,
}

pub(in crate::binary::veil) struct CircuitReader<'a> {
    pub transcript: CircuitTranscript,
    pub masked: &'a [NativePoly192Target],
    cursor: usize,
}

impl LinearTarget {
    pub fn constant(value: NativePoly192Target) -> Self {
        Self {
            constant: value,
            terms: vec![],
        }
    }
    pub fn wire(b: &mut CircuitBuilder<F>, index: usize) -> Self {
        Self {
            constant: constant(b, E::ZERO),
            terms: vec![(index, constant(b, E::ONE))],
        }
    }
    pub fn add(&self, b: &mut CircuitBuilder<F>, other: &Self) -> Self {
        let mut terms = self.terms.clone();
        terms.extend(other.terms.clone());
        Self {
            constant: b.native_poly192_add(&self.constant, &other.constant),
            terms,
        }
    }
    pub fn scale(&self, b: &mut CircuitBuilder<F>, factor: &NativePoly192Target) -> Self {
        Self {
            constant: b.native_poly192_mul(&self.constant, factor),
            terms: self
                .terms
                .iter()
                .map(|(i, c)| (*i, b.native_poly192_mul(c, factor)))
                .collect(),
        }
    }
}

impl<'a> CircuitReader<'a> {
    pub fn new(transcript: CircuitTranscript, masked: &'a [NativePoly192Target]) -> Self {
        Self {
            transcript,
            masked,
            cursor: 0,
        }
    }
    pub fn position(&self) -> usize {
        self.cursor
    }
    /// An oracle sub-verifier has already hashed these exact masked inputs.
    pub fn consume_authenticated(&mut self, count: usize) -> Result<()> {
        ensure!(
            count <= self.masked.len().saturating_sub(self.cursor),
            "masked cursor overflow"
        );
        self.cursor += count;
        Ok(())
    }
    pub fn read(
        &mut self,
        b: &mut CircuitBuilder<F>,
        label: &[u8],
        count: usize,
    ) -> Result<Vec<LinearTarget>> {
        let end = self
            .cursor
            .checked_add(count)
            .ok_or_else(|| anyhow::anyhow!("masked cursor overflow"))?;
        ensure!(
            count > 0 && end <= self.masked.len(),
            "masked circuit transcript exhausted"
        );
        self.transcript
            .fields(b, label, &self.masked[self.cursor..end])?;
        let values = (self.cursor..end)
            .map(|i| LinearTarget::wire(b, i))
            .collect();
        self.cursor = end;
        Ok(values)
    }
    pub fn challenge(
        &mut self,
        b: &mut CircuitBuilder<F>,
        label: &[u8],
    ) -> Result<NativePoly192Target> {
        self.transcript.challenge(b, label)
    }
}

pub(in crate::binary::veil) fn constant(
    b: &mut CircuitBuilder<F>,
    value: E,
) -> NativePoly192Target {
    let coefficients: &[F] = value.as_basis_coefficients_slice();
    b.native_poly192_constant(std::array::from_fn(|i| coefficients[i].to_repr()))
}
