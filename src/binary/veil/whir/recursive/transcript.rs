//! Circuit replay of the masked child's framed BLAKE3 transcript.
use anyhow::{Result, ensure};
use p3_circuit::ops::binary_encoding::NativeBinaryEncoding;
use p3_circuit::ops::binary_host::BinaryCircuitHost;
use p3_circuit::ops::{ByteHash, NativePoly192Target};
use p3_circuit::{CircuitBuilder, ExprId};
use p3_field::PrimeCharacteristicRing;

use crate::binary::veil::{F, hash::TRANSCRIPT_DOMAIN, transcript::query_groups};

pub(in crate::binary::veil) struct CircuitTranscript {
    state: [ExprId; 32],
}

pub(in crate::binary::veil) struct Query {
    pub value: ExprId,
    pub bits: Vec<ExprId>,
}

impl CircuitTranscript {
    /// A component may start from an already authenticated transcript state.
    /// The complete child verifier must construct that state from its public
    /// statement and preceding proof messages, never accept it as a free hint.
    pub fn from_state(state: [ExprId; 32]) -> Self {
        Self { state }
    }

    pub fn fingerprint(&self) -> &[ExprId; 32] {
        &self.state
    }

    pub fn integers(
        &mut self,
        builder: &mut CircuitBuilder<F>,
        label: &[u8],
        values: &[usize],
    ) -> Result<()> {
        let bytes: Vec<_> = values
            .iter()
            .flat_map(|&v| (v as u64).to_le_bytes())
            .collect();
        let targets = constants(builder, &bytes);
        self.bytes(builder, label, &targets)
    }

    pub fn base_fields(
        &mut self,
        builder: &mut CircuitBuilder<F>,
        label: &[u8],
        values: &[ExprId],
    ) -> Result<()> {
        let mut words = self.header(builder, label, 8 * values.len())?;
        for &value in values {
            words.extend(builder.native_poly64_unchecked_words(value, 4)?);
        }
        self.finish_words(builder, &words)
    }

    pub fn indices(
        &mut self,
        builder: &mut CircuitBuilder<F>,
        count: usize,
        length: usize,
    ) -> Result<Vec<Query>> {
        ensure!(
            length.is_power_of_two() && length.ilog2() <= 32,
            "invalid query domain"
        );
        let mut queries = Vec::with_capacity(count);
        ensure!(count > 0 && count < length, "wrong query count");
        let one = builder.define_const(F::ONE);
        for (range, depth) in query_groups(count, length.ilog2() as usize) {
            let low = length.ilog2() as usize - depth;
            for (stratum, i) in range.enumerate() {
                self.integers(builder, b"query", &[i])?;
                let first =
                    builder.native_poly64_from_bytes(self.state[..8].try_into().unwrap())?;
                let mut bits = builder.binary_decompose_coordinates(first, 64)?;
                bits.truncate(low);
                bits.extend((0..depth).map(|bit| {
                    if (stratum >> bit) & 1 == 0 {
                        ExprId::ZERO
                    } else {
                        one
                    }
                }));
                let value = builder.binary_recompose_coordinates(&bits)?;
                queries.push(Query { value, bits });
            }
        }
        Ok(queries)
    }

    pub fn bytes(
        &mut self,
        builder: &mut CircuitBuilder<F>,
        label: &[u8],
        payload: &[ExprId],
    ) -> Result<()> {
        let mut words = self.header(builder, label, payload.len())?;
        let mut padded = payload.to_vec();
        if !padded.len().is_multiple_of(2) {
            padded.push(ExprId::ZERO);
        }
        words.extend(NativeBinaryEncoding::words_from_bytes(builder, &padded)?);
        self.finish_words(builder, &words)
    }

    pub fn fields(
        &mut self,
        builder: &mut CircuitBuilder<F>,
        label: &[u8],
        fields: &[NativePoly192Target],
    ) -> Result<()> {
        let mut words = self.header(builder, label, 24 * fields.len())?;
        for field in fields {
            for &coefficient in field.coefficients() {
                words.extend(builder.native_poly64_unchecked_words(coefficient, 4)?);
            }
        }
        self.finish_words(builder, &words)
    }

    fn header(
        &self,
        builder: &mut CircuitBuilder<F>,
        label: &[u8],
        payload_bytes: usize,
    ) -> Result<Vec<ExprId>> {
        let mut bytes = constants(builder, TRANSCRIPT_DOMAIN);
        bytes.extend_from_slice(&self.state);
        bytes.extend(constants(builder, &(label.len() as u64).to_le_bytes()));
        bytes.extend(constants(builder, label));
        if !label.len().is_multiple_of(2) {
            bytes.push(ExprId::ZERO);
        }
        bytes.extend(constants(builder, &(payload_bytes as u64).to_le_bytes()));
        Ok(NativeBinaryEncoding::words_from_bytes(builder, &bytes)?)
    }

    fn finish_words(&mut self, builder: &mut CircuitBuilder<F>, words: &[ExprId]) -> Result<()> {
        // Every unchecked input word is absorbed by the BLAKE3 AIR, which
        // constrains its 16-bit range; recomposition then uniquely binds the
        // complete Poly64 coefficient. A host hash alone would not suffice.
        let digest = NativeBinaryEncoding::hash_words(builder, ByteHash::Blake3, words)?;
        self.state = NativeBinaryEncoding::bytes_from_words(builder, &digest)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("wrong transcript digest length"))?;
        Ok(())
    }

    /// Exactly the native single-draw sampler, including its rare abort.
    pub fn challenge(
        &mut self,
        builder: &mut CircuitBuilder<F>,
        label: &[u8],
    ) -> Result<NativePoly192Target> {
        self.integers(builder, label, &[0])?;
        checked_challenge(builder, &self.state)
    }
}

fn checked_challenge(
    builder: &mut CircuitBuilder<F>,
    digest: &[ExprId; 32],
) -> Result<NativePoly192Target> {
    let one = builder.define_const(F::ONE);
    let mut coefficients = [ExprId::ZERO; 3];
    for (coefficient, bytes) in coefficients.iter_mut().zip(digest[..24].as_chunks::<8>().0) {
        *coefficient = builder.native_poly64_from_bytes(*bytes)?;
    }
    let [a, b, c] = coefficients;
    let b_zero = builder.binary_is_zero(b)?;
    let c_zero = builder.binary_is_zero(c)?;
    let high_zero = builder.mul(b_zero, c_zero);
    let a_plus_one = builder.add(a, one);
    let low_product = builder.mul(a, a_plus_one);
    let low_bad = builder.binary_is_zero(low_product)?;
    let rejected = builder.mul(low_bad, high_zero);
    builder.assert_zero(rejected);
    Ok(builder.native_poly192_from_coefficients(coefficients))
}

fn constants(builder: &mut CircuitBuilder<F>, bytes: &[u8]) -> Vec<ExprId> {
    bytes
        .iter()
        .map(|&byte| builder.define_const(F::new(u64::from(byte))))
        .collect()
}

#[cfg(test)]
mod tests;
