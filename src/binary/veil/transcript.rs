use anyhow::{Result, ensure};
use p3_field::{PrimeCharacteristicRing, RawDataSerializable};
use sha3::{Digest, Keccak256};

use super::hash::TRANSCRIPT_DOMAIN;
use super::{E, F};

#[derive(Clone)]
pub(super) struct Transcript {
    state: [u8; 32],
}

impl Transcript {
    pub fn new(binding: &[u8]) -> Self {
        Self::for_protocol(b"experimental-binary-veil-inner-v4", binding)
    }

    pub fn for_protocol(protocol: &[u8], binding: &[u8]) -> Self {
        let mut transcript = Self { state: [0; 32] };
        transcript.bytes(b"protocol", protocol);
        transcript.bytes(b"statement", binding);
        transcript
    }

    pub fn fingerprint(&self) -> [u8; 32] {
        self.state
    }

    /// Protocol dimensions and indices use fixed-width little-endian u64s,
    /// independently of the machine's pointer width or transport serializer.
    pub fn integers(&mut self, label: &[u8], values: &[usize]) {
        let bytes: Vec<_> = values
            .iter()
            .flat_map(|&v| (v as u64).to_le_bytes())
            .collect();
        self.bytes(label, &bytes);
    }

    pub fn bytes(&mut self, label: &[u8], bytes: &[u8]) {
        let mut hash = Keccak256::new();
        hash.update(TRANSCRIPT_DOMAIN);
        hash.update(self.state);
        hash.update((label.len() as u64).to_le_bytes());
        hash.update(label);
        if !label.len().is_multiple_of(2) {
            hash.update([0]);
        }
        hash.update((bytes.len() as u64).to_le_bytes());
        hash.update(bytes);
        if !bytes.len().is_multiple_of(2) {
            hash.update([0]);
        }
        self.state = hash.finalize().into();
    }

    pub fn fields(&mut self, label: &[u8], fields: &[E]) {
        let mut hash = Keccak256::new();
        hash.update(TRANSCRIPT_DOMAIN);
        hash.update(self.state);
        hash.update((label.len() as u64).to_le_bytes());
        hash.update(label);
        if !label.len().is_multiple_of(2) {
            hash.update([0]);
        }
        hash.update((fields.len() as u64 * 24).to_le_bytes());
        for field in fields {
            hash.update(field.into_bytes().into_iter().collect::<Vec<_>>());
        }
        self.state = hash.finalize().into();
    }

    /// Sample once and fail closed on {0,1}. In the random-oracle model this
    /// aborts with probability 2^-191 per call; there is no prover-selected
    /// retry counter. Charge the union of these aborts in privacy analysis.
    pub fn challenge(&mut self, label: &[u8]) -> Result<E> {
        self.bytes(label, &0u64.to_le_bytes());
        let coordinates = std::array::from_fn(|i| {
            F::new(u64::from_le_bytes(
                self.state[8 * i..8 * i + 8].try_into().unwrap(),
            ))
        });
        let value = E::new(coordinates);
        ensure!(
            value != E::ZERO && value != E::ONE,
            "degenerate Fiat-Shamir challenge; proof attempt aborted"
        );
        Ok(value)
    }

    pub fn indices(&mut self, count: usize, length: usize) -> Vec<usize> {
        assert!(length.is_power_of_two());
        let mut indices = Vec::with_capacity(count);
        for (range, depth) in query_groups(count, length.ilog2() as usize) {
            let low_bits = length.ilog2() as usize - depth;
            for (stratum, i) in range.enumerate() {
                self.bytes(b"query", &(i as u64).to_le_bytes());
                let raw = u64::from_le_bytes(self.state[..8].try_into().unwrap()) as usize;
                indices.push((raw & ((1 << low_bits) - 1)) | (stratum << low_bits));
            }
        }
        indices
    }
}

/// Same deepest-first stratification as Plonky3's BinaryWhirQueryPlan.
/// Each complete group samples once from every equal-sized high-bit stratum.
/// AM-GM bounds its query miss probability by (1-delta)^group_size, so the
/// existing q-query miss bound applies to all groups together as well.
pub(super) fn query_groups(
    count: usize,
    index_bits: usize,
) -> Vec<(std::ops::Range<usize>, usize)> {
    assert!(count > 0 && count < 1 << index_bits);
    let mut start = 0;
    (0..index_bits)
        .rev()
        .filter(|&depth| (count >> depth) & 1 != 0)
        .map(|depth| {
            let end = start + (1 << depth);
            let range = start..end;
            start = end;
            (range, depth)
        })
        .collect()
}
