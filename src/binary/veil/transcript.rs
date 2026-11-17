use anyhow::{Result, bail};
use p3_field::{PrimeCharacteristicRing, RawDataSerializable};
use sha3::{Digest, Keccak256};

use super::{E, F};

pub(super) struct Transcript {
    state: [u8; 32],
}

impl Transcript {
    pub fn new(binding: &[u8]) -> Self {
        let mut transcript = Self { state: [0; 32] };
        transcript.bytes(b"protocol", b"experimental-binary-veil-inner-v1");
        transcript.bytes(b"statement", binding);
        transcript
    }

    pub fn bytes(&mut self, label: &[u8], bytes: &[u8]) {
        let mut hash = Keccak256::new();
        hash.update(self.state);
        hash.update((label.len() as u64).to_le_bytes());
        hash.update(label);
        hash.update((bytes.len() as u64).to_le_bytes());
        hash.update(bytes);
        self.state = hash.finalize().into();
    }

    pub fn fields(&mut self, label: &[u8], fields: &[E]) {
        let mut hash = Keccak256::new();
        hash.update(self.state);
        hash.update((label.len() as u64).to_le_bytes());
        hash.update(label);
        hash.update((fields.len() as u64 * 24).to_le_bytes());
        for field in fields {
            hash.update(field.into_bytes().into_iter().collect::<Vec<_>>());
        }
        self.state = hash.finalize().into();
    }

    /// Reject 0 and 1: mask coefficients must be invertible and the two
    /// tautological padding rows require r(r+1) != 0. Bounded retries fail closed.
    pub fn challenge(&mut self, label: &[u8]) -> Result<E> {
        for counter in 0u64..16 {
            self.bytes(label, &counter.to_le_bytes());
            let coordinates = std::array::from_fn(|i| {
                F::new(u64::from_le_bytes(
                    self.state[8 * i..8 * i + 8].try_into().unwrap(),
                ))
            });
            let value = E::new(coordinates);
            if value != E::ZERO && value != E::ONE {
                return Ok(value);
            }
        }
        bail!("Fiat-Shamir challenge sampling exhausted")
    }

    pub fn indices(&mut self, count: usize, length: usize) -> Vec<usize> {
        assert!(length.is_power_of_two());
        (0..count)
            .map(|i| {
                self.bytes(b"query", &(i as u64).to_le_bytes());
                (u64::from_le_bytes(self.state[..8].try_into().unwrap()) as usize) & (length - 1)
            })
            .collect()
    }
}
