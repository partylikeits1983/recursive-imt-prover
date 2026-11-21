//! Sample private field coins directly from the caller's byte source.
//! Each Poly192 is the bijective image of three little-endian Poly64 limbs.
use anyhow::{Result, anyhow};
use rand::TryCryptoRng;

use super::{E, F};

pub(super) fn fill_fields(rng: &mut impl TryCryptoRng, fields: &mut [E]) -> Result<()> {
    const FIELDS_PER_READ: usize = 512;
    let mut block = [0u8; 24 * FIELDS_PER_READ];
    for chunk in fields.chunks_mut(FIELDS_PER_READ) {
        let bytes = &mut block[..24 * chunk.len()];
        rng.try_fill_bytes(bytes)
            .map_err(|err| anyhow!("private coin source failed: {err}"))?;
        for (field, repr) in chunk.iter_mut().zip(bytes.as_chunks::<24>().0) {
            *field = E::new(std::array::from_fn(|i| {
                F::new(u64::from_le_bytes(repr.as_chunks::<8>().0[i]))
            }));
        }
    }
    Ok(())
}

pub(super) fn fields(rng: &mut impl TryCryptoRng, count: usize) -> Result<Vec<E>> {
    use p3_field::PrimeCharacteristicRing;
    let mut result = E::zero_vec(count);
    fill_fields(rng, &mut result)?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_field::RawDataSerializable;
    use rand::{TryCryptoRng, TryRng};
    use std::io;

    // A finite private tape exercises the byte-to-field conversion and exhaustion.
    struct Tape<'a>(&'a [u8]);
    impl TryRng for Tape<'_> {
        type Error = io::Error;
        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> io::Result<()> {
            io::Read::read_exact(&mut self.0, dst)
        }
        fn try_next_u32(&mut self) -> io::Result<u32> {
            unreachable!()
        }
        fn try_next_u64(&mut self) -> io::Result<u64> {
            unreachable!()
        }
    }
    impl TryCryptoRng for Tape<'_> {}

    #[test]
    fn field_masks_consume_exactly_192_private_bits_each() -> Result<()> {
        let bytes: Vec<_> = (0..513 * 24).map(|i| (i % 251) as u8).collect();
        let mut tape = Tape(&bytes);
        let sampled = fields(&mut tape, 513)?;
        let mut actual = Vec::new();
        for value in sampled {
            actual.extend(value.into_bytes());
        }
        assert_eq!(actual, bytes);
        assert!(tape.0.is_empty());
        assert!(fields(&mut tape, 1).is_err());
        Ok(())
    }
}
