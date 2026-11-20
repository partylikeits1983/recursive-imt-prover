//! Eight independent bit selections in one byte, LSB first.
use p3_field::PrimeCharacteristicRing;

pub(super) fn byte_table<T: PrimeCharacteristicRing + Copy>(basis: &[T]) -> [T; 256] {
    let mut values = [T::ZERO; 256];
    for i in 1usize..256 {
        values[i] = values[i & (i - 1)] + basis[i.trailing_zeros() as usize];
    }
    values
}

/// Transpose eight input bytes so each output byte selects one bit from each input.
pub(super) fn transpose8(mut x: u64) -> u64 {
    for (shift, mask) in [
        (7, 0x00aa00aa00aa00aa),
        (14, 0x0000cccc0000cccc),
        (28, 0x00000000f0f0f0f0),
    ] {
        let swap = (x ^ (x >> shift)) & mask;
        x ^= swap ^ (swap << shift);
    }
    x
}
