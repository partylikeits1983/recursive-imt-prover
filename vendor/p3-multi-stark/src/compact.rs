//! Release unused storage after large sumcheck polynomials have been folded.

use core::mem::{replace, size_of};

use p3_field::PrimeCharacteristicRing;
use p3_multilinear_util::poly::Poly;

// Keep small buffers in place; copying them would cost more than their storage.
const MIN_COMPACT_BYTES: usize = 1 << 16;

/// Preserve every evaluation while returning unused capacity to the allocator.
///
/// Upstream folds truncate their vectors without reducing capacity. With mixed
/// trace heights, those old allocations otherwise remain live as new stages start.
pub(crate) fn compact_poly<F: PrimeCharacteristicRing>(poly: &mut Poly<F>) {
    if poly.num_evals().saturating_mul(size_of::<F>()) < MIN_COMPACT_BYTES {
        return;
    }
    let mut values = replace(poly, Poly::zero(0)).into_evals();
    values.shrink_to_fit();
    *poly = Poly::new(values);
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use p3_binary_field::{Poly64, Poly192, TowerLevel};
    use p3_multilinear_util::poly::Poly;

    use super::compact_poly;

    #[test]
    fn compacted_folds_preserve_evaluations_and_release_large_capacity() {
        let values: Vec<_> = (0..1 << 16)
            .map(|value| Poly192::from(Poly64::from_repr(value)))
            .collect();
        let mut dense = Poly::new(values.clone());
        let mut compact = Poly::new(values);
        for round in 0..16 {
            let challenge = Poly192::from(Poly64::from_repr(0x1234_5678 + round));
            dense.fix_prefix_var_mut(challenge);
            compact.fix_prefix_var_mut(challenge);
            compact_poly(&mut compact);
            assert_eq!(compact, dense);
            if compact.num_evals() >= 1 << 12 {
                // Inspect the original allocation; cloning would hide retained capacity.
                let actual = core::mem::replace(&mut compact, Poly::zero(0)).into_evals();
                assert!(actual.capacity() <= actual.len() * 2);
                compact = Poly::new(actual);
            }
        }
    }
}
