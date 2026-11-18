use alloc::vec;
use alloc::vec::Vec;
use core::ops::Range;

use p3_binary_field::{BinaryChallenger, BinaryField128, Poly64, Poly192, TowerLevel};
use p3_challenger::fs::TranscriptField;
use p3_challenger::{CanSample, HashChallenger};
use p3_field::{ExtensionField, PrimeCharacteristicRing};
use p3_keccak::Keccak256Hash;
use rand::distr::{Distribution, StandardUniform};
use rand::{RngExt, SeedableRng};
use rand_xoshiro::Xoroshiro128Plus;

use crate::{
    PreparedProductGkr, ProductGkrProof, ProductGkrRootShape, ProductGkrShape, RegeneratedLeaves,
};

fn compare<B: TowerLevel + TranscriptField, F: ExtensionField<B>>()
where
    StandardUniform: Distribution<F>,
{
    let mut rng = Xoroshiro128Plus::seed_from_u64(0x51ea_0001);
    for height in 0..=16 {
        let capacity = 1usize << height;
        // Empty, partial pairs, all identities, trailing identities, and chunks
        // on either side of the source boundary. Odd heights include a binary top.
        let mut lengths: Vec<usize> = vec![
            0,
            1,
            3,
            7,
            9,
            capacity / 2,
            capacity.saturating_sub(1),
            capacity,
        ];
        lengths.extend([16383, 16384, 16385]);
        lengths.retain(|&len| len <= capacity);
        lengths.sort_unstable();
        lengths.dedup();
        for len in lengths {
            let inputs = [
                (0..len)
                    .map(|i| if i % 11 == 0 { F::ONE } else { rng.random() })
                    .collect::<Vec<F>>(),
                (0..len.saturating_sub(1))
                    .map(|_| rng.random())
                    .collect::<Vec<F>>(),
                vec![F::ONE; len],
            ];
            let shape =
                ProductGkrShape::new(height, inputs.len(), ProductGkrRootShape::Distinct).unwrap();
            let leaves = inputs
                .iter()
                .map(|input| {
                    RegeneratedLeaves::<B, F, _>::new(height, input.len(), |range: Range<usize>| {
                        input[range].to_vec()
                    })
                })
                .collect::<Vec<_>>();
            let mut dense_transcript =
                BinaryChallenger::<B, _>::from_hasher(Vec::new(), Keccak256Hash);
            let mut compact_transcript = dense_transcript.clone();
            let mut verifier = dense_transcript.clone();
            let borrowed = inputs.iter().map(Vec::as_slice).collect::<Vec<_>>();
            let dense = ProductGkrProof::prove::<B, _>(&borrowed, shape, &mut dense_transcript);
            let compact = PreparedProductGkr::from_leaves::<B, _>(&leaves, shape)
                .prove_with_leaves::<B, _, _>(&leaves, &mut compact_transcript);
            assert_eq!(dense, compact, "height={height}, prefix={len}");
            assert_eq!(
                compact.0.verify::<B, _>(shape, &mut verifier).unwrap(),
                compact.1
            );
            let next_dense: F = dense_transcript.sample();
            let next_compact: F = compact_transcript.sample();
            let next_verifier: F = verifier.sample();
            assert_eq!(next_dense, next_compact);
            assert_eq!(next_dense, next_verifier);
        }
    }
}

#[test]
fn regenerated_binary_leaves_match_dense_proofs_and_transcripts() {
    compare::<BinaryField128, BinaryField128>();
    compare::<Poly64, Poly192>();
}

#[test]
fn regenerated_shared_products_match_dense_and_reject_tampering() {
    let input = (0..513)
        .map(|x| Poly192::from(Poly64::from_repr(x + 1)))
        .collect::<Vec<_>>();
    let mut permuted = input.clone();
    permuted.reverse();
    let inputs = [&input, &permuted];
    let leaves = inputs.map(|input| {
        RegeneratedLeaves::<Poly64, Poly192, _>::new(10, input.len(), |range: Range<usize>| {
            input[range].to_vec()
        })
    });
    let shape = ProductGkrShape::new(10, 2, ProductGkrRootShape::FirstTwoShared).unwrap();
    let new_challenger = || {
        BinaryChallenger::<Poly64, HashChallenger<u8, Keccak256Hash, 32>>::from_hasher(
            Vec::new(),
            Keccak256Hash,
        )
    };
    let dense =
        ProductGkrProof::prove::<Poly64, _>(&[&input, &permuted], shape, &mut new_challenger());
    let compact = PreparedProductGkr::from_leaves::<Poly64, _>(&leaves, shape)
        .prove_with_leaves::<Poly64, _, _>(&leaves, &mut new_challenger());
    assert_eq!(dense, compact);
    let mut corrupted = compact.0;
    corrupted.roots[0] += Poly192::ONE;
    assert!(
        corrupted
            .verify::<Poly64, _>(shape, &mut new_challenger())
            .is_err()
    );
}
