//! Regenerate a bottom product layer instead of retaining its expanded leaves.

use alloc::borrow::Cow;
use alloc::vec;
use alloc::vec::Vec;
use core::marker::PhantomData;
use core::ops::Range;

use p3_field::{ExtensionField, Field};
use p3_maybe_rayon::prelude::*;

use super::{BlockWeights, LayerRounds, PairSums, RadixFourBatch, RoundNodes};
use crate::ProductLeaves;
use crate::math::interpolate_pair;

const CHUNK: usize = 1 << 14;

/// An identity-padded leaf prefix regenerated in bounded chunks.
///
/// The callback must deterministically return exactly the requested range from
/// one fixed leaf vector. It must not depend on calls made while proving.
pub struct RegeneratedLeaves<B, F, S> {
    log_height: usize,
    prefix_len: usize,
    source: S,
    fields: PhantomData<fn() -> (B, F)>,
}

/// Bottom-layer rounds backed by regeneration until the first variable is bound.
pub struct RegeneratedLayer<'a, B: Field, F: ExtensionField<B>, S> {
    leaves: &'a RegeneratedLeaves<B, F, S>,
    point: Vec<F>,
    round: usize,
    dense: Option<RadixFourBatch<'a, B, F, 4>>,
}

impl<B, F, S> RegeneratedLeaves<B, F, S> {
    /// Construct a deterministic prefix source. Suffix leaves are implicitly one.
    pub fn new(log_height: usize, prefix_len: usize, source: S) -> Self {
        assert!(log_height < usize::BITS as usize);
        assert!(prefix_len <= 1usize << log_height);
        Self {
            log_height,
            prefix_len,
            source,
            fields: PhantomData,
        }
    }
}

impl<B: Field, F: ExtensionField<B>, S: Fn(Range<usize>) -> Vec<F> + Sync>
    RegeneratedLeaves<B, F, S>
{
    fn read(&self, range: Range<usize>) -> Vec<F> {
        let expected = range.len();
        let values = (self.source)(range);
        assert_eq!(
            values.len(),
            expected,
            "leaf source returned the wrong length"
        );
        values
    }
}

impl<B: Field, F: ExtensionField<B>, S: Fn(Range<usize>) -> Vec<F> + Sync> ProductLeaves<F>
    for RegeneratedLeaves<B, F, S>
{
    type Layer<'a>
        = RegeneratedLayer<'a, B, F, S>
    where
        Self: 'a;

    fn own_layers(&self) -> usize {
        usize::from(self.log_height >= 2)
    }

    fn materialize(&self) -> Cow<'_, [F]> {
        if self.own_layers() == 0 {
            return Cow::Owned(self.read(0..self.prefix_len));
        }
        // Retain one product per four leaves, never the complete leaf prefix.
        let mut products = vec![F::ONE; self.prefix_len.div_ceil(4)];
        products
            .par_chunks_mut(CHUNK / 4)
            .enumerate()
            .for_each(|(chunk, out)| {
                let start = chunk * CHUNK;
                let values = self.read(start..(start + CHUNK).min(self.prefix_len));
                for (product, leaves) in out.iter_mut().zip(values.chunks(4)) {
                    *product = leaves.iter().copied().product();
                }
            });
        Cow::Owned(products)
    }

    fn layer(&self, j: usize, point: &[F]) -> Self::Layer<'_> {
        assert_eq!(j, 0);
        assert_eq!(self.own_layers(), 1);
        assert_eq!(point.len(), self.log_height - 2);
        RegeneratedLayer {
            leaves: self,
            point: point.to_vec(),
            round: 0,
            dense: None,
        }
    }
}

impl<B: Field, F: ExtensionField<B>, S: Fn(Range<usize>) -> Vec<F> + Sync> LayerRounds<F, 4>
    for RegeneratedLayer<'_, B, F, S>
{
    const READS_EQUALITY: bool = false;

    fn round(&mut self, _: &[F], equality_pair: [F; 2], logical_len: usize, batching: F) -> [F; 5] {
        assert_eq!(logical_len, 1usize << (self.point.len() - self.round));
        let weights = BlockWeights::new(&self.point[self.round + 1..]);
        if let Some(dense) = &mut self.dense {
            return dense.round_with_weights(&weights, equality_pair, batching);
        }
        let sums = (0..self.leaves.prefix_len.div_ceil(CHUNK))
            .into_par_iter()
            .map(|chunk| {
                let start = chunk * CHUNK;
                let values = self
                    .leaves
                    .read(start..(start + CHUNK).min(self.leaves.prefix_len));
                let mut sums = PairSums::new();
                sums.add_pairs::<B, 4>(&values, start / 8, &weights);
                sums
            })
            .collect::<Vec<_>>()
            .into_iter()
            .fold(PairSums::new(), PairSums::merge);
        let nodes = RoundNodes::<F>::new();
        // Identity padding is restored once per tree, after merging all chunks.
        let inner = nodes.evaluate(&PairSums::batch::<4>(vec![sums], batching));
        let equality = nodes.line(equality_pair[0], equality_pair[1]);
        core::array::from_fn(|i| inner[i] * equality[i])
    }

    fn fold(&mut self, challenge: F, logical_len: usize) {
        if let Some(dense) = &mut self.dense {
            dense.fold(challenge, logical_len);
        } else {
            // Only the first folded prefix is retained: half as many values.
            let mut folded = vec![F::ONE; self.leaves.prefix_len.div_ceil(8) * 4];
            folded
                .par_chunks_mut(CHUNK / 2)
                .enumerate()
                .for_each(|(chunk, out)| {
                    let start = chunk * CHUNK;
                    let values = self
                        .leaves
                        .read(start..(start + CHUNK).min(self.leaves.prefix_len));
                    for (out, pair) in out.chunks_mut(4).zip(values.chunks(8)) {
                        for (child, value) in out.iter_mut().enumerate() {
                            *value = interpolate_pair(
                                [
                                    pair.get(child).copied().unwrap_or(F::ONE),
                                    pair.get(child + 4).copied().unwrap_or(F::ONE),
                                ],
                                challenge,
                            );
                        }
                    }
                });
            self.dense = Some(RadixFourBatch::from_level(folded));
        }
        self.round += 1;
    }

    fn children(&self) -> Vec<[F; 4]> {
        if let Some(dense) = &self.dense {
            return dense.children();
        }
        assert!(self.point.is_empty());
        let values = self.leaves.read(0..self.leaves.prefix_len);
        let mut children = [F::ONE; 4];
        children[..values.len()].copy_from_slice(&values);
        vec![children]
    }
}
