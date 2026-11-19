//! Trusted, injective coordinate encodings for Poly64 trace columns.
use anyhow::{Result, ensure};
use core::ops::Range;
use p3_recursion::pcs::binary::{CoordinateEncoding, Poly64WordOpening};
use p3_sumcheck::TableShape;

#[derive(Clone, Debug)]
pub struct TableEncoding {
    pub word: Option<Poly64WordOpening>,
    pub widths: Vec<usize>,
    pub columns: Vec<Range<usize>>,
    pub boolean_columns: usize,
    pub committed_width: usize,
}

impl TableEncoding {
    pub fn new(widths: Vec<usize>) -> Result<Self> {
        Self::with_word_openings(widths, false)
    }

    pub fn with_word_openings(widths: Vec<usize>, fold: bool) -> Result<Self> {
        let encoding = if fold {
            CoordinateEncoding::UniformWords
        } else {
            CoordinateEncoding::Bits
        };
        Self::with_encoding(widths, 0, encoding)
    }

    pub fn with_encoding(
        widths: Vec<usize>,
        log_height: usize,
        mode: CoordinateEncoding,
    ) -> Result<Self> {
        ensure!(!widths.is_empty(), "empty coordinate encoding");
        let word = mode.word(&widths, log_height);
        let digit_bits = word.as_ref().map_or(1, Poly64WordOpening::digit_bits);
        let mut committed_width = 0usize;
        let mut columns = Vec::with_capacity(widths.len());
        for &width in &widths {
            ensure!(width <= 64, "coordinate width outside 0..=64");
            let end = committed_width
                .checked_add(width.div_ceil(digit_bits))
                .ok_or_else(|| anyhow::anyhow!("coordinate width overflow"))?;
            columns.push(committed_width..end);
            committed_width = end;
        }
        Ok(Self {
            boolean_columns: if word.is_some() {
                0
            } else {
                widths.iter().take_while(|&&width| width == 1).count()
            },
            word,
            widths,
            columns,
            // An all-zero table keeps one dummy committed bit column.
            committed_width: committed_width.max(1),
        })
    }
}

pub fn committed_shapes(shapes: &[TableShape], encodings: &[TableEncoding]) -> Vec<TableShape> {
    assert_eq!(shapes.len(), encodings.len(), "one encoding per table");
    shapes
        .iter()
        .zip(encodings)
        .map(|(shape, encoding)| {
            assert_eq!(shape.width(), encoding.widths.len(), "one width per column");
            let extra = encoding.word.as_ref().map_or(0, |word| word.suffix.len());
            TableShape::new(shape.num_variables() + extra, encoding.committed_width)
        })
        .collect()
}
