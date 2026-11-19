//! Reconstruct logical Poly64 columns from authenticated Boolean-coordinate openings.
use alloc::{vec, vec::Vec};
use core::ops::Range;

use p3_binary_field::{Poly64, TowerLevel};
use p3_circuit::{CircuitBuilder, ops::NativePoly192Target};
use p3_field::PrimeCharacteristicRing;
use p3_sumcheck::{OpeningBatch, OpeningProtocol, TableShape, TableSpec};

use super::trace_plan::TracePlan;
use super::whir_plan::invalid;
use crate::verifier::{VerificationError, VerifierLimits};

#[derive(Clone, Copy)]
pub enum CoordinateEncoding {
    Bits,
    UniformWords,
    PreprocessedDigits,
}

/// Public MLE suffix for the little-endian polynomial basis of a Poly64 word.
#[derive(Clone, Debug)]
pub struct Poly64WordOpening {
    pub suffix: Vec<u64>,
    pub scale: u64,
}

pub struct BinaryPolyCoordinateOpeningPlan {
    protocol: OpeningProtocol,
    columns: Vec<Vec<Range<usize>>>,
    widths: Vec<usize>,
    variables: usize,
    claims: usize,
    folds: Vec<Option<Poly64WordOpening>>,
}

impl CoordinateEncoding {
    pub fn word(self, widths: &[usize], log_height: usize) -> Option<Poly64WordOpening> {
        match self {
            Self::Bits => None,
            Self::UniformWords => Poly64WordOpening::for_widths(widths),
            Self::PreprocessedDigits => {
                let largest = widths.iter().copied().max()?;
                if !(2..=64).contains(&largest) {
                    return None;
                }
                // Short tables can pad their last digit more cheaply. The trusted
                // preprocessing commitment binds the unused bits to zero.
                let bits = match log_height {
                    0..=6 => 32,
                    7..=16 => 8,
                    _ => 2,
                };
                Poly64WordOpening::for_widths(&[bits.min(largest.next_power_of_two())])
            }
        }
    }
}

impl Poly64WordOpening {
    pub fn digit_bits(&self) -> usize {
        1 << self.suffix.len()
    }

    pub fn for_widths(widths: &[usize]) -> Option<Self> {
        let &width = widths.first()?;
        if !(2..=64).contains(&width)
            || !width.is_power_of_two()
            || widths.iter().any(|&w| w != width)
        {
            return None;
        }
        // For bit j, q/(1+q) = X^(2^j). Multiplying eq(q, i) by the
        // product of denominators gives the polynomial basis element X^i.
        let mut scale = Poly64::ONE;
        let suffix = (0..width.ilog2())
            .rev()
            .map(|bit| {
                let weight = Poly64::new(1u64 << (1 << bit));
                let denominator = Poly64::ONE + weight;
                scale *= denominator;
                (weight / denominator).to_repr()
            })
            .collect();
        Some(Self {
            suffix,
            scale: scale.to_repr(),
        })
    }
}

impl BinaryPolyCoordinateOpeningPlan {
    /// Column widths and the opening schedule are trusted circuit metadata.
    /// This adapter supports the backend's current-only arithmetic openings.
    pub fn new(
        logical: &OpeningProtocol,
        widths: &[Vec<usize>],
    ) -> Result<Self, VerificationError> {
        Self::with_word_openings(logical, widths, false)
    }

    pub fn with_word_openings(
        logical: &OpeningProtocol,
        widths: &[Vec<usize>],
        fold_words: bool,
    ) -> Result<Self, VerificationError> {
        Self::with_encoding(
            logical,
            widths,
            if fold_words {
                CoordinateEncoding::UniformWords
            } else {
                CoordinateEncoding::Bits
            },
        )
    }

    pub fn with_encoding(
        logical: &OpeningProtocol,
        widths: &[Vec<usize>],
        encoding: CoordinateEncoding,
    ) -> Result<Self, VerificationError> {
        let shapes = logical.table_shapes();
        let limits = VerifierLimits::default();
        if shapes.is_empty() || shapes.len() != widths.len() || shapes.len() > limits.max_instances
        {
            return Err(invalid("coordinate table count mismatch"));
        }
        let mut table_folds = Vec::with_capacity(shapes.len());
        let mut ranges: Vec<Vec<Range<usize>>> = Vec::with_capacity(shapes.len());
        let mut encoded = Vec::with_capacity(shapes.len());
        for (shape, widths) in shapes.iter().zip(widths) {
            if widths.is_empty()
                || widths.len() != shape.width()
                || widths.len() > limits.max_matrix_width
                || widths.iter().any(|&w| w > 64)
            {
                return Err(invalid("invalid coordinate column widths"));
            }
            let fold = encoding.word(widths, shape.num_variables());
            let digit_bits = fold.as_ref().map_or(1, Poly64WordOpening::digit_bits);
            let mut offset = 0usize;
            let columns = widths
                .iter()
                .map(|&width| {
                    let start = offset;
                    offset += width.div_ceil(digit_bits);
                    start..offset
                })
                .collect();
            let committed = offset.max(1);
            let height = shape
                .num_variables()
                .checked_add(fold.as_ref().map_or(0, |w| w.suffix.len()))
                .ok_or_else(|| invalid("word table height overflow"))?;
            if committed > limits.max_matrix_width || height > limits.max_log_domain_or_degree {
                return Err(invalid("coordinate table exceeds verifier limits"));
            }
            ranges.push(columns);
            encoded.push(TableShape::new(height, committed));
            table_folds.push(fold);
        }
        let mut columns = Vec::new();
        let mut folds = Vec::new();
        let mut committed_widths = Vec::new();
        let mut schedules = vec![Vec::new(); shapes.len()];
        for (table, batch) in logical.iter_openings() {
            if batch.current().is_empty()
                || !batch.next().is_empty()
                || batch.current().iter().enumerate().any(|(i, &column)| {
                    column >= shapes[table].width() || batch.current()[..i].contains(&column)
                })
            {
                return Err(invalid(
                    "coordinate adapter requires distinct current columns",
                ));
            }
            columns.push(
                batch
                    .current()
                    .iter()
                    .map(|&c| ranges[table][c].clone())
                    .collect(),
            );
            let width = encoded[table].width();
            folds.push(table_folds[table].clone());
            committed_widths.push(width);
            schedules[table].push(OpeningBatch::new((0..width).collect(), vec![]));
        }
        let protocol = OpeningProtocol::new(
            encoded
                .into_iter()
                .zip(schedules)
                .map(|(shape, schedule)| TableSpec::new(shape, schedule))
                .collect(),
        );
        // Validate arithmetic before invoking the layout planner.
        let cells = protocol
            .checked_num_cells()
            .filter(|&n| n > 0)
            .and_then(usize::checked_next_power_of_two)
            .ok_or_else(|| invalid("coordinate layout overflow"))?;
        let variables = cells.trailing_zeros() as usize;
        let plan = TracePlan::with_value_limbs(protocol.clone(), variables, 12, &limits)?;
        Ok(Self {
            protocol,
            columns,
            widths: committed_widths,
            variables,
            claims: plan.specs.len(),
            folds,
        })
    }

    pub fn protocol(&self) -> &OpeningProtocol {
        &self.protocol
    }
    pub const fn num_variables(&self) -> usize {
        self.variables
    }
    pub const fn ring_claim_count(&self) -> usize {
        self.claims
    }

    pub fn opening_points<T: Clone>(
        &self,
        points: &[Vec<T>],
        mut constant: impl FnMut(u64) -> T,
    ) -> Result<Vec<Vec<T>>, VerificationError> {
        if points.len() != self.folds.len() {
            return Err(invalid("coordinate point count mismatch"));
        }
        Ok(points
            .iter()
            .zip(&self.folds)
            .map(|(point, fold)| {
                let mut coordinates = point.clone();
                if let Some(fold) = fold {
                    coordinates.extend(fold.suffix.iter().copied().map(&mut constant));
                }
                coordinates
            })
            .collect())
    }

    /// Only pass openings authenticated by the PCS verifier under `self.protocol()`.
    pub fn recombine_native(
        &self,
        b: &mut CircuitBuilder<Poly64>,
        authenticated: &[OpeningBatch<NativePoly192Target>],
    ) -> Result<Vec<OpeningBatch<NativePoly192Target>>, VerificationError> {
        if authenticated.len() != self.columns.len()
            || authenticated
                .iter()
                .zip(&self.widths)
                .any(|(batch, &width)| batch.current().len() != width || !batch.next().is_empty())
        {
            return Err(invalid("coordinate opening shape mismatch"));
        }
        let basis: Vec<_> = (0..64)
            .map(|k| b.define_const(Poly64::new(1u64 << k)))
            .collect();
        let zero = b.define_const(Poly64::new(0));
        self.columns
            .iter()
            .zip(&self.folds)
            .zip(authenticated)
            .map(|((columns, fold), values)| {
                let logical = columns
                    .iter()
                    .map(|range| {
                        if let Some(word) = fold
                            && range.len() == 1
                        {
                            let scale = b.define_const(Poly64::new(word.scale));
                            let coeffs = values.current()[range.start]
                                .coefficients()
                                .map(|v| b.mul(v, scale));
                            return Ok(b.native_poly192_from_coefficients(coeffs));
                        }
                        let stride = fold.as_ref().map_or(1, Poly64WordOpening::digit_bits);
                        let mut result = [zero; 3];
                        for (k, value) in values.current()[range.clone()].iter().enumerate() {
                            for (slot, &coordinate) in result.iter_mut().zip(value.coefficients()) {
                                let term = b.mul(basis[k * stride], coordinate);
                                *slot = b.add(*slot, term);
                            }
                        }
                        if let Some(fold) = fold {
                            let scale = b.define_const(Poly64::new(fold.scale));
                            result = result.map(|v| b.mul(v, scale));
                        }
                        b.check_construction_limits()?;
                        Ok(b.native_poly192_from_coefficients(result))
                    })
                    .collect::<Result<_, VerificationError>>()?;
                Ok(OpeningBatch::new(logical, vec![]))
            })
            .collect()
    }
}
