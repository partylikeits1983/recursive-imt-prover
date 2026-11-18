//! Reconstruct logical Poly64 columns from authenticated Boolean-coordinate openings.
use alloc::{vec, vec::Vec};
use core::ops::Range;

use p3_binary_field::Poly64;
use p3_circuit::{CircuitBuilder, ops::NativePoly192Target};
use p3_sumcheck::{OpeningBatch, OpeningProtocol, TableShape, TableSpec};

use super::trace_plan::TracePlan;
use super::whir_plan::invalid;
use crate::verifier::{VerificationError, VerifierLimits};

pub struct BinaryPolyCoordinateOpeningPlan {
    protocol: OpeningProtocol,
    columns: Vec<Vec<Range<usize>>>,
    widths: Vec<usize>,
    variables: usize,
    claims: usize,
}

impl BinaryPolyCoordinateOpeningPlan {
    /// Column widths and the opening schedule are trusted circuit metadata.
    /// This adapter supports the backend's current-only arithmetic openings.
    pub fn new(
        logical: &OpeningProtocol,
        widths: &[Vec<usize>],
    ) -> Result<Self, VerificationError> {
        let shapes = logical.table_shapes();
        let limits = VerifierLimits::default();
        if shapes.is_empty() || shapes.len() != widths.len() || shapes.len() > limits.max_instances
        {
            return Err(invalid("coordinate table count mismatch"));
        }
        let mut ranges = Vec::with_capacity(shapes.len());
        let mut encoded = Vec::with_capacity(shapes.len());
        for (shape, widths) in shapes.iter().zip(widths) {
            if widths.is_empty()
                || widths.len() != shape.width()
                || widths.len() > limits.max_matrix_width
                || widths.iter().any(|&w| w > 64)
            {
                return Err(invalid("invalid coordinate column widths"));
            }
            let mut offset = 0usize;
            let columns: Vec<_> = widths
                .iter()
                .map(|&width| {
                    let start = offset;
                    offset += width;
                    start..offset
                })
                .collect();
            // Match the native encoding of an all-zero table.
            let committed = offset.max(1);
            if committed > limits.max_matrix_width
                || shape.num_variables() > limits.max_log_domain_or_degree
            {
                return Err(invalid("coordinate table exceeds verifier limits"));
            }
            ranges.push(columns);
            encoded.push(TableShape::new(shape.num_variables(), committed));
        }
        let mut columns = Vec::new();
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
            .zip(authenticated)
            .map(|(columns, values)| {
                let logical = columns
                    .iter()
                    .map(|range| {
                        let mut result = [zero; 3];
                        for (k, value) in values.current()[range.clone()].iter().enumerate() {
                            for (slot, &coordinate) in result.iter_mut().zip(value.coefficients()) {
                                let term = b.mul(basis[k], coordinate);
                                *slot = b.add(*slot, term);
                            }
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
