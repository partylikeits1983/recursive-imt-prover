// Adapted from Plonky3 708900d7a730d6ce4d5421d43e2193f2301920fa, MIT OR Apache-2.0.
//! Commit mixed Poly64 tables as Boolean coordinate columns. Each width is fixed
//! by the verifier key. The prover rejects values outside that subspace. At an
//! opening point, the verifier reconstructs each field value using its coordinate
//! basis. Weighted claims retain their original indices on leading Boolean columns.

#[cfg(test)]
mod tests;

use crate::encoding::{TableEncoding, committed_shapes};

use p3_binary_field::{BinaryField8, BitCoordinates, PackedGf2x64, TowerLevel};
use p3_challenger::fs::TranscriptField;
use p3_challenger::{CanObserve, CanSampleUniformBits, FieldChallenger, GrindingChallenger};
use p3_commit::MultilinearPcs;
use p3_field::{Algebra, ExtensionField, Field};
use p3_matrix::dense::RowMajorMatrix;
use p3_maybe_rayon::prelude::*;
use p3_multilinear_util::point::Point;
use p3_sumcheck::layout::{ColumnView, Table};
use p3_sumcheck::{
    OpeningBatch, OpeningEvals, OpeningProtocol, PrescribedOpeningSecurity, PrescribedPointPcs,
    TableShape, TableSpec, WeightedColumnClaim,
};

use p3_binary_pcs::{BooleanBackend, BooleanMultilinearPcs};
use p3_binary_pcs::{
    BooleanTraceCommitment, BooleanTraceCommitmentData, BooleanTraceCommitmentError,
    BooleanTraceCommitmentProof,
};
use p3_binary_pcs::{Coordinates, coordinate_bytes, pack};

/// Rows one packed word holds.
const WORD_BITS: usize = 64;

/// A commitment to tables with a bit region and a dense region, one bit witness underneath.
///
/// Each table has a trusted encoding. Its leading one-coordinate columns retain
/// their indices for weighted Boolean claims; other columns expand into their
/// declared number of low coordinates.
///
/// Source cells and packed elements use `F`.
///
/// Opening points and evaluations use its extension `EF`.
///
/// Dense columns split into the coordinates of `F`, and recombine by its embedding into `EF`.
///
/// `F` must be the backend's `B::Val`.
///
/// The default `F = EF` preserves the square case where `B::Val = EF`.
///
/// Specify `F` explicitly when the backend's `Val` differs from `EF`.
///
/// The split is part of the statement, so prover and verifier build it from the same tables.
pub struct MixedTraceCommitment<EF, B, F = EF> {
    /// The Boolean trace commitment every claim is discharged against.
    inner: BooleanTraceCommitment<EF, B>,
    encodings: Vec<TableEncoding>,
    basis: Vec<F>,
}

/// The committed tables, held until the commitment is opened.
pub struct MixedTraceData<EF: Field, D> {
    /// Prover data of the Boolean trace commitment underneath.
    inner: BooleanTraceCommitmentData<EF, D>,
    /// Source tables, lent back to whatever evaluates constraints over them.
    tables: Vec<Table<EF>>,
}

/// The coordinate basis of `EF`: element `k` has only coordinate `k` set.
///
/// A cell `v` is `sum_k c_k * e_k`, where `c_k` is bit `k` of its little-endian bytes.
///
/// A word view over these elements reads bits as the cell whose low coordinates they are.
#[must_use]
pub fn coordinate_basis<EF: Coordinates>() -> Vec<EF> {
    let bytes = EF::COORDINATES / 8;
    (0..EF::COORDINATES)
        .map(|k| {
            let mut cells = vec![BinaryField8::from_le_bytes([0]); bytes];
            cells[k / 8] = BinaryField8::from_le_bytes([1 << (k % 8)]);
            pack::<BinaryField8, EF>(&cells)[0]
        })
        .collect()
}

impl<EF, B, F: Coordinates> MixedTraceCommitment<EF, B, F> {
    /// Split each table at its bit region, and commit through `inner`.
    ///
    /// `inner` must hold the arity [`committed_shapes`] stacks to.
    pub fn new(inner: BooleanTraceCommitment<EF, B>, encodings: Vec<TableEncoding>) -> Self
    where
        B: BooleanBackend<EF, Val = F>,
    {
        Self {
            inner,
            encodings,
            basis: coordinate_basis(),
        }
    }
}

impl<EF: ExtensionField<F>, B, F: Field + Coordinates> MixedTraceCommitment<EF, B, F> {
    /// Refuse a protocol whose table count or widths disagree with the bit regions.
    ///
    /// A table whose committed width overflows a word is refused too.
    fn check_regions<E>(
        &self,
        shapes: &[TableShape],
    ) -> Result<(), BooleanTraceCommitmentError<E>> {
        if shapes.len() != self.encodings.len() {
            return Err(BooleanTraceCommitmentError::TableCountMismatch {
                expected: self.encodings.len(),
                actual: shapes.len(),
            });
        }
        for (shape, encoding) in shapes.iter().zip(&self.encodings) {
            if shape.width() != encoding.widths.len()
                || encoding.widths.iter().any(|&width| width > F::COORDINATES)
            {
                return Err(BooleanTraceCommitmentError::InvalidOpeningProtocol);
            }
        }
        Ok(())
    }

    /// The same schedule over the committed columns, each batch widened to its whole table.
    ///
    /// A table read one row ahead anywhere is read one row ahead in all of its batches.
    ///
    /// Every batch is then complete, so each table costs one reduction per aligned column block.
    ///
    /// The extra readings are opened and verified like the others, and dropped on the way back.
    fn expand_protocol(&self, protocol: &OpeningProtocol) -> OpeningProtocol {
        let shapes = protocol.table_shapes();
        let committed = committed_shapes(&shapes, &self.encodings);
        let mut successor = vec![false; shapes.len()];
        for (table, batch) in protocol.iter_openings() {
            successor[table] |= !batch.next().is_empty();
        }
        let mut schedules = vec![Vec::new(); shapes.len()];
        for (table, _) in protocol.iter_openings() {
            let all: Vec<usize> = (0..committed[table].width()).collect();
            let next = if successor[table] {
                all.clone()
            } else {
                Vec::new()
            };
            schedules[table].push(OpeningBatch::new(all, next));
        }
        OpeningProtocol::new(
            committed
                .into_iter()
                .zip(schedules)
                .map(|(shape, schedule)| TableSpec::new(shape, schedule))
                .collect(),
        )
    }

    /// A field evaluation cannot be split into evaluations of its Boolean
    /// coordinates. Forward supplied values only when expansion changes
    /// neither the columns nor the complete ordered opening request.
    fn expand_known<E>(
        &self,
        protocol: &OpeningProtocol,
        committed: &OpeningProtocol,
        known: &[Option<OpeningEvals<EF>>],
    ) -> Result<Vec<Option<OpeningEvals<EF>>>, BooleanTraceCommitmentError<E>> {
        if known.len() != protocol.iter_openings().count() {
            return Err(BooleanTraceCommitmentError::InvalidOpeningProtocol);
        }
        protocol
            .iter_openings()
            .zip(committed.iter_openings())
            .zip(known)
            .map(|(((table, original), (_, expanded)), hint)| {
                if let Some(values) = hint
                    && (values.current().len() != original.current().len()
                        || values.next().len() != original.next().len())
                {
                    return Err(BooleanTraceCommitmentError::InvalidOpeningProtocol);
                }
                Ok(
                    if self.encodings[table].widths.iter().all(|&width| width == 1)
                        && original == expanded
                    {
                        hint.clone()
                    } else {
                        None
                    },
                )
            })
            .collect()
    }

    /// Read each requested column back out of its table's committed readings.
    ///
    /// A dense column folds its coordinate readings into one value.
    fn recombine(
        &self,
        protocol: &OpeningProtocol,
        evals: &[OpeningEvals<EF>],
    ) -> Vec<OpeningEvals<EF>> {
        protocol
            .iter_openings()
            .zip(evals)
            .map(|((table, batch), committed)| {
                let encoding = &self.encodings[table];
                let side = |columns: &[usize], values: &[EF]| {
                    columns
                        .iter()
                        .map(|&column| {
                            let range = encoding.columns[column].clone();
                            if encoding.widths[column] == 0 {
                                EF::ZERO
                            } else if encoding.widths[column] == 1 {
                                values[range.start]
                            } else {
                                // v(r) = sum_k c_k(r) * embed(e_k)
                                <EF as Algebra<F>>::batched_linear_combination(
                                    &values[range],
                                    &self.basis[..encoding.widths[column]],
                                )
                            }
                        })
                        .collect()
                };
                OpeningBatch::new(
                    side(batch.current(), committed.current()),
                    side(batch.next(), committed.next()),
                )
            })
            .collect()
    }

    /// Lay one table out as packed bits: its bit region, then each dense cell's coordinates.
    fn expand_table<E>(
        &self,
        index: usize,
        table: &Table<F>,
    ) -> Result<Table<F>, BooleanTraceCommitmentError<E>> {
        let num_variables = table.num_variables();
        let height = 1usize << num_variables;
        let width = table.num_polys();
        let encoding = &self.encodings[index];
        let bits = encoding.boolean_columns;
        let committed = encoding.committed_width;
        let blocks = height.div_ceil(WORD_BITS);
        let mut words = vec![0u64; blocks * committed];

        // Each block row holds sixty-four rows of every committed column, filled on its own.
        let refused = words
            .par_chunks_mut(committed)
            .enumerate()
            .filter_map(|(block, row)| {
                let rows = block * WORD_BITS..((block + 1) * WORD_BITS).min(height);
                for (column, slot) in row[..bits].iter_mut().enumerate() {
                    let view = table.column(column);
                    *slot = match view.boolean_word(block) {
                        Some(word) => word,
                        None => {
                            let mut word = 0;
                            for (lane, r) in rows.clone().enumerate() {
                                let value = view.value(r);
                                if value == F::ONE {
                                    word |= 1 << lane;
                                } else if value != F::ZERO {
                                    return Some(column);
                                }
                            }
                            word
                        }
                    };
                }
                for column in bits..width {
                    let view = table.column(column);
                    let out = &mut row[encoding.columns[column].clone()];
                    let mut cells = [F::ZERO; WORD_BITS];
                    let values = match view {
                        ColumnView::Dense(values) => &values[rows.clone()],
                        _ => {
                            for (cell, r) in cells.iter_mut().zip(rows.clone()) {
                                *cell = view.value(r);
                            }
                            &cells[..rows.len()]
                        }
                    };
                    if !expand_bounded_block(values, out) {
                        return Some(column);
                    }
                }
                None
            })
            .min();
        if let Some(column) = refused {
            if encoding.widths[column] != 1 {
                return Err(BooleanTraceCommitmentError::InvalidOpeningProtocol);
            }
            return Err(BooleanTraceCommitmentError::NonBooleanCell {
                table: index,
                column,
            });
        }
        Ok(Table::from_packed_bits(
            RowMajorMatrix::new(words, committed),
            num_variables,
        ))
    }
}

// Transpose one block into coordinate columns. Reject a nonzero bit above the trusted width.
fn expand_bounded_block<A: Coordinates>(values: &[A], out: &mut [u64]) -> bool {
    debug_assert!(values.len() <= WORD_BITS && out.len() <= A::COORDINATES);
    let bytes = coordinate_bytes(values);
    let stride = A::COORDINATES / 8;
    if out.is_empty() {
        return bytes.iter().all(|&byte| byte == 0);
    }
    for start in (0..stride).step_by(8) {
        let end = (start + 8).min(stride);
        let offset = 8 * start;
        let width = out.len().saturating_sub(offset).min(WORD_BITS);
        let mut rows = [PackedGf2x64::new(0); WORD_BITS];
        let mut occupied = 0;
        let mut set_bits = 0;
        for (row, value) in rows.iter_mut().zip(bytes.chunks_exact(stride)) {
            let mut repr = [0; 8];
            repr[..end - start].copy_from_slice(&value[start..end]);
            let word = u64::from_le_bytes(repr);
            occupied |= word;
            set_bits += word.count_ones();
            *row = PackedGf2x64::new(word);
        }
        if width < WORD_BITS && occupied >> width != 0 {
            return false;
        }
        if occupied == 0 {
            continue;
        }
        let output = &mut out[offset..offset + width];
        if set_bits > 256 {
            PackedGf2x64::transpose(&mut rows);
            for (slot, row) in output.iter_mut().zip(rows) {
                *slot = row.to_bits();
            }
        } else {
            for (lane, row) in rows[..values.len()].iter().enumerate() {
                let mut word = row.to_bits();
                while word != 0 {
                    output[word.trailing_zeros() as usize] |= 1 << lane;
                    word &= word - 1;
                }
            }
        }
    }
    true
}

impl<EF: Field, D: Clone> Clone for MixedTraceData<EF, D> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            tables: self.tables.clone(),
        }
    }
}

impl<EF: Field, D> MixedTraceData<EF, D> {
    /// One source table, in the order the tables were supplied.
    ///
    /// # Panics
    ///
    /// Panics on a table index this commitment does not hold.
    #[must_use]
    pub fn table(&self, index: usize) -> &Table<EF> {
        &self.tables[index]
    }
}

impl<EF, B, F, Challenger> MultilinearPcs<EF, Challenger> for MixedTraceCommitment<EF, B, F>
where
    F: TranscriptField + TowerLevel + Coordinates,
    EF: BitCoordinates + ExtensionField<F>,
    B: BooleanMultilinearPcs<EF, Challenger, Val = F>,
    Challenger: FieldChallenger<F>
        + GrindingChallenger<Witness = F>
        + CanSampleUniformBits<F>
        + CanObserve<B::Commitment>,
{
    type Val = F;
    type Commitment = B::Commitment;
    type ProverData = MixedTraceData<F, B::ProverData>;
    type Proof = BooleanTraceCommitmentProof<EF, B::Proof>;
    type Error = BooleanTraceCommitmentError<B::Error>;
    type ProverError = BooleanTraceCommitmentError<B::Error>;
    type Witness = Vec<Table<F>>;
    type OpeningProtocol = OpeningProtocol;

    fn num_vars(&self) -> usize {
        self.inner.num_variables()
    }

    fn commit(
        &self,
        witness: Self::Witness,
        challenger: &mut Challenger,
    ) -> Result<(Self::Commitment, Self::ProverData), Self::ProverError> {
        // Every refusal comes back before the transcript moves.
        let shapes: Vec<_> = witness.iter().map(Table::shape).collect();
        self.check_regions(&shapes)?;
        let committed = tracing::info_span!("expand mixed tables").in_scope(|| {
            witness
                .iter()
                .enumerate()
                .map(|(index, table)| self.expand_table(index, table))
                .collect::<Result<Vec<_>, _>>()
        })?;
        let (commitment, inner) = self.inner.commit(committed, challenger)?;
        Ok((
            commitment,
            MixedTraceData {
                inner,
                tables: witness,
            },
        ))
    }

    fn observe_commitment(&self, commitment: &Self::Commitment, challenger: &mut Challenger) {
        MultilinearPcs::observe_commitment(&self.inner, commitment, challenger);
    }

    fn open(
        &self,
        prover_data: Self::ProverData,
        protocol: Self::OpeningProtocol,
        challenger: &mut Challenger,
    ) -> Result<Self::Proof, Self::ProverError> {
        self.check_regions(&protocol.table_shapes())?;
        let committed = self.expand_protocol(&protocol);
        drop(prover_data.tables);
        self.inner.open(prover_data.inner, committed, challenger)
    }

    fn verify(
        &self,
        commitment: &Self::Commitment,
        proof: &Self::Proof,
        challenger: &mut Challenger,
        protocol: Self::OpeningProtocol,
    ) -> Result<(), Self::Error> {
        self.check_regions(&protocol.table_shapes())?;
        let committed = self.expand_protocol(&protocol);
        self.inner.verify(commitment, proof, challenger, committed)
    }
}

/// Supplied values for unchanged Boolean batches retain their original meaning.
/// All other expanded batches are evaluated from the committed tables as before.
impl<EF, B, F, Challenger> PrescribedPointPcs<EF, Challenger> for MixedTraceCommitment<EF, B, F>
where
    F: TranscriptField + TowerLevel + Coordinates,
    EF: BitCoordinates + ExtensionField<F>,
    B: BooleanMultilinearPcs<EF, Challenger, Val = F>,
    Challenger: FieldChallenger<F>
        + GrindingChallenger<Witness = F>
        + CanSampleUniformBits<F>
        + CanObserve<B::Commitment>,
{
    fn bit_region(&self, table: usize, _width: usize) -> usize {
        // A table this scheme was not sized for has no bit region.
        self.encodings.get(table).map_or(0, |e| e.boolean_columns)
    }

    fn prescribed_security(&self, protocol: &OpeningProtocol) -> Option<PrescribedOpeningSecurity> {
        // The recombination draws nothing, so the committed protocol's evidence is the whole.
        self.check_regions::<B::Error>(&protocol.table_shapes())
            .ok()?;
        self.inner
            .prescribed_security(&self.expand_protocol(protocol))
    }

    fn open_at(
        &self,
        prover_data: Self::ProverData,
        protocol: &OpeningProtocol,
        points: &[Point<EF>],
        challenger: &mut Challenger,
    ) -> Result<Self::Proof, Self::ProverError> {
        self.check_regions(&protocol.table_shapes())?;
        let committed = self.expand_protocol(protocol);
        drop(prover_data.tables);
        self.inner
            .open_at(prover_data.inner, &committed, points, challenger)
    }

    fn open_at_known(
        &self,
        prover_data: Self::ProverData,
        protocol: &OpeningProtocol,
        points: &[Point<EF>],
        known: &[Option<OpeningEvals<EF>>],
        challenger: &mut Challenger,
    ) -> Result<Self::Proof, Self::ProverError> {
        self.check_regions(&protocol.table_shapes())?;
        let committed = self.expand_protocol(protocol);
        let known = self.expand_known(protocol, &committed, known)?;
        drop(prover_data.tables);
        self.inner
            .open_at_known(prover_data.inner, &committed, points, &known, challenger)
    }

    fn verify_at(
        &self,
        commitment: &Self::Commitment,
        proof: &Self::Proof,
        protocol: &OpeningProtocol,
        points: &[Point<EF>],
        challenger: &mut Challenger,
    ) -> Result<Vec<OpeningEvals<EF>>, Self::Error> {
        self.check_regions(&protocol.table_shapes())?;
        let committed = self.expand_protocol(protocol);
        let evals = self
            .inner
            .verify_at(commitment, proof, &committed, points, challenger)?;
        Ok(self.recombine(protocol, &evals))
    }
    fn weighted_security(
        &self,
        protocol: &OpeningProtocol,
        weighted: usize,
    ) -> Option<PrescribedOpeningSecurity> {
        self.check_regions::<B::Error>(&protocol.table_shapes())
            .ok()?;
        self.inner
            .weighted_security(&self.expand_protocol(protocol), weighted)
    }

    fn open_at_known_weighted(
        &self,
        data: Self::ProverData,
        protocol: &OpeningProtocol,
        points: &[Point<EF>],
        known: &[Option<OpeningEvals<EF>>],
        weighted: &[WeightedColumnClaim<EF>],
        challenger: &mut Challenger,
    ) -> Option<Result<Self::Proof, Self::ProverError>> {
        // Circuit tables commit a single Boolean column. Such columns keep their
        // table/column indices, height and weights when dense neighbours expand.
        if weighted
            .iter()
            .any(|c| c.column >= self.encodings.get(c.table).map_or(0, |e| e.boolean_columns))
        {
            return Some(Err(BooleanTraceCommitmentError::InvalidOpeningProtocol));
        }
        if let Err(e) = self.check_regions(&protocol.table_shapes()) {
            return Some(Err(e));
        }
        let committed = self.expand_protocol(protocol);
        let known = match self.expand_known(protocol, &committed, known) {
            Ok(known) => known,
            Err(error) => return Some(Err(error)),
        };
        drop(data.tables);
        self.inner
            .open_at_known_weighted(data.inner, &committed, points, &known, weighted, challenger)
    }

    fn verify_at_weighted(
        &self,
        commitment: &Self::Commitment,
        proof: &Self::Proof,
        protocol: &OpeningProtocol,
        points: &[Point<EF>],
        weighted: &[WeightedColumnClaim<EF>],
        challenger: &mut Challenger,
    ) -> Option<Result<Vec<OpeningEvals<EF>>, Self::Error>> {
        if weighted
            .iter()
            .any(|c| c.column >= self.encodings.get(c.table).map_or(0, |e| e.boolean_columns))
        {
            return Some(Err(BooleanTraceCommitmentError::InvalidOpeningProtocol));
        }
        if let Err(e) = self.check_regions(&protocol.table_shapes()) {
            return Some(Err(e));
        }
        self.inner
            .verify_at_weighted(
                commitment,
                proof,
                &self.expand_protocol(protocol),
                points,
                weighted,
                challenger,
            )
            .map(|result| result.map(|evals| self.recombine(protocol, &evals)))
    }
}
