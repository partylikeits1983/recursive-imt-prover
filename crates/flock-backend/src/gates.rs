//! Independent arithmetic rows grouped by their trusted coordinate widths.
use crate::F;
use anyhow::{Result, ensure};
use old_binary_field::{Poly64 as OldF, TowerLevel as OldTowerLevel};
use p3_binary_field::TowerLevel;
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use std::sync::Arc;

pub struct GateShard {
    pub coordinate_widths: Vec<usize>,
    pub source_rows: Vec<u32>,
    pub log_height: usize,
    pub zero_columns: Vec<bool>,
    // Fixed preprocessing is stored compactly in memory, then expanded exactly
    // for the upstream AIR/PCS. This is lossless storage, not a proof encoding.
    column_bytes: Arc<[usize]>,
    preprocessing_bytes: Vec<u8>,
}

impl GateShard {
    #[cfg(test)]
    pub fn preprocessing(&self) -> RowMajorMatrix<F> {
        self.selected_preprocessing(&(0..self.column_bytes.len()).collect::<Vec<_>>())
    }

    pub fn compact_preprocessing(&self) -> RowMajorMatrix<F> {
        let columns: Vec<_> = self
            .zero_columns
            .iter()
            .enumerate()
            .filter_map(|(column, &zero)| (!zero).then_some(column))
            .collect();
        assert!(
            !columns.is_empty(),
            "arithmetic preprocessing needs a live column"
        );
        self.selected_preprocessing(&columns)
    }

    fn selected_preprocessing(&self, columns: &[usize]) -> RowMajorMatrix<F> {
        let width = columns.len();
        let mut values = vec![F::ZERO; width * (1 << self.log_height)];
        let mut offset = 0;
        for row in values.chunks_exact_mut(width).take(self.source_rows.len()) {
            let mut kept = 0;
            for (column, &bytes) in self.column_bytes.iter().enumerate() {
                if columns.get(kept) == Some(&column) {
                    let mut repr = [0u8; 8];
                    repr[..bytes]
                        .copy_from_slice(&self.preprocessing_bytes[offset..offset + bytes]);
                    row[kept] = F::from_repr(u64::from_le_bytes(repr));
                    kept += 1;
                }
                offset += bytes;
            }
            assert_eq!(kept, width);
        }
        debug_assert_eq!(offset, self.preprocessing_bytes.len());
        RowMajorMatrix::new(values, width)
    }
}

pub fn partition(
    widths: &[u8],
    preprocessing: &[OldF],
    pp_width: usize,
    main_width: usize,
    removed_rows: &[bool],
) -> Result<Vec<Arc<GateShard>>> {
    ensure!(
        (1..=5).contains(&main_width) && pp_width > main_width,
        "unexpected native gate layout"
    );
    ensure!(
        preprocessing.len().is_multiple_of(pp_width),
        "incomplete gate preprocessing row"
    );
    let mut occupied = vec![0u64; pp_width];
    for row in preprocessing.chunks_exact(pp_width) {
        for (bits, value) in occupied.iter_mut().zip(row) {
            *bits |= value.to_repr();
        }
    }
    let column_bytes: Arc<[usize]> = occupied
        .iter()
        .map(|v| (64 - v.leading_zeros() as usize).div_ceil(8).max(1))
        .collect();
    // Two bits per main column select 0, 1, 16 or 64 coordinates. Stable key order
    // fixes the AIR order, independently of the prover's values.
    let mut groups: Vec<Option<GateShard>> = (0..1 << (2 * main_width)).map(|_| None).collect();
    let mut padding = false;
    for (source_row, row) in preprocessing.chunks_exact(pp_width).enumerate() {
        if row.iter().all(|v| v.to_repr() == 0) {
            padding = true;
            continue;
        }
        ensure!(!padding, "noncontiguous native gate rows");
        if removed_rows.get(source_row) == Some(&true) {
            continue;
        }
        let mut key = 0;
        for (column, id) in row[..main_width].iter().enumerate() {
            let id = usize::try_from(id.to_repr())?;
            ensure!(id < widths.len(), "gate witness ID out of range");
            let class = match widths[id] {
                0 => 0,
                1 => 1,
                2..=16 => 2,
                _ => 3,
            };
            key |= class << (2 * column);
        }
        let shard = groups[key].get_or_insert_with(|| GateShard {
            coordinate_widths: (0..main_width)
                .map(|c| [0, 1, 16, 64][(key >> (2 * c)) & 3])
                .collect(),
            source_rows: vec![],
            log_height: 0,
            zero_columns: vec![true; pp_width],
            column_bytes: column_bytes.clone(),
            preprocessing_bytes: vec![],
        });
        shard.source_rows.push(u32::try_from(source_row)?);
        for ((value, &bytes), zero) in row
            .iter()
            .zip(column_bytes.iter())
            .zip(&mut shard.zero_columns)
        {
            *zero &= value.to_repr() == 0;
            shard
                .preprocessing_bytes
                .extend_from_slice(&value.to_repr().to_le_bytes()[..bytes]);
        }
    }
    let mut shards = Vec::new();
    for mut shard in coalesce(groups.into_iter().flatten().collect()) {
        let count = shard.source_rows.len();
        let half = count.next_power_of_two() / 2;
        // One group just over a power-of-two boundary otherwise doubles its
        // commitment. Split at most once, and only when padded cells fall by
        // at least 25%. Arithmetic rows have no successor/boundary dependency.
        if count > half && half >= 32 && (count - half).next_power_of_two().max(16) <= half / 2 {
            let row_bytes: usize = shard.column_bytes.iter().sum();
            let tail = GateShard {
                coordinate_widths: shard.coordinate_widths.clone(),
                source_rows: shard.source_rows.split_off(half),
                log_height: 0,
                zero_columns: shard.zero_columns.clone(),
                column_bytes: shard.column_bytes.clone(),
                preprocessing_bytes: shard.preprocessing_bytes.split_off(half * row_bytes),
            };
            shards.push(finish(shard));
            shards.push(finish(tail));
        } else {
            shards.push(finish(shard));
        }
    }
    Ok(shards)
}

fn finish(mut shard: GateShard) -> Arc<GateShard> {
    shard.log_height = shard
        .source_rows
        .len()
        .next_power_of_two()
        .trailing_zeros()
        .max(4) as usize;
    shard.source_rows.shrink_to_fit();
    shard.preprocessing_bytes.shrink_to_fit();
    Arc::new(shard)
}

// More AIRs can save committed bits yet multiply the number of expensive
// opening reductions. Deterministically merge groups to reduce that cost,
// allowing at most 10% more gate coordinates than the fine partition.
fn coalesce(mut groups: Vec<GateShard>) -> Vec<GateShard> {
    let budget = groups
        .iter()
        .map(|s| costs(&s.coordinate_widths, s.source_rows.len()).0)
        .sum::<usize>()
        * 11
        / 10;
    loop {
        let total: usize = groups
            .iter()
            .map(|s| costs(&s.coordinate_widths, s.source_rows.len()).0)
            .sum();
        let mut best = None;
        for i in 0..groups.len() {
            for j in i + 1..groups.len() {
                let widths: Vec<_> = groups[i]
                    .coordinate_widths
                    .iter()
                    .zip(&groups[j].coordinate_widths)
                    .map(|(&a, &b)| a.max(b))
                    .collect();
                let merged = costs(
                    &widths,
                    groups[i].source_rows.len() + groups[j].source_rows.len(),
                );
                let a = costs(&groups[i].coordinate_widths, groups[i].source_rows.len());
                let b = costs(&groups[j].coordinate_widths, groups[j].source_rows.len());
                if total - a.0 - b.0 + merged.0 <= budget && merged.1 < a.1 + b.1 {
                    let candidate = (a.1 + b.1 - merged.1, usize::MAX - merged.0, i, j);
                    if best.is_none_or(|old| candidate > old) {
                        best = Some(candidate);
                    }
                }
            }
        }
        let Some((_, _, i, j)) = best else {
            return groups;
        };
        let mut other = groups.remove(j);
        let group = &mut groups[i];
        for (width, other) in group
            .coordinate_widths
            .iter_mut()
            .zip(other.coordinate_widths)
        {
            *width = (*width).max(other);
        }
        for (zero, other) in group.zero_columns.iter_mut().zip(other.zero_columns) {
            *zero &= other;
        }
        group.source_rows.append(&mut other.source_rows);
        group
            .preprocessing_bytes
            .append(&mut other.preprocessing_bytes);
    }
}

// Committed bit cells and opened bit coordinates after the optional split.
fn costs(widths: &[usize], rows: usize) -> (usize, usize) {
    let width = widths.iter().sum::<usize>().max(1);
    let height = rows.next_power_of_two().max(16);
    let half = height / 2;
    if rows > half && half >= 32 && (rows - half).next_power_of_two().max(16) <= half / 2 {
        (
            width * (half + (rows - half).next_power_of_two().max(16)),
            2 * width,
        )
    } else {
        (width * height, width)
    }
}
