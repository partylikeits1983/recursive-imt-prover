//! Independent arithmetic rows grouped by their trusted coordinate widths.
use crate::{F, recursive_layout::WITNESS_ID_BITS as ID};
use anyhow::{Result, ensure};
use old_binary_field::{Poly64 as OldF, TowerLevel as OldTowerLevel};
use p3_binary_field::TowerLevel;
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use std::{collections::HashMap, sync::Arc};

#[cfg(test)]
mod tests;

#[derive(Clone, Copy, Debug)]
pub struct GateLayout {
    main: [usize; 5],
    log_height: usize,
    preprocessing: [usize; 14],
}

pub struct GateShard {
    pub coordinate_widths: Vec<usize>,
    pub source_columns: Vec<usize>,
    pub source_rows: Vec<u32>,
    pub log_height: usize,
    pub preprocessing_widths: Vec<usize>,
    // Fixed preprocessing is stored compactly in memory, then expanded exactly
    // for the upstream AIR/PCS. This is lossless storage, not a proof encoding.
    column_bytes: Arc<[usize]>,
    preprocessing_bytes: Vec<u8>,
}

impl GateLayout {
    const fn new(main: [usize; 5], log_height: usize, preprocessing: [usize; 14]) -> Self {
        Self {
            main,
            log_height,
            preprocessing,
        }
    }
}

// Five wire IDs, one field coefficient, then eight native operation selectors.
const SMALL_OUTPUT: [usize; 14] = [ID, ID, ID, 0, ID, 1, 1, 1, 1, 1, 1, 0, 1, 1];
const SELECT_OR_PRODUCT: [usize; 14] = [ID, ID, ID, 0, ID, 0, 0, 1, 1, 0, 1, 0, 0, 0];
const PRODUCT: [usize; 14] = [ID, ID, 0, 0, ID, 0, 0, 0, 1, 0, 0, 0, 0, 0];
const fn constant_gates(coefficient_bits: usize) -> [usize; 14] {
    [ID, 0, ID, 0, ID, coefficient_bits, 1, 0, 0, 0, 0, 0, 1, 1]
}
const FIVE_WIRE_GATES: [usize; 14] = [ID, ID, ID, ID, ID, 0, 0, 0, 0, 0, 0, 1, 0, 0];

pub const RECURSIVE_LAYOUT: [GateLayout; 6] = [
    GateLayout::new([16, 16, 16, 0, 16], 20, SMALL_OUTPUT),
    GateLayout::new([64, 64, 64, 0, 64], 20, SELECT_OR_PRODUCT),
    GateLayout::new([64, 64, 0, 0, 64], 18, PRODUCT),
    GateLayout::new([64, 0, 64, 0, 64], 20, constant_gates(17)),
    GateLayout::new([64, 0, 64, 0, 64], 19, constant_gates(64)),
    GateLayout::new([64, 64, 64, 64, 64], 17, FIVE_WIRE_GATES),
];

impl GateShard {
    pub fn fill_witness(&self, output: &mut [F], read: impl Fn(u32) -> F) {
        let stride: usize = self.column_bytes.iter().sum();
        let height = 1 << self.log_height;
        for (&column, values) in self
            .source_columns
            .iter()
            .zip(output.chunks_exact_mut(height))
        {
            let offset = self.column_bytes[..column].iter().sum::<usize>();
            let bytes = self.column_bytes[column];
            if bytes == 0 {
                continue;
            }
            for (value, row) in values
                .iter_mut()
                .zip(self.preprocessing_bytes.chunks_exact(stride))
            {
                let mut id = [0; 8];
                id[..bytes].copy_from_slice(&row[offset..offset + bytes]);
                *value = read(u64::from_le_bytes(id) as u32);
            }
        }
    }

    #[cfg(test)]
    pub fn preprocessing(&self) -> RowMajorMatrix<F> {
        self.selected_preprocessing(&(0..self.column_bytes.len()).collect::<Vec<_>>())
    }

    pub fn compact_preprocessing(&self) -> RowMajorMatrix<F> {
        let columns: Vec<_> = self
            .preprocessing_widths
            .iter()
            .enumerate()
            .filter_map(|(column, &width)| (width != 0).then_some(column))
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

/// Infer input bounds from the full, trusted native gate table. In a Boolean
/// conditional swap both branches occur among the two outputs.
pub fn narrow_inputs(widths: &mut [u8], preprocessing: &[OldF], pp_width: usize) -> Result<()> {
    let (rows, tail) = preprocessing.as_chunks::<14>();
    ensure!(
        pp_width == 14 && tail.is_empty(),
        "unexpected native gate schema"
    );
    let mut selects = HashMap::new();
    for row in rows.iter().rev() {
        let select = row[7].to_repr() == 1;
        let constant_product = row[12].to_repr() == 1 || row[13].to_repr() == 1;
        if !select && !constant_product {
            continue;
        }
        let [a, b, c, _, out] = core::array::from_fn(|i| row[i].to_repr() as usize);
        ensure!(
            [a, b, c, out].iter().all(|&id| id < widths.len()),
            "gate witness ID out of range"
        );
        if select {
            if widths[a] <= 1 && widths[out] < widths[b].max(widths[c]) {
                if let Some(&other) = selects.get(&(a, c, b)) {
                    let bound = widths[out].max(other);
                    widths[b] = widths[b].min(bound);
                    widths[c] = widths[c].min(bound);
                }
                let bound = selects.entry((a, b, c)).or_insert(widths[out]);
                *bound = (*bound).min(widths[out]);
            }
        } else {
            let coefficient = (64 - row[5].to_repr().leading_zeros()) as u8;
            let product = crate::fanout::product_width(widths[a], coefficient);
            // In polynomial coordinates addend = out XOR (coefficient * a).
            widths[c] = widths[c].min(widths[out].max(product));
            if coefficient == 1 {
                widths[a] = widths[a].min(widths[out].max(widths[c]));
            }
        }
    }
    Ok(())
}

pub fn partition(
    widths: &[u8],
    preprocessing: &[OldF],
    pp_width: usize,
    main_width: usize,
    removed_rows: &[bool],
    fixed: Option<&[GateLayout]>,
) -> Result<Vec<Arc<GateShard>>> {
    ensure!(
        (1..=5).contains(&main_width) && pp_width > main_width,
        "unexpected native gate layout"
    );
    ensure!(
        preprocessing.len().is_multiple_of(pp_width),
        "incomplete gate preprocessing row"
    );
    if let Some(layout) = fixed {
        ensure!(
            main_width == 5 && pp_width == 14,
            "unsupported fixed gate schema"
        );
        return partition_fixed(widths, preprocessing, removed_rows, layout);
    }
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
            source_columns: (0..main_width).collect(),
            coordinate_widths: (0..main_width)
                .map(|c| [0, 1, 16, 64][(key >> (2 * c)) & 3])
                .collect(),
            source_rows: vec![],
            log_height: 0,
            preprocessing_widths: vec![0; pp_width],
            column_bytes: column_bytes.clone(),
            preprocessing_bytes: vec![],
        });
        shard.source_rows.push(u32::try_from(source_row)?);
        for ((value, &bytes), width) in row
            .iter()
            .zip(column_bytes.iter())
            .zip(&mut shard.preprocessing_widths)
        {
            *width = (*width).max((64 - value.to_repr().leading_zeros()) as usize);
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
                source_columns: shard.source_columns.clone(),
                coordinate_widths: shard.coordinate_widths.clone(),
                source_rows: shard.source_rows.split_off(half),
                log_height: 0,
                preprocessing_widths: shard.preprocessing_widths.clone(),
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

fn partition_fixed(
    widths: &[u8],
    preprocessing: &[OldF],
    removed_rows: &[bool],
    layout: &[GateLayout],
) -> Result<Vec<Arc<GateShard>>> {
    ensure!(
        !layout.is_empty()
            && layout.iter().all(|g| (4..=26).contains(&g.log_height)
                && g.main
                    .iter()
                    .chain(&g.preprocessing)
                    .all(|&width| width <= 64)),
        "invalid fixed gate layout"
    );
    let mut shards: Vec<_> = layout
        .iter()
        .map(|g| {
            // An absent wire has both a zero coordinate width and a trusted zero wire ID.
            let source_columns: Vec<_> = (0..5)
                .filter(|&column| g.main[column] != 0 || g.preprocessing[column] != 0)
                .collect();
            GateShard {
                coordinate_widths: source_columns.iter().map(|&i| g.main[i]).collect(),
                source_columns,
                source_rows: vec![],
                log_height: g.log_height,
                preprocessing_widths: g.preprocessing.to_vec(),
                column_bytes: g.preprocessing.map(|bits| bits.div_ceil(8)).into(),
                preprocessing_bytes: vec![],
            }
        })
        .collect();
    let mut order: Vec<_> = (0..layout.len()).collect();
    order.sort_by_key(|&i| {
        (
            layout[i].main.iter().sum::<usize>(),
            layout[i].preprocessing[5],
        )
    });
    let mut padding = false;
    for (index, row) in preprocessing.as_chunks::<14>().0.iter().enumerate() {
        if row.iter().all(|v| v.to_repr() == 0) {
            padding = true;
            continue;
        }
        ensure!(!padding, "noncontiguous native gate rows");
        if removed_rows.get(index) == Some(&true) {
            continue;
        }
        let mut required = [0; 5];
        for (width, id) in required.iter_mut().zip(&row[..5]) {
            *width = usize::from(
                *widths
                    .get(usize::try_from(id.to_repr())?)
                    .ok_or_else(|| anyhow::anyhow!("gate witness ID out of range"))?,
            );
        }
        let observed = row.map(|v| (64 - v.to_repr().leading_zeros()) as usize);
        let candidate = order.iter().copied().find(|&i| {
            let g = &layout[i];
            shards[i].source_rows.len() < 1 << g.log_height
                && g.main.iter().zip(required).all(|(&max, w)| w <= max)
                && g.preprocessing
                    .iter()
                    .zip(observed)
                    .all(|(&max, w)| w <= max)
        });
        let group = candidate.ok_or_else(|| {
            anyhow::anyhow!(
                "no fixed gate table has capacity for wires {required:?} and preprocessing {observed:?}"
            )
        })?;
        let shard = &mut shards[group];
        shard.source_rows.push(u32::try_from(index)?);
        for (value, &bytes) in row.iter().zip(shard.column_bytes.iter()) {
            shard
                .preprocessing_bytes
                .extend_from_slice(&value.to_repr().to_le_bytes()[..bytes]);
        }
    }
    Ok(shards.into_iter().map(Arc::new).collect())
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
        for (width, other) in group
            .preprocessing_widths
            .iter_mut()
            .zip(other.preprocessing_widths)
        {
            *width = (*width).max(other);
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
