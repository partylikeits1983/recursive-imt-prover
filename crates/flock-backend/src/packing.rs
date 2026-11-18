use std::sync::Arc;

use anyhow::{Result, ensure};
use old_binary_field::{Poly64 as OldF, TowerLevel as OldTowerLevel};
use p3_binary_field::TowerLevel;
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;

use crate::F;

#[cfg(test)]
mod tests;

pub const TERMS: usize = 16;
pub const WIDTH: usize = TERMS + 2;
pub const COEFFICIENTS: usize = WIDTH;
pub const ACTIVE: usize = WIDTH + TERMS;
pub const PP_WIDTH: usize = ACTIVE + WIDTH;

pub struct Packing {
    pub shard: Option<Arc<PackedShard>>,
    pub removed_rows: Vec<bool>,
    pub removed_ids: Vec<bool>,
}

pub struct PackedShard {
    pub rows: Vec<PackedRow>,
    pub log_height: usize,
}

pub struct PackedRow {
    pub sources: Vec<u32>,
    ids: [u32; WIDTH],
    coefficients: [u64; TERMS],
}

impl Packing {
    pub fn new(
        widths: &[u8],
        gates: &[OldF],
        pp_width: usize,
        main_width: usize,
        fanout: &[OldF],
    ) -> Result<Self> {
        ensure!(
            pp_width != 0 && gates.len().is_multiple_of(pp_width) && fanout.len().is_multiple_of(3),
            "invalid packing source shape"
        );
        let mut result = Self {
            shard: None,
            removed_rows: vec![false; gates.len() / pp_width],
            removed_ids: vec![false; widths.len()],
        };
        // The pinned full native gate schema has five IDs, a constant and eight selectors.
        // Other compact schemas keep their original rows.
        if main_width != 5 || pp_width != 14 {
            return Ok(result);
        }
        let mut counts = vec![0u32; widths.len()];
        for row in fanout.as_chunks::<3>().0 {
            if row[1].to_repr() == 1 {
                let id = row[0].to_repr() as usize;
                ensure!(id < counts.len(), "packing witness ID out of range");
                counts[id] = counts[id]
                    .checked_add(1)
                    .ok_or_else(|| anyhow::anyhow!("packing occurrence overflow"))?;
            }
        }
        let rows = gates.as_chunks::<14>().0;
        let eligible: Vec<_> = rows
            .iter()
            .map(|row| {
                let selector = matches!((row[12].to_repr(), row[13].to_repr()), (1, 0) | (0, 1));
                let ids = [row[0], row[2], row[4]].map(|v| v.to_repr() as usize);
                selector
                    && row[1].to_repr() == 0
                    && row[3].to_repr() == 0
                    && row[6..12].iter().all(|v| v.to_repr() == 0)
                    && ids.iter().all(|&id| id < widths.len())
                    && widths[ids[0]] <= 1
                    && ids[2] != 0
                    && ids[2] != ids[0]
                    && ids[2] != ids[1]
            })
            .collect();
        let mut consumers = vec![u32::MAX; widths.len()];
        for (index, row) in rows.iter().enumerate().filter(|(i, _)| eligible[*i]) {
            consumers[row[2].to_repr() as usize] = u32::try_from(index)?;
        }
        let mut packed = Vec::new();
        for start in 0..rows.len() {
            if !eligible[start] || result.removed_rows[start] {
                continue;
            }
            let mut sources = vec![u32::try_from(start)?];
            while sources.len() < TERMS {
                let current = *sources.last().unwrap() as usize;
                let output = rows[current][4].to_repr() as usize;
                let next = consumers[output] as usize;
                if counts[output] != 2
                    || next <= current
                    || next >= rows.len()
                    || result.removed_rows[next]
                {
                    break;
                }
                sources.push(u32::try_from(next)?);
            }
            if sources.len() < 4 {
                continue;
            }
            let mut row = PackedRow {
                sources,
                ids: [0; WIDTH],
                coefficients: [0; TERMS],
            };
            row.ids[TERMS] = u32::try_from(rows[start][2].to_repr())?;
            row.ids[TERMS + 1] =
                u32::try_from(rows[*row.sources.last().unwrap() as usize][4].to_repr())?;
            for (term, &source) in row.sources.iter().enumerate() {
                let source = source as usize;
                row.ids[term] = u32::try_from(rows[source][0].to_repr())?;
                row.coefficients[term] = rows[source][5].to_repr();
                result.removed_rows[source] = true;
                if term + 1 < row.sources.len() {
                    result.removed_ids[rows[source][4].to_repr() as usize] = true;
                }
            }
            packed.push(row);
        }
        if !packed.is_empty() {
            let log_height = packed.len().next_power_of_two().trailing_zeros().max(4) as usize;
            result.shard = Some(Arc::new(PackedShard {
                rows: packed,
                log_height,
            }));
        }
        Ok(result)
    }
}

impl PackedShard {
    pub fn preprocessing(&self) -> RowMajorMatrix<F> {
        let mut values = vec![F::ZERO; PP_WIDTH * (1 << self.log_height)];
        for (output, row) in values
            .as_chunks_mut::<PP_WIDTH>()
            .0
            .iter_mut()
            .zip(&self.rows)
        {
            for (i, &id) in row.ids.iter().enumerate() {
                output[i] = F::from_repr(u64::from(id));
                output[ACTIVE + i] = F::from_bool(i < row.sources.len() || i >= TERMS);
            }
            for (i, &coefficient) in row.coefficients.iter().enumerate() {
                output[COEFFICIENTS + i] = F::from_repr(coefficient);
            }
        }
        RowMajorMatrix::new(values, PP_WIDTH)
    }
}
