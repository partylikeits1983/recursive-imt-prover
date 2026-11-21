//! Partition whole witness-ID groups using bounds from the fixed circuit.
use crate::{F, copies::CopyPruner};
use anyhow::{Result, ensure};
use old_binary_field::{Poly64 as OldF, TowerLevel as OldTowerLevel};
use p3_binary_field::TowerLevel;
use p3_circuit::{AluOpKind, Circuit, Op};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use std::sync::Arc;

/// Repeat ordinary bus factors, never a field-valued multiplicity (which
/// would lose even counts in characteristic two).
pub const MAX_COPIES_PER_ROW: u8 = 16;

pub const RECURSIVE_LAYOUT: [(usize, usize, usize, bool); 10] = [
    (1, 2, 4, true),
    (1, 4, 14, false),
    (1, 8, 9, false),
    (1, 16, 17, true),
    (16, 4, 16, false),
    (16, 8, 11, false),
    (16, 16, 15, true),
    (64, 4, 18, false),
    (64, 8, 18, false),
    (64, 16, 17, true),
];

pub struct FanoutShard {
    pub coordinate_width: usize,
    pub rows: Vec<FanoutRow>,
    pub log_height: usize,
    copies_per_row: usize,
    successor: bool,
}

pub struct FanoutRow {
    pub source_row: u32,
    pub id: u32,
    pub copies: u8,
}

impl FanoutShard {
    pub fn needs_successor(&self) -> bool {
        self.successor
    }
    pub fn copies_per_row(&self) -> usize {
        self.copies_per_row
    }

    pub fn preprocessed_width(&self) -> usize {
        2 + self.copies_per_row()
    }

    pub fn preprocessing(&self) -> RowMajorMatrix<F> {
        // An inactive zero row preserves the imported first-row zero check.
        // If the first real group is the zero sentinel, link it to this row.
        let width = self.preprocessed_width();
        let mut values = vec![F::ZERO; width * (1 << self.log_height)];
        values[2] = F::from_bool(self.rows.first().is_some_and(|r| r.id == 0));
        for (i, row) in self.rows.iter().enumerate() {
            values[width * (i + 1)] = F::from_repr(u64::from(row.id));
            values[width * (i + 1) + 1] = F::ONE;
            values[width * (i + 1) + 2] =
                F::from_bool(self.rows.get(i + 1).is_some_and(|next| next.id == row.id));
            for copy in 1..usize::from(row.copies) {
                values[width * (i + 1) + 2 + copy] = F::ONE;
            }
        }
        RowMajorMatrix::new(values, width)
    }
}

pub fn coordinate_widths(
    circuit: &Circuit<OldF>,
    bridge: &[OldF],
    bridge_width: usize,
) -> Result<Vec<u8>> {
    ensure!(bridge_width >= 119, "unexpected bridge preprocessing");
    let mut widths = vec![64u8; circuit.witness_count as usize + 1];
    widths[0] = 0; // The native bus reserves ID zero for an absent addend.
    for op in &circuit.ops {
        match op {
            Op::Const { out, val } => {
                let bits = (64 - val.to_repr().leading_zeros()) as u8;
                widths[out.0 as usize + 1] = widths[out.0 as usize + 1].min(bits);
            }
            Op::Alu {
                kind: AluOpKind::BoolCheck,
                a,
                out,
                ..
            } => {
                widths[a.0 as usize + 1] = 1;
                widths[out.0 as usize + 1] = 1;
            }
            _ => {} // Hints never establish a width bound.
        }
    }
    for row in bridge.chunks_exact(bridge_width) {
        if row[117] == OldF::from_repr(1) {
            for id in &row[..116] {
                let id = usize::try_from(id.to_repr())?;
                ensure!(id < widths.len(), "bridge witness ID out of range");
                widths[id] = widths[id].min(16);
            }
        }
    }
    // Poly64 uses polynomial coordinates: addition is XOR; a product of
    // u- and v-bit polynomials has at most u+v-1 bits before reduction. At
    // 64 bits we keep the full field. This forward pass only tightens bounds
    // already implied by real arithmetic equations, never by hint code.
    for op in &circuit.ops {
        if let Op::Alu {
            kind,
            a,
            b,
            c,
            out,
            intermediate_out,
        } = op
        {
            let a = widths[a.0 as usize + 1];
            let b = widths[b.0 as usize + 1];
            let c = c.map_or(0, |id| widths[id.0 as usize + 1]);
            let product = product_width(a, b);
            let width = match kind {
                AluOpKind::Add => a.max(b),
                AluOpKind::Mul => product,
                AluOpKind::BoolCheck => 1,
                AluOpKind::MulAdd => {
                    if let Some(id) = intermediate_out {
                        widths[id.0 as usize + 1] = widths[id.0 as usize + 1].min(product);
                    }
                    product.max(c)
                }
                AluOpKind::HornerAcc => {
                    let acc = widths
                        [intermediate_out.expect("validated Horner accumulator").0 as usize + 1];
                    product_width(acc, b).max(c).max(a)
                }
            };
            widths[out.0 as usize + 1] = widths[out.0 as usize + 1].min(width);
        }
    }
    Ok(widths)
}

pub fn partition(
    widths: &[u8],
    fanout: &[OldF],
    removed_uses: &[u32],
    recursive: bool,
) -> Result<(Vec<Arc<FanoutShard>>, CopyPruner)> {
    ensure!(fanout.len().is_multiple_of(3), "incomplete fanout row");
    let mut copies = CopyPruner::new(widths.len(), recursive);
    let mut shards: Vec<_> = [1, 16, 64]
        .into_iter()
        .flat_map(|coordinate_width| {
            (0..=MAX_COPIES_PER_ROW.ilog2()).map(move |log| FanoutShard {
                coordinate_width,
                rows: vec![],
                log_height: 0,
                copies_per_row: 1 << log,
                successor: false,
            })
        })
        .collect();
    let mut previous = 0;
    let mut start = 0;
    let mut count = 0;
    let mut padding = false;
    for (source_row, row) in fanout.as_chunks::<3>().0.iter().enumerate() {
        ensure!(
            row[1] == OldF::from_repr(0) || row[1] == OldF::from_repr(1),
            "non-Boolean fanout activation"
        );
        if row[1] == OldF::from_repr(0) {
            padding = true;
            continue;
        }
        ensure!(!padding, "noncontiguous fanout rows");
        let id = usize::try_from(row[0].to_repr())?;
        ensure!(
            id >= previous && id < widths.len(),
            "invalid fanout witness ID order"
        );
        if count != 0 && id != previous {
            record_group(
                &mut shards,
                &mut copies,
                widths,
                removed_uses,
                (previous, start, count),
            )?;
            count = 0;
        }
        if count == 0 {
            start = source_row;
        }
        count += 1;
        previous = id;
    }
    if count != 0 {
        record_group(
            &mut shards,
            &mut copies,
            widths,
            removed_uses,
            (previous, start, count),
        )?;
    }
    if recursive {
        return Ok((fixed(shards)?, copies));
    }
    Ok((
        shards
            .into_iter()
            .filter(|s| !s.rows.is_empty())
            .map(|mut s| {
                s.successor = s.rows.first().is_some_and(|r| r.id == 0)
                    || s.rows.windows(2).any(|r| r[0].id == r[1].id);
                s.log_height = (s.rows.len() + 1)
                    .next_power_of_two()
                    .trailing_zeros()
                    .max(4) as usize;
                s.rows.shrink_to_fit();
                Arc::new(s)
            })
            .collect(),
        copies,
    ))
}

fn fixed(mut shards: Vec<FanoutShard>) -> Result<Vec<Arc<FanoutShard>>> {
    let mut zero = Vec::new();
    for shard in shards.iter_mut().take(5) {
        let count = shard.rows.partition_point(|row| row.id == 0);
        for row in shard.rows.drain(..count) {
            for offset in (0..row.copies).step_by(2) {
                zero.push(FanoutRow {
                    source_row: row.source_row + u32::from(offset),
                    id: 0,
                    copies: (row.copies - offset).min(2),
                });
            }
        }
    }
    ensure!(
        shards[0].rows.is_empty() && shards[1].rows.is_empty(),
        "unexpected singleton or paired fanout"
    );
    shards[1].rows.append(&mut zero);
    let mut result = Vec::new();
    let mut spill = Vec::new();
    for (width, copies, log, successor) in RECURSIVE_LAYOUT {
        let index = shards
            .iter()
            .position(|s| s.coordinate_width == width && s.copies_per_row == copies)
            .ok_or_else(|| anyhow::anyhow!("missing fixed fanout shard"))?;
        let mut shard = shards.remove(index);
        let capacity = (1 << log) - 1;
        if width >= 16 && copies == 4 && shard.rows.len() > capacity {
            // Every three- or four-use ID occupies exactly one row. Move whole
            // IDs to unused slots in the wider tables with their exact counts.
            spill = shard.rows.split_off(capacity);
        } else if width >= 16 && copies > 4 {
            let available = capacity.saturating_sub(shard.rows.len());
            shard
                .rows
                .extend(spill.drain(spill.len().saturating_sub(available)..));
        }
        if copies == usize::from(MAX_COPIES_PER_ROW) {
            ensure!(
                spill.is_empty(),
                "fixed fanout capacity exceeded for width {width}"
            );
        }
        ensure!(
            shard.rows.len() < 1 << log,
            "fixed fanout capacity exceeded: width {width}, copies {copies}, rows {}, log height {log}",
            shard.rows.len()
        );
        let needs_next = shard.rows.first().is_some_and(|r| r.id == 0)
            || shard.rows.windows(2).any(|r| r[0].id == r[1].id);
        ensure!(
            successor || !needs_next,
            "fixed fanout omitted a successor: width {width}, copies {copies}"
        );
        shard.log_height = log;
        shard.successor = successor;
        result.push(Arc::new(shard));
    }
    ensure!(
        spill.is_empty() && shards.iter().all(|s| s.rows.is_empty()),
        "unassigned fixed fanout"
    );
    Ok(result)
}

fn record_group(
    shards: &mut [FanoutShard],
    copies: &mut CopyPruner,
    widths: &[u8],
    removed_uses: &[u32],
    (id, start, count): (usize, usize, usize),
) -> Result<()> {
    let removed = removed_uses.get(id).copied().unwrap_or(0) as usize;
    ensure!(
        removed <= count && (id != 0 || removed == 0),
        "invalid removed wire uses"
    );
    let count = count - removed;
    if count > 0 && !copies.remove_group(id, count) {
        append_group(shards, widths[id], id, start, count)?;
    }
    Ok(())
}

fn append_group(
    shards: &mut [FanoutShard],
    width: u8,
    id: usize,
    start: usize,
    count: usize,
) -> Result<()> {
    let width_bucket = match width {
        0..=1 => 0,
        2..=16 => 1,
        _ => 2,
    };
    let copies = count
        .next_power_of_two()
        .min(usize::from(MAX_COPIES_PER_ROW));
    let buckets = MAX_COPIES_PER_ROW.ilog2() as usize + 1;
    let shard = &mut shards[width_bucket * buckets + copies.ilog2() as usize];
    // Keep every chunk of an ID in one shard so the imported successor
    // equality still links all copies, including the partial final chunk.
    for offset in (0..count).step_by(copies) {
        shard.rows.push(FanoutRow {
            source_row: u32::try_from(start + offset)?,
            id: u32::try_from(id)?,
            copies: u8::try_from((count - offset).min(copies))?,
        });
    }
    Ok(())
}

pub(super) fn product_width(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        0
    } else {
        (a + b - 1).min(64)
    }
}
