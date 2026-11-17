//! Partition whole witness-ID groups using bounds from the fixed circuit.
use crate::F;
use anyhow::{Result, ensure};
use old_binary_field::{Poly64 as OldF, TowerLevel as OldTowerLevel};
use p3_binary_field::TowerLevel;
use p3_circuit::{AluOpKind, Circuit, Op};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use std::sync::Arc;

pub struct FanoutShard {
    pub coordinate_width: usize,
    pub rows: Vec<FanoutRow>,
    pub log_height: usize,
}

pub struct FanoutRow {
    pub source_row: u32,
    pub id: u32,
}

impl FanoutShard {
    pub fn preprocessing(&self) -> RowMajorMatrix<F> {
        // An inactive zero row preserves the imported first-row zero check.
        // If the first real group is the zero sentinel, link it to this row.
        let mut values = vec![F::ZERO; 3 * (1 << self.log_height)];
        values[2] = F::from_bool(self.rows.first().is_some_and(|r| r.id == 0));
        for (i, row) in self.rows.iter().enumerate() {
            values[3 * (i + 1)] = F::from_repr(u64::from(row.id));
            values[3 * (i + 1) + 1] = F::ONE;
            values[3 * (i + 1) + 2] =
                F::from_bool(self.rows.get(i + 1).is_some_and(|next| next.id == row.id));
        }
        RowMajorMatrix::new(values, 3)
    }
}

pub fn coordinate_widths(
    circuit: &Circuit<OldF>,
    bridge: &[OldF],
    bridge_width: usize,
) -> Result<Vec<u8>> {
    ensure!(bridge_width >= 119, "unexpected bridge preprocessing");
    let mut widths = vec![64u8; circuit.witness_count as usize + 1];
    widths[0] = 1; // The native bus reserves ID zero for an absent addend.
    for op in &circuit.ops {
        match op {
            Op::Const { out, val } => {
                let bits = (64 - val.to_repr().leading_zeros()).max(1) as u8;
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
            let c = c.map_or(1, |id| widths[id.0 as usize + 1]);
            let product = (a + b - 1).min(64);
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
                    (acc + b - 1).min(64).max(c).max(a)
                }
            };
            widths[out.0 as usize + 1] = widths[out.0 as usize + 1].min(width);
        }
    }
    Ok(widths)
}

pub fn partition(widths: &[u8], fanout: &[OldF]) -> Result<Vec<Arc<FanoutShard>>> {
    let mut shards: Vec<_> = [1, 16, 64]
        .into_iter()
        .map(|coordinate_width| FanoutShard {
            coordinate_width,
            rows: vec![],
            log_height: 0,
        })
        .collect();
    let mut previous = 0;
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
        previous = id;
        let shard = match widths[id] {
            1 => 0,
            2..=16 => 1,
            _ => 2,
        };
        shards[shard].rows.push(FanoutRow {
            source_row: u32::try_from(source_row)?,
            id: u32::try_from(id)?,
        });
    }
    Ok(shards
        .into_iter()
        .filter(|s| !s.rows.is_empty())
        .map(|mut s| {
            s.log_height = (s.rows.len() + 1)
                .next_power_of_two()
                .trailing_zeros()
                .max(4) as usize;
            s.rows.shrink_to_fit();
            Arc::new(s)
        })
        .collect())
}
