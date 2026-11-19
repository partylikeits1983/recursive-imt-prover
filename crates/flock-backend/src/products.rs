use anyhow::{Result, ensure};
use old_binary_field::{Poly64 as OldF, TowerLevel as OldTowerLevel};
use p3_air::{AirBuilder, WindowAccess};

use crate::F;

#[cfg(test)]
mod tests;

pub const WIDTH: usize = 9;
pub const LOG_HEIGHT: usize = 17;

pub struct Products {
    pub rows: Vec<[u32; WIDTH]>,
}

pub(super) fn eval<AB: AirBuilder<F = F>>(builder: &mut AB, offset: usize) {
    let row = builder.main();
    let [a, b, c, d, e, f, g, h, i] = core::array::from_fn(|j| row.current(offset + j).unwrap());
    let cross = b * f + c * e;
    let high = c * f;
    builder.assert_zero(g - a * d - cross.clone());
    builder.assert_zero(h - a * e - b * d - cross - high.clone());
    builder.assert_zero(i - a * f - b * e - c * d - high);
}

type Gate = (usize, [usize; 5]);

// Labels 1..=6 are the input coefficients, 7..=9 the output, and 10..=16 local wires.
// Each slot is in upstream order: a, b, addend, Horner accumulator, output.
const PREFIX: [Gate; 4] = [
    (8, [2, 6, 0, 0, 10]),
    (10, [3, 5, 10, 0, 11]),
    (8, [3, 6, 0, 0, 12]),
    (10, [1, 4, 11, 0, 7]),
];
const MIDDLES: [&[Gate]; 3] = [
    &[
        (12, [11, 0, 12, 0, 13]),
        (10, [1, 5, 13, 0, 14]),
        (10, [2, 4, 14, 0, 8]),
    ],
    &[
        (10, [1, 5, 11, 0, 13]),
        (10, [2, 4, 13, 0, 14]),
        (12, [14, 0, 12, 0, 8]),
    ],
    &[(11, [12, 5, 11, 1, 13]), (10, [2, 4, 13, 0, 8])],
];
const END: [Gate; 3] = [
    (10, [1, 6, 12, 0, 15]),
    (10, [2, 5, 15, 0, 16]),
    (10, [3, 4, 16, 0, 9]),
];

impl Products {
    pub fn extract(
        gates: &[[OldF; 14]],
        counts: &[u32],
        widths: &[u8],
        removed: &mut [bool],
        uses: &mut [u32],
    ) -> Result<Self> {
        let mut rows = Vec::new();
        let mut index = 0;
        while index + 9 <= gates.len() && rows.len() < 1 << LOG_HEIGHT {
            let start = index;
            index += 1;
            if gates[start][8].to_repr() != 1 {
                continue;
            }
            let mut prefix = [0u32; 17];
            if !match_rows(&gates[start..], &PREFIX, &mut prefix, widths) {
                continue;
            }
            for middle in MIDDLES {
                let len = PREFIX.len() + middle.len() + END.len();
                let mut ids = prefix;
                if start + len > gates.len()
                    || removed[start..start + len].contains(&true)
                    || !match_rows(&gates[start + PREFIX.len()..], middle, &mut ids, widths)
                    || !match_rows(
                        &gates[start + PREFIX.len() + middle.len()..],
                        &END,
                        &mut ids,
                        widths,
                    )
                {
                    continue;
                }
                // An intermediate may disappear only if every occurrence is inside this product.
                if !(10..17).all(|i| {
                    ids[i] == 0 || counts[ids[i] as usize] == if i == 11 || i == 12 { 3 } else { 2 }
                }) {
                    continue;
                }
                for &id in &ids[1..7] {
                    let total = &mut uses[id as usize];
                    *total = total
                        .checked_add(2)
                        .ok_or_else(|| anyhow::anyhow!("product wire use overflow"))?;
                    ensure!(
                        *total < counts[id as usize],
                        "incorrect product input multiplicity"
                    );
                }
                for &id in ids[10..].iter().filter(|&&id| id != 0) {
                    uses[id as usize] = counts[id as usize];
                }
                removed[start..start + len].fill(true);
                rows.push(ids[1..=WIDTH].try_into().unwrap());
                index = start + len;
                break;
            }
        }
        Ok(Self { rows })
    }
}

fn match_rows(rows: &[[OldF; 14]], pattern: &[Gate], ids: &mut [u32; 17], widths: &[u8]) -> bool {
    for (row, &(kind, labels)) in rows.iter().zip(pattern) {
        if row[5].to_repr() != u64::from(kind == 12)
            || row[6..]
                .iter()
                .enumerate()
                .any(|(i, v)| v.to_repr() != u64::from(i + 6 == kind))
        {
            return false;
        }
        for (v, label) in row.iter().zip(labels) {
            let Ok(id) = u32::try_from(v.to_repr()) else {
                return false;
            };
            if ids[label] == 0 && label != 0 {
                if id == 0 || widths.get(id as usize) != Some(&64) || ids.contains(&id) {
                    return false;
                }
                ids[label] = id;
            }
            if ids[label] != id {
                return false;
            }
        }
    }
    true
}
