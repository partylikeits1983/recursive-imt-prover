use std::collections::HashMap;

use anyhow::{Result, ensure};
use old_binary_field::{Poly64 as OldF, TowerLevel};
use p3_air::{AirBuilder, WindowAccess};

use crate::F;

#[cfg(test)]
mod tests;

pub const WIDTH: usize = 5;
pub const LOG_HEIGHT: usize = 18;

pub struct Swaps {
    pub rows: Vec<[u32; WIDTH]>,
}

impl Swaps {
    pub fn extract(
        gates: &[[OldF; 14]],
        widths: &[u8],
        removed_rows: &mut [bool],
        removed_uses: &mut [u32],
    ) -> Result<Self> {
        ensure!(
            gates.len() == removed_rows.len() && widths.len() == removed_uses.len(),
            "invalid swap extraction layout"
        );
        let bounded =
            |id: u32, bits| id != 0 && widths.get(id as usize).is_some_and(|&w| w <= bits);
        let mut pending = HashMap::new();
        let mut rows = Vec::new();
        for (index, gate) in gates.iter().enumerate() {
            if removed_rows[index]
                || gate[7].to_repr() != 1
                || gate[3].to_repr() != 0
                || [5, 6, 8, 9, 10, 11, 12, 13]
                    .iter()
                    .any(|&i| gate[i].to_repr() != 0)
            {
                continue;
            }
            let [Ok(s), Ok(x), Ok(y), Ok(out)] =
                [0, 1, 2, 4].map(|i| u32::try_from(gate[i].to_repr()))
            else {
                continue;
            };
            if x == y || !bounded(s, 1) || ![x, y, out].iter().all(|&id| bounded(id, 16)) {
                continue;
            }
            let Some((other, reverse)) = pending.remove(&[s, y, x]) else {
                pending.insert([s, x, y], (index, out));
                continue;
            };
            rows.push([s, x, y, out, reverse]);
            removed_rows[index] = true;
            removed_rows[other] = true;
            for id in [s, x, y] {
                removed_uses[id as usize] = removed_uses[id as usize]
                    .checked_add(1)
                    .ok_or_else(|| anyhow::anyhow!("swap wire use overflow"))?;
            }
            if rows.len() == 1 << LOG_HEIGHT {
                break;
            }
        }
        Ok(Self { rows })
    }
}

pub(super) fn eval<AB: AirBuilder<F = F>>(builder: &mut AB, offset: usize) {
    let row = builder.main();
    let [selector, x, y, left, right] = core::array::from_fn(|i| row.current(offset + i).unwrap());
    builder.assert_eq(left, selector * (x - y) + y);
    builder.assert_eq(left + right, x + y);
}
