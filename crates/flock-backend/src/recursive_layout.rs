use anyhow::{Result, ensure};

pub const WITNESS_ID_BITS: usize = 25;
pub const HASH_ROWS_LOG: usize = 16;
pub const HASH_STRIDE: usize = 1 << (HASH_ROWS_LOG + 1);
pub const HASH_ROLE_BITS: usize = HASH_ROWS_LOG + 2;
pub const PACKED_ROWS_LOG: usize = 19;

pub fn check_coordinates(observed: &[u64], widths: &[usize]) -> Result<()> {
    ensure!(
        observed.len() == widths.len(),
        "recursive coordinate count mismatch"
    );
    for (column, (&value, &width)) in observed.iter().zip(widths).enumerate() {
        ensure!(
            width <= 64 && 64 - value.leading_zeros() as usize <= width,
            "recursive preprocessing column {column} exceeds {width} coordinates"
        );
    }
    Ok(())
}
