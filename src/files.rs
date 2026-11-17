//! Bounded public-artifact reads and JSON reports shared by the binary CLIs.
use std::{
    fs::{self, File},
    io::Read,
    path::Path,
};

use anyhow::{Context, Result, ensure};
use serde::{Serialize, de::DeserializeOwned};

pub fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let file = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= limit,
        "{} exceeds the {limit}-byte input limit",
        path.display()
    );
    Ok(bytes)
}

pub fn read_json<T: DeserializeOwned>(path: &Path) -> Result<T> {
    serde_json::from_slice(&read_bounded(path, 1 << 20)?)
        .with_context(|| format!("decode JSON {}", path.display()))
}

pub fn write_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    fs::write(path, bytes).with_context(|| format!("write {}", path.display()))
}
