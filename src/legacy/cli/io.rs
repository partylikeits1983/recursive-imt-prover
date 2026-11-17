use super::types::Manifest;
use anyhow::{Context, Result, ensure};
use recursive_imt_prover::legacy::tree::check_depth;
use recursive_imt_prover::legacy::{FORMAT_VERSION, OUTER_PROTOCOL, RELATION, check_count};
use serde::{Serialize, de::DeserializeOwned};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::Path,
};

pub(super) const SMALL_JSON_LIMIT: usize = 4 * 1024;
pub(super) const INPUT_JSON_LIMIT: usize = 16 * 1024;

pub(super) fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let file = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("read {}", path.display()))?;
    ensure!(
        bytes.len() <= limit,
        "{} exceeds the {limit}-byte input limit",
        path.display()
    );
    Ok(bytes)
}

pub(super) fn read_json<T: DeserializeOwned>(path: &Path, limit: usize) -> Result<T> {
    let bytes = read_bounded(path, limit)?;
    serde_json::from_slice(&bytes).with_context(|| format!("decode JSON {}", path.display()))
}

pub(super) fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("create {}", path.display()))?;
    file.write_all(bytes)
        .with_context(|| format!("write {}", path.display()))
}

pub(super) fn write_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    write_new(path, &bytes)
}

pub(super) fn create_output_dir(path: &Path) -> Result<()> {
    ensure!(!path.exists(), "output must be new: {}", path.display());
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent)
            .with_context(|| format!("create parent directory {}", parent.display()))?;
    }
    fs::create_dir(path).with_context(|| format!("create output directory {}", path.display()))
}

pub(super) fn read_manifest(trusted: &Path) -> Result<Manifest> {
    let manifest: Manifest = read_json(&trusted.join("manifest.json"), SMALL_JSON_LIMIT)?;
    ensure!(
        manifest.version == FORMAT_VERSION && manifest.relation == RELATION,
        "wrong trusted manifest"
    );
    ensure!(
        manifest.outer_protocol == OUTER_PROTOCOL,
        "regenerate trusted setup for the WHIR aggregation protocol"
    );
    check_count(manifest.count)?;
    check_depth(manifest.depth)?;
    Ok(manifest)
}
