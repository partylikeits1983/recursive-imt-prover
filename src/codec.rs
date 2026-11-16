//! Versioned, role-separated, fixed-width little-endian bincode. Reject trailing
//! bytes, oversize allocations (bincode limit), and noncanonical re-encodings.
use anyhow::{Result, ensure};
use bincode::Options;
use serde::{Serialize, de::DeserializeOwned};
use std::path::Path;
pub const MAX_BYTES: u64 = 256 * 1024 * 1024;
fn options() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_little_endian()
        .with_limit(MAX_BYTES)
        .reject_trailing_bytes()
}
pub fn encode<T: Serialize>(role: u8, value: &T) -> Result<Vec<u8>> {
    let mut out = b"RIMT\x01\0\0".to_vec();
    out.push(role);
    out.extend(options().serialize(value)?);
    Ok(out)
}
pub fn decode<T: Serialize + DeserializeOwned>(role: u8, bytes: &[u8]) -> Result<T> {
    ensure!(bytes.len() as u64 <= MAX_BYTES, "artifact too large");
    ensure!(
        bytes.len() >= 8 && &bytes[..7] == b"RIMT\x01\0\0" && bytes[7] == role,
        "wrong artifact role/version"
    );
    let value: T = options().deserialize(&bytes[8..])?;
    ensure!(encode(role, &value)? == bytes, "noncanonical encoding");
    Ok(value)
}
pub fn write<T: Serialize>(p: &Path, role: u8, value: &T) -> Result<()> {
    std::fs::write(p, encode(role, value)?)?;
    Ok(())
}
pub fn read<T: Serialize + DeserializeOwned>(p: &Path, role: u8) -> Result<T> {
    ensure!(
        std::fs::metadata(p)?.len() <= MAX_BYTES,
        "artifact too large"
    );
    decode(role, &std::fs::read(p)?)
}
pub fn id<T: Serialize>(role: u8, value: &T) -> Result<String> {
    use sha2::{Digest, Sha256};
    Ok(Sha256::digest(encode(role, value)?)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}
