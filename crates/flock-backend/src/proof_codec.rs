use std::borrow::Cow;

use anyhow::{Context, Result, ensure};
use miniz_oxide::{
    deflate::compress_to_vec_zlib,
    inflate::{
        TINFLStatus,
        core::{DecompressorOxide, decompress, inflate_flags},
    },
};
use serde::{Serialize, de::DeserializeOwned};

const PREFIX: &[u8] = b"IMTPRF01";
const COMPRESSED: &[u8] = b"IMTPRF02";
const MAX_BYTES: usize = 16 << 20;

pub(crate) fn encode<T: Serialize>(proof: &T) -> Result<Vec<u8>> {
    let mut bytes = PREFIX.to_vec();
    bytes.extend(bincode::serde::encode_to_vec(proof, config())?);
    ensure!(bytes.len() <= MAX_BYTES, "oversized aggregate proof");
    Ok(bytes)
}

/// Losslessly compress a serialized aggregate for storage or transmission.
pub fn compact_aggregate_proof(bytes: &[u8]) -> Result<Vec<u8>> {
    ensure!(bytes.len() <= MAX_BYTES, "oversized aggregate proof");
    let payload = bytes
        .strip_prefix(PREFIX)
        .context("expected an uncompressed aggregate proof")?;
    let body = compress_to_vec_zlib(payload, 6);
    if COMPRESSED.len() + 4 + body.len() >= bytes.len() {
        return Ok(bytes.to_vec());
    }
    let mut output = Vec::with_capacity(COMPRESSED.len() + 4 + body.len());
    output.extend_from_slice(COMPRESSED);
    output.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    output.extend_from_slice(&body);
    Ok(output)
}

pub(crate) fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    ensure!(bytes.len() <= MAX_BYTES, "oversized aggregate proof");
    let payload = if let Some(payload) = bytes.strip_prefix(PREFIX) {
        Cow::Borrowed(payload)
    } else {
        let (length, body) = bytes
            .strip_prefix(COMPRESSED)
            .and_then(|rest| rest.split_first_chunk::<4>())
            .context("unsupported or truncated aggregate proof encoding")?;
        let length = u32::from_le_bytes(*length) as usize;
        ensure!(
            length <= MAX_BYTES - PREFIX.len(),
            "oversized uncompressed aggregate proof"
        );
        let mut output = vec![0; length + 1];
        let flags = inflate_flags::TINFL_FLAG_PARSE_ZLIB_HEADER
            | inflate_flags::TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF;
        let (status, read, written) =
            decompress(&mut DecompressorOxide::new(), body, &mut output, 0, flags);
        ensure!(
            status == TINFLStatus::Done && read == body.len() && written == length,
            "invalid compressed aggregate proof"
        );
        output.truncate(length);
        Cow::Owned(output)
    };
    let (proof, used) = bincode::serde::decode_from_slice(&payload, config())?;
    ensure!(used == payload.len(), "trailing aggregate proof data");
    Ok(proof)
}

fn config() -> impl bincode::config::Config {
    bincode::config::standard()
        .with_fixed_int_encoding()
        .with_limit::<MAX_BYTES>()
}

#[cfg(test)]
mod tests {
    use super::{COMPRESSED, MAX_BYTES, PREFIX, compact_aggregate_proof, decode, encode};

    #[test]
    fn final_encoding_preserves_proof_values_and_enforces_both_lengths() {
        let values = vec![0x1234u64; 2048];
        let raw = encode(&values).unwrap();
        let compact = compact_aggregate_proof(&raw).unwrap();
        assert!(compact.starts_with(COMPRESSED) && compact.len() < raw.len());
        assert_eq!(decode::<Vec<u64>>(&compact).unwrap(), values);
        for length in [0, 1, raw.len(), MAX_BYTES + 1] {
            let mut altered = compact.clone();
            altered[8..12].copy_from_slice(&(length as u32).to_le_bytes());
            assert!(decode::<Vec<u64>>(&altered).is_err());
        }
        let mut trailing = compact.clone();
        trailing.push(0);
        assert!(decode::<Vec<u64>>(&trailing).is_err());
        assert!(decode::<Vec<u64>>(&compact[..compact.len() - 1]).is_err());
        let mut corrupt = compact;
        *corrupt.last_mut().unwrap() ^= 1;
        assert!(decode::<Vec<u64>>(&corrupt).is_err());
        let short = encode(&false).unwrap();
        assert_eq!(compact_aggregate_proof(&short).unwrap(), short);
    }

    #[test]
    fn rejects_trailing_truncated_and_oversized_lengths() {
        let expected = vec![u64::MAX; 3];
        let bytes = encode(&expected).unwrap();
        assert_eq!(decode::<Vec<u64>>(&bytes).unwrap(), expected);
        assert!(decode::<Vec<u64>>(&postcard::to_allocvec(&expected).unwrap()).is_err());
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(decode::<Vec<u64>>(&trailing).is_err());
        assert!(decode::<Vec<u64>>(&bytes[..bytes.len() - 1]).is_err());
        let mut oversized = PREFIX.to_vec();
        oversized.extend(u64::MAX.to_le_bytes());
        assert!(decode::<Vec<u64>>(&oversized).is_err());
        assert!(decode::<Vec<u64>>(&vec![0; MAX_BYTES + 1]).is_err());
    }
}
