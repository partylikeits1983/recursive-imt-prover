use anyhow::{Result, ensure};
use serde::{Serialize, de::DeserializeOwned};

const PREFIX: &[u8] = b"IMTPRF01";
const MAX_BYTES: usize = 16 << 20;

pub(crate) fn encode<T: Serialize>(proof: &T) -> Result<Vec<u8>> {
    let mut bytes = PREFIX.to_vec();
    bytes.extend(bincode::serde::encode_to_vec(proof, config())?);
    ensure!(bytes.len() <= MAX_BYTES, "oversized aggregate proof");
    Ok(bytes)
}

pub(crate) fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    ensure!(bytes.len() <= MAX_BYTES, "oversized aggregate proof");
    let payload = bytes
        .strip_prefix(PREFIX)
        .ok_or_else(|| anyhow::anyhow!("unsupported aggregate proof encoding"))?;
    let (proof, used) = bincode::serde::decode_from_slice(payload, config())?;
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
    use super::{MAX_BYTES, PREFIX, decode, encode};

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
