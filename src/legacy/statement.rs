//! Public roots, canonical statements and digest encodings.
use crate::legacy::config::F;
use anyhow::{Error, Result, ensure};
use core::array::from_fn;
use hex::{decode_to_slice, encode};
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use serde::{Deserialize, Serialize};
use sha3::{Digest as _, Sha3_256};

pub const DIGEST_BYTES: usize = 32;
pub const DIGEST_LIMBS: usize = DIGEST_BYTES / 2;
pub const AMOUNT_LIMBS: usize = size_of::<u64>() / 2;
pub const CLAIM_FIELDS: usize = DIGEST_LIMBS + AMOUNT_LIMBS;
pub const FORMAT_VERSION: u32 = 4;
pub const MAX_BATCH: usize = 64;
pub const RELATION: &str = "zk-sha3-256-imt-note-membership-v4";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Digest(pub [u8; DIGEST_BYTES]);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Claim {
    pub root: Digest,
    pub amount: u64,
}

/// Matching positions in the two arrays describe one child's claim.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Statement {
    pub version: u32,
    pub relation: String,
    pub roots: Vec<Digest>,
    pub amounts: Vec<u64>,
}

impl TryFrom<String> for Digest {
    type Error = Error;

    fn try_from(encoded: String) -> Result<Self> {
        ensure!(
            encoded.len() == DIGEST_BYTES * 2
                && encoded
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
            "digest must be 64 lowercase hexadecimal characters"
        );
        let mut bytes = [0; DIGEST_BYTES];
        decode_to_slice(encoded, &mut bytes)?;
        Ok(Self(bytes))
    }
}

impl From<Digest> for String {
    fn from(digest: Digest) -> Self {
        encode(digest.0)
    }
}

impl Digest {
    pub fn fields(self) -> [F; DIGEST_LIMBS] {
        from_fn(|i| F::from_u16(u16::from_le_bytes([self.0[2 * i], self.0[2 * i + 1]])))
    }
}

impl Claim {
    pub fn fields(self) -> [F; CLAIM_FIELDS] {
        let root = self.root.fields();
        from_fn(|index| {
            if index < DIGEST_LIMBS {
                root[index]
            } else {
                F::from_u16((self.amount >> (16 * (index - DIGEST_LIMBS))) as u16)
            }
        })
    }
}

impl Statement {
    pub fn new(claims: impl IntoIterator<Item = Claim>) -> Result<Self> {
        let (roots, amounts): (Vec<_>, Vec<_>) = claims
            .into_iter()
            .map(|claim| (claim.root, claim.amount))
            .unzip();
        check_count(roots.len())?;
        Ok(Self {
            version: FORMAT_VERSION,
            relation: RELATION.into(),
            roots,
            amounts,
        })
    }

    pub fn fields(&self) -> Result<Vec<F>> {
        ensure!(
            self.version == FORMAT_VERSION && self.relation == RELATION,
            "wrong statement relation/version"
        );
        check_count(self.roots.len())?;
        ensure!(
            self.roots.len() == self.amounts.len(),
            "root and amount counts differ"
        );
        Ok(self
            .roots
            .iter()
            .zip(&self.amounts)
            .flat_map(|(&root, &amount)| Claim { root, amount }.fields())
            .collect())
    }

    pub fn bytes(&self) -> Result<Vec<u8>> {
        Ok(field_bytes(&self.fields()?))
    }
}

pub fn field_bytes(fields: &[F]) -> Vec<u8> {
    fields
        .iter()
        .flat_map(|field| field.as_canonical_u32().to_le_bytes())
        .collect()
}

pub fn hash(preimage: &[u8]) -> Digest {
    Digest(Sha3_256::digest(preimage).into())
}

pub fn check_count(count: usize) -> Result<()> {
    ensure!(
        (1..=MAX_BATCH).contains(&count),
        "batch size must be 1..={MAX_BATCH}"
    );
    Ok(())
}
