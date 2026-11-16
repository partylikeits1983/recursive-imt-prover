use anyhow::{Result, ensure};
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use rand::RngExt;
use serde::{Deserialize, Serialize};
pub use spartan_whir::engine::F;

pub const MODULUS: u32 = 2_130_706_433;
pub const NOTE: u32 = 0x494d01;
pub const NULLIFIER: u32 = 0x494d02;
pub const NODE: u32 = 0x494d03;
pub const EMPTY: Digest = Digest([0; 8]);
pub const CTX: Digest = Digest([0x494d54, 1, 2026, 11, 16, 0, 0, 1]);
pub const HASH_PROFILE: &str = "koalabear-poseidon2-width24-rate16-capacity8-digest8-v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "[u32;8]")]
pub struct Digest(pub [u32; 8]);
impl TryFrom<[u32; 8]> for Digest {
    type Error = String;
    fn try_from(x: [u32; 8]) -> Result<Self, Self::Error> {
        if x.iter().any(|x| *x >= MODULUS) {
            return Err("noncanonical KoalaBear digest".into());
        }
        Ok(Self(x))
    }
}
impl Digest {
    pub fn fields(self) -> [F; 8] {
        self.0.map(|x| {
            assert!(x < MODULUS);
            F::from_u32(x)
        })
    }
    pub fn from_fields(x: [F; 8]) -> Self {
        Self(x.map(|x| x.as_canonical_u32()))
    }
    pub fn random(rng: &mut impl rand::CryptoRng) -> Self {
        Self(core::array::from_fn(|_| {
            loop {
                let x: u32 = rng.random();
                if x < MODULUS {
                    break x;
                }
            }
        }))
    }
}
pub fn hash(domain: u32, fields: &[F]) -> Digest {
    Digest::from_fields(spartan_whir::withdrawal::hash_fields(domain, fields))
}
pub fn note(ctx: Digest, secret: Digest, randomness: Digest) -> Digest {
    hash(
        NOTE,
        &[ctx.fields(), secret.fields(), randomness.fields()].concat(),
    )
}
pub fn nullifier(ctx: Digest, secret: Digest, randomness: Digest) -> Digest {
    hash(
        NULLIFIER,
        &[ctx.fields(), secret.fields(), randomness.fields()].concat(),
    )
}
pub fn node(left: Digest, right: Digest) -> Digest {
    hash(NODE, &[left.fields(), right.fields()].concat())
}
pub fn check_depth(depth: u8) -> Result<()> {
    ensure!((1..=32).contains(&depth), "depth must be 1..=32");
    Ok(())
}
pub fn root_from_path(leaf: Digest, index: u64, path: &[Digest]) -> Result<Digest> {
    check_depth(path.len().try_into()?)?;
    ensure!(index < 1u64 << path.len(), "index outside tree");
    Ok(path.iter().enumerate().fold(leaf, |v, (i, s)| {
        if (index >> i) & 1 == 0 {
            node(v, *s)
        } else {
            node(*s, v)
        }
    }))
}
