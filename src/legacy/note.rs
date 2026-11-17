use crate::legacy::statement::{DIGEST_BYTES, Digest, hash};
use rand::Rng;
use serde::{Deserialize, Serialize};

pub const SECRET_BYTES: usize = DIGEST_BYTES;
pub const AMOUNT_BYTES: usize = size_of::<u64>();
pub const AMOUNT_OFFSET: usize = 2 * SECRET_BYTES;
pub const NOTE_BYTES: usize = AMOUNT_OFFSET + AMOUNT_BYTES;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Note {
    pub secret: Digest,
    pub nullifier: Digest,
    pub amount: u64,
}

impl Note {
    pub fn random(amount: u64) -> Self {
        let mut secret = [0; SECRET_BYTES];
        let mut nullifier = [0; SECRET_BYTES];
        let mut rng = rand::rng();
        rng.fill_bytes(&mut secret);
        rng.fill_bytes(&mut nullifier);
        Self {
            secret: Digest(secret),
            nullifier: Digest(nullifier),
            amount,
        }
    }

    pub fn message(&self) -> [u8; NOTE_BYTES] {
        let mut message = [0; NOTE_BYTES];
        message[..SECRET_BYTES].copy_from_slice(&self.secret.0);
        message[SECRET_BYTES..AMOUNT_OFFSET].copy_from_slice(&self.nullifier.0);
        message[AMOUNT_OFFSET..].copy_from_slice(&self.amount.to_le_bytes());
        message
    }

    pub fn commitment(&self) -> Digest {
        hash(&self.message())
    }
}
