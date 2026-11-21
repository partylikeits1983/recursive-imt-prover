use crate::scalar::Fr;
use ark_ff::{BigInteger, PrimeField};
use sha3::{Digest, Keccak256};

pub struct Sponge([u8; 32]);

impl Sponge {
    pub fn new() -> Self {
        Self(Keccak256::digest(b"recursive-imt/three-round-gkr-control/v1").into())
    }
    pub fn bit_claims() -> Self {
        Self(Keccak256::digest(b"recursive-imt/segment-gkr-bits/v1").into())
    }
    pub fn absorb(&mut self, value: Fr) {
        self.0 = Keccak256::new()
            .chain_update(self.0)
            .chain_update([0])
            .chain_update(value.into_bigint().to_bytes_be())
            .finalize()
            .into();
    }
    pub fn squeeze(&mut self) -> Fr {
        self.0 = Keccak256::new()
            .chain_update(self.0)
            .chain_update([1])
            .finalize()
            .into();
        let second = Keccak256::new()
            .chain_update(self.0)
            .chain_update([2])
            .finalize();
        Fr::from_be_bytes_mod_order(&[self.0.as_slice(), &second].concat())
    }
}
