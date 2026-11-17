use anyhow::{Result, ensure};
use p3_binary_field::{Poly64, TowerLevel};
use p3_circuit::ops::binary_native::BinaryCoordinateField;
use p3_circuit::{Circuit, CircuitBuilder};
use serde::{Deserialize, Serialize};

use super::tree::{Hash, LEAF_DOMAIN, NODE_DOMAIN};

pub type F = Poly64;
pub const PUBLIC_BYTES: usize = 40;

#[derive(Clone, Debug)]
pub struct ClientWitness {
    pub secret: Hash,
    pub nonce: Hash,
    pub leaf_index: u32,
    pub merkle_path: Vec<Hash>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientPublic {
    pub root: Hash,
    pub amount: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AggregatePublic {
    pub children: Vec<ClientPublic>,
}

impl ClientPublic {
    /// Each byte is a raw binary-field coordinate, NOT an integer field embedding.
    pub fn fields(&self) -> Vec<F> {
        self.root
            .iter()
            .chain(self.amount.to_le_bytes().iter())
            .map(|&b| F::from_repr(u64::from(b)))
            .collect()
    }
}

impl ClientWitness {
    pub fn fields(&self, depth: usize) -> Result<Vec<F>> {
        ensure!((1..=32).contains(&depth), "depth must be in 1..=32");
        ensure!(self.merkle_path.len() == depth, "incorrect path length");
        ensure!(
            u64::from(self.leaf_index) < 1u64 << depth,
            "index outside tree"
        );
        let mut fields: Vec<_> = self
            .secret
            .iter()
            .chain(&self.nonce)
            .map(|&b| F::from_repr(u64::from(b)))
            .collect();
        for (level, sibling) in self.merkle_path.iter().enumerate() {
            fields.push(F::from_repr(u64::from((self.leaf_index >> level) & 1)));
            fields.extend(sibling.iter().map(|&b| F::from_repr(u64::from(b))));
        }
        Ok(fields)
    }
}

pub fn membership_circuit(depth: usize) -> Result<Circuit<F>> {
    membership_circuit_over::<F>(depth)
}

/// The same byte/bit relation over a supported native binary carrier.
pub fn membership_circuit_over<F: BinaryCoordinateField>(depth: usize) -> Result<Circuit<F>> {
    ensure!((1..=32).contains(&depth), "depth must be in 1..=32");
    ensure!(F::COORDINATE_BITS >= 8, "carrier must represent full bytes");
    let mut builder = CircuitBuilder::<F>::new();
    builder.enable_native_keccak_f1600()?;
    let root = builder.alloc_public_input_array::<32>("root");
    let amount = builder.alloc_public_input_array::<8>("amount_le");
    let secret = builder.alloc_private_input_array::<32>("secret");
    let nonce = builder.alloc_private_input_array::<32>("nonce");
    let mut message: Vec<_> = LEAF_DOMAIN
        .iter()
        .map(|&byte| {
            builder
                .define_const(F::from_raw_coordinates(u128::from(byte)).expect("byte fits carrier"))
        })
        .collect();
    message.extend(secret);
    message.extend(amount);
    message.extend(nonce);
    // The native sponge constrains every byte to eight Boolean coordinates,
    // including amount bytes, and enforces Keccak padding and permutation calls.
    let mut digest = builder.native_keccak256_bytes(&message)?;
    for _ in 0..depth {
        let direction = builder.alloc_private_input("index_bit");
        builder.assert_bool(direction);
        let sibling = builder.alloc_private_input_array::<32>("sibling");
        let mut node: Vec<_> = NODE_DOMAIN
            .iter()
            .map(|&byte| {
                builder.define_const(
                    F::from_raw_coordinates(u128::from(byte)).expect("byte fits carrier"),
                )
            })
            .collect();
        let mut right = Vec::with_capacity(32);
        for i in 0..32 {
            let delta = builder.add(digest[i], sibling[i]);
            let swap = builder.mul(direction, delta);
            node.push(builder.add(digest[i], swap));
            right.push(builder.add(sibling[i], swap));
        }
        node.extend(right);
        digest = builder.native_keccak256_bytes(&node)?;
    }
    for i in 0..32 {
        builder.connect(digest[i], root[i]);
    }
    Ok(builder.build()?)
}
