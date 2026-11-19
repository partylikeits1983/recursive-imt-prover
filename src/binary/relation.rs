use anyhow::{Result, ensure};
use p3_binary_field::{Poly64, TowerLevel};
use p3_circuit::ops::binary_native::BinaryCoordinateField;
use p3_circuit::{Circuit, CircuitBuilder};
use serde::{Deserialize, Serialize};

use super::{
    IMT_DEPTH,
    tree::{Hash, LEAF_DOMAIN, NODE_DOMAIN, NULLIFIER_DOMAIN},
};

pub type F = Poly64;
pub const PUBLIC_BYTES: usize = 64;

#[derive(Clone, Debug)]
pub struct ClientWitness {
    pub secret_num: Hash,
    pub nullifier: Hash,
    pub leaf_index: u32,
    pub merkle_path: Vec<Hash>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientPublic {
    pub root: Hash,
    pub nullifier_hash: Hash,
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
            .chain(&self.nullifier_hash)
            .map(|&b| F::from_repr(u64::from(b)))
            .collect()
    }
}

impl ClientWitness {
    pub fn fields(&self, depth: usize) -> Result<Vec<F>> {
        ensure!(depth == IMT_DEPTH, "child IMT depth must be 32");
        ensure!(self.merkle_path.len() == depth, "incorrect path length");
        let mut fields: Vec<_> = self
            .secret_num
            .iter()
            .chain(&self.nullifier)
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
    ensure!(depth == IMT_DEPTH, "child IMT depth must be 32");
    ensure!(F::COORDINATE_BITS >= 8, "carrier must represent full bytes");
    let mut builder = CircuitBuilder::<F>::new();
    builder.enable_native_blake3_compress()?;
    let root = builder.alloc_public_input_array::<32>("root");
    let nullifier_hash = builder.alloc_public_input_array::<32>("nullifier-hash");
    let secret = builder.alloc_private_input_array::<32>("secret-num");
    let nullifier = builder.alloc_private_input_array::<32>("nullifier");
    let mut message: Vec<_> = LEAF_DOMAIN
        .iter()
        .map(|&byte| {
            builder
                .define_const(F::from_raw_coordinates(u128::from(byte)).expect("byte fits carrier"))
        })
        .collect();
    message.extend(secret);
    message.extend(nullifier);
    // The native sponge constrains every byte to eight Boolean coordinates,
    // and enforces BLAKE3 padding and permutation calls.
    let mut digest = builder.native_blake3_bytes(&message)?;
    let mut message: Vec<_> = NULLIFIER_DOMAIN
        .iter()
        .map(|&byte| {
            builder
                .define_const(F::from_raw_coordinates(u128::from(byte)).expect("byte fits carrier"))
        })
        .collect();
    message.extend(nullifier);
    let computed = builder.native_blake3_bytes(&message)?;
    for (actual, expected) in computed.into_iter().zip(nullifier_hash) {
        builder.connect(actual, expected);
    }
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
        digest = builder.native_blake3_bytes(&node)?;
    }
    for i in 0..32 {
        builder.connect(digest[i], root[i]);
    }
    Ok(builder.build()?)
}
