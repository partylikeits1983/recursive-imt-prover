use anyhow::{Result, ensure};
use p3_binary_field::{Poly64, TowerLevel};
use p3_circuit::ops::binary_native::BinaryCoordinateField;
use p3_circuit::{Circuit, CircuitBuilder, ExprId};
use serde::{Deserialize, Serialize};

use super::{
    IMT_DEPTH,
    tree::{Hash, NODE_DOMAIN, RECORD_DOMAIN, TAG_DOMAIN},
};

pub type F = Poly64;
pub const PUBLIC_BYTES: usize = 96;

#[derive(Clone, Debug)]
pub struct ClientWitness {
    pub input_label: Hash,
    pub input_nonce: Hash,
    pub output_label: Hash,
    pub output_nonce: Hash,
    pub quantity: u64,
    pub leaf_index: u32,
    pub merkle_path: Vec<Hash>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientPublic {
    pub root: Hash,
    pub input_tag: Hash,
    pub output_commitment: Hash,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AggregatePublic {
    pub children: Vec<ClientPublic>,
}

impl ClientPublic {
    pub fn bytes(&self) -> impl Iterator<Item = u8> + '_ {
        self.root
            .iter()
            .chain(&self.input_tag)
            .chain(&self.output_commitment)
            .copied()
    }

    /// Each byte is a raw binary-field coordinate, NOT an integer field embedding.
    pub fn fields(&self) -> Vec<F> {
        self.bytes().map(|b| F::from_repr(u64::from(b))).collect()
    }
}

impl ClientWitness {
    pub fn fields(&self, depth: usize) -> Result<Vec<F>> {
        ensure!(depth == IMT_DEPTH, "child IMT depth must be 32");
        ensure!(self.merkle_path.len() == depth, "incorrect path length");
        let mut fields: Vec<_> = self
            .input_label
            .iter()
            .chain(&self.input_nonce)
            .chain(&self.output_label)
            .chain(&self.output_nonce)
            .chain(&self.quantity.to_le_bytes())
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
    builder.enable_native_keccak_f1600()?;
    let root = builder.alloc_public_input_array::<32>("root");
    let input_tag = builder.alloc_public_input_array::<32>("input-tag");
    let output = builder.alloc_public_input_array::<32>("output-commitment");
    let input_label = builder.alloc_private_input_array::<32>("input-label");
    let input_nonce = builder.alloc_private_input_array::<32>("input-nonce");
    let output_label = builder.alloc_private_input_array::<32>("output-label");
    let output_nonce = builder.alloc_private_input_array::<32>("output-nonce");
    let quantity = builder.alloc_private_input_array::<8>("quantity-le");
    let mut digest = hash(
        &mut builder,
        RECORD_DOMAIN,
        &[&input_label, &input_nonce, &quantity],
    )?;
    let tag = hash(&mut builder, TAG_DOMAIN, &[&input_nonce])?;
    let replacement = hash(
        &mut builder,
        RECORD_DOMAIN,
        &[&output_label, &output_nonce, &quantity],
    )?;
    for (actual, expected) in tag
        .into_iter()
        .zip(input_tag)
        .chain(replacement.into_iter().zip(output))
    {
        builder.connect(actual, expected);
    }
    for _ in 0..depth {
        let direction = builder.alloc_private_input("index_bit");
        builder.assert_bool(direction);
        let sibling = builder.alloc_private_input_array::<32>("sibling");
        let mut left = Vec::with_capacity(32);
        let mut right = Vec::with_capacity(32);
        for i in 0..32 {
            let delta = builder.add(digest[i], sibling[i]);
            let swap = builder.mul(direction, delta);
            left.push(builder.add(digest[i], swap));
            right.push(builder.add(sibling[i], swap));
        }
        digest = hash(&mut builder, NODE_DOMAIN, &[&left, &right])?;
    }
    for i in 0..32 {
        builder.connect(digest[i], root[i]);
    }
    Ok(builder.build()?)
}

fn hash<F: BinaryCoordinateField>(
    builder: &mut CircuitBuilder<F>,
    domain: &[u8],
    parts: &[&[ExprId]],
) -> Result<[ExprId; 32]> {
    let mut message: Vec<_> = domain
        .iter()
        .map(|&b| {
            builder.define_const(F::from_raw_coordinates(u128::from(b)).expect("byte fits carrier"))
        })
        .collect();
    for part in parts {
        message.extend_from_slice(part);
    }
    Ok(builder.native_keccak256_bytes(&message)?)
}
