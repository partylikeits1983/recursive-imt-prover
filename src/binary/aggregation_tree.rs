//! Fixed-size statement binding for a balanced aggregation tree.
//! These gadgets hash statements; callers must also constrain proof verification.
use anyhow::{Result, ensure};
use p3_circuit::{CircuitBuilder, ExprId};
use serde::{Deserialize, Serialize};

use super::{
    MAX_CHILDREN,
    relation::{AggregatePublic, ClientPublic, F, PUBLIC_BYTES},
    tree::{Hash, keccak},
};

const LEAF_DOMAIN: &[u8] = b"IMT-AGG-LEAF-V1";
const NODE_DOMAIN: &[u8] = b"IMT-AGG-NODE-V1";
pub const STATEMENT_BYTES: usize = 33;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeStatement {
    pub digest: Hash,
    pub count: u8,
}

#[derive(Clone, Copy)]
pub struct TreeTarget {
    pub digest: [ExprId; 32],
    pub count: ExprId,
}

impl TreeStatement {
    pub fn leaf(public: &ClientPublic) -> Self {
        let mut message = LEAF_DOMAIN.to_vec();
        message.extend(public.root);
        message.extend(public.amount.to_le_bytes());
        Self {
            digest: keccak(&message),
            count: 1,
        }
    }

    pub fn merge(left: &Self, right: &Self) -> Result<Self> {
        ensure!(
            left.count == right.count
                && left.count.is_power_of_two()
                && usize::from(left.count) <= MAX_CHILDREN / 2,
            "merge requires equal power-of-two counts, each at most 32"
        );
        let mut message = NODE_DOMAIN.to_vec();
        message.extend(left.digest);
        message.push(left.count);
        message.extend(right.digest);
        message.push(right.count);
        Ok(Self {
            digest: keccak(&message),
            count: left.count * 2,
        })
    }

    pub fn from_public(public: &AggregatePublic) -> Result<Self> {
        let count = public.children.len();
        ensure!(
            count.is_power_of_two() && count <= MAX_CHILDREN,
            "tree requires a power-of-two count in 1..=64"
        );
        let mut level: Vec<_> = public.children.iter().map(Self::leaf).collect();
        while level.len() > 1 {
            level = level
                .as_chunks::<2>()
                .0
                .iter()
                .map(|pair| Self::merge(&pair[0], &pair[1]))
                .collect::<Result<_>>()?;
        }
        Ok(level.remove(0))
    }

    pub fn fields(&self) -> [F; STATEMENT_BYTES] {
        std::array::from_fn(|i| F::new(u64::from(if i < 32 { self.digest[i] } else { self.count })))
    }
}

impl TreeTarget {
    pub fn leaf(b: &mut CircuitBuilder<F>, public: [ExprId; PUBLIC_BYTES]) -> Result<Self> {
        let mut message = domain(b, LEAF_DOMAIN);
        message.extend(public);
        Ok(Self {
            digest: b.native_keccak256_bytes(&message)?,
            count: b.define_const(F::new(1)),
        })
    }

    pub fn merge(b: &mut CircuitBuilder<F>, left: Self, right: Self) -> Result<Self> {
        b.connect(left.count, right.count);
        let bits = b.binary_decompose_coordinates(left.count, MAX_CHILDREN.ilog2() as usize)?;
        let mut selected = ExprId::ZERO;
        let mut count = ExprId::ZERO;
        for (i, &bit) in bits.iter().enumerate() {
            // XOR parity alone would accept 3, 5, ... selected bits.
            for &earlier in &bits[..i] {
                let both = b.mul(bit, earlier);
                b.connect(both, ExprId::ZERO);
            }
            selected = b.add(selected, bit);
            let weight = b.define_const(F::new(1 << (i + 1)));
            count = b.mul_add(bit, weight, count);
        }
        let one = b.define_const(F::new(1));
        b.connect(selected, one);
        let mut message = domain(b, NODE_DOMAIN);
        message.extend(left.digest);
        message.push(left.count);
        message.extend(right.digest);
        message.push(right.count);
        Ok(Self {
            digest: b.native_keccak256_bytes(&message)?,
            count,
        })
    }

    pub fn connect(self, b: &mut CircuitBuilder<F>, expected: [ExprId; STATEMENT_BYTES]) {
        for (actual, expected) in self.digest.into_iter().chain([self.count]).zip(expected) {
            b.connect(actual, expected);
        }
    }
}

fn domain(b: &mut CircuitBuilder<F>, bytes: &[u8]) -> Vec<ExprId> {
    bytes
        .iter()
        .map(|&byte| b.define_const(F::new(u64::from(byte))))
        .collect()
}

#[cfg(test)]
mod tests;
