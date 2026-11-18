use alloc::vec::Vec;
use core::hash::Hash;

use p3_circuit::CircuitBuilder;
use p3_field::Field;

use super::{BinaryRelationPolicy, VerificationError, evaluate_table};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum PeriodicColumn {
    Dense(Vec<u128>),
    Address { log: usize, successor: bool },
}

impl PeriodicColumn {
    pub fn new(values: Vec<u128>) -> Self {
        for successor in [false, true] {
            if values
                .iter()
                .enumerate()
                .all(|(i, &v)| v == ((i + usize::from(successor)) & (values.len() - 1)) as u128)
            {
                return Self::Address {
                    log: values.len().ilog2() as usize,
                    successor,
                };
            }
        }
        Self::Dense(values)
    }

    pub fn len(&self) -> usize {
        match self {
            Self::Dense(v) => v.len(),
            Self::Address { log, .. } => 1 << log,
        }
    }

    pub fn storage_len(&self) -> usize {
        match self {
            Self::Dense(v) => v.len(),
            Self::Address { .. } => 2,
        }
    }

    pub fn value(&self, i: usize) -> u128 {
        match self {
            Self::Dense(v) => v[i],
            Self::Address { successor, .. } => {
                ((i + usize::from(*successor)) & (self.len() - 1)) as u128
            }
        }
    }

    pub fn evaluate<P, F>(
        &self,
        b: &mut CircuitBuilder<F>,
        point: &[P::ChallengeTarget],
    ) -> Result<P::ChallengeTarget, VerificationError>
    where
        F: Field + Eq + Hash,
        P: BinaryRelationPolicy<F>,
    {
        let point = &point[point.len() - self.len().ilog2() as usize..];
        match self {
            Self::Address { successor, .. } => {
                let mut value = P::constant(b, 0)?;
                let mut carry = P::constant(b, 1)?;
                for (bit, x) in point.iter().rev().enumerate() {
                    let digit = if *successor {
                        P::add(b, x, &carry)
                    } else {
                        x.clone()
                    };
                    let basis = P::constant(b, 1u128 << bit)?;
                    value = P::mul_add(b, &basis, &digit, &value);
                    if *successor {
                        carry = P::mul(b, &carry, x);
                    }
                    b.check_construction_limits()?;
                }
                Ok(value)
            }
            Self::Dense(values) => {
                let values = values
                    .iter()
                    .map(|&v| {
                        let value = P::constant(b, v)?;
                        b.check_construction_limits()?;
                        Ok(value)
                    })
                    .collect::<Result<Vec<_>, VerificationError>>()?;
                evaluate_table::<P, F>(b, &values, point)
            }
        }
    }
}
