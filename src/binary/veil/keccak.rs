//! Direct constraint fixture using the upstream characteristic-two Keccak AIR.
//! This deliberately exposes the cost of applying the inner argument to a whole
//! execution. The intended fast compiler applies it to verifier algebra only.

use anyhow::{Result, bail, ensure};
use p3_air::{AirLayout, BaseEntry, BaseLeaf, SymbolicExpression, get_symbolic_constraints};
use p3_field::PrimeCharacteristicRing;
use p3_keccak_air::{KeccakBinaryAir, NUM_KECCAK_BINARY_COLS, generate_binary_trace_rows};

use super::{
    E, F,
    constraints::{Linear, Relation},
};
use crate::binary::{
    relation::{ClientPublic, ClientWitness},
    tree::{LEAF_DOMAIN, NODE_DOMAIN, commitment, parent},
};

const STATE_BITS: usize = 1600;
const ROWS: usize = 25;
const PERMUTATION_WIRES: usize = ROWS * STATE_BITS;

pub struct KeccakMembership {
    pub relation: Relation,
    pub depth: usize,
    derived: Vec<[Linear; 2]>,
    base_variables: usize,
}

impl KeccakMembership {
    /// Depth zero is the standalone private note-preimage experiment.
    pub fn new(depth: usize) -> Result<Self> {
        ensure!(depth <= 32, "depth exceeds 32");
        let hashes = depth + 1;
        let base_variables = hashes * PERMUTATION_WIRES + depth;
        let mut result = Self {
            relation: Relation {
                variables: base_variables,
                public_wires: vec![],
                linear: vec![],
                products: vec![],
            },
            depth,
            derived: vec![],
            base_variables,
        };
        let air = KeccakBinaryAir::default();
        let expressions = get_symbolic_constraints::<F, _>(&air, AirLayout::from_air::<F>(&air));
        for hash in 0..hashes {
            for row in 0..ROWS {
                for expression in &expressions {
                    result.constrain_air(expression, hash, row)?;
                }
            }
            let domain = if hash == 0 { LEAF_DOMAIN } else { NODE_DOMAIN };
            let message_len = if hash == 0 { 88 } else { 80 };
            // Fixed tag, Keccak suffix, rate padding, and zero capacity bits.
            for byte in 0..200 {
                let fixed = if let Some(&value) = domain.get(byte) {
                    Some(value)
                } else if byte == message_len {
                    Some(1)
                } else if byte == 135 {
                    Some(128)
                } else if byte > message_len {
                    Some(0)
                } else {
                    None
                };
                if let Some(value) = fixed {
                    for bit in 0..8 {
                        result.relation.linear.push(Linear {
                            constant: E::from_u8((value >> bit) & 1),
                            terms: vec![(hash * PERMUTATION_WIRES + byte * 8 + bit, E::ONE)],
                        });
                    }
                }
            }
            if hash > 0 {
                let direction = hashes * PERMUTATION_WIRES + hash - 1;
                let d = Linear::wire(direction);
                let mut opposite = d.clone();
                opposite.constant = E::ONE;
                result
                    .relation
                    .products
                    .push([d.clone(), opposite.clone(), Linear::default()]);
                for bit in 0..256 {
                    let previous = (hash - 1) * PERMUTATION_WIRES + 24 * STATE_BITS + bit;
                    for (offset, selector) in [(16 * 8, opposite.clone()), (48 * 8, d.clone())] {
                        let delta = Linear {
                            constant: E::ZERO,
                            terms: vec![
                                (hash * PERMUTATION_WIRES + offset + bit, E::ONE),
                                (previous, E::ONE),
                            ],
                        };
                        result
                            .relation
                            .products
                            .push([selector, delta, Linear::default()]);
                    }
                }
            }
        }
        result
            .relation
            .public_wires
            .extend((0..256).map(|bit| depth * PERMUTATION_WIRES + 24 * STATE_BITS + bit));
        result.relation.public_wires.extend(48 * 8..56 * 8);
        Ok(result)
    }

    pub fn public_values(public: &ClientPublic) -> Vec<E> {
        public
            .root
            .iter()
            .chain(public.amount.to_le_bytes().iter())
            .flat_map(|&byte| (0..8).map(move |bit| E::from_u8((byte >> bit) & 1)))
            .collect()
    }

    pub fn witness(&self, public: &ClientPublic, witness: &ClientWitness) -> Result<Vec<E>> {
        ensure!(
            witness.merkle_path.len() == self.depth,
            "incorrect path length"
        );
        ensure!(
            u64::from(witness.leaf_index) < 1u64 << self.depth,
            "index outside tree"
        );
        let mut note = Vec::from(LEAF_DOMAIN.as_slice());
        note.extend(witness.secret);
        note.extend(public.amount.to_le_bytes());
        note.extend(witness.nonce);
        let mut inputs = vec![sponge_input(&note)];
        let mut current = commitment(&witness.secret, public.amount, &witness.nonce);
        for (level, sibling) in witness.merkle_path.iter().enumerate() {
            let (left, right) = if (witness.leaf_index >> level) & 1 == 0 {
                (&current, sibling)
            } else {
                (sibling, &current)
            };
            let mut message = Vec::from(NODE_DOMAIN.as_slice());
            message.extend(left);
            message.extend(right);
            inputs.push(sponge_input(&message));
            current = parent(left, right);
        }
        let trace = generate_binary_trace_rows::<F>(inputs, 0);
        let mut values = Vec::with_capacity(self.relation.variables);
        for row in trace
            .values
            .as_chunks::<NUM_KECCAK_BINARY_COLS>()
            .0
            .iter()
            .take((self.depth + 1) * ROWS)
        {
            values.extend(row[ROWS..].iter().copied().map(E::from));
        }
        for level in 0..self.depth {
            values.push(E::from_u32((witness.leaf_index >> level) & 1));
        }
        ensure!(values.len() == self.base_variables, "incorrect trace shape");
        for [a, b] in &self.derived {
            values.push(a.evaluate(&values) * b.evaluate(&values));
        }
        Ok(values)
    }

    fn constrain_air(
        &mut self,
        expression: &SymbolicExpression<F>,
        hash: usize,
        row: usize,
    ) -> Result<()> {
        // Avoid introducing a separate witness for a product constrained to zero.
        if let SymbolicExpression::Mul { x, y, .. } = expression {
            let a = self.compile(x, hash, row)?;
            if a.terms.is_empty() && a.constant == E::ZERO {
                return Ok(());
            }
            let b = self.compile(y, hash, row)?;
            if !a.terms.is_empty() && !b.terms.is_empty() {
                self.relation.products.push([a, b, Linear::default()]);
                return Ok(());
            }
            let value = multiply_constant(a, b);
            self.assert_linear(value);
        } else {
            let value = self.compile(expression, hash, row)?;
            self.assert_linear(value);
        }
        Ok(())
    }

    fn assert_linear(&mut self, value: Linear) {
        if !value.terms.is_empty() || value.constant != E::ZERO {
            self.relation.linear.push(value);
        }
    }

    fn compile(
        &mut self,
        expression: &SymbolicExpression<F>,
        hash: usize,
        row: usize,
    ) -> Result<Linear> {
        match expression {
            SymbolicExpression::Leaf(leaf) => Ok(match leaf {
                BaseLeaf::Constant(value) => Linear::constant(E::from(*value)),
                BaseLeaf::IsFirstRow => Linear::constant(E::from_bool(row == 0)),
                BaseLeaf::IsLastRow => Linear::constant(E::from_bool(row == ROWS - 1)),
                BaseLeaf::IsTransition => Linear::constant(E::from_bool(row != ROWS - 1)),
                BaseLeaf::Variable(variable) => {
                    let BaseEntry::Main { offset } = variable.entry else {
                        bail!("unsupported Keccak AIR leaf");
                    };
                    ensure!(
                        offset <= 1 && variable.index < NUM_KECCAK_BINARY_COLS,
                        "unexpected AIR window"
                    );
                    let selected = (row + offset) % ROWS;
                    if variable.index < ROWS {
                        Linear::constant(E::from_bool(variable.index == selected))
                    } else {
                        Linear::wire(
                            hash * PERMUTATION_WIRES + selected * STATE_BITS + variable.index
                                - ROWS,
                        )
                    }
                }
            }),
            SymbolicExpression::Add { x, y, .. } | SymbolicExpression::Sub { x, y, .. } => {
                let mut a = self.compile(x, hash, row)?;
                let b = self.compile(y, hash, row)?;
                a.constant += b.constant;
                a.terms.extend(b.terms);
                Ok(a)
            }
            SymbolicExpression::Neg { x, .. } => self.compile(x, hash, row),
            SymbolicExpression::Mul { x, y, .. } => {
                let a = self.compile(x, hash, row)?;
                if a.terms.is_empty() && a.constant == E::ZERO {
                    return Ok(a);
                }
                let b = self.compile(y, hash, row)?;
                if a.terms.is_empty() || b.terms.is_empty() {
                    return Ok(multiply_constant(a, b));
                }
                let output = Linear::wire(self.relation.variables);
                self.relation.variables += 1;
                self.relation
                    .products
                    .push([a.clone(), b.clone(), output.clone()]);
                self.derived.push([a, b]);
                Ok(output)
            }
        }
    }
}

fn multiply_constant(a: Linear, b: Linear) -> Linear {
    let (coefficient, mut expression) = if a.terms.is_empty() {
        (a.constant, b)
    } else {
        (b.constant, a)
    };
    expression.constant *= coefficient;
    if coefficient == E::ZERO {
        expression.terms.clear();
    } else {
        for (_, value) in &mut expression.terms {
            *value *= coefficient;
        }
    }
    expression
}

fn sponge_input(message: &[u8]) -> [u64; 25] {
    assert!(message.len() < 135);
    let mut state = [0u8; 200];
    state[..message.len()].copy_from_slice(message);
    state[message.len()] = 1;
    state[135] = 128;
    std::array::from_fn(|i| u64::from_le_bytes(state[8 * i..8 * i + 8].try_into().unwrap()))
}
