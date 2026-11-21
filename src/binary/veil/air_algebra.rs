//! Compile the fixed AIR endpoint into the small masked verifier relation.
//! Public preprocessing is evaluated independently; every private multiplication
//! gets a masked wire and an enforced product equation.

use std::collections::HashMap;

use anyhow::{Result, bail, ensure};
use p3_air::{BaseEntry, BaseLeaf, SymbolicExpression};
use p3_multi_stark::selectors::BoundaryEvals;
use serde::Serialize;
use sha3::{Digest, Keccak256};

use super::{E, F, compiler::MaskedReader, constraints::Linear};

pub(super) mod recursive;

pub(super) struct AirAlgebra {
    pub(super) gates: Vec<Gate>,
    pub(super) private: Vec<bool>,
    pub(super) outputs: Vec<usize>,
    pub products: usize,
    pub identity: [u8; 32],
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, Serialize)]
pub enum Gate {
    Constant(F),
    Main(usize, usize),
    Preprocessed(usize, usize),
    Public(usize),
    First,
    Last,
    Transition,
    Add(usize, usize),
    Mul(usize, usize),
}

pub(super) struct PublicEvaluation<'a> {
    pub inputs: &'a [F],
    pub preprocessed: &'a [Vec<E>],
    pub boundary: BoundaryEvals<E>,
}

pub(super) struct AlgebraConstraints {
    pub outputs: Vec<Linear>,
    pub products: Vec<[Linear; 3]>,
}

impl AirAlgebra {
    pub fn new(expressions: &[SymbolicExpression<F>]) -> Result<Self> {
        let mut result = Self {
            gates: vec![],
            private: vec![],
            outputs: vec![],
            products: 0,
            identity: [0; 32],
        };
        let mut cache = HashMap::new();
        for expression in expressions {
            let output = result.compile(expression, &mut cache)?;
            result.outputs.push(output);
        }
        result.identity = Keccak256::digest(postcard::to_allocvec(&(
            b"binary-masked-air-algebra-v1",
            &result.gates,
            &result.outputs,
        ))?)
        .into();
        Ok(result)
    }

    fn compile(
        &mut self,
        expression: &SymbolicExpression<F>,
        cache: &mut HashMap<Gate, usize>,
    ) -> Result<usize> {
        let gate = match expression {
            SymbolicExpression::Leaf(leaf) => match *leaf {
                BaseLeaf::Constant(value) => Gate::Constant(value),
                BaseLeaf::IsFirstRow => Gate::First,
                BaseLeaf::IsLastRow => Gate::Last,
                BaseLeaf::IsTransition => Gate::Transition,
                BaseLeaf::Variable(v) => match v.entry {
                    BaseEntry::Main { offset } if offset < 2 => Gate::Main(offset, v.index),
                    BaseEntry::Preprocessed { offset } if offset < 2 => {
                        Gate::Preprocessed(offset, v.index)
                    }
                    BaseEntry::Public => Gate::Public(v.index),
                    _ => bail!("unsupported AIR endpoint variable"),
                },
            },
            SymbolicExpression::Neg { x, .. } => return self.compile(x, cache),
            SymbolicExpression::Add { x, y, .. } | SymbolicExpression::Sub { x, y, .. } => {
                Gate::Add(self.compile(x, cache)?, self.compile(y, cache)?)
            }
            SymbolicExpression::Mul { x, y, .. } => {
                Gate::Mul(self.compile(x, cache)?, self.compile(y, cache)?)
            }
        };
        if let Some(&index) = cache.get(&gate) {
            return Ok(index);
        }
        let private = match gate {
            Gate::Main(..) => true,
            Gate::Add(a, b) | Gate::Mul(a, b) => self.private[a] || self.private[b],
            _ => false,
        };
        if let Gate::Mul(a, b) = gate {
            self.products += usize::from(self.private[a] && self.private[b]);
        }
        let index = self.gates.len();
        self.gates.push(gate);
        self.private.push(private);
        cache.insert(gate, index);
        Ok(index)
    }

    /// This computes only the private multiplication outputs used by the
    /// verifier algebra. No original trace element is added to the transcript.
    pub fn witness(&self, main: &[Vec<E>], public: &PublicEvaluation<'_>) -> Result<Vec<E>> {
        let mut values = Vec::with_capacity(self.gates.len());
        let mut products = Vec::with_capacity(self.products);
        for gate in &self.gates {
            let value = match *gate {
                Gate::Main(row, column) => main[row][column],
                Gate::Add(a, b) => values[a] + values[b],
                Gate::Mul(a, b) => {
                    let product = values[a] * values[b];
                    if self.private[a] && self.private[b] {
                        products.push(product);
                    }
                    product
                }
                _ => public.value(gate)?,
            };
            values.push(value);
        }
        Ok(products)
    }

    pub fn constrain(
        &self,
        main: &[Vec<Linear>],
        public: &PublicEvaluation<'_>,
        reader: &mut MaskedReader<'_>,
    ) -> Result<AlgebraConstraints> {
        let wires = reader.read(b"air-verifier-products", self.products)?;
        let mut cursor = 0;
        let mut values: Vec<Linear> = Vec::with_capacity(self.gates.len());
        let mut products = Vec::with_capacity(self.products);
        for gate in &self.gates {
            let value = match *gate {
                Gate::Main(row, column) => main[row][column].clone(),
                Gate::Add(a, b) => add(&values[a], &values[b]),
                Gate::Mul(a, b) if self.private[a] && self.private[b] => {
                    let output = wires[cursor].clone();
                    cursor += 1;
                    products.push([values[a].clone(), values[b].clone(), output.clone()]);
                    output
                }
                Gate::Mul(a, b) => {
                    let (fixed, other) = if self.private[a] { (b, a) } else { (a, b) };
                    ensure!(
                        values[fixed].terms.is_empty(),
                        "public AIR gate became private"
                    );
                    scale(&values[other], values[fixed].constant)
                }
                _ => Linear::constant(public.value(gate)?),
            };
            values.push(value);
        }
        ensure!(cursor == self.products, "AIR product schedule mismatch");
        Ok(AlgebraConstraints {
            outputs: self.outputs.iter().map(|&i| values[i].clone()).collect(),
            products,
        })
    }
}

impl PublicEvaluation<'_> {
    fn value(&self, gate: &Gate) -> Result<E> {
        Ok(match *gate {
            Gate::Constant(value) => E::from(value),
            Gate::Public(i) => E::from(self.inputs[i]),
            Gate::Preprocessed(row, column) => self.preprocessed[row][column],
            Gate::First => self.boundary.first,
            Gate::Last => self.boundary.last,
            Gate::Transition => self.boundary.transition,
            _ => bail!("not a public AIR leaf"),
        })
    }
}

pub(super) fn add(a: &Linear, b: &Linear) -> Linear {
    let mut result = a.clone();
    result.constant += b.constant;
    result.terms.extend_from_slice(&b.terms);
    result
}

pub(super) fn scale(a: &Linear, factor: E) -> Linear {
    Linear {
        constant: a.constant * factor,
        terms: a.terms.iter().map(|&(i, c)| (i, c * factor)).collect(),
    }
}
