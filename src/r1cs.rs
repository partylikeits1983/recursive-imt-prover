//! Small linear-combination R1CS builder adapted from the pinned Spartan withdrawal example.
use crate::gadgets::poseidon::Arithmetic;
use p3_field::{Field, PrimeCharacteristicRing, PrimeField32};
use spartan_whir::{R1csShape, R1csWitness, SparseMatEntry, SparseMatrix, engine::F};
use std::collections::BTreeMap;
#[derive(Clone, Debug, serde::Serialize)]
pub struct CircuitStats {
    pub constraints: usize,
    pub witness_variables: usize,
    pub public_inputs: usize,
    pub poseidon_permutations: usize,
    pub matrix_nonzeros: usize,
}
pub struct Circuit {
    pub shape: R1csShape<F>,
    pub witness: R1csWitness<F>,
    pub public_inputs: Vec<F>,
    pub stats: CircuitStats,
}
impl Circuit {
    pub fn satisfied(&self) -> bool {
        let mut z = self.witness.w.clone();
        z.push(F::ONE);
        z.extend(&self.public_inputs);
        let Ok((a, b, c)) = self.shape.multiply_vec(&z) else {
            return false;
        };
        a.iter().zip(b).zip(c).all(|((&a, b), c)| a * b == c)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Wire {
    One,
    Public(usize),
    Witness(usize),
}

#[derive(Clone, Debug)]
pub struct Linear(pub Vec<(Wire, F)>);

impl Linear {
    pub fn constant(value: F) -> Self {
        Self(if value == F::ZERO {
            vec![]
        } else {
            vec![(Wire::One, value)]
        })
    }

    pub fn wire(wire: Wire) -> Self {
        Self(vec![(wire, F::ONE)])
    }

    pub fn add(&self, rhs: &Self) -> Self {
        let mut entries = BTreeMap::new();
        for &(wire, value) in self.0.iter().chain(&rhs.0) {
            *entries.entry(wire).or_insert(F::ZERO) += value;
        }
        Self(
            entries
                .into_iter()
                .filter(|(_, value)| *value != F::ZERO)
                .collect(),
        )
    }

    pub fn scale(&self, scalar: F) -> Self {
        Self(
            self.0
                .iter()
                .map(|&(wire, value)| (wire, value * scalar))
                .filter(|(_, value)| *value != F::ZERO)
                .collect(),
        )
    }

    pub fn sub(&self, rhs: &Self) -> Self {
        self.add(&rhs.scale(-F::ONE))
    }
}

pub struct Builder {
    pub public: Vec<F>,
    pub witness: Vec<F>,
    pub constraints: Vec<[Linear; 3]>,
    pub permutations: usize,
    pub record_constraints: bool,
}

impl Builder {
    pub fn new(public: Vec<F>, record_constraints: bool) -> Self {
        Self {
            public,
            witness: Vec::new(),
            constraints: Vec::new(),
            permutations: 0,
            record_constraints,
        }
    }

    pub fn value(&self, linear: &Linear) -> F {
        linear
            .0
            .iter()
            .map(|&(wire, coefficient)| {
                coefficient
                    * match wire {
                        Wire::One => F::ONE,
                        Wire::Public(i) => self.public[i],
                        Wire::Witness(i) => self.witness[i],
                    }
            })
            .sum()
    }

    pub fn private(&mut self, value: F) -> Linear {
        let result = Linear::wire(Wire::Witness(self.witness.len()));
        self.witness.push(value);
        result
    }

    pub fn private_digest(&mut self, values: [F; 8]) -> Vec<Linear> {
        values
            .into_iter()
            .map(|value| self.private(value))
            .collect()
    }

    pub fn enforce(&mut self, a: Linear, b: Linear, c: Linear) {
        if self.record_constraints {
            self.constraints.push([a, b, c]);
        }
    }

    pub fn equal(&mut self, left: Linear, right: Linear) {
        self.enforce(left, Linear::constant(F::ONE), right);
    }

    pub fn mul(&mut self, left: Linear, right: Linear) -> Linear {
        let out = self.private(self.value(&left) * self.value(&right));
        self.enforce(left, right, out.clone());
        out
    }

    pub fn compact(&mut self, expression: Linear) -> Linear {
        if expression.0.len() <= 4 {
            expression
        } else {
            let out = self.private(self.value(&expression));
            self.equal(expression, out.clone());
            out
        }
    }

    pub fn boolean(&mut self, value: bool) -> Linear {
        let bit = self.private(F::from_bool(value));
        self.enforce(
            bit.clone(),
            bit.sub(&Linear::constant(F::ONE)),
            Linear::constant(F::ZERO),
        );
        bit
    }

    pub fn range(&mut self, input: Linear, bits: usize) {
        let value = self.value(&input).as_canonical_u32();
        let mut reconstructed = Linear::constant(F::ZERO);
        for bit in 0..bits {
            let wire = self.boolean((value >> bit) & 1 != 0);
            reconstructed = reconstructed.add(&wire.scale(F::from_u32(1 << bit)));
        }
        self.equal(input, reconstructed);
    }

    pub fn hash(&mut self, domain: u32, input: &[Linear]) -> Vec<Linear> {
        self.permutations += input.len().div_ceil(16).max(1);
        crate::gadgets::poseidon::hash(self, domain, input)
    }
    pub fn nonzero_digest(&mut self, x: &[Linear]) {
        let mut sum = Linear::constant(F::ZERO);
        let mut selected = false;
        for t in x {
            let v = self.value(t);
            let inv = if !selected && v != F::ZERO {
                selected = true;
                v.inverse()
            } else {
                F::ZERO
            };
            let iv = self.private(inv);
            let p = self.mul(t.clone(), iv);
            sum = sum.add(&p);
        }
        self.equal(sum, Linear::constant(F::ONE));
    }
    pub fn finish(self) -> Circuit {
        let num_vars = self.witness.len();
        let num_io = self.public.len();
        let num_cons = self.constraints.len();
        let mut matrices: [SparseMatrix<F>; 3] = core::array::from_fn(|_| SparseMatrix {
            num_rows: num_cons,
            num_cols: num_vars + 1 + num_io,
            entries: Vec::new(),
        });
        for (row, constraint) in self.constraints.into_iter().enumerate() {
            for (matrix, expression) in matrices.iter_mut().zip(constraint) {
                matrix
                    .entries
                    .extend(expression.0.into_iter().map(|(wire, val)| SparseMatEntry {
                        row,
                        col: match wire {
                            Wire::One => num_vars,
                            Wire::Public(i) => num_vars + 1 + i,
                            Wire::Witness(i) => i,
                        },
                        val,
                    }));
            }
        }
        let stats = CircuitStats {
            constraints: num_cons,
            witness_variables: num_vars,
            public_inputs: num_io,
            poseidon_permutations: self.permutations,
            matrix_nonzeros: matrices.iter().map(SparseMatrix::nnz).sum(),
        };
        let [a, b, c] = matrices;
        Circuit {
            shape: R1csShape {
                num_cons,
                num_vars,
                num_io,
                a,
                b,
                c,
            },
            witness: R1csWitness { w: self.witness },
            public_inputs: self.public,
            stats,
        }
    }
}

impl Arithmetic for Builder {
    type V = Linear;
    fn constant(&mut self, f: F) -> Linear {
        Linear::constant(f)
    }
    fn add(&mut self, a: Linear, b: Linear) -> Linear {
        a.add(&b)
    }
    fn mul(&mut self, a: Linear, b: Linear) -> Linear {
        Builder::mul(self, a, b)
    }
    fn scale(&mut self, a: Linear, f: F) -> Linear {
        a.scale(f)
    }
    fn compact(&mut self, x: Linear) -> Linear {
        Builder::compact(self, x)
    }
}
