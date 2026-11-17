use anyhow::{Result, ensure};
use p3_circuit::{CircuitBuilder, ops::NativePoly192Target};
use p3_field::PrimeCharacteristicRing;

use super::{AirAlgebra, Gate};
use crate::binary::veil::{
    E, F,
    compiler::recursive::{CircuitReader, LinearTarget, constant},
};

pub(in crate::binary::veil) struct PublicTarget {
    pub inputs: Vec<NativePoly192Target>,
    pub preprocessed: [Vec<NativePoly192Target>; 2],
    pub first: NativePoly192Target,
    pub last: NativePoly192Target,
    pub transition: NativePoly192Target,
}

pub(in crate::binary::veil) struct AlgebraTarget {
    pub outputs: Vec<LinearTarget>,
    pub products: Vec<[LinearTarget; 3]>,
}

impl AirAlgebra {
    pub fn constrain_circuit(
        &self,
        b: &mut CircuitBuilder<F>,
        main: &[Vec<LinearTarget>],
        public: &PublicTarget,
        reader: &mut CircuitReader<'_>,
    ) -> Result<AlgebraTarget> {
        let wires = reader.read(b, b"air-verifier-products", self.products)?;
        let mut cursor = 0;
        let mut values: Vec<LinearTarget> = Vec::with_capacity(self.gates.len());
        let mut products = Vec::with_capacity(self.products);
        for gate in &self.gates {
            let value = match *gate {
                Gate::Main(row, column) => main[row][column].clone(),
                Gate::Add(a, c) => values[a].add(b, &values[c]),
                Gate::Mul(a, c) if self.private[a] && self.private[c] => {
                    let output = wires[cursor].clone();
                    cursor += 1;
                    products.push([values[a].clone(), values[c].clone(), output.clone()]);
                    output
                }
                Gate::Mul(a, c) => {
                    let (fixed, other) = if self.private[a] { (c, a) } else { (a, c) };
                    ensure!(
                        values[fixed].terms.is_empty(),
                        "public circuit AIR gate became private"
                    );
                    values[other].scale(b, &values[fixed].constant)
                }
                Gate::Constant(value) => LinearTarget::constant(constant(b, E::from(value))),
                Gate::Public(i) => LinearTarget::constant(public.inputs[i].clone()),
                Gate::Preprocessed(row, column) => {
                    LinearTarget::constant(public.preprocessed[row][column].clone())
                }
                Gate::First => LinearTarget::constant(public.first.clone()),
                Gate::Last => LinearTarget::constant(public.last.clone()),
                Gate::Transition => LinearTarget::constant(public.transition.clone()),
            };
            values.push(value);
        }
        ensure!(
            cursor == self.products,
            "AIR circuit product schedule mismatch"
        );
        Ok(AlgebraTarget {
            outputs: self.outputs.iter().map(|&i| values[i].clone()).collect(),
            products,
        })
    }
}

pub(in crate::binary::veil) fn public_evaluation(
    b: &mut CircuitBuilder<F>,
    inputs: Vec<NativePoly192Target>,
    columns: &[Vec<E>],
    point: &[NativePoly192Target],
) -> Result<PublicTarget> {
    let one = constant(b, E::ONE);
    let zero = constant(b, E::ZERO);
    let mut weights = vec![one.clone()];
    for r in point {
        weights = weights
            .iter()
            .flat_map(|w| {
                let hi = b.native_poly192_mul(w, r);
                let lo = b.native_poly192_add(w, &hi);
                [lo, hi]
            })
            .collect();
    }
    let first = weights[0].clone();
    let last = weights.last().unwrap().clone();
    let transition = b.native_poly192_add(&one, &last);
    let mut current = Vec::new();
    for column in columns {
        ensure!(
            column.len() == weights.len(),
            "wrong trusted preprocessing height"
        );
        let mut sum = zero.clone();
        for (&v, w) in column.iter().zip(&weights) {
            if v == E::ZERO {
                continue;
            }
            let term = if v == E::ONE {
                w.clone()
            } else {
                let c = constant(b, v);
                b.native_poly192_mul(w, &c)
            };
            sum = b.native_poly192_add(&sum, &term);
        }
        current.push(sum);
    }
    Ok(PublicTarget {
        inputs,
        preprocessed: [current, vec![zero; columns.len()]],
        first,
        last,
        transition,
    })
}
