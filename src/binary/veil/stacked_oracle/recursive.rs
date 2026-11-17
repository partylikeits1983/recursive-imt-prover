//! Circuit counterpart of the verifier-derived stacked oracle functional.
use anyhow::{Result, ensure};
use p3_circuit::CircuitBuilder;
use p3_circuit::ops::NativePoly192Target;

use super::StackedSpec;
use crate::binary::veil::{
    F,
    code::BinaryCode,
    whir::recursive::{
        blend::CircuitFunctional,
        transcript::{CircuitTranscript, Query},
    },
};

struct ViewTarget {
    point: Vec<NativePoly192Target>,
    next: bool,
}

struct FunctionalTarget {
    spec: StackedSpec,
    code: BinaryCode,
    views: Vec<ViewTarget>,
    queries: Vec<Query>,
    theta: NativePoly192Target,
    beta: NativePoly192Target,
}

impl CircuitFunctional for FunctionalTarget {
    fn length(&self) -> usize {
        self.code.input_len
    }

    fn bind(&self, b: &mut CircuitBuilder<F>, transcript: &mut CircuitTranscript) -> Result<()> {
        transcript.integers(
            b,
            b"coefficient-functional-v2",
            &[
                self.spec.variables,
                self.spec.columns,
                self.spec.log_stack,
                self.code.input_len,
                self.code.codeword_len,
                self.code.queries,
            ],
        )?;
        bind_views(b, &self.views, transcript)?;
        let indices: Vec<_> = self.queries.iter().map(|q| q.value).collect();
        transcript.base_fields(b, b"coefficient-functional-indices", &indices)?;
        transcript.fields(
            b,
            b"coefficient-functional-challenges",
            &[self.theta.clone(), self.beta.clone()],
        )
    }

    fn evaluate(
        &self,
        b: &mut CircuitBuilder<F>,
        point: &[NativePoly192Target],
    ) -> Result<NativePoly192Target> {
        ensure!(
            point.len() == self.length().ilog2() as usize,
            "wrong functional point arity"
        );
        let prefix = point
            .len()
            .checked_sub(self.spec.variables + self.spec.log_stack)
            .ok_or_else(|| anyhow::anyhow!("wrong coefficient geometry"))?;
        let one = b.native_poly192_constant([1, 0, 0]);
        let mut selector = one.clone();
        for coordinate in &point[..prefix] {
            selector = b.native_poly192_mul(&selector, coordinate);
        }
        let mut slot = one.clone();
        let mut theta = self.theta.clone();
        for coordinate in point[prefix..prefix + self.spec.log_stack].iter().rev() {
            let term = b.native_poly192_mul(coordinate, &theta);
            let term = b.native_poly192_add(&term, coordinate);
            let term = b.native_poly192_add(&term, &one);
            slot = b.native_poly192_mul(&slot, &term);
            theta = b.native_poly192_square(&theta);
        }
        let selected_slot = b.native_poly192_mul(&selector, &slot);
        let row_point = &point[prefix + self.spec.log_stack..];
        let mut sum = b.native_poly192_constant([0; 3]);
        let mut power = one.clone();
        for view in &self.views {
            let row = evaluate_view(b, view, row_point)?;
            let term = b.native_poly192_mul(&selected_slot, &row);
            let term = b.native_poly192_mul(&term, &power);
            sum = b.native_poly192_add(&sum, &term);
            power = b.native_poly192_mul(&power, &self.beta);
        }
        // Novel-basis subspace polynomials are GF(2)-linear. Their value at a
        // verifier-derived index is a fixed linear combination of index bits.
        // This reuses upstream's exact twiddles without a non-native operation.
        let offset = self.code.coefficient_factors(0)?;
        let linear = (0..self.code.codeword_len.ilog2())
            .map(|bit| self.code.coefficient_factors(1 << bit))
            .collect::<Result<Vec<_>>>()?;
        for query in &self.queries {
            ensure!(query.bits.len() == linear.len(), "wrong query bit count");
            // Bind the integer hashed into the descriptor to exactly the same
            // bits used for the generator evaluation and Merkle path.
            let encoded = b.binary_recompose_coordinates(&query.bits)?;
            b.connect(query.value, encoded);
            let mut value = one.clone();
            for (j, coordinate) in point.iter().enumerate() {
                let mut factor = b.define_const(offset[j]);
                for (&bit, row) in query.bits.iter().zip(&linear) {
                    let coefficient = b.define_const(row[j] + offset[j]);
                    factor = b.mul_add(bit, coefficient, factor);
                }
                let coefficients = coordinate.coefficients().map(|v| b.mul(v, factor));
                let product = b.native_poly192_from_coefficients(coefficients);
                let term = b.native_poly192_add(&product, coordinate);
                let term = b.native_poly192_add(&term, &one);
                value = b.native_poly192_mul(&value, &term);
            }
            let term = b.native_poly192_mul(&power, &value);
            sum = b.native_poly192_add(&sum, &term);
            power = b.native_poly192_mul(&power, &self.beta);
        }
        Ok(sum)
    }
}

fn bind_views(
    b: &mut CircuitBuilder<F>,
    views: &[ViewTarget],
    transcript: &mut CircuitTranscript,
) -> Result<()> {
    transcript.integers(b, b"stacked-oracle-view-count", &[views.len()])?;
    for view in views {
        transcript.integers(
            b,
            b"stacked-oracle-view",
            &[usize::from(view.next), view.point.len()],
        )?;
        transcript.fields(b, b"stacked-oracle-point", &view.point)?;
    }
    Ok(())
}

fn evaluate_view(
    b: &mut CircuitBuilder<F>,
    view: &ViewTarget,
    row: &[NativePoly192Target],
) -> Result<NativePoly192Target> {
    ensure!(view.point.len() == row.len(), "wrong oracle point arity");
    let one = b.native_poly192_constant([1, 0, 0]);
    if !view.next {
        let mut value = one.clone();
        for (p, r) in view.point.iter().zip(row) {
            let term = b.native_poly192_add(p, r);
            let term = b.native_poly192_add(&one, &term);
            value = b.native_poly192_mul(&value, &term);
        }
        return Ok(value);
    }
    let mut carry = one.clone();
    let mut done = b.native_poly192_constant([0; 3]);
    let mut omega = one.clone();
    for (p, r) in view.point.iter().zip(row).rev() {
        let previous = carry;
        let eq = b.native_poly192_add(p, r);
        let eq = b.native_poly192_add(&eq, &one);
        let not_r = b.native_poly192_add(r, &one);
        let not_p = b.native_poly192_add(p, &one);
        let term = b.native_poly192_mul(p, &not_r);
        carry = b.native_poly192_mul(&previous, &term);
        let settles = b.native_poly192_mul(&not_p, r);
        let settles = b.native_poly192_mul(&settles, &previous);
        let retained = b.native_poly192_mul(&done, &eq);
        done = b.native_poly192_add(&retained, &settles);
        let term = b.native_poly192_mul(p, r);
        omega = b.native_poly192_mul(&omega, &term);
    }
    Ok(b.native_poly192_add(&done, &omega))
}

#[cfg(test)]
mod tests;

pub(in crate::binary::veil) mod opening;
