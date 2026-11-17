use anyhow::{Result, ensure};
use p3_circuit::{CircuitBuilder, ops::NativePoly192Target};
use p3_field::PrimeCharacteristicRing;

use crate::binary::veil::{
    F,
    code::BinaryCode,
    whir::recursive::{
        blend::CircuitFunctional,
        transcript::{CircuitTranscript, Query},
    },
};

pub(super) struct FunctionalTarget<'a> {
    pub code: &'a BinaryCode,
    pub product: bool,
    pub prefix: &'a [NativePoly192Target],
    pub queries: &'a [Query],
    pub beta: NativePoly192Target,
}

impl CircuitFunctional for FunctionalTarget<'_> {
    fn length(&self) -> usize {
        self.code.input_len << usize::from(self.product)
    }

    fn bind(&self, b: &mut CircuitBuilder<F>, transcript: &mut CircuitTranscript) -> Result<()> {
        transcript.integers(
            b,
            b"vector-coefficient-functional-v1",
            &[
                self.code.message_len,
                self.code.input_len,
                self.code.codeword_len,
                self.code.queries,
                usize::from(self.product),
            ],
        )?;
        let indices: Vec<_> = self.queries.iter().map(|q| q.value).collect();
        transcript.base_fields(b, b"vector-functional-indices", &indices)?;
        transcript.fields(
            b,
            b"vector-functional-beta",
            std::slice::from_ref(&self.beta),
        )
    }

    fn evaluate(
        &self,
        b: &mut CircuitBuilder<F>,
        point: &[NativePoly192Target],
    ) -> Result<NativePoly192Target> {
        let length = self.length();
        ensure!(
            point.len() == length.ilog2() as usize && self.prefix.len() == self.code.message_len,
            "wrong vector functional geometry"
        );
        let zero = b.native_poly192_constant([0; 3]);
        let one = b.native_poly192_constant([1, 0, 0]);
        let mut weights = self.prefix.to_vec();
        weights.resize(length, zero);
        // Transpose of the exact pinned additive-NTT butterflies. These are
        // constant Poly64 scalars, so no non-native arithmetic is needed.
        for layer in (0..length.ilog2() as usize).rev() {
            let size = length >> layer;
            for (block, values) in weights.chunks_exact_mut(size).enumerate() {
                let (lo, hi) = values.split_at_mut(size / 2);
                let t = self.code.blend_plan(self.product).twiddle(layer, block);
                for (a, c) in lo.iter_mut().zip(hi) {
                    *a = b.native_poly192_add(a, c);
                    if t != F::ZERO {
                        let t = b.define_const(t);
                        let coefficients = std::array::from_fn(|i| {
                            b.mul_add(a.coefficients()[i], t, c.coefficients()[i])
                        });
                        *c = b.native_poly192_from_coefficients(coefficients);
                    }
                }
            }
        }
        let mut sum = weights.evaluate(b, point)?;
        let offset = self.code.blend_factors(0, self.product)?;
        let linear = (0..self.code.codeword_len.ilog2())
            .map(|bit| self.code.blend_factors(1 << bit, self.product))
            .collect::<Result<Vec<_>>>()?;
        let mut power = self.beta.clone();
        for query in self.queries {
            ensure!(query.bits.len() == linear.len(), "wrong vector query bits");
            let encoded = b.binary_recompose_coordinates(&query.bits)?;
            b.connect(encoded, query.value);
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
            let term = b.native_poly192_mul(&value, &power);
            sum = b.native_poly192_add(&sum, &term);
            power = b.native_poly192_mul(&power, &self.beta);
        }
        Ok(sum)
    }
}
