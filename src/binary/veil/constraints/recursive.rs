use anyhow::{Result, ensure};
use p3_circuit::{CircuitBuilder, ops::NativePoly192Target};
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};

use super::{ExperimentalProof, Relation};
use crate::binary::veil::{
    E, F,
    compiler::recursive::{LinearTarget, constant},
    parameters::Parameters,
    stacked_oracle::recursive::opening::{circuit_dot, circuit_powers, field},
    transcript::Transcript,
    vector::{
        powers,
        recursive::{PreparedVector, VectorTargets},
    },
    whir::recursive::transcript::CircuitTranscript,
};

pub(in crate::binary::veil) struct RelationTarget {
    pub variables: usize,
    pub linear: Vec<LinearTarget>,
    pub products: Vec<[LinearTarget; 3]>,
}

pub(in crate::binary::veil) struct PreparedInner {
    variables: usize,
    products: usize,
    masks: PreparedVector,
    product_vectors: PreparedVector,
    parameters: Parameters,
}

pub(in crate::binary::veil) struct InnerTargets {
    pub masked: Vec<NativePoly192Target>,
    pub masks: VectorTargets,
    products: VectorTargets,
}

impl PreparedInner {
    pub fn new(variables: usize, products: usize, parameters: &Parameters) -> Result<Self> {
        Ok(Self {
            variables,
            products,
            masks: PreparedVector::new(
                parameters.code(variables + 6, false)?,
                1,
                false,
                parameters,
            )?,
            product_vectors: PreparedVector::new(
                parameters.code(products + 2, true)?,
                3,
                true,
                parameters,
            )?,
            parameters: parameters.clone(),
        })
    }

    pub fn allocate(&self, b: &mut CircuitBuilder<F>) -> Result<InnerTargets> {
        let masked = (0..self.variables + 6).map(|_| field(b)).collect();
        let masks = self.masks.allocate(b)?;
        let products = self.product_vectors.allocate(b)?;
        Ok(InnerTargets {
            masked,
            masks,
            products,
        })
    }

    pub fn import(
        &self,
        proof: &ExperimentalProof,
        relation: &Relation,
        mut transcript: Transcript,
    ) -> Result<Vec<F>> {
        ensure!(
            relation.variables == self.variables
                && relation.products.len() == self.products
                && relation.public_wires.is_empty(),
            "wrong inner relation geometry"
        );
        ensure!(
            proof.masked.len() == self.variables + 6,
            "wrong inner masked length"
        );
        let mut private: Vec<F> = proof
            .masked
            .iter()
            .flat_map(|v| v.as_basis_coefficients_slice().iter().copied())
            .collect();
        transcript.bytes(b"product-commitment", &proof.products.root);
        let link = transcript.challenge(b"product-link")?;
        let products = relation.padded_products();
        let weights = powers(link, products.len());
        let product_inputs = self.product_vectors.import(
            &proof.products,
            &weights,
            &self.parameters,
            transcript.clone(),
        )?;
        proof.products.verify(
            &self.parameters.code(products.len(), true)?,
            &weights,
            3,
            true,
            &self.parameters,
            &mut transcript,
        )?;
        let batch = transcript.challenge(b"linear-batch")?;
        let (weights, _) =
            relation.linear_test(&[], &products, &weights, &proof.products.dot.claims, batch);
        private.extend(
            self.masks
                .import(&proof.masks, &weights, &self.parameters, transcript)?,
        );
        private.extend(product_inputs);
        Ok(private)
    }

    pub fn verify(
        &self,
        b: &mut CircuitBuilder<F>,
        proof: &InnerTargets,
        relation: &RelationTarget,
        mut transcript: CircuitTranscript,
    ) -> Result<()> {
        ensure!(
            relation.variables == self.variables && relation.products.len() == self.products,
            "wrong circuit relation geometry"
        );
        transcript.bytes(b, b"product-commitment", &proof.products.root)?;
        let link = transcript.challenge(b, b"product-link")?;
        let link_weights = circuit_powers(b, &link, self.products + 2);
        transcript = self
            .product_vectors
            .verify(b, &proof.products, &link_weights, transcript)?;
        let batch = transcript.challenge(b, b"linear-batch")?;
        let (weights, c) = relation.weights(b, &link, &proof.products.claims, &batch)?;
        let dot = circuit_dot(b, &weights, &proof.masked)?;
        let actual = b.native_poly192_add(&dot, &c);
        for (&a, &c) in actual
            .coefficients()
            .iter()
            .zip(proof.masks.claims[0].coefficients())
        {
            b.connect(a, c);
        }
        let _ = self.masks.verify(b, &proof.masks, &weights, transcript)?;
        Ok(())
    }
}

impl RelationTarget {
    pub fn weights(
        &self,
        b: &mut CircuitBuilder<F>,
        link: &NativePoly192Target,
        claims: &[NativePoly192Target],
        batch: &NativePoly192Target,
    ) -> Result<(Vec<NativePoly192Target>, NativePoly192Target)> {
        ensure!(claims.len() == 3, "wrong product link claims");
        let mut products = self.products.clone();
        for offset in [0, 3] {
            products.push(std::array::from_fn(|i| {
                LinearTarget::wire(b, self.variables + offset + i)
            }));
        }
        let link_weights = circuit_powers(b, link, products.len());
        let mut weights = vec![constant(b, E::ZERO); self.variables + 6];
        let mut c = constant(b, E::ZERO);
        let mut scale = constant(b, E::ONE);
        for expression in &self.linear {
            accumulate(b, expression, &scale, &mut weights, &mut c)?;
            scale = b.native_poly192_mul(&scale, batch);
        }
        for j in 0..3 {
            for (product, power) in products.iter().zip(&link_weights) {
                let factor = b.native_poly192_mul(&scale, power);
                accumulate(b, &product[j], &factor, &mut weights, &mut c)?;
            }
            let claim = b.native_poly192_mul(&scale, &claims[j]);
            c = b.native_poly192_add(&c, &claim);
            scale = b.native_poly192_mul(&scale, batch);
        }
        Ok((weights, c))
    }

    pub fn finish(
        &self,
        b: &mut CircuitBuilder<F>,
        masked: &[NativePoly192Target],
        transcript: &mut CircuitTranscript,
    ) -> Result<()> {
        ensure!(
            masked.len() == self.variables + 6,
            "wrong circuit padding length"
        );
        transcript.fields(b, b"multiplication-padding", &masked[self.variables..])?;
        transcript.integers(
            b,
            b"verifier-constraint-shape-v1",
            &[self.variables, self.linear.len(), self.products.len()],
        )
    }
}

fn accumulate(
    b: &mut CircuitBuilder<F>,
    expression: &LinearTarget,
    scale: &NativePoly192Target,
    weights: &mut [NativePoly192Target],
    c: &mut NativePoly192Target,
) -> Result<()> {
    let term = b.native_poly192_mul(scale, &expression.constant);
    *c = b.native_poly192_add(c, &term);
    for &(i, ref coefficient) in &expression.terms {
        ensure!(i < weights.len(), "wire outside linear check");
        let term = b.native_poly192_mul(scale, coefficient);
        weights[i] = b.native_poly192_add(&weights[i], &term);
    }
    Ok(())
}
