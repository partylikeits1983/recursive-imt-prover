//! VEIL-style private affine and multiplication constraints.
//!
//! This direct argument is intended for the small algebraic verifier transcript.
//! Sending a masked copy of an entire execution witness is supported for research
//! but is linear-size; it does not provide the succinct outer PCS integration.

use anyhow::{Result, ensure};
use p3_field::PrimeCharacteristicRing;
use rand::{RngExt, SeedableRng, rngs::StdRng};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};

use super::{
    E,
    parameters::Parameters,
    transcript::Transcript,
    vector::{CommittedVectors, VectorProof, dot, powers},
};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Linear {
    pub constant: E,
    pub terms: Vec<(usize, E)>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Relation {
    pub variables: usize,
    pub public_wires: Vec<usize>,
    /// Each affine expression must equal zero.
    pub linear: Vec<Linear>,
    /// Each triple enforces a(w) * b(w) = c(w).
    pub products: Vec<[Linear; 3]>,
}

/// A research proof format, distinct from the accepted application child format.
#[derive(Clone, Serialize, Deserialize)]
pub struct ExperimentalProof {
    masked: Vec<E>,
    masks: VectorProof,
    products: VectorProof,
}

impl Linear {
    pub fn wire(index: usize) -> Self {
        Self {
            constant: E::ZERO,
            terms: vec![(index, E::ONE)],
        }
    }
    pub fn constant(value: E) -> Self {
        Self {
            constant: value,
            terms: vec![],
        }
    }
    pub fn evaluate(&self, witness: &[E]) -> E {
        self.terms
            .iter()
            .fold(self.constant, |sum, &(i, c)| sum + c * witness[i])
    }
    fn accumulate(&self, scale: E, weights: &mut [E], constant: &mut E) {
        *constant += scale * self.constant;
        for &(i, coefficient) in &self.terms {
            weights[i] += scale * coefficient;
        }
    }
}

impl Relation {
    fn validate(&self, parameters: &Parameters, public: &[E]) -> Result<()> {
        parameters.validate()?;
        ensure!(
            self.variables > 0 && self.variables <= parameters.max_message_len.saturating_sub(6),
            "invalid relation size"
        );
        ensure!(
            self.products.len() <= parameters.max_message_len.saturating_sub(2),
            "too many product constraints"
        );
        ensure!(
            self.linear.len() <= 8 * parameters.max_message_len,
            "too many linear constraints"
        );
        ensure!(
            self.public_wires.len() == public.len(),
            "incorrect public input count"
        );
        ensure!(
            self.public_wires.iter().all(|&i| i < self.variables),
            "public wire outside relation"
        );
        for expression in self.linear.iter().chain(self.products.iter().flatten()) {
            ensure!(
                expression.terms.iter().all(|&(i, _)| i < self.variables),
                "constraint wire outside relation"
            );
        }
        Ok(())
    }

    pub fn check(&self, parameters: &Parameters, public: &[E], witness: &[E]) -> Result<()> {
        self.validate(parameters, public)?;
        ensure!(witness.len() == self.variables, "incorrect witness size");
        ensure!(
            self.public_wires
                .iter()
                .zip(public)
                .all(|(&i, &x)| witness[i] == x),
            "public input mismatch"
        );
        ensure!(
            self.linear.iter().all(|c| c.evaluate(witness) == E::ZERO),
            "linear constraint failed"
        );
        ensure!(
            self.products
                .iter()
                .all(|p| p[0].evaluate(witness) * p[1].evaluate(witness) == p[2].evaluate(witness)),
            "product constraint failed"
        );
        Ok(())
    }

    pub fn prove(
        &self,
        parameters: &Parameters,
        public: &[E],
        witness: &[E],
    ) -> Result<ExperimentalProof> {
        self.check(parameters, public, witness)?;
        self.prove_inner(
            parameters,
            public,
            witness,
            &mut StdRng::from_rng(&mut rand::rng()),
        )
    }

    fn prove_inner(
        &self,
        parameters: &Parameters,
        public: &[E],
        witness: &[E],
        rng: &mut StdRng,
    ) -> Result<ExperimentalProof> {
        let mut transcript = self.transcript(parameters, public)?;
        let mut padded = witness.to_vec();
        let r: E = rng.random();
        let s: E = rng.random();
        let t: E = rng.random();
        padded.extend([r, s, r * s, r + E::ONE, t, (r + E::ONE) * t]);
        let masks: Vec<E> = (0..padded.len()).map(|_| rng.random()).collect();
        let mask_data = CommittedVectors::new(
            std::slice::from_ref(&masks),
            parameters.code(masks.len(), false)?,
            false,
            rng,
        )?;
        transcript.bytes(b"mask-commitment", &mask_data.root);
        let masked: Vec<_> = padded.iter().zip(&masks).map(|(&a, &b)| a + b).collect();
        transcript.fields(b"masked-transcript", &masked);
        let products = self.padded_products();
        let vectors: Vec<_> = (0..3)
            .map(|i| products.iter().map(|p| p[i].evaluate(&padded)).collect())
            .collect();
        let product_data =
            CommittedVectors::new(&vectors, parameters.code(products.len(), true)?, true, rng)?;
        // Bind the multiplication vectors BEFORE drawing the link test. A
        // prover must not choose vectors after seeing the compression weights.
        transcript.bytes(b"product-commitment", &product_data.root);
        let link = transcript.challenge(b"product-link")?;
        let link_weights = powers(link, products.len());
        let product_proof = product_data.prove(&link_weights, &mut transcript)?;
        let batch = transcript.challenge(b"linear-batch")?;
        let (weights, _) = self.linear_test(
            public,
            &products,
            &link_weights,
            &product_proof.dot.claims,
            batch,
        );
        let mask_proof = mask_data.prove(&weights, &mut transcript)?;
        Ok(ExperimentalProof {
            masked,
            masks: mask_proof,
            products: product_proof,
        })
    }

    pub fn verify(
        &self,
        parameters: &Parameters,
        public: &[E],
        proof: &ExperimentalProof,
    ) -> Result<()> {
        self.validate(parameters, public)?;
        ensure!(
            proof.masked.len() == self.variables + 6,
            "wrong masked transcript length"
        );
        ensure!(
            proof.products.dot.claims.len() == 3,
            "wrong product claim count"
        );
        ensure!(proof.masks.dot.claims.len() == 1, "wrong mask claim count");
        let mut transcript = self.transcript(parameters, public)?;
        transcript.bytes(b"mask-commitment", &proof.masks.root);
        transcript.fields(b"masked-transcript", &proof.masked);
        transcript.bytes(b"product-commitment", &proof.products.root);
        let link = transcript.challenge(b"product-link")?;
        let products = self.padded_products();
        let link_weights = powers(link, products.len());
        proof.products.verify(
            &parameters.code(products.len(), true)?,
            &link_weights,
            3,
            true,
            &mut transcript,
        )?;
        let batch = transcript.challenge(b"linear-batch")?;
        let (weights, constant) = self.linear_test(
            public,
            &products,
            &link_weights,
            &proof.products.dot.claims,
            batch,
        );
        ensure!(
            dot(&weights, &proof.masked) + constant == proof.masks.dot.claims[0],
            "masked constraint consistency failed"
        );
        proof.masks.verify(
            &parameters.code(proof.masked.len(), false)?,
            &weights,
            1,
            false,
            &mut transcript,
        )
    }

    fn transcript(&self, parameters: &Parameters, public: &[E]) -> Result<Transcript> {
        // Trusted relation, all parameters and the exact ordered public vector
        // are authenticated before any prover-dependent challenge.
        let encoded = postcard::to_allocvec(&(parameters, self, public))?;
        Ok(Transcript::new(&Keccak256::digest(encoded)))
    }

    fn padded_products(&self) -> Vec<[Linear; 3]> {
        let mut products = self.products.clone();
        let n = self.variables;
        products.push([Linear::wire(n), Linear::wire(n + 1), Linear::wire(n + 2)]);
        products.push([
            Linear::wire(n + 3),
            Linear::wire(n + 4),
            Linear::wire(n + 5),
        ]);
        products
    }

    fn linear_test(
        &self,
        public: &[E],
        products: &[[Linear; 3]],
        link_weights: &[E],
        claims: &[E],
        batch: E,
    ) -> (Vec<E>, E) {
        let mut weights = vec![E::ZERO; self.variables + 6];
        let mut constant = E::ZERO;
        let mut scale = E::ONE;
        for expression in &self.linear {
            expression.accumulate(scale, &mut weights, &mut constant);
            scale *= batch;
        }
        for (&wire, &value) in self.public_wires.iter().zip(public) {
            weights[wire] += scale;
            constant += scale * value;
            scale *= batch;
        }
        for j in 0..3 {
            for (p, &power) in products.iter().zip(link_weights) {
                p[j].accumulate(scale * power, &mut weights, &mut constant);
            }
            constant += scale * claims[j];
            scale *= batch;
        }
        (weights, constant)
    }
}

impl ExperimentalProof {
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        Ok(postcard::to_allocvec(self)?)
    }
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() <= 256 << 20,
            "experimental proof exceeds transport limit"
        );
        let (proof, rest) = postcard::take_from_bytes(bytes)?;
        ensure!(rest.is_empty(), "trailing proof bytes");
        Ok(proof)
    }
}

#[cfg(test)]
mod tests {
    use super::{E, Linear, Parameters, Relation, StdRng};
    use p3_field::PrimeCharacteristicRing;
    use rand::SeedableRng;

    #[test]
    fn invalid_witness_fails_the_proof_relation_without_native_precheck() {
        let parameters = Parameters::default();
        let relation = Relation {
            variables: 3,
            public_wires: vec![2],
            linear: vec![],
            products: vec![[Linear::wire(0), Linear::wire(1), Linear::wire(2)]],
        };
        // Deliberately call the internal prover: a native witness check is not
        // evidence that the verifier enforces multiplication or public binding.
        for (public, witness) in [
            ([E::ZERO], [E::ONE, E::ONE, E::ZERO]),
            ([E::ZERO], [E::ONE, E::ONE, E::ONE]),
        ] {
            let proof = relation
                .prove_inner(
                    &parameters,
                    &public,
                    &witness,
                    &mut StdRng::seed_from_u64(17),
                )
                .unwrap();
            assert!(relation.verify(&parameters, &public, &proof).is_err());
        }
        let relation = Relation {
            variables: 1,
            public_wires: vec![],
            linear: vec![Linear {
                constant: E::ONE,
                terms: vec![(0, E::ONE)],
            }],
            products: vec![],
        };
        let proof = relation
            .prove_inner(&parameters, &[], &[E::ZERO], &mut StdRng::seed_from_u64(19))
            .unwrap();
        assert!(relation.verify(&parameters, &[], &proof).is_err());
    }
}
