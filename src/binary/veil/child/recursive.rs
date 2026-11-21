//! Complete masked-child verification relation. Every input other than the
//! public record statement comes from the serialized child proof.
use anyhow::{Result, ensure};
use p3_circuit::{
    Circuit, CircuitBuilder, CircuitConstructionLimits, ExprId, ops::NativePoly192Target,
};
use p3_field::PrimeCharacteristicRing;

use super::{MaskedMembershipProof, PROTOCOL, PreparedMembership};
use crate::binary::{
    relation::{ClientPublic, PUBLIC_BYTES},
    veil::{
        E, F,
        air_algebra::recursive::public_evaluation,
        compiler::{
            self, MaskedReader,
            recursive::{CircuitReader, LinearTarget, constant},
        },
        constraints::recursive::{PreparedInner, RelationTarget},
        parameters::Parameters,
        stacked_oracle::recursive::opening::{OpeningTargets, PreparedStacked, circuit_powers},
        whir::recursive::transcript::CircuitTranscript,
    },
};

pub struct PreparedMaskedVerifier {
    child: PreparedMembership,
    inner: PreparedInner,
    oracle: PreparedStacked,
}

impl PreparedMaskedVerifier {
    pub fn new(depth: usize, parameters: Parameters) -> Result<Self> {
        Self::for_protocol(depth, parameters, PROTOCOL)
    }

    pub fn for_protocol(depth: usize, parameters: Parameters, protocol: &str) -> Result<Self> {
        let child = PreparedMembership::for_protocol(depth, parameters.clone(), protocol)?;
        let inner = PreparedInner::new(child.messages, child.algebra.products, &parameters)?;
        let oracle = PreparedStacked::new(child.oracle.clone(), &parameters)?;
        Ok(Self {
            child,
            inner,
            oracle,
        })
    }

    pub fn circuit(&self) -> Result<Circuit<F>> {
        let mut b = CircuitBuilder::<F>::with_construction_limits(CircuitConstructionLimits {
            max_expression_nodes: 1 << 27,
            max_pending_connects: 1 << 26,
            max_non_primitive_calls: 1 << 21,
            max_non_primitive_slots: 1 << 29,
        })?;
        b.enable_native_keccak_f1600()?;
        let public = b.alloc_public_input_array::<PUBLIC_BYTES>("record-statement");
        self.verify_in(&mut b, public)?;
        Ok(b.build()?)
    }

    /// Append the complete verifier for one caller-owned record statement.
    pub fn verify_in(
        &self,
        b: &mut CircuitBuilder<F>,
        public: [ExprId; PUBLIC_BYTES],
    ) -> Result<()> {
        let inner = self.inner.allocate(b)?;
        let oracle_root = b.alloc_private_input_array::<32>("masked-oracle-root");
        let oracle = self.oracle.allocate(b)?;
        let (relation, transcript) = self.replay_circuit(
            b,
            public,
            &inner.masked,
            &inner.masks.root,
            &oracle_root,
            &oracle,
        )?;
        self.inner.verify(b, &inner, &relation, transcript)?;
        Ok(())
    }

    fn replay_circuit(
        &self,
        b: &mut CircuitBuilder<F>,
        public: [ExprId; PUBLIC_BYTES],
        masked: &[NativePoly192Target],
        mask_root: &[ExprId; 32],
        oracle_root: &[ExprId; 32],
        oracle: &OpeningTargets,
    ) -> Result<(RelationTarget, CircuitTranscript)> {
        let mut transcript = CircuitTranscript::from_state([ExprId::ZERO; 32]);
        let protocol = bytes(b, compiler::PROTOCOL);
        transcript.bytes(b, b"protocol", &protocol)?;
        let mut binding = self.child.protocol().as_bytes().to_vec();
        binding.extend(self.child.identity);
        for value in [
            self.child.parameters.query_bits,
            self.child.parameters.min_algebraic_bits,
            self.child.parameters.log_inv_rate,
            self.child.parameters.max_message_len,
        ] {
            binding.extend((value as u64).to_le_bytes());
        }
        let mut binding = bytes(b, &binding);
        binding.extend(public);
        binding.extend(oracle_root);
        transcript.bytes(b, b"statement", &binding)?;
        transcript.integers(
            b,
            b"online-parameters",
            &[
                self.child.parameters.query_bits,
                self.child.parameters.min_algebraic_bits,
                self.child.parameters.log_inv_rate,
                self.child.parameters.max_message_len,
                self.child.messages,
            ],
        )?;
        transcript.bytes(b, b"mask-commitment", mask_root)?;
        let mut reader = CircuitReader::new(transcript, masked);
        let reduction = self.child.program.replay_circuit(b, &mut reader)?;
        let start = reader.position();
        for (a, c) in oracle
            .masked
            .iter()
            .zip(&masked[start..start + oracle.masked.len()])
        {
            for (&a, &c) in a.coefficients().iter().zip(c.coefficients()) {
                b.connect(a, c);
            }
        }
        let transcript = std::mem::replace(
            &mut reader.transcript,
            CircuitTranscript::from_state([ExprId::ZERO; 32]),
        );
        let opening = self
            .oracle
            .verify(b, oracle_root, &reduction.point, oracle, transcript)?;
        reader.transcript = opening.transcript;
        reader.consume_authenticated(oracle.masked.len())?;
        let main: Vec<Vec<_>> = (0..2)
            .map(|j| {
                (0..self.child.trace_width())
                    .map(|i| LinearTarget::wire(b, start + j * self.child.trace_width() + i))
                    .collect()
            })
            .collect();
        let mut linear = Vec::new();
        for (j, values) in main.iter().enumerate() {
            // Match the native canonical ordering, including zero constants.
            let mask = LinearTarget::wire(b, start + 2 * self.child.trace_width() + j)
                .scale(b, &opening.mask_coefficient);
            let mut check = LinearTarget::constant(opening.constants[j].clone()).add(b, &mask);
            for (value, coefficient) in values.iter().zip(&opening.coefficients) {
                let term = value.scale(b, coefficient);
                check = check.add(b, &term);
            }
            linear.push(check);
        }
        let inputs = public
            .into_iter()
            .map(|byte| b.native_poly192_from_coefficients([byte, ExprId::ZERO, ExprId::ZERO]))
            .collect();
        let public = public_evaluation(b, inputs, &self.child.prep_columns, &reduction.point)?;
        let endpoint = self
            .child
            .algebra
            .constrain_circuit(b, &main, &public, &mut reader)?;
        ensure!(
            reader.position() == self.child.messages,
            "incomplete child verifier schedule"
        );
        let powers = circuit_powers(b, &reduction.alpha, endpoint.outputs.len());
        let mut combined = LinearTarget::constant(constant(b, E::ZERO));
        for (output, power) in endpoint.outputs.iter().zip(powers.iter().rev()) {
            let term = output.scale(b, power);
            combined = combined.add(b, &term);
        }
        let one = constant(b, E::ONE);
        let mut eq = one.clone();
        for (tau, r) in reduction.tau.iter().zip(&reduction.point) {
            let sum = b.native_poly192_add(tau, r);
            let factor = b.native_poly192_add(&one, &sum);
            eq = b.native_poly192_mul(&eq, &factor);
        }
        linear.push(combined.scale(b, &eq).add(b, &reduction.claim));
        let relation = RelationTarget {
            variables: self.child.messages,
            linear,
            products: endpoint.products,
        };
        relation.finish(b, masked, &mut reader.transcript)?;
        Ok((relation, reader.transcript))
    }

    pub fn import(&self, public: &ClientPublic, proof: &MaskedMembershipProof) -> Result<Vec<F>> {
        let binding = self.child.binding(public, &proof.oracle_root)?;
        let mut reader = MaskedReader::new(
            &self.child.parameters,
            &binding,
            self.child.messages,
            &proof.inner.masks.root,
            &proof.inner.masked,
        )?;
        let replay = self.child.program.replay(&mut reader)?;
        let reduction = self.child.program.reduce(replay)?;
        let start = self.child.program.message_count();
        let count = self.child.oracle.messages(2)?;
        let oracle_inputs = self.oracle.import(
            &proof.opening,
            &proof.oracle_root,
            &reduction.point,
            &proof.inner.masked[start..start + count],
            reader.public_transcript().clone(),
        )?;
        let mut reader = MaskedReader::new(
            &self.child.parameters,
            &binding,
            self.child.messages,
            &proof.inner.masks.root,
            &proof.inner.masked,
        )?;
        let relation =
            self.child
                .replay(public, &proof.oracle_root, &proof.opening, &mut reader)?;
        reader.finish(&relation)?;
        let mut private =
            self.inner
                .import(&proof.inner, &relation, reader.public_transcript().clone())?;
        private.extend(proof.oracle_root.into_iter().map(|v| F::new(u64::from(v))));
        private.extend(oracle_inputs);
        Ok(private)
    }
}

fn bytes(b: &mut CircuitBuilder<F>, values: &[u8]) -> Vec<ExprId> {
    values
        .iter()
        .map(|&v| b.define_const(F::new(u64::from(v))))
        .collect()
}

#[cfg(test)]
mod tests;

pub mod parts;
