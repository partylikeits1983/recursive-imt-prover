use crate::checkpoint_keccak::{
    Statement,
    linked::{LinkedBatch, LinkedProof, PORTS, PortOpening},
    recursive::{PortTargets, PreparedLinkedVerifier},
};
use anyhow::{Result, ensure};
use old_binary_field::Poly64 as F;
use p3_circuit::Circuit;

use super::{BoundaryPcs, builder};

/// Component circuit with public arithmetic port readings. A merge must derive these
/// readings inside its arithmetic verifier, with the boundary bound before its challenges.
pub struct PreparedLinkedCheckpoint {
    seed: [u8; 32],
    native: LinkedBatch,
    pcs: BoundaryPcs,
    pub circuit: Circuit<F>,
}

impl PreparedLinkedCheckpoint {
    pub fn new(log_batch: usize, main_candidate_log2: f64, context: &[u8]) -> Result<Self> {
        let native = LinkedBatch::for_recursion(log_batch, main_candidate_log2)?;
        let seed = native.transcript_seed(context);
        let pcs = BoundaryPcs::new(log_batch, 2, native.recursive_pcs_seed())?;
        let reduction = PreparedLinkedVerifier::new(log_batch)?;
        let mut b = builder()?;
        let cap = pcs.allocate_cap(&mut b, true);
        let mut field = || {
            let coefficients = b.alloc_public_input_array::<3>("arithmetic port reading");
            b.native_poly192_from_coefficients(coefficients)
        };
        let ports = PortTargets {
            instance: (0..log_batch).map(|_| field()).collect(),
            values: (0..PORTS).map(|_| field()).collect(),
        };
        let proof = reduction.allocate(&mut b)?;
        let opening = pcs.verifier.allocate_native_targets(&mut b)?;
        let ch = pcs.challenger(&mut b, &seed, &cap)?;
        let claims = reduction.verify_reduction(&mut b, ch, &ports, &proof)?;
        let (values, _) = pcs.verifier.verify_at_native(
            &mut b,
            claims.challenger.clone(),
            &cap,
            &claims.points,
            &opening,
        )?;
        ensure!(
            values.len() == 4
                && values
                    .iter()
                    .all(|v| v.current().len() == 1 && v.next().is_empty()),
            "incorrect linked Keccak routing"
        );
        claims.authenticate(&mut b, core::array::from_fn(|i| &values[i].current()[0]));
        Ok(Self {
            seed,
            native,
            pcs,
            circuit: b.build()?,
        })
    }

    pub fn public_inputs(&self, statement: &Statement, ports: &PortOpening) -> Result<Vec<F>> {
        let mut public = self.pcs.public_inputs(statement)?;
        ensure!(
            ports.instance.len() == self.pcs.log_batch && ports.values.len() == PORTS,
            "incorrect port input shape"
        );
        public.extend(
            ports
                .instance
                .iter()
                .chain(&ports.values)
                .flat_map(|v| v.coefficients().map(|c| F::new(c.to_bits()))),
        );
        Ok(public)
    }

    pub fn private_inputs(
        &self,
        statement: &Statement,
        proof: &LinkedProof,
        ports: &PortOpening,
    ) -> Result<Vec<F>> {
        self.public_inputs(statement, ports)?;
        let mut ch = self.pcs.native_challenger(statement, &self.seed)?;
        let input = self.native.recursive_input(proof, ports, &mut ch)?;
        let mut private = input.private_values;
        private.extend(self.pcs.private_inputs(
            statement,
            &input.points,
            &input.opening,
            &mut ch,
        )?);
        Ok(private)
    }
}
