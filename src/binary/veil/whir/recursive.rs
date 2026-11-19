//! Native Poly64 circuit verification of the actual prefixed-BLAKE3 WHIR PCS.
//! This is the PCS component, not the complete masked membership verifier.
use anyhow::{Result, ensure};
use p3_circuit::ops::binary_encoding::NativeBinaryEncoding;
use p3_circuit::ops::binary_host::BinaryCircuitHost;
use p3_circuit::ops::{ByteHash, NativePoly192Target};
use p3_circuit::{CircuitBuilder, ExprId};
use p3_commit::MultilinearPcs;
use p3_multilinear_util::point::Point;
use p3_recursion::BinaryTower128Challenger;
use p3_recursion::pcs::binary::{
    BinaryPolyWhirInputShape, BinaryPolyWhirProofTargets, BinaryPolyWhirVerifier,
    BinaryWhirHashDomains,
};
use p3_sumcheck::strategy::VariableOrder;
use p3_symmetric::MerkleCap;
use p3_whir::pcs::proof::PcsProof;

use super::{
    LEAF_DOMAIN, NODE_DOMAIN, Pcs, SEAL_TAG, TRANSCRIPT_DOMAIN, Tree, backend, challenger, tree,
};
use crate::binary::veil::{E, F, parameters::Parameters};

pub(super) type Targets = BinaryPolyWhirProofTargets<NativePoly192Target, ExprId>;

pub(super) struct PreparedWhir {
    pcs: Pcs,
    verifier: BinaryPolyWhirVerifier,
    shape: BinaryPolyWhirInputShape,
    domains: BinaryWhirHashDomains,
    variables: usize,
}

pub(super) struct VerifiedOpening {
    pub value: NativePoly192Target,
    pub seal: [ExprId; 32],
}

pub(in crate::binary::veil) mod blend;
pub(in crate::binary::veil) mod transcript;

impl PreparedWhir {
    pub fn new(length: usize, parameters: &Parameters) -> Result<Self> {
        let (pcs, protocol, _) = backend(length, parameters)?;
        let verifier = BinaryPolyWhirVerifier::new(
            &pcs,
            protocol,
            VariableOrder::Prefix,
            ByteHash::Blake3,
            0,
        )?;
        let shape = verifier.input_shape();
        Ok(Self {
            pcs,
            verifier,
            shape,
            domains: BinaryWhirHashDomains::new(LEAF_DOMAIN, NODE_DOMAIN)?,
            variables: length.ilog2() as usize,
        })
    }

    pub fn allocate(&self, builder: &mut CircuitBuilder<F>) -> Result<Targets> {
        Ok(self.shape.allocate_native_targets(builder)?)
    }

    /// Restore pruned paths in the trusted layout. This supplies witness values;
    /// the circuit below independently constrains every verification obligation.
    pub fn import(
        &self,
        seed: &[u8; 32],
        root: &[u8; 32],
        point: &[E],
        proof: &PcsProof<F, E, Tree>,
    ) -> Result<Vec<F>> {
        ensure!(
            point.len() == self.variables,
            "wrong recursive WHIR point arity"
        );
        let mut channel = challenger(seed);
        let cap = MerkleCap::new(vec![*root]);
        self.pcs.observe_commitment(&cap, &mut channel);
        let input = self.verifier.import_native(
            &self.pcs,
            &tree(),
            &cap,
            &[Point::new(point.to_vec())],
            proof,
            &mut channel,
        )?;
        Ok(input.private_native_values(&self.shape)?)
    }

    pub fn verify(
        &self,
        builder: &mut CircuitBuilder<F>,
        seed: &[ExprId; 32],
        root: &[ExprId; 32],
        point: &[NativePoly192Target],
        proof: &Targets,
    ) -> Result<VerifiedOpening> {
        ensure!(
            point.len() == self.variables,
            "wrong recursive WHIR point arity"
        );
        let cap = vec![NativeBinaryEncoding::words_from_bytes(builder, root)?];
        let mut channel =
            BinaryTower128Challenger::new_with_hash_prefix(ByteHash::Blake3, TRANSCRIPT_DOMAIN);
        channel.observe_bytes_with_host::<NativeBinaryEncoding, F>(builder, seed)?;
        self.verifier
            .observe_commitment_with_host::<NativeBinaryEncoding, F>(builder, &mut channel, &cap)?;
        let (evals, mut channel) = self.verifier.verify_at_native_with_domains(
            builder,
            channel,
            &cap,
            &[point.to_vec()],
            proof,
            &self.domains,
        )?;
        ensure!(
            evals.len() == 1 && evals[0].current().len() == 3 && evals[0].next().is_empty(),
            "wrong recursive WHIR evaluation shape"
        );
        let mut result = builder.native_poly192_constant([0; 3]);
        for (i, value) in evals[0].current().iter().enumerate() {
            let basis = builder.native_poly192_constant(std::array::from_fn(|j| u64::from(i == j)));
            let term = builder.native_poly192_mul(value, &basis);
            result = builder.native_poly192_add(&result, &term);
        }
        let tag = SEAL_TAG.map(|byte| builder.define_const(F::new(u64::from(byte))));
        channel.observe_bytes_with_host::<NativeBinaryEncoding, F>(builder, &tag)?;
        let seal = channel
            .sample_bytes_with_host::<NativeBinaryEncoding, F>(builder, 32)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("wrong WHIR seal length"))?;
        Ok(VerifiedOpening {
            value: result,
            seal,
        })
    }
}

#[cfg(test)]
mod tests;
