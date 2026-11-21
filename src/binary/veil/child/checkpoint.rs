//! Reference public messages for the masked AIR reduction and its first oracle.
use super::{MaskedMembershipProof, PreparedMembership};
use crate::binary::{
    ClientPublic,
    veil::{E, compiler::MaskedReader, native::OraclePoint},
};
use anyhow::{Result, ensure};
use p3_field::{PrimeCharacteristicRing, RawDataSerializable};

/// Inputs and reference outputs for the AIR reduction and stacked Merkle openings.
pub struct StackedOracleCheckpoint {
    pub oracle_root: [u8; 32],
    pub mask_root: [u8; 32],
    pub masked_round_bytes: Vec<u8>,
    pub challenges: Vec<u8>,
    pub air_fingerprint: [u8; 32],
    pub claim_coefficients: Vec<u8>,
    pub column_evaluations: Vec<u8>,
    pub mask_evaluations: Vec<u8>,
    pub blend_root: [u8; 32],
    pub blend_evaluations: Vec<u8>,
    pub query_indices: Vec<usize>,
    pub query_fingerprint: [u8; 32],
    pub openings: Vec<OracleRowOpening>,
    pub blend: Option<StackedBlendCheckpoint>,
}

/// Inputs and native results at the point passed to the WHIR PCS verifier.
pub struct StackedBlendCheckpoint {
    pub rounds: Vec<[E; 2]>,
    pub value: E,
    pub point: Vec<E>,
    pub seed: [u8; 32],
}

/// Salted row bytes and the leaf-to-root siblings contained in the proof.
pub struct OracleRowOpening {
    pub salted_row: Vec<u8>,
    pub siblings: Vec<[u8; 32]>,
}

use crate::binary::veil::F;
pub use p3_recursion::pcs::binary::{BinaryWhirPlan, WhirFoldShape, WhirOracleSite};

/// Public proof data for a coordinate opening. The value, point and transcript
/// seed are native reference results; the external verifier must derive them.
pub struct CoordinateMessages {
    pub root: [u8; 32],
    pub blend: StackedBlendCheckpoint,
    pub raw: Vec<F>,
    pub seal: [u8; 32],
}

pub struct VectorMessages {
    pub root: [u8; 32],
    pub gamma: Option<E>,
    pub claims: Vec<E>,
    pub mask_dot: E,
    pub rows: Vec<OracleRowOpening>,
    pub coordinates: Vec<CoordinateMessages>,
}

pub struct ConstraintMessages {
    pub product_wires: Vec<E>,
    pub padding: Vec<E>,
    pub product: VectorMessages,
    pub product_state: [u8; 32],
    pub mask: VectorMessages,
    pub final_state: [u8; 32],
}

pub use super::super::air_algebra::Gate as EndpointGate;

/// Verifier-owned AIR gate graph, public preprocessing and constraint order.
pub struct EndpointProgram<'a> {
    pub gates: &'a [EndpointGate],
    pub private: &'a [bool],
    pub outputs: &'a [usize],
    pub preprocessing: &'a [Vec<E>],
}

impl PreparedMembership {
    pub fn endpoint_program(&self) -> EndpointProgram<'_> {
        EndpointProgram {
            gates: &self.algebra.gates,
            private: &self.algebra.private,
            outputs: &self.algebra.outputs,
            preprocessing: &self.prep_columns,
        }
    }

    /// Decode the public messages of both vector arguments in native transcript order.
    pub fn constraint_messages(
        &self,
        public: &ClientPublic,
        proof: &MaskedMembershipProof,
    ) -> Result<ConstraintMessages> {
        use super::super::vector::powers;
        let mut reader = MaskedReader::new(
            &self.parameters,
            &self.binding(public, &proof.oracle_root)?,
            self.messages,
            &proof.inner.masks.root,
            &proof.inner.masked,
        )?;
        ensure!(
            proof.inner.products.dot.claims.len() == 3 && proof.inner.masks.dot.claims.len() == 1,
            "invalid vector claim counts"
        );
        let relation = self.replay(public, &proof.oracle_root, &proof.opening, &mut reader)?;
        reader.finish(&relation)?;
        let t = reader.public_transcript();
        t.bytes(b"product-commitment", &proof.inner.products.root);
        let link = t.challenge(b"product-link")?;
        let products = relation.padded_products();
        let link_weights = powers(link, products.len());
        let product = proof.inner.products.opening_messages(
            &self.parameters.code(products.len(), true)?,
            &link_weights,
            &self.parameters,
            t,
        )?;
        let product_state = t.fingerprint();
        let batch = t.challenge(b"linear-batch")?;
        let (weights, constant) =
            relation.linear_test(&[], &products, &link_weights, &product.claims, batch);
        ensure!(
            super::super::vector::dot(&weights, &proof.inner.masked) + constant
                == proof.inner.masks.dot.claims[0],
            "invalid masked consistency"
        );
        let mask = proof.inner.masks.opening_messages(
            &self.parameters.code(proof.inner.masked.len(), false)?,
            &weights,
            &self.parameters,
            t,
        )?;
        Ok(ConstraintMessages {
            product_wires: proof.inner.masked[self.messages - self.algebra.products..self.messages]
                .to_vec(),
            padding: proof.inner.masked[self.messages..].to_vec(),
            product,
            product_state,
            mask,
            final_state: t.fingerprint(),
        })
    }

    pub fn coordinate_plan(&self, length: usize) -> Result<BinaryWhirPlan<F, E>> {
        Ok(
            super::super::whir::recursive::PreparedWhir::new(length, &self.parameters)?
                .plan()
                .clone(),
        )
    }

    /// Trusted geometry of the coordinate opening of the stacked polynomial.
    pub fn stacked_whir_plan(&self) -> Result<BinaryWhirPlan<F, E>> {
        let (_, h) = self.stacked_query_geometry()?;
        let length = 1 << (h - self.parameters.log_inv_rate);
        Ok(
            super::super::whir::recursive::PreparedWhir::new(length, &self.parameters)?
                .plan()
                .clone(),
        )
    }

    /// Canonical public proof messages, expanded paths, and native transcript seal.
    pub fn stacked_whir_advice(
        &self,
        proof: &MaskedMembershipProof,
        cp: &StackedBlendCheckpoint,
    ) -> Result<(Vec<F>, [u8; 32])> {
        proof.opening.opening_advice(cp, &self.parameters)
    }

    /// Replay the AIR and stacked oracle query schedule using only the statement and the decoded client proof.
    /// The checkpoint alone does not authenticate the terminal AIR or PCS claims.
    pub fn stacked_oracle_checkpoint(
        &self,
        public: &ClientPublic,
        proof: &MaskedMembershipProof,
    ) -> Result<StackedOracleCheckpoint> {
        self.oracle_checkpoint(public, proof, false)
    }

    /// Also evaluate the coded-row functional and its quadratic sumcheck.
    pub fn stacked_blend_checkpoint(
        &self,
        public: &ClientPublic,
        proof: &MaskedMembershipProof,
    ) -> Result<StackedOracleCheckpoint> {
        self.oracle_checkpoint(public, proof, true)
    }

    fn oracle_checkpoint(
        &self,
        public: &ClientPublic,
        proof: &MaskedMembershipProof,
        include_blend: bool,
    ) -> Result<StackedOracleCheckpoint> {
        let mut reader = MaskedReader::new(
            &self.parameters,
            &self.binding(public, &proof.oracle_root)?,
            self.messages,
            &proof.inner.masks.root,
            &proof.inner.masked,
        )?;
        let replay = self.program.replay(&mut reader)?;
        let challenges = replay
            .challenges
            .iter()
            .flat_map(|x| x.into_bytes())
            .collect();
        let reduced = self.program.reduce(replay)?;
        ensure!(
            reduced.claim.constant == E::ZERO,
            "unexpected constant in masked round claim"
        );
        let mut coefficients = vec![E::ZERO; self.program.message_count()];
        for (index, weight) in reduced.claim.terms {
            coefficients[index] += weight;
        }
        let air_fingerprint = reader.public_transcript().fingerprint();
        let code = self.oracle.code(&self.parameters)?;
        let queries = proof.opening.read_queries(
            &self.oracle,
            &proof.oracle_root,
            &[
                OraclePoint::Current(&reduced.point),
                OraclePoint::Next(&reduced.point),
            ],
            &code,
            &mut reader,
        )?;
        let start = self.program.message_count();
        let middle = start + 2 * self.trace_width();
        let (blend_root, blend_evals) = proof.opening.blend_messages();
        let encode = |fields: &[E]| {
            fields
                .iter()
                .flat_map(|x| x.into_bytes())
                .collect::<Vec<_>>()
        };
        let rows = proof.opening.opened_rows();
        ensure!(rows.len() == code.queries, "wrong stacked opening count");
        let mut openings = Vec::with_capacity(rows.len());
        for row in rows {
            ensure!(
                row.rows.len() == 1 && row.rows[0].len() == self.oracle_columns(),
                "wrong stacked row width"
            );
            ensure!(
                row.path.0.len() == 1 && row.path.0[0].len() == 2,
                "wrong stacked row salt width"
            );
            ensure!(
                row.path.1.len() == code.codeword_len.ilog2() as usize,
                "wrong stacked path height"
            );
            openings.push(OracleRowOpening {
                salted_row: row.rows[0]
                    .iter()
                    .chain(&row.path.0[0])
                    .flat_map(|x| x.into_bytes())
                    .collect(),
                siblings: row.path.1.clone(),
            });
        }
        let query_fingerprint = reader.public_transcript().fingerprint();
        let query_indices = queries.indices.clone();
        let blend = if include_blend {
            Some(proof.opening.blend_checkpoint(
                &self.oracle,
                code,
                queries,
                reader.public_transcript(),
            )?)
        } else {
            None
        };
        Ok(StackedOracleCheckpoint {
            oracle_root: proof.oracle_root,
            mask_root: proof.inner.masks.root,
            masked_round_bytes: proof.inner.masked[..self.program.message_count()]
                .iter()
                .flat_map(|x| x.into_bytes())
                .collect(),
            challenges,
            claim_coefficients: coefficients.iter().flat_map(|x| x.into_bytes()).collect(),
            air_fingerprint,
            column_evaluations: encode(&proof.inner.masked[start..middle]),
            mask_evaluations: encode(&proof.inner.masked[middle..middle + 2]),
            blend_root: *blend_root,
            blend_evaluations: encode(blend_evals),
            query_indices,
            openings,
            query_fingerprint,
            blend,
        })
    }
}
