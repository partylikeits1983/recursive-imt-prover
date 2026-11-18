//! One aggregate containing arithmetic and Keccak subarguments, linked at
//! authenticated trace openings. Neither subargument is accepted in isolation.
use anyhow::{Result, ensure};
use p3_binary_field::Poly192;
use p3_multi_stark::{VerifierInstances, folder::VerifierAir, verify_with_trace_openings};
use serde::{Deserialize, Serialize};

use crate::{
    F, Proof,
    checkpoint_keccak::{
        Statement,
        linked::{LinkedBatch, LinkedProof, PortOpening, arithmetic_seed},
    },
    config::{Config, challenger},
};

#[derive(Serialize, Deserialize)]
pub(crate) struct AggregateProof {
    pub statement: Statement,
    pub arithmetic: Proof,
    pub keccak: LinkedProof,
}

pub(crate) fn arithmetic_opening<'a, A: VerifierAir<F, Poly192>>(
    config: &Config,
    instances: VerifierInstances<'a, Config, A>,
    arithmetic: &Proof,
    statement: &Statement,
    authority: &[u8],
    hash_index: usize,
    log_batch: usize,
) -> Result<PortOpening> {
    ensure!(
        statement.log_batch as usize == log_batch,
        "incorrect boundary batch size"
    );
    let seed = arithmetic_seed(authority, statement)?;
    let opening =
        verify_with_trace_openings(config, instances, arithmetic, 0, &mut challenger(&seed))?;
    ensure!(
        opening.point.num_variables() >= log_batch,
        "invalid port opening arity"
    );
    let values = opening
        .current
        .get(hash_index)
        .ok_or_else(|| anyhow::anyhow!("missing authenticated Keccak ports"))?
        .clone();
    Ok(PortOpening {
        instance: opening.point.as_slice()[opening.point.num_variables() - log_batch..].to_vec(),
        values,
    })
}

pub(crate) fn verify<'a, A: VerifierAir<F, Poly192>>(
    config: &Config,
    instances: VerifierInstances<'a, Config, A>,
    scheme: &LinkedBatch,
    authority: &[u8],
    hash_index: usize,
    bytes: &[u8],
) -> Result<()> {
    ensure!(bytes.len() <= 16 << 20, "oversized aggregate proof");
    let proof: AggregateProof = crate::proof_codec::decode(bytes)?;
    let ports = arithmetic_opening(
        config,
        instances,
        &proof.arithmetic,
        &proof.statement,
        authority,
        hash_index,
        scheme.log_batch,
    )?;
    scheme.verify(&proof.statement, &proof.keccak, authority, &ports)
}
