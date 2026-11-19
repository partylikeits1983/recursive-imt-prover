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
        linked::{LinkedBatch, LinkedProof, PortOpening},
        ports::BRIDGE_LIMBS,
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
    scheme: &LinkedBatch,
) -> Result<PortOpening> {
    ensure!(
        statement.log_batch as usize == scheme.log_batch,
        "incorrect boundary batch size"
    );
    let seed = scheme.arithmetic_seed(authority, statement)?;
    let opening =
        verify_with_trace_openings(config, instances, arithmetic, 0, &mut challenger(&seed))?;
    ensure!(
        opening.point.num_variables() >= scheme.log_batch + usize::from(scheme.direct_bridge),
        "invalid port opening arity"
    );
    let values = opening
        .current
        .get(hash_index)
        .ok_or_else(|| anyhow::anyhow!("missing authenticated Keccak ports"))?
        .clone();
    let arity = scheme.log_batch + usize::from(scheme.direct_bridge);
    let instance = opening.point.as_slice()[opening.point.num_variables() - arity..].to_vec();
    let values = if scheme.direct_bridge {
        ensure!(
            values.len() == 2 * BRIDGE_LIMBS,
            "invalid authenticated Keccak bridge"
        );
        // The first coordinate selects the template. The last selects its
        // input/output row. Both come from the arithmetic sumcheck.
        values[..BRIDGE_LIMBS]
            .iter()
            .zip(&values[BRIDGE_LIMBS..])
            .map(|(&l, &r)| l + instance[0] * (r - l))
            .collect()
    } else {
        values
    };
    Ok(PortOpening { instance, values })
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
        scheme,
    )?;
    scheme.verify(&proof.statement, &proof.keccak, authority, &ports)
}
