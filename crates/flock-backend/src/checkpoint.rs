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
    bridge_ports(
        scheme,
        &opening.point,
        opening
            .current
            .get(hash_index)
            .ok_or_else(|| anyhow::anyhow!("missing authenticated Keccak ports"))?,
    )
}

pub(crate) fn bridge_ports(
    scheme: &LinkedBatch,
    point: &p3_multilinear_util::point::Point<Poly192>,
    values: &[Poly192],
) -> Result<PortOpening> {
    let arity = scheme.log_batch + usize::from(scheme.direct_bridge);
    ensure!(point.num_variables() >= arity, "invalid port opening arity");
    let instance = point.as_slice()[point.num_variables() - arity..].to_vec();
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
        values.to_vec()
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
    if config.joint_security.is_some() {
        let (proof, coefficients) = JointProof::decode(bytes, scheme.packed_chi)?;
        return verify_joint(
            config,
            instances,
            scheme,
            authority,
            hash_index,
            &proof,
            &coefficients,
        );
    }
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

#[derive(Serialize, Deserialize)]
pub(crate) struct JointProof {
    pub arithmetic: Proof,
    pub keccak: crate::checkpoint_keccak::linked::LinkedClaims,
    pub ports: PortOpening,
}

impl JointProof {
    pub(crate) fn decode(bytes: &[u8], packed: bool) -> Result<(Self, Vec<Vec<Poly192>>)> {
        if packed {
            crate::proof_codec::decode(bytes)
        } else {
            Ok((crate::proof_codec::decode(bytes)?, Vec::new()))
        }
    }
    pub(crate) fn encode(&self, packed: bool, coefficients: &[Vec<Poly192>]) -> Result<Vec<u8>> {
        if packed {
            crate::proof_codec::encode(&(self, coefficients))
        } else {
            crate::proof_codec::encode(self)
        }
    }
}

pub(crate) fn prove_joint(
    config: &Config,
    instances: p3_multi_stark::ProverInstances<'_, Config, crate::air::Chip>,
    scheme: &LinkedBatch,
    authority: &[u8],
    hash_index: usize,
    witness: crate::checkpoint_keccak::linked::BoundaryWitness,
) -> Result<Vec<u8>> {
    use p3_commit::MultilinearPcs;
    let mut linked = None;
    let arithmetic =
        p3_multi_stark::prover::prove_with_extra_tables::<_, _, p3_multi_stark::GenericBackend>(
            config,
            instances,
            0,
            &mut challenger(authority),
            scheme.tables(&witness),
            |cap, point, hints| {
                let reduce = || -> Result<_> {
                    // This layout has one current-row batch for each arithmetic table in order.
                    let row = hints
                        .get(hash_index)
                        .and_then(Option::as_ref)
                        .ok_or_else(|| anyhow::anyhow!("missing Keccak bridge batch"))?;
                    let ports = bridge_ports(scheme, point, row.current())?;
                    let mut ch = challenger(&scheme.transcript_seed(authority));
                    config.main.observe_commitment(cap, &mut ch);
                    let openings = scheme.prove_claims(&witness, &ports, &mut ch)?;
                    Ok((ports, openings))
                };
                let (ports, openings) = reduce().map_err(|err| err.to_string())?;
                linked = Some((openings.claims, ports, openings.coefficients));
                Ok((openings.points, openings.hints))
            },
        )?;
    let (keccak, ports, coefficients) =
        linked.ok_or_else(|| anyhow::anyhow!("missing linked reduction"))?;
    JointProof {
        arithmetic,
        keccak,
        ports,
    }
    .encode(scheme.packed_chi, &coefficients)
}

pub(crate) fn verify_joint<'a, A: VerifierAir<F, Poly192>>(
    config: &Config,
    instances: VerifierInstances<'a, Config, A>,
    scheme: &LinkedBatch,
    authority: &[u8],
    hash_index: usize,
    proof: &JointProof,
    coefficients: &[Vec<Poly192>],
) -> Result<()> {
    use p3_commit::MultilinearPcs;
    let mut linked = challenger(&scheme.transcript_seed(authority));
    ensure!(
        proof.arithmetic.commitment.roots().len() == 1,
        "invalid joint commitment cap"
    );
    config
        .main
        .observe_commitment(&proof.arithmetic.commitment, &mut linked);
    let reduced = scheme.reduce_claims(&proof.keccak, coefficients, &proof.ports, &mut linked)?;
    let opened = p3_multi_stark::verifier::verify_with_extra_tables(
        config,
        instances,
        &proof.arithmetic,
        0,
        &mut challenger(authority),
        |_| Ok(reduced.points.clone()),
    )?;
    let ports = bridge_ports(
        scheme,
        &opened.point,
        opened
            .current
            .get(hash_index)
            .ok_or_else(|| anyhow::anyhow!("missing Keccak bridge"))?,
    )?;
    ensure!(
        ports.instance == proof.ports.instance && ports.values == proof.ports.values,
        "incorrect joint Keccak bridge"
    );
    reduced.authenticate(&opened.auxiliary)?;
    #[cfg(feature = "opening-bench")]
    if scheme.packed_chi {
        crate::opening_trace::record_linked_prefix(
            authority,
            &proof.arithmetic.commitment.roots()[0],
            &proof.ports,
            &proof.keccak,
            &coefficients[0],
            reduced.points[2].as_slice(),
            None,
        );
    }
    Ok(())
}
