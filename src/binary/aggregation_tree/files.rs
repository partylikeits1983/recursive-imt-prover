use std::{fs, path::Path};

use anyhow::{Result, ensure};
use imt_flock_backend::{HashBackend, MAX_VERIFIER_BYTES, verifier_key_digest};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::merge::{PROTOCOL, PreparedMerge, TreeProof, TreeVerifier};
use crate::{
    binary::{
        engine::Settings,
        veil::{
            aggregate::{MaskedAggregateVerifier, StatementFormat},
            child::PreparedMembership,
            parameters::Parameters,
        },
    },
    files::{read_bounded, read_json, write_json},
};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MergeTrust {
    protocol: String,
    identity: String,
    verifier_digest: [u8; 32],
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FirstTrust {
    protocol: String,
    settings: Settings,
    child_parameters: Parameters,
    child_identity: [u8; 32],
    components: bool,
    identities: Vec<String>,
    verifier_digest: [u8; 32],
    keccak_backend: HashBackend,
    statement_format: StatementFormat,
}

pub fn read_proof(directory: &Path) -> Result<TreeProof> {
    Ok(TreeProof {
        proof: read_bounded(&directory.join("aggregate.proof"), 16 << 20)?,
        public: read_json(&directory.join("statement.json"))?,
    })
}

/// Verifier files must come from an independently trusted source.
pub fn read_verifier(directory: &Path) -> Result<(TreeVerifier, [u8; 32])> {
    let data: Value = read_json(&directory.join("trusted.json"))?;
    let key = read_bounded(&directory.join("verifier.key"), MAX_VERIFIER_BYTES)?;
    if data["protocol"] == PROTOCOL {
        let trusted: MergeTrust = serde_json::from_value(data)?;
        return Ok((
            TreeVerifier::from_bytes(&key, &trusted.verifier_digest, &trusted.identity)?,
            trusted.verifier_digest,
        ));
    }
    let trusted: FirstTrust = serde_json::from_value(data)?;
    ensure!(
        !trusted.components
            && trusted.keccak_backend == HashBackend::Checkpoint
            && trusted.statement_format == StatementFormat::TreePair
            && trusted.protocol == StatementFormat::TreePair.protocol(HashBackend::Checkpoint)
            && trusted.identities.len() == 1,
        "expected checkpoint first-aggregation authority"
    );
    let child = PreparedMembership::new(trusted.settings.depth, trusted.child_parameters.clone())?;
    ensure!(
        child.identity() == trusted.child_identity,
        "incorrect child authority"
    );
    let verifier = MaskedAggregateVerifier::with_format(
        &trusted.settings,
        &trusted.child_parameters,
        &key,
        &trusted.verifier_digest,
        &trusted.identities[0],
        trusted.keccak_backend,
        trusted.statement_format,
    )?;
    Ok((verifier.into_tree_verifier()?, trusted.verifier_digest))
}

pub fn write_proof(directory: &Path, proof: &TreeProof, prepared: &PreparedMerge) -> Result<()> {
    let key = prepared.export_verifier_key()?;
    fs::write(directory.join("aggregate.proof"), &proof.proof)?;
    write_json(&directory.join("statement.json"), &proof.public)?;
    fs::write(directory.join("verifier.key"), &key)?;
    write_json(
        &directory.join("trusted.json"),
        &MergeTrust {
            protocol: PROTOCOL.to_owned(),
            identity: prepared.identity(),
            verifier_digest: verifier_key_digest(&key),
        },
    )
}
