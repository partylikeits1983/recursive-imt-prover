//! Hiding child proofs, trusted authority and canonical proof decoding.
use crate::legacy::air::ImtAir;
use crate::legacy::config::{F, Profile, ZkConfig, ZkProof};
use crate::legacy::statement::{CLAIM_FIELDS, Claim, FORMAT_VERSION, RELATION};
use crate::legacy::tree::Witness;
use anyhow::{Result, ensure};
use p3_recursion::{TrustedPreparedInput, TrustedPreparedSource};
use p3_uni_stark::{prove as prove_stark, verify as verify_stark};
use postcard::{take_from_bytes, to_allocvec};
use serde::{Deserialize, Serialize};
use std::time::Instant;

pub const MAX_CHILD_PROOF_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Authority {
    version: u32,
    relation: String,
    depth: u8,
    profile: Profile,
}

/// Authority is selected by trusted application configuration, not by proof metadata.
pub struct LeafVerifier {
    pub air: ImtAir,
    pub profile: Profile,
    pub config: ZkConfig,
}

pub struct Leaf {
    pub verifier: LeafVerifier,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChildTimings {
    pub trace_ms: f64,
    pub prove_ms: f64,
    pub verify_ms: f64,
}

/// A natively verified child; recursion independently checks its entire proof.
pub struct Child {
    proof: ZkProof,
    authority: LeafVerifier,
    fields: [F; CLAIM_FIELDS],
}

impl LeafVerifier {
    pub fn new(profile: Profile, depth: u8) -> Result<Self> {
        Ok(Self {
            air: ImtAir::new(depth)?,
            profile,
            config: profile.zk_config()?,
        })
    }

    pub fn bytes(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(&Authority {
            version: FORMAT_VERSION,
            relation: RELATION.into(),
            depth: self.air.depth(),
            profile: self.profile,
        })?)
    }

    pub fn decode(profile: Profile, bytes: &[u8]) -> Result<Self> {
        let authority: Authority = serde_json::from_slice(bytes)?;
        ensure!(
            authority.version == FORMAT_VERSION
                && authority.relation == RELATION
                && authority.profile == profile,
            "wrong child authority"
        );
        let verifier = Self::new(profile, authority.depth)?;
        ensure!(verifier.bytes()? == bytes, "noncanonical child authority");
        Ok(verifier)
    }

    pub fn verify(&self, proof: &ZkProof, claim: Claim) -> Result<()> {
        ensure!(
            proof.degree_bits == self.air.height(self.profile).ilog2() as usize + 1,
            "unsupported child proof degree"
        );
        verify_stark(&self.config, &self.air, proof, &claim.fields())?;
        Ok(())
    }
}

impl Leaf {
    pub fn prepare(profile: Profile, depth: u8) -> Result<Self> {
        Ok(Self {
            verifier: LeafVerifier::new(profile, depth)?,
        })
    }

    pub fn prove(&self, witness: &Witness, claim: Claim) -> Result<ZkProof> {
        Ok(self.prove_timed(witness, claim)?.0)
    }

    pub fn prove_timed(&self, witness: &Witness, claim: Claim) -> Result<(ZkProof, ChildTimings)> {
        let start = Instant::now();
        let trace = self.verifier.air.trace(witness, self.verifier.profile)?;
        let trace_ms = start.elapsed().as_secs_f64() * 1e3;
        let start = Instant::now();
        let proof = prove_stark(
            &self.verifier.config,
            &self.verifier.air,
            trace,
            &claim.fields(),
        )?;
        let prove_ms = start.elapsed().as_secs_f64() * 1e3;
        let start = Instant::now();
        self.verifier.verify(&proof, claim)?;
        let verify_ms = start.elapsed().as_secs_f64() * 1e3;
        Ok((
            proof,
            ChildTimings {
                trace_ms,
                prove_ms,
                verify_ms,
            },
        ))
    }

    pub fn verifier_bytes(&self) -> Result<Vec<u8>> {
        self.verifier.bytes()
    }

    pub fn encode_proof(&self, proof: &ZkProof) -> Result<Vec<u8>> {
        Ok(to_allocvec(proof)?)
    }
}

impl Child {
    pub fn statement(&self) -> &[F] {
        &self.fields
    }

    pub fn as_source(&self) -> TrustedPreparedSource<'_, '_, ZkConfig, ImtAir> {
        TrustedPreparedSource::UniStark {
            config: self.authority.config.clone(),
            air: &self.authority.air,
            preprocessed_commit: None,
            proof: &self.proof,
            public_inputs: &self.fields,
        }
    }

    pub fn as_input(&self) -> TrustedPreparedInput<'_, ZkConfig> {
        TrustedPreparedInput::UniStark {
            proof: &self.proof,
            public_inputs: &self.fields,
        }
    }
}

pub fn importer(profile: Profile, pin: &[u8]) -> Result<LeafVerifier> {
    LeafVerifier::decode(profile, pin)
}

pub fn import_child(verifier: &LeafVerifier, claim: Claim, bytes: &[u8]) -> Result<Child> {
    ensure!(
        bytes.len() <= MAX_CHILD_PROOF_BYTES,
        "child proof exceeds 16 MiB limit"
    );
    let (proof, tail) = take_from_bytes::<ZkProof>(bytes)?;
    ensure!(
        tail.is_empty() && to_allocvec(&proof)? == bytes,
        "noncanonical child proof"
    );
    verifier.verify(&proof, claim)?;
    Ok(Child {
        proof,
        authority: LeafVerifier::new(verifier.profile, verifier.air.depth())?,
        fields: claim.fields(),
    })
}
