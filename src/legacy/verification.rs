//! Portable outer-proof encoding, verification and accepted-root policy.
use crate::legacy::config::{Config, Proof};
use crate::legacy::statement::{Digest, Statement, field_bytes};
use anyhow::{Result, ensure};
use p3_circuit_prover::CircuitVerifier;
use p3_recursion::artifact::{
    ArtifactLimits, CanonicalStatement, ExpectedVerifierArtifact, PortableArtifactExport,
    PortableVerifier,
};

pub fn encode_verifier(verifier: &CircuitVerifier<Config>) -> Result<Vec<u8>> {
    Ok(verifier.encode_verifier_artifact(ArtifactLimits::default())?)
}

pub fn encode_proof(verifier: &CircuitVerifier<Config>, proof: &Proof) -> Result<Vec<u8>> {
    Ok(verifier.encode_proof_artifact(proof, ArtifactLimits::default())?)
}

pub fn verify(pin: &[u8], statement: &Statement, proof: &[u8]) -> Result<()> {
    let verifier = PortableVerifier::decode(
        pin,
        ExpectedVerifierArtifact::from_trusted_bytes(pin),
        ArtifactLimits::default(),
    )?;
    let fields = statement.fields()?;
    verifier.verify_encoded(
        proof,
        CanonicalStatement::new(&field_bytes(&fields), fields.len()),
    )?;
    Ok(())
}

/// Application policy is separate from proof validity. This list must come from
/// the verifier's independently maintained tree/history, never the prover.
pub fn verify_allowed(
    pin: &[u8],
    statement: &Statement,
    proof: &[u8],
    allowed: &[Digest],
) -> Result<()> {
    ensure!(
        statement.roots.iter().all(|r| allowed.contains(r)),
        "unaccepted membership root"
    );
    verify(pin, statement, proof)
}
