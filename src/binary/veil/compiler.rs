//! Online masking of algebraic verifier messages, following VEIL's context model.
//!
//! No oracle commitments or PCS openings are implemented here. A caller supplies
//! a fixed verifier replay, including its terminal checks; satisfying only the
//! intermediate transcript equations would not prove a polynomial statement.

use anyhow::{Result, ensure};
use rand::TryCryptoRng;

use super::{
    E, F,
    constraints::{ExperimentalProof, Linear, PreparedTranscript, Relation, pad_witness},
    native::{NativeProverContext, NativeVerifierContext},
    parameters::Parameters,
    transcript::Transcript,
    vector::CommittedVectors,
};

pub(super) const PROTOCOL: &[u8] = b"experimental-binary-veil-online-v3";

pub(super) mod recursive;

/// Private, single-use state. All masks are committed before the first message.
pub(super) struct MaskedProver {
    parameters: Parameters,
    binding: Vec<u8>,
    variables: usize,
    witness: Vec<E>,
    masked: Vec<E>,
    masks: Vec<E>,
    commitment: CommittedVectors,
    transcript: Transcript,
}

/// Both prover replay and verification use this reader. It cannot read secrets.
pub(super) struct MaskedReader<'a> {
    transcript: Transcript,
    commitment: [u8; 32],
    masked: &'a [E],
    variables: usize,
    cursor: usize,
}

impl MaskedProver {
    pub fn public_transcript(&mut self) -> &mut Transcript {
        &mut self.transcript
    }
    pub fn new(
        parameters: &Parameters,
        binding: &[u8],
        variables: usize,
        rng: &mut impl TryCryptoRng,
    ) -> Result<Self> {
        validate_size(parameters, variables)?;
        let masks = super::coins::fields(rng, variables + 6)?;
        let commitment = CommittedVectors::new(
            std::slice::from_ref(&masks),
            parameters.code(masks.len(), false)?,
            false,
            rng,
        )?;
        let transcript = start(parameters, binding, variables, &commitment.root)?;
        Ok(Self {
            parameters: parameters.clone(),
            binding: binding.to_vec(),
            variables,
            witness: Vec::with_capacity(variables),
            masked: Vec::with_capacity(variables + 6),
            masks,
            commitment,
            transcript,
        })
    }

    pub fn send(&mut self, label: &[u8], values: &[E]) -> Result<()> {
        let start = self.witness.len();
        ensure!(
            !values.is_empty() && values.len() <= self.variables - start,
            "masked message exceeds fixed schedule"
        );
        self.witness.extend_from_slice(values);
        self.masked.extend(
            values
                .iter()
                .zip(&self.masks[start..])
                .map(|(&v, &m)| v + m),
        );
        self.transcript.fields(label, &self.masked[start..]);
        Ok(())
    }

    pub fn challenge(&mut self, label: &[u8]) -> Result<E> {
        self.transcript.challenge(label)
    }

    /// Consume the commitment; replay once to construct the same constraints
    /// as the verifier. There is no second commitment to a replacement mask.
    pub fn finish(
        self,
        verify: impl FnOnce(&mut MaskedReader<'_>) -> Result<Relation>,
        rng: &mut impl TryCryptoRng,
    ) -> Result<ExperimentalProof> {
        let parameters = self.parameters.clone();
        let (relation, prepared) = self.prepare(verify, rng)?;
        relation.check(&parameters, &[], &prepared.witness[..relation.variables])?;
        relation.prove_prepared(&parameters, &[], prepared, rng)
    }

    #[cfg(test)]
    pub fn finish_unchecked(
        self,
        verify: impl FnOnce(&mut MaskedReader<'_>) -> Result<Relation>,
        rng: &mut impl TryCryptoRng,
    ) -> Result<ExperimentalProof> {
        let parameters = self.parameters.clone();
        let (relation, prepared) = self.prepare(verify, rng)?;
        relation.prove_prepared(&parameters, &[], prepared, rng)
    }

    fn prepare(
        mut self,
        verify: impl FnOnce(&mut MaskedReader<'_>) -> Result<Relation>,
        rng: &mut impl TryCryptoRng,
    ) -> Result<(Relation, PreparedTranscript)> {
        ensure!(
            self.witness.len() == self.variables,
            "unfinished masked schedule"
        );
        let witness = pad_witness(&self.witness, rng)?;
        self.masked.extend(
            witness[self.variables..]
                .iter()
                .zip(&self.masks[self.variables..])
                .map(|(&v, &m)| v + m),
        );
        let mut reader = MaskedReader::new(
            &self.parameters,
            &self.binding,
            self.variables,
            &self.commitment.root,
            &self.masked,
        )?;
        let relation = verify(&mut reader)?;
        // Replaying never touches the prover's live sponge. This comparison
        // catches changed framing, labels, challenge calls or message order.
        ensure!(
            self.transcript.fingerprint() == reader.transcript.fingerprint(),
            "prover and verifier transcript schedules differ"
        );
        reader.finish(&relation)?;
        let transcript = reader.transcript;
        Ok((
            relation,
            PreparedTranscript {
                witness,
                masked: self.masked,
                masks: self.commitment,
                transcript,
            },
        ))
    }
}

impl<'a> MaskedReader<'a> {
    pub fn public_transcript(&mut self) -> &mut Transcript {
        &mut self.transcript
    }
    pub fn new(
        parameters: &Parameters,
        binding: &[u8],
        variables: usize,
        root: &[u8; 32],
        masked: &'a [E],
    ) -> Result<Self> {
        validate_size(parameters, variables)?;
        ensure!(
            masked.len() == variables + 6,
            "wrong masked schedule length"
        );
        Ok(Self {
            transcript: start(parameters, binding, variables, root)?,
            commitment: *root,
            masked,
            variables,
            cursor: 0,
        })
    }

    pub fn read(&mut self, label: &[u8], count: usize) -> Result<Vec<Linear>> {
        ensure!(
            count > 0 && count <= self.variables - self.cursor,
            "masked transcript exhausted"
        );
        let end = self.cursor + count;
        self.transcript
            .fields(label, &self.masked[self.cursor..end]);
        let expressions = (self.cursor..end).map(Linear::wire).collect();
        self.cursor = end;
        Ok(expressions)
    }

    pub fn challenge(&mut self, label: &[u8]) -> Result<E> {
        self.transcript.challenge(label)
    }

    pub(super) fn finish(&mut self, relation: &Relation) -> Result<()> {
        ensure!(self.cursor == self.variables, "unread masked messages");
        ensure!(
            relation.variables == self.variables,
            "wrong replay relation size"
        );
        ensure!(
            relation.public_wires.is_empty(),
            "bind public values in verifier replay"
        );
        self.transcript
            .fields(b"multiplication-padding", &self.masked[self.variables..]);
        // The trusted verifier program was bound at start. Its coefficients
        // are deterministic functions of this authenticated transcript and
        // are used directly by the inner check, so hashing a second large
        // serialization of the derived relation adds no binding information.
        self.transcript.integers(
            b"verifier-constraint-shape-v1",
            &[
                relation.variables,
                relation.linear.len(),
                relation.products.len(),
            ],
        );
        Ok(())
    }

    pub fn verify(
        mut self,
        parameters: &Parameters,
        proof: &ExperimentalProof,
        relation: &Relation,
    ) -> Result<()> {
        ensure!(
            self.commitment == proof.masks.root && self.masked == proof.masked,
            "algebraic proof does not open the replayed mask commitment/messages"
        );
        self.finish(relation)?;
        relation.verify_prepared(parameters, &[], proof, &mut self.transcript)
    }
}

impl NativeProverContext for MaskedProver {
    fn public(&mut self, value: F) -> Result<()> {
        self.transcript.fields(b"native-public", &[E::from(value)]);
        Ok(())
    }
    fn message(&mut self, values: &[E]) -> Result<()> {
        self.send(b"native-message", values)
    }
    fn challenge(&mut self) -> Result<E> {
        self.challenge(b"native-challenge")
    }
}

impl NativeVerifierContext for MaskedReader<'_> {
    type Hidden = Linear;
    fn public(&mut self, value: F) -> Result<()> {
        self.transcript.fields(b"native-public", &[E::from(value)]);
        Ok(())
    }
    fn message(&mut self, count: usize) -> Result<Vec<Linear>> {
        self.read(b"native-message", count)
    }
    fn challenge(&mut self) -> Result<E> {
        self.challenge(b"native-challenge")
    }
}

fn validate_size(parameters: &Parameters, variables: usize) -> Result<()> {
    parameters.validate()?;
    ensure!(
        variables > 0 && variables <= parameters.max_message_len.saturating_sub(6),
        "invalid masked transcript size"
    );
    Ok(())
}

fn start(
    parameters: &Parameters,
    binding: &[u8],
    variables: usize,
    root: &[u8; 32],
) -> Result<Transcript> {
    let mut transcript = Transcript::for_protocol(PROTOCOL, binding);
    transcript.integers(
        b"online-parameters",
        &[
            parameters.query_bits,
            parameters.min_algebraic_bits,
            parameters.log_inv_rate,
            parameters.max_message_len,
            variables,
        ],
    );
    transcript.bytes(b"mask-commitment", root);
    Ok(transcript)
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use p3_field::PrimeCharacteristicRing;
    use rand::{SeedableRng, rngs::StdRng};

    use super::{MaskedProver, MaskedReader};
    use crate::binary::veil::{
        E,
        constraints::{Linear, Relation},
        parameters::Parameters,
    };

    fn replay(reader: &mut MaskedReader<'_>) -> Result<Relation> {
        let mut message = reader.read(b"message", 1)?.remove(0);
        let _ = reader.challenge(b"challenge")?;
        message.constant += E::ONE;
        Ok(Relation {
            variables: 1,
            public_wires: vec![],
            linear: vec![message],
            products: vec![],
        })
    }

    #[test]
    fn schedule_requires_exact_reads_labels_and_challenges() -> Result<()> {
        let parameters = Parameters::default();
        let mut rng = StdRng::seed_from_u64(129);
        for kind in 0..5 {
            let mut prover = MaskedProver::new(&parameters, b"schedule-test", 1, &mut rng)?;
            if kind == 0 {
                assert!(prover.finish(replay, &mut rng).is_err());
                continue;
            }
            let label: &[u8] = if kind == 1 {
                b"different-message"
            } else {
                b"message"
            };
            prover.send(label, &[E::ONE])?;
            assert!(prover.send(b"overflow", &[E::ONE]).is_err());
            if kind != 2 {
                let _ = prover.challenge(b"challenge")?;
            }
            if kind == 3 {
                let _ = prover.challenge(b"extra-challenge")?;
            }
            if kind == 4 {
                assert!(
                    prover
                        .finish(
                            |_| Ok(Relation {
                                variables: 1,
                                public_wires: vec![],
                                linear: vec![Linear::wire(0)],
                                products: vec![],
                            }),
                            &mut rng
                        )
                        .is_err()
                );
            } else {
                assert!(prover.finish(replay, &mut rng).is_err());
            }
        }
        Ok(())
    }

    #[test]
    fn reader_cannot_substitute_mask_commitment_or_messages_at_finish() -> Result<()> {
        let parameters = Parameters::default();
        let mut rng = StdRng::seed_from_u64(130);
        let mut prover = MaskedProver::new(&parameters, b"substitution-test", 1, &mut rng)?;
        prover.send(b"message", &[E::ONE])?;
        let _ = prover.challenge(b"challenge")?;
        let proof = prover.finish(replay, &mut rng)?;
        for kind in 0..3 {
            let mut altered = proof.clone();
            if kind == 0 {
                altered.masks.root[0] ^= 1;
            }
            if kind == 1 {
                altered.masked[0] += E::ONE;
            }
            if kind == 2 {
                altered.masked[1] += E::ONE;
            }
            let mut reader = MaskedReader::new(
                &parameters,
                b"substitution-test",
                1,
                &proof.masks.root,
                &proof.masked,
            )?;
            let relation = replay(&mut reader)?;
            assert!(reader.verify(&parameters, &altered, &relation).is_err());
        }
        Ok(())
    }
}
