//! Standalone authentication of both Keccak boundaries through the existing PCS.
//! This component is non-hiding and is not yet connected to the aggregate bus.
use super::recursive::{Bridge, CommittedInput, PreparedVerifier, deferred_seed, sumcheck_values};
use anyhow::{Result, ensure};
use old_binary_field::{Poly64 as CF, Poly192 as CE};
use p3_binary_pcs::whir::BooleanWhirOpening;
use p3_challenger::FieldChallenger;
use p3_commit::MultilinearPcs;
use p3_field::PrimeCharacteristicRing;
use p3_keccak::KeccakF;
use p3_matrix::dense::RowMajorMatrix;
use p3_multilinear_util::point::Point;
use p3_security::{ErrorBits, SecurityTerm};
use p3_sumcheck::{
    OpeningBatch, OpeningProtocol, PrescribedPointPcs, TableShape, TableSpec, layout::Table,
};
use p3_symmetric::Permutation;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};

use super::{
    BITS, Claim, E, F, POSITION_LOG, POSITIONS, Proof, State, Transcript, algebraic_error_degree,
    closing,
};
use crate::{
    config::{Challenger, Pcs, challenger, pcs},
    encoding::TableEncoding,
};

pub(crate) type Commitment = <Pcs as MultilinearPcs<E, Challenger>>::Commitment;
pub(crate) type Opening = <Pcs as MultilinearPcs<E, Challenger>>::Proof;
const DOMAIN: &[u8] = b"imt-committed-checkpoint-keccak-v1";

/// A claim that the committed output states are Keccak-f of the input states,
/// in the same order. The commitment does not itself identify any IMT statement.
#[derive(Clone, Serialize, Deserialize)]
pub struct Statement {
    pub log_batch: u32,
    pub commitment: Commitment,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct CommittedProof {
    output: E,
    reduction: Proof,
    closing: closing::Proof,
    opening: Opening,
}

pub struct CommittedBatch {
    log_batch: usize,
    transcript: Transcript,
    pcs: Pcs,
    protocol: OpeningProtocol,
    /// Conditional algebraic/PCS union bound, including candidate-set charges.
    /// Excludes Fiat–Shamir, knowledge, hash and protocol-composition claims.
    pub conditional_algebraic_bits: f64,
}

impl CommittedBatch {
    pub fn new(log_batch: usize) -> Result<Self> {
        Self::with_transcript(log_batch, Transcript::PostcardV1)
    }

    pub fn for_recursion(log_batch: usize) -> Result<Self> {
        Self::with_transcript(log_batch, Transcript::FixedV2)
    }

    fn with_transcript(log_batch: usize, transcript: Transcript) -> Result<Self> {
        let degree = algebraic_error_degree(log_batch)?;
        let shape = TableShape::new(log_batch + POSITION_LOG, 1);
        let pcs = pcs(&[shape; 2], vec![TableEncoding::new(vec![1])?; 2])?;
        let protocol = OpeningProtocol::new(vec![
            TableSpec::new(shape, vec![OpeningBatch::new(vec![0], vec![])]),
            TableSpec::new(shape, vec![OpeningBatch::new(vec![0], vec![])]),
        ]);
        let mut security = pcs
            .prescribed_security(&protocol)
            .ok_or_else(|| anyhow::anyhow!("missing PCS security evidence"))?;
        ensure!(
            security.candidates().is_some(),
            "invalid PCS candidate bound"
        );
        security.charge_reduction(SecurityTerm::new(
            "checkpoint Keccak GKR, output batching and input closing",
            ErrorBits::from_numerator(192, (degree + log_batch + 3 * POSITION_LOG) as u128),
        ));
        let conditional_algebraic_bits = security.error().bits();
        ensure!(
            conditional_algebraic_bits >= 144.0,
            "insufficient conditional algebraic margin"
        );
        Ok(Self {
            log_batch,
            transcript,
            pcs,
            protocol,
            conditional_algebraic_bits,
        })
    }

    /// Produce a non-hiding committed permutation proof. Context is supplied by
    /// the enclosing application and must be identical at verification.
    pub fn prove(&self, inputs: &[State], context: &[u8]) -> Result<(Statement, CommittedProof)> {
        ensure!(
            inputs.len() == 1 << self.log_batch,
            "incorrect Keccak batch size"
        );
        let outputs = inputs
            .iter()
            .map(|&s| KeccakF.permute(s))
            .collect::<Vec<_>>();
        self.prove_outputs(inputs, &outputs, context)
    }

    /// Verify without receiving the original input or output state vectors.
    /// The caller must separately link `statement.commitment` to its application.
    pub fn verify(
        &self,
        statement: &Statement,
        proof: &CommittedProof,
        context: &[u8],
    ) -> Result<()> {
        ensure!(
            statement.log_batch as usize == self.log_batch,
            "incorrect Keccak batch size"
        );
        let mut ch = self.challenger(context);
        self.pcs.observe_commitment(&statement.commitment, &mut ch);
        let (mut output, point) = self.output_claim(&mut ch);
        output.value = proof.output;
        let input = super::verify_using(
            &proof.reduction,
            &output,
            self.log_batch,
            &mut ch,
            self.transcript,
        )?;
        let closing = closing::verify(&proof.closing, &input, &mut ch)?;
        let evals = self.pcs.verify_at(
            &statement.commitment,
            &proof.opening,
            &self.protocol,
            &[closing.point, point],
            &mut ch,
        )?;
        ensure!(
            evals.len() == 2 && evals[1].current() == [output.value],
            "incorrect committed Keccak output"
        );
        ensure!(
            evals[0].current().len() == 1
                && evals[0].current()[0] * closing.weight == closing.product,
            "incorrect committed Keccak input"
        );
        Ok(())
    }

    fn prove_outputs(
        &self,
        inputs: &[State],
        outputs: &[State],
        context: &[u8],
    ) -> Result<(Statement, CommittedProof)> {
        ensure!(
            inputs.len() == 1 << self.log_batch && outputs.len() == inputs.len(),
            "incorrect Keccak batch size"
        );
        let tables = vec![
            table(inputs, self.log_batch),
            table(outputs, self.log_batch),
        ];
        let mut ch = self.challenger(context);
        let (commitment, data) = self.pcs.commit(tables, &mut ch)?;
        let (mut output, point) = self.output_claim(&mut ch);
        let equality = Point::new(output.instance.as_slice()).equality_weights_msb();
        output.value = outputs
            .iter()
            .zip(equality)
            .map(|(state, weight)| {
                weight
                    * (0..BITS)
                        .filter(|&j| (state[j / 64] >> (j % 64)) & 1 != 0)
                        .map(|j| output.weights[j])
                        .sum::<E>()
            })
            .sum();
        // Deliberately no native validity check: tests also feed false outputs
        // through this path and require the authenticated proof to reject them.
        let (reduction, input) = super::prove_using(inputs, &output, &mut ch, self.transcript)?;
        let (closing, input_point, input_value) = closing::prove(inputs, &input, &mut ch);
        let opening = self.pcs.open_at_known(
            data,
            &self.protocol,
            &[input_point, point],
            &[
                Some(OpeningBatch::new(vec![input_value], vec![])),
                Some(OpeningBatch::new(vec![output.value], vec![])),
            ],
            &mut ch,
        )?;
        Ok((
            Statement {
                log_batch: self.log_batch as u32,
                commitment,
            },
            CommittedProof {
                output: output.value,
                reduction,
                closing,
                opening,
            },
        ))
    }

    /// Replay only through the PCS entry. The circuit must authenticate both returned openings.
    /// `ch` must already have observed this batch's commitment.
    pub fn recursive_input<C>(&self, proof: &CommittedProof, ch: &mut C) -> Result<CommittedInput>
    where
        C: old_challenger::FieldChallenger<CF> + old_challenger::GrindingChallenger<Witness = CF>,
    {
        ensure!(
            matches!(self.transcript, Transcript::FixedV2),
            "recursive input requires the fixed transcript"
        );
        let mut ch = Bridge(ch);
        let (mut output, output_point) = self.output_claim(&mut ch);
        output.value = proof.output;
        let input = super::verify_using(
            &proof.reduction,
            &output,
            self.log_batch,
            &mut ch,
            self.transcript,
        )?;
        let closing = closing::verify(&proof.closing, &input, &mut ch)?;
        let private_values = recursive_values(
            self.log_batch,
            proof.output,
            &proof.reduction,
            &proof.closing,
        )?;
        let points = [closing.point, output_point].map(|point| {
            point
                .iter()
                .map(|v| CE::new(v.coefficients().map(|c| CF::new(c.to_bits()))))
                .collect()
        });
        Ok(CommittedInput {
            private_values,
            points,
            opening: recursive_opening(&proof.opening)?,
        })
    }

    pub fn recursive_pcs_seed(&self) -> Vec<CF> {
        deferred_seed(self.log_batch + POSITION_LOG + 1, 2)
    }

    fn challenger(&self, context: &[u8]) -> Challenger {
        challenger(&self.transcript_seed(context))
    }

    pub fn transcript_seed(&self, context: &[u8]) -> [u8; 32] {
        let mut hash = Keccak256::new();
        hash.update(match self.transcript {
            Transcript::PostcardV1 => DOMAIN,
            Transcript::FixedV2 => b"imt-committed-checkpoint-keccak-v2",
        });
        hash.update((self.log_batch as u64).to_le_bytes());
        hash.update(context);
        hash.finalize().into()
    }

    fn output_claim<C: FieldChallenger<F>>(&self, ch: &mut C) -> (Claim, Point<E>) {
        let instance = (0..self.log_batch)
            .map(|_| ch.sample_algebra_element())
            .collect::<Vec<_>>();
        let position = (0..POSITION_LOG)
            .map(|_| ch.sample_algebra_element())
            .collect::<Vec<_>>();
        let mut weights = Point::new(position.as_slice()).equality_weights_msb();
        weights.truncate(BITS);
        let mut point = instance.clone();
        point.extend(position);
        (
            Claim {
                instance,
                weights,
                value: E::ZERO,
            },
            Point::new(point),
        )
    }
}

pub(super) fn table(states: &[State], log_batch: usize) -> Table<F> {
    let mut words = Vec::with_capacity(states.len() * POSITIONS / 64);
    for state in states {
        words.extend_from_slice(state);
        words.resize(words.len() + POSITIONS / 64 - state.len(), 0);
    }
    Table::from_packed_bits(RowMajorMatrix::new(words, 1), log_batch + POSITION_LOG)
}

pub(super) fn recursive_values(
    log_batch: usize,
    output: E,
    reduction: &Proof,
    closing: &closing::Proof,
) -> Result<Vec<CF>> {
    let mut values: Vec<_> = output.coefficients().map(|c| CF::new(c.to_bits())).to_vec();
    values.extend(PreparedVerifier::new(log_batch)?.private_values(reduction)?);
    values.extend(sumcheck_values(closing, POSITION_LOG, 2)?);
    Ok(values)
}

pub(crate) fn recursive_opening(proof: &Opening) -> Result<Vec<u8>> {
    let BooleanWhirOpening::Deferred(opening) = &proof.opening else {
        anyhow::bail!("recursive Keccak requires deferred WHIR");
    };
    ensure!(
        opening
            .reduction
            .claims
            .iter()
            .all(|c| c.successor.is_none()),
        "unexpected successor tensor"
    );
    let tensors: Vec<_> = opening.reduction.claims.iter().map(|c| &c.tensor).collect();
    Ok(postcard::to_allocvec(&(
        &proof.values,
        tensors,
        &opening.opening,
    ))?)
}

#[cfg(test)]
mod tests {
    use super::{CommittedBatch, CommittedProof, E, Statement};
    use crate::checkpoint_keccak::tests::inputs;
    use p3_field::PrimeCharacteristicRing;
    use p3_keccak::KeccakF;
    use p3_symmetric::Permutation;

    #[test]
    fn committed_keccak_authenticates_both_boundaries() {
        for log in [0, 1, 3] {
            let scheme = CommittedBatch::new(log).unwrap();
            assert!(scheme.conditional_algebraic_bits >= 144.0);
            let states = inputs(1 << log);
            let (statement, proof) = scheme.prove(&states, b"test").unwrap();
            let encoded = postcard::to_allocvec(&(statement.clone(), proof.clone())).unwrap();
            let (restored_statement, restored): (Statement, CommittedProof) =
                postcard::from_bytes(&encoded).unwrap();
            scheme
                .verify(&restored_statement, &restored, b"test")
                .unwrap();
            assert!(scheme.verify(&statement, &proof, b"other context").is_err());
            let mut changed = proof.clone();
            changed.output += E::ONE;
            assert!(scheme.verify(&statement, &changed, b"test").is_err());
            changed = proof.clone();
            changed.opening.values[0] += E::ONE;
            assert!(scheme.verify(&statement, &changed, b"test").is_err());
            changed = proof.clone();
            changed.closing.round_polys[0][0] += E::ONE;
            assert!(scheme.verify(&statement, &changed, b"test").is_err());
            changed = proof.clone();
            changed.reduction.layers[12].values[2] += E::ONE;
            assert!(scheme.verify(&statement, &changed, b"test").is_err());
            let mut wrong_count = statement.clone();
            wrong_count.log_batch += 1;
            assert!(scheme.verify(&wrong_count, &proof, b"test").is_err());
            let mut other_inputs = states.clone();
            other_inputs[0][0] ^= 1;
            let (other_statement, _) = scheme.prove(&other_inputs, b"test").unwrap();
            assert!(scheme.verify(&other_statement, &proof, b"test").is_err());
            let mut outputs = states
                .iter()
                .map(|&s| KeccakF.permute(s))
                .collect::<Vec<_>>();
            outputs[0][0] ^= 1;
            // Produce the false relation without a native validity gate; its
            // actual cryptographic verifier must reject it.
            let (false_statement, false_proof) =
                scheme.prove_outputs(&states, &outputs, b"test").unwrap();
            assert!(
                scheme
                    .verify(&false_statement, &false_proof, b"test")
                    .is_err()
            );
        }
    }
}
