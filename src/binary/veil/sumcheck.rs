//! Executable fixture for the online compiler, using Plonky3's sumcheck kernels.
//!
//! The two polynomial tables are PUBLIC. This deliberately closes the terminal
//! claims without assuming an unimplemented hiding PCS. It tests masked protocol
//! integration, not private IMT proving or a full zero-knowledge theorem.

use anyhow::{Result, ensure};
use p3_multilinear_util::{point::Point, poly::Poly};
use p3_sumcheck::strategy::{Basis, VariableOrder};
use rand::rngs::SysRng;
use serde::{Deserialize, Serialize};

use super::{
    E, F,
    compiler::{MaskedProver, MaskedReader},
    constraints::{ExperimentalProof, Linear, Relation},
    parameters::Parameters,
};

const PROGRAM: &[u8] = b"public-product-sumcheck-prefix-evaluation-v1";
const PROOF_MAGIC: &[u8; 8] = b"IMTVSC03";
const MAX_TABLE_LEN: usize = 1 << 16;
const MAX_PROOF_BYTES: usize = 1 << 20;

/// Public hypercube evaluations, in Plonky3 prefix order, and their claimed dot
/// product. This is a correctness fixture, not a commitment to private tables.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicSumcheck {
    pub left: Vec<E>,
    pub right: Vec<E>,
    pub claimed_sum: E,
}

/// Contains masked messages and an actual algebraic proof; no ordinary
/// sumcheck transcript or private mask data is serialized alongside it.
#[derive(Clone, Serialize, Deserialize)]
pub struct MaskedSumcheckProof {
    inner: ExperimentalProof,
}

impl PublicSumcheck {
    pub fn prove(&self, parameters: &Parameters) -> Result<MaskedSumcheckProof> {
        self.validate(parameters)?;
        let sum: E = self
            .left
            .iter()
            .zip(&self.right)
            .map(|(&a, &b)| a * b)
            .sum();
        ensure!(sum == self.claimed_sum, "incorrect public sumcheck claim");
        let mut rng = SysRng;
        let mut prover =
            MaskedProver::new(parameters, &self.binding()?, self.message_count(), &mut rng)?;
        let mut left = Poly::new(self.left.clone());
        let mut right = Poly::new(self.right.clone());
        for _ in 0..self.rounds() {
            // Reuse the existing characteristic-two-safe computation. No
            // interpolation at the integer 2, nor division by 2, is performed.
            let message = Basis::Evaluation.sumcheck_coefficients(
                VariableOrder::Prefix,
                left.as_slice(),
                right.as_slice(),
            );
            prover.send(b"round-polynomial", &[message.c_a, message.c_inf])?;
            let challenge = prover.challenge(b"round-challenge")?;
            VariableOrder::Prefix.fix_var(&mut left, challenge);
            VariableOrder::Prefix.fix_var(&mut right, challenge);
        }
        prover.send(
            b"terminal-evaluations",
            &[left.as_slice()[0], right.as_slice()[0]],
        )?;
        let inner = prover.finish(|reader| self.replay(reader), &mut rng)?;
        Ok(MaskedSumcheckProof { inner })
    }

    pub fn verify(&self, parameters: &Parameters, proof: &MaskedSumcheckProof) -> Result<()> {
        self.validate(parameters)?;
        let mut reader = MaskedReader::new(
            parameters,
            &self.binding()?,
            self.message_count(),
            &proof.inner.masks.root,
            &proof.inner.masked,
        )?;
        let relation = self.replay(&mut reader)?;
        reader.verify(parameters, &proof.inner, &relation)
    }

    fn validate(&self, parameters: &Parameters) -> Result<()> {
        parameters.validate()?;
        ensure!(
            self.left.len().is_power_of_two()
                && (2..=MAX_TABLE_LEN).contains(&self.left.len())
                && self.right.len() == self.left.len(),
            "sumcheck needs equal power-of-two public tables of length 2..=65536"
        );
        ensure!(
            self.message_count() <= parameters.max_message_len.saturating_sub(6),
            "sumcheck exceeds trusted message limit"
        );
        Ok(())
    }

    fn binding(&self) -> Result<Vec<u8>> {
        Ok(postcard::to_allocvec(&(PROGRAM, self))?)
    }

    fn rounds(&self) -> usize {
        self.left.len().ilog2() as usize
    }

    fn message_count(&self) -> usize {
        2 * self.rounds() + 2
    }

    /// The sole definition of the verifier's constraints, shared with prover
    /// replay. No native accept/reject Boolean is supplied as a witness.
    fn replay(&self, reader: &mut MaskedReader<'_>) -> Result<Relation> {
        let (running, challenges) = replay_rounds(reader, self.rounds(), self.claimed_sum)?;
        let endpoints = reader.read(b"terminal-evaluations", 2)?;
        let point = Point::new(challenges);
        let left = Poly::new(self.left.as_slice()).eval_ext::<F>(&point);
        let right = Poly::new(self.right.as_slice()).eval_ext::<F>(&point);
        let mut left_check = endpoints[0].clone();
        left_check.constant += left;
        let mut right_check = endpoints[1].clone();
        right_check.constant += right;
        Ok(Relation {
            variables: self.message_count(),
            public_wires: vec![],
            linear: vec![left_check, right_check],
            products: vec![[endpoints[0].clone(), endpoints[1].clone(), running]],
        })
    }
}

pub(super) fn replay_rounds(
    reader: &mut MaskedReader<'_>,
    rounds: usize,
    claimed_sum: E,
) -> Result<(Linear, Vec<E>)> {
    let mut running = Linear::constant(claimed_sum);
    let mut challenges = Vec::with_capacity(rounds);
    for _ in 0..rounds {
        let coefficients = reader.read(b"round-polynomial", 2)?;
        let r = reader.challenge(b"round-challenge")?;
        // Over characteristic two, h(0)+h(1)=C reconstructs the linear
        // coefficient as C+c_inf. Thus h(r)=c_0+r*C+(r^2+r)*c_inf.
        running.constant *= r;
        for (_, weight) in &mut running.terms {
            *weight *= r;
        }
        running.terms.extend(coefficients[0].terms.iter().copied());
        running.terms.extend(
            coefficients[1]
                .terms
                .iter()
                .map(|&(i, c)| (i, c * (r * r + r))),
        );
        challenges.push(r);
    }
    Ok((running, challenges))
}

impl MaskedSumcheckProof {
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = PROOF_MAGIC.to_vec();
        bytes.extend(postcard::to_allocvec(self)?);
        ensure!(
            bytes.len() <= MAX_PROOF_BYTES,
            "masked sumcheck exceeds transport limit"
        );
        Ok(bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() <= MAX_PROOF_BYTES,
            "masked sumcheck exceeds transport limit"
        );
        let payload = bytes
            .strip_prefix(PROOF_MAGIC)
            .ok_or_else(|| anyhow::anyhow!("unsupported masked sumcheck format"))?;
        let (proof, rest) = postcard::take_from_bytes(payload)?;
        ensure!(rest.is_empty(), "trailing masked sumcheck bytes");
        Ok(proof)
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use p3_field::PrimeCharacteristicRing;
    use p3_multilinear_util::poly::Poly;
    use p3_sumcheck::strategy::{Basis, VariableOrder};
    use rand::{RngExt, SeedableRng, rngs::StdRng};

    use super::{MaskedSumcheckProof, PublicSumcheck};
    use crate::binary::veil::{E, compiler::MaskedProver, parameters::Parameters};

    #[test]
    fn verifier_rejects_false_rounds_and_endpoints_without_native_precheck() -> Result<()> {
        let parameters = Parameters::default();
        let mut rng = StdRng::seed_from_u64(934);
        let left: Vec<E> = (0..8).map(|_| rng.random()).collect();
        let right: Vec<E> = (0..8).map(|_| rng.random()).collect();
        let claimed_sum: E = left.iter().zip(&right).map(|(&a, &b)| a * b).sum();
        for kind in 0..6 {
            let statement = PublicSumcheck {
                left: left.clone(),
                right: right.clone(),
                claimed_sum: claimed_sum + if kind == 5 { E::ONE } else { E::ZERO },
            };
            let mut prover = MaskedProver::new(
                &parameters,
                &statement.binding()?,
                statement.message_count(),
                &mut rng,
            )?;
            let mut a = Poly::new(left.clone());
            let mut b = Poly::new(right.clone());
            let mut running = statement.claimed_sum;
            for round in 0..statement.rounds() {
                let message = Basis::Evaluation.sumcheck_coefficients(
                    VariableOrder::Prefix,
                    a.as_slice(),
                    b.as_slice(),
                );
                let mut sent = [message.c_a, message.c_inf];
                if kind < 2 && round == 1 {
                    sent[kind] += E::ONE;
                }
                prover.send(b"round-polynomial", &sent)?;
                let r = prover.challenge(b"round-challenge")?;
                running = Basis::Evaluation.reduce_claim(sent[0], sent[1], r, running);
                VariableOrder::Prefix.fix_var(&mut a, r);
                VariableOrder::Prefix.fix_var(&mut b, r);
            }
            let mut terminal = [a.as_slice()[0], b.as_slice()[0]];
            if kind == 2 {
                terminal[0] += E::ONE;
            }
            if kind == 3 {
                terminal[1] += E::ONE;
            }
            if kind == 4 {
                // Satisfy the terminal product while lying about BOTH oracle
                // evaluations. Round consistency alone must not accept this.
                terminal = [E::ONE, running];
            }
            prover.send(b"terminal-evaluations", &terminal)?;
            let inner = prover.finish_unchecked(|reader| statement.replay(reader), &mut rng)?;
            assert!(
                statement
                    .verify(&parameters, &MaskedSumcheckProof { inner })
                    .is_err(),
                "forgery {kind}"
            );
        }
        Ok(())
    }

    #[test]
    fn changed_masked_messages_padding_and_commitment_are_rejected() -> Result<()> {
        let parameters = Parameters::default();
        let statement = PublicSumcheck {
            left: vec![E::ZERO, E::ONE],
            right: vec![E::ONE, E::ONE],
            claimed_sum: E::ONE,
        };
        let proof = statement.prove(&parameters)?;
        for kind in 0..5 {
            let mut altered = proof.clone();
            match kind {
                0 => altered.inner.masked[0] += E::ONE,
                1 => altered.inner.masked[statement.message_count()] += E::ONE,
                2 => altered.inner.masks.root[0] ^= 1,
                3 => {
                    altered.inner.masked.pop();
                }
                4 => altered.inner.masked.push(E::ZERO),
                _ => unreachable!(),
            }
            assert!(
                statement.verify(&parameters, &altered).is_err(),
                "tamper {kind}"
            );
        }
        Ok(())
    }
}
