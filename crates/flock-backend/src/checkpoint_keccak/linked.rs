//! Keccak subargument linked to authenticated native port-table openings.
//! The enclosing protocol must bind `statement` before its AIR challenges.
use anyhow::{Result, ensure};
use p3_binary_field::TowerLevel;
use p3_challenger::{CanObserve, FieldChallenger};
use p3_commit::MultilinearPcs;
use p3_field::PrimeCharacteristicRing;
use p3_keccak::KeccakF;
use p3_multilinear_util::point::Point;
use p3_security::{CandidateSet, ErrorBits, SecurityTerm};
use p3_sumcheck::{
    OpeningBatch, OpeningProtocol, PrescribedPointPcs, TableShape, TableSpec, layout::Table,
};
use p3_symmetric::Permutation;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};

use super::{
    BITS, Claim, E, F, POSITION_LOG, POSITIONS, Proof, State, Statement, algebraic_error_degree,
    closing,
    committed::{Opening, table},
    ports,
};
use crate::{
    config::{Challenger, Data, Pcs, challenger, pcs},
    encoding::TableEncoding,
};

const DOMAIN: &[u8] = b"imt-checkpoint-keccak-native-ports-v1";

pub(crate) struct LinkedBatch {
    pub log_batch: usize,
    pcs: Pcs,
    protocol: OpeningProtocol,
    pub conditional_algebraic_bits: f64,
    pub initial_codeword_cells: usize,
}

pub(crate) struct BoundaryWitness {
    inputs: Vec<State>,
    outputs: Vec<State>,
}

pub(crate) struct Pending {
    pub statement: Statement,
    data: Data,
    witness: BoundaryWitness,
    challenger: Challenger,
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct LinkedProof {
    output: E,
    reduction: Proof,
    input_closing: closing::Proof,
    port_closing: closing::Proof,
    opening: Opening,
}

/// Created by the enclosing verifier from a fully authenticated AIR opening.
#[derive(Clone, Serialize)]
pub(crate) struct PortOpening {
    pub instance: Vec<E>,
    pub values: Vec<E>,
}

impl BoundaryWitness {
    pub fn new(inputs: Vec<State>) -> Self {
        let outputs = inputs.iter().map(|&state| KeccakF.permute(state)).collect();
        Self { inputs, outputs }
    }

    pub fn ports(&self) -> Table<F> {
        ports::table(&self.inputs, &self.outputs)
    }
}

impl LinkedBatch {
    pub fn new(log_batch: usize, main_candidate_log2: f64) -> Result<Self> {
        let degree = algebraic_error_degree(log_batch)?;
        ensure!(
            main_candidate_log2.is_finite() && main_candidate_log2 >= 0.0,
            "invalid arithmetic candidate bound"
        );
        let shape = TableShape::new(log_batch + POSITION_LOG, 1);
        let pcs = pcs(&[shape; 2], vec![TableEncoding::new(vec![1])?; 2])?;
        let protocol = OpeningProtocol::new(
            (0..2)
                .map(|_| TableSpec::new(shape, vec![OpeningBatch::new(vec![0], vec![]); 2]))
                .collect(),
        );
        let mut security = pcs
            .prescribed_security(&protocol)
            .ok_or_else(|| anyhow::anyhow!("missing linked Keccak PCS evidence"))?;
        ensure!(
            security.candidates().is_some(),
            "invalid boundary candidate bound"
        );
        security.charge_reduction(SecurityTerm::new(
            "checkpoint Keccak GKR, output batching and input closing",
            ErrorBits::from_numerator(192, (degree + log_batch + 3 * POSITION_LOG) as u128),
        ));
        // A mismatched port survives only at a zero of a polynomial in the
        // AIR row challenges and eight fresh port coordinates. Charge both
        // commitment candidate sets conservatively, also for the link closing.
        let candidates =
            CandidateSet::from_log2(main_candidate_log2 + security.log2_max_candidates)
                .ok_or_else(|| anyhow::anyhow!("invalid joint candidate bound"))?;
        let link_degree = log_batch + ports::PORT_LOG + 2 * (POSITION_LOG + 1);
        security.terms.push(
            SecurityTerm::new(
                "checkpoint/native port linkage",
                ErrorBits::from_numerator(192, link_degree as u128),
            )
            .over_candidates(candidates),
        );
        let conditional_algebraic_bits = security.error().bits();
        ensure!(
            conditional_algebraic_bits >= 144.0,
            "linked Keccak margin below 144 bits"
        );
        Ok(Self {
            log_batch,
            pcs,
            protocol,
            conditional_algebraic_bits,
            initial_codeword_cells: 1 << (log_batch + POSITION_LOG + 1 - 6 + 1),
        })
    }

    /// Must precede the enclosing arithmetic proof's commitment/challenges.
    pub fn commit(&self, witness: BoundaryWitness, authority: &[u8]) -> Result<Pending> {
        ensure!(
            witness.inputs.len() == 1 << self.log_batch,
            "incorrect boundary batch size"
        );
        let mut challenger = self.challenger(authority);
        let (commitment, data) = self.pcs.commit(
            vec![
                table(&witness.inputs, self.log_batch),
                table(&witness.outputs, self.log_batch),
            ],
            &mut challenger,
        )?;
        Ok(Pending {
            statement: Statement {
                log_batch: self.log_batch as u32,
                commitment,
            },
            data,
            witness,
            challenger,
        })
    }

    pub fn prove(&self, pending: Pending, ports: &PortOpening) -> Result<LinkedProof> {
        let Pending {
            statement,
            data,
            witness,
            mut challenger,
        } = pending;
        ensure!(
            statement.log_batch as usize == self.log_batch,
            "incorrect boundary batch size"
        );
        self.bind_ports(ports, &mut challenger)?;
        let (mut output, output_point) = self.output_claim(&mut challenger);
        output.value = closing::fold_states(&witness.outputs, &output.instance)
            .iter()
            .zip(&output.weights)
            .map(|(&a, &b)| a * b)
            .sum();
        let (reduction, input) = super::prove(&witness.inputs, &output, &mut challenger)?;
        let (input_closing, input_point, input_value) =
            closing::prove(&witness.inputs, &input, &mut challenger);
        let (weights, value) = ports::claim(ports, &mut challenger);
        let folded_input = closing::fold_states(&witness.inputs, &ports.instance);
        let folded_output = closing::fold_states(&witness.outputs, &ports.instance);
        let mut values = folded_input.clone();
        values.resize(POSITIONS, E::ZERO);
        values.extend_from_slice(&folded_output);
        values.resize(2 * POSITIONS, E::ZERO);
        let (port_closing, port_point, _) =
            closing::prove_functional(weights, values, value, &mut challenger);
        let link_input = closing::evaluate_folded(&folded_input, &port_point.as_slice()[1..]);
        let link_output = closing::evaluate_folded(&folded_output, &port_point.as_slice()[1..]);
        let link_point = link_point(ports, &port_point);
        let opening = self.pcs.open_at_known(
            data,
            &self.protocol,
            &[input_point, link_point.clone(), output_point, link_point],
            &[input_value, link_input, output.value, link_output]
                .map(|v| Some(OpeningBatch::new(vec![v], vec![]))),
            &mut challenger,
        )?;
        Ok(LinkedProof {
            output: output.value,
            reduction,
            input_closing,
            port_closing,
            opening,
        })
    }

    pub fn verify(
        &self,
        statement: &Statement,
        proof: &LinkedProof,
        authority: &[u8],
        ports: &PortOpening,
    ) -> Result<()> {
        ensure!(
            statement.log_batch as usize == self.log_batch,
            "incorrect boundary batch size"
        );
        let mut ch = self.challenger(authority);
        self.pcs.observe_commitment(&statement.commitment, &mut ch);
        self.bind_ports(ports, &mut ch)?;
        let (mut output, output_point) = self.output_claim(&mut ch);
        output.value = proof.output;
        let input = super::verify(&proof.reduction, &output, self.log_batch, &mut ch)?;
        let input = closing::verify(&proof.input_closing, &input, &mut ch)?;
        let (weights, value) = ports::claim(ports, &mut ch);
        let link = closing::verify_functional(&proof.port_closing, &weights, value, &mut ch)?;
        let selector = link.point.as_slice()[0];
        let link_point = link_point(ports, &link.point);
        let evals = self.pcs.verify_at(
            &statement.commitment,
            &proof.opening,
            &self.protocol,
            &[input.point, link_point.clone(), output_point, link_point],
            &mut ch,
        )?;
        ensure!(
            evals.len() == 4 && evals.iter().all(|e| e.current().len() == 1),
            "incorrect boundary opening count"
        );
        ensure!(
            evals[2].current()[0] == output.value,
            "incorrect Keccak output"
        );
        ensure!(
            input.product == input.weight * evals[0].current()[0],
            "incorrect Keccak input"
        );
        let a = evals[1].current()[0];
        let b = evals[3].current()[0];
        ensure!(
            link.product == link.weight * (a + selector * (b - a)),
            "native Keccak ports do not match committed boundaries"
        );
        Ok(())
    }

    fn challenger(&self, authority: &[u8]) -> Challenger {
        let mut hash = Keccak256::new();
        hash.update(DOMAIN);
        hash.update((self.log_batch as u64).to_le_bytes());
        hash.update(authority);
        challenger(&hash.finalize())
    }

    fn bind_ports(&self, ports: &PortOpening, ch: &mut Challenger) -> Result<()> {
        ensure!(
            ports.instance.len() == self.log_batch && ports.values.len() == ports::PORTS,
            "incorrect native Keccak port opening shape"
        );
        let digest = Keccak256::digest(postcard::to_allocvec(&(
            DOMAIN,
            self.log_batch as u64,
            ports,
        ))?);
        for bytes in digest.as_chunks::<8>().0 {
            ch.observe(F::from_repr(u64::from_le_bytes(*bytes)));
        }
        Ok(())
    }

    fn output_claim(&self, ch: &mut Challenger) -> (Claim, Point<E>) {
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

/// The arithmetic transcript must use this seed, fixing the boundary commitment
/// before its own trace commitment and every row challenge used by the link.
pub(crate) fn arithmetic_seed(authority: &[u8], statement: &Statement) -> Result<Vec<u8>> {
    Ok(Keccak256::digest(postcard::to_allocvec(&(DOMAIN, authority, statement))?).to_vec())
}

fn link_point(ports: &PortOpening, low: &Point<E>) -> Point<E> {
    let mut point = ports.instance.clone();
    point.extend_from_slice(&low.as_slice()[1..]);
    Point::new(point)
}

#[cfg(test)]
mod tests {
    use p3_challenger::FieldChallenger;
    use p3_field::PrimeCharacteristicRing;
    use p3_multilinear_util::{point::Point, poly::Poly};

    use super::{BoundaryWitness, E, LinkedBatch, PortOpening, arithmetic_seed};
    use crate::{checkpoint_keccak::tests::inputs, config::challenger};

    #[test]
    fn false_port_link_reaches_prover_and_is_rejected_cryptographically() {
        let scheme = LinkedBatch::new(4, 0.0).unwrap();
        let inputs = inputs(16);
        let witness = BoundaryWitness::new(inputs.clone());
        let table = witness.ports();
        let pending = scheme.commit(witness, b"port-test").unwrap();
        let mut ch = challenger(&arithmetic_seed(b"port-test", &pending.statement).unwrap());
        let instance = (0..4)
            .map(|_| ch.sample_algebra_element::<E>())
            .collect::<Vec<_>>();
        let point = Point::new(instance.clone());
        let ports = PortOpening {
            instance,
            values: (0..232)
                .map(|column| Poly::new(table.poly(column).as_slice().to_vec()).eval_base(&point))
                .collect(),
        };
        let statement = pending.statement.clone();
        let proof = scheme.prove(pending, &ports).unwrap();
        scheme
            .verify(&statement, &proof, b"port-test", &ports)
            .unwrap();
        for column in [0, 99, 100, 199, 200, 215, 216, 231] {
            let mut false_ports = ports.clone();
            false_ports.values[column] += E::ONE;
            let pending = scheme
                .commit(BoundaryWitness::new(inputs.clone()), b"port-test")
                .unwrap();
            // The permutation proof itself is genuine. There is no native
            // equality gate stopping the false port claim from being proved.
            let false_proof = scheme.prove(pending, &false_ports).unwrap();
            assert!(
                scheme
                    .verify(&statement, &false_proof, b"port-test", &false_ports)
                    .is_err()
            );
        }
    }
}
