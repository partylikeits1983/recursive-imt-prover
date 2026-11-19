//! Keccak subargument linked to authenticated native port-table openings.
//! The enclosing protocol must bind `statement` before its AIR challenges.
use anyhow::{Result, ensure};
use old_binary_field::{Poly64 as CF, Poly192 as CE};
use p3_binary_field::TowerLevel;
use p3_challenger::FieldChallenger;
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
    BITS, Claim, E, F, POSITION_LOG, POSITIONS, Proof, State, Statement, Transcript,
    algebraic_error_degree, closing,
    committed::{Opening, recursive_opening, recursive_values, table},
    ports,
    recursive::{Bridge, LinkedInput, deferred_seed, sumcheck_values},
};
use crate::{
    config::{Challenger, Data, Pcs, WHIR_LOG_INV_RATE, challenger, pcs},
    encoding::TableEncoding,
};

const DOMAIN: &[u8] = b"imt-checkpoint-keccak-native-ports-v1";
pub(super) fn port_domain(direct_bridge: bool) -> &'static [u8] {
    if direct_bridge {
        b"imt-checkpoint-keccak-bridge-rows-v1"
    } else {
        b"imt-checkpoint-keccak-native-ports-fixed-v2"
    }
}
pub const PORTS: usize = ports::PORTS;

pub struct LinkedBatch {
    pub(crate) log_batch: usize,
    pub(crate) direct_bridge: bool,
    transcript: Transcript,
    pcs: Pcs,
    protocol: OpeningProtocol,
    pub conditional_algebraic_bits: f64,
    pub initial_codeword_cells: usize,
}

pub struct BoundaryWitness {
    inputs: Vec<State>,
    outputs: Vec<State>,
}

pub struct Pending {
    pub statement: Statement,
    data: Data,
    witness: BoundaryWitness,
    challenger: Challenger,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct LinkedProof {
    output: E,
    reduction: Proof,
    input_closing: closing::Proof,
    port_closing: closing::Proof,
    opening: Opening,
}

/// Created by the enclosing verifier from a fully authenticated AIR opening.
#[derive(Clone, Serialize, Deserialize)]
pub struct PortOpening {
    /// Direct bridge openings append the input/output selector to the batch point.
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

    pub fn opening(&self, point: &[CE]) -> Result<PortOpening> {
        ensure!(
            point.len() <= super::MAX_BATCH_LOG && 1usize << point.len() == self.inputs.len(),
            "incorrect port opening arity"
        );
        let instance: Vec<_> = point
            .iter()
            .map(|v| E::new(v.coefficients().map(|c| F::new(c.to_bits()))))
            .collect();
        let weights = Point::new(instance.as_slice()).equality_weights_msb();
        let table = self.ports();
        let values = (0..PORTS)
            .map(|column| {
                table
                    .poly(column)
                    .as_slice()
                    .iter()
                    .zip(&weights)
                    .map(|(&v, &w)| w * v)
                    .sum()
            })
            .collect();
        Ok(PortOpening { instance, values })
    }
}

impl LinkedBatch {
    pub(crate) fn with_bridge(
        log_batch: usize,
        main_candidate_log2: f64,
        direct_bridge: bool,
    ) -> Result<Self> {
        Self::with_transcript(
            log_batch,
            main_candidate_log2,
            Transcript::FixedV2,
            direct_bridge,
        )
    }

    pub fn new(log_batch: usize, main_candidate_log2: f64) -> Result<Self> {
        Self::with_transcript(
            log_batch,
            main_candidate_log2,
            Transcript::PostcardV1,
            false,
        )
    }

    pub fn for_recursion(log_batch: usize, main_candidate_log2: f64) -> Result<Self> {
        Self::with_bridge(log_batch, main_candidate_log2, false)
    }

    fn with_transcript(
        log_batch: usize,
        main_candidate_log2: f64,
        transcript: Transcript,
        direct_bridge: bool,
    ) -> Result<Self> {
        ensure!(
            !direct_bridge || log_batch >= 1,
            "bridge needs two template instances"
        );
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
        // AIR row challenges and fresh port coordinates. Charge both
        // commitment candidate sets conservatively, also for the link closing.
        let candidates =
            CandidateSet::from_log2(main_candidate_log2 + security.log2_max_candidates)
                .ok_or_else(|| anyhow::anyhow!("invalid joint candidate bound"))?;
        // The bridge uses one extra row challenge for the input/output side
        // and one fewer port-coordinate challenge (116 limbs instead of 232).
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
            direct_bridge,
            transcript,
            pcs,
            protocol,
            conditional_algebraic_bits,
            initial_codeword_cells: 1 << (log_batch + POSITION_LOG + 1 - 6 + WHIR_LOG_INV_RATE),
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
        let (reduction, input) =
            super::prove_using(&witness.inputs, &output, &mut challenger, self.transcript)?;
        let (input_closing, input_point, input_value) =
            closing::prove(&witness.inputs, &input, &mut challenger);
        let (weights, value) = ports::claim(ports, self.direct_bridge, &mut challenger);
        let folded_input = closing::fold_states(&witness.inputs, &ports.instance[..self.log_batch]);
        let folded_output =
            closing::fold_states(&witness.outputs, &ports.instance[..self.log_batch]);
        let mut values = folded_input.clone();
        values.resize(POSITIONS, E::ZERO);
        values.extend_from_slice(&folded_output);
        values.resize(2 * POSITIONS, E::ZERO);
        let (port_closing, port_point, _) =
            closing::prove_functional(weights, values, value, &mut challenger);
        let link_input = closing::evaluate_folded(&folded_input, &port_point.as_slice()[1..]);
        let link_output = closing::evaluate_folded(&folded_output, &port_point.as_slice()[1..]);
        let link_point = link_point(&ports.instance[..self.log_batch], &port_point);
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
        let input = super::verify_using(
            &proof.reduction,
            &output,
            self.log_batch,
            &mut ch,
            self.transcript,
        )?;
        let input = closing::verify(&proof.input_closing, &input, &mut ch)?;
        let (weights, value) = ports::claim(ports, self.direct_bridge, &mut ch);
        let link = closing::verify_functional(&proof.port_closing, &weights, value, &mut ch)?;
        let selector = link.point.as_slice()[0];
        let link_point = link_point(&ports.instance[..self.log_batch], &link.point);
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

    /// The commitment has already entered `ch`; acceptance remains a circuit constraint.
    pub fn recursive_input<C>(
        &self,
        proof: &LinkedProof,
        ports: &PortOpening,
        ch: &mut C,
    ) -> Result<LinkedInput>
    where
        C: old_challenger::FieldChallenger<CF> + old_challenger::GrindingChallenger<Witness = CF>,
    {
        ensure!(
            matches!(self.transcript, Transcript::FixedV2),
            "recursive input requires the fixed transcript"
        );
        let mut ch = Bridge(ch);
        self.bind_ports(ports, &mut ch)?;
        let (mut output, output_point) = self.output_claim(&mut ch);
        output.value = proof.output;
        let input = super::verify_using(
            &proof.reduction,
            &output,
            self.log_batch,
            &mut ch,
            self.transcript,
        )?;
        let input = closing::verify(&proof.input_closing, &input, &mut ch)?;
        let (weights, value) = ports::claim(ports, self.direct_bridge, &mut ch);
        let link = closing::verify_functional(&proof.port_closing, &weights, value, &mut ch)?;
        let link_point = link_point(&ports.instance[..self.log_batch], &link.point);
        let mut private_values = recursive_values(
            self.log_batch,
            proof.output,
            &proof.reduction,
            &proof.input_closing,
        )?;
        private_values.extend(sumcheck_values(&proof.port_closing, POSITION_LOG + 1, 2)?);
        let points = [input.point, link_point.clone(), output_point, link_point].map(|point| {
            point
                .iter()
                .map(|v| CE::new(v.coefficients().map(|c| CF::new(c.to_bits()))))
                .collect()
        });
        Ok(LinkedInput {
            private_values,
            points,
            opening: recursive_opening(&proof.opening)?,
        })
    }

    pub fn recursive_pcs_seed(&self) -> Vec<CF> {
        deferred_seed(self.log_batch + POSITION_LOG + 1, 4)
    }

    pub fn arithmetic_seed(&self, authority: &[u8], statement: &Statement) -> Result<Vec<u8>> {
        ensure!(
            statement.log_batch as usize == self.log_batch,
            "incorrect boundary batch size"
        );
        if matches!(self.transcript, Transcript::PostcardV1) {
            return arithmetic_seed(authority, statement);
        }
        let mut hash = Keccak256::new();
        hash.update(port_domain(self.direct_bridge));
        hash.update((authority.len() as u64).to_le_bytes());
        hash.update(authority);
        hash.update((self.log_batch as u64).to_le_bytes());
        hash.update((statement.commitment.roots().len() as u64).to_le_bytes());
        for root in statement.commitment.roots() {
            hash.update(root);
        }
        Ok(hash.finalize().to_vec())
    }

    fn challenger(&self, authority: &[u8]) -> Challenger {
        challenger(&self.transcript_seed(authority))
    }

    pub fn transcript_seed(&self, authority: &[u8]) -> [u8; 32] {
        let mut hash = Keccak256::new();
        hash.update(match self.transcript {
            Transcript::PostcardV1 => DOMAIN,
            Transcript::FixedV2 => port_domain(self.direct_bridge),
        });
        hash.update((self.log_batch as u64).to_le_bytes());
        hash.update(authority);
        hash.finalize().into()
    }

    fn bind_ports<C: FieldChallenger<F>>(&self, ports: &PortOpening, ch: &mut C) -> Result<()> {
        ensure!(
            ports.instance.len() == self.log_batch + usize::from(self.direct_bridge)
                && ports.values.len()
                    == if self.direct_bridge {
                        ports::BRIDGE_LIMBS
                    } else {
                        ports::PORTS
                    },
            "incorrect native Keccak port opening shape"
        );
        if matches!(self.transcript, Transcript::FixedV2) {
            ch.observe_algebra_slice(&ports.instance);
            ch.observe_algebra_slice(&ports.values);
            return Ok(());
        }
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

/// The arithmetic transcript must use this seed, fixing the boundary commitment
/// before its own trace commitment and every row challenge used by the link.
pub(crate) fn arithmetic_seed(authority: &[u8], statement: &Statement) -> Result<Vec<u8>> {
    Ok(Keccak256::digest(postcard::to_allocvec(&(DOMAIN, authority, statement))?).to_vec())
}

fn link_point(batch_point: &[E], low: &Point<E>) -> Point<E> {
    let mut point = batch_point.to_vec();
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
    #[test]
    fn direct_bridge_rejects_false_limb_and_side_claims() {
        let batch = inputs(8);
        let scheme = LinkedBatch::with_bridge(3, 0.0, true).unwrap();
        let old = LinkedBatch::for_recursion(3, 0.0).unwrap();
        let witness = BoundaryWitness::new(batch.clone());
        let table = witness.ports();
        let pending = scheme.commit(witness, b"bridge").unwrap();
        let statement = pending.statement.clone();
        let mut ch = challenger(&scheme.arithmetic_seed(b"bridge", &statement).unwrap());
        let coordinates: Vec<E> = (0..4).map(|_| ch.sample_algebra_element()).collect();
        let point = Point::new(coordinates[..3].to_vec());
        let direction = coordinates[3];
        let value = |c| Poly::new(table.poly(c).as_slice().to_vec()).eval_base(&point);
        let ports = PortOpening {
            values: (0..116)
                .map(|limb| {
                    let (i, o) = if limb < 100 {
                        (limb, 100 + limb)
                    } else {
                        (100 + limb, 116 + limb)
                    };
                    let input = value(i);
                    input + direction * (value(o) - input)
                })
                .collect(),
            instance: coordinates,
        };
        let valid = scheme.prove(pending, &ports).unwrap();
        scheme
            .verify(&statement, &valid, b"bridge", &ports)
            .unwrap();
        assert!(old.verify(&statement, &valid, b"bridge", &ports).is_err());
        assert!(
            scheme.arithmetic_seed(b"bridge", &statement).unwrap()
                != old.arithmetic_seed(b"bridge", &statement).unwrap()
        );
        for mutation in 0..4 {
            let mut altered = ports.clone();
            match mutation {
                0 => altered.values[99] += E::ONE,
                1 => altered.values[115] += E::ONE,
                2 => altered.instance[0] += E::ONE,
                _ => altered.instance[3] += E::ONE,
            }
            let pending = scheme
                .commit(BoundaryWitness::new(batch.clone()), b"bridge")
                .unwrap();
            let forged = scheme.prove(pending, &altered).unwrap();
            assert!(
                scheme
                    .verify(&statement, &forged, b"bridge", &altered)
                    .is_err()
            );
        }
    }
}
