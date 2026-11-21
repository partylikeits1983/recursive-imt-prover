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
    pub(crate) packed_chi: bool,
    transcript: Transcript,
    pub(crate) pcs: Pcs,
    protocol: OpeningProtocol,
    pub conditional_algebraic_bits: f64,
    /// Additional cells committed outside the arithmetic PCS.
    pub initial_codeword_cells: usize,
}

pub struct BoundaryWitness {
    pub(crate) inputs: Vec<State>,
    pub(crate) outputs: Vec<State>,
}

pub struct Pending {
    pub statement: Statement,
    data: Data,
    witness: BoundaryWitness,
    challenger: Challenger,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct LinkedProof {
    claims: LinkedClaims,
    opening: Opening,
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct LinkedClaims {
    output: E,
    reduction: Proof,
    input_closing: closing::Proof,
    port_closing: closing::Proof,
}

#[cfg(feature = "opening-bench")]
impl LinkedClaims {
    pub(crate) fn closing_proofs(&self) -> [&closing::Proof; 2] {
        [&self.input_closing, &self.port_closing]
    }

    pub(crate) fn first_round(
        &self,
    ) -> (
        E,
        &p3_sumcheck::generic_degree::GenericDegreeProof<F, E>,
        [E; 3],
    ) {
        let layer = &self.reduction.layers[0];
        (self.output, &layer.sumcheck, layer.values)
    }
}

pub(crate) struct ProvedBoundaryOpenings {
    pub claims: LinkedClaims,
    pub coefficients: Vec<Vec<E>>,
    pub points: Vec<Point<E>>,
    pub hints: Vec<Option<OpeningBatch<E>>>,
    pub middle: Option<E>,
}

/// Created by the enclosing verifier from a fully authenticated AIR opening.
#[derive(Clone, Serialize, Deserialize)]
pub struct PortOpening {
    /// Direct bridge openings append the input/output selector to the batch point.
    pub instance: Vec<E>,
    pub values: Vec<E>,
}

impl BoundaryWitness {
    pub(crate) fn segment_inputs(&self) -> Vec<State> {
        use p3_maybe_rayon::prelude::*;
        let mut inputs = self.inputs.clone();
        inputs.par_extend(
            self.inputs
                .par_iter()
                .map(|s| super::packed::advance(*s, 0, 12)),
        );
        inputs
    }

    pub fn new(inputs: Vec<State>) -> Self {
        let outputs = inputs.iter().map(|&state| KeccakF.permute(state)).collect();
        Self { inputs, outputs }
    }

    pub(crate) fn pad(&mut self, len: usize, zero_output: State) {
        self.inputs.resize(len, [0; 25]);
        self.outputs.resize(len, zero_output);
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
            None,
            false,
            log_batch,
            main_candidate_log2,
            Transcript::FixedV2,
            direct_bridge,
        )
    }

    pub fn new(log_batch: usize, main_candidate_log2: f64) -> Result<Self> {
        Self::with_transcript(
            None,
            false,
            log_batch,
            main_candidate_log2,
            Transcript::PostcardV1,
            false,
        )
    }

    pub fn for_recursion(log_batch: usize, main_candidate_log2: f64) -> Result<Self> {
        Self::with_bridge(log_batch, main_candidate_log2, false)
    }

    pub(crate) fn joint(
        log_batch: usize,
        security: &p3_sumcheck::PrescribedOpeningSecurity,
        packed_chi: bool,
    ) -> Result<Self> {
        Self::with_transcript(
            Some(security),
            packed_chi,
            log_batch,
            security.log2_max_candidates,
            Transcript::FixedV2,
            true,
        )
    }

    /// Combined algebraic error before enforcing the linked verifier's acceptance margin.
    pub(crate) fn link_security(
        log_batch: usize,
        packed_chi: bool,
        main_candidate_log2: f64,
        mut security: p3_sumcheck::PrescribedOpeningSecurity,
    ) -> Result<f64> {
        ensure!(!packed_chi || log_batch >= 4, "packed chi needs 16 lanes");
        ensure!(
            main_candidate_log2.is_finite() && main_candidate_log2 >= 0.0,
            "invalid arithmetic candidate bound"
        );
        let degree = algebraic_error_degree(log_batch)?
            + if packed_chi {
                46 * super::ROUNDS + 2 * 4
            } else {
                0
            };
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
        // For a shared root the product bound also covers choosing the same
        // candidate for both roles. The PCS error is conservatively charged
        // again by the arithmetic security report.
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
        Ok(security.error().bits())
    }

    fn with_transcript(
        joint: Option<&p3_sumcheck::PrescribedOpeningSecurity>,
        packed_chi: bool,
        log_batch: usize,
        main_candidate_log2: f64,
        transcript: Transcript,
        direct_bridge: bool,
    ) -> Result<Self> {
        ensure!(
            !direct_bridge || log_batch >= 1,
            "bridge needs two template instances"
        );
        ensure!(
            !packed_chi || (joint.is_some() && log_batch >= 4),
            "packed chi requires a joint 16-lane batch"
        );
        let shape = TableShape::new(log_batch + POSITION_LOG, 1);
        let pcs = pcs(&[shape; 2], vec![TableEncoding::new(vec![1])?; 2])?;
        let protocol = OpeningProtocol::new(boundary_specs(log_batch));
        let security = match joint {
            Some(joint) => joint.clone(),
            None => pcs
                .prescribed_security(&protocol)
                .ok_or_else(|| anyhow::anyhow!("missing linked Keccak PCS evidence"))?,
        };
        let conditional_algebraic_bits =
            Self::link_security(log_batch, packed_chi, main_candidate_log2, security)?;
        ensure!(
            conditional_algebraic_bits >= 144.0,
            "linked Keccak margin below 144 bits"
        );
        Ok(Self {
            log_batch,
            direct_bridge,
            packed_chi,
            transcript,
            pcs,
            protocol,
            conditional_algebraic_bits,
            initial_codeword_cells: if joint.is_some() {
                0
            } else {
                1 << (log_batch + POSITION_LOG + 1 - 6 + WHIR_LOG_INV_RATE)
            },
        })
    }

    pub(crate) fn boundary_specs(&self) -> Vec<TableSpec> {
        boundary_specs(self.log_batch)
    }

    pub(crate) fn tables(&self, witness: &BoundaryWitness) -> Vec<Table<F>> {
        self.segment_tables(witness, &witness.inputs, false)
    }

    pub(crate) fn segment_tables(
        &self,
        witness: &BoundaryWitness,
        inputs: &[State],
        midpoint: bool,
    ) -> Vec<Table<F>> {
        vec![
            table(inputs, self.log_batch + usize::from(midpoint)),
            table(&witness.outputs, self.log_batch),
        ]
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
        let ProvedBoundaryOpenings {
            claims,
            points,
            hints,
            ..
        } = self.prove_claims(&witness, ports, &mut challenger)?;
        let opening =
            self.pcs
                .open_at_known(data, &self.protocol, &points, &hints, &mut challenger)?;
        Ok(LinkedProof { claims, opening })
    }

    pub(crate) fn prove_claims(
        &self,
        witness: &BoundaryWitness,
        ports: &PortOpening,
        challenger: &mut Challenger,
    ) -> Result<ProvedBoundaryOpenings> {
        self.prove_segments(witness, &witness.inputs, ports, challenger)
    }

    pub(crate) fn prove_segments(
        &self,
        witness: &BoundaryWitness,
        inputs: &[State],
        ports: &PortOpening,
        challenger: &mut Challenger,
    ) -> Result<ProvedBoundaryOpenings> {
        ensure!(
            witness.inputs.len() == 1 << self.log_batch
                && witness.outputs.len() == witness.inputs.len(),
            "incorrect boundary batch size"
        );
        self.bind_ports(ports, challenger)?;
        let (mut output, output_point) = self.output_claim(challenger);
        let n = witness.inputs.len();
        ensure!(
            inputs.len() == n || (self.packed_chi && inputs.len() == 2 * n),
            "incorrect input geometry"
        );
        let middle = (inputs.len() == 2 * n).then(|| {
            closing::fold_states(&inputs[n..], &output.instance)
                .iter()
                .zip(&output.weights)
                .map(|(&b, &w)| b * w)
                .sum()
        });
        output.value = closing::fold_states(&witness.outputs, &output.instance)
            .iter()
            .zip(&output.weights)
            .map(|(&a, &b)| a * b)
            .sum();
        let (reduction, coefficients, input_closing, input_point, input_value) = if self.packed_chi
        {
            super::packed::linked::prove(inputs, &output, middle, challenger)?
        } else {
            let (reduction, input) =
                super::prove_using(&witness.inputs, &output, challenger, self.transcript)?;
            let (input_closing, input_point, input_value) =
                closing::prove(&witness.inputs, &input, challenger);
            (reduction, vec![], input_closing, input_point, input_value)
        };
        let (weights, value) = ports::claim(ports, self.direct_bridge, challenger);
        let folded_input = closing::fold_states(&witness.inputs, &ports.instance[..self.log_batch]);
        let folded_output =
            closing::fold_states(&witness.outputs, &ports.instance[..self.log_batch]);
        let mut values = folded_input.clone();
        values.resize(POSITIONS, E::ZERO);
        values.extend_from_slice(&folded_output);
        values.resize(2 * POSITIONS, E::ZERO);
        let (port_closing, port_point, _) =
            closing::prove_functional(weights, values, value, challenger);
        let link_input = closing::evaluate_folded(&folded_input, &port_point.as_slice()[1..]);
        let link_output = closing::evaluate_folded(&folded_output, &port_point.as_slice()[1..]);
        let link_point = link_point(&ports.instance[..self.log_batch], &port_point);
        let mut points = vec![input_point];
        let mut values = vec![input_value, link_input];
        if let Some(mid) = middle {
            points.push(segment_point(E::ZERO, &link_point));
            points.push(segment_point(E::ONE, &output_point));
            values.push(mid);
        } else {
            points.push(link_point.clone());
        }
        points.extend([output_point, link_point]);
        values.extend([output.value, link_output]);
        Ok(ProvedBoundaryOpenings {
            claims: LinkedClaims {
                output: output.value,
                reduction,
                input_closing,
                port_closing,
            },
            coefficients,
            points,
            middle,
            hints: values
                .into_iter()
                .map(|v| Some(OpeningBatch::new(vec![v], vec![])))
                .collect(),
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
        let reduced = self.reduce_claims(&proof.claims, &[], ports, &mut ch)?;
        let evals = self.pcs.verify_at(
            &statement.commitment,
            &proof.opening,
            &self.protocol,
            &reduced.points,
            &mut ch,
        )?;
        reduced.authenticate(&evals)
    }

    pub(crate) fn reduce_claims<
        C: FieldChallenger<F> + p3_challenger::GrindingChallenger<Witness = F>,
    >(
        &self,
        proof: &LinkedClaims,
        coefficients: &[Vec<E>],
        ports: &PortOpening,
        ch: &mut C,
    ) -> Result<LinkedOpenings> {
        self.reduce_segments(proof, coefficients, ports, None, ch)
    }

    pub(crate) fn reduce_segments<
        C: FieldChallenger<F> + p3_challenger::GrindingChallenger<Witness = F>,
    >(
        &self,
        proof: &LinkedClaims,
        coefficients: &[Vec<E>],
        ports: &PortOpening,
        middle: Option<E>,
        ch: &mut C,
    ) -> Result<LinkedOpenings> {
        ensure!(
            middle.is_none() || self.packed_chi,
            "midpoint requires packed Keccak"
        );
        self.bind_ports(ports, ch)?;
        let (mut output, output_point) = self.output_claim(ch);
        output.value = proof.output;
        let input = if self.packed_chi {
            super::packed::linked::verify(
                &proof.reduction,
                coefficients,
                &proof.input_closing,
                &output,
                middle,
                ch,
            )?
        } else {
            let input = super::verify_using(
                &proof.reduction,
                &output,
                self.log_batch,
                ch,
                self.transcript,
            )?;
            closing::verify(&proof.input_closing, &input, ch)?
        };
        let (weights, value) = ports::claim(ports, self.direct_bridge, ch);
        let link = closing::verify_functional(&proof.port_closing, &weights, value, ch)?;
        let selector = link.point.as_slice()[0];
        let link_point = link_point(&ports.instance[..self.log_batch], &link.point);
        let mut points = vec![input.point.clone()];
        if middle.is_some() {
            points.extend([
                segment_point(E::ZERO, &link_point),
                segment_point(E::ONE, &output_point),
            ]);
        } else {
            points.push(link_point.clone());
        }
        points.extend([output_point, link_point]);
        Ok(LinkedOpenings {
            points,
            input,
            link,
            selector,
            output: output.value,
            middle,
        })
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
        let (private_values, points) = self.import_claims(&proof.claims, &[], ports, ch)?;
        Ok(LinkedInput {
            private_values,
            points,
            opening: recursive_opening(&proof.opening)?,
        })
    }

    pub(crate) fn import_claims<C>(
        &self,
        proof: &LinkedClaims,
        coefficients: &[Vec<E>],
        ports: &PortOpening,
        ch: &mut C,
    ) -> Result<(Vec<CF>, [Vec<CE>; 4])>
    where
        C: old_challenger::FieldChallenger<CF> + old_challenger::GrindingChallenger<Witness = CF>,
    {
        ensure!(
            matches!(self.transcript, Transcript::FixedV2),
            "recursive input requires the fixed transcript"
        );
        let reduced = self.reduce_claims(proof, coefficients, ports, &mut Bridge(ch))?;
        let mut private_values = if self.packed_chi {
            let mut values = proof
                .output
                .coefficients()
                .map(|c| CF::new(c.to_bits()))
                .to_vec();
            for (layer, coeff) in proof.reduction.layers.iter().zip(coefficients) {
                for v in coeff {
                    values.extend(v.coefficients().map(|c| CF::new(c.to_bits())));
                }
                values.extend(sumcheck_values(
                    &layer.sumcheck,
                    self.log_batch - 4 + POSITION_LOG,
                    3,
                )?);
                for v in layer.values {
                    values.extend(v.coefficients().map(|c| CF::new(c.to_bits())));
                }
            }
            values.extend(sumcheck_values(&proof.input_closing, POSITION_LOG + 4, 2)?);
            values
        } else {
            recursive_values(
                self.log_batch,
                proof.output,
                &proof.reduction,
                &proof.input_closing,
            )?
        };
        private_values.extend(sumcheck_values(&proof.port_closing, POSITION_LOG + 1, 2)?);
        let points = reduced
            .points
            .iter()
            .map(|point| {
                point
                    .iter()
                    .map(|v| CE::new(v.coefficients().map(|c| CF::new(c.to_bits()))))
                    .collect()
            })
            .collect::<Vec<_>>()
            .try_into()
            .map_err(|_| anyhow::anyhow!("expected four boundary points"))?;
        Ok((private_values, points))
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

pub(crate) fn boundary_specs(log_batch: usize) -> Vec<TableSpec> {
    let shape = TableShape::new(log_batch + POSITION_LOG, 1);
    vec![TableSpec::new(shape, vec![OpeningBatch::new(vec![0], vec![]); 2]); 2]
}

pub(crate) fn midpoint_specs(bits: usize) -> Vec<TableSpec> {
    [(bits + 1, 3), (bits, 2)]
        .into_iter()
        .map(|(height, batches)| {
            TableSpec::new(
                TableShape::new(height, 1),
                vec![OpeningBatch::new(vec![0], vec![]); batches],
            )
        })
        .collect()
}

fn segment_point(segment: E, row: &Point<E>) -> Point<E> {
    let mut coordinates = vec![segment];
    coordinates.extend(row.as_slice());
    Point::new(coordinates)
}

pub(crate) struct LinkedOpenings {
    pub points: Vec<Point<E>>,
    input: closing::Closing,
    link: closing::Closing,
    selector: E,
    output: E,
    middle: Option<E>,
}

impl LinkedOpenings {
    pub(crate) fn authenticate(&self, evals: &[OpeningBatch<E>]) -> Result<()> {
        let output = 2 + usize::from(self.middle.is_some());
        ensure!(
            evals.len() == output + 2 && evals.iter().all(|e| e.current().len() == 1),
            "incorrect boundary opening count"
        );
        ensure!(
            evals[output].current()[0] == self.output,
            "incorrect Keccak output"
        );
        ensure!(
            self.input.product == self.input.weight * evals[0].current()[0],
            "incorrect Keccak input"
        );
        let a = evals[1].current()[0];
        if let Some(middle) = self.middle {
            ensure!(evals[2].current()[0] == middle, "incorrect Keccak midpoint");
        }
        let b = evals[output + 1].current()[0];
        ensure!(
            self.link.product == self.link.weight * (a + self.selector * (b - a)),
            "native Keccak ports do not match committed boundaries"
        );
        Ok(())
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
    fn linked_midpoint_binds_both_segments_and_all_boundary_readings() {
        use p3_sumcheck::{OpeningBatch, PrescribedPointPcs};
        let base = LinkedBatch::with_bridge(4, 0.0, true).unwrap();
        let security = base.pcs.prescribed_security(&base.protocol).unwrap();
        let scheme = LinkedBatch::joint(4, &security, true).unwrap();
        let witness = BoundaryWitness::new(inputs(16));
        let segments = witness.segment_inputs();
        let table = witness.ports();
        let mut source = challenger(b"midpoint arithmetic row");
        let row = Point::new(
            (0..4)
                .map(|_| source.sample_algebra_element::<E>())
                .collect::<Vec<_>>(),
        );
        let side: E = source.sample_algebra_element();
        let eval = |c| Poly::new(table.poly(c).as_slice().to_vec()).eval_base(&row);
        let ports = PortOpening {
            instance: [row.as_slice(), &[side]].concat(),
            values: (0..116)
                .map(|limb| {
                    let (i, o) = if limb < 100 {
                        (limb, 100 + limb)
                    } else {
                        (100 + limb, 116 + limb)
                    };
                    eval(i) + side * (eval(o) - eval(i))
                })
                .collect(),
        };
        let fresh = || challenger(b"linked midpoint regression");
        let proved = scheme
            .prove_segments(&witness, &segments, &ports, &mut fresh())
            .unwrap();
        let reduce = |middle| {
            scheme.reduce_segments(
                &proved.claims,
                &proved.coefficients,
                &ports,
                middle,
                &mut fresh(),
            )
        };
        let verified = reduce(proved.middle).unwrap();
        assert_eq!(verified.points, proved.points);
        assert_eq!(proved.claims.reduction.layers.len(), 12);
        let evals: Vec<_> = verified
            .points
            .iter()
            .enumerate()
            .map(|(i, p)| {
                let (states, rows) = if i < 3 {
                    (&segments[..], 5)
                } else {
                    (&witness.outputs[..], 4)
                };
                let folded = super::closing::fold_states(states, &p.as_slice()[..rows]);
                OpeningBatch::new(
                    vec![super::closing::evaluate_folded(
                        &folded,
                        &p.as_slice()[rows..],
                    )],
                    vec![],
                )
            })
            .collect();
        verified.authenticate(&evals).unwrap();
        for i in 0..5 {
            let mut changed = evals.clone();
            changed[i] = OpeningBatch::new(vec![changed[i].current()[0] + E::ONE], vec![]);
            assert!(verified.authenticate(&changed).is_err());
        }
        assert!(reduce(proved.middle.map(|v| v + E::ONE)).is_err());
        assert!(reduce(None).is_err());
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
