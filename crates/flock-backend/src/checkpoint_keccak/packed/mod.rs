//! Experimental authenticated Keccak component. The bit-input and word-output
//! tables can be opened together, including an optional round-12 checkpoint.
pub(super) mod circuit;
pub(super) mod linked;
pub(in crate::checkpoint_keccak) mod maps;
#[cfg(feature = "opening-bench")]
mod recursive;
mod reduction;
pub(super) mod rows;

use anyhow::{Result, ensure};
use p3_binary_field::TowerLevel;
use p3_challenger::{CanObserve, FieldChallenger, GrindingChallenger};
use p3_commit::MultilinearPcs;
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use p3_maybe_rayon::prelude::*;
use p3_multilinear_util::point::Point;
use p3_security::{CandidateSet, ErrorBits, SecurityTerm};
use p3_sumcheck::{
    OpeningBatch, OpeningProtocol, PrescribedPointPcs, TableShape, TableSpec,
    generic_degree::RoundProver, layout::Table,
};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use std::time::{Duration, Instant};

use super::{
    BITS, Claim, E, F, LayerProof, MAX_BATCH_LOG, POSITION_LOG, POSITIONS, State, bind_values,
    closing, committed, linear, previous_claim, rounds::ChiSumcheck,
};
use crate::{
    config::{Challenger, Pcs, challenger, pcs},
    encoding::TableEncoding,
};
use reduction::PackedClaim;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kernel {
    Scalar,
    Packed16,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Openings {
    Separate,
    Joint,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Schedule {
    OneRound,
    Full,
    Midpoint,
}

impl Schedule {
    fn depth(self) -> usize {
        match self {
            Schedule::OneRound => 1,
            Schedule::Full => 24,
            Schedule::Midpoint => 12,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct Statement {
    commitments: Vec<committed::Commitment>,
}

#[derive(Serialize, Deserialize)]
enum Layer {
    Scalar(LayerProof),
    Packed(reduction::Layer),
}

#[derive(Serialize, Deserialize)]
pub struct Proof {
    output: [E; 25],
    midpoint: Option<closing::Proof>,
    layers: Vec<Layer>,
    closing: closing::Proof,
    openings: Vec<committed::Opening>,
}

#[derive(Debug, Default)]
pub struct Timings {
    pub commit: Duration,
    pub reduction: Duration,
    pub opening: Duration,
}

type BoundaryClaims = (Vec<Point<E>>, Vec<(E, E)>);

pub struct Batch {
    log: usize,
    schedule: Schedule,
    kernel: Kernel,
    mode: Openings,
    groups: Vec<(Pcs, OpeningProtocol)>,
    pub conditional_algebraic_bits: f64,
}

impl Batch {
    pub fn new(log: usize, schedule: Schedule, kernel: Kernel, mode: Openings) -> Result<Self> {
        ensure!(
            (4..=MAX_BATCH_LOG).contains(&log),
            "expected at least one 16-way pack"
        );
        let midpoint = schedule == Schedule::Midpoint;
        let shapes = [
            TableShape::new(log + usize::from(midpoint) + POSITION_LOG, 1),
            TableShape::new(log, 25),
        ];
        let encodings = [
            TableEncoding::new(vec![1])?,
            TableEncoding::with_word_openings(vec![64; 25], true)?,
        ];
        let specs = [
            TableSpec::new(
                shapes[0],
                vec![OpeningBatch::new(vec![0], vec![]); 1 + usize::from(midpoint)],
            ),
            TableSpec::new(
                shapes[1],
                vec![OpeningBatch::new((0..25).collect(), vec![])],
            ),
        ];
        let group_size = if mode == Openings::Joint { 2 } else { 1 };
        let mut groups = Vec::new();
        let mut errors = Vec::new();
        let mut log_candidates = 0.0;
        for ((shapes, encodings), specs) in shapes
            .chunks(group_size)
            .zip(encodings.chunks(group_size))
            .zip(specs.chunks(group_size))
        {
            let pcs = pcs(shapes, encodings.to_vec())?;
            let protocol = OpeningProtocol::new(specs.to_vec());
            let security = pcs
                .prescribed_security(&protocol)
                .ok_or_else(|| anyhow::anyhow!("missing WHIR security evidence"))?;
            ensure!(
                security.candidates().is_some(),
                "invalid WHIR candidate bound"
            );
            errors.push(security.error());
            log_candidates += security.log2_max_candidates;
            groups.push((pcs, protocol));
        }
        let candidates = CandidateSet::from_log2(log_candidates)
            .ok_or_else(|| anyhow::anyhow!("invalid joint candidate bound"))?;
        let packed = kernel == Kernel::Packed16;
        let depth = schedule.depth();
        let instance_log = log - 4 * usize::from(packed) + usize::from(midpoint);
        // Output row and lane batching, optional midpoint closing and segment
        // batching, cubic sumchecks, 3-to-1 terminal batching, input closing.
        // The packed product additionally costs 46 per random polynomial check.
        let closing_log = POSITION_LOG + 4 * usize::from(packed);
        let degree = log
            + 5
            + usize::from(midpoint) * (2 * POSITION_LOG + 1)
            + depth * (3 * (instance_log + POSITION_LOG) + 2 + 46 * usize::from(packed))
            + 2 * closing_log;
        errors.push(
            SecurityTerm::new(
                "Keccak boundary and layer reductions",
                ErrorBits::from_numerator(192, degree as u128),
            )
            .over_candidates(candidates)
            .bits,
        );
        let conditional_algebraic_bits = ErrorBits::sum(&errors).bits();
        ensure!(
            conditional_algebraic_bits >= 144.0,
            "insufficient conditional algebraic margin"
        );
        Ok(Self {
            log,
            schedule,
            kernel,
            mode,
            groups,
            conditional_algebraic_bits,
        })
    }

    fn seed(&self, context: &[u8]) -> [u8; 32] {
        let mut hash = Keccak256::new();
        hash.update(b"imt-packed-keccak-mixed-whir-v1");
        hash.update([
            self.log as u8,
            self.schedule.depth() as u8,
            u8::from(self.kernel == Kernel::Packed16),
            u8::from(self.mode == Openings::Joint),
        ]);
        hash.update(context);
        hash.finalize().into()
    }

    fn output_claim(
        &self,
        row: &Point<E>,
        output: &[E; 25],
        ch: &mut impl FieldChallenger<F>,
    ) -> PackedClaim {
        ch.observe_algebra_slice(output);
        let lanes = sample_point(5, ch).equality_weights_msb();
        let weights = (0..BITS)
            .map(|j| lanes[j / 64] * F::from_repr(1 << (j % 64)))
            .collect();
        let value = output.iter().zip(lanes).map(|(&v, w)| v * w).sum();
        let mut instance = row.as_slice().to_vec();
        let mut lanes = [E::ZERO; 16];
        lanes[0] = E::ONE;
        if self.kernel == Kernel::Packed16 {
            lanes.copy_from_slice(
                &Point::new(instance.split_off(self.log - 4)).equality_weights_msb(),
            );
        }
        PackedClaim {
            claim: Claim {
                instance,
                weights,
                value,
            },
            lanes,
        }
    }

    pub fn prove(&self, inputs: &[State], context: &[u8]) -> Result<(Statement, Proof, Timings)> {
        ensure!(inputs.len() == 1 << self.log, "incorrect Keccak batch size");
        let start = Instant::now();
        let split = self.schedule == Schedule::Midpoint;
        let mut boundaries = inputs.to_vec();
        if split {
            boundaries.extend(
                inputs
                    .par_iter()
                    .map(|s| advance(*s, 0, 12))
                    .collect::<Vec<_>>(),
            );
        }
        let last = &boundaries[boundaries.len() - inputs.len()..];
        let start_round = if split { 12 } else { 0 };
        let outputs: Vec<_> = last
            .par_iter()
            .map(|s| advance(*s, start_round, start_round + self.schedule.depth()))
            .collect();
        self.prove_boundaries(&boundaries, &outputs, context, start)
    }

    fn prove_boundaries(
        &self,
        boundaries: &[State],
        outputs: &[State],
        context: &[u8],
        start: Instant,
    ) -> Result<(Statement, Proof, Timings)> {
        let split = self.schedule == Schedule::Midpoint;
        let n = 1 << self.log;
        let words = (0..25)
            .flat_map(|lane| outputs.iter().map(move |state| F::from_repr(state[lane])))
            .collect();
        let tables = [
            committed::table(boundaries, self.log + usize::from(split)),
            Table::new(RowMajorMatrix::new(words, n)),
        ];
        let mut tables = tables.into_iter();
        let mut ch = challenger(&self.seed(context));
        let mut commitments = Vec::new();
        let mut data = Vec::new();
        for (pcs, protocol) in &self.groups {
            let (root, d) = pcs.commit(
                tables
                    .by_ref()
                    .take(protocol.table_shapes().len())
                    .collect(),
                &mut ch,
            )?;
            commitments.push(root);
            data.push(d);
        }
        let commit = start.elapsed();
        let start = Instant::now();
        let row = sample_point(self.log, &mut ch);
        let eq = row.equality_weights_msb();
        let output = core::array::from_fn(|lane| {
            outputs
                .iter()
                .zip(&eq)
                .map(|(s, &w)| w * F::from_repr(s[lane]))
                .sum()
        });
        let mut claim = self.output_claim(&row, &output, &mut ch);
        let mut points = Vec::new();
        let mut known = Vec::new();
        let midpoint = if split {
            let mut bits = closing::fold_states(&boundaries[n..], row.as_slice());
            let value = bits
                .iter()
                .zip(&claim.claim.weights)
                .map(|(&b, &w)| b * w)
                .sum();
            bits.resize(POSITIONS, E::ZERO);
            let mut weights = claim.claim.weights.clone();
            weights.resize(POSITIONS, E::ZERO);
            let (proof, pos, bit) = closing::prove_functional(weights, bits, value, &mut ch);
            points.push(midpoint_point(&row, pos));
            known.push(Some(OpeningBatch::new(vec![bit], vec![])));
            merge_midpoint(&mut claim, value, &mut ch);
            Some(proof)
        } else {
            None
        };
        let stride = if self.kernel == Kernel::Packed16 {
            6
        } else {
            12
        };
        let checkpoints = Checkpoints::new(
            boundaries,
            self.schedule.depth(),
            stride,
            if split { n } else { boundaries.len() },
        );
        let mut layers = Vec::with_capacity(self.schedule.depth());
        for round in (0..self.schedule.depth()).rev() {
            ch.observe(F::from_repr(round as u64));
            let (states, before_chi) = checkpoints.before_chi(round);
            let (layer, next) = match self.kernel {
                Kernel::Packed16 => {
                    let (proof, next) = reduction::prove(
                        states,
                        |group, s| before_chi(group * 16, s),
                        &claim,
                        &mut ch,
                    );
                    (Layer::Packed(proof), next)
                }
                Kernel::Scalar => {
                    let instance = &claim.claim.instance;
                    let before = states
                        .par_iter()
                        .enumerate()
                        .map(|(i, &s)| before_chi(i, s))
                        .collect();
                    let mut sc = ChiSumcheck::new(before, instance, claim.claim.weights.clone());
                    let sum = claim.claim.value + self.constant(&claim, round);
                    let (sumcheck, point) =
                        sc.prove::<F, _>(&mut ch, instance.len() + POSITION_LOG, 3, 0, sum);
                    let values = sc.terminal();
                    let next = previous_claim(
                        point.as_slice(),
                        values,
                        bind_values(values, &mut ch),
                        instance.len(),
                    );
                    (
                        Layer::Scalar(LayerProof { sumcheck, values }),
                        PackedClaim {
                            claim: next,
                            lanes: claim.lanes,
                        },
                    )
                }
            };
            layers.push(layer);
            claim = next;
        }
        let (closing, point, bit) = match self.kernel {
            Kernel::Scalar => closing::prove(boundaries, &claim.claim, &mut ch),
            Kernel::Packed16 => packed_closing(boundaries, &claim, &mut ch),
        };
        points.push(point);
        points.push(row);
        known.push(Some(OpeningBatch::new(vec![bit], vec![])));
        known.push(Some(OpeningBatch::new(output.to_vec(), vec![])));
        let reduction = start.elapsed();
        let start = Instant::now();
        let mut openings = Vec::new();
        let mut index = 0;
        for ((pcs, protocol), d) in self.groups.iter().zip(data) {
            let end = index + protocol.num_openings();
            openings.push(pcs.open_at_known(
                d,
                protocol,
                &points[index..end],
                &known[index..end],
                &mut ch,
            )?);
            index = end;
        }
        Ok((
            Statement { commitments },
            Proof {
                output,
                midpoint,
                layers,
                closing,
                openings,
            },
            Timings {
                commit,
                reduction,
                opening: start.elapsed(),
            },
        ))
    }

    fn constant(&self, claim: &PackedClaim, round: usize) -> E {
        let first = reduction::iota(claim, round);
        if self.schedule == Schedule::Midpoint {
            first + claim.claim.instance[0] * (first + reduction::iota(claim, round + 12))
        } else {
            first
        }
    }

    pub fn verify(&self, statement: &Statement, proof: &Proof, context: &[u8]) -> Result<()> {
        ensure!(
            statement.commitments.len() == self.groups.len()
                && proof.openings.len() == self.groups.len(),
            "incorrect WHIR group count"
        );
        ensure!(
            proof.layers.len() == self.schedule.depth()
                && proof.midpoint.is_some() == (self.schedule == Schedule::Midpoint),
            "incorrect round schedule"
        );
        let mut ch = challenger(&self.seed(context));
        for ((pcs, _), root) in self.groups.iter().zip(&statement.commitments) {
            pcs.observe_commitment(root, &mut ch);
        }
        let (points, products) = self.reduce(proof, &mut ch)?;
        let mut evals = Vec::new();
        for (((pcs, protocol), root), opening) in self
            .groups
            .iter()
            .zip(&statement.commitments)
            .zip(&proof.openings)
        {
            let index = evals.len();
            let result = pcs.verify_at(
                root,
                opening,
                protocol,
                &points[index..index + protocol.num_openings()],
                &mut ch,
            )?;
            ensure!(
                result.len() == protocol.num_openings(),
                "incorrect opening count"
            );
            evals.extend(result);
        }
        for ((weight, product), eval) in products.into_iter().zip(&evals) {
            ensure!(
                eval.current().len() == 1 && eval.current()[0] * weight == product,
                "incorrect Boolean boundary"
            );
        }
        ensure!(
            evals.last().unwrap().current() == proof.output,
            "incorrect arithmetic output"
        );
        Ok(())
    }
    pub(crate) fn reduce<C: FieldChallenger<F> + GrindingChallenger<Witness = F>>(
        &self,
        proof: &Proof,
        ch: &mut C,
    ) -> Result<BoundaryClaims> {
        let row = sample_point(self.log, ch);
        let mut claim = self.output_claim(&row, &proof.output, ch);
        let mut points = Vec::new();
        let mut products = Vec::new();
        if let Some(mid) = &proof.midpoint {
            let closing =
                closing::verify_functional(mid, &claim.claim.weights, mid.claimed_sum, ch)?;
            points.push(midpoint_point(&row, closing.point));
            products.push((closing.weight, closing.product));
            merge_midpoint(&mut claim, mid.claimed_sum, ch);
        }
        for (round, layer) in (0..self.schedule.depth()).rev().zip(&proof.layers) {
            ch.observe(F::from_repr(round as u64));
            let constant = self.constant(&claim, round);
            claim = match (self.kernel, layer) {
                (Kernel::Packed16, Layer::Packed(p)) => reduction::verify(p, &claim, constant, ch)?,
                (Kernel::Scalar, Layer::Scalar(p)) => {
                    ensure!(
                        p.sumcheck.claimed_sum == claim.claim.value + constant,
                        "incorrect scalar chi claim"
                    );
                    let instance = &claim.claim.instance;
                    let (point, end) =
                        p.sumcheck.verify(ch, instance.len() + POSITION_LOG, 3, 0)?;
                    let (r, z) = point.as_slice().split_at(instance.len());
                    let [a, b, c] = p.values;
                    ensure!(
                        end == Point::eval_eq(instance, r)
                            * closing::evaluate_folded(&claim.claim.weights, z)
                            * (a + c + b * c),
                        "incorrect scalar chi endpoint"
                    );
                    let next = previous_claim(
                        point.as_slice(),
                        p.values,
                        bind_values(p.values, ch),
                        instance.len(),
                    );
                    PackedClaim {
                        claim: next,
                        lanes: claim.lanes,
                    }
                }
                _ => anyhow::bail!("incorrect chi kernel"),
            };
        }
        let final_claim = match self.kernel {
            Kernel::Scalar => closing::verify(&proof.closing, &claim.claim, ch)?,
            Kernel::Packed16 => {
                ensure!(
                    proof.closing.claimed_sum == claim.claim.value,
                    "incorrect packed input claim"
                );
                let (pos, product) = proof.closing.verify(ch, POSITION_LOG + 4, 2, 0)?;
                let (i, z) = pos.as_slice().split_at(4);
                let weight = closing::evaluate_folded(&claim.lanes, i)
                    * closing::evaluate_folded(&claim.claim.weights, z);
                let mut point = claim.claim.instance;
                point.extend_from_slice(pos.as_slice());
                closing::Closing {
                    point: Point::new(point),
                    weight,
                    product,
                }
            }
        };
        points.push(final_claim.point);
        products.push((final_claim.weight, final_claim.product));
        points.push(row);
        Ok((points, products))
    }
}

fn sample_point(n: usize, ch: &mut impl FieldChallenger<F>) -> Point<E> {
    Point::new(
        (0..n)
            .map(|_| ch.sample_algebra_element::<E>())
            .collect::<Vec<_>>(),
    )
}

// Each chunk of sixteen states is transformed and transposed while it is hot.
// Snapshots bound forward replay even though the sumchecks visit rounds backwards.
struct Checkpoints<'a> {
    initial: &'a [State],
    snapshots: Vec<Vec<State>>,
    stride: usize,
    segment_rows: usize,
}

impl<'a> Checkpoints<'a> {
    fn new(initial: &'a [State], depth: usize, stride: usize, segment_rows: usize) -> Self {
        let mut snapshots: Vec<Vec<State>> = Vec::new();
        for round in (stride..depth).step_by(stride) {
            let previous = snapshots.last().map_or(initial, Vec::as_slice);
            let next = previous
                .par_iter()
                .enumerate()
                .map(|(i, &s)| {
                    let offset = if i >= segment_rows { 12 } else { 0 };
                    advance(s, offset + round - stride, offset + round)
                })
                .collect();
            snapshots.push(next);
        }
        Self {
            initial,
            snapshots,
            stride,
            segment_rows,
        }
    }

    fn before_chi(&self, round: usize) -> (&[State], impl Fn(usize, State) -> State + Sync) {
        let block = round / self.stride;
        let states = if block == 0 {
            self.initial
        } else {
            self.snapshots[block - 1].as_slice()
        };
        (states, move |i, s| {
            let offset = if i >= self.segment_rows { 12 } else { 0 };
            linear::forward(&advance(s, offset + block * self.stride, offset + round))
        })
    }
}

fn advance(mut state: State, start: usize, end: usize) -> State {
    for round in start..end {
        state = linear::finish_round(&linear::forward(&state), round);
    }
    state
}

fn midpoint_point(row: &Point<E>, position: Point<E>) -> Point<E> {
    let mut point = vec![E::ONE];
    point.extend_from_slice(row.as_slice());
    point.extend_from_slice(position.as_slice());
    Point::new(point)
}

fn merge_midpoint(claim: &mut PackedClaim, middle: E, ch: &mut impl FieldChallenger<F>) {
    ch.observe_algebra_element(middle);
    let segment: E = ch.sample_algebra_element();
    claim.claim.instance.insert(0, segment);
    claim.claim.value = middle + segment * (middle + claim.claim.value);
}

fn packed_closing(
    states: &[State],
    current: &PackedClaim,
    ch: &mut Challenger,
) -> (closing::Proof, Point<E>, E) {
    let mut weights = Vec::with_capacity(16 * POSITIONS);
    let mut values = Vec::with_capacity(16 * POSITIONS);
    for (i, &lane) in current.lanes.iter().enumerate() {
        let column: Vec<_> = states
            .as_chunks::<16>()
            .0
            .iter()
            .map(|pack| pack[i])
            .collect();
        values.extend(closing::fold_states(&column, &current.claim.instance));
        values.resize((i + 1) * POSITIONS, E::ZERO);
        weights.extend(current.claim.weights.iter().map(|&w| w * lane));
        weights.resize((i + 1) * POSITIONS, E::ZERO);
    }
    let (proof, pos, bit) = closing::prove_functional(weights, values, current.claim.value, ch);
    let mut point = current.claim.instance.clone();
    point.extend_from_slice(pos.as_slice());
    (proof, Point::new(point), bit)
}

impl Proof {
    /// Poly192 values serialized outside the WHIR opening(s), including running sums.
    pub fn reduction_scalars(&self) -> usize {
        let sc = |p: &closing::Proof| 1 + p.round_polys.iter().map(Vec::len).sum::<usize>();
        self.output.len()
            + self.midpoint.as_ref().map_or(0, sc)
            + sc(&self.closing)
            + self
                .layers
                .iter()
                .map(|l| match l {
                    Layer::Scalar(p) => sc(&p.sumcheck) + p.values.len(),
                    Layer::Packed(p) => p.scalar_count(),
                })
                .sum::<usize>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_keccak::KeccakF;
    use p3_symmetric::Permutation;
    fn states(n: usize) -> Vec<State> {
        (0..n)
            .map(|i| {
                core::array::from_fn(|j| {
                    ((i * 25 + j + 1) as u64)
                        .wrapping_mul(0x9e3779b97f4a7c15)
                        .rotate_left(j as u32)
                })
            })
            .collect()
    }

    #[test]
    fn both_kernels_and_opening_modes() -> Result<()> {
        for (log, schedule, kernel, mode) in [
            (4, Schedule::OneRound, Kernel::Packed16, Openings::Separate),
            (5, Schedule::OneRound, Kernel::Packed16, Openings::Joint),
            (5, Schedule::Full, Kernel::Packed16, Openings::Joint),
            (4, Schedule::Midpoint, Kernel::Packed16, Openings::Joint),
            (5, Schedule::Midpoint, Kernel::Scalar, Openings::Separate),
        ] {
            let batch = Batch::new(log, schedule, kernel, mode)?;
            let (statement, mut proof, _) = batch.prove(&states(1 << log), b"test")?;
            batch.verify(&statement, &proof, b"test")?;
            assert!(batch.verify(&statement, &proof, b"wrong context").is_err());
            proof.output[24] += E::ONE;
            assert!(batch.verify(&statement, &proof, b"test").is_err());
            proof.output[24] += E::ONE;
            proof.openings.pop();
            assert!(batch.verify(&statement, &proof, b"test").is_err());
        }
        Ok(())
    }

    #[cfg(feature = "opening-bench")]
    #[test]
    fn recursive_verifier_authenticates_packed_segments() -> Result<()> {
        let batch = Batch::new(5, Schedule::Midpoint, Kernel::Packed16, Openings::Joint)?;
        let (statement, proof, _) = batch.prove(&states(32), b"recursive")?;
        let cost = batch.recursive_cost(&statement, &proof, b"recursive")?;
        assert!(cost.keccak_permutations > 0);
        Ok(())
    }

    #[test]
    fn reject_inconsistent_committed_boundaries() -> Result<()> {
        let batch = Batch::new(4, Schedule::Midpoint, Kernel::Packed16, Openings::Joint)?;
        let input = states(16);
        let middle: Vec<_> = input.iter().map(|s| advance(*s, 0, 12)).collect();
        let mut boundaries = input.clone();
        boundaries.extend(middle);
        let mut output: Vec<_> = input.iter().map(|&s| KeccakF.permute(s)).collect();
        let (statement, proof, _) =
            batch.prove_boundaries(&boundaries, &output, b"test", Instant::now())?;
        batch.verify(&statement, &proof, b"test")?;
        // Change each witness before commitment, then run the honest prover
        // against that false relation. Both openings match their own tables.
        output[15][24] ^= 1 << 63;
        let (statement, proof, _) =
            batch.prove_boundaries(&boundaries, &output, b"test", Instant::now())?;
        assert!(batch.verify(&statement, &proof, b"test").is_err());
        output[15][24] ^= 1 << 63;
        boundaries[16][0] ^= 1;
        let (statement, proof, _) =
            batch.prove_boundaries(&boundaries, &output, b"test", Instant::now())?;
        assert!(batch.verify(&statement, &proof, b"test").is_err());
        Ok(())
    }
}
