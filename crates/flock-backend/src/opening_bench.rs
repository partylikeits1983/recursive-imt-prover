//! PCS-only replay of a verified parent. Preserve its actual tables, hints and
//! prescribed queries. The independent replay transcript has no AIR acceptance role.
mod fixed;
pub use fixed::FixedColumnProfile;

use crate::{
    F, Prepared,
    config::{challenger, pcs_with_rate},
    encoding::TableEncoding,
};
use anyhow::{Result, ensure};
use p3_binary_field::Poly192 as E;
use p3_commit::MultilinearPcs;
use p3_multilinear_util::point::Point;
use p3_sumcheck::{OpeningEvals, OpeningProtocol, PrescribedPointPcs, TableSpec, layout::Table};
use serde::Serialize;
use std::{sync::Mutex, time::Instant};

pub(crate) struct Request<EF> {
    pub(crate) tables: Vec<Table<F>>,
    pub(crate) encodings: Vec<TableEncoding>,
    pub(crate) protocol: OpeningProtocol,
    pub(crate) points: Vec<Point<EF>>,
    pub(crate) known: Vec<Option<OpeningEvals<EF>>>,
    pub(crate) weighted: bool,
}

impl<EF> Request<EF> {
    fn split_at(mut self, index: usize) -> Result<(Self, Self)> {
        let shapes = self.protocol.table_shapes();
        ensure!(
            index > 0 && index < shapes.len(),
            "invalid recorded table split"
        );
        let mut batches = vec![Vec::new(); shapes.len()];
        for (table, batch) in self.protocol.iter_openings() {
            batches[table].push(batch.clone());
        }
        let mut specs: Vec<_> = shapes
            .into_iter()
            .zip(batches)
            .map(|(s, b)| TableSpec::new(s, b))
            .collect();
        let boundary = OpeningProtocol::new(specs.split_off(index));
        self.protocol = OpeningProtocol::new(specs);
        let cut = self.protocol.num_openings();
        let rest = Self {
            protocol: boundary,
            tables: self.tables.split_off(index),
            encodings: self.encodings.split_off(index),
            points: self.points.split_off(cut),
            known: self.known.split_off(cut),
            weighted: self.weighted,
        };
        Ok((self, rest))
    }
}

#[derive(Serialize)]
pub struct CircuitCost {
    pub witnesses: u32,
    pub operations: usize,
    pub keccak_permutations: usize,
}

pub(crate) const SEED: &[u8] = b"recursive-parent-opening-comparison-v1";

#[derive(Serialize)]
pub struct Sample {
    #[serde(skip_serializing_if = "Option::is_none")]
    recursive_circuit: Option<CircuitCost>,
    joint: bool,
    log_inv_rate: usize,
    opening_proofs: usize,
    tables: usize,
    prescribed_points: usize,
    opened_values: usize,
    initial_codeword_cells: usize,
    commit_s: f64,
    open_s: f64,
    verify_s: f64,
    proof_bytes: usize,
}

impl Prepared {
    pub fn record_openings(&mut self) -> Result<()> {
        let checkpoint = self
            .checkpoint
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("expected checkpoint parent"))?;
        self.config.main.capture = Some(Mutex::new(None));
        if self.config.joint_security.is_none() {
            checkpoint.pcs.capture = Some(Mutex::new(None));
        }
        Ok(())
    }

    pub fn compare_recorded_openings(&mut self, repetitions: u32) -> Result<Vec<Sample>> {
        let recorded = |slot: &mut Option<Mutex<Option<Request<E>>>>| {
            slot.take()
                .and_then(|x| x.into_inner().ok().flatten())
                .ok_or_else(|| anyhow::anyhow!("missing captured PCS request"))
        };
        let main = recorded(&mut self.config.main.capture)?;
        let (main, boundary) = if self.config.joint_security.is_some() {
            main.split_at(self.airs.len())?
        } else {
            (
                main,
                recorded(
                    &mut self
                        .checkpoint
                        .as_mut()
                        .ok_or_else(|| anyhow::anyhow!("expected checkpoint parent"))?
                        .pcs
                        .capture,
                )?,
            )
        };
        ensure!(
            !main.weighted && !boundary.weighted && repetitions > 0,
            "expected ordinary prescribed openings"
        );
        let mut samples = Vec::new();
        let mut reference = None;
        for i in 0..repetitions {
            for joint in [i % 2 == 1, i % 2 == 0] {
                let (sample, evals) = replay(
                    [&main, &boundary],
                    joint,
                    i == 0,
                    self.config.main_log_inv_rate,
                )?;
                if let Some(expected) = &reference {
                    ensure!(expected == &evals, "joint and separate openings disagree");
                } else {
                    reference = Some(evals);
                }
                samples.push(sample);
            }
        }
        Ok(samples)
    }
}

fn replay(
    requests: [&Request<E>; 2],
    joint: bool,
    circuit: bool,
    log_inv_rate: usize,
) -> Result<(Sample, Vec<OpeningEvals<E>>)> {
    let mut ch = challenger(SEED);
    let mut verifier = ch.clone();
    let mut circuit_inputs = Vec::new();
    let mut sample = Sample {
        recursive_circuit: None,
        joint,
        log_inv_rate,
        opening_proofs: 0,
        tables: 0,
        prescribed_points: 0,
        opened_values: 0,
        initial_codeword_cells: 0,
        commit_s: 0.,
        open_s: 0.,
        verify_s: 0.,
        proof_bytes: 0,
    };
    let mut pending = Vec::new();
    for group in requests.chunks(if joint { 2 } else { 1 }) {
        let mut specs = Vec::new();
        let mut tables = Vec::new();
        let mut encodings = Vec::new();
        let mut points = Vec::new();
        let mut known = Vec::new();
        for request in group {
            let shapes = request.protocol.table_shapes();
            let mut schedules = vec![Vec::new(); shapes.len()];
            for (index, batch) in request.protocol.iter_openings() {
                schedules[index].push(batch.clone());
            }
            specs.extend(
                shapes
                    .into_iter()
                    .zip(schedules)
                    .map(|(shape, batches)| TableSpec::new(shape, batches)),
            );
            tables.extend_from_slice(&request.tables);
            encodings.extend_from_slice(&request.encodings);
            points.extend_from_slice(&request.points);
            known.extend_from_slice(&request.known);
        }
        let protocol = OpeningProtocol::new(specs);
        let widths = circuit.then(|| encodings.iter().map(|e| e.widths.clone()).collect());
        let pcs = pcs_with_rate(&protocol.table_shapes(), encodings, log_inv_rate)?;
        sample.opening_proofs += 1;
        sample.tables += tables.len();
        sample.prescribed_points += points.len();
        sample.opened_values += protocol
            .checked_num_claims()
            .ok_or_else(|| anyhow::anyhow!("claim count overflow"))?;
        sample.initial_codeword_cells += 1usize << (pcs.num_vars() - 6 + log_inv_rate);
        let start = Instant::now();
        let (root, data) = pcs.commit(tables, &mut ch)?;
        sample.commit_s += start.elapsed().as_secs_f64();
        pcs.observe_commitment(&root, &mut verifier);
        pending.push((pcs, root, data, protocol, points, known, widths));
    }
    let mut evals = Vec::new();
    for (pcs, root, data, protocol, points, known, widths) in pending {
        let start = Instant::now();
        let proof = pcs.open_at_known(data, &protocol, &points, &known, &mut ch)?;
        sample.open_s += start.elapsed().as_secs_f64();
        sample.proof_bytes +=
            postcard::to_allocvec(&proof)?.len() + postcard::to_allocvec(&root)?.len();
        let start = Instant::now();
        let opened = pcs.verify_at(&root, &proof, &protocol, &points, &mut verifier)?;
        sample.verify_s += start.elapsed().as_secs_f64();
        ensure!(
            opened.len() == known.len()
                && opened
                    .iter()
                    .zip(known)
                    .all(|(o, k)| k.is_none_or(|v| v == *o)),
            "replayed PCS openings disagree with parent"
        );
        if let Some(widths) = widths {
            circuit_inputs.push(crate::verifier::CircuitInput {
                log_inv_rate,
                root,
                proof,
                protocol,
                points,
                widths,
                opened: opened.clone(),
            });
        }
        evals.extend(opened);
    }
    if circuit {
        sample.recursive_circuit = Some(crate::verifier::check_circuit(circuit_inputs)?);
    }
    Ok((sample, evals))
}
