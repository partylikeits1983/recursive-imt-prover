//! Experimental final prover using Plonky3 Flock for Keccak and the native
//! product bus for the arithmetic circuit. This proof is deliberately non-hiding.
mod air;
mod config;
mod encoding;
mod fanout;
mod gates;
mod keccak;
mod mixed;
#[cfg(test)]
mod tests;

use air::{Chip, convert};
use anyhow::{Result, ensure};
use config::{Config, challenger};
use encoding::TableEncoding;
use fanout::FanoutShard;
use gates::GateShard;
use old_air::BaseAir as OldBaseAir;
use old_binary_field::{Poly64 as OldF, TowerLevel as OldTowerLevel};
use p3_air::BaseAir;
use p3_binary_field::{Poly64, TowerLevel};
use p3_circuit::Circuit;
use p3_circuit_prover::{
    direct::DirectCircuitLimits,
    native_bus::{KeccakCommitment, NativeBusCircuit},
};
use p3_field::PrimeCharacteristicRing;
use p3_flock::{Circuit as BooleanCircuit, Witness};
use p3_matrix::dense::RowMajorMatrix;
use p3_multi_stark::{
    MultiStarkProof, ProverInstance, ProverInstances, ProvingKey, VerifierInstance,
    VerifierInstances, VerifyingKey, prove, security_report, setup, verify,
};
use p3_sumcheck::{TableShape, layout::Table};
use serde::Serialize;
use sha3::{Digest, Keccak256};
use std::{sync::Arc, time::Instant};

type F = Poly64;
type Proof = MultiStarkProof<Config>;

pub struct Prepared {
    circuit: Circuit<OldF>,
    bus: NativeBusCircuit<OldF>,
    airs: Vec<Chip>,
    hash: BooleanCircuit,
    hash_index: usize,
    calls: usize,
    sources: Vec<TableSource>,
    source_hash_index: usize,
    log_heights: Vec<usize>,
    config: Config,
    pk: ProvingKey<Config>,
    vk: VerifyingKey<Config>,
    seed: Vec<u8>,
    pub geometry: Geometry,
}

struct TableSource {
    index: usize,
    shard: Option<Arc<FanoutShard>>,
    gates: Option<Arc<GateShard>>,
}

#[derive(Serialize)]
pub struct Geometry {
    pub witnesses: u32,
    pub fanout_rows_by_width: Vec<(usize, usize)>,
    pub gate_rows_by_width: Vec<(Vec<usize>, usize)>,
    pub keccak_permutations: usize,
    pub table_widths: Vec<usize>,
    pub log_heights: Vec<usize>,
    pub algebraic_bits: f64,
    pub initial_codeword_cells: usize,
    pub main_codeword_cells: usize,
    pub preprocessed_codeword_cells: usize,
    pub main_coordinate_widths: Vec<Vec<usize>>,
    pub preprocessed_coordinate_widths: Vec<Vec<usize>>,
    pub security_terms: Vec<(String, f64)>,
}

#[derive(Serialize)]
pub struct Metrics {
    pub witness_ms: f64,
    pub prove_ms: f64,
    pub verify_ms: f64,
    pub proof_bytes: usize,
}

impl Prepared {
    pub fn new(circuit: Circuit<OldF>, domain: &[u8]) -> Result<Self> {
        let bus = NativeBusCircuit::with_compact_options(
            &circuit,
            "imt",
            4,
            DirectCircuitLimits {
                max_witnesses: 1 << 26,
                max_operations: 1 << 26,
                max_trace_cells: 1 << 31,
            },
            KeccakCommitment::Bits,
        )?;
        let hash_index = bus
            .packed_table_index()
            .ok_or_else(|| anyhow::anyhow!("missing Keccak table"))?;
        let bridge = bus.airs()[hash_index + 1].preprocessed_trace().unwrap();
        ensure!(bridge.width >= 119, "unexpected native bridge layout");
        let calls = bridge
            .values
            .chunks_exact(bridge.width)
            .filter(|r| r[117].to_repr() == 1)
            .count()
            / 2;
        ensure!(
            bus.airs()[0].width() == 1
                && bus.airs()[0].preprocessed_width() == 3
                && bus.airs()[0].main_next_row_columns() == [0],
            "unexpected native fanout layout"
        );
        let widths = fanout::coordinate_widths(&circuit, &bridge.values, bridge.width)?;
        let shards =
            fanout::partition(&widths, &bus.airs()[0].preprocessed_trace().unwrap().values)?;
        let gates_pp = bus.airs()[1].preprocessed_trace().unwrap();
        let gates = gates::partition(
            &widths,
            &gates_pp.values,
            gates_pp.width,
            bus.airs()[1].width(),
        )?;
        drop(gates_pp);
        drop(widths);
        let gate_rows_by_width: Vec<_> = gates
            .iter()
            .map(|s| (s.coordinate_widths.clone(), s.source_rows.len()))
            .collect();
        eprintln!("Gate live rows by coordinate widths: {gate_rows_by_width:?}");
        drop(bridge);
        let fanout_rows_by_width: Vec<_> = shards
            .iter()
            .map(|s| (s.coordinate_width, s.rows.len()))
            .collect();
        eprintln!("Fanout live rows by coordinate width: {fanout_rows_by_width:?}");
        ensure!(
            calls > 0 && calls <= 1 << 20,
            "unsupported Keccak call count"
        );
        let hash = keccak::circuit();
        let log_calls = calls.next_power_of_two().trailing_zeros() as usize;
        let log_calls = log_calls.max(4);
        let mut preprocessing = vec![F::ZERO; 3 * (1 << log_calls)];
        for (i, row) in preprocessing
            .as_chunks_mut::<3>()
            .0
            .iter_mut()
            .take(calls)
            .enumerate()
        {
            row.copy_from_slice(&[
                F::from_repr((2 * i + 1) as u64),
                F::from_repr((2 * i + 2) as u64),
                F::ONE,
            ]);
        }
        let source_hash_index = hash_index;
        let mut airs = Vec::new();
        let mut sources = Vec::new();
        let mut log_heights = Vec::new();
        for shard in shards {
            airs.push(Chip::import_shard(
                bus.airs()[0].clone(),
                shard.log_height,
                Some(shard.clone()),
            )?);
            log_heights.push(shard.log_height);
            sources.push(TableSource {
                index: 0,
                shard: Some(shard),
                gates: None,
            });
        }
        for shard in gates {
            airs.push(Chip::import_gates(bus.airs()[1].clone(), shard.clone())?);
            log_heights.push(shard.log_height);
            sources.push(TableSource {
                index: 1,
                shard: None,
                gates: Some(shard),
            });
        }
        let hash_index = source_hash_index + airs.len() - 2;
        for (i, air) in bus.airs().iter().enumerate().skip(2) {
            airs.push(if i == source_hash_index {
                Chip::Keccak {
                    preprocessing: RowMajorMatrix::new(preprocessing.clone(), 3),
                }
            } else {
                Chip::import(air.clone(), bus.log_heights()[i])?
            });
            log_heights.push(if i == source_hash_index {
                log_calls
            } else {
                bus.log_heights()[i]
            });
            sources.push(TableSource {
                index: i,
                shard: None,
                gates: None,
            });
        }
        // Canonically bind the actual imported AIR and preprocessing, not a prover-supplied identity.
        let mut identity = Keccak256::new();
        identity.update(b"imt-flock-backend-v7/708900d7a730d6ce4d5421d43e2193f2301920fa");
        identity.update((domain.len() as u64).to_le_bytes());
        identity.update(domain);
        identity.update(hash.digest());
        let mut pp_encoding = Vec::new();
        for a in &airs {
            identity.update((a.width() as u64).to_le_bytes());
            identity.update((a.num_public_values() as u64).to_le_bytes());
            identity.update(a.periodic_statement());
            let s = p3_bus::BusSymbolicBuilder::<F, F>::from_air(a, p3_air::AirLayout::from_air(a));
            identity.update(format!("{:?}{:?}", s.base_constraints(), s.interactions()).as_bytes());
            if let Some(pp) = a.preprocessed_trace() {
                identity.update((pp.width as u64).to_le_bytes());
                identity.update((pp.values.len() as u64).to_le_bytes());
                let mut coordinates = vec![0u64; pp.width];
                for row in pp.values.chunks_exact(pp.width) {
                    for (column, value) in row.iter().enumerate() {
                        let raw = value.to_repr();
                        identity.update(raw.to_le_bytes());
                        coordinates[column] |= raw;
                    }
                }
                pp_encoding.push(TableEncoding::new(
                    coordinates
                        .into_iter()
                        .map(|v| 64 - v.leading_zeros() as usize)
                        .collect(),
                )?);
            } else {
                identity.update(0u64.to_le_bytes());
            }
        }
        let shapes: Vec<_> = airs
            .iter()
            .enumerate()
            .map(|(i, a)| {
                if i == hash_index {
                    TableShape::new(log_calls + hash.k_log(), 1)
                } else {
                    TableShape::new(log_heights[i], a.width())
                }
            })
            .collect();
        let pp: Vec<_> = airs
            .iter()
            .enumerate()
            .filter(|(_, a)| a.preprocessed_width() > 0)
            .map(|(i, a)| TableShape::new(log_heights[i], a.preprocessed_width()))
            .collect();
        let main_encoding = shapes
            .iter()
            .enumerate()
            .map(|(i, shape)| {
                if airs[i].is_public_table() {
                    return TableEncoding::new(vec![0]);
                }
                if let Some(gates) = &sources[i].gates {
                    return TableEncoding::new(gates.coordinate_widths.clone());
                }
                let width = if let Some(shard) = &sources[i].shard {
                    shard.coordinate_width
                } else if i == hash_index {
                    1
                } else if i == hash_index + 1 {
                    16
                } else {
                    64
                };
                TableEncoding::new(vec![width; shape.width()])
            })
            .collect::<Result<Vec<_>>>()?;
        let main_coordinate_widths: Vec<_> =
            main_encoding.iter().map(|e| e.widths.clone()).collect();
        let preprocessed_coordinate_widths: Vec<_> =
            pp_encoding.iter().map(|e| e.widths.clone()).collect();
        // Encodings are verifier-authorized parts of the statement, including
        // widths inferred from the fixed preprocessing (never from a witness).
        for encodings in [&main_encoding, &pp_encoding] {
            identity.update((encodings.len() as u64).to_le_bytes());
            for encoding in encodings {
                identity.update((encoding.widths.len() as u64).to_le_bytes());
                for &width in &encoding.widths {
                    identity.update((width as u64).to_le_bytes());
                }
            }
        }
        let seed = identity.finalize().to_vec();
        eprintln!(
            "Flock tables: widths {:?}, log heights {:?}, {calls} Keccak calls",
            airs.iter().map(BaseAir::width).collect::<Vec<_>>(),
            log_heights
        );
        let config = Config::new(&shapes, main_encoding, &pp, pp_encoding)?;
        let (pk, vk) = setup(
            &config,
            &airs.iter().collect::<Vec<_>>(),
            &mut challenger(&seed),
        )?;
        let public: Vec<Vec<F>> = airs
            .iter()
            .map(|a| vec![F::ZERO; a.num_public_values()])
            .collect();
        let instances = verifier_instances(&airs, &hash, hash_index, &log_heights, &vk, &public);
        let report = security_report(&config, &instances)?;
        ensure!(
            report.unassessed_components().is_empty(),
            "unassessed Flock security components: {:?}",
            report.unassessed_components()
        );
        let terms: Vec<_> = report
            .terms()
            .iter()
            .map(|t| (t.label.to_string(), t.bits.bits()))
            .collect();
        let error: f64 = terms
            .iter()
            .filter(|(l, _)| l != "commitment-and-transcript-collision")
            .map(|(_, b)| 2f64.powf(-b))
            .sum();
        let algebraic_bits = -error.log2();
        ensure!(
            algebraic_bits >= 144.0,
            "Flock algebraic bound {algebraic_bits} below 144-bit budget"
        );
        let geometry = Geometry {
            witnesses: circuit.witness_count,
            fanout_rows_by_width,
            gate_rows_by_width,
            keccak_permutations: calls,
            table_widths: airs.iter().map(BaseAir::width).collect(),
            log_heights: log_heights.clone(),
            algebraic_bits,
            initial_codeword_cells: config.initial_codeword_cells,
            main_codeword_cells: config.main_codeword_cells,
            preprocessed_codeword_cells: config.preprocessed_codeword_cells,
            main_coordinate_widths,
            preprocessed_coordinate_widths,
            security_terms: terms,
        };
        Ok(Self {
            circuit,
            bus,
            airs,
            hash,
            hash_index,
            calls,
            sources,
            source_hash_index,
            log_heights,
            config,
            pk,
            vk,
            seed,
            geometry,
        })
    }

    pub fn identity(&self) -> String {
        hex::encode(&self.seed)
    }

    pub fn prove(&self, public: &[OldF], private: &[OldF]) -> Result<(Vec<u8>, Metrics)> {
        let start = Instant::now();
        let mut runner = self.circuit.runner();
        runner.set_public_inputs(public)?;
        runner.set_private_inputs(private)?;
        let witness = runner.run_witness()?;
        let mut source: Vec<_> = self
            .bus
            .column_major_tables(&witness)?
            .into_iter()
            .map(Some)
            .collect();
        drop(witness);
        // The legacy Keccak trace is replaced by Flock. Release it before
        // constructing Flock's witness and the partitioned native tables.
        drop(source[self.source_hash_index].take());
        let bridge = source[self.source_hash_index + 1].as_ref().unwrap();
        let rows: Vec<[u64; 100]> = (0..self.calls)
            .map(|i| core::array::from_fn(|j| bridge.column(j).value(2 * i).to_repr()))
            .collect();
        let hash_witness = Witness::generate(
            &self.hash,
            self.log_heights[self.hash_index],
            &rows,
            &[0; 100],
            |row, words| words.copy_from_slice(row),
        );
        let mut tables = Vec::new();
        for (i, mapping) in self.sources.iter().enumerate() {
            if i == self.hash_index {
                tables.push(None);
                continue;
            }
            // Table clones share storage. Release each original after its last
            // partition, avoiding simultaneous retention of both full layouts.
            let table = source[mapping.index].as_ref().unwrap().clone();
            if self
                .sources
                .get(i + 1)
                .is_none_or(|next| next.index != mapping.index)
            {
                drop(source[mapping.index].take());
            }
            if let Some(shard) = &mapping.shard {
                let height = 1 << shard.log_height;
                let column = table.column(0);
                let mut values = vec![F::ZERO; 2 * height];
                for (r, row) in shard.rows.iter().enumerate() {
                    values[r + 1] = convert(column.value(row.source_row as usize));
                }
                for r in 0..height {
                    values[height + r] = values[(r + 1).min(height - 1)];
                }
                tables.push(Some(Table::new(RowMajorMatrix::new(values, height))));
                continue;
            }
            if let Some(shard) = &mapping.gates {
                let height = 1 << shard.log_height;
                let mut values = vec![F::ZERO; height * table.num_polys()];
                for c in 0..table.num_polys() {
                    let column = table.column(c);
                    for (r, &source_row) in shard.source_rows.iter().enumerate() {
                        values[c * height + r] = convert(column.value(source_row as usize));
                    }
                }
                tables.push(Some(Table::new(RowMajorMatrix::new(values, height))));
                continue;
            }
            let height = 1 << table.num_variables();
            if self.airs[i].is_public_table() {
                tables.push(Some(Table::new(RowMajorMatrix::new(
                    vec![F::ZERO; height],
                    height,
                ))));
                continue;
            }
            let mut values: Vec<_> = (0..table.num_polys())
                .flat_map(|c| {
                    let column = table.column(c);
                    (0..height).map(move |r| convert(column.value(r)))
                })
                .collect();
            if self.airs[i].has_successor() {
                let column = table.column(0);
                values.extend((0..height).map(|r| convert(column.value((r + 1).min(height - 1)))));
            }
            tables.push(Some(Table::new(RowMajorMatrix::new(values, height))));
        }
        drop(source);
        let public = self.public(public)?;
        let mut hash_witness = Some(hash_witness);
        let instances = ProverInstances::new(
            tables
                .into_iter()
                .enumerate()
                .map(|(i, t)| match t {
                    Some(t) => ProverInstance::new(&self.airs[i], t, &self.pk, &public[i]),
                    None => ProverInstance::circuit(
                        &self.airs[i],
                        &self.hash,
                        hash_witness.take().unwrap(),
                        &self.pk,
                        &public[i],
                    ),
                })
                .collect(),
        );
        let witness_ms = elapsed(start);
        let start = Instant::now();
        let proof = prove(&self.config, instances, 0, &mut challenger(&self.seed))?;
        let prove_ms = elapsed(start);
        let start = Instant::now();
        verify(
            &self.config,
            verifier_instances(
                &self.airs,
                &self.hash,
                self.hash_index,
                &self.log_heights,
                &self.vk,
                &public,
            ),
            &proof,
            0,
            &mut challenger(&self.seed),
        )?;
        let verify_ms = elapsed(start);
        let bytes = postcard::to_allocvec(&proof)?;
        let proof_bytes = bytes.len();
        Ok((
            bytes,
            Metrics {
                witness_ms,
                prove_ms,
                verify_ms,
                proof_bytes,
            },
        ))
    }

    pub fn verify(&self, bytes: &[u8], public: &[OldF]) -> Result<()> {
        ensure!(bytes.len() <= 16 << 20, "oversized aggregate proof");
        let (proof, rest): (Proof, _) = postcard::take_from_bytes(bytes)?;
        ensure!(rest.is_empty(), "trailing aggregate proof data");
        let public = self.public(public)?;
        verify(
            &self.config,
            verifier_instances(
                &self.airs,
                &self.hash,
                self.hash_index,
                &self.log_heights,
                &self.vk,
                &public,
            ),
            &proof,
            0,
            &mut challenger(&self.seed),
        )?;
        Ok(())
    }

    fn public(&self, values: &[OldF]) -> Result<Vec<Vec<F>>> {
        let original = self.bus.public_values(values)?;
        Ok(self
            .sources
            .iter()
            .map(|s| original[s.index].iter().copied().map(convert).collect())
            .collect())
    }
}

fn verifier_instances<'a>(
    airs: &'a [Chip],
    hash: &'a BooleanCircuit,
    hash_index: usize,
    logs: &[usize],
    vk: &'a VerifyingKey<Config>,
    public: &'a [Vec<F>],
) -> VerifierInstances<'a, Config, Chip> {
    VerifierInstances::new(
        airs.iter()
            .enumerate()
            .map(|(i, a)| {
                if i == hash_index {
                    VerifierInstance::circuit(a, hash, vk, logs[i], &public[i])
                } else {
                    VerifierInstance::new(a, vk, logs[i], &public[i])
                }
            })
            .collect(),
    )
}
fn elapsed(start: Instant) -> f64 {
    start.elapsed().as_secs_f64() * 1000.0
}
