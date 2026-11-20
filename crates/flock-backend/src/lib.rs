//! Experimental final prover using a linked Keccak GKR argument or Plonky3 Flock,
//! and the native product bus for arithmetic. This proof is deliberately non-hiding.
mod air;
mod checkpoint;
pub mod checkpoint_keccak;
#[cfg(test)]
mod checkpoint_tests;

mod config;
#[cfg(test)]
mod coordinate_recursion_tests;
mod copies;
#[cfg(test)]
mod copies_tests;
mod encoding;
mod fanout;
mod gates;
mod keccak;
#[cfg(test)]
mod known_openings_tests;
mod mixed;
#[cfg(feature = "opening-bench")]
pub mod opening_bench;
mod packing;
mod products;
mod proof_codec;
mod recursive_layout;
mod swaps;
mod verifier;
mod witness;

pub use config::{WHIR_CAP_HEIGHT, WHIR_FOLD, WHIR_LOG_INV_RATE};
pub use proof_codec::compact_aggregate_proof;
pub use verifier::{AUTHORITY_BYTES, RecursiveAggregate, RecursiveArithmetic, RecursiveAuthority};
pub use verifier::{MAX_VERIFIER_BYTES, Verifier, verifier_key_digest};
#[cfg(test)]
mod tests;

use air::{Chip, WitnessSource, convert};
use anyhow::{Result, ensure};
use checkpoint_keccak::linked::{BoundaryWitness, LinkedBatch};
use config::{Config, challenger};
use encoding::TableEncoding;
use old_air::BaseAir as OldBaseAir;
use old_binary_field::{Poly64 as OldF, TowerLevel as OldTowerLevel};
use p3_air::BaseAir;
use p3_binary_field::{Poly64, TowerLevel};
use p3_circuit::{Circuit, ops::keccak_state_to_limbs};
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
use p3_recursion::pcs::binary::CoordinateEncoding;
use p3_sumcheck::TableShape;
use packing::Packing;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use std::time::Instant;

type F = Poly64;
type Proof = MultiStarkProof<Config>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HashBackend {
    Flock,
    Checkpoint,
}

pub struct Prepared {
    direct_bridge: bool,
    backend: HashBackend,
    checkpoint: Option<LinkedBatch>,
    circuit: Circuit<OldF>,
    instances: usize,
    keccak_wires: Vec<witness::KeccakWires>,
    airs: Vec<Chip>,
    hash: BooleanCircuit,
    hash_index: usize,
    calls: usize,
    log_heights: Vec<usize>,
    config: Config,
    pk: ProvingKey<Config>,
    vk: VerifyingKey<Config>,
    seed: Vec<u8>,
    pub geometry: Geometry,
}

#[derive(Serialize)]
pub struct Geometry {
    pub hash_backend: HashBackend,
    pub checkpoint_codeword_cells: usize,
    pub witnesses: u32,
    pub template_instances: usize,
    pub template_witnesses: u32,
    pub packed_rows: usize,
    pub extension_products: usize,
    pub conditional_swaps: usize,
    pub packed_geometric_rows: usize,
    pub packing_intermediates_removed: usize,
    pub single_use_copies_removed: usize,
    pub paired_copy_ids: usize,
    pub fanout_rows_by_width: Vec<(usize, usize)>,
    /// (coordinate width, maximum occurrences per row, stored rows).
    pub fanout_copy_layout: Vec<(usize, usize, usize)>,
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
        Self::repeated(circuit, 1, domain, HashBackend::Flock)
    }

    pub fn new_checkpoint(circuit: Circuit<OldF>, domain: &[u8]) -> Result<Self> {
        Self::repeated(circuit, 1, domain, HashBackend::Checkpoint)
    }

    pub fn repeated(
        circuit: Circuit<OldF>,
        instances: usize,
        domain: &[u8],
        backend: HashBackend,
    ) -> Result<Self> {
        Self::prepare(circuit, instances, domain, backend, false)
    }

    pub fn recursive_pair(circuit: Circuit<OldF>, domain: &[u8]) -> Result<Self> {
        Self::prepare(circuit, 2, domain, HashBackend::Checkpoint, true)
    }

    fn prepare(
        circuit: Circuit<OldF>,
        instances: usize,
        domain: &[u8],
        backend: HashBackend,
        recursive: bool,
    ) -> Result<Self> {
        ensure!((1..=64).contains(&instances), "unsupported instance count");
        if recursive {
            ensure!(
                (circuit.witness_count as usize) < 1 << recursive_layout::WITNESS_ID_BITS,
                "recursive witness ID capacity exceeded"
            );
        }
        let witnesses = circuit
            .witness_count
            .checked_mul(instances as u32)
            .ok_or_else(|| anyhow::anyhow!("witness count overflow"))?;
        let bus_constructor = if recursive {
            NativeBusCircuit::with_options
        } else {
            NativeBusCircuit::with_compact_options
        };
        let bus = bus_constructor(
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
        let mut widths = fanout::coordinate_widths(&circuit, &bridge.values, bridge.width)?;
        let fanout_pp = bus.airs()[0].preprocessed_trace().unwrap();
        let gates_pp = bus.airs()[1].preprocessed_trace().unwrap();
        if recursive {
            gates::narrow_inputs(&mut widths, &gates_pp.values, gates_pp.width)?;
        }
        let packing = Packing::new(
            &widths,
            &gates_pp.values,
            gates_pp.width,
            bus.airs()[1].width(),
            &fanout_pp.values,
            recursive.then_some(recursive_layout::PACKED_ROWS_LOG),
        )?;
        let packed_rows = packing.shard.as_ref().map_or(0, |s| s.rows.len());
        let packed_geometric_rows = if recursive {
            packed_rows
        } else {
            packing
                .shard
                .as_ref()
                .map_or(0, |s| s.rows.iter().filter(|r| r.is_geometric()).count())
        };
        let packing_intermediates_removed = packing
            .shard
            .as_ref()
            .map_or(0, |s| s.rows.iter().map(|r| r.sources.len() - 1).sum());
        let extension_products = packing.products.as_ref().map_or(0, |s| s.rows.len());
        let conditional_swaps = packing.swaps.as_ref().map_or(0, |s| s.rows.len());
        let (shards, mut copies) =
            fanout::partition(&widths, &fanout_pp.values, &packing.removed_uses, recursive)?;
        drop(fanout_pp);
        let gates = gates::partition(
            &widths,
            &gates_pp.values,
            gates_pp.width,
            bus.airs()[1].width(),
            &packing.removed_rows,
            recursive.then_some(gates::RECURSIVE_LAYOUT.as_slice()),
        )?;
        drop(packing.removed_uses);
        drop(packing.removed_rows);
        drop(gates_pp);
        drop(widths);
        let gate_rows_by_width: Vec<_> = gates
            .iter()
            .map(|s| (s.coordinate_widths.clone(), s.source_rows.len()))
            .collect();
        let keccak_wires = witness::KeccakWires::from_bridge(
            &bridge.values,
            bridge.width,
            calls,
            circuit.witness_count,
        )?;
        drop(bridge);
        let fanout_copy_layout: Vec<_> = shards
            .iter()
            .map(|s| (s.coordinate_width, s.copies_per_row(), s.rows.len()))
            .collect();
        let fanout_rows_by_width = [1, 16, 64]
            .into_iter()
            .map(|width| {
                (
                    width,
                    shards
                        .iter()
                        .filter(|s| s.coordinate_width == width)
                        .map(|s| s.rows.len())
                        .sum(),
                )
            })
            .collect();
        ensure!(
            calls > 0 && calls * instances <= 1 << 20,
            "unsupported Keccak call count"
        );
        let hash_stride = if recursive {
            ensure!(
                calls * instances <= 1 << recursive_layout::HASH_ROWS_LOG,
                "recursive Keccak capacity exceeded"
            );
            recursive_layout::HASH_STRIDE
        } else {
            (2 * calls + 1).next_power_of_two()
        };
        let calls_per_instance = calls;
        let calls = calls * instances;
        let hash = keccak::circuit();
        let log_calls = if recursive {
            recursive_layout::HASH_ROWS_LOG
        } else {
            (calls.next_power_of_two().trailing_zeros() as usize).max(4)
        };
        let mut preprocessing = if recursive {
            Vec::new()
        } else {
            vec![F::ZERO; 3 << log_calls]
        };
        for (i, row) in preprocessing
            .as_chunks_mut::<3>()
            .0
            .iter_mut()
            .take(calls)
            .enumerate()
        {
            let role = (i / calls_per_instance) * hash_stride + 2 * (i % calls_per_instance);
            row.copy_from_slice(&[
                F::from_repr((role + 1) as u64),
                F::from_repr((role + 2) as u64),
                F::ONE,
            ]);
        }
        let source_hash_index = hash_index;
        let mut airs = Vec::new();
        let mut log_heights = Vec::new();
        for shard in shards {
            let mut air =
                Chip::import_shard(bus.airs()[0].clone(), shard.log_height, Some(shard.clone()))?;
            if recursive {
                air.fix_fanout_zero()?;
            }
            airs.push(air);
            log_heights.push(shard.log_height);
        }
        for shard in gates {
            airs.push(Chip::import_gates(
                bus.airs()[1].clone(),
                shard.clone(),
                recursive,
            )?);
            log_heights.push(shard.log_height);
        }
        if let Some(shard) = packing.shard {
            airs.push(Chip::packed(shard.clone()));
            log_heights.push(shard.log_height);
        }
        if let Some(products) = packing.products {
            airs.push(Chip::products(products));
            log_heights.push(products::LOG_HEIGHT);
        }
        if let Some(shard) = packing.swaps {
            airs.push(Chip::swaps(shard));
            log_heights.push(swaps::LOG_HEIGHT);
        }
        let hash_index = source_hash_index + airs.len() - 2;
        for (i, air) in bus.airs().iter().enumerate().skip(2) {
            if recursive && i == source_hash_index {
                continue;
            }
            let mut imported = if i == source_hash_index {
                Chip::Keccak {
                    preprocessing: RowMajorMatrix::new(preprocessing.clone(), 3),
                }
            } else {
                Chip::import(air.clone(), bus.log_heights()[i])?
            };
            ensure!(
                imported.is_public_table() || i == source_hash_index || i == source_hash_index + 1,
                "unexpected native witness table"
            );
            if recursive && i == source_hash_index + 1 {
                imported.link_keccak_bridge(log_calls)?;
            }
            airs.push(imported);
            log_heights.push(
                if i == source_hash_index || (recursive && i == source_hash_index + 1) {
                    log_calls
                } else {
                    bus.log_heights()[i]
                },
            );
        }
        for air in &mut airs {
            if recursive && air.is_public_table() {
                air.commit_public_ids()?;
            }
            air.prune_copies(&mut copies)?;
        }
        let copy_stats = copies.finish()?;
        for air in &mut airs {
            air.repeat(instances, hash_stride);
        }
        // Canonically bind the actual imported AIR and preprocessing, not a prover-supplied identity.
        let mut identity = Keccak256::new();
        identity.update(match backend {
            HashBackend::Flock => {
                b"imt-flock-backend-v12/708900d7a730d6ce4d5421d43e2193f2301920fa".as_slice()
            }
            HashBackend::Checkpoint => {
                b"imt-checkpoint-backend-v6/708900d7a730d6ce4d5421d43e2193f2301920fa".as_slice()
            }
        });
        if recursive {
            identity.update(b"/poly64-word-openings-v1/direct-bridge-v1/pp-digits-v1/pp-rate-half/joint-boundaries-v1/main-rate-half/packed-chi16");
        }
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
                let widths = if recursive {
                    let widths = a.recursive_preprocessed_widths()?;
                    recursive_layout::check_coordinates(&coordinates, &widths)?;
                    widths
                } else {
                    coordinates
                        .into_iter()
                        .map(|v| 64 - v.leading_zeros() as usize)
                        .collect()
                };
                let mode = if recursive {
                    CoordinateEncoding::PreprocessedDigits
                } else {
                    CoordinateEncoding::Bits
                };
                pp_encoding.push(TableEncoding::with_encoding(
                    widths,
                    (pp.values.len() / pp.width).ilog2() as usize,
                    mode,
                )?);
            } else {
                identity.update(0u64.to_le_bytes());
            }
        }
        let shapes: Vec<_> = airs
            .iter()
            .enumerate()
            .map(|(i, a)| {
                if i == hash_index && backend == HashBackend::Flock {
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
                let widths = match airs[i].witness_source() {
                    WitnessSource::Gates(shard) => shard.coordinate_widths.repeat(instances),
                    WitnessSource::Fanout(shard) => vec![shard.coordinate_width; shape.width()],
                    WitnessSource::Packed(_) => {
                        let mut widths = vec![1; packing::TERMS];
                        widths.extend([64, 64]);
                        widths.repeat(instances)
                    }
                    WitnessSource::WireRows {
                        coordinate_width, ..
                    } => vec![coordinate_width; shape.width()],
                    WitnessSource::Public => vec![0],
                    WitnessSource::Keccak if backend == HashBackend::Flock => {
                        vec![1; shape.width()]
                    }
                    WitnessSource::Bridge | WitnessSource::Keccak => vec![16; shape.width()],
                };
                TableEncoding::with_word_openings(widths, recursive)
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
        let pp_log_inv_rate = if recursive {
            config::RECURSIVE_PP_LOG_INV_RATE
        } else {
            WHIR_LOG_INV_RATE
        };
        let config = Config::with_boundary(
            &shapes,
            main_encoding,
            &pp,
            pp_encoding,
            pp_log_inv_rate,
            recursive.then_some(log_calls),
            if recursive { 1 } else { WHIR_LOG_INV_RATE },
        )?;
        let checkpoint = if let Some(security) = &config.joint_security {
            Some(LinkedBatch::joint(log_calls, security, true)?)
        } else if backend == HashBackend::Checkpoint {
            Some(LinkedBatch::with_bridge(
                log_calls,
                config.main_log2_candidates,
                recursive,
            )?)
        } else {
            None
        };
        let checkpoint_codeword_cells = checkpoint.as_ref().map_or(0, |c| c.initial_codeword_cells);
        ensure!(
            config.initial_codeword_cells + checkpoint_codeword_cells <= 1 << 30,
            "arithmetic and checkpoint codewords exceed this prototype's 2^30 budget"
        );
        let (pk, vk) = setup(
            &config,
            &airs.iter().collect::<Vec<_>>(),
            &mut challenger(&seed),
        )?;
        let public: Vec<Vec<F>> = airs
            .iter()
            .map(|a| vec![F::ZERO; a.num_public_values()])
            .collect();
        let security_instances = verifier_instances(
            &airs,
            &hash,
            hash_index,
            &log_heights,
            &vk,
            &public,
            backend,
        );
        let report = security_report(&config, &security_instances)?;
        ensure!(
            report.unassessed_components().is_empty(),
            "unassessed binary security components: {:?}",
            report.unassessed_components()
        );
        let mut terms: Vec<_> = report
            .terms()
            .iter()
            .map(|t| (t.label.to_string(), t.bits.bits()))
            .collect();
        if let Some(checkpoint) = &checkpoint {
            terms.push((
                "checkpoint-permutation-pcs-and-port-link".to_owned(),
                checkpoint.conditional_algebraic_bits,
            ));
        }
        let error: f64 = terms
            .iter()
            .filter(|(l, _)| l != "commitment-and-transcript-collision")
            .map(|(_, b)| 2f64.powf(-b))
            .sum();
        let algebraic_bits = -error.log2();
        ensure!(
            algebraic_bits >= 144.0,
            "binary algebraic bound {algebraic_bits} below 144-bit budget"
        );
        let geometry = Geometry {
            hash_backend: backend,
            checkpoint_codeword_cells,
            witnesses,
            template_instances: instances,
            template_witnesses: circuit.witness_count,
            extension_products: extension_products * instances,
            conditional_swaps: conditional_swaps * instances,
            packed_rows: packed_rows * instances,
            packed_geometric_rows: packed_geometric_rows * instances,
            packing_intermediates_removed: packing_intermediates_removed * instances,
            single_use_copies_removed: copy_stats.single_use * instances,
            paired_copy_ids: copy_stats.pairs * instances,
            fanout_rows_by_width,
            fanout_copy_layout,
            gate_rows_by_width,
            keccak_permutations: calls,
            table_widths: airs.iter().map(BaseAir::width).collect(),
            log_heights: log_heights.clone(),
            algebraic_bits,
            initial_codeword_cells: config.initial_codeword_cells + checkpoint_codeword_cells,
            main_codeword_cells: config.main_codeword_cells,
            preprocessed_codeword_cells: config.preprocessed_codeword_cells,
            main_coordinate_widths,
            preprocessed_coordinate_widths,
            security_terms: terms,
        };
        Ok(Self {
            direct_bridge: recursive,
            backend,
            checkpoint,
            circuit,
            instances,
            keccak_wires,
            airs,
            hash,
            hash_index,
            calls,
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
        let (mut tables, states) = self.witness_tables(public, private)?;
        let mut hash_witness = (self.backend == HashBackend::Flock).then(|| {
            Witness::generate(
                &self.hash,
                self.log_heights[self.hash_index],
                &states.inputs,
                &[0; 25],
                |state, words| words.copy_from_slice(&keccak_state_to_limbs(state).map(u64::from)),
            )
        });
        let boundaries = (self.backend == HashBackend::Checkpoint).then_some(states);
        if !self.direct_bridge {
            tables[self.hash_index] = boundaries.as_ref().map(BoundaryWitness::ports);
        }
        let public = self.public(public)?;
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
        let bytes = if let Some(scheme) = self
            .checkpoint
            .as_ref()
            .filter(|_| self.config.joint_security.is_some())
        {
            checkpoint::prove_joint(
                &self.config,
                instances,
                scheme,
                &self.seed,
                self.hash_index,
                boundaries.ok_or_else(|| anyhow::anyhow!("missing joint checkpoint boundaries"))?,
            )?
        } else {
            let pending = boundaries
                .map(|witness| {
                    self.checkpoint
                        .as_ref()
                        .unwrap()
                        .commit(witness, &self.seed)
                })
                .transpose()?;
            let seed = pending.as_ref().map_or_else(
                || Ok(self.seed.clone()),
                |pending| {
                    self.checkpoint
                        .as_ref()
                        .unwrap()
                        .arithmetic_seed(&self.seed, &pending.statement)
                },
            )?;
            let proof = prove(&self.config, instances, 0, &mut challenger(&seed))?;
            if let Some(pending) = pending {
                let scheme = self.checkpoint.as_ref().unwrap();
                let ports = checkpoint::arithmetic_opening(
                    &self.config,
                    verifier_instances(
                        &self.airs,
                        &self.hash,
                        self.hash_index,
                        &self.log_heights,
                        &self.vk,
                        &public,
                        self.backend,
                    ),
                    &proof,
                    &pending.statement,
                    &self.seed,
                    self.hash_index,
                    scheme,
                )?;
                let statement = pending.statement.clone();
                let keccak = scheme.prove(pending, &ports)?;
                proof_codec::encode(&checkpoint::AggregateProof {
                    statement,
                    arithmetic: proof,
                    keccak,
                })?
            } else {
                proof_codec::encode(&proof)?
            }
        };
        let prove_ms = elapsed(start);
        let start = Instant::now();
        self.verify_public(&bytes, &public)?;
        let verify_ms = elapsed(start);
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
        self.verify_public(bytes, &self.public(public)?)
    }

    fn verify_public(&self, bytes: &[u8], public: &[Vec<F>]) -> Result<()> {
        ensure!(bytes.len() <= 16 << 20, "oversized aggregate proof");
        let instances = verifier_instances(
            &self.airs,
            &self.hash,
            self.hash_index,
            &self.log_heights,
            &self.vk,
            public,
            self.backend,
        );
        if let Some(scheme) = &self.checkpoint {
            return checkpoint::verify(
                &self.config,
                instances,
                scheme,
                &self.seed,
                self.hash_index,
                bytes,
            );
        }
        let proof: Proof = proof_codec::decode(bytes)?;
        verify(
            &self.config,
            instances,
            &proof,
            0,
            &mut challenger(&self.seed),
        )?;
        Ok(())
    }

    fn public(&self, values: &[OldF]) -> Result<Vec<Vec<F>>> {
        ensure!(
            values.len() == self.circuit.public_flat_len * self.instances,
            "incorrect public input count"
        );
        let values: Vec<_> = values.iter().copied().map(convert).collect();
        Ok(self
            .airs
            .iter()
            .map(|air| {
                if air.num_public_values() == 0 {
                    vec![]
                } else {
                    values.clone()
                }
            })
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
    backend: HashBackend,
) -> VerifierInstances<'a, Config, Chip> {
    VerifierInstances::new(
        airs.iter()
            .enumerate()
            .map(|(i, a)| {
                if i == hash_index && backend == HashBackend::Flock {
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
