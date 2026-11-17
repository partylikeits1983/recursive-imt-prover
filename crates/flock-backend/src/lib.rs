//! Experimental final prover using Plonky3 Flock for Keccak and the native
//! product bus for the arithmetic circuit. This proof is deliberately non-hiding.
mod air;
mod config;
mod keccak;
mod mixed;
#[cfg(test)]
mod tests;

use air::{Chip, convert};
use anyhow::{Result, ensure};
use config::{Config, challenger};
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
use std::time::Instant;

type F = Poly64;
type Proof = MultiStarkProof<Config>;

pub struct Prepared {
    circuit: Circuit<OldF>,
    bus: NativeBusCircuit<OldF>,
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
    pub witnesses: u32,
    pub keccak_permutations: usize,
    pub table_widths: Vec<usize>,
    pub log_heights: Vec<usize>,
    pub algebraic_bits: f64,
    pub initial_codeword_cells: usize,
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
        drop(bridge);
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
        let airs: Vec<_> = bus
            .airs()
            .iter()
            .enumerate()
            .map(|(i, a)| {
                if i == hash_index {
                    Ok(Chip::Keccak {
                        preprocessing: RowMajorMatrix::new(preprocessing.clone(), 3),
                    })
                } else {
                    Chip::import(a.clone(), bus.log_heights()[i])
                }
            })
            .collect::<Result<_>>()?;
        // Canonically bind the actual imported AIR and preprocessing, not a prover-supplied identity.
        let mut identity = Keccak256::new();
        identity.update(b"imt-flock-backend-v3/708900d7a730d6ce4d5421d43e2193f2301920fa");
        identity.update((domain.len() as u64).to_le_bytes());
        identity.update(domain);
        identity.update(hash.digest());
        for a in &airs {
            identity.update((a.width() as u64).to_le_bytes());
            identity.update((a.num_public_values() as u64).to_le_bytes());
            identity.update(a.periodic_statement());
            let s = p3_bus::BusSymbolicBuilder::<F, F>::from_air(a, p3_air::AirLayout::from_air(a));
            identity.update(format!("{:?}{:?}", s.base_constraints(), s.interactions()).as_bytes());
            if let Some(pp) = a.preprocessed_trace() {
                identity.update((pp.width as u64).to_le_bytes());
                identity.update((pp.values.len() as u64).to_le_bytes());
                for value in pp.values {
                    identity.update(value.to_repr().to_le_bytes());
                }
            } else {
                identity.update(0u64.to_le_bytes());
            }
        }
        let seed = identity.finalize().to_vec();
        let mut log_heights = bus.log_heights().to_vec();
        log_heights[hash_index] = log_calls;
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
        let mut regions = vec![0; airs.len()];
        regions[hash_index] = 1;
        eprintln!(
            "Flock tables: widths {:?}, log heights {:?}, {calls} Keccak calls",
            airs.iter().map(BaseAir::width).collect::<Vec<_>>(),
            log_heights
        );
        let config = Config::new(&shapes, regions, &pp)?;
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
            keccak_permutations: calls,
            table_widths: airs.iter().map(BaseAir::width).collect(),
            log_heights: log_heights.clone(),
            algebraic_bits,
            initial_codeword_cells: config.initial_codeword_cells,
            security_terms: terms,
        };
        Ok(Self {
            circuit,
            bus,
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
        let mut runner = self.circuit.runner();
        runner.set_public_inputs(public)?;
        runner.set_private_inputs(private)?;
        let witness = runner.run_witness()?;
        let mut source = self.bus.column_major_tables(&witness)?;
        drop(witness);
        let bridge = &source[self.hash_index + 1];
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
        for (i, table) in source.drain(..).enumerate() {
            if i == self.hash_index {
                tables.push(None);
                continue;
            }
            let height = 1 << table.num_variables();
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
        Ok(self
            .bus
            .public_values(values)?
            .into_iter()
            .map(|v| v.into_iter().map(convert).collect())
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
