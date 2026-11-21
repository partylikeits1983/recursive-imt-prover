use anyhow::{Result, ensure};
use old_binary_field::{Poly64 as OldF, TowerLevel};
use p3_binary_field::TowerLevel as NewTowerLevel;
use p3_circuit::{
    WitnessId,
    ops::{keccak_limbs_to_state, keccak_state_to_limbs},
};
use p3_field::PrimeCharacteristicRing;
use p3_keccak::KeccakF;
use p3_matrix::dense::RowMajorMatrix;
use p3_sumcheck::layout::Table;
use p3_symmetric::Permutation;

use crate::{
    F, HashBackend, Prepared,
    air::{WitnessSource, convert},
    checkpoint_keccak::{State, linked::BoundaryWitness},
};

#[cfg(test)]
mod tests;

type WitnessTables = (Vec<Option<Table<F>>>, BoundaryWitness);

pub(super) struct KeccakWires {
    input: [u32; 100],
    output: [u32; 100],
}

impl KeccakWires {
    pub fn from_bridge(
        bridge: &[OldF],
        width: usize,
        calls: usize,
        witnesses: u32,
    ) -> Result<Vec<Self>> {
        ensure!(
            matches!(width, 119 | 120) && 2 * calls <= bridge.len() / width,
            "unexpected Keccak bridge shape"
        );
        let ids = |row: &[OldF], live| -> Result<[u32; 100]> {
            let mut ids = [0; 100];
            for (i, (id, v)) in ids.iter_mut().zip(row).enumerate() {
                *id = u32::try_from(v.to_repr())?;
                ensure!(
                    *id <= witnesses && (*id != 0) == (i < live),
                    "invalid Keccak bridge wire ID"
                );
            }
            Ok(ids)
        };
        bridge
            .chunks_exact(2 * width)
            .take(calls)
            .map(|pair| {
                let (input, output) = pair.split_at(width);
                let limbs = if width == 119 || output[119].to_repr() == 1 {
                    100
                } else {
                    16
                };
                Ok(Self {
                    input: ids(input, 100)?,
                    output: ids(output, limbs)?,
                })
            })
            .collect()
    }

    fn fill(
        &self,
        read: &impl Fn(u32) -> F,
        table: &mut [F],
        height: usize,
        row: usize,
    ) -> Result<(State, State)> {
        let mut limbs = [0u16; 100];
        for (limb, &id) in limbs.iter_mut().zip(&self.input) {
            *limb = u16::try_from(read(id).to_repr())?;
        }
        let input = keccak_limbs_to_state(&limbs);
        let output = KeccakF.permute(input);
        let result = keccak_state_to_limbs(&output);
        for (i, (&value, &id)) in result.iter().zip(&self.output).enumerate() {
            ensure!(
                id == 0 || read(id).to_repr() == u64::from(value),
                "incorrect Keccak output limb"
            );
            table[i * height + row] = F::from_repr(u64::from(limbs[i]));
            table[i * height + row + 1] = F::from_repr(u64::from(value));
            if i < 16 {
                table[(100 + i) * height + row] = F::from_repr(u64::from(limbs[i].swap_bytes()));
                table[(100 + i) * height + row + 1] = F::from_repr(u64::from(value.swap_bytes()));
            }
        }
        Ok((input, output))
    }
}

impl Prepared {
    #[cfg(feature = "opening-bench")]
    pub fn write_keccak_checkpoints(
        &self,
        public: &[OldF],
        private: &[OldF],
        mut out: impl std::io::Write,
    ) -> Result<()> {
        ensure!(
            self.backend == HashBackend::Checkpoint,
            "missing Keccak checkpoints"
        );
        let (tables, states) = self.witness_tables(public, private)?;
        drop(tables);
        let segments = states.segment_inputs();
        let midpoints = &segments[states.inputs.len()..];
        for ((input, middle), output) in states.inputs.iter().zip(midpoints).zip(&states.outputs) {
            for lane in input.iter().chain(middle).chain(output) {
                out.write_all(&lane.to_le_bytes())?;
            }
        }
        out.flush()?;
        Ok(())
    }

    pub(crate) fn witness_tables(
        &self,
        public: &[OldF],
        private: &[OldF],
    ) -> Result<WitnessTables> {
        let public_width = self.circuit.public_flat_len;
        let private_width = self.circuit.private_flat_len;
        ensure!(
            public.len() == public_width * self.instances,
            "incorrect public input count"
        );
        ensure!(
            private.len() == private_width * self.instances,
            "incorrect private input count"
        );
        let boundary_rows = if self.backend == HashBackend::Checkpoint {
            1 << self.log_heights[self.hash_index]
        } else {
            self.calls
        };
        let mut boundaries = BoundaryWitness {
            inputs: Vec::with_capacity(boundary_rows),
            outputs: Vec::with_capacity(boundary_rows),
        };
        let zero_output = KeccakF.permute([0; 25]);
        let mut values: Vec<_> = self
            .airs
            .iter()
            .zip(&self.log_heights)
            .enumerate()
            .map(|(i, (air, &log))| {
                let width = if i == self.hash_index && !self.direct_bridge() {
                    0
                } else if air.is_public_table() {
                    1
                } else {
                    self.instances * air.instance_width()
                };
                F::zero_vec(width << log)
            })
            .collect();
        for instance in 0..self.instances {
            let mut runner = self.circuit.runner();
            runner.set_public_inputs(
                &public[instance * public_width..(instance + 1) * public_width],
            )?;
            runner.set_private_inputs(
                &private[instance * private_width..(instance + 1) * private_width],
            )?;
            let witness = runner.run_witness()?;
            let read = |id: u32| match id.checked_sub(1) {
                Some(index) => convert(
                    *witness
                        .get_value(WitnessId(index))
                        .expect("validated wire ID"),
                ),
                None => F::ZERO,
            };
            for (i, air) in self.airs.iter().enumerate() {
                let height = 1 << self.log_heights[i];
                let size = values[i].len() / self.instances;
                let output = &mut values[i][instance * size..(instance + 1) * size];
                match air.witness_source() {
                    WitnessSource::Public | WitnessSource::Keccak => continue,
                    WitnessSource::Fanout(shard) => {
                        for (value, row) in output[1..].iter_mut().zip(&shard.rows) {
                            *value = read(row.id);
                        }
                    }
                    WitnessSource::WireRows { ids, width, .. } => {
                        for (r, ids) in ids.chunks_exact(width).enumerate() {
                            for (column, &id) in ids.iter().enumerate() {
                                output[column * height + r] = read(id);
                            }
                        }
                    }
                    WitnessSource::Packed(shard) => {
                        for (r, row) in shard.rows.iter().enumerate() {
                            for (column, &id) in row.ids.iter().enumerate() {
                                output[column * height + r] = read(id);
                            }
                        }
                    }
                    WitnessSource::Gates(shard) => shard.fill_witness(output, read),
                    WitnessSource::Bridge => {
                        ensure!(
                            i == self.hash_index + usize::from(!self.direct_bridge())
                                && 2 * self.keccak_wires.len() <= height,
                            "invalid Keccak bridge table"
                        );
                        for (r, call) in self.keccak_wires.iter().enumerate() {
                            let (before, after) = call.fill(&read, output, height, 2 * r)?;
                            boundaries.inputs.push(before);
                            boundaries.outputs.push(after);
                        }
                        if self.direct_bridge() {
                            let count = self.keccak_wires.len();
                            let limbs = keccak_state_to_limbs(&zero_output);
                            for (column, words) in output.chunks_exact_mut(height).enumerate() {
                                let value = if column < 100 {
                                    limbs[column]
                                } else {
                                    limbs[column - 100].swap_bytes()
                                };
                                for pair in words[2 * count..].as_chunks_mut::<2>().0 {
                                    pair[1] = F::from_repr(u64::from(value));
                                }
                            }
                            boundaries.pad((instance + 1) * (height / 2), zero_output);
                        }
                    }
                }
                if air.has_successor() {
                    for r in 0..height {
                        output[height + r] = output[(r + 1).min(height - 1)];
                    }
                }
            }
        }
        let tables = values
            .into_iter()
            .enumerate()
            .map(|(i, values)| {
                (i != self.hash_index || self.direct_bridge())
                    .then(|| Table::new(RowMajorMatrix::new(values, 1 << self.log_heights[i])))
            })
            .collect();
        if self.backend == HashBackend::Checkpoint {
            boundaries.pad(boundary_rows, zero_output);
        }
        Ok((tables, boundaries))
    }
}
