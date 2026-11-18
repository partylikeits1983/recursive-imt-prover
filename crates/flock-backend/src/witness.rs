use anyhow::{Result, ensure};
use old_binary_field::{Poly64 as OldF, TowerLevel};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use p3_sumcheck::layout::Table;

use crate::{F, Prepared, air::convert};

type WitnessTables = (Vec<Option<Table<F>>>, Vec<[u64; 100]>);

impl Prepared {
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
        let calls = self.calls / self.instances;
        let mut rows = Vec::with_capacity(self.calls);
        let mut values = vec![Vec::new(); self.airs.len()];
        for instance in 0..self.instances {
            let mut runner = self.circuit.runner();
            runner.set_public_inputs(
                &public[instance * public_width..(instance + 1) * public_width],
            )?;
            runner.set_private_inputs(
                &private[instance * private_width..(instance + 1) * private_width],
            )?;
            let witness = runner.run_witness()?;
            let mut source: Vec<_> = self
                .bus
                .column_major_tables(&witness)?
                .into_iter()
                .map(Some)
                .collect();
            drop(witness);
            drop(source[self.source_hash_index].take());
            let bridge = source[self.source_hash_index + 1].as_ref().unwrap();
            rows.extend(
                (0..calls)
                    .map(|i| core::array::from_fn(|j| bridge.column(j).value(2 * i).to_repr())),
            );
            for (i, mapping) in self.sources.iter().enumerate() {
                if i == self.hash_index {
                    continue;
                }
                let table = source[mapping.index].as_ref().unwrap().clone();
                if self
                    .sources
                    .get(i + 1)
                    .is_none_or(|next| next.index != mapping.index)
                {
                    drop(source[mapping.index].take());
                }
                let height = 1 << self.log_heights[i];
                if self.airs[i].is_public_table() {
                    values[i].resize(height, F::ZERO);
                    continue;
                }
                let offset = values[i].len();
                values[i].resize(offset + self.airs[i].instance_width() * height, F::ZERO);
                let output = &mut values[i][offset..];
                if let Some(shard) = &mapping.shard {
                    let column = table.column(0);
                    for (r, row) in shard.rows.iter().enumerate() {
                        output[r + 1] = convert(column.value(row.source_row as usize));
                    }
                } else if let Some(shard) = &mapping.gates {
                    for c in 0..table.num_polys() {
                        let column = table.column(c);
                        for (r, &source_row) in shard.source_rows.iter().enumerate() {
                            output[c * height + r] = convert(column.value(source_row as usize));
                        }
                    }
                } else {
                    for c in 0..table.num_polys() {
                        let column = table.column(c);
                        for r in 0..height {
                            output[c * height + r] = convert(column.value(r));
                        }
                    }
                }
                if self.airs[i].has_successor() {
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
                (i != self.hash_index)
                    .then(|| Table::new(RowMajorMatrix::new(values, 1 << self.log_heights[i])))
            })
            .collect();
        Ok((tables, rows))
    }
}
