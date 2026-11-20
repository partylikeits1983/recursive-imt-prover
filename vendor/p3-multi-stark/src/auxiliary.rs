//! Append application-owned tables to the main commitment. The caller fixes
//! their layout, derives their prescribed points and checks their opened values.
use alloc::vec::Vec;
use p3_sumcheck::{OpeningProtocol, TableSpec};

pub fn append_protocol(main: OpeningProtocol, extra: &[TableSpec]) -> OpeningProtocol {
    if extra.is_empty() {
        return main;
    }
    let shapes = main.table_shapes();
    let mut schedules = alloc::vec![Vec::new(); shapes.len()];
    for (t, batch) in main.iter_openings() {
        schedules[t].push(batch.clone());
    }
    let mut tables: Vec<_> = shapes
        .into_iter()
        .zip(schedules)
        .map(|(shape, batches)| TableSpec::new(shape, batches))
        .collect();
    tables.extend_from_slice(extra);
    OpeningProtocol::new(tables)
}
