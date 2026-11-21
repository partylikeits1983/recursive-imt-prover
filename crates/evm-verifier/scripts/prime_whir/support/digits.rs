//! Geometry shared by the digit sumcheck, round prover fixture and streamed commitment.
use super::segments;
use rayon::prelude::*;
use std::{fs, path::Path};

pub fn slot(segment: usize, lane: usize) -> usize {
    if segment == 8 {
        32 * (lane / 7) + 25 + lane % 7
    } else {
        32 * segment + lane
    }
}

pub fn table(bundle: &Path, row_bits: usize, digit_bits: usize) -> Vec<u8> {
    assert!((1..=16).contains(&row_bits) && matches!(digit_bits, 2 | 4));
    if bundle.is_file() {
        let table = fs::read(bundle).unwrap();
        assert_eq!(
            table.len(),
            (1usize << row_bits) * 8 * 32 * (64 / digit_bits)
        );
        assert!(table
            .iter()
            .all(|&digit| usize::from(digit) < (1usize << digit_bits)));
        return table;
    }
    let raw = fs::read(bundle.join("keccak-checkpoints.bin")).unwrap();
    assert_eq!(raw.len(), 65536 * 600);
    let rows = 1 << row_bits;
    let stride = 65536 / rows;
    let positions = 64 / digit_bits;
    let width = 8 * 32 * positions;
    let mask = (1 << digit_bits) - 1;
    let mut table = vec![0; rows * width];
    table
        .par_chunks_exact_mut(width)
        .enumerate()
        .for_each(|(i, row)| {
            let local = i % (rows / 2);
            let selected = if local == 21670 / stride {
                21670
            } else {
                local * stride
            };
            let original = i / (rows / 2) * 32768 + selected;
            let trace = &raw[original * 600..original * 600 + 600];
            segments::visit_states(&trace[..200], Some(trace), |segment, bytes| {
                for (lane, chunk) in bytes.chunks_exact(8).enumerate() {
                    let col = positions * slot(segment, lane);
                    for (j, d) in row[col..col + positions].iter_mut().enumerate() {
                        let bit = j * digit_bits;
                        *d = (chunk[bit / 8] >> (bit % 8)) & mask;
                    }
                }
            });
        });
    table
}
