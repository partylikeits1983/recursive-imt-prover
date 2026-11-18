use old_binary_field::{Poly64 as F, TowerLevel};
use p3_binary_field::TowerLevel as NewTowerLevel;

use super::{GateLayout, partition};

const LAYOUT: [GateLayout; 3] = [
    GateLayout::new([64, 64, 64, 0, 64], 4, [64; 14]),
    GateLayout::new([64, 64, 64, 0, 64], 4, [64; 14]),
    GateLayout::new([16, 0, 16, 0, 16], 4, [64; 14]),
];

fn rows(count: usize) -> Vec<F> {
    let mut values = vec![F::from_repr(0); 14 * count.next_power_of_two()];
    for row in values.as_chunks_mut::<14>().0.iter_mut().take(count) {
        row[0] = F::from_repr(1);
        row[1] = F::from_repr(2);
        row[4] = F::from_repr(3);
        row[8] = F::from_repr(1);
    }
    values
}

#[test]
fn fixed_layout_preserves_empty_tables_and_every_source_row() {
    for count in [5, 18] {
        let source = rows(count);
        let shards = partition(&[0, 64, 64, 64], &source, 14, 5, &[], Some(&LAYOUT)).unwrap();
        assert_eq!(shards.len(), LAYOUT.len());
        assert!(shards.last().unwrap().source_rows.is_empty());
        assert_eq!(
            shards
                .iter()
                .flat_map(|s| s.source_rows.iter().copied())
                .collect::<Vec<_>>(),
            (0..count as u32).collect::<Vec<_>>()
        );
        for (shard, layout) in shards.iter().zip(LAYOUT) {
            let (widths, log) = (layout.main, layout.log_height);
            assert_eq!(shard.coordinate_widths, widths);
            assert_eq!(shard.log_height, log);
            assert_eq!(shard.preprocessing_widths, layout.preprocessing);
            let pp = shard.preprocessing();
            assert_eq!(pp.width, 14);
            assert_eq!(pp.values.len(), 14 << log);
            for (row, &index) in pp.values.as_chunks::<14>().0.iter().zip(&shard.source_rows) {
                let expected = &source[index as usize * 14..(index as usize + 1) * 14];
                assert!(
                    row.iter()
                        .zip(expected)
                        .all(|(a, b)| a.to_repr() == b.to_repr())
                );
            }
            assert!(
                pp.values[shard.source_rows.len() * 14..]
                    .iter()
                    .all(|v| v.to_repr() == 0)
            );
        }
    }
}

#[test]
fn fixed_layout_rejects_overflow_and_invalid_sources() {
    let source = rows(17);
    let widths = [0, 64, 64, 64];
    assert!(partition(&widths, &source, 14, 5, &[], Some(&LAYOUT[..1])).is_err());
    let mut removed = vec![false; 17];
    removed[1] = true;
    let shards = partition(&widths, &source, 14, 5, &removed, Some(&LAYOUT[..1])).unwrap();
    assert_eq!(shards[0].source_rows.len(), 16);
    assert!(!shards[0].source_rows.contains(&1));
    let mut bad = source.clone();
    bad[0] = F::from_repr(99);
    assert!(partition(&widths, &bad, 14, 5, &[], Some(&LAYOUT)).is_err());
    bad[..14].fill(F::from_repr(0));
    assert!(partition(&widths, &bad, 14, 5, &[], Some(&LAYOUT)).is_err());
    assert!(partition(&widths, &source, 14, 3, &[], Some(&LAYOUT)).is_err());
    assert!(partition(&widths, &source, 14, 5, &[], Some(&LAYOUT[2..])).is_err());
    assert!(partition(&widths, &source, 14, 5, &[], Some(&[])).is_err());
}

#[test]
fn fixed_gate_columns_must_be_zero_before_they_are_omitted() {
    let omitted = [3, 5, 11];
    let layout = [GateLayout::new(
        [64; 5],
        4,
        core::array::from_fn(|i| if omitted.contains(&i) { 0 } else { 64 }),
    )];
    let mut source = rows(5);
    let widths = [0, 64, 64, 64];
    let shards = partition(&widths, &source, 14, 5, &[], Some(&layout)).unwrap();
    let pp = shards[0].compact_preprocessing();
    assert_eq!(pp.width, 11);
    let live: Vec<_> = source[..14]
        .iter()
        .enumerate()
        .filter(|(column, _)| !omitted.contains(column))
        .map(|(_, v)| v.to_repr())
        .collect();
    assert!(pp.values[..11].iter().map(|v| v.to_repr()).eq(live));
    for column in omitted {
        source[column] = F::from_repr(1);
        assert!(partition(&widths, &source, 14, 5, &[], Some(&layout)).is_err());
        source[column] = F::from_repr(0);
    }
}

#[test]
fn wide_coefficients_use_the_general_gate_table() {
    let mut narrow = [64; 14];
    narrow[5] = 1;
    let layout = [
        GateLayout::new([16, 0, 16, 0, 16], 4, narrow),
        GateLayout::new([64, 0, 64, 0, 64], 4, [64; 14]),
    ];
    let mut rows = [F::from_repr(0); 28];
    for (row, coefficient) in rows.as_chunks_mut::<14>().0.iter_mut().zip([1, 2]) {
        row[0] = F::from_repr(1);
        row[2] = F::from_repr(2);
        row[4] = F::from_repr(3);
        row[5] = F::from_repr(coefficient);
        row[12] = F::from_repr(1);
    }
    let groups = partition(&[0, 16, 16, 16], &rows, 14, 5, &[], Some(&layout)).unwrap();
    assert_eq!(groups[0].source_rows, [0]);
    assert_eq!(groups[1].source_rows, [1]);
    assert_eq!(groups[1].preprocessing().values[5].to_repr(), 2);
}
