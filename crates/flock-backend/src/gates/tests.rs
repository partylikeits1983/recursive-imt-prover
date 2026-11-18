use old_binary_field::{Poly64 as F, TowerLevel};
use p3_binary_field::TowerLevel as NewTowerLevel;

use super::{GateLayout, partition};

const LAYOUT: [GateLayout; 3] = [
    ([64, 64, 64, 0, 64], 4),
    ([64, 64, 64, 0, 64], 4),
    ([16, 0, 16, 0, 16], 4),
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
        for (shard, (widths, log)) in shards.iter().zip(LAYOUT) {
            assert_eq!(shard.coordinate_widths, widths);
            assert_eq!(shard.log_height, log);
            assert_eq!(shard.zero_columns, [false; 14]);
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
