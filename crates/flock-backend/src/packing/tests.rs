use anyhow::Result;
use old_binary_field::{Poly64 as OldF, TowerLevel as OldTowerLevel};
use p3_air::check_all_constraints;
use p3_binary_field::TowerLevel;
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;

use super::{PackedShard, Packing, TERMS, WIDTH};
use crate::{F, air::Chip};

struct Fixture {
    gates: Vec<OldF>,
    fanout: Vec<OldF>,
    widths: Vec<u8>,
    values: Vec<F>,
}

fn fixture(count: usize) -> Fixture {
    let mut values = vec![F::ZERO; 2 * count + 2];
    let mut widths = vec![64; values.len()];
    widths[0] = 0;
    widths[1..=count].fill(1);
    let mut gates = vec![OldF::from_repr(0); count.next_power_of_two() * 14];
    let mut ids = Vec::new();
    values[count + 1] = F::from_repr(0xa55a);
    for (i, row) in gates
        .as_chunks_mut::<14>()
        .0
        .iter_mut()
        .take(count)
        .enumerate()
    {
        let bit = i + 1;
        let previous = count + i + 1;
        let out = previous + 1;
        let coefficient = 0x9e3779b97f4a7c15u64.rotate_left(i as u32);
        row[0] = OldF::from_repr(bit as u64);
        row[2] = OldF::from_repr(previous as u64);
        row[4] = OldF::from_repr(out as u64);
        row[5] = OldF::from_repr(coefficient);
        row[12 + i % 2] = OldF::from_repr(1);
        values[bit] = F::from_bool(i % 3 != 0);
        values[out] = values[previous] + values[bit] * F::from_repr(coefficient);
        ids.extend([bit, previous, out]);
    }
    ids.push(2 * count + 1);
    ids.sort_unstable();
    let fanout = ids
        .into_iter()
        .flat_map(|id| [id as u64, 1, 0].map(OldF::from_repr))
        .collect();
    Fixture {
        gates,
        fanout,
        widths,
        values,
    }
}

fn trace(shard: &PackedShard, values: &[F]) -> RowMajorMatrix<F> {
    let mut main = vec![F::ZERO; WIDTH * (1 << shard.log_height)];
    for (row, packed) in main.as_chunks_mut::<WIDTH>().0.iter_mut().zip(&shard.rows) {
        for (column, &id) in packed.ids.iter().enumerate() {
            if column < packed.sources.len() || column >= TERMS {
                row[column] = values[id as usize];
            }
        }
    }
    RowMajorMatrix::new(main, WIDTH)
}

#[test]
fn packed_chains_preserve_equations_and_every_retained_copy() -> Result<()> {
    let fixture = fixture(37);
    let packing = Packing::new(&fixture.widths, &fixture.gates, 14, 5, &fixture.fanout)?;
    let shard = packing.shard.as_ref().unwrap();
    assert_eq!(
        shard
            .rows
            .iter()
            .map(|r| r.sources.len())
            .collect::<Vec<_>>(),
        [16, 16, 5]
    );
    assert_eq!(packing.removed_ids.iter().filter(|&&v| v).count(), 34);
    assert_eq!(packing.removed_rows.iter().filter(|&&v| v).count(), 37);

    let air = Chip::packed(shard.clone());
    let main = trace(shard, &fixture.values);
    assert!(check_all_constraints(&air, &main, &[], Some(1)).is_ok());
    let mut original = Vec::new();
    for row in fixture.gates.as_chunks::<14>().0.iter().take(37) {
        for column in [0, 2, 4] {
            let id = row[column].to_repr() as usize;
            if !packing.removed_ids[id] {
                original.push((id, fixture.values[id].to_repr()));
            }
        }
    }
    let mut packed: Vec<_> = shard
        .rows
        .iter()
        .flat_map(|r| {
            r.ids.iter().enumerate().filter_map(|(column, &id)| {
                (column < r.sources.len() || column >= TERMS)
                    .then_some((id as usize, fixture.values[id as usize].to_repr()))
            })
        })
        .collect();
    original.sort_unstable();
    packed.sort_unstable();
    assert_eq!(original, packed);

    for row in 0..shard.rows.len() {
        let mut bad = main.clone();
        bad.values[row * WIDTH + TERMS + 1] += F::ONE;
        assert!(!check_all_constraints(&air, &bad, &[], Some(1)).is_ok());
        // Keep the linear equation valid while violating one bit's Booleanity.
        let mut bad = main.clone();
        bad.values[row * WIDTH] += F::from_repr(2);
        bad.values[row * WIDTH + TERMS + 1] +=
            F::from_repr(2) * F::from_repr(shard.rows[row].coefficients[0]);
        assert!(!check_all_constraints(&air, &bad, &[], Some(1)).is_ok());
    }
    Ok(())
}

#[test]
fn shared_intermediates_and_other_gate_shapes_are_preserved() -> Result<()> {
    let mut fixture = fixture(37);
    let live = 37 + 8;
    fixture
        .fanout
        .extend([live as u64, 1, 0].map(OldF::from_repr));
    let packing = Packing::new(&fixture.widths, &fixture.gates, 14, 5, &fixture.fanout)?;
    assert!(!packing.removed_ids[live]);
    assert!(
        packing
            .shard
            .as_ref()
            .unwrap()
            .rows
            .iter()
            .any(|r| r.ids[TERMS + 1] as usize == live)
    );
    fixture.widths[1..=37].fill(64);
    let packing = Packing::new(&fixture.widths, &fixture.gates, 14, 5, &fixture.fanout)?;
    assert!(packing.shard.is_none());
    assert!(!packing.removed_rows.iter().any(|&v| v));
    assert!(
        Packing::new(&fixture.widths, &fixture.gates, 14, 3, &fixture.fanout)?
            .shard
            .is_none()
    );
    assert!(Packing::new(&fixture.widths, &fixture.gates, 0, 5, &fixture.fanout).is_err());
    Ok(())
}
