use old_binary_field::{Poly64 as OldF, TowerLevel as OldTowerLevel};
use p3_air::{Air, AirBuilder, BaseAir, check_all_constraints};
use p3_binary_field::TowerLevel;
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;

use super::{Swaps, WIDTH, eval};
use crate::F;

struct SwapAir;

impl BaseAir<F> for SwapAir {
    fn width(&self) -> usize {
        WIDTH
    }
}

impl<AB: AirBuilder<F = F>> Air<AB> for SwapAir {
    fn eval(&self, builder: &mut AB) {
        eval(builder, 0);
    }
}

fn gate(x: u64, y: u64, out: u64) -> [OldF; 14] {
    let mut row = [0; 14];
    row[..5].copy_from_slice(&[1, x, y, 0, out]);
    row[7] = 1;
    row.map(OldF::from_repr)
}

#[test]
fn paired_selects_preserve_both_outputs_and_wire_multiplicities() {
    let gates = [gate(2, 3, 4), gate(3, 2, 5)];
    let widths = [0, 1, 16, 16, 16, 16];
    let mut removed = [false; 2];
    let mut uses = [0; 6];
    let swaps = Swaps::extract(&gates, &widths, &mut removed, &mut uses).unwrap();
    assert_eq!(swaps.rows, [[1, 3, 2, 5, 4]]);
    assert_eq!(removed, [true, true]);
    assert_eq!(uses, [0, 1, 1, 1, 0, 0]);
    let x = F::from_repr(123);
    let y = F::from_repr(456);
    for s in [F::ZERO, F::ONE, F::from_repr(7)] {
        let values = [s, x, y, s * (x - y) + y, s * (y - x) + x];
        let accepts = |row: [F; WIDTH]| {
            check_all_constraints(
                &SwapAir,
                &RowMajorMatrix::new(row.to_vec(), WIDTH),
                &[],
                Some(1),
            )
            .is_ok()
        };
        assert!(accepts(values));
        for column in [3, 4] {
            let mut invalid = values;
            invalid[column] += F::ONE;
            assert!(!accepts(invalid));
        }
    }
}

#[test]
fn unmatched_or_ineligible_rows_keep_their_original_constraints() {
    for kind in 0..6 {
        let mut gates = [gate(2, 3, 4), gate(3, 2, 5)];
        let mut widths = [0, 1, 16, 16, 16, 16];
        let mut removed = [false; 2];
        match kind {
            0 => removed[1] = true,
            1 => gates[1][8] = OldF::from_repr(1),
            2 => gates[1][1] = OldF::from_repr(2),
            3 => widths[1] = 16,
            4 => widths[3] = 64,
            _ => gates[0][1] = OldF::from_repr(0),
        }
        let before = removed;
        let mut uses = [0; 6];
        assert!(
            Swaps::extract(&gates, &widths, &mut removed, &mut uses)
                .unwrap()
                .rows
                .is_empty()
        );
        assert_eq!(uses, [0; 6]);
        assert_eq!(removed, before);
    }
}
