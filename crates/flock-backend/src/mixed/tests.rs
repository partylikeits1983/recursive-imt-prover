use super::expand_bounded_block;
use p3_binary_field::{BinaryField128, TowerLevel};

#[test]
fn transposed_coordinates_match_individual_bits_and_reject_high_values() {
    for width in [0, 1, 7, 16, 24, 63, 64, 65, 127, 128] {
        for height in [1, 31, 64] {
            let mut columns = vec![0u64; width];
            let mut values: Vec<_> = (0..height)
                .map(|row| {
                    let mut bits = 0u128;
                    for (bit, column) in columns.iter_mut().enumerate() {
                        if (bit * 19 + row * 7) % 17 < 8 {
                            *column |= 1 << row;
                            bits |= 1 << bit;
                        }
                    }
                    BinaryField128::from_repr(bits)
                })
                .collect();
            let mut got = vec![0; width];
            assert!(expand_bounded_block(&values, &mut got));
            assert_eq!(got, columns);
            if width < 128 {
                values[height - 1] = BinaryField128::from_repr(1u128 << width);
                assert!(!expand_bounded_block(&values, &mut vec![0; width]));
            }
        }
    }
}
