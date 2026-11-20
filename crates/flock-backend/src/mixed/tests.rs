use super::expand_bounded_block;
use p3_binary_field::{BinaryField128, TowerLevel};

#[test]
fn packed_boolean_openings_share_only_identity_encoded_tables() -> anyhow::Result<()> {
    use crate::{F, config::pcs, encoding::TableEncoding};
    use p3_matrix::dense::RowMajorMatrix;
    use p3_sumcheck::{TableShape, layout::Table};

    let small = TableShape::new(4, 2);
    let large = TableShape::new(16, 2);
    let pcs = pcs(
        &[small, large, small],
        vec![
            TableEncoding::new(vec![1, 1])?,
            TableEncoding::new(vec![1, 1])?,
            TableEncoding::new(vec![1, 0])?,
        ],
    )?;
    for (i, shape) in [small, large].into_iter().enumerate() {
        let blocks = (1usize << shape.num_variables()).div_ceil(64);
        let table = Table::<F>::from_packed_bits(
            RowMajorMatrix::new(vec![0xabcd; blocks * 2], 2),
            shape.num_variables(),
        );
        let encoded = pcs.expand_table::<()>(i, &table).unwrap();
        assert!(core::ptr::eq(
            table.packed_bits().unwrap(),
            encoded.packed_bits().unwrap()
        ));
        if i == 0 {
            assert!(pcs.expand_table::<()>(2, &table).is_err());
        }
    }
    Ok(())
}

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
