use alloc::vec::Vec;

use p3_baby_bear::BabyBear;
use p3_binary_field::{Poly64, Poly192};
use p3_field::extension::BinomialExtensionField;
use p3_field::{Algebra, Field};
use p3_matrix::dense::RowMajorMatrix;
use p3_multilinear_util::poly::Poly;
use p3_sumcheck::layout::{ColumnView, Table};
use rand::distr::{Distribution, StandardUniform};
use rand::rngs::SmallRng;
use rand::{RngExt, SeedableRng};

use super::{DEFERRED_FOLD_ROWS, Source};

fn compare<F, EF>(column: ColumnView<'_, F>, rng: &mut SmallRng)
where
    F: Field,
    EF: Field + Algebra<F>,
    StandardUniform: Distribution<EF>,
{
    for first in [EF::ZERO, EF::ONE, rng.random()] {
        let mut source = Source::Committed(column);
        let mut dense = Poly::new(column.values().map(EF::from).collect());
        source.fold(first);
        dense.fix_prefix_var_mut(first);
        assert!(matches!(source, Source::Deferred { .. }));
        for row in 0..dense.num_evals() {
            assert_eq!(source.at(row), dense.as_slice()[row]);
        }
        let mut round = 0;
        while dense.num_evals() > 1 {
            let half = dense.num_evals() / 2;
            for node in [EF::ZERO, EF::ONE, rng.random()] {
                for row in 0..half {
                    let low = dense.as_slice()[row];
                    let high = dense.as_slice()[row + half];
                    assert_eq!(
                        source.interpolate(row, half, node),
                        low + (high - low) * node
                    );
                }
            }
            let challenge = match round % 3 {
                0 => EF::ZERO,
                1 => EF::ONE,
                _ => rng.random(),
            };
            source.fold(challenge);
            dense.fix_prefix_var_mut(challenge);
            let Source::Folded(actual) = &source else {
                panic!("second and later folds must materialize the surviving rows");
            };
            assert_eq!(actual, &dense);
            round += 1;
        }
    }
}

fn check<F, EF>()
where
    F: Field,
    EF: Field + Algebra<F>,
    StandardUniform: Distribution<F> + Distribution<EF>,
{
    let mut rng = SmallRng::seed_from_u64(0xDEFE_2219);
    let height = DEFERRED_FOLD_ROWS;
    let values = (0..2 * height).map(|_| rng.random()).collect::<Vec<F>>();
    let table = Table::new(RowMajorMatrix::new(values, height));
    compare::<F, EF>(table.column(1), &mut rng);
    let words = (0..2 * height / 64)
        .map(|_| rng.random())
        .collect::<Vec<u64>>();
    let packed = Table::<F>::from_packed_bits(
        RowMajorMatrix::new(words, 2),
        height.trailing_zeros() as usize,
    );
    compare::<F, EF>(packed.column(1), &mut rng);
}

#[test]
fn deferred_bus_columns_match_every_dense_round() {
    check::<Poly64, Poly192>();
    check::<BabyBear, BinomialExtensionField<BabyBear, 4>>();
}
