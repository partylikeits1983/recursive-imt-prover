//! Factored storage for a multilinear equality polynomial and its bound prefix.

use alloc::vec::Vec;

use p3_field::Field;
use p3_multilinear_util::point::Point;

/// `prefix * eq(point, row)` in MSB-first row order, stored in two short tables.
pub(super) struct FactoredEquality<F> {
    point: Vec<F>,
    prefix: F,
    high: Vec<F>,
    low: Vec<F>,
    low_variables: usize,
}

impl<F: Field> FactoredEquality<F> {
    pub(super) fn new(point: Vec<F>) -> Self {
        let mut result = Self {
            point,
            prefix: F::ONE,
            high: Vec::new(),
            low: Vec::new(),
            low_variables: 0,
        };
        result.rebuild();
        result
    }

    pub(super) fn len(&self) -> usize {
        1usize << self.point.len()
    }

    pub(super) fn num_variables(&self) -> usize {
        self.point.len()
    }

    #[inline]
    pub(super) fn at(&self, row: usize) -> F {
        self.high[row >> self.low_variables] * self.low[row & (self.low.len() - 1)]
    }

    #[inline]
    pub(super) fn sum_endpoints(&self, row: usize) -> F {
        let hi = row >> self.low_variables;
        (self.high[hi] + self.high[hi + self.high.len() / 2]) * self.low[row & (self.low.len() - 1)]
    }

    pub(super) fn fix_prefix_var_mut(&mut self, challenge: F) {
        let anchor = self.point.remove(0);
        self.prefix *= Point::eval_eq(&[anchor], &[challenge]);
        self.rebuild();
    }

    pub(super) fn sum_prefix_var_mut(&mut self) {
        // The two endpoints of an unbound equality factor sum to one.
        self.point.remove(0);
        self.rebuild();
    }

    fn rebuild(&mut self) {
        self.low_variables = self.point.len() / 2;
        let split = self.point.len() - self.low_variables;
        self.high = Point::new(&self.point[..split]).equality_weights_msb();
        self.low = Point::new(&self.point[split..]).equality_weights_msb();
        for weight in &mut self.high {
            *weight *= self.prefix;
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use p3_binary_field::{Poly64, Poly192};
    use p3_field::Field;
    use p3_multilinear_util::{point::Point, poly::Poly};
    use rand::distr::{Distribution, StandardUniform};
    use rand::rngs::SmallRng;
    use rand::{RngExt, SeedableRng};

    use super::FactoredEquality;

    fn compare<F: Field>()
    where
        StandardUniform: Distribution<F>,
    {
        let mut rng = SmallRng::seed_from_u64(0xe9_2026);
        for variables in 0usize..=16 {
            for mode in 0..4 {
                let point = (0..variables)
                    .map(|_| match mode {
                        0 => F::ZERO,
                        1 => F::ONE,
                        _ => rng.random(),
                    })
                    .collect::<Vec<F>>();
                let mut dense = Poly::new(Point::new(point.as_slice()).equality_weights_msb());
                let mut factored = FactoredEquality::new(point);
                for round in 0..=variables {
                    assert_eq!(factored.num_variables(), variables - round);
                    let actual = (0..factored.len())
                        .map(|row| factored.at(row))
                        .collect::<Vec<_>>();
                    assert_eq!(actual.as_slice(), dense.as_slice());
                    assert!(
                        factored.high.len() + factored.low.len()
                            <= 2 * (1usize << (variables - round).div_ceil(2))
                    );
                    if round == variables {
                        break;
                    }
                    let half = factored.len() / 2;
                    for row in 0..half {
                        assert_eq!(
                            factored.sum_endpoints(row),
                            actual[row] + actual[row + half]
                        );
                    }
                    if mode == 3 && round % 2 == 0 {
                        factored.sum_prefix_var_mut();
                        dense.sum_prefix_var_mut();
                    } else {
                        let challenge = match mode {
                            0 => F::ONE, // Exercise a zero accumulated equality prefix.
                            1 => F::ZERO,
                            _ => rng.random(),
                        };
                        factored.fix_prefix_var_mut(challenge);
                        dense.fix_prefix_var_mut(challenge);
                    }
                }
            }
        }
    }

    #[test]
    fn factored_weights_match_dense_after_binding_and_summing() {
        compare::<Poly64>();
        compare::<Poly192>();
    }
}
