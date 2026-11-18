use std::borrow::Cow;

use anyhow::Result;
use old_air::{Air, AirBuilder, BaseAir};
use old_binary_field::{Poly64 as F, Poly192 as E};
use old_multilinear_util::point::Point;
use p3_circuit::CircuitBuilder;
use p3_recursion::verifier::BinaryPolyAirConstraintPlan;

struct AddressAir {
    log: usize,
    successor: bool,
    corrupted: bool,
}

impl BaseAir<F> for AddressAir {
    fn width(&self) -> usize {
        1
    }
    fn main_next_row_columns(&self) -> Vec<usize> {
        vec![]
    }
    fn num_periodic_columns(&self) -> usize {
        1
    }
    fn periodic_columns(&self) -> Cow<'_, [Vec<F>]> {
        let size = 1usize << self.log;
        let mut values: Vec<_> = (0..size)
            .map(|i| F::new(((i + usize::from(self.successor)) & (size - 1)) as u64))
            .collect();
        if self.corrupted {
            values[3] = F::new(values[3].to_bits() ^ 1);
        }
        Cow::Owned(vec![values])
    }
}

impl<B: AirBuilder<F = F>> Air<B> for AddressAir {
    fn eval(&self, b: &mut B) {
        b.assert_zero(b.periodic_values()[0]);
    }
}

#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "million-row periodic reference; run with --release"
)]
fn compact_addresses_match_dense_extensions_and_preserve_non_address_tables() -> Result<()> {
    for (log, corrupted) in [(0, false), (1, false), (4, false), (4, true), (20, false)] {
        for successor in [false, true] {
            let air = AddressAir {
                log,
                successor,
                corrupted,
            };
            let plan = BinaryPolyAirConstraintPlan::from_air(&air, log)?;
            let mut b = CircuitBuilder::<F>::new();
            let point: Vec<_> = (0..log)
                .map(|_| {
                    let limbs = b.alloc_public_input_array::<3>("row point");
                    b.native_poly192_from_coefficients(limbs)
                })
                .collect();
            let zero = b.native_poly192_constant([0; 3]);
            let alpha = b.native_poly192_constant([7, 3, 1]);
            let value = plan.evaluate_native(&mut b, &point, &[zero], &[], &[], &alpha)?;
            let expected = b.alloc_public_input_array::<3>("address evaluation");
            for (&a, e) in value.coefficients().iter().zip(expected) {
                b.connect(a, e);
            }
            let circuit = b.build()?;
            assert!(
                circuit.witness_count < 2000,
                "address expansion at log {log}"
            );
            for case in 0..3 {
                let point: Vec<E> = (0..log)
                    .map(|i| {
                        E::new(if case < 2 {
                            [F::new(case), F::new(0), F::new(0)]
                        } else {
                            [F::new(i as u64 + 2), F::new(3), F::new(7)]
                        })
                    })
                    .collect();
                let periods = air.periodic_columns();
                let weights = Point::new(point.as_slice()).equality_weights_msb();
                let expected: E = periods[0].iter().zip(weights).map(|(&v, w)| w * v).sum();
                let public: Vec<_> = point
                    .iter()
                    .chain([&expected])
                    .flat_map(|v| v.coefficients())
                    .collect();
                let mut runner = circuit.runner();
                runner.set_public_inputs(&public)?;
                runner.run_witness()?;
            }
        }
    }
    Ok(())
}
