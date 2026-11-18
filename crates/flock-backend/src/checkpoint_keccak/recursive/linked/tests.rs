use anyhow::Result;
use p3_challenger::FieldChallenger;
use p3_field::PrimeCharacteristicRing;
use p3_multilinear_util::point::Point;

use super::{CF, CircuitBuilder, connect, equality_weights, port_weight};
use crate::checkpoint_keccak::{E, linked::PortOpening, ports};
use crate::config::challenger;

#[test]
fn port_weight_matches_native_at_boolean_and_extension_points() -> Result<()> {
    let mut b = CircuitBuilder::<CF>::new();
    let point: Vec<_> = (0..20)
        .map(|_| {
            let coefficients = b.alloc_public_input_array::<3>("port or closing point");
            b.native_poly192_from_coefficients(coefficients)
        })
        .collect();
    let coefficients = equality_weights(&mut b, &point[..8]);
    let actual = port_weight(&mut b, &coefficients, &point[8..]);
    let expected = b.alloc_public_input_array::<3>("native weight");
    let expected = b.native_poly192_from_coefficients(expected);
    connect(&mut b, &actual, &expected);
    let circuit = b.build()?;
    let ports = PortOpening {
        instance: vec![],
        values: E::zero_vec(ports::PORTS),
    };
    let mut source = challenger(b"linked-port-weight-reference");
    for case in 0..8 {
        let mut ch = challenger(&[case]);
        let port_point: Vec<E> = (0..8).map(|_| ch.sample_algebra_element()).collect();
        let low: Vec<E> = (0..12)
            .map(|i| match case {
                0 => E::ZERO,
                1 => E::ONE,
                2 => E::from_bool(i == 0),
                3 => E::from_bool(i == 8),
                _ => source.sample_algebra_element(),
            })
            .collect();
        let (weights, _) = ports::claim(&ports, &mut challenger(&[case]));
        let value: E = weights
            .iter()
            .zip(Point::new(low.as_slice()).equality_weights_msb())
            .map(|(&a, c)| a * c)
            .sum();
        let public: Vec<_> = port_point
            .iter()
            .chain(&low)
            .chain([&value])
            .flat_map(|v| v.coefficients().map(|c| CF::new(c.to_bits())))
            .collect();
        let mut runner = circuit.runner();
        runner.set_public_inputs(&public)?;
        runner.run_witness()?;
        let mut bad = public;
        let last = bad.len() - 1;
        bad[last] = CF::new(bad[last].to_bits() ^ 1);
        let mut runner = circuit.runner();
        runner.set_public_inputs(&bad)?;
        assert!(runner.run_witness().is_err());
    }
    Ok(())
}
