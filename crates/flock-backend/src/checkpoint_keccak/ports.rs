//! The exact native recursion Keccak port map, including byte-swapped limbs.
use p3_binary_field::TowerLevel;
use p3_challenger::FieldChallenger;
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use p3_multilinear_util::point::Point;
use p3_sumcheck::layout::Table;

use super::{E, F, POSITIONS, State, linked::PortOpening};

pub(super) const PORTS: usize = 232;
pub(super) const PORT_LOG: usize = 8;

pub(super) fn table(inputs: &[State], outputs: &[State]) -> Table<F> {
    assert_eq!(inputs.len(), outputs.len());
    let columns = (0..PORTS)
        .flat_map(|port| {
            inputs.iter().zip(outputs).map(move |(input, output)| {
                let (side, start, swapped) = location(port);
                let state = if side == 0 { input } else { output };
                let word = (state[start / 64] >> (start % 64)) as u16;
                F::from_repr(u64::from(if swapped { word.swap_bytes() } else { word }))
            })
        })
        .collect();
    Table::new(RowMajorMatrix::new(columns, inputs.len()))
}

pub(super) fn claim<C: FieldChallenger<F>>(opening: &PortOpening, ch: &mut C) -> (Vec<E>, E) {
    let point = Point::new(
        (0..PORT_LOG)
            .map(|_| ch.sample_algebra_element())
            .collect::<Vec<E>>(),
    );
    let coefficients = point.equality_weights_msb();
    let mut weights = E::zero_vec(2 * POSITIONS);
    for (port, &coefficient) in coefficients.iter().take(PORTS).enumerate() {
        let (side, start, swapped) = location(port);
        for bit in 0..16 {
            weights[side * POSITIONS + start + if swapped { bit ^ 8 } else { bit }] +=
                coefficient * E::from(F::from_repr(1 << bit));
        }
    }
    let value = opening
        .values
        .iter()
        .zip(coefficients)
        .map(|(&value, weight)| value * weight)
        .sum();
    (weights, value)
}

pub(super) fn location(port: usize) -> (usize, usize, bool) {
    match port {
        0..100 => (0, port * 16, false),
        100..200 => (1, (port - 100) * 16, false),
        200..216 => (0, (port - 200) * 16, true),
        216..232 => (1, (port - 216) * 16, true),
        _ => unreachable!(),
    }
}
