use old_binary_field::{Poly64 as OldF, TowerLevel as OldTowerLevel};
use p3_binary_field::{Poly192, TowerLevel};
use p3_field::PrimeCharacteristicRing;
use p3_flock::Witness;
use p3_keccak::KeccakF;
use p3_symmetric::Permutation;

use crate::{F, keccak};

#[test]
fn field_versions_have_identical_polynomial_arithmetic() {
    let mut state = 0x123456789abcdef0u64;
    for _ in 0..1000 {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let x = state;
        let y = state.rotate_right(23) ^ u64::MAX;
        assert_eq!(
            (OldF::from_repr(x) * OldF::from_repr(y)).to_repr(),
            (F::from_repr(x) * F::from_repr(y)).to_repr()
        );
    }
}

#[test]
fn flock_ports_match_native_keccak_and_byte_swaps() {
    let circuit = keccak::circuit();
    let inputs: Vec<[u64; 100]> = (0..16)
        .map(|i| core::array::from_fn(|j| (((i * 100 + j) * 317) & 0xffff) as u64))
        .collect();
    let witness = Witness::generate(&circuit, 4, &inputs, &[0; 100], |row, words| {
        words.copy_from_slice(row)
    });
    let stride = (1 << circuit.k_log()) / 64;
    for (row, packed) in inputs.iter().zip(witness.z().chunks_exact(stride)) {
        let mut state: [u64; 25] =
            core::array::from_fn(|i| (0..4).fold(0, |word, j| word | row[4 * i + j] << (16 * j)));
        KeccakF.permute_mut(&mut state);
        let output = circuit.output_words(packed);
        for i in 0..100 {
            assert_eq!(output[i], (state[i / 4] >> (16 * (i % 4))) & 0xffff);
        }
        for i in 0..16 {
            assert_eq!(output[100 + i], u64::from((row[i] as u16).swap_bytes()));
            assert_eq!(output[116 + i], u64::from((output[i] as u16).swap_bytes()));
        }
    }
}

#[test]
fn periodic_successor_addresses_match_their_actual_tables() {
    for log in 1..9 {
        let point: Vec<_> = (0..log)
            .map(|i| Poly192::from(F::from_repr(1234567u64 << i)))
            .collect();
        let height = 1 << log;
        let mut direct = vec![Poly192::ZERO; 2];
        for row in 0..height {
            let weight = point
                .iter()
                .enumerate()
                .map(|(i, &x)| {
                    if (row >> (log - 1 - i)) & 1 == 1 {
                        x
                    } else {
                        Poly192::ONE - x
                    }
                })
                .product::<Poly192>();
            direct[0] += weight * F::from_repr(row as u64);
            direct[1] += weight * F::from_repr(((row + 1) % height) as u64);
        }
        assert_eq!(crate::air::successor_values(&point), direct);
    }
}
