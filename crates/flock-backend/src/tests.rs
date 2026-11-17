use old_binary_field::{Poly64 as OldF, TowerLevel as OldTowerLevel};
use p3_binary_field::{Poly192, TowerLevel};
use p3_commit::MultilinearPcs;
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};
use p3_flock::Witness;
use p3_keccak::KeccakF;
use p3_matrix::dense::RowMajorMatrix;
use p3_multilinear_util::{point::Point, poly::Poly};
use p3_sumcheck::{
    OpeningBatch, OpeningProtocol, PrescribedPointPcs, TableShape, TableSpec, layout::Table,
};
use p3_symmetric::Permutation;

use crate::{
    F,
    config::{challenger, pcs},
    encoding::TableEncoding,
    keccak,
};

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

#[test]
fn bounded_coordinates_bind_current_and_successor_openings() {
    let widths = [vec![1, 8, 1, 16, 64], vec![3, 16]];
    let shapes = [TableShape::new(8, 5), TableShape::new(4, 2)];
    let encodings: Vec<_> = widths
        .iter()
        .map(|v| TableEncoding::new(v.clone()).unwrap())
        .collect();
    let pcs = pcs(&shapes, encodings).unwrap();
    let tables: Vec<_> = shapes
        .iter()
        .zip(&widths)
        .map(|(shape, widths)| {
            let rows = 1 << shape.num_variables();
            let values = widths
                .iter()
                .enumerate()
                .flat_map(|(column, &width)| {
                    (0..rows).map(move |row| {
                        let raw = ((row as u64 + 1).wrapping_mul(0x9e3779b97f4a7c15))
                            .rotate_left(column as u32 * 7);
                        F::from_repr(raw & (u64::MAX >> (64 - width)))
                    })
                })
                .collect();
            Table::new(RowMajorMatrix::new(values, rows))
        })
        .collect();
    let protocol = OpeningProtocol::new(vec![
        TableSpec::new(
            shapes[0],
            vec![OpeningBatch::new(vec![4, 1, 0, 2], vec![3, 2])],
        ),
        TableSpec::new(shapes[1], vec![OpeningBatch::new(vec![1, 0], vec![0, 1])]),
    ]);
    let points: Vec<_> = shapes
        .iter()
        .map(|shape| {
            Point::new(
                (0..shape.num_variables())
                    .map(|i| {
                        Poly192::from_basis_coefficients_fn(|j| {
                            F::from_repr((1234567 + i as u64).rotate_left(17 * j as u32))
                        })
                    })
                    .collect(),
            )
        })
        .collect();
    let seed = b"bounded-coordinate-opening-test";
    let mut prover = challenger(seed);
    let (commitment, data) = pcs.commit(tables.clone(), &mut prover).unwrap();
    let proof = pcs.open_at(data, &protocol, &points, &mut prover).unwrap();
    let mut verifier = challenger(seed);
    pcs.observe_commitment(&commitment, &mut verifier);
    let evals = pcs
        .verify_at(&commitment, &proof, &protocol, &points, &mut verifier)
        .unwrap();
    for (((table, batch), point), actual) in protocol.iter_openings().zip(&points).zip(evals) {
        for (&column, &got) in batch.current().iter().zip(actual.current()) {
            assert_eq!(
                got,
                Poly::new(tables[table].poly(column).as_slice().to_vec()).eval_base(point)
            );
        }
        for (&column, &got) in batch.next().iter().zip(actual.next()) {
            let values = tables[table].poly(column).as_slice().to_vec();
            let shifted: Vec<_> = (0..values.len())
                .map(|r| values[(r + 1).min(values.len() - 1)])
                .collect();
            assert_eq!(got, Poly::new(shifted).eval_base(point));
        }
    }
    for index in [0, 1, 8, 9, 10, 25, 89, 179, proof.values.len() - 1] {
        let mut tampered = proof.clone();
        tampered.values[index] += Poly192::ONE;
        let mut verifier = challenger(seed);
        pcs.observe_commitment(&commitment, &mut verifier);
        assert!(
            pcs.verify_at(&commitment, &tampered, &protocol, &points, &mut verifier)
                .is_err()
        );
    }
    // A source column outside its declared subspace must not be truncated into
    // a different statement, including a Boolean column after dense columns.
    for (table, column) in [(0, 0), (0, 1), (0, 2), (0, 3), (1, 0), (1, 1)] {
        let mut invalid = tables.clone();
        let rows = 1 << shapes[table].num_variables();
        let mut values: Vec<_> = (0..shapes[table].width())
            .flat_map(|c| invalid[table].poly(c).as_slice().to_vec())
            .collect();
        values[column * rows + rows - 1] += F::from_repr(1 << widths[table][column]);
        invalid[table] = Table::new(RowMajorMatrix::new(values, rows));
        assert!(pcs.commit(invalid, &mut challenger(seed)).is_err());
    }
    for invalid in [vec![], vec![0], vec![65]] {
        assert!(TableEncoding::new(invalid).is_err());
    }
    for (width, column) in [(4, 0), (6, 0)] {
        let malformed = OpeningProtocol::new(vec![
            TableSpec::new(
                TableShape::new(8, width),
                vec![OpeningBatch::new(vec![column], vec![])],
            ),
            TableSpec::new(shapes[1], vec![OpeningBatch::new(vec![0], vec![])]),
        ]);
        let mut verifier = challenger(seed);
        pcs.observe_commitment(&commitment, &mut verifier);
        assert!(
            pcs.verify_at(&commitment, &proof, &malformed, &points, &mut verifier)
                .is_err()
        );
    }
}
