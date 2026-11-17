use old_air::BaseAir as OldBaseAir;
use old_binary_field::{Poly64 as OldF, TowerLevel as OldTowerLevel};
use p3_air::{AirLayout, BaseAir, check_all_constraints};
use p3_binary_field::{Poly192, TowerLevel};
use p3_bus::{BusDebugInstance, BusDebugReport, BusSymbolicBuilder};
use p3_circuit::CircuitBuilder;
use p3_circuit_prover::{
    direct::DirectCircuitLimits,
    native_bus::{KeccakCommitment, NativeBusCircuit},
};
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
    air::{Chip, convert},
    config::{challenger, pcs},
    encoding::TableEncoding,
    fanout, gates, keccak,
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
    let widths = [vec![1, 8, 1, 16, 64], vec![3, 0, 16], vec![0, 0]];
    let shapes = [
        TableShape::new(8, 5),
        TableShape::new(4, 3),
        TableShape::new(4, 2),
    ];
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
                        F::from_repr(if width == 0 {
                            0
                        } else {
                            raw & (u64::MAX >> (64 - width))
                        })
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
        TableSpec::new(
            shapes[1],
            vec![OpeningBatch::new(vec![2, 1, 0], vec![0, 1, 2])],
        ),
        TableSpec::new(shapes[2], vec![OpeningBatch::new(vec![1, 0], vec![0, 1])]),
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
    for (table, column) in [
        (0, 0),
        (0, 1),
        (0, 2),
        (0, 3),
        (1, 0),
        (1, 1),
        (1, 2),
        (2, 0),
        (2, 1),
    ] {
        let mut invalid = tables.clone();
        let rows = 1 << shapes[table].num_variables();
        let mut values: Vec<_> = (0..shapes[table].width())
            .flat_map(|c| invalid[table].poly(c).as_slice().to_vec())
            .collect();
        values[column * rows + rows - 1] += F::from_repr(1 << widths[table][column]);
        invalid[table] = Table::new(RowMajorMatrix::new(values, rows));
        assert!(pcs.commit(invalid, &mut challenger(seed)).is_err());
    }
    for invalid in [vec![], vec![65]] {
        assert!(TableEncoding::new(invalid).is_err());
    }
    for (width, column) in [(4, 0), (6, 0)] {
        let malformed = OpeningProtocol::new(vec![
            TableSpec::new(
                TableShape::new(8, width),
                vec![OpeningBatch::new(vec![column], vec![])],
            ),
            TableSpec::new(shapes[1], vec![OpeningBatch::new(vec![0], vec![])]),
            TableSpec::new(shapes[2], vec![OpeningBatch::new(vec![0], vec![])]),
        ]);
        let mut verifier = challenger(seed);
        pcs.observe_commitment(&commitment, &mut verifier);
        assert!(
            pcs.verify_at(&commitment, &proof, &malformed, &points, &mut verifier)
                .is_err()
        );
    }
}

#[test]
fn split_fanout_preserves_copy_constraints_and_zero_sentinel() {
    let mut builder = CircuitBuilder::<OldF>::new();
    let bit = builder.alloc_private_input("bit");
    builder.assert_bool(bit);
    let x = builder.alloc_private_input("field_element");
    let constant = builder.define_const(OldF::from_repr(0x1234));
    let product = builder.mul(x, constant);
    let sum = builder.add(product, bit);
    let public = builder.alloc_public_input("result");
    builder.connect(sum, public);
    let scaled = builder.mul(bit, constant);
    let scaled_public = builder.alloc_public_input("scaled_bit");
    builder.connect(scaled, scaled_public);
    let circuit = builder.build().unwrap();
    let bus = NativeBusCircuit::with_compact_options(
        &circuit,
        "imt",
        4,
        DirectCircuitLimits {
            max_witnesses: 1024,
            max_operations: 1024,
            max_trace_cells: 1 << 20,
        },
        KeccakCommitment::Bits,
    )
    .unwrap();
    let fanout_pp = bus.airs()[0].preprocessed_trace().unwrap();
    let widths = fanout::coordinate_widths(&circuit, &[], 119).unwrap();
    let shards = fanout::partition(&widths, &fanout_pp.values).unwrap();
    assert_eq!(
        shards
            .iter()
            .map(|s| s.coordinate_width)
            .collect::<Vec<_>>(),
        [1, 16, 64]
    );
    let mut source_rows: Vec<_> = shards
        .iter()
        .flat_map(|s| s.rows.iter().map(|r| r.source_row))
        .collect();
    source_rows.sort_unstable();
    let live = fanout_pp
        .values
        .as_chunks::<3>()
        .0
        .iter()
        .filter(|r| r[1].to_repr() == 1)
        .count();
    assert_eq!(source_rows, (0..live as u32).collect::<Vec<_>>());
    let public = [
        OldF::from_repr(0x1234) * OldF::from_repr(3) + OldF::from_repr(1),
        OldF::from_repr(0x1234),
    ];
    let mut runner = circuit.runner();
    runner
        .set_private_inputs(&[OldF::from_repr(1), OldF::from_repr(3)])
        .unwrap();
    runner.set_public_inputs(&public).unwrap();
    let witness = runner.run_witness().unwrap();
    let original = bus.column_major_tables(&witness).unwrap();
    let mut airs = Vec::new();
    let mut rows = Vec::new();
    let mut publics = Vec::new();
    for shard in &shards {
        airs.push(
            Chip::import_shard(bus.airs()[0].clone(), shard.log_height, Some(shard.clone()))
                .unwrap(),
        );
        let height = 1 << shard.log_height;
        let mut values = vec![F::ZERO; height * 2];
        for (i, r) in shard.rows.iter().enumerate() {
            values[2 * (i + 1)] = convert(original[0].column(0).value(r.source_row as usize));
        }
        for i in 0..height {
            values[2 * i + 1] = values[2 * (i + 1).min(height - 1)];
        }
        rows.push(RowMajorMatrix::new(values, 2));
        publics.push(vec![]);
    }
    let original_public = bus.public_values(&public).unwrap();
    let gate_pp = bus.airs()[1].preprocessed_trace().unwrap();
    let gate_shards = gates::partition(
        &widths,
        &gate_pp.values,
        gate_pp.width,
        bus.airs()[1].width(),
    )
    .unwrap();
    let mut gate_rows: Vec<_> = gate_shards
        .iter()
        .flat_map(|s| s.source_rows.iter().copied())
        .collect();
    gate_rows.sort_unstable();
    let live_gates = gate_pp
        .values
        .chunks_exact(gate_pp.width)
        .filter(|row| row.iter().any(|v| v.to_repr() != 0))
        .count();
    assert_eq!(gate_rows, (0..live_gates as u32).collect::<Vec<_>>());
    for shard in gate_shards {
        let pp = shard.preprocessing();
        for (r, &source_row) in shard.source_rows.iter().enumerate() {
            for c in 0..gate_pp.width {
                assert_eq!(
                    pp.values[r * pp.width + c],
                    convert(gate_pp.values[source_row as usize * gate_pp.width + c])
                );
            }
        }
        let width = original[1].num_polys();
        let mut values = vec![F::ZERO; width * (1 << shard.log_height)];
        for (r, &source_row) in shard.source_rows.iter().enumerate() {
            for c in 0..width {
                values[r * width + c] = convert(original[1].column(c).value(source_row as usize));
            }
        }
        airs.push(Chip::import_gates(bus.airs()[1].clone(), shard).unwrap());
        rows.push(RowMajorMatrix::new(values, width));
        publics.push(vec![]);
    }
    for i in 2..bus.airs().len() {
        airs.push(Chip::import(bus.airs()[i].clone(), bus.log_heights()[i]).unwrap());
        let height = 1 << original[i].num_variables();
        let width = original[i].num_polys();
        let values = (0..height)
            .flat_map(|r| (0..width).map(move |c| (r, c)))
            .map(|(r, c)| convert(original[i].column(c).value(r)))
            .collect();
        rows.push(RowMajorMatrix::new(values, width));
        publics.push(original_public[i].iter().copied().map(convert).collect());
    }
    assert_eq!(fanout_diagnostics(&airs, &rows, &publics), (true, true));
    // Corrupt a real copy; keeping its successor consistent cannot hide the
    // changed witness-bus multiset or the equality to other copies of this ID.
    for i in 0..shards.len() {
        let mut tampered = rows.clone();
        tampered[i].values[2] += F::ONE;
        tampered[i].values[1] = tampered[i].values[2];
        assert_ne!(fanout_diagnostics(&airs, &tampered, &publics), (true, true));
    }
    // A nonzero absent addend is rejected even if every copy of ID zero agrees.
    let mut tampered = rows.clone();
    assert!(shards[0].rows.iter().any(|r| r.id == 0));
    tampered[0].values[0] = F::ONE;
    for (i, r) in shards[0].rows.iter().enumerate().filter(|(_, r)| r.id == 0) {
        assert_eq!(r.id, 0);
        tampered[0].values[2 * (i + 1)] = F::ONE;
    }
    for i in 0..1 << shards[0].log_height {
        tampered[0].values[2 * i + 1] =
            tampered[0].values[2 * (i + 1).min((1 << shards[0].log_height) - 1)];
    }
    assert!(!fanout_diagnostics(&airs, &tampered, &publics).0);
    // Swap two next-values across different shards at the same row address.
    // Their distinct bus names prevent an otherwise cancelling cross-table swap.
    let mut tampered = rows.clone();
    let a = tampered[1].values[1];
    let b = tampered[2].values[1];
    assert_ne!(a, b);
    tampered[1].values[1] = b;
    tampered[2].values[1] = a;
    assert!(!fanout_diagnostics(&airs, &tampered, &publics).1);
}

fn fanout_diagnostics(
    airs: &[Chip],
    rows: &[RowMajorMatrix<F>],
    publics: &[Vec<F>],
) -> (bool, bool) {
    let constraints = airs
        .iter()
        .zip(rows)
        .zip(publics)
        .all(|((a, row), public)| check_all_constraints(a, row, public, Some(1)).is_ok());
    let profiles: Vec<_> = airs
        .iter()
        .map(|a| BusSymbolicBuilder::<F, F>::from_air(a, AirLayout::from_air(a)))
        .collect();
    let tables: Vec<_> = rows.iter().map(|row| Table::new(row.transpose())).collect();
    let pp: Vec<_> = airs
        .iter()
        .map(|a| a.preprocessed_trace().map(|m| Table::new(m.transpose())))
        .collect();
    let periodic: Vec<_> = airs
        .iter()
        .map(|a| {
            let columns = a.periodic_columns();
            if columns.is_empty() {
                None
            } else {
                Some(Table::new(RowMajorMatrix::new(
                    columns.iter().flatten().copied().collect(),
                    columns[0].len(),
                )))
            }
        })
        .collect();
    let instances: Vec<_> = (0..airs.len())
        .map(|i| {
            let instance =
                BusDebugInstance::new(&tables[i], pp[i].as_ref(), &publics[i], &profiles[i])
                    .unwrap();
            periodic[i]
                .as_ref()
                .map_or(instance, |p| instance.with_periodic(p))
        })
        .collect();
    (
        constraints,
        BusDebugReport::check(&instances).unwrap().is_balanced(),
    )
}

#[test]
fn arithmetic_partitions_avoid_padding_cliffs_without_losing_preprocessing() {
    for count in [1usize, 16, 17, 32, 33, 48, 49, 64, 65, 96, 97, 128, 129] {
        let source: Vec<_> = (0..count)
            .flat_map(|r| {
                [
                    OldF::from_repr(1),
                    OldF::from_repr((r as u64 + 1).wrapping_mul(0x9e3779b97f4a7c15)),
                    OldF::from_repr(1),
                ]
            })
            .collect();
        let shards = gates::partition(&[1, 16], &source, 3, 1).unwrap();
        let indices: Vec<_> = shards
            .iter()
            .flat_map(|s| s.source_rows.iter().copied())
            .collect();
        assert_eq!(indices, (0..count as u32).collect::<Vec<_>>());
        let cells: usize = shards.iter().map(|s| 1 << s.log_height).sum();
        assert!(cells <= count.next_power_of_two().max(16));
        if shards.len() == 2 {
            assert!(4 * cells <= 3 * count.next_power_of_two().max(16));
        }
        for shard in shards {
            assert_eq!(shard.coordinate_widths, [16]);
            let actual = shard.preprocessing();
            for (r, &i) in shard.source_rows.iter().enumerate() {
                assert_eq!(
                    &actual.values[3 * r..3 * r + 3],
                    &source[3 * i as usize..3 * i as usize + 3]
                        .iter()
                        .copied()
                        .map(convert)
                        .collect::<Vec<_>>()
                );
            }
            assert!(
                actual.values[3 * shard.source_rows.len()..]
                    .iter()
                    .all(|&v| v == F::ZERO)
            );
        }
    }
}
