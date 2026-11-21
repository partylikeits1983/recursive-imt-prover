use old_air::BaseAir as OldBaseAir;
use old_binary_field::{Poly64 as OldF, TowerLevel as OldTowerLevel};
use p3_air::{AirLayout, BaseAir, check_all_constraints};
use p3_binary_field::{Poly192, TowerLevel};
use p3_bus::{BusDebugInstance, BusDebugReport, BusSymbolicBuilder};
use p3_circuit::{CircuitBuilder, WitnessId};
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
use std::sync::Arc;

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
    for commit_public_ids in [false, true] {
        check_split_fanout(commit_public_ids);
    }
}

fn check_split_fanout(commit_public_ids: bool) {
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
    // Keep a sixteen-coordinate ID with three uses after pairs are eliminated.
    let third_public = builder.public_input();
    builder.connect(scaled, third_public);
    // Force several packed rows for the same ID, including a partial final
    // row. Distinct outputs prevent common-subexpression elimination.
    let mut extra_public = Vec::new();
    for i in 1..40 {
        let c = builder.define_const(OldF::from_repr(i));
        let y = builder.mul(x, c);
        let output = builder.public_input();
        builder.connect(y, output);
        extra_public.push(OldF::from_repr(3) * OldF::from_repr(i));
    }
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
    let (shards, mut copies) = fanout::partition(&widths, &fanout_pp.values, &[], false).unwrap();
    let (fixed, _) = fanout::partition(&widths, &fanout_pp.values, &[], true).unwrap();
    assert_eq!(fixed.len(), fanout::RECURSIVE_LAYOUT.len());
    for (shard, (width, copies, log, successor)) in fixed.iter().zip(fanout::RECURSIVE_LAYOUT) {
        assert_eq!(
            (
                shard.coordinate_width,
                shard.copies_per_row(),
                shard.log_height,
                shard.needs_successor()
            ),
            (width, copies, log, successor)
        );
    }
    let occurrences = |shards: &[Arc<fanout::FanoutShard>]| {
        let mut rows: Vec<_> = shards
            .iter()
            .flat_map(|s| {
                s.rows.iter().flat_map(move |r| {
                    (0..u32::from(r.copies))
                        .map(move |offset| (s.coordinate_width, r.source_row + offset, r.id))
                })
            })
            .collect();
        rows.sort_unstable();
        rows
    };
    assert_eq!(occurrences(&fixed), occurrences(&shards));
    let mut shard_widths = shards
        .iter()
        .map(|s| s.coordinate_width)
        .collect::<Vec<_>>();
    shard_widths.dedup();
    assert_eq!(shard_widths, [1, 16, 64]);
    let mut source_rows: Vec<_> = shards
        .iter()
        .flat_map(|s| {
            s.rows
                .iter()
                .flat_map(|r| r.source_row..r.source_row + u32::from(r.copies))
        })
        .collect();
    source_rows.sort_unstable();
    let live = fanout_pp
        .values
        .as_chunks::<3>()
        .0
        .iter()
        .filter(|r| r[1].to_repr() == 1)
        .count();
    let all_ids: Vec<_> = fanout_pp
        .values
        .as_chunks::<3>()
        .0
        .iter()
        .take(live)
        .map(|r| r[0].to_repr())
        .collect();
    let mut occurrences = vec![0usize; widths.len()];
    for &id in &all_ids {
        occurrences[id as usize] += 1;
    }
    let expected: Vec<_> = all_ids
        .iter()
        .enumerate()
        .filter_map(|(row, &id)| (id == 0 || occurrences[id as usize] > 2).then_some(row as u32))
        .collect();
    assert!(expected.len() < live, "fixture must contain singleton IDs");
    assert_eq!(source_rows, expected);
    assert!(shards.iter().any(|s| {
        s.rows
            .iter()
            .any(|r| r.copies == fanout::MAX_COPIES_PER_ROW)
    }));
    assert!(
        shards
            .iter()
            .any(|s| s.rows.windows(2).any(|r| r[0].id == r[1].id))
    );
    let mut public = vec![
        OldF::from_repr(0x1234) * OldF::from_repr(3) + OldF::from_repr(1),
        OldF::from_repr(0x1234),
        OldF::from_repr(0x1234),
    ];
    public.extend(extra_public);
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
        if commit_public_ids {
            airs.last_mut().unwrap().fix_fanout_zero().unwrap();
        }
        let height = 1 << shard.log_height;
        let width = airs.last().unwrap().width();
        let mut values = vec![F::ZERO; height * width];
        for (i, r) in shard.rows.iter().enumerate() {
            values[width * (i + 1)] = convert(original[0].column(0).value(r.source_row as usize));
        }
        if shard.needs_successor() {
            for i in 0..height {
                values[2 * i + 1] = values[2 * (i + 1).min(height - 1)];
            }
        }
        rows.push(RowMajorMatrix::new(values, width));
        publics.push(vec![]);
    }
    let original_public = bus.public_values(&public).unwrap();
    let gate_pp = bus.airs()[1].preprocessed_trace().unwrap();
    let gate_shards = gates::partition(
        &widths,
        &gate_pp.values,
        gate_pp.width,
        bus.airs()[1].width(),
        &[],
        None,
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
        let full = shard.preprocessing();
        let compact = shard.compact_preprocessing();
        let retained: Vec<_> = shard
            .preprocessing_widths
            .iter()
            .enumerate()
            .filter_map(|(column, &width)| (width != 0).then_some(column))
            .collect();
        assert_eq!(compact.width, retained.len());
        for (original, reduced) in full
            .values
            .chunks_exact(full.width)
            .zip(compact.values.chunks_exact(compact.width))
        {
            for (column, &value) in original.iter().enumerate() {
                if shard.preprocessing_widths[column] == 0 {
                    assert_eq!(value, F::ZERO);
                }
            }
            assert_eq!(
                reduced,
                retained
                    .iter()
                    .map(|&column| original[column])
                    .collect::<Vec<_>>()
            );
        }
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
        let mut direct = vec![F::ZERO; values.len()];
        shard.fill_witness(&mut direct, |id| match id.checked_sub(1) {
            Some(i) => convert(*witness.get_value(WitnessId(i)).unwrap()),
            None => F::ZERO,
        });
        assert_eq!(
            RowMajorMatrix::new(direct, 1 << shard.log_height)
                .transpose()
                .values,
            values
        );
        airs.push(Chip::import_gates(bus.airs()[1].clone(), shard, false).unwrap());
        rows.push(RowMajorMatrix::new(values, width));
        publics.push(vec![]);
    }
    for i in 2..bus.airs().len() {
        airs.push(Chip::import(bus.airs()[i].clone(), bus.log_heights()[i]).unwrap());
        let height = 1 << original[i].num_variables();
        if airs.last().unwrap().is_public_table() {
            rows.push(RowMajorMatrix::new(vec![F::ZERO; height], 1));
            publics.push(original_public[i].iter().copied().map(convert).collect());
            continue;
        }
        let width = original[i].num_polys();
        let values = (0..height)
            .flat_map(|r| (0..width).map(move |c| (r, c)))
            .map(|(r, c)| convert(original[i].column(c).value(r)))
            .collect();
        rows.push(RowMajorMatrix::new(values, width));
        publics.push(original_public[i].iter().copied().map(convert).collect());
    }
    for air in &mut airs {
        if commit_public_ids && air.is_public_table() {
            air.commit_public_ids().unwrap();
        }
        air.prune_copies(&mut copies).unwrap();
    }
    let stats = copies.finish().unwrap();
    assert_eq!(
        stats.single_use,
        occurrences[1..].iter().filter(|&&count| count == 1).count()
    );
    assert_eq!(
        stats.pairs,
        occurrences[1..].iter().filter(|&&count| count == 2).count()
    );
    assert!(stats.single_use > 0 && stats.pairs > 0);
    assert_eq!(stats.single_use + 2 * stats.pairs, live - expected.len());
    assert_eq!(fanout_diagnostics(&airs, &rows, &publics), (true, true));
    // Substituting public copies must still bind their values to witness reads.
    let public_index = airs.iter().position(Chip::is_public_table).unwrap();
    let mut altered_public = publics.clone();
    altered_public[public_index][0] += F::ONE;
    assert!(!fanout_diagnostics(&airs, &rows, &altered_public).1);
    let mut altered_dummy = rows.clone();
    altered_dummy[public_index].values[0] = F::ONE;
    assert!(!fanout_diagnostics(&airs, &altered_dummy, &publics).0);
    // Corrupt a real copy; keeping its successor consistent cannot hide the
    // changed witness-bus multiset or the equality to other copies of this ID.
    for i in 0..shards.len() {
        let mut tampered = rows.clone();
        let width = tampered[i].width;
        tampered[i].values[width] += F::ONE;
        if shards[i].needs_successor() {
            tampered[i].values[1] = tampered[i].values[width];
        }
        assert_ne!(fanout_diagnostics(&airs, &tampered, &publics), (true, true));
    }
    // A nonzero absent addend is rejected even if every copy of ID zero agrees.
    let mut tampered = rows.clone();
    let zero_shard = shards
        .iter()
        .position(|s| s.rows.iter().any(|r| r.id == 0))
        .unwrap();
    tampered[zero_shard].values[0] = F::ONE;
    for (i, r) in shards[zero_shard]
        .rows
        .iter()
        .enumerate()
        .filter(|(_, r)| r.id == 0)
    {
        assert_eq!(r.id, 0);
        tampered[zero_shard].values[2 * (i + 1)] = F::ONE;
    }
    for i in 0..1 << shards[zero_shard].log_height {
        tampered[zero_shard].values[2 * i + 1] =
            tampered[zero_shard].values[2 * (i + 1).min((1 << shards[zero_shard].log_height) - 1)];
    }
    assert!(!fanout_diagnostics(&airs, &tampered, &publics).0);
    // Swap two next-values across different shards at the same row address.
    // Their distinct bus names prevent an otherwise cancelling cross-table swap.
    let mut tampered = rows.clone();
    let (left, right) = (0..shards.len())
        .flat_map(|i| (i + 1..shards.len()).map(move |j| (i, j)))
        .find(|&(i, j)| {
            shards[i].needs_successor()
                && shards[j].needs_successor()
                && tampered[i].values[1] != tampered[j].values[1]
        })
        .unwrap();
    let a = tampered[left].values[1];
    let b = tampered[right].values[1];
    tampered[left].values[1] = b;
    tampered[right].values[1] = a;
    assert!(!fanout_diagnostics(&airs, &tampered, &publics).1);
}

#[test]
fn recursive_fanout_keeps_zero_copies_in_one_fixed_table() {
    for count in [1usize, 2, 3, 4, 5, 8, 9, 16, 17, 29] {
        let mut rows = vec![OldF::from_repr(0); 3 * count.next_power_of_two().max(16)];
        for (index, row) in rows
            .as_chunks_mut::<3>()
            .0
            .iter_mut()
            .take(count)
            .enumerate()
        {
            row[1] = OldF::from_repr(1);
            row[2] = OldF::from_repr(u64::from(index + 1 < count));
        }
        let (shards, _) = fanout::partition(&[0], &rows, &[], true).unwrap();
        let zero = &shards[0];
        assert!(zero.needs_successor());
        assert_eq!(zero.copies_per_row(), 2);
        assert_eq!(zero.log_height, 4);
        assert!(shards[1..].iter().all(|shard| shard.rows.is_empty()));
        let source: Vec<_> = zero
            .rows
            .iter()
            .flat_map(|row| {
                assert_eq!(row.id, 0);
                (0..u32::from(row.copies)).map(|offset| row.source_row + offset)
            })
            .collect();
        assert_eq!(source, (0..count as u32).collect::<Vec<_>>());
        let pp = zero.preprocessing();
        assert_eq!(pp.values[2], F::ONE);
        for (index, row) in zero.rows.iter().enumerate() {
            assert_eq!(
                pp.values[(index + 1) * pp.width + 2],
                F::from_bool(index + 1 < zero.rows.len())
            );
            assert_eq!(
                pp.values[(index + 1) * pp.width + 3],
                F::from_bool(row.copies == 2)
            );
        }
    }
}

#[test]
fn public_wire_ids_do_not_specialize_recursive_equations() {
    let mut equations = Vec::new();
    let mut preprocessings = Vec::new();
    for constant in [0, 5] {
        let mut builder = CircuitBuilder::<OldF>::new();
        let value = builder.define_const(OldF::from_repr(constant));
        let public = builder.alloc_public_input("result");
        builder.connect(value, public);
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
        let index = bus
            .airs()
            .iter()
            .position(|air| air.num_public_values() != 0)
            .unwrap();
        let mut air = Chip::import(bus.airs()[index].clone(), bus.log_heights()[index]).unwrap();
        air.commit_public_ids().unwrap();
        assert!(air.commit_public_ids().is_err());
        let pp = air.preprocessed_trace().unwrap();
        assert_eq!(pp.width, 1);
        assert!(pp.values[1..].iter().all(|&v| v == F::ZERO));
        let mut copies = crate::copies::CopyPruner::new(circuit.witness_count as usize + 1, true);
        air.prune_copies(&mut copies).unwrap();
        copies.finish().unwrap();
        air.repeat(2, 0);
        let symbolic = BusSymbolicBuilder::<F, F>::from_air(&air, AirLayout::from_air(&air));
        equations.push(format!(
            "{:?}{:?}",
            symbolic.base_constraints(),
            symbolic.interactions()
        ));
        let widths = air.recursive_preprocessed_widths().unwrap();
        assert_eq!(widths, [crate::recursive_layout::WITNESS_ID_BITS, 1, 1]);
        preprocessings.push(pp.values);
        assert_eq!(air.num_public_values(), 2);
        assert_eq!(air.preprocessed_width(), 3);
    }
    assert_ne!(preprocessings[0], preprocessings[1]);
    assert_eq!(equations[0], equations[1]);
}

#[test]
fn recursive_keccak_padding_preserves_the_committed_bridge() {
    let mut builder = CircuitBuilder::<OldF>::new();
    builder.enable_native_keccak_f1600().unwrap();
    let inputs = builder.alloc_private_input_array::<100>("input");
    let (outputs, _) = builder
        .add_native_keccak_f1600_digest_with_swapped(&inputs)
        .unwrap();
    let public = builder.public_input();
    builder.connect(outputs[0], public);
    let circuit = builder.build().unwrap();
    let bus = NativeBusCircuit::with_options(
        &circuit,
        "imt",
        4,
        DirectCircuitLimits {
            max_witnesses: 1 << 16,
            max_operations: 1 << 16,
            max_trace_cells: 1 << 20,
        },
        KeccakCommitment::Bits,
    )
    .unwrap();
    let index = bus.packed_table_index().unwrap() + 1;
    let log_height = bus.log_heights()[index];
    let mut air = Chip::import(bus.airs()[index].clone(), log_height).unwrap();
    let original = air.preprocessed_trace().unwrap();
    assert_eq!(original.width, 120);
    assert!(air.pad_keccak_bridge(log_height - 1).is_err());
    air.pad_keccak_bridge(log_height + 1).unwrap();
    let padded = air.preprocessed_trace().unwrap();
    assert_eq!(padded.values.len(), original.values.len() * 2);
    assert_eq!(&padded.values[..original.values.len()], original.values);
    assert!(
        padded.values[original.values.len()..]
            .iter()
            .all(|&v| v == F::ZERO)
    );
    let widths = air.recursive_preprocessed_widths().unwrap();
    let mut observed = vec![0u64; padded.width];
    for row in padded.values.chunks_exact(padded.width) {
        for (bits, value) in observed.iter_mut().zip(row) {
            *bits |= value.to_repr();
        }
    }
    crate::recursive_layout::check_coordinates(&observed, &widths).unwrap();
    let mut copies = crate::copies::CopyPruner::new(circuit.witness_count as usize + 1, true);
    air.prune_copies(&mut copies).unwrap();
    copies.finish().unwrap();
    let pruned = air.preprocessed_trace().unwrap();
    assert_eq!(pruned.width, 120 + 2 * 116);
    assert_eq!(
        air.recursive_preprocessed_widths().unwrap().len(),
        pruned.width
    );
    for (row, expected) in pruned
        .values
        .chunks_exact(pruned.width)
        .zip(padded.values.as_chunks::<120>().0)
    {
        assert_eq!(&row[..120], expected);
        for column in 0..116 {
            assert_eq!(
                row[120 + 2 * column],
                expected[if column < 16 {
                    117
                } else if column < 100 {
                    119
                } else {
                    118
                }]
            );
            assert_eq!(row[121 + 2 * column], F::ZERO);
        }
    }
}

#[test]
fn recursive_coordinate_capacity_rejects_truncation() {
    let widths = [0, 1, 17, 25, 64];
    let values = [0, 1, (1 << 17) - 1, (1 << 25) - 1, u64::MAX];
    crate::recursive_layout::check_coordinates(&values, &widths).unwrap();
    for (column, &width) in widths[..4].iter().enumerate() {
        let mut altered = values;
        altered[column] = 1 << width;
        assert!(crate::recursive_layout::check_coordinates(&altered, &widths).is_err());
    }
    assert!(crate::recursive_layout::check_coordinates(&values[..4], &widths).is_err());
    assert!(crate::recursive_layout::check_coordinates(&[0], &[65]).is_err());
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
        let shards = gates::partition(&[1, 16], &source, 3, 1, &[], None).unwrap();
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

#[test]
fn recursive_fanout_spills_word16_ids_only_into_word16_rows() {
    // Two more IDs than fit across both the four-copy and eight-copy shards.
    let ids = (1 << 16) - 1 + (1 << 11) - 1 + 2;
    let mut source = Vec::with_capacity(3 * 4 * ids);
    for id in 1..=ids {
        for copy in 0..4 {
            source.extend([
                OldF::from_repr(id as u64),
                OldF::from_repr(1),
                OldF::from_repr(u64::from(copy != 3)),
            ]);
        }
    }
    let (shards, _) = fanout::partition(&vec![16; ids + 1], &source, &[], true).unwrap();
    let mut counts = vec![0; ids + 1];
    for shard in &shards {
        for row in &shard.rows {
            assert_eq!(shard.coordinate_width, 16);
            assert_eq!(row.copies, 4);
            assert_eq!(row.source_row, (row.id - 1) * 4);
            counts[row.id as usize] += 1;
        }
    }
    assert!(counts[1..].iter().all(|&count| count == 1));
    assert_eq!(shards[6].rows.len(), 2);
}
