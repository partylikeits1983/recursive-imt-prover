use p3_binary_field::{Poly192 as E, TowerLevel};
use p3_challenger::CanSample;
use p3_commit::MultilinearPcs;
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};
use p3_matrix::dense::RowMajorMatrix;
use p3_multilinear_util::{point::Point, poly::Poly};
use p3_sumcheck::{
    OpeningBatch, OpeningEvals, OpeningProtocol, PrescribedPointPcs, TableShape, TableSpec,
    layout::Table,
};

use crate::{
    F,
    config::{Pcs, challenger, pcs},
    encoding::TableEncoding,
};

struct Fixture {
    pcs: Pcs,
    tables: Vec<Table<F>>,
    protocol: OpeningProtocol,
    points: Vec<Point<E>>,
    known: Vec<Option<OpeningEvals<E>>>,
}

impl Fixture {
    fn new(mode: usize) -> Self {
        let widths = [vec![1, 1], vec![1, 16], vec![0], vec![1]];
        let shapes = widths
            .iter()
            .map(|w| TableShape::new(7, w.len()))
            .collect::<Vec<_>>();
        let encodings = widths
            .iter()
            .map(|w| TableEncoding::new(w.clone()).unwrap())
            .collect();
        let pcs = pcs(&shapes, encodings).unwrap();
        let tables = widths
            .iter()
            .map(|widths| {
                let values = widths
                    .iter()
                    .enumerate()
                    .flat_map(|(col, &width)| {
                        (0..128).map(move |row| {
                            F::from_repr(
                                ((row as u64 + 1) * 317 + col as u64 * 991) & ((1u64 << width) - 1),
                            )
                        })
                    })
                    .collect();
                Table::new(RowMajorMatrix::new(values, 128))
            })
            .collect::<Vec<_>>();
        let boolean = match mode {
            0 => vec![OpeningBatch::new(vec![0, 1], vec![])],
            1 => vec![OpeningBatch::new(vec![0, 1], vec![0, 1])],
            2 => vec![OpeningBatch::new(vec![1, 0], vec![1, 0])],
            // The first batch expands to also open a successor because the
            // second batch requests it. Neither hint covers the expanded view.
            3 => vec![
                OpeningBatch::new(vec![0, 1], vec![]),
                OpeningBatch::new(vec![1], vec![0]),
            ],
            _ => unreachable!(),
        };
        let protocol = OpeningProtocol::new(vec![
            TableSpec::new(shapes[0], boolean),
            TableSpec::new(shapes[1], vec![OpeningBatch::new(vec![0, 1], vec![0, 1])]),
            TableSpec::new(shapes[2], vec![OpeningBatch::new(vec![0], vec![])]),
            TableSpec::new(shapes[3], vec![OpeningBatch::new(vec![0], vec![]); 2]),
        ]);
        let points = protocol
            .iter_openings()
            .enumerate()
            .map(|(batch, _)| {
                Point::new(
                    (0..7)
                        .map(|j| {
                            E::from_basis_coefficients_fn(|i| {
                                F::from_repr((batch * 37 + j * 13 + i + 1) as u64)
                            })
                        })
                        .collect(),
                )
            })
            .collect::<Vec<_>>();
        let known = protocol
            .iter_openings()
            .zip(&points)
            .map(|((table, batch), point)| {
                let evaluate = |columns: &[usize], next: bool| {
                    columns
                        .iter()
                        .map(|&column| {
                            let values = tables[table].poly(column).as_slice().to_vec();
                            let values = if next {
                                (0..values.len())
                                    .map(|r| values[(r + 1).min(values.len() - 1)])
                                    .collect()
                            } else {
                                values
                            };
                            Poly::new(values).eval_base(point)
                        })
                        .collect()
                };
                Some(OpeningBatch::new(
                    evaluate(batch.current(), false),
                    evaluate(batch.next(), true),
                ))
            })
            .collect();
        Self {
            pcs,
            tables,
            protocol,
            points,
            known,
        }
    }
}

#[test]
fn supplied_boolean_evaluations_preserve_proof_bytes_and_transcript() {
    for mode in 0..4 {
        let f = Fixture::new(mode);
        let mut baseline_ch = challenger(b"known-opening-differential");
        let (commitment, data) = f.pcs.commit(f.tables.clone(), &mut baseline_ch).unwrap();
        let baseline = f
            .pcs
            .open_at(data, &f.protocol, &f.points, &mut baseline_ch)
            .unwrap();
        let continuation: E = baseline_ch.sample();
        let mut verify_ch = challenger(b"known-opening-differential");
        f.pcs.observe_commitment(&commitment, &mut verify_ch);
        let expected = f
            .pcs
            .verify_at(
                &commitment,
                &baseline,
                &f.protocol,
                &f.points,
                &mut verify_ch,
            )
            .unwrap();
        for weighted in [false, true] {
            let mut known = f.known.clone();
            // Poison hints that cannot be forwarded: their coordinate layout
            // or ordered opening shape changes. They must be recomputed.
            for ((table, _), hint) in f.protocol.iter_openings().zip(&mut known) {
                if table == 1 || table == 2 || (table == 0 && mode >= 2) {
                    let values = hint.take().unwrap();
                    let mut current = values.current().to_vec();
                    current[0] += E::ONE;
                    *hint = Some(OpeningBatch::new(current, values.next().to_vec()));
                }
            }
            let mut ch = challenger(b"known-opening-differential");
            let (_, data) = f.pcs.commit(f.tables.clone(), &mut ch).unwrap();
            let proof = if weighted {
                f.pcs
                    .open_at_known_weighted(data, &f.protocol, &f.points, &known, &[], &mut ch)
                    .unwrap()
                    .unwrap()
            } else {
                f.pcs
                    .open_at_known(data, &f.protocol, &f.points, &known, &mut ch)
                    .unwrap()
            };
            assert_eq!(
                postcard::to_allocvec(&proof).unwrap(),
                postcard::to_allocvec(&baseline).unwrap()
            );
            let actual: E = ch.sample();
            assert_eq!(actual, continuation);
            let mut ch = challenger(b"known-opening-differential");
            f.pcs.observe_commitment(&commitment, &mut ch);
            assert_eq!(
                f.pcs
                    .verify_at(&commitment, &proof, &f.protocol, &f.points, &mut ch)
                    .unwrap(),
                expected
            );
        }
    }
}

#[test]
fn incorrect_boolean_hint_cannot_bypass_the_pcs() {
    let f = Fixture::new(1);
    for weighted in [false, true] {
        let mut known = f.known.clone();
        let mut current = known[0].as_ref().unwrap().current().to_vec();
        current[0] += E::ONE;
        known[0] = Some(OpeningBatch::new(
            current,
            known[0].as_ref().unwrap().next().to_vec(),
        ));
        let mut ch = challenger(b"wrong-known-opening");
        let (commitment, data) = f.pcs.commit(f.tables.clone(), &mut ch).unwrap();
        let result = if weighted {
            f.pcs
                .open_at_known_weighted(data, &f.protocol, &f.points, &known, &[], &mut ch)
                .unwrap()
        } else {
            f.pcs
                .open_at_known(data, &f.protocol, &f.points, &known, &mut ch)
        };
        if let Ok(proof) = result {
            let mut ch = challenger(b"wrong-known-opening");
            f.pcs.observe_commitment(&commitment, &mut ch);
            assert!(
                f.pcs
                    .verify_at(&commitment, &proof, &f.protocol, &f.points, &mut ch)
                    .is_err()
            );
        }
    }
}

#[test]
fn malformed_known_batches_fail_before_challenges() {
    let f = Fixture::new(1);
    for case in 0..4 {
        let mut known = f.known.clone();
        match case {
            0 => {
                known.pop();
            }
            1 => known.push(None),
            2 => known[0] = Some(OpeningBatch::new(vec![E::ZERO], vec![])),
            3 => known[1] = Some(OpeningBatch::new(vec![E::ZERO; 2], vec![])),
            _ => unreachable!(),
        }
        let mut ch = challenger(b"malformed-known-opening");
        let (_, data) = f.pcs.commit(f.tables.clone(), &mut ch).unwrap();
        let mut expected = ch.clone();
        assert!(
            f.pcs
                .open_at_known(data, &f.protocol, &f.points, &known, &mut ch)
                .is_err()
        );
        let actual: E = ch.sample();
        let expected: E = expected.sample();
        assert_eq!(actual, expected);
    }
}

#[test]
fn word_openings_authenticate_logical_values_and_reject_invalid_requests() {
    for bits in [2, 4, 8, 16, 32, 64] {
        let shape = TableShape::new(9, 2);
        let encoding = TableEncoding::with_word_openings(vec![bits; 2], true).unwrap();
        let scheme = pcs(&[shape], vec![encoding]).unwrap();
        let mask = u64::MAX >> (64 - bits);
        let values: Vec<_> = (0..1024u64)
            .map(|i| F::new(i.wrapping_mul(0x9e3779b97f4a7c15) & mask))
            .collect();
        let table = Table::new(RowMajorMatrix::new(values.clone(), 512));
        let protocol = |next| {
            OpeningProtocol::new(vec![TableSpec::new(
                shape,
                vec![OpeningBatch::new(vec![0, 1], next)],
            )])
        };
        let current = protocol(vec![]);
        let points = vec![Point::new(
            (1..=9).map(|i| E::from(F::new(37 * i))).collect(),
        )];
        let expected = OpeningBatch::new(
            values
                .as_chunks::<512>()
                .0
                .iter()
                .map(|column| Poly::new(column.to_vec()).eval_base(&points[0]))
                .collect(),
            vec![],
        );
        let mut ch = challenger(b"word opening");
        let (root, data) = scheme.commit(vec![table], &mut ch).unwrap();
        assert!(
            scheme
                .open_at(data.clone(), &protocol(vec![0]), &points, &mut ch)
                .is_err()
        );
        assert!(
            scheme
                .open_at(data.clone(), &current, &[], &mut ch)
                .is_err()
        );
        let proof = scheme
            .open_at_known(data, &current, &points, &[Some(expected.clone())], &mut ch)
            .unwrap();
        let mut ch = challenger(b"word opening");
        scheme.observe_commitment(&root, &mut ch);
        assert_eq!(
            scheme
                .verify_at(&root, &proof, &current, &points, &mut ch)
                .unwrap(),
            [expected]
        );
        if bits < 64 {
            let mut invalid = values;
            invalid[250] = F::new(1u64 << bits);
            let invalid = Table::new(RowMajorMatrix::new(invalid, 512));
            assert!(scheme.commit(vec![invalid], &mut ch).is_err());
        }
    }
}
