use super::*;
use crate::config::challenger;
use p3_challenger::FieldChallenger;
use p3_multilinear_util::poly::Poly;
use p3_whir::QueryOpenings;

#[test]
fn one_whir_opens_both_pinned_faces() -> Result<()> {
    let variables = 14;
    let mut source = challenger(b"paired-words-and-points-test");
    let mut values = |n| {
        (0..(1 << n))
            .map(|_| source.sample_algebra_element::<F>())
            .collect::<Vec<_>>()
    };
    let main = values(variables - 1);
    let fixed = values(variables - 2);
    let fixed_root = PairedOpening::fixed_root(&fixed)?;
    let pcs = PairedOpening::new(variables, fixed_root)?;
    let seed = b"imt-paired-whir-test-v1";
    let mut prover = challenger(seed);
    let pair = pcs.commit(&main, &fixed, &mut prover)?;
    let roots = pair.roots;
    let sample =
        |ch: &mut Challenger, n| Point::new((0..n).map(|_| ch.sample_algebra_element()).collect());
    let am = sample(&mut prover, variables - 1);
    let af = sample(&mut prover, variables - 2);
    let points = [&am, &af];
    let expected = [
        Poly::new(main).eval_base(&am),
        Poly::new(fixed).eval_base(&af),
    ];
    let mut proof = pcs.open(pair, points, &mut prover)?;
    let verify = |roots, expected, proof: &OpeningProof| -> Result<()> {
        let mut verifier = challenger(seed);
        pcs.observe(roots, &mut verifier)?;
        let mp = sample(&mut verifier, variables - 1);
        let fp = sample(&mut verifier, variables - 2);
        pcs.verify(roots, [&mp, &fp], expected, proof, &mut verifier)
    };
    verify(roots, expected, &proof)?;
    let mut wrong = roots;
    wrong[1][0] ^= 1;
    assert!(verify(wrong, expected, &proof).is_err());
    wrong = roots;
    wrong[0][0] ^= 1;
    assert!(verify(wrong, expected, &proof).is_err());
    for i in 0..2 {
        let mut changed = expected;
        changed[i] += E::ONE;
        assert!(verify(roots, changed, &proof).is_err());
    }
    for pos in [0, MAIN, MAIN + FIXED] {
        let QueryOpenings::Base(rows) = &mut proof.0.whir.rounds[0].openings else {
            panic!()
        };
        rows.rows[0][pos] += F::ONE;
        assert!(verify(roots, expected, &proof).is_err());
        let QueryOpenings::Base(rows) = &mut proof.0.whir.rounds[0].openings else {
            panic!()
        };
        rows.rows[0][pos] += F::ONE;
    }
    for i in 0..2 {
        let QueryOpenings::Base(rows) = &mut proof.0.whir.rounds[0].openings else {
            panic!()
        };
        rows.proof[i].sibling_hashes[0][0] ^= 1;
        assert!(verify(roots, expected, &proof).is_err());
        let QueryOpenings::Base(rows) = &mut proof.0.whir.rounds[0].openings else {
            panic!()
        };
        rows.proof[i].sibling_hashes[0][0] ^= 1;
    }
    verify(roots, expected, &proof)
}

#[test]
fn batched_bits_close_at_one_opening() -> Result<()> {
    use super::batch::{Claims, prove};
    let n = 7;
    let variables = n + 6;
    let mut rng = challenger(b"imt-batch-poly-reference-v1");
    let words: Vec<F> = (0..1 << n).map(|_| rng.sample_algebra_element()).collect();
    let bits = Poly::new(
        words
            .iter()
            .flat_map(|word| (0..64).map(move |b| F::from_bool((word.to_bits() >> b) & 1 == 1)))
            .collect::<Vec<_>>(),
    );
    let points: Vec<Point<E>> = (0..5)
        .map(|i| {
            let mut p: Vec<E> = (0..variables)
                .map(|_| rng.sample_algebra_element())
                .collect();
            if i < 2 {
                p[0] = E::from_bool(i == 1);
            }
            Point::new(p)
        })
        .collect();
    let values = points.iter().map(|p| bits.eval_base(p)).collect::<Vec<_>>();
    let planes = points
        .iter()
        .map(|p| {
            let (high, _) = p.split_at(n);
            (0..64)
                .map(|b| {
                    Poly::new(
                        words
                            .iter()
                            .map(|w| F::from_bool((w.to_bits() >> b) & 1 == 1))
                            .collect::<Vec<_>>(),
                    )
                    .eval_base(&high)
                })
                .collect()
        })
        .collect::<Vec<_>>();
    let claims = Claims {
        points: &points,
        values: &values,
        variables,
    };
    let seed = b"imt-batch-test-v1";
    let mut prover = challenger(seed);
    let (mut proof, point) = prove(&claims, &words, &planes, &mut prover)?;
    let check = |proof: &batch::BatchProof| claims.verify(proof, &mut challenger(seed));
    assert_eq!(check(&proof)?, point);
    assert_eq!(proof.value, bits.eval_base(&point));
    for i in [0, 5, 6, variables - 1] {
        for j in 0..2 {
            proof.rounds[i][j] += E::ONE;
            assert!(check(&proof).is_err());
            proof.rounds[i][j] += E::ONE;
        }
    }
    proof.value += E::ONE;
    assert!(check(&proof).is_err());
    proof.value += E::ONE;
    let mut changed = values.clone();
    changed[2] += E::ONE;
    assert!(
        Claims {
            values: &changed,
            ..claims
        }
        .verify(&proof, &mut challenger(seed))
        .is_err()
    );
    proof.rounds.pop();
    assert!(check(&proof).is_err());
    Ok(())
}

#[test]
fn shared_readings_bind_both_faces_to_the_external_authority() -> Result<()> {
    use super::bound::Readings;
    use p3_sumcheck::ring_switch::bits::{BitPacking, BitRingSwitch};

    let variables = 14;
    let mut rng = challenger(b"imt-joint-two-face-regression");
    let mut make_face = |n| -> Result<_> {
        let words: Vec<F> = (0..1 << n).map(|_| rng.sample_algebra_element()).collect();
        let packing = BitPacking::from_packed(Poly::new(words.clone()))?;
        let mut points = Vec::new();
        let mut values = Vec::new();
        let mut planes = Vec::new();
        for _ in 0..2 {
            let point = Point::new((0..n + 6).map(|_| rng.sample_algebra_element()).collect());
            let switch = BitRingSwitch::<F, E>::new(&point)?;
            let tensor = switch.tensor(&packing)?;
            values.push(switch.incoming_claim(&tensor));
            planes.push(tensor.columns());
            points.push(point);
        }
        Ok((words, points, values, planes))
    };
    let (main, main_points, main_values, mut planes) = make_face(variables - 1)?;
    let (fixed, fixed_points, fixed_values, fixed_planes) = make_face(variables - 2)?;
    planes.extend(fixed_planes);
    let fixed_root = PairedOpening::fixed_root(&fixed)?;
    let scheme = || PairedOpening::new(variables, fixed_root);
    let (main_cap, _) = commit_borrowed_base(
        &BinaryWhirDomain::<F>::default(),
        &merkle_tree(),
        FIRST - 1,
        TERMINAL_LOG_INV_RATE,
        &main,
    );
    let roots = [main_cap[0], fixed_root];
    let seed = b"terminal authority A";
    let read = |points: &[Point<E>], values: &[E], fixed_values: &[E]| {
        Readings::new(variables, [(points, values), (&fixed_points, fixed_values)])
    };
    let readings = read(&main_points, &main_values, &fixed_values)?;
    let words = scheme()?.words(&main, &fixed)?;
    let proof = scheme()?.prove_readings(words, roots, &readings, &planes, seed)?;
    scheme()?.verify_readings(roots, &readings, &proof, seed)?;
    assert!(
        scheme()?
            .verify_readings(roots, &readings, &proof, b"terminal authority B")
            .is_err()
    );
    for i in 0..2 {
        let mut wrong = roots;
        wrong[i][0] ^= 1;
        assert!(
            scheme()?
                .verify_readings(wrong, &readings, &proof, seed)
                .is_err()
        );
    }
    let mut swapped = main_points.clone();
    swapped.swap(0, 1);
    let mut altered = main_values.clone();
    altered[0] += E::ONE;
    let mut changed_fixed = fixed_values.clone();
    changed_fixed[1] += E::ONE;
    for wrong in [
        read(&swapped, &main_values, &fixed_values)?,
        read(&main_points, &altered, &fixed_values)?,
        read(&main_points, &main_values, &changed_fixed)?,
        read(&main_points[..1], &main_values[..1], &fixed_values)?,
    ] {
        assert!(
            scheme()?
                .verify_readings(roots, &wrong, &proof, seed)
                .is_err()
        );
    }
    Ok(())
}
