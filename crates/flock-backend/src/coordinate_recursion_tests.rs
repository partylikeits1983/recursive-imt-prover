use anyhow::Result;
use old_binary_field::{BinaryChallenger, Poly64 as CF, Poly192 as CE};
use old_binary_pcs::whir::BinaryWhirDomain;
use old_challenger::{FieldChallenger as OldFieldChallenger, HashChallenger};
use old_keccak::Keccak256Hash;
use old_merkle_tree::{MerkleCap, MerkleTreeMmcs};
use old_multilinear_util::point::Point as OldPoint;
use old_sumcheck::{
    OpeningBatch as OB, OpeningProtocol as OP, TableShape as TS, TableSpec as Spec,
    ring_switch::bits::BitTensor,
};
use old_symmetric::{CompressionFunctionFromHasher, SerializingHasher};
use old_whir::{
    FoldingFactor, ProtocolParameters, SecurityAssumption, WhirConfig,
    pcs::proof::{PcsProof, WhirProof},
};
use p3_binary_field::Poly192 as E;
use p3_binary_pcs::whir::BooleanWhirOpening;
use p3_challenger::FieldChallenger;
use p3_circuit::{
    Circuit, CircuitBuilder,
    ops::{ByteHash, NativePoly192Target, binary_encoding::NativeBinaryEncoding, bytes_to_limbs},
};
use p3_commit::MultilinearPcs;
use p3_matrix::dense::RowMajorMatrix;
use p3_multilinear_util::{point::Point, poly::Poly};
use p3_recursion::{
    BinaryTower128Challenger,
    pcs::binary::{BinaryPolyCoordinateOpeningPlan, BinaryPolyDeferredWhirTraceVerifier},
};
use p3_sumcheck::{
    OpeningBatch, OpeningProtocol, PrescribedPointPcs, TableShape, TableSpec, layout::Table,
};

use crate::{
    F,
    checkpoint_keccak::recursive::deferred_seed,
    config::{challenger, pcs},
    encoding::TableEncoding,
};

type Ch = BinaryChallenger<CF, HashChallenger<u8, Keccak256Hash, 32>>;
type Mmcs = MerkleTreeMmcs<
    CF,
    u8,
    SerializingHasher<Keccak256Hash>,
    CompressionFunctionFromHasher<Keccak256Hash, 2, 32>,
    2,
    32,
>;
type Wire = (Vec<CE>, Vec<BitTensor<CE, CF>>, WhirProof<CF, CE, Mmcs>);
const SEED: &[u8] = b"coordinate-recursion-test";

fn target(b: &mut CircuitBuilder<CF>) -> NativePoly192Target {
    let coefficients = b.alloc_public_input_array::<3>("opening point or value");
    b.native_poly192_from_coefficients(coefficients)
}

fn accepts(circuit: &Circuit<CF>, public: &[CF], private: &[CF]) -> bool {
    let mut runner = circuit.runner();
    runner
        .set_public_inputs(public)
        .and_then(|()| runner.set_private_inputs(private))
        .and_then(|()| runner.run_witness())
        .is_ok()
}

#[test]
#[cfg_attr(debug_assertions, ignore = "recursive PCS proof; run with --release")]
fn coordinate_adapter_authenticates_real_mixed_pcs_openings() -> Result<()> {
    let widths = vec![
        vec![0, 1, 16, 64],
        vec![1, 1, 0],
        vec![0, 0],
        vec![64, 7],
        vec![16, 16],
        vec![64],
    ];
    let logs = [7, 8, 6, 9, 4, 5];
    let requests = [
        vec![vec![3, 0, 1, 2], vec![2]],
        vec![vec![2, 1]],
        vec![vec![0, 1]],
        vec![],
        vec![vec![1, 0]],
        vec![vec![0]],
    ];
    let shapes: Vec<_> = logs
        .iter()
        .zip(&widths)
        .map(|(&n, w)| TableShape::new(n, w.len()))
        .collect();
    let protocol = OpeningProtocol::new(
        shapes
            .iter()
            .zip(&requests)
            .map(|(&shape, batches)| {
                TableSpec::new(
                    shape,
                    batches
                        .iter()
                        .map(|c| OpeningBatch::new(c.clone(), vec![]))
                        .collect(),
                )
            })
            .collect(),
    );
    let logical = OP::new(
        logs.iter()
            .zip(&widths)
            .zip(&requests)
            .map(|((&n, w), batches)| {
                Spec::new(
                    TS::new(n, w.len()),
                    batches.iter().map(|c| OB::new(c.clone(), vec![])).collect(),
                )
            })
            .collect(),
    );
    let plan = BinaryPolyCoordinateOpeningPlan::with_word_openings(&logical, &widths, true)?;
    let pcs = pcs(
        &shapes,
        widths
            .iter()
            .cloned()
            .map(|widths| TableEncoding::with_word_openings(widths, true))
            .collect::<Result<_>>()?,
    )?;
    let mut random = challenger(b"coordinate-test-witness");
    let tables: Vec<_> = widths
        .iter()
        .zip(logs)
        .map(|(widths, log)| {
            let values = widths
                .iter()
                .flat_map(|&width| {
                    (0..1 << log)
                        .map(|_| {
                            let value = random.sample_algebra_element::<F>().to_bits();
                            F::new(value & (u64::MAX.checked_shr((64 - width) as u32).unwrap_or(0)))
                        })
                        .collect::<Vec<_>>()
                })
                .collect();
            Table::new(RowMajorMatrix::new(values, 1 << log))
        })
        .collect();
    let points: Vec<_> = protocol
        .iter_openings()
        .map(|(t, _)| {
            Point::new(
                (0..logs[t])
                    .map(|_| random.sample_algebra_element::<E>())
                    .collect(),
            )
        })
        .collect();
    let expected: Vec<_> = protocol
        .iter_openings()
        .zip(&points)
        .map(|((t, batch), point)| {
            batch
                .current()
                .iter()
                .map(|&col| Poly::new(tables[t].poly(col).as_slice().to_vec()).eval_base(point))
                .collect::<Vec<_>>()
        })
        .collect();
    let mut prover = challenger(SEED);
    let (cap, data) = pcs.commit(tables, &mut prover)?;
    let proof = pcs.open_at(data, &protocol, &points, &mut prover)?;
    let mut native = challenger(SEED);
    pcs.observe_commitment(&cap, &mut native);
    let evals = pcs.verify_at(&cap, &proof, &protocol, &points, &mut native)?;
    assert!(
        evals
            .iter()
            .zip(&expected)
            .all(|(actual, want)| actual.current() == want)
    );
    let next = native.sample_algebra_element::<E>();
    let BooleanWhirOpening::Deferred(opening) = &proof.opening else {
        panic!("expected deferred opening")
    };
    let tensors: Vec<_> = opening.reduction.claims.iter().map(|c| &c.tensor).collect();
    assert_eq!(tensors.len(), plan.ring_claim_count());
    let wire = postcard::to_allocvec(&(&proof.values, tensors, &opening.opening))?;
    let (values, tensors, whir): Wire = postcard::from_bytes(&wire)?;
    let config = WhirConfig::<CE, CF, Ch>::new_with_domain(
        plan.num_variables() - 6,
        ProtocolParameters {
            security_level: 152,
            pow_bits: 16,
            round_log_inv_rates: vec![],
            folding_factor: FoldingFactor::Constant(crate::WHIR_FOLD),
            soundness_type: SecurityAssumption::JohnsonBound,
            starting_log_inv_rate: crate::WHIR_LOG_INV_RATE,
        },
        &BinaryWhirDomain::<CF>::default(),
    )?;
    let cap_height = crate::WHIR_CAP_HEIGHT;
    let mmcs = Mmcs::new(
        SerializingHasher::new(Keccak256Hash),
        CompressionFunctionFromHasher::new(Keccak256Hash),
        cap_height,
    );
    let verifier = BinaryPolyDeferredWhirTraceVerifier::new(
        &config,
        plan.protocol().clone(),
        ByteHash::Keccak256,
        cap_height,
        deferred_seed(plan.num_variables(), plan.ring_claim_count()),
    )?;
    let old_cap = MerkleCap::<CF, [u8; 32]>::new(cap.roots().to_vec());
    let logical_points: Vec<Vec<_>> = points
        .iter()
        .map(|p| {
            p.iter()
                .map(|v| CE::new(v.coefficients().map(|c| CF::new(c.to_bits()))))
                .collect()
        })
        .collect();
    let old_points: Vec<_> = plan
        .opening_points(&logical_points, |raw| CE::from(CF::new(raw)))?
        .into_iter()
        .map(OldPoint::new)
        .collect();
    let mut imported = Ch::from_hasher(SEED.to_vec(), Keccak256Hash);
    verifier.observe_native_commitment(&mut imported, &old_cap)?;
    let private = verifier.import_native(
        &config,
        &mmcs,
        &old_cap,
        &old_points,
        &values,
        &tensors,
        &PcsProof {
            evals: vec![],
            whir,
        },
        &mut imported,
    )?;
    assert_eq!(
        imported
            .sample_algebra_element::<CE>()
            .coefficients()
            .map(|c| c.to_bits()),
        next.coefficients().map(|c| c.to_bits())
    );
    let mut b = CircuitBuilder::<CF>::new();
    b.enable_native_keccak_f1600()?;
    let cap_targets: Vec<_> = cap
        .roots()
        .iter()
        .map(|_| b.alloc_public_input_array::<16>("cap").to_vec())
        .collect();
    let point_targets: Vec<Vec<_>> = points
        .iter()
        .map(|p| p.iter().map(|_| target(&mut b)).collect())
        .collect();
    let point_targets =
        plan.opening_points(&point_targets, |raw| b.native_poly192_constant([raw, 0, 0]))?;
    let proof_targets = verifier.allocate_native_targets(&mut b)?;
    let seed: Vec<_> = SEED
        .iter()
        .map(|&v| b.define_const(CF::new(u64::from(v))))
        .collect();
    let mut ch = BinaryTower128Challenger::with_initial_bytes_with_host::<NativeBinaryEncoding, CF>(
        &mut b,
        ByteHash::Keccak256,
        &seed,
    )?;
    verifier.observe_commitment_native(&mut b, &mut ch, &cap_targets)?;
    let (authenticated, _) =
        verifier.verify_at_native(&mut b, ch, &cap_targets, &point_targets, &proof_targets)?;
    let actual = plan.recombine_native(&mut b, &authenticated)?;
    for value in actual.iter().flat_map(|v| v.current()) {
        let expected = target(&mut b);
        for (&a, &e) in value.coefficients().iter().zip(expected.coefficients()) {
            b.connect(a, e);
        }
    }
    let circuit = b.build()?;
    let mut public: Vec<_> = cap
        .roots()
        .iter()
        .flat_map(|r| bytes_to_limbs(r).into_iter().map(|v| CF::new(u64::from(v))))
        .collect();
    public.extend(
        points
            .iter()
            .flat_map(|p| p.iter())
            .chain(evals.iter().flat_map(|v| v.current()))
            .flat_map(|v| v.coefficients().map(|c| CF::new(c.to_bits()))),
    );
    assert!(accepts(&circuit, &public, &private));
    let output_start = public.len() - 3 * evals.iter().map(|v| v.current().len()).sum::<usize>();
    for index in (output_start..public.len()).step_by(3).chain([0, 16]) {
        let mut bad = public.clone();
        bad[index] = CF::new(bad[index].to_bits() ^ 1);
        assert!(!accepts(&circuit, &bad, &private), "public {index}");
    }
    // Mutate authenticated readings after import, including a matching forged logical output.
    let mut bad_public = public.clone();
    bad_public[output_start] = CF::new(bad_public[output_start].to_bits() ^ 1);
    let mut bad_private = private.clone();
    bad_private[3 * 17] = CF::new(bad_private[3 * 17].to_bits() ^ 1);
    assert!(!accepts(&circuit, &bad_public, &bad_private));
    for index in [0, 3, private.len() - 1] {
        let mut bad = private.clone();
        bad[index] = CF::new(bad[index].to_bits() ^ 1);
        assert!(!accepts(&circuit, &public, &bad));
    }
    Ok(())
}
