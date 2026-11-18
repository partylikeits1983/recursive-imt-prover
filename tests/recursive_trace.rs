use p3_binary_field::{BinaryChallenger, Poly64 as F, Poly192 as E};
use p3_binary_pcs::{
    BooleanTraceCommitment, BooleanTraceCommitmentProof,
    whir::{BinaryWhirDomain, BooleanWhirPcs, BooleanWhirProof},
};
use p3_challenger::{FieldChallenger, HashChallenger};
use p3_circuit::{
    Circuit, CircuitBuilder,
    ops::{ByteHash, NativePoly192Target, binary_encoding::NativeBinaryEncoding, bytes_to_limbs},
};
use p3_commit::MultilinearPcs;
use p3_field::PrimeCharacteristicRing;
use p3_keccak::Keccak256Hash;
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_multilinear_util::point::Point;
use p3_recursion::{BinaryTower128Challenger, pcs::binary::BinaryPolyBooleanWhirTraceVerifier};
use p3_sumcheck::{
    OpeningBatch, OpeningProtocol, PrescribedPointPcs, TableShape, TableSpec,
    layout::{SuffixProver, Table, plan_stacked_layout},
};
use p3_symmetric::{CompressionFunctionFromHasher, SerializingHasher};
use p3_whir::{FoldingFactor, ProtocolParameters, SecurityAssumption, WhirConfig, WhirProver};

type Ch = BinaryChallenger<F, HashChallenger<u8, Keccak256Hash, 32>>;
type Mmcs = MerkleTreeMmcs<
    F,
    u8,
    SerializingHasher<Keccak256Hash>,
    CompressionFunctionFromHasher<Keccak256Hash, 2, 32>,
    2,
    32,
>;
type Proof = BooleanTraceCommitmentProof<E, BooleanWhirProof<F, E, Mmcs>>;
const SEED: &[u8] = b"multi-table-recursive-test";

fn challenger() -> Ch {
    Ch::from_hasher(SEED.to_vec(), Keccak256Hash {})
}

fn public_value(b: &mut CircuitBuilder<F>) -> NativePoly192Target {
    let coefficients = b.alloc_public_input_array::<3>("opening");
    b.native_poly192_from_coefficients(coefficients)
}

fn bind(b: &mut CircuitBuilder<F>, actual: &NativePoly192Target) {
    let expected = public_value(b);
    for (&a, &e) in actual.coefficients().iter().zip(expected.coefficients()) {
        b.connect(a, e);
    }
}

fn accepts(circuit: &Circuit<F>, public: &[F], private: &[F]) -> bool {
    let mut runner = circuit.runner();
    runner
        .set_public_inputs(public)
        .and_then(|()| runner.set_private_inputs(private))
        .and_then(|()| runner.run())
        .is_ok()
}

#[test]
fn complete_multi_table_openings_are_constrained() {
    // Small test-only query budget. Production security settings are unchanged.
    let shapes = [
        (8, 3, true, 2),
        (9, 5, false, 1),
        (7, 1, true, 1),
        (8, 2, false, 0),
    ];
    let protocol = OpeningProtocol::new(
        shapes
            .iter()
            .map(|&(rows, width, next, count)| {
                let columns: Vec<_> = (0..width).collect();
                TableSpec::new(
                    TableShape::new(rows, width),
                    vec![
                        OpeningBatch::new(columns.clone(), if next { columns } else { vec![] });
                        count
                    ],
                )
            })
            .collect(),
    );
    let bits = plan_stacked_layout(&protocol.table_shapes()).0;
    let config = WhirConfig::<E, F, Ch>::new_with_domain(
        bits - 6,
        ProtocolParameters {
            security_level: 16,
            pow_bits: 0,
            round_log_inv_rates: vec![],
            folding_factor: FoldingFactor::Constant(2),
            soundness_type: SecurityAssumption::JohnsonBound,
            starting_log_inv_rate: 2,
        },
        &BinaryWhirDomain::<F>::default(),
    )
    .unwrap();
    let mmcs = Mmcs::new(
        SerializingHasher::new(Keccak256Hash {}),
        CompressionFunctionFromHasher::new(Keccak256Hash {}),
        0,
    );
    let inner = WhirProver::<E, F, _, _, Ch, SuffixProver<F, E>>::new(
        config.clone(),
        BinaryWhirDomain::<F>::default(),
        mmcs.clone(),
    );
    let pcs = BooleanTraceCommitment::from_commitment(BooleanWhirPcs::new(inner, bits).unwrap());
    let verifier =
        BinaryPolyBooleanWhirTraceVerifier::new(&config, protocol.clone(), ByteHash::Keccak256, 0)
            .unwrap();
    let mut random = challenger();
    let tables = shapes
        .iter()
        .map(|&(rows, width, _, _)| {
            let words = (0..width * (1 << (rows - 6)))
                .map(|_| random.sample_algebra_element::<F>().to_bits() | (1 << 63))
                .collect();
            Table::from_packed_bits(RowMajorMatrix::new(words, width), rows)
        })
        .collect();
    let points: Vec<_> = protocol
        .iter_openings()
        .map(|(table, _)| {
            Point::new(
                (0..shapes[table].0)
                    .map(|_| random.sample_algebra_element::<E>())
                    .collect(),
            )
        })
        .collect();
    let mut prover = challenger();
    let (commitment, data) = pcs.commit(tables, &mut prover).unwrap();
    let proof = pcs.open_at(data, &protocol, &points, &mut prover).unwrap();
    let proof: Proof = postcard::from_bytes(&postcard::to_allocvec(&proof).unwrap()).unwrap();
    let mut native = challenger();
    pcs.observe_commitment(&commitment, &mut native);
    pcs.verify_at(&commitment, &proof, &protocol, &points, &mut native)
        .unwrap();
    let next = native.sample_algebra_element::<E>();
    let mut entry = challenger();
    pcs.observe_commitment(&commitment, &mut entry);
    let private = verifier
        .import_native(&config, &mmcs, &commitment, &points, &proof, &mut entry)
        .unwrap()
        .private_native_values(&verifier.input_shape())
        .unwrap();
    assert_eq!(entry.sample_algebra_element::<E>(), next);

    let mut b = CircuitBuilder::<F>::new();
    b.enable_native_keccak_f1600().unwrap();
    let cap = vec![b.alloc_public_input_array::<16>("commitment").to_vec()];
    let targets: Vec<Vec<_>> = points
        .iter()
        .map(|point| point.iter().map(|_| public_value(&mut b)).collect())
        .collect();
    let proof_targets = verifier
        .input_shape()
        .allocate_native_targets(&mut b)
        .unwrap();
    let seed: Vec<_> = SEED
        .iter()
        .map(|&byte| b.define_const(F::new(u64::from(byte))))
        .collect();
    let mut ch = BinaryTower128Challenger::with_initial_bytes_with_host::<NativeBinaryEncoding, F>(
        &mut b,
        ByteHash::Keccak256,
        &seed,
    )
    .unwrap();
    verifier
        .observe_commitment_native(&mut b, &mut ch, &cap)
        .unwrap();
    let (values, mut ch) = verifier
        .verify_at_native(&mut b, ch, &cap, &targets, &proof_targets)
        .unwrap();
    for value in values
        .iter()
        .flat_map(|v| v.current().iter().chain(v.next()))
    {
        bind(&mut b, value);
    }
    let next_bits = ch
        .sample_poly192_with_host::<NativeBinaryEncoding, F>(&mut b)
        .unwrap();
    let next_target = b
        .native_poly192_from_bits(core::array::from_fn(|i| {
            next_bits.coefficients()[i / 64].bits()[i % 64]
        }))
        .unwrap();
    bind(&mut b, &next_target);
    let circuit = b.build().unwrap();
    let mut public: Vec<_> = commitment
        .roots()
        .iter()
        .flat_map(|root| {
            bytes_to_limbs(root)
                .into_iter()
                .map(|v| F::new(u64::from(v)))
        })
        .collect();
    public.extend(
        points
            .iter()
            .flat_map(|p| p.iter())
            .chain(&proof.values)
            .chain([&next])
            .flat_map(|v| v.coefficients()),
    );
    assert!(accepts(&circuit, &public, &private));
    let opened_start = 16 + 3 * points.iter().map(Point::num_variables).sum::<usize>();
    for index in [
        0,
        16,
        opened_start,
        opened_start + 3 * 12,
        opened_start + 3 * 17,
        public.len() - 1,
    ] {
        let mut bad = public.clone();
        bad[index] += F::ONE;
        assert!(!accepts(&circuit, &bad, &private), "public {index}");
    }
    // Alter proof data after import, bypassing every native precheck.
    for index in [0, 3 * 12, 3 * 17, private.len() - 1] {
        let mut bad = private.clone();
        bad[index] += F::ONE;
        assert!(!accepts(&circuit, &public, &bad), "private {index}");
    }
    for index in [0, 9, 3 * 12, 3 * 17, 3 * 18] {
        let mut bad_private = private.clone();
        let mut bad_public = public.clone();
        bad_private[index] += F::ONE;
        bad_public[opened_start + index] += F::ONE;
        assert!(
            !accepts(&circuit, &bad_public, &bad_private),
            "forged matching opening {index}"
        );
    }
}
