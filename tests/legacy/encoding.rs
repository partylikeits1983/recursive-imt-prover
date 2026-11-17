use p3_field::PrimeField32;
use recursive_imt_prover::legacy::{
    Claim, Digest, LeafVerifier, MAX_BATCH, Note, Profile, Statement,
};

#[test]
fn statement_preserves_canonical_json_and_little_endian_limbs() {
    let encoded = br#"{"version":4,"relation":"zk-sha3-256-imt-note-membership-v4","roots":["000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"],"amounts":[72623859790382856]}"#;
    let statement: Statement = serde_json::from_slice(encoded).unwrap();
    assert_eq!(serde_json::to_vec(&statement).unwrap(), encoded);
    assert_eq!(
        Statement::new([Claim {
            root: statement.roots[0],
            amount: statement.amounts[0]
        }])
        .unwrap(),
        statement
    );
    assert_eq!(
        statement.roots[0]
            .fields()
            .map(|limb| limb.as_canonical_u32()),
        [
            0x0100, 0x0302, 0x0504, 0x0706, 0x0908, 0x0b0a, 0x0d0c, 0x0f0e, 0x1110, 0x1312, 0x1514,
            0x1716, 0x1918, 0x1b1a, 0x1d1c, 0x1f1e,
        ]
    );
    assert_eq!(
        statement.bytes().unwrap(),
        [
            0, 1, 0, 0, 2, 3, 0, 0, 4, 5, 0, 0, 6, 7, 0, 0, 8, 9, 0, 0, 10, 11, 0, 0, 12, 13, 0, 0,
            14, 15, 0, 0, 16, 17, 0, 0, 18, 19, 0, 0, 20, 21, 0, 0, 22, 23, 0, 0, 24, 25, 0, 0, 26,
            27, 0, 0, 28, 29, 0, 0, 30, 31, 0, 0, 8, 7, 0, 0, 6, 5, 0, 0, 4, 3, 0, 0, 2, 1, 0, 0,
        ]
    );
}

#[test]
fn child_authority_preserves_canonical_bytes_and_trusted_profile() {
    let encoded = br#"{"version":4,"relation":"zk-sha3-256-imt-note-membership-v4","depth":4,"profile":"smoke"}"#;
    let verifier = LeafVerifier::decode(Profile::Smoke, encoded).unwrap();
    assert_eq!(verifier.bytes().unwrap(), encoded);
    assert_eq!(
        LeafVerifier::new(Profile::Smoke, 4)
            .unwrap()
            .bytes()
            .unwrap(),
        encoded
    );
    assert!(LeafVerifier::decode(Profile::Reference, encoded).is_err());
    let mut trailing_whitespace = encoded.to_vec();
    trailing_whitespace.push(b'\n');
    assert!(LeafVerifier::decode(Profile::Smoke, &trailing_whitespace).is_err());
}

#[test]
fn statement_rejects_unknown_fields_and_wrong_relation() {
    let mut value = serde_json::to_value(
        Statement::new([Claim {
            root: Digest([0; 32]),
            amount: 0,
        }])
        .unwrap(),
    )
    .unwrap();
    value["extra"] = true.into();
    assert!(serde_json::from_value::<Statement>(value).is_err());

    let mut statement = Statement::new([Claim {
        root: Digest([0; 32]),
        amount: 0,
    }])
    .unwrap();
    statement.relation = "other-relation".into();
    assert!(statement.fields().is_err());
}

#[test]
fn note_commitment_matches_fixed_width_sha3_reference() {
    let note = Note {
        secret: Digest([1; 32]),
        nullifier: Digest([2; 32]),
        amount: 0x0102030405060708,
    };
    assert_eq!(note.message().len(), 72);
    assert_eq!(&note.message()[64..], &[8, 7, 6, 5, 4, 3, 2, 1]);
    assert_eq!(
        String::from(note.commitment()),
        "51e604bf554e5facd5039f2c4cd0f172b0b3611e1de870084422d243b54d53d2"
    );
}

#[test]
fn statement_vectors_have_equal_lengths_and_support_maximum_batch() {
    let claims = (0..MAX_BATCH).map(|index| Claim {
        root: Digest([index as u8; 32]),
        amount: u64::MAX - index as u64,
    });
    let mut statement = Statement::new(claims).unwrap();
    assert_eq!(statement.fields().unwrap().len(), 20 * MAX_BATCH);
    assert!(serde_json::to_vec(&statement).unwrap().len() < 16 * 1024);
    statement.amounts.pop();
    assert!(statement.fields().is_err());
}
