mod privacy;

use std::panic::{AssertUnwindSafe, catch_unwind};

use anyhow::Result;
use p3_air::check_constraints;
use p3_field::PrimeCharacteristicRing;

use super::{MaskedMembershipProof, PendingChild, PreparedMembership};
use crate::binary::{
    cli::fixtures,
    tree::{commitment, input_tag},
    veil::{
        F,
        membership_air::{
            CheckLayout, DIRECTION, MembershipAir, NONCE, ROWS_PER_HASH, STATE_START, WIDTH,
        },
        parameters::Parameters,
    },
};

#[test]
fn membership_air_constrains_the_entire_hash_chain() -> Result<()> {
    for layout in [
        CheckLayout::Bitwise,
        CheckLayout::Packed,
        CheckLayout::PackedInputs,
    ] {
        check_hash_chain(32, layout)?;
    }
    Ok(())
}

fn check_hash_chain(depth: usize, layout: CheckLayout) -> Result<()> {
    let (public, witness) = fixtures(depth, 1)?.remove(0);
    let mut air = MembershipAir::new(depth)?;
    air.checks = layout;
    let trace = air.trace(&public, &witness)?;
    let inputs = MembershipAir::public_values(&public);
    check_constraints(&air, &trace, &inputs);
    if layout == CheckLayout::PackedInputs {
        for pos in [
            ROWS_PER_HASH * WIDTH + STATE_START + 47 * 8,
            24 * WIDTH + STATE_START + 255,
            875 * WIDTH + STATE_START + 16 * 8,
            1023 * WIDTH + STATE_START + 199 * 8,
        ] {
            let mut bad = trace.clone();
            bad.values[pos] += F::new(2);
            assert!(
                catch_unwind(AssertUnwindSafe(|| check_constraints(&air, &bad, &inputs))).is_err()
            );
        }
    }
    // This mutation leaves the packed value of the lane unchanged in GF(2^64).
    // It must fail because the Keccak AIR constrains the individual bits.
    let mut nonboolean = trace.clone();
    nonboolean.values[STATE_START] += F::new(2);
    nonboolean.values[STATE_START + 1] += F::ONE;
    assert!(
        catch_unwind(AssertUnwindSafe(|| check_constraints(
            &air,
            &nonboolean,
            &inputs
        )))
        .is_err()
    );
    for kind in 0..10 {
        let mut bad = trace.clone();
        let cell = match kind {
            0 => STATE_START + 16 * 8,     // input label
            1 => STATE_START + 48 * 8,     // input nonce
            2 => 500 * WIDTH + NONCE,      // carried input nonce
            3 => STATE_START,              // leaf domain
            4 => STATE_START + 88 * 8,     // Keccak suffix
            5 => 24 * WIDTH + STATE_START, // leaf output / link
            6 => 24 * WIDTH + DIRECTION,
            7 => 25 * WIDTH + 24, // schedule: first node or padding flag
            8 => 33 * ROWS_PER_HASH * WIDTH + STATE_START, // tag domain
            _ => (34 * ROWS_PER_HASH - 1) * WIDTH + STATE_START, // input tag
        };
        bad.values[cell] += F::ONE;
        assert!(
            catch_unwind(AssertUnwindSafe(|| check_constraints(&air, &bad, &inputs))).is_err(),
            "depth={depth}, mutation={kind}"
        );
    }
    for kind in 0..3 {
        let mut altered = public.clone();
        if kind == 0 {
            altered.root[0] ^= 1;
        } else if kind == 1 {
            altered.input_tag[0] ^= 1;
        } else {
            altered.output_commitment[0] ^= 1;
        }
        assert!(
            catch_unwind(AssertUnwindSafe(|| check_constraints(
                &air,
                &trace,
                &MembershipAir::public_values(&altered)
            )))
            .is_err()
        );
    }
    // Both Keccak computations are valid, but they use different nonces.
    let mut other = witness.clone();
    other.input_nonce[31] ^= 1;
    let other_trace = air.trace(&public, &other)?;
    let mut forged = trace.clone();
    let first = 33 * ROWS_PER_HASH;
    for row in first..first + ROWS_PER_HASH {
        forged.values[row * WIDTH..row * WIDTH + NONCE]
            .copy_from_slice(&other_trace.values[row * WIDTH..row * WIDTH + NONCE]);
    }
    let mut changed = public.clone();
    changed.input_tag = input_tag(&other.input_nonce);
    let changed_inputs = MembershipAir::public_values(&changed);
    assert!(
        catch_unwind(AssertUnwindSafe(|| check_constraints(
            &air,
            &forged,
            &changed_inputs
        )))
        .is_err()
    );
    // Replacing all carry cells cannot disconnect the original leaf preimage.
    for row in 0..air.height() {
        forged.values[row * WIDTH + NONCE..(row + 1) * WIDTH]
            .copy_from_slice(&other_trace.values[row * WIDTH + NONCE..(row + 1) * WIDTH]);
    }
    assert!(
        catch_unwind(AssertUnwindSafe(|| check_constraints(
            &air,
            &forged,
            &changed_inputs
        )))
        .is_err()
    );
    // A valid output hash for another quantity must fail even when the
    // public commitment and every round of that hash agree.
    let mut other = witness.clone();
    other.quantity ^= 1 << 63;
    let other_trace = air.trace(&public, &other)?;
    let mut forged = trace.clone();
    let start = 34 * ROWS_PER_HASH;
    for row in start..start + ROWS_PER_HASH {
        let state = row * WIDTH..row * WIDTH + DIRECTION;
        forged.values[state.clone()].copy_from_slice(&other_trace.values[state]);
    }
    let mut changed = public.clone();
    changed.output_commitment =
        commitment(&other.output_label, &other.output_nonce, other.quantity);
    let inputs = MembershipAir::public_values(&changed);
    assert!(
        catch_unwind(AssertUnwindSafe(|| check_constraints(
            &air, &forged, &inputs
        )))
        .is_err()
    );
    Ok(())
}

#[test]
#[cfg_attr(debug_assertions, ignore = "depth-32 child proof; run with --release")]
fn compiled_child_roundtrip_and_forged_public_input_rejection() -> Result<()> {
    for (protocol, other) in [
        (super::PROTOCOL, super::PACKED_PROTOCOL),
        (super::PACKED_PROTOCOL, super::PROTOCOL),
    ] {
        check_compiled_roundtrip(protocol, other)?;
    }
    Ok(())
}

fn check_compiled_roundtrip(protocol: &str, other: &str) -> Result<()> {
    let parameters = Parameters::default();
    let prepared = PreparedMembership::for_protocol(32, parameters.clone(), protocol)?;
    let (public, witness) = fixtures(32, 1)?.remove(0);
    let proof = prepared.prove(&public, &witness)?;
    let bytes = proof.to_bytes()?;
    let decoded = MaskedMembershipProof::from_bytes(&bytes)?;
    for old_magic in [
        b"IMTVCA01",
        b"IMTVCA02",
        b"IMTVCA03",
        b"IMTVCA04",
        b"IMTVCA05",
        b"IMTVCA06",
    ] {
        let mut old = bytes.clone();
        old[..8].copy_from_slice(old_magic);
        assert!(MaskedMembershipProof::from_bytes(&old).is_err());
    }
    prepared.verify(&public, &decoded)?;
    let foreign = PreparedMembership::for_protocol(32, parameters.clone(), other)?;
    assert_ne!(foreign.identity(), prepared.identity());
    assert!(foreign.verify(&public, &decoded).is_err());
    for kind in 0..3 {
        let mut altered = public.clone();
        if kind == 0 {
            altered.root[0] ^= 1;
        } else if kind == 1 {
            altered.input_tag[0] ^= 1;
        } else {
            altered.output_commitment[0] ^= 1;
        }
        assert!(prepared.verify(&altered, &decoded).is_err());
    }
    assert!(
        PreparedMembership::for_protocol(
            32,
            Parameters {
                query_bits: 161,
                ..parameters.clone()
            },
            protocol
        )?
        .verify(&public, &decoded)
        .is_err()
    );
    for unsupported in [0, 1, 8, 16, 31, 33] {
        assert!(PreparedMembership::new(unsupported, parameters.clone()).is_err());
    }
    let mut appended = bytes.clone();
    appended.push(0);
    assert!(MaskedMembershipProof::from_bytes(&appended).is_err());
    for i in [0, 8, bytes.len() / 2, bytes.len() - 1] {
        let mut altered = bytes.clone();
        altered[i] ^= 0x80;
        if let Ok(proof) = MaskedMembershipProof::from_bytes(&altered) {
            assert!(prepared.verify(&public, &proof).is_err());
        }
    }

    // Actual proof attempt for a false statement, bypassing only the prover's
    // private relation precheck. The child verifier must enforce the AIR itself.
    let trace = prepared.witness(&public, &witness)?;
    let mut false_public = public.clone();
    false_public.output_commitment[0] ^= 1;
    let mut rng = rand::rngs::SysRng;
    let PendingChild { root, ctx, opening } = prepared.prepare(&false_public, trace, &mut rng)?;
    let inner = ctx.finish_unchecked(
        |reader| prepared.replay(&false_public, &root, &opening, reader),
        &mut rng,
    )?;
    let forged = MaskedMembershipProof {
        oracle_root: root,
        inner,
        opening,
    };
    assert!(prepared.verify(&false_public, &forged).is_err());
    Ok(())
}

#[test]
fn preimage_profile_enforces_the_root_path_and_reserved_fields() -> Result<()> {
    use crate::binary::{
        IMT_DEPTH,
        cli::membership_fixtures,
        tree::{Imt, keccak},
    };
    let mut air = MembershipAir::new(IMT_DEPTH)?;
    air.checks = CheckLayout::Preimage;
    let (public, witness) = membership_fixtures(IMT_DEPTH, 1, true)?.remove(0);
    let trace = air.preimage_trace(
        &witness.input_label,
        witness.leaf_index,
        &witness.merkle_path,
    )?;
    let inputs = public.fields();
    check_constraints(&air, &trace, &inputs);
    assert_eq!(trace.width, DIRECTION + 1);
    let rejects = |trace: &p3_matrix::dense::RowMajorMatrix<F>, inputs: &[F]| {
        catch_unwind(AssertUnwindSafe(|| check_constraints(&air, trace, inputs))).is_err()
    };
    for field in [0, 32, 95] {
        let mut wrong = inputs.clone();
        wrong[field] += F::ONE;
        assert!(rejects(&trace, &wrong));
    }
    let mut preimage = witness.input_label;
    preimage[31] ^= 1;
    let mut path = witness.merkle_path.clone();
    path[IMT_DEPTH - 1][0] ^= 1;
    for (preimage, index, path) in [
        (&preimage, witness.leaf_index, &witness.merkle_path),
        (
            &witness.input_label,
            witness.leaf_index ^ 1,
            &witness.merkle_path,
        ),
        (&witness.input_label, witness.leaf_index, &path),
    ] {
        assert!(rejects(
            &air.preimage_trace(preimage, index, path)?,
            &inputs
        ));
    }
    assert!(
        air.preimage_trace(&preimage, 0, &path[..IMT_DEPTH - 1])
            .is_err()
    );
    let mut altered = trace.clone();
    altered.values[24 * trace.width + DIRECTION] = F::new(2);
    assert!(rejects(&altered, &inputs));
    let mut tree = Imt::new(IMT_DEPTH)?;
    // An ordinary Keccak-256 commitment without the protocol domain has a different root.
    tree.append(keccak(&preimage))?;
    let untagged = super::ClientPublic::membership_root(tree.root()).fields();
    assert!(rejects(
        &air.preimage_trace(&preimage, 0, &tree.path(0)?)?,
        &untagged
    ));
    Ok(())
}
