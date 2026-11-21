use super::*;
use experimental_lean_vm_core::cpu::{execute, from_scalar};
use recursive_imt_prover::binary::cli::membership_fixtures;

#[test]
#[ignore = "generates a full masked depth-32 client proof and executes its stacked oracle verifier"]
fn real_client_checkpoint_binds_statement_queries_and_paths() -> Result<()> {
    let params = Parameters::default();
    let trusted =
        PreparedMembership::for_protocol(IMT_DEPTH, params.clone(), ALIGNED_PREIMAGE_PROTOCOL)?;
    let (statement, witness) = membership_fixtures(IMT_DEPTH, 1, true)?.remove(0);
    let proof = trusted.prove(&statement, &witness)?;
    let proof = MaskedMembershipProof::from_bytes(&proof.to_bytes()?)?;
    trusted.verify(&statement, &proof)?;
    let original = PreparedMembership::for_protocol(IMT_DEPTH, params.clone(), PREIMAGE_PROTOCOL)?;
    assert_ne!(trusted.identity(), original.identity());
    assert!(original.verify(&statement, &proof).is_err());
    let cp = trusted.stacked_oracle_checkpoint(&statement, &proof)?;
    let mut inputs = advice(&statement, &cp, &trusted);
    let program = guest::program(&trusted, &params, false);
    let public: [E; 2] = verifier::Digest(digest(
        &statement.root,
        &cp,
        trusted.stacked_row_domains().0,
    ))
    .halves()
    .into();
    let run = |inputs: &[(String, Vec<Vec<E>>)]| run_guest(&program, inputs, public);
    run(&inputs)?;
    for (name, entry, word, delta) in [
        ("root", 0, 0, E::new(1, 0)),
        ("point", 0, 0, E::new(1, 0)),
        ("columns", 0, 20, E::new(0, 1)),
        ("row", 0, 18, E::new(1, 0)),
        ("sibling", 0, 0, E::new(1, 0)),
    ] {
        let i = inputs.iter().position(|(n, _)| n == name).unwrap();
        inputs[i].1[entry][word] += delta;
        assert!(run(&inputs).is_err(), "guest accepted changed {name}");
        inputs[i].1[entry][word] += delta;
    }
    // These two changes cancel in the packed Keccak input. The guest must
    // independently reject the out-of-range byte at the serialization boundary.
    let mask = inputs.iter_mut().find(|(name, _)| name == "mask").unwrap();
    mask.1[0][0] += E::new(256, 0);
    mask.1[0][1] += E::new(1, 0);
    assert!(run(&inputs).is_err());
    let cp = trusted.stacked_blend_checkpoint(&statement, &proof)?;
    let program = guest::program(&trusted, &params, true);
    let blend_public: [E; 2] = verifier::Digest(digest(
        &statement.root,
        &cp,
        trusted.stacked_row_domains().0,
    ))
    .halves()
    .into();
    let run_blend = |inputs: &[(String, Vec<Vec<E>>)], pi: [E; 2]| run_guest(&program, inputs, pi);
    let mut inputs = advice(&statement, &cp, &trusted);
    run_blend(&inputs, blend_public)?;
    assert!(run_blend(&inputs, public).is_err());
    for (name, entry, word) in [
        ("sumcheck", 0, 0),
        ("sumcheck", cp.blend.as_ref().unwrap().rounds.len() - 1, 5),
        ("blend_value", 0, 2),
    ] {
        let idx = inputs.iter().position(|(n, _)| n == name).unwrap();
        inputs[idx].1[entry][word] += E::new(1, 0);
        let err = run_blend(&inputs, blend_public).expect_err("altered sumcheck accepted");
        assert!(
            err.site.starts_with("check_blend_endpoint "),
            "changed {name} rejected at unexpected site: {err}"
        );
        inputs[idx].1[entry][word] += E::new(1, 0);
    }
    let plan = trusted.stacked_whir_plan()?;
    let (raw, seal) = trusted.stacked_whir_advice(&proof, cp.blend.as_ref().unwrap())?;
    let (program, schema, _) = guest::compile(&trusted, &params, true, Some(&plan), false, false);
    let pi = verifier::Digest(digest_with_seal(
        &statement.root,
        &cp,
        trusted.stacked_row_domains().0,
        Some(&seal),
        None,
    ))
    .halves()
    .into();
    let mut inputs = advice(&statement, &cp, &trusted);
    inputs.extend(whir::advice(&schema, &raw)?);
    run_guest(&program, &inputs, pi)?;
    // Modify advice after native decoding and reference verification.
    for i in [0, plan.sites.len() - 1] {
        for (name, at_end) in [
            (format!("pcs_row_{i}"), false),
            (format!("pcs_path_{i}"), true),
        ] {
            let stream = &mut inputs.iter_mut().find(|(n, _)| n == &name).unwrap().1;
            let index = if at_end { stream.len() - 1 } else { 0 };
            stream[index][0] += E::new(1, 0);
            let err =
                run_guest(&program, &inputs, pi).expect_err("invalid WHIR path or row accepted");
            assert!(
                err.site.starts_with(&format!("pcs_row_{i} ")),
                "unexpected rejection {err}"
            );
            inputs.iter_mut().find(|(n, _)| n == &name).unwrap().1[index][0] += E::new(1, 0);
        }
    }
    let constraints = trusted.constraint_messages(&statement, &proof)?;
    let (membership, pcs, vectors) =
        guest::compile(&trusted, &params, true, Some(&plan), true, true);
    let pi = verifier::Digest(statement.root).halves().into();
    let mut full = full_advice(
        &statement,
        &cp,
        &trusted,
        &raw,
        &pcs,
        &constraints,
        &vectors,
    )?;
    run_guest(&membership, &full, pi)?;
    for key in [
        "column_fields",
        "product_wires",
        "product_claims",
        "open_had_pcs_row_0",
        "mask_claim",
        "mask_sibling",
        "open_masked_pcs_row_0",
    ] {
        let i = full.iter().position(|(k, _)| k == key).unwrap();
        full[i].1[0][0] += E::new(1, 0);
        let err =
            run_guest(&membership, &full, pi).expect_err("guest accepted corrupted masked proof");
        assert!(!err.site.is_empty(), "missing guest error for {key}");
        full[i].1[0][0] += E::new(1, 0);
    }
    Ok(())
}

fn run_guest(
    program: &isa::Program,
    inputs: &[(String, Vec<Vec<E>>)],
    public: [E; 2],
) -> Result<(), experimental_lean_vm_core::cpu::ExecError> {
    let hints = inputs
        .iter()
        .map(|(name, stream)| {
            (
                name.clone(),
                stream
                    .iter()
                    .map(|row| row.iter().copied().map(from_scalar).collect())
                    .collect(),
            )
        })
        .collect::<Vec<_>>();
    execute(program, &hints, public.map(from_scalar)).map(|_| ())
}
