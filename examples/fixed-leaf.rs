//! Native controls on the same statements and private inputs as the LeanVM leaf benchmark.
#[path = "../adapters/leanvm/examples/support/imt.rs"]
mod fixture;

use anyhow::{Result, ensure};
use imt_flock_backend::{HashBackend, Prepared};
use recursive_imt_prover::binary::{
    IMT_DEPTH,
    aggregation_tree::TreeStatement,
    relation::{ClientPublic, ClientWitness, membership_circuit},
    tree::{commitment, input_tag, parent, preimage_leaf},
    veil::child::{PREIMAGE_PROTOCOL, PreparedMembership},
};
use serde_json::json;
use std::time::Instant;

fn main() -> Result<()> {
    let preimage = match std::env::args().nth(1).as_deref() {
        None => false,
        Some("--preimage") => true,
        _ => anyhow::bail!("usage: fixed-leaf [--preimage]"),
    };
    let [input_label, input_nonce, output_label, output_nonce] = fixture::record_fields();
    let witness = ClientWitness {
        input_label,
        input_nonce,
        output_label,
        output_nonce,
        quantity: fixture::QUANTITY,
        leaf_index: fixture::INDEX,
        merkle_path: fixture::siblings().into(),
    };
    let mut root = if preimage {
        preimage_leaf(&input_label)
    } else {
        commitment(&input_label, &input_nonce, witness.quantity)
    };
    for (level, sibling) in witness.merkle_path.iter().enumerate() {
        root = if witness.leaf_index >> level & 1 == 1 {
            parent(sibling, &root)
        } else {
            parent(&root, sibling)
        };
    }
    if preimage {
        let circuit =
            PreparedMembership::for_protocol(IMT_DEPTH, Default::default(), PREIMAGE_PROTOCOL)?;
        let public = ClientPublic::membership_root(root);
        for sample in 0..4 {
            let start = Instant::now();
            let proof =
                circuit.prove_preimage(root, &input_label, fixture::INDEX, &witness.merkle_path)?;
            let prove_s = start.elapsed().as_secs_f64();
            let bytes = proof.to_bytes()?;
            let start = Instant::now();
            let decoded =
                recursive_imt_prover::binary::veil::child::MaskedMembershipProof::from_bytes(
                    &bytes,
                )?;
            circuit.verify(&public, &decoded)?;
            let verify_s = start.elapsed().as_secs_f64();
            let mut wrong = public.clone();
            wrong.root[0] ^= 1;
            ensure!(
                circuit.verify(&wrong, &decoded).is_err(),
                "accepted another public root"
            );
            println!(
                "{}",
                json!({"protocol":PREIMAGE_PROTOCOL, "sample":sample, "public_root":hex::encode(root), "bytes": bytes.len(),"prove_s":prove_s,"decode_verify_s":verify_s})
            );
        }
        return Ok(());
    }
    let public = ClientPublic {
        root,
        input_tag: input_tag(&input_nonce),
        output_commitment: commitment(&output_label, &output_nonce, witness.quantity),
    };
    let digest = hex::encode(TreeStatement::leaf(&public).digest);
    let private = witness.fields(IMT_DEPTH)?;
    for backend in [HashBackend::Checkpoint, HashBackend::Flock] {
        let circuit = Prepared::repeated(
            membership_circuit(IMT_DEPTH)?,
            1,
            b"imt-fixed-leaf-comparison-v1",
            backend,
        )?;
        for sample in 0..4 {
            let (proof, metrics) = circuit.prove(&public.fields(), &private)?;
            circuit.verify(&proof, &public.fields())?;
            let mut wrong = public.clone();
            wrong.input_tag[0] ^= 1;
            ensure!(
                circuit.verify(&proof, &wrong.fields()).is_err(),
                "accepted changed tag"
            );
            println!(
                "{}",
                json!({"backend":backend,"sample":sample,"digest":digest,
                "hashes":circuit.geometry.keccak_permutations,"cells":circuit.geometry.initial_codeword_cells,
                "metrics":metrics})
            );
        }
    }
    Ok(())
}
