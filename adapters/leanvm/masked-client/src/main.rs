//! LeanVM verification of the masked client's AIR reduction and stacked polynomial opening.
mod blend;
mod endpoint;
mod guest;
mod oracle;
mod vector;
mod whir;

use std::{
    io::Write,
    path::{Path, PathBuf},
    time::Instant,
};

use anyhow::{Context, Result, ensure};
use clap::{Parser, Subcommand};
use experimental_lean_vm_core::ExperimentalProver;
use isa::Prover;
use p3_binary_field::{Poly192, TowerLevel};
use recursive_imt_prover::{
    binary::{
        ClientPublic, IMT_DEPTH,
        veil::{
            child::{
                ALIGNED_PREIMAGE_PROTOCOL, MaskedMembershipProof, PREIMAGE_PROTOCOL,
                PreparedMembership, checkpoint::StackedOracleCheckpoint,
            },
            parameters::Parameters,
        },
    },
    files::{read_bounded, read_json},
};
use sha3::{Digest, Keccak256};
use verifier::{E, Proof};

#[derive(Parser)]
#[command(
    about = "Verify the masked client's AIR reduction and stacked oracle in LeanVM (component proof)"
)]
struct Args {
    /// Additionally verify the stacked oracle quadratic sumcheck and its terminal equation.
    #[arg(long, global = true)]
    blend: bool,
    /// Verify the complete stacked WHIR polynomial opening after the blend sumcheck.
    #[arg(long, global = true)]
    whir: bool,
    /// Verify the full masked membership proof against its public IMT root.
    #[arg(long, global = true)]
    membership: bool,
    /// Continue through both authenticated openings of the product-vector argument.
    #[arg(long, global = true)]
    products: bool,
    /// Read original masked-preimage-v1 clients with 18-byte stacked oracle domains.
    #[arg(long, global = true)]
    original_domains: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Write the trusted full membership subroutine for the recursive LeanVM guest.
    BuildGuest { out: PathBuf },
    /// Expand a saved public masked client proof into recursion advice.
    Prepare {
        client: PathBuf,
        out: PathBuf,
        /// Read one member of a saved batch prepared by cargo prove.
        #[arg(long)]
        index: Option<usize>,
    },
    /// Produce a checkpoint from the masked proof and its public statement.
    Prove {
        client: PathBuf,
        out: PathBuf,
        #[arg(short = 'j', default_value = "4")]
        threads: std::num::NonZeroUsize,
    },
    /// Verify the saved proof against the public checkpoint derived from a client transcript.
    Verify { client: PathBuf, proof: PathBuf },
}

#[cfg(test)]
fn digest(root: &[u8; 32], cp: &StackedOracleCheckpoint, leaf_domain: &[u8]) -> [u8; 32] {
    digest_with_seal(root, cp, leaf_domain, None, None)
}
fn digest_with_seal(
    root: &[u8; 32],
    cp: &StackedOracleCheckpoint,
    leaf_domain: &[u8],
    seal: Option<&[u8; 32]>,
    product_state: Option<&[u8; 32]>,
) -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update(if product_state.is_some() {
        vector::DOMAIN
    } else if seal.is_some() {
        whir::DOMAIN
    } else if cp.blend.is_some() {
        blend::DOMAIN
    } else {
        guest::CHECKPOINT_DOMAIN
    });
    h.update(root);
    h.update(cp.air_fingerprint);
    h.update(&cp.challenges);
    h.update(&cp.claim_coefficients);
    h.update(cp.query_fingerprint);
    for &q in &cp.query_indices {
        h.update((q as u64).to_le_bytes());
    }
    for row in &cp.openings {
        let mut leaf = Keccak256::new();
        leaf.update(leaf_domain);
        leaf.update(&row.salted_row);
        h.update(leaf.finalize());
    }
    if let Some(blend) = &cp.blend {
        h.update(blend.seed);
        for element in blend.point.iter().chain([&blend.value]) {
            for limb in element.coefficients() {
                h.update(limb.to_repr().to_le_bytes());
            }
        }
    }
    if let Some(seal) = seal {
        h.update(seal);
    }
    if let Some(state) = product_state {
        h.update(state);
    }
    h.finalize().into()
}

fn stream(name: &str, bytes: &[u8]) -> (String, Vec<Vec<E>>) {
    (
        name.to_owned(),
        vec![bytes.iter().map(|&b| E::new(u64::from(b), 0)).collect()],
    )
}

fn advice(
    public: &ClientPublic,
    cp: &StackedOracleCheckpoint,
    trusted: &PreparedMembership,
) -> Vec<(String, Vec<Vec<E>>)> {
    let height = trusted.trace_height();
    let (leaf, node) = trusted.stacked_row_domains();
    let mut inputs = vec![
        stream("root", &public.root),
        stream("oracle", &cp.oracle_root),
        stream("mask", &cp.mask_root),
        stream("rounds", &cp.masked_round_bytes),
        stream(
            "point",
            &cp.challenges[(2 + height.ilog2() as usize) * 24..],
        ),
        (
            "columns".into(),
            vec![oracle::packed_columns(&cp.column_evaluations)],
        ),
        stream("masks", &cp.mask_evaluations),
        stream("blend", &cp.blend_root),
        stream("evaluations", &cp.blend_evaluations),
        (
            "row".into(),
            cp.openings
                .iter()
                .map(|r| {
                    if cp.blend.is_some() {
                        raw_row(&r.salted_row)
                    } else {
                        oracle::packed_row(&r.salted_row, leaf)
                    }
                })
                .collect(),
        ),
        (
            "sibling".into(),
            cp.openings
                .iter()
                .flat_map(|r| {
                    r.siblings
                        .iter()
                        .map(|d| oracle::sibling(d, node.len() == 16))
                })
                .collect(),
        ),
    ];
    if let Some(blend) = &cp.blend {
        let limbs = |x: &Poly192| x.coefficients().map(|f| E::new(f.to_repr(), 0));
        inputs.push((
            "sumcheck".into(),
            blend
                .rounds
                .iter()
                .map(|r| r.iter().flat_map(limbs).collect())
                .collect(),
        ));
        inputs.push(("blend_value".into(), vec![limbs(&blend.value).to_vec()]));
    }
    inputs
}

fn raw_row(row: &[u8]) -> Vec<E> {
    row.chunks(16)
        .map(|c| {
            let mut word = [0; 16];
            word[..c.len()].copy_from_slice(c);
            E::new(
                u64::from_le_bytes(word[..8].try_into().unwrap()),
                u64::from_le_bytes(word[8..].try_into().unwrap()),
            )
        })
        .collect()
}

fn save_new(out: &Path, bytes: &[u8]) -> Result<()> {
    let dir = out
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut file = tempfile::NamedTempFile::new_in(dir)?;
    file.write_all(bytes)?;
    file.persist_noclobber(out)
        .with_context(|| format!("save to fresh path {}", out.display()))?;
    Ok(())
}

fn full_advice(
    public: &ClientPublic,
    cp: &StackedOracleCheckpoint,
    trusted: &PreparedMembership,
    raw: &[p3_binary_field::Poly64],
    schema: &[whir::Stream],
    vectors: &recursive_imt_prover::binary::veil::child::checkpoint::ConstraintMessages,
    vector_schemas: &[Vec<whir::Stream>],
) -> Result<Vec<(String, Vec<Vec<E>>)>> {
    let mut witness = advice(public, cp, trusted);
    witness.retain(|(name, _)| name != "columns");
    witness.push((
        "column_fields".into(),
        vec![
            cp.column_evaluations
                .as_chunks::<8>()
                .0
                .iter()
                .map(|b| E::new(u64::from_le_bytes(*b), 0))
                .collect(),
        ],
    ));
    witness.extend(whir::advice(schema, raw)?);
    witness.extend(vector::advice(vectors, vector_schemas)?);
    Ok(witness)
}

fn main() -> Result<()> {
    let args = Args::parse();
    let params = Parameters::default();
    let protocol = if args.original_domains {
        PREIMAGE_PROTOCOL
    } else {
        ALIGNED_PREIMAGE_PROTOCOL
    };
    let trusted = PreparedMembership::for_protocol(IMT_DEPTH, params.clone(), protocol)?;
    let full = args.membership || matches!(args.command, Command::Prepare { .. });
    let client = match &args.command {
        Command::BuildGuest { out } => {
            let plan = trusted.stacked_whir_plan()?;
            let (src, _, _) = guest::source(&trusted, &params, true, Some(&plan), true, true, true);
            save_new(out, src.as_bytes())?;
            return Ok(());
        }
        Command::Prepare { client, .. }
        | Command::Prove { client, .. }
        | Command::Verify { client, .. } => client,
    };
    let (public, proof_file) = if let Command::Prepare { index: Some(i), .. } = &args.command {
        let batch: recursive_imt_prover::binary::AggregatePublic =
            read_json(&client.join("statement.json"))?;
        (
            batch
                .children
                .get(*i)
                .context("index outside saved batch")?
                .clone(),
            client.join(format!("0-{i}.proof")),
        )
    } else {
        (
            read_json::<ClientPublic>(&client.join("statement.json"))?,
            client.join("child.proof"),
        )
    };
    ensure!(
        public == ClientPublic::membership_root(public.root),
        "expected a root-only statement"
    );
    if args.membership
        && let Command::Verify { proof, .. } = &args.command
    {
        let plan = trusted.stacked_whir_plan()?;
        let (program, _, _) = guest::compile(&trusted, &params, true, Some(&plan), true, true);
        let proof = Proof::from_bytes(&read_bounded(proof, 64 << 20)?)
            .context("malformed LeanVM membership proof")?;
        verifier::verify_execution(program.bytecode(), &public.root, &proof)?;
        println!("Full masked membership verified against the public IMT root");
        return Ok(());
    }
    let bytes = read_bounded(&proof_file, 64 << 20)?;
    let child = MaskedMembershipProof::from_bytes(&bytes)?;
    let products = args.products || full;
    let whir = args.whir || products;
    let blend = args.blend || whir;
    let cp = if blend {
        trusted.stacked_blend_checkpoint(&public, &child)?
    } else {
        trusted.stacked_oracle_checkpoint(&public, &child)?
    };
    let opening = whir
        .then(|| trusted.stacked_whir_advice(&child, cp.blend.as_ref().unwrap()))
        .transpose()?;
    let plan = whir.then(|| trusted.stacked_whir_plan()).transpose()?;
    let vectors = products
        .then(|| trusted.constraint_messages(&public, &child))
        .transpose()?;
    if let Command::Prepare { out, .. } = &args.command {
        let (_, schema, vec_schemas) =
            guest::source(&trusted, &params, true, plan.as_ref(), true, true, true);
        let hints = full_advice(
            &public,
            &cp,
            &trusted,
            &opening.as_ref().unwrap().0,
            &schema,
            vectors.as_ref().unwrap(),
            &vec_schemas,
        )?;
        let mut buf = b"IMTZKH01".to_vec();
        buf.extend(public.root);
        let push = |buf: &mut Vec<u8>, n: usize| -> Result<()> {
            buf.extend(u32::try_from(n)?.to_le_bytes());
            Ok(())
        };
        push(&mut buf, hints.len())?;
        for (name, entries) in hints {
            push(&mut buf, name.len())?;
            buf.extend(name.as_bytes());
            push(&mut buf, entries.len())?;
            for entry in entries {
                push(&mut buf, entry.len())?;
                for w in entry {
                    buf.extend(w.c0.to_le_bytes());
                    buf.extend(w.c1.to_le_bytes());
                }
            }
        }
        save_new(out, &buf)?;
        return Ok(());
    }
    let (program, schema, vector_schemas) = guest::compile(
        &trusted,
        &params,
        blend,
        plan.as_ref(),
        products,
        args.membership,
    );
    let pi = if args.membership {
        public.root
    } else {
        digest_with_seal(
            &public.root,
            &cp,
            trusted.stacked_row_domains().0,
            opening.as_ref().map(|(_, seal)| seal),
            vectors.as_ref().map(|v| &v.product_state),
        )
    };
    let stage = if args.membership {
        "Full masked membership"
    } else if products {
        "Stacked, product dot and Hadamard openings"
    } else if whir {
        "Merkle, blend and complete WHIR opening"
    } else if blend {
        "Merkle and blend sumcheck"
    } else {
        "Merkle"
    };
    match args.command {
        Command::Prepare { .. } | Command::BuildGuest { .. } => unreachable!(),
        Command::Prove { out, threads, .. } => {
            ExperimentalProver::set_num_threads(threads.get());
            let witness = if full {
                full_advice(
                    &public,
                    &cp,
                    &trusted,
                    &opening.as_ref().unwrap().0,
                    &schema,
                    vectors.as_ref().unwrap(),
                    &vector_schemas,
                )?
            } else {
                let mut witness = advice(&public, &cp, &trusted);
                if let Some((raw, _)) = &opening {
                    witness.extend(whir::advice(&schema, raw)?);
                }
                if let Some(c) = &vectors {
                    witness.extend(vector::advice(c, &vector_schemas)?);
                }
                witness
            };
            let timer = Instant::now();
            let (proof, stats) = ExperimentalProver::prove(
                &program,
                &witness,
                verifier::Digest(pi).halves().into(),
                2,
            )
            .map_err(anyhow::Error::msg)?;
            let elapsed = timer.elapsed();
            let wire = proof.to_bytes();
            let decoded = Proof::from_bytes(&wire).context("malformed checkpoint proof")?;
            verifier::verify_execution(program.bytecode(), &pi, &decoded)?;
            save_new(&out, &wire)?;
            println!(
                "{stage} checkpoint verified, {} AIR challenges, {} affine coefficients, {} authenticated Merkle rows, {} steps, {} Keccak permutations, {} bytes, {:.3} s proving",
                cp.challenges.len() / 24,
                cp.claim_coefficients.len() / 24,
                cp.query_indices.len(),
                stats.cycles,
                stats.table_heights[5],
                wire.len(),
                elapsed.as_secs_f64()
            );
        }
        Command::Verify { proof, .. } => {
            let proof = Proof::from_bytes(&read_bounded(&proof, 64 << 20)?)
                .context("malformed checkpoint proof")?;
            verifier::verify_execution(program.bytecode(), &pi, &proof)?;
            println!("{stage} checkpoint verified against the public root and opened rows");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
