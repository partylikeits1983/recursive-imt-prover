use std::{fs, path::PathBuf, process::Command, time::Instant};

use anyhow::{Result, ensure};
use clap::Parser;
use mimalloc::MiMalloc;
use rayon::ThreadPoolBuilder;
use serde_json::{Value, json};

use recursive_imt_prover::{
    benchmark::{environment, ms, peak_rss, statistics},
    binary::aggregation_tree::{
        files::{read_proof, read_verifier, write_proof},
        merge::{PROTOCOL, PreparedMerge, TreeProof},
    },
    files::write_json,
};

#[global_allocator]
static ALLOCATOR: MiMalloc = MiMalloc;

#[derive(Parser)]
#[command(
    about = "Merge two checkpoint tree aggregates under a fixed source authority; cyclic key reuse remains experimental work"
)]
struct Args {
    #[arg(long, required_unless_present = "verify", conflicts_with = "verify")]
    left: Option<PathBuf>,
    #[arg(long, required_unless_present = "verify", conflicts_with = "verify")]
    right: Option<PathBuf>,
    #[arg(long)]
    out: PathBuf,
    #[arg(long)]
    verify: bool,
    #[arg(long, default_value_t = 4)]
    threads: usize,
    #[arg(long, default_value_t = 1)]
    samples: usize,
}

fn main() -> Result<()> {
    let args = Args::parse();
    ensure!(
        (1..=64).contains(&args.threads),
        "threads must be in 1..=64"
    );
    ThreadPoolBuilder::new()
        .num_threads(args.threads)
        .build_global()?;
    if args.verify {
        let proof = read_proof(&args.out)?;
        let start = Instant::now();
        let (verifier, _) = read_verifier(&args.out)?;
        let setup_ms = ms(start);
        let start = Instant::now();
        verifier.verify(&proof.proof, &proof.public)?;
        println!(
            "{}",
            json!({"verified":true,"setup_ms":setup_ms,"verify_ms":ms(start),"peak_rss_bytes":peak_rss()})
        );
        return Ok(());
    }
    ensure!(
        (1..=20).contains(&args.samples),
        "samples must be in 1..=20"
    );
    ensure!(!args.out.exists(), "output directory must be fresh");
    let left = args.left.as_ref().unwrap();
    let right = args.right.as_ref().unwrap();
    let children = [read_proof(left)?, read_proof(right)?];
    let (authority, digest) = read_verifier(left)?;
    let (_, right_digest) = read_verifier(right)?;
    ensure!(
        digest == right_digest,
        "merge inputs require the same trusted source authority"
    );
    for child in &children {
        authority.verify(&child.proof, &child.public)?;
    }
    eprintln!(
        "Preparing merge of {} + {} authenticated child statements...",
        children[0].public.children.len(),
        children[1].public.children.len()
    );
    let start = Instant::now();
    let prepared = PreparedMerge::new(authority)?;
    let setup_ms = ms(start);
    eprintln!(
        "Merge: {} witnesses per verifier, {} initial codeword cells",
        prepared.geometry().template_witnesses,
        prepared.geometry().initial_codeword_cells
    );
    fs::create_dir_all(&args.out)?;
    let mut samples = Vec::new();
    let mut walls = Vec::new();
    for index in 0..args.samples {
        let (public, proof, metrics) = prepared.prove(&children)?;
        eprintln!(
            "Merge sample {}: {:.1} ms, {} bytes",
            index + 1,
            metrics.aggregation_wall_ms,
            proof.len()
        );
        walls.push(metrics.aggregation_wall_ms);
        samples.push(json!({"phase":if index == 0 {"cold-first-proof"} else {"warm"},"metrics":metrics,"peak_rss_bytes":peak_rss()}));
        write_proof(&args.out, &TreeProof { proof, public }, &prepared)?;
    }
    let start = Instant::now();
    let output = Command::new(std::env::current_exe()?)
        .arg("--verify")
        .arg("--out")
        .arg(&args.out)
        .arg("--threads")
        .arg(args.threads.to_string())
        .output()?;
    let fresh_ms = ms(start);
    ensure!(
        output.status.success(),
        "fresh verifier failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let fresh: Value = serde_json::from_slice(&output.stdout)?;
    let report = json!({
        "protocol":PROTOCOL,"environment":environment(),"source_authority_digest":digest,
        "children":children.iter().map(|c| c.public.children.len()).sum::<usize>(),
        "same_key_recursion":false,"acceptance_pass":false,"end_to_end_security_bits":null,
        "setup_ms":setup_ms,"geometry":prepared.geometry(),"samples":samples,
        "summary":{"all":statistics(walls.clone()),"warm":statistics(walls[1..].to_vec())},"fresh_verifier":fresh,"fresh_verifier_wall_ms":fresh_ms
    });
    write_json(&args.out.join("report.json"), &report)?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}
