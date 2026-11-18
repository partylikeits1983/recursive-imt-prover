//! Experimental masked children -> one proof of their complete verifiers.
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::Instant,
};

use anyhow::{Result, ensure};
use clap::{Parser, ValueEnum};
use imt_flock_backend::{HashBackend, MAX_VERIFIER_BYTES, verifier_key_digest};
use mimalloc::MiMalloc;
use rayon::ThreadPoolBuilder;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use recursive_imt_prover::{
    benchmark::{environment, ms, peak_rss, statistics},
    binary::{
        IMT_DEPTH, MAX_CHILDREN,
        cli::fixtures,
        engine::Settings,
        relation::AggregatePublic,
        veil::{
            aggregate::{
                MaskedAggregateVerifier, MaskedChildInput, PreparedMaskedAggregate, StatementFormat,
            },
            child::{MaskedMembershipProof, PreparedMembership},
            components::{
                ComponentMetrics, PROTOCOL as COMPONENT_PROTOCOL, PreparedComponentBatch,
            },
            parameters::Parameters,
        },
    },
    files::{read_bounded, read_json, write_json},
};

#[global_allocator]
static ALLOCATOR: MiMalloc = MiMalloc;

#[derive(Clone, Copy, Default, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "kebab-case")]
enum KeccakBackend {
    #[default]
    Flock,
    Checkpoint,
}

#[derive(Parser)]
#[command(
    about = "Experimental statistically masked binary Keccak children and non-ZK aggregation; privacy/security review outstanding"
)]
struct Args {
    #[arg(long, default_value_t = IMT_DEPTH)]
    depth: usize,
    #[arg(long, default_value_t = 2)]
    batch_size: usize,
    #[arg(long, default_value_t = 1)]
    samples: usize,
    #[arg(long, default_value_t = 4)]
    threads: usize,
    #[arg(long, default_value = "run/masked-demo")]
    out: PathBuf,
    #[arg(long)]
    verify: bool,
    /// Run the three-proof correctness baseline; this is not a compressed aggregate.
    #[arg(long)]
    components: bool,
    /// Produce the first tree aggregate with a fixed-size statement; exactly two children.
    #[arg(long, conflicts_with = "components")]
    tree_pair: bool,
    /// Aggregate Keccak prover; checkpoint is an experimental memory/time comparison.
    #[arg(long, value_enum, default_value_t = KeccakBackend::Flock)]
    keccak_backend: KeccakBackend,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Trusted {
    protocol: String,
    settings: Settings,
    child_parameters: Parameters,
    child_identity: [u8; 32],
    components: bool,
    identities: Vec<String>,
    #[serde(default)]
    verifier_digest: Option<[u8; 32]>,
    #[serde(default)]
    keccak_backend: KeccakBackend,
    #[serde(default)]
    statement_format: StatementFormat,
}

#[derive(Serialize)]
struct ChildMetrics {
    witness_ms: f64,
    prove_ms: f64,
    decode_verify_ms: f64,
    proof_bytes: usize,
}

#[derive(Serialize)]
struct Sample {
    phase: &'static str,
    children: Vec<ChildMetrics>,
    aggregation: Value,
    aggregation_wall_ms: f64,
    aggregate_decode_verify_ms: f64,
    critical_path_ms: f64,
    peak_rss_bytes: u64,
}

enum PreparedBatch {
    Recursive(Box<PreparedMaskedAggregate>),
    Components(Box<PreparedComponentBatch>),
}

impl From<KeccakBackend> for HashBackend {
    fn from(backend: KeccakBackend) -> Self {
        match backend {
            KeccakBackend::Flock => Self::Flock,
            KeccakBackend::Checkpoint => Self::Checkpoint,
        }
    }
}

impl PreparedBatch {
    fn new(
        settings: &Settings,
        parameters: Parameters,
        components: bool,
        backend: KeccakBackend,
        format: StatementFormat,
    ) -> Result<Self> {
        if components {
            ensure!(
                format == StatementFormat::Ordered,
                "components do not produce tree pairs"
            );
            ensure!(
                matches!(backend, KeccakBackend::Flock),
                "components use the Flock backend"
            );
            Ok(Self::Components(Box::new(PreparedComponentBatch::new(
                settings, parameters,
            )?)))
        } else {
            Ok(Self::Recursive(Box::new(
                PreparedMaskedAggregate::with_format(settings, parameters, backend.into(), format)?,
            )))
        }
    }
    fn identities(&self) -> Vec<String> {
        match self {
            Self::Recursive(a) => vec![a.identity()],
            Self::Components(a) => a.identities(),
        }
    }
    fn geometry(&self) -> Value {
        match self {
            Self::Recursive(a) => {
                json!({"aggregate":a.geometry()})
            }
            Self::Components(a) => json!({"parts":a.geometry}),
        }
    }
    fn prove(
        &self,
        children: &[MaskedChildInput],
    ) -> Result<(AggregatePublic, Vec<u8>, Value, f64)> {
        match self {
            Self::Recursive(a) => {
                let (public, proof, metrics) = a.prove(children)?;
                let wall = metrics.aggregation_wall_ms;
                Ok((public, proof, serde_json::to_value(metrics)?, wall))
            }
            Self::Components(a) => {
                let (public, proof, metrics): (_, _, ComponentMetrics) = a.prove(children)?;
                let wall = metrics.wall_ms;
                Ok((public, proof, serde_json::to_value(metrics)?, wall))
            }
        }
    }
    fn verify(&self, proof: &[u8], public: &AggregatePublic) -> Result<()> {
        match self {
            Self::Recursive(a) => a.verify(proof, public),
            Self::Components(a) => a.verify(proof, public),
        }
    }
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
        return verify_files(&args.out);
    }
    ensure!(args.depth == IMT_DEPTH, "child IMT depth must be 32");
    ensure!(
        args.batch_size.is_power_of_two() && args.batch_size <= MAX_CHILDREN,
        "batch size must be a power of two through 64"
    );
    ensure!(
        (1..=20).contains(&args.samples),
        "samples must be in 1..=20"
    );
    ensure!(!args.out.exists(), "output directory must be fresh");
    let settings = Settings {
        depth: args.depth,
        batch_size: args.batch_size,
        log_inv_rate: imt_flock_backend::WHIR_LOG_INV_RATE,
        fold: imt_flock_backend::WHIR_FOLD,
        max_codeword_cells: 1 << 29,
        ..Settings::default()
    };
    let statement_format = if args.tree_pair {
        ensure!(
            args.batch_size == 2,
            "first aggregation requires two children"
        );
        StatementFormat::TreePair
    } else {
        StatementFormat::Ordered
    };
    let protocol = if args.components {
        COMPONENT_PROTOCOL
    } else {
        statement_format.protocol(args.keccak_backend.into())
    };
    let parameters = Parameters::default();
    let child = PreparedMembership::new(args.depth, parameters.clone())?;
    fs::create_dir_all(&args.out)?;
    let mut report = json!({"protocol":protocol, "statement_format":statement_format, "depth":args.depth, "batch_size":args.batch_size,
        "field":"Poly64/Poly192", "hash":"Keccak-256", "bound":"Johnson", "child_parameters":parameters,
        "settings":settings, "outer_parameters":if args.components {json!(null)} else {json!({"pcs_bits":152,"pow_bits":16,"log_inv_rate":imt_flock_backend::WHIR_LOG_INV_RATE,"fold":imt_flock_backend::WHIR_FOLD,"max_initial_codeword_cells":1usize<<30})},  "environment":environment(),
        "acceptance_pass":false, "experimental_statistical_zk_candidate":true, "full_zk_established":false, "end_to_end_security_bits":null, "aggregate":!args.components, "succinct":!args.components, "complete":false, "component_proof_count":if args.components {3*args.batch_size} else {1}, "samples":[]});
    write_json(&args.out.join("report.json"), &report)?;
    eprintln!(
        "Preparing {} for N={}...",
        if args.components {
            "linked component baseline (not a succinct aggregate)"
        } else {
            match args.keccak_backend {
                KeccakBackend::Flock => "Flock aggregate of complete masked verifiers",
                KeccakBackend::Checkpoint => {
                    "Binary aggregate of complete masked verifiers with linked Keccak GKR"
                }
            }
        },
        args.batch_size
    );
    let start = Instant::now();
    let aggregate = PreparedBatch::new(
        &settings,
        parameters.clone(),
        args.components,
        args.keccak_backend,
        statement_format,
    )?;
    report["setup_ms"] = json!(ms(start));
    report["geometry"] = aggregate.geometry();
    write_json(&args.out.join("report.json"), &report)?;
    let export_start = Instant::now();
    let verifier_digest = if let PreparedBatch::Recursive(prepared) = &aggregate {
        let key = prepared.export_verifier_key()?;
        let digest = verifier_key_digest(&key);
        fs::write(args.out.join("verifier.key"), &key)?;
        report["verifier_key_bytes"] = json!(key.len());
        Some(digest)
    } else {
        None
    };
    report["verifier_key_export_ms"] = json!(ms(export_start));
    let trusted = Trusted {
        protocol: protocol.into(),
        settings,
        child_parameters: parameters,
        child_identity: child.identity(),
        components: args.components,
        identities: aggregate.identities(),
        verifier_digest,
        keccak_backend: args.keccak_backend,
        statement_format,
    };
    write_json(&args.out.join("trusted.json"), &trusted)?;
    let cached = if let Some(digest) = trusted.verifier_digest {
        let key = read_bounded(&args.out.join("verifier.key"), MAX_VERIFIER_BYTES)?;
        Some(MaskedAggregateVerifier::with_format(
            &trusted.settings,
            &trusted.child_parameters,
            &key,
            &digest,
            &trusted.identities[0],
            trusted.keccak_backend.into(),
            trusted.statement_format,
        )?)
    } else {
        None
    };
    let mut samples = Vec::new();
    for sample in 0..args.samples {
        let start = Instant::now();
        let (inputs, children) = make_children(&child, args.depth, args.batch_size)?;
        // `make_children` has dropped every original witness. This API receives
        // only serialized/decoded child proofs and their public statements.
        let (public, proof, aggregation, aggregation_wall_ms) = aggregate.prove(&inputs)?;
        let check = Instant::now();
        aggregate.verify(&proof, &public)?;
        let aggregate_decode_verify_ms = ms(check);
        let critical_path_ms = ms(start);
        negative_checks(|p, x| aggregate.verify(p, x), &proof, &public)?;
        if let Some(verifier) = &cached {
            verifier.verify(&proof, &public)?;
            negative_checks(|p, x| verifier.verify(p, x), &proof, &public)?;
        }
        eprintln!(
            "Output: total {:.3} ms, final verify {:.3} ms, {} bytes",
            aggregation_wall_ms,
            aggregate_decode_verify_ms,
            proof.len()
        );
        fs::write(args.out.join("aggregate.proof"), &proof)?;
        write_json(&args.out.join("statement.json"), &public)?;
        samples.push(Sample {
            phase: if sample == 0 {
                "cold-first-proof"
            } else {
                "warm-process"
            },
            children,
            aggregation,
            aggregation_wall_ms,
            aggregate_decode_verify_ms,
            critical_path_ms,
            peak_rss_bytes: peak_rss(),
        });
        report["samples"] = json!(samples);
        write_json(&args.out.join("report.json"), &report)?;
    }
    // Release setup/trace allocations before the independent verifier starts.
    drop(cached);
    drop(aggregate);
    drop(child);
    let start = Instant::now();
    let output = Command::new(std::env::current_exe()?)
        .args(["--verify", "--threads", &args.threads.to_string(), "--out"])
        .arg(&args.out)
        .output()?;
    ensure!(
        output.status.success(),
        "fresh aggregate verifier failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let mut fresh: Value = serde_json::from_slice(&output.stdout)?;
    fresh["process_wall_ms"] = json!(ms(start));
    report["fresh_verifier"] = fresh;
    report["complete"] = json!(true);
    let warm = &samples[usize::from(samples.len() > 1)..];
    report["summary"] = json!({"aggregation_wall_ms":statistics(warm.iter().map(|s| s.aggregation_wall_ms).collect()), "aggregate_verify_ms":statistics(warm.iter().map(|s| s.aggregate_decode_verify_ms).collect()), "critical_path_ms":statistics(warm.iter().map(|s| s.critical_path_ms).collect())});
    write_json(&args.out.join("report.json"), &report)?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

fn make_children(
    child: &PreparedMembership,
    depth: usize,
    count: usize,
) -> Result<(Vec<MaskedChildInput>, Vec<ChildMetrics>)> {
    let mut inputs = Vec::with_capacity(count);
    let mut metrics = Vec::with_capacity(count);
    for (i, (public, witness)) in fixtures(depth, count)?.into_iter().enumerate() {
        let start = Instant::now();
        let trace = child.witness(&public, &witness)?;
        let witness_ms = ms(start);
        let start = Instant::now();
        let proof = child.prove_trace(&public, trace)?;
        let prove_ms = ms(start);
        let encoded = proof.to_bytes()?;
        let start = Instant::now();
        let proof = MaskedMembershipProof::from_bytes(&encoded)?;
        child.verify(&public, &proof)?;
        let decode_verify_ms = ms(start);
        eprintln!(
            "Child {}: prove {:.3} ms, verify {:.3} ms, {} bytes",
            i + 1,
            prove_ms,
            decode_verify_ms,
            encoded.len()
        );
        metrics.push(ChildMetrics {
            witness_ms,
            prove_ms,
            decode_verify_ms,
            proof_bytes: encoded.len(),
        });
        inputs.push(MaskedChildInput { public, proof });
    }
    Ok((inputs, metrics))
}

fn verify_files(directory: &Path) -> Result<()> {
    let trusted: Trusted = read_json(&directory.join("trusted.json"))?;
    trusted.settings.validate()?;
    let expected_protocol = if trusted.components {
        COMPONENT_PROTOCOL
    } else {
        trusted
            .statement_format
            .protocol(trusted.keccak_backend.into())
    };
    ensure!(
        trusted.protocol == expected_protocol,
        "unsupported aggregate protocol"
    );
    let public: AggregatePublic = read_json(&directory.join("statement.json"))?;
    ensure!(
        public.children.len() == trusted.settings.batch_size,
        "incorrect public count"
    );
    let proof = read_bounded(
        &directory.join("aggregate.proof"),
        if trusted.components {
            (24 << 20) * trusted.settings.batch_size
        } else {
            16 << 20
        },
    )?;
    let start = Instant::now();
    let child = PreparedMembership::new(trusted.settings.depth, trusted.child_parameters.clone())?;
    ensure!(
        child.identity() == trusted.child_identity,
        "child verifier identity mismatch"
    );
    if let Some(digest) = trusted.verifier_digest {
        ensure!(
            !trusted.components && trusted.identities.len() == 1,
            "invalid cached verifier authority"
        );
        let key = read_bounded(&directory.join("verifier.key"), MAX_VERIFIER_BYTES)?;
        let verifier = MaskedAggregateVerifier::with_format(
            &trusted.settings,
            &trusted.child_parameters,
            &key,
            &digest,
            &trusted.identities[0],
            trusted.keccak_backend.into(),
            trusted.statement_format,
        )?;
        let setup_ms = ms(start);
        let check = Instant::now();
        verifier.verify(&proof, &public)?;
        println!(
            "{}",
            json!({"verified":true, "cached_verifier":true, "setup_ms":setup_ms, "decode_verify_ms":ms(check), "peak_rss_bytes":peak_rss()})
        );
        return Ok(());
    }
    let aggregate = PreparedBatch::new(
        &trusted.settings,
        trusted.child_parameters,
        trusted.components,
        trusted.keccak_backend,
        trusted.statement_format,
    )?;
    ensure!(
        aggregate.identities() == trusted.identities,
        "aggregate verifier identity mismatch"
    );
    let setup_ms = ms(start);
    let start = Instant::now();
    aggregate.verify(&proof, &public)?;
    println!(
        "{}",
        json!({"verified":true,"setup_ms":setup_ms,"decode_verify_ms":ms(start),"peak_rss_bytes":peak_rss()})
    );
    Ok(())
}

fn negative_checks(
    verify: impl Fn(&[u8], &AggregatePublic) -> Result<()>,
    proof: &[u8],
    public: &AggregatePublic,
) -> Result<()> {
    for kind in 0..5 {
        let mut changed = public.clone();
        match kind {
            0 => changed.children[0].nullifier_hash[0] ^= 1,
            1 => changed.children[0].root[0] ^= 1,
            2 => {
                changed.children.pop();
            }
            3 => changed.children.push(changed.children[0].clone()),
            _ => {
                if changed.children.len() == 1 {
                    continue;
                }
                changed.children.swap(0, 1);
            }
        }
        ensure!(
            verify(proof, &changed).is_err(),
            "altered aggregate statement accepted: {kind}"
        );
    }
    let mut changed = proof.to_vec();
    let midpoint = changed.len() / 2;
    changed[midpoint] ^= 0x80;
    ensure!(
        verify(&changed, public).is_err(),
        "corrupted aggregate accepted"
    );
    Ok(())
}
