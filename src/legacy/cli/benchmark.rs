use super::demo::{run_batch, setup_process};
use super::io::{INPUT_JSON_LIMIT, create_output_dir, read_json, write_json, write_new};
use super::types::{RunMetrics, SetupMetrics, TreeOptions};
use anyhow::{Result, ensure};
use clap::Args;
use recursive_imt_prover::legacy::Profile;
use recursive_imt_prover::legacy::scenario::ScenarioConfig;
use serde::Serialize;
use std::{
    env::consts::{ARCH, OS},
    path::PathBuf,
    process::Command,
    thread::available_parallelism,
};

#[derive(Args)]
pub(crate) struct BenchmarkOptions {
    #[arg(long)]
    out: PathBuf,
    #[arg(
        long,
        alias = "count",
        value_delimiter = ',',
        default_value = "1,2,4,8"
    )]
    counts: Vec<usize>,
    #[arg(long, default_value_t = 3)]
    samples: usize,
    #[arg(long, value_enum, default_value = "reference")]
    profile: Profile,
    #[command(flatten)]
    tree: TreeOptions,
}

#[derive(Serialize)]
struct Distribution {
    min: f64,
    median: f64,
    max: f64,
    mean: f64,
}

#[derive(Serialize)]
struct Summary {
    client_trace_ms: Distribution,
    client_prove_ms: Distribution,
    client_verify_ms: Distribution,
    client_wall_ms: Distribution,
    aggregation_prepare_ms: Distribution,
    aggregation_prove_ms: Distribution,
    aggregation_wall_ms: Distribution,
    aggregate_verify_ms: Distribution,
    verification_wall_ms: Distribution,
    end_to_end_ms: Distribution,
    child_proof_bytes: Distribution,
    outer_proof_bytes: Distribution,
}

#[derive(Serialize)]
struct Series {
    count: usize,
    setup_wall_ms: f64,
    setup: SetupMetrics,
    summary: Summary,
    samples: Vec<RunMetrics>,
}

#[derive(Serialize)]
struct Environment {
    os: &'static str,
    arch: &'static str,
    cpu: Option<String>,
    memory_bytes: Option<u64>,
    logical_cpus: usize,
    rayon_threads: usize,
    rustc: Option<String>,
    debug_assertions: bool,
    source_sha3_256: String,
}

#[derive(Serialize)]
struct Report {
    environment: Environment,
    profile: Profile,
    tree: ScenarioConfig,
    samples_per_count: usize,
    methodology: &'static str,
    series: Vec<Series>,
}

impl Distribution {
    fn from_values(values: impl Iterator<Item = f64>) -> Self {
        let mut values: Vec<_> = values.collect();
        values.sort_by(f64::total_cmp);
        let count = values.len();
        let median = if count.is_multiple_of(2) {
            (values[count / 2 - 1] + values[count / 2]) / 2.0
        } else {
            values[count / 2]
        };
        Self {
            min: values[0],
            median,
            max: values[count - 1],
            mean: values.iter().sum::<f64>() / count as f64,
        }
    }
}

impl Summary {
    fn from_samples(samples: &[RunMetrics]) -> Self {
        Self {
            client_trace_ms: Distribution::from_values(samples.iter().map(|run| {
                run.clients
                    .iter()
                    .map(|client| client.timings.trace_ms)
                    .sum()
            })),
            client_prove_ms: Distribution::from_values(samples.iter().map(|run| {
                run.clients
                    .iter()
                    .map(|client| client.timings.prove_ms)
                    .sum()
            })),
            client_verify_ms: Distribution::from_values(samples.iter().map(|run| {
                run.clients
                    .iter()
                    .map(|client| client.timings.verify_ms)
                    .sum()
            })),
            client_wall_ms: Distribution::from_values(samples.iter().map(|run| run.client_wall_ms)),
            aggregation_prepare_ms: Distribution::from_values(
                samples
                    .iter()
                    .map(|run| run.aggregation.aggregation.prepare_ms),
            ),
            aggregation_prove_ms: Distribution::from_values(
                samples
                    .iter()
                    .map(|run| run.aggregation.aggregation.prove_ms),
            ),
            aggregation_wall_ms: Distribution::from_values(
                samples.iter().map(|run| run.aggregate_wall_ms),
            ),
            aggregate_verify_ms: Distribution::from_values(
                samples.iter().map(|run| run.aggregation.verify_ms),
            ),
            verification_wall_ms: Distribution::from_values(
                samples.iter().map(|run| run.verify_wall_ms),
            ),
            end_to_end_ms: Distribution::from_values(samples.iter().map(|run| run.total_ms)),
            child_proof_bytes: Distribution::from_values(samples.iter().map(|run| {
                run.clients
                    .iter()
                    .map(|client| client.proof_bytes as f64)
                    .sum()
            })),
            outer_proof_bytes: Distribution::from_values(
                samples
                    .iter()
                    .map(|run| run.aggregation.outer_proof_bytes as f64),
            ),
        }
    }
}

pub(crate) fn benchmark(options: BenchmarkOptions) -> Result<()> {
    ensure!(options.samples > 0, "samples must be positive");
    ensure!(
        !options.counts.is_empty(),
        "provide at least one batch size"
    );
    for (index, &count) in options.counts.iter().enumerate() {
        options.tree.config().validate(count)?;
        ensure!(
            !options.counts[..index].contains(&count),
            "duplicate batch size {count}"
        );
    }
    create_output_dir(&options.out)?;
    let mut report = Report {
        environment: environment(),
        profile: options.profile,
        tree: options.tree.config(),
        samples_per_count: options.samples,
        methodology: "Release build recommended. Setup runs once per batch size and is excluded from sample totals. Each sample uses fresh random notes and fresh sequential client, aggregator and verifier processes. Aggregation preparation is repeated. Child trace generation, proving and native verification are timed separately. Recursive proving includes trace generation. Aggregate verify_ms includes decoding but excludes file I/O and process startup. Wall times include process startup and artifact I/O. No warmup samples are discarded. Security analysis is per child, not composed recursion security.",
        series: Vec::new(),
    };
    let mut csv = String::from(
        "count,samples,setup_ms,client_prove_ms,client_verify_ms,aggregation_prepare_ms,aggregation_prove_ms,aggregation_wall_ms,aggregate_verify_ms,verification_wall_ms,end_to_end_ms,child_proof_bytes,outer_proof_bytes\n",
    );
    let mut children_csv =
        String::from("count,sample,child,trace_ms,prove_ms,verify_ms,proof_bytes\n");
    for count in options.counts {
        let directory = options.out.join(format!("n-{count}"));
        create_output_dir(&directory)?;
        let trusted = directory.join("trusted");
        eprintln!("Benchmark N={count}: provisioning trusted verifiers...");
        let setup_wall_ms = setup_process(&trusted, count, report.tree.depth, options.profile)?;
        let setup: SetupMetrics = read_json(&trusted.join("metrics.json"), INPUT_JSON_LIMIT)?;
        println!(
            "N={count}: proven Johnson child model {:.1} bits; binding term {}",
            setup.child_security.round_by_round_bits, setup.child_security.binding_term
        );
        println!(
            "N={count}: WHIR aggregation, KoalaBear, proven Johnson, {}-bit per-term target",
            setup.outer.security_target_per_term
        );
        let mut samples = Vec::with_capacity(options.samples);
        for index in 0..options.samples {
            let out = directory.join(format!("sample-{}", index + 1));
            create_output_dir(&out)?;
            eprintln!(
                "Benchmark N={count}: sample {}/{}",
                index + 1,
                options.samples
            );
            let sample = run_batch(&out, &trusted, count, report.tree, &[])?;
            for (child, metrics) in sample.clients.iter().enumerate() {
                children_csv.push_str(&format!(
                    "{count},{},{},{:.3},{:.3},{:.3},{}\n",
                    index + 1,
                    child + 1,
                    metrics.timings.trace_ms,
                    metrics.timings.prove_ms,
                    metrics.timings.verify_ms,
                    metrics.proof_bytes
                ));
            }
            samples.push(sample);
        }
        let summary = Summary::from_samples(&samples);
        println!(
            "N={count}: median batch {:.1} ms, aggregation wall {:.1} ms, aggregate verify {:.1} ms, fresh verifier wall {:.1} ms, outer proof {:.0} bytes",
            summary.end_to_end_ms.median,
            summary.aggregation_wall_ms.median,
            summary.aggregate_verify_ms.median,
            summary.verification_wall_ms.median,
            summary.outer_proof_bytes.median
        );
        csv.push_str(&format!(
            "{count},{},{setup_wall_ms:.3},{:.3},{:.3},{:.3},{:.3},{:.3},{:.3},{:.3},{:.3},{:.0},{:.0}\n",
            options.samples,
            summary.client_prove_ms.median,
            summary.client_verify_ms.median,
            summary.aggregation_prepare_ms.median,
            summary.aggregation_prove_ms.median,
            summary.aggregation_wall_ms.median,
            summary.aggregate_verify_ms.median,
            summary.verification_wall_ms.median,
            summary.end_to_end_ms.median,
            summary.child_proof_bytes.median,
            summary.outer_proof_bytes.median
        ));
        let series = Series {
            count,
            setup_wall_ms,
            setup,
            summary,
            samples,
        };
        write_json(&directory.join("summary.json"), &series)?;
        report.series.push(series);
    }
    write_json(&options.out.join("report.json"), &report)?;
    write_new(&options.out.join("summary.csv"), csv.as_bytes())?;
    write_new(&options.out.join("children.csv"), children_csv.as_bytes())?;
    Ok(())
}

fn environment() -> Environment {
    Environment {
        os: OS,
        arch: ARCH,
        cpu: command_text("sysctl", &["-n", "machdep.cpu.brand_string"]),
        memory_bytes: command_text("sysctl", &["-n", "hw.memsize"])
            .and_then(|value| value.parse().ok()),
        logical_cpus: available_parallelism().map(usize::from).unwrap_or(1),
        rayon_threads: rayon::current_num_threads(),
        rustc: command_text("rustc", &["--version"]),
        debug_assertions: cfg!(debug_assertions),
        source_sha3_256: env!("IMT_SOURCE_SHA3_256").into(),
    }
}

fn command_text(program: &str, arguments: &[&str]) -> Option<String> {
    let output = Command::new(program).args(arguments).output().ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
}
