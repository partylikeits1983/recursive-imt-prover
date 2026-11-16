//! Measurements of implemented components, never described as recursive throughput.
use anyhow::{Result, ensure};
use clap::Parser;
use recursive_imt_poc::{client, codec, fixtures, outer};
use serde::Serialize;
use std::{path::PathBuf, time::Instant};
#[derive(Parser)]
struct Args {
    #[arg(long, default_value_t = 8)]
    depth: u8,
    #[arg(long, default_value_t = 5)]
    samples: usize,
    #[arg(long, default_value = "artifacts/components-depth8.json")]
    out: PathBuf,
    /// Required while the recursive verifier is incomplete.
    #[arg(long)]
    diagnostic_components: bool,
}
#[derive(Serialize)]
struct Sample {
    sample: usize,
    client_witness_ms: [f64; 2],
    client_prove_ms: [f64; 2],
    client_verify_ms: [f64; 2],
    child_proof_bytes: [usize; 2],
    transition_trace_ms: f64,
    transition_prove_ms: f64,
    transition_verify_ms: f64,
    transition_proof_bytes: usize,
    sequential_component_ms: f64,
    idealized_client_parallel_component_ms: f64,
    process_high_water_bytes: u64,
}
fn ms(t: Instant) -> f64 {
    t.elapsed().as_secs_f64() * 1000.
}
fn high_water() -> u64 {
    // getrusage is read-only. Values are process-lifetime maxima, NOT phase peaks.
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::uninit();
    unsafe {
        if libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) != 0 {
            return 0;
        }
        let x = usage.assume_init().ru_maxrss as u64;
        if cfg!(target_os = "macos") {
            x
        } else {
            x * 1024
        }
    }
}
fn command(cmd: &str, args: &[&str]) -> String {
    std::process::Command::new(cmd)
        .args(args)
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default()
}
fn main() -> Result<()> {
    let a = Args::parse();
    ensure!(
        a.diagnostic_components,
        "recursive pipeline is incomplete; use --diagnostic-components only for partial-path measurements"
    );
    ensure!(a.samples >= 5, "use at least five measured samples");
    let f = fixtures::pair(a.depth, false)?;
    let t = Instant::now();
    let c = client::build(a.depth, &f.clients[0], &f.witnesses[0])?;
    let client_build_ms = ms(t);
    let dimensions = serde_json::to_value(&c.stats)?;
    let t = Instant::now();
    let (pk, vk) = client::setup(c.shape)?;
    let client_setup_ms = ms(t);
    let t = Instant::now();
    let outer = outer::build_transition(a.depth)?;
    let transition_build_ms = ms(t);
    let t = Instant::now();
    let prepared = outer::prepare(&outer)?;
    let transition_prepare_ms = ms(t);
    let verifier = prepared.verifier();
    let mut samples = Vec::new();
    for sample in 0..=a.samples {
        let f = fixtures::pair(a.depth, false)?;
        let mut witness_ms = [0.; 2];
        let mut prove_ms = [0.; 2];
        let mut verify_ms = [0.; 2];
        let mut sizes = [0; 2];
        for i in 0..2 {
            let t = Instant::now();
            let assignment = client::assignment(a.depth, &f.clients[i], &f.witnesses[i])?;
            witness_ms[i] = ms(t);
            let t = Instant::now();
            let proof = pk
                .prove(assignment, f.clients[i].fields())
                .map_err(|e| anyhow::anyhow!("proving: {e:?}"))?;
            prove_ms[i] = ms(t);
            let t = Instant::now();
            client::verify(&vk, &f.clients[i], &proof)?;
            verify_ms[i] = ms(t);
            sizes[i] = codec::encode(3, &proof)?.len();
        }
        let public: Vec<_> = f.batch.fields().into_iter().map(outer::convert).collect();
        let private = outer::private_inputs(&f.batch, &f.append)?;
        let t = Instant::now();
        let mut runner = outer.circuit.runner();
        runner.set_public_inputs(&public)?;
        runner.set_private_inputs(&private)?;
        let traces = runner.run()?;
        let trace_ms = ms(t);
        let t = Instant::now();
        let proof = prepared.prove(&traces)?;
        let outer_prove_ms = ms(t);
        let t = Instant::now();
        verifier.verify(&proof, &public)?;
        let outer_verify_ms = ms(t);
        let client_total = [witness_ms[0] + prove_ms[0], witness_ms[1] + prove_ms[1]];
        let rest = verify_ms.iter().sum::<f64>() + trace_ms + outer_prove_ms + outer_verify_ms;
        let item = Sample {
            sample,
            client_witness_ms: witness_ms,
            client_prove_ms: prove_ms,
            client_verify_ms: verify_ms,
            child_proof_bytes: sizes,
            transition_trace_ms: trace_ms,
            transition_prove_ms: outer_prove_ms,
            transition_verify_ms: outer_verify_ms,
            transition_proof_bytes: codec::encode(4, &proof)?.len(),
            sequential_component_ms: client_total.iter().sum::<f64>() + rest,
            idealized_client_parallel_component_ms: client_total[0].max(client_total[1]) + rest,
            process_high_water_bytes: high_water(),
        };
        eprintln!(
            "{} sample {sample}: {:.2} ms components",
            if sample == 0 { "warmup" } else { "measured" },
            item.sequential_component_ms
        );
        if sample > 0 {
            samples.push(item);
        }
    }
    let data = serde_json::json!({"status":"INCOMPLETE: component diagnostics, NOT recursive aggregation", "depth":a.depth,"samples":samples,"warmup_samples":1,
        "machine":{"os":command("uname",&["-a"]),"cpu":command("sysctl",&["-n","machdep.cpu.brand_string"]),"ram_bytes":command("sysctl",&["-n","hw.memsize"]),"logical_cpus":command("sysctl",&["-n","hw.ncpu"]),"rayon_threads":rayon::current_num_threads().to_string(),"rustc":command("rustc",&["-Vv"]),"rustflags_env":std::env::var("RUSTFLAGS").unwrap_or_default()},
        "source":{"spartan":"14d6da4211eda59e65cfd0af5e2dcd89d523edc3","client_plonky3":"458ef546a251ab4d9d73c453d24a414334786ca0","recursion":"3a69ba61f713c8400b14eb3d8f0e52caa13512c7","outer_plonky3":"fe5e46d755b8a7d9069778361e21b33e5978b377"},
        "profile":{"client":client::config(),"outer":"upstream config::koala_bear(), FRI benchmark_high_arity, no composed security claim", "release":"opt-level=3, lto=thin, codegen-units=16, no target-cpu override"},
        "cold":{"client_build_ms":client_build_ms,"client_setup_ms":client_setup_ms,"transition_build_ms":transition_build_ms,"transition_prepare_ms":transition_prepare_ms},
        "costs":{"client_dimensions":dimensions,"transition_operations":outer.circuit.ops.len(),"transition_witnesses":outer.circuit.witness_count,"transition_app_permutations":4*a.depth as usize,"recursive_spartan_whir_cost":null},
        "statement":{"field_elements":f.batch.fields().len(),"canonical_field_bytes":4*f.batch.fields().len(),"envelope_bytes":codec::encode(5,&f.batch)?.len()},
        "limitations":["No recursive client verifier: sizes are not comparable as aggregation compression","Parallel critical path is an idealized sum, NOT measured concurrent execution","Peak RSS is cumulative process high-water; per-phase peak unavailable","Fixture generation, serialization, disk/process startup excluded from warm component sums","No aggregate-only latency exists"]});
    if let Some(parent) = a.out.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&a.out, serde_json::to_vec_pretty(&data)?)?;
    let mut csv = String::from(
        "sample,client0_witness_ms,client1_witness_ms,client0_prove_ms,client1_prove_ms,client0_verify_ms,client1_verify_ms,child0_bytes,child1_bytes,transition_trace_ms,transition_prove_ms,transition_verify_ms,transition_bytes,sequential_component_ms,idealized_parallel_component_ms,process_high_water_bytes\n",
    );
    for x in &samples {
        csv += &format!(
            "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}\n",
            x.sample,
            x.client_witness_ms[0],
            x.client_witness_ms[1],
            x.client_prove_ms[0],
            x.client_prove_ms[1],
            x.client_verify_ms[0],
            x.client_verify_ms[1],
            x.child_proof_bytes[0],
            x.child_proof_bytes[1],
            x.transition_trace_ms,
            x.transition_prove_ms,
            x.transition_verify_ms,
            x.transition_proof_bytes,
            x.sequential_component_ms,
            x.idealized_client_parallel_component_ms,
            x.process_high_water_bytes
        );
    }
    std::fs::write(a.out.with_extension("csv"), csv)?;
    println!("Wrote component diagnostics to {}", a.out.display());
    Ok(())
}
