use super::io::{
    INPUT_JSON_LIMIT, SMALL_JSON_LIMIT, create_output_dir, read_bounded, read_json, write_json,
    write_new,
};
use super::types::{BatchMetrics, ClientMetrics, RunMetrics};
use anyhow::{Context, Result, ensure};
use recursive_imt_prover::legacy::scenario::{ScenarioConfig, TreeHistory, populate};
use recursive_imt_prover::legacy::{Note, Profile};
use std::{env::current_exe, fs, path::Path, process::Command, time::Instant};

pub(crate) fn demo(
    out: &Path,
    count: usize,
    profile: Profile,
    tree: ScenarioConfig,
    amounts: &[u64],
) -> Result<()> {
    tree.validate(count)?;
    check_amounts(count, amounts)?;
    create_output_dir(out)?;
    let trusted = out.join("trusted");
    let setup_ms = setup_process(&trusted, count, tree.depth, profile)?;
    let metrics = run_batch(out, &trusted, count, tree, amounts)?;
    println!(
        "VERIFIED one outer proof for {count} ordered IMT roots and amounts. Setup: {setup_ms:.1} ms; batch: {:.1} ms.",
        metrics.total_ms
    );
    Ok(())
}

pub(crate) fn fixtures(
    out: &Path,
    count: usize,
    tree: ScenarioConfig,
    amounts: &[u64],
) -> Result<TreeHistory> {
    tree.validate(count)?;
    check_amounts(count, amounts)?;
    let notes = (0..count)
        .map(|index| {
            Note::random(
                amounts
                    .get(index)
                    .copied()
                    .unwrap_or((index as u64 + 1) * 100),
            )
        })
        .collect();
    let scenario = populate(notes, tree)?;
    create_output_dir(out)?;
    for (index, input) in scenario.inputs.iter().enumerate() {
        write_json(&out.join(format!("client-{index}.json")), input)?;
    }
    write_json(
        &out.join("allowed-roots.json"),
        &scenario
            .inputs
            .iter()
            .map(|input| input.root)
            .collect::<Vec<_>>(),
    )?;
    write_json(&out.join("tree-history.json"), &scenario.history)?;
    Ok(scenario.history)
}

pub(super) fn setup_process(out: &Path, count: usize, depth: u8, profile: Profile) -> Result<f64> {
    let name = match profile {
        Profile::Reference => "reference",
        Profile::Smoke => "smoke",
    };
    run_process(
        Command::new(current_exe()?)
            .arg("setup")
            .arg("--out")
            .arg(out)
            .args([
                "--profile",
                name,
                "--count",
                &count.to_string(),
                "--depth",
                &depth.to_string(),
            ]),
        "setup",
    )
}

pub(super) fn run_batch(
    out: &Path,
    trusted: &Path,
    count: usize,
    tree: ScenarioConfig,
    amounts: &[u64],
) -> Result<RunMetrics> {
    let total = Instant::now();
    let executable = current_exe()?;
    let inputs = out.join("private-inputs");
    let start = Instant::now();
    let history = fixtures(&inputs, count, tree, amounts)?;
    let allowed = read_bounded(&inputs.join("allowed-roots.json"), INPUT_JSON_LIMIT)?;
    write_new(&out.join("allowed-roots.json"), &allowed)?;
    write_json(&out.join("tree-history.json"), &history)?;
    let fixture_ms = start.elapsed().as_secs_f64() * 1e3;
    let mut children = Vec::with_capacity(count);
    let mut clients = Vec::with_capacity(count);
    let mut client_wall_ms = 0.0;
    for index in 0..count {
        let child = out.join(format!("client-{index}"));
        client_wall_ms += run_process(
            Command::new(&executable)
                .arg("client")
                .arg("--trusted-dir")
                .arg(trusted)
                .arg("--out")
                .arg(&child)
                .arg("--witness")
                .arg(inputs.join(format!("client-{index}.json"))),
            "client",
        )?;
        let metrics: ClientMetrics = read_json(&child.join("metrics.json"), SMALL_JSON_LIMIT)?;
        println!(
            "  Child {}: prove {:.3} ms, verify {:.3} ms, trace {:.3} ms",
            index + 1,
            metrics.timings.prove_ms,
            metrics.timings.verify_ms,
            metrics.timings.trace_ms
        );
        clients.push(metrics);
        children.push(child);
    }
    // Aggregation must succeed after all private notes and paths have been removed.
    fs::remove_dir_all(inputs)?;
    let result = out.join("result");
    let aggregate_wall_ms = run_process(
        Command::new(&executable)
            .arg("aggregate")
            .arg("--trusted-dir")
            .arg(trusted)
            .arg("--out")
            .arg(&result)
            .arg("--children")
            .args(&children),
        "aggregation",
    )?;
    let aggregation: BatchMetrics = read_json(&result.join("metrics.json"), INPUT_JSON_LIMIT)?;
    println!(
        "  Aggregate: prepare {:.3} ms, prove {:.3} ms, verify {:.3} ms (includes decoding)",
        aggregation.aggregation.prepare_ms, aggregation.aggregation.prove_ms, aggregation.verify_ms
    );
    write_json(&out.join("client-metrics.json"), &clients)?;
    for child in children {
        fs::remove_dir_all(child)?;
    }
    // The final verifier receives only public inputs, trusted authority and one proof.
    let verify_wall_ms = run_process(
        Command::new(&executable)
            .arg("verify")
            .arg("--trusted-dir")
            .arg(trusted)
            .arg("--statement")
            .arg(result.join("statement.json"))
            .arg("--proof")
            .arg(result.join("outer.proof"))
            .arg("--allowed-roots")
            .arg(out.join("allowed-roots.json")),
        "verification",
    )?;
    let metrics = RunMetrics {
        fixture_ms,
        client_wall_ms,
        aggregate_wall_ms,
        verify_wall_ms,
        total_ms: total.elapsed().as_secs_f64() * 1e3,
        clients,
        aggregation,
        tree: history,
    };
    write_json(&out.join("metrics.json"), &metrics)?;
    Ok(metrics)
}

fn check_amounts(count: usize, amounts: &[u64]) -> Result<()> {
    ensure!(
        amounts.is_empty() || amounts.len() == count,
        "provide exactly one amount per user"
    );
    Ok(())
}

fn run_process(command: &mut Command, stage: &str) -> Result<f64> {
    let start = Instant::now();
    let output = command
        .output()
        .with_context(|| format!("launch {stage}"))?;
    ensure!(
        output.status.success(),
        "{stage} process failed: {}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(start.elapsed().as_secs_f64() * 1e3)
}
