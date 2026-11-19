//! Shared measurements for the binary baseline and VEIL experiment.
use std::{mem::MaybeUninit, process::Command, time::Instant};

use serde_json::{Value, json};

pub fn ms(start: Instant) -> f64 {
    start.elapsed().as_secs_f64() * 1000.0
}

pub fn statistics(mut values: Vec<f64>) -> Value {
    if values.is_empty() {
        return Value::Null;
    }
    values.sort_by(f64::total_cmp);
    let n = values.len();
    json!({"min":values[0], "median":(values[n / 2] + values[(n - 1) / 2]) / 2.0, "max":values[n - 1]})
}

pub fn environment() -> Value {
    json!({"hardware":cpu_model(), "memory_bytes":memory_bytes(),
        "logical_cpus":sysconf(libc::_SC_NPROCESSORS_ONLN), "os":command("uname", &["-a"]),
        "rustc":command("rustc", &["-Vv"]), "threads":rayon::current_num_threads(),
        "rustflags_runtime":std::env::var("RUSTFLAGS").unwrap_or_default(),
        "source_blake3":env!("IMT_SOURCE_BLAKE3"),
        "profile":if cfg!(debug_assertions) {"debug"} else {"release"},
        "compile_time_included":false,
        "plonky3_crates":"0.9.0-rc.2", "plonky3_revision":"fe5e46d755b8a7d9069778361e21b33e5978b377",
        "flock_revision":"708900d7a730d6ce4d5421d43e2193f2301920fa",
        "recursion_revision":"3a69ba61f713c8400b14eb3d8f0e52caa13512c7",
        "memory_method":"getrusage RUSAGE_SELF lifetime high-water RSS; cumulative across stages and warm samples",
        "release_profile":{"lto":"thin","codegen_units":16}})
}

#[cfg(not(target_os = "linux"))]
fn cpu_model() -> Option<String> {
    command("sysctl", &["-n", "machdep.cpu.brand_string"])
}

#[cfg(target_os = "linux")]
fn cpu_model() -> Option<String> {
    fn model_name(info: &str) -> Option<String> {
        info.lines().find_map(|line| {
            let (field, value) = line.split_once(':')?;
            let value = value.trim();
            (field.trim().eq_ignore_ascii_case("model name") && !value.is_empty())
                .then(|| value.to_owned())
        })
    }

    std::fs::read_to_string("/proc/cpuinfo")
        .ok()
        .as_deref()
        .and_then(model_name)
        .or_else(|| command("lscpu", &[]).as_deref().and_then(model_name))
}

#[cfg(not(target_os = "linux"))]
fn memory_bytes() -> Option<String> {
    command("sysctl", &["-n", "hw.memsize"])
}

#[cfg(target_os = "linux")]
fn memory_bytes() -> Option<String> {
    let bytes = sysconf(libc::_SC_PHYS_PAGES)?.checked_mul(sysconf(libc::_SC_PAGESIZE)?)?;
    Some(bytes.to_string())
}

fn sysconf(name: libc::c_int) -> Option<u64> {
    // These queries take an integer selector and do not access caller memory.
    let value = unsafe { libc::sysconf(name) };
    (value > 0).then_some(value as u64)
}

pub fn peak_rss() -> u64 {
    // getrusage initializes the output on success. Darwin reports bytes; Linux KiB.
    let mut usage = MaybeUninit::<libc::rusage>::uninit();
    if unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) } != 0 {
        return 0;
    }
    let usage = unsafe { usage.assume_init() };
    let scale = if cfg!(target_os = "macos") { 1 } else { 1024 };
    usage.ru_maxrss.max(0) as u64 * scale
}

fn command(program: &str, args: &[&str]) -> Option<String> {
    let output = Command::new(program)
        .args(args)
        .env("LC_ALL", "C")
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
}
