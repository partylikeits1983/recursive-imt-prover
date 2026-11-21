use std::{
    sync::mpsc::{self, RecvTimeoutError, Sender},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use recursive_imt_prover::benchmark::peak_rss;
use serde_json::{Value, json};

const SAMPLE_INTERVAL: Duration = Duration::from_millis(250);

pub(super) struct ProcessMonitor {
    worker: Option<(Sender<()>, JoinHandle<ProcessPeaks>)>,
}

impl ProcessMonitor {
    /// Sample the resident memory and CPU of the persistent LeanVM prover processes together.
    pub fn workers(pids: &[u32], on_sample: impl Fn(ProcessPeaks) + Send + 'static) -> Self {
        let pids = pids
            .iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let (stop, receiver) = mpsc::channel();
        let worker = thread::spawn(move || {
            let mut peaks = ProcessPeaks::default();
            loop {
                if let Ok(sample) = std::process::Command::new("ps")
                    .args(["-o", "rss=,pcpu=", "-p", &pids])
                    .env("LC_ALL", "C")
                    .output()
                {
                    let stdout = String::from_utf8_lossy(&sample.stdout);
                    let rows = stdout.lines().filter_map(|line| {
                        let mut fields = line.split_whitespace();
                        Some((
                            fields.next()?.parse::<u64>().ok()? * 1024,
                            fields.next()?.parse::<f64>().ok()?,
                        ))
                    });
                    let (rss, cpu) = rows.fold((0, 0.), |(r, c), (rr, cc)| (r + rr, c + cc));
                    if rss > 0 {
                        peaks.rss_bytes = peaks.rss_bytes.max(Some(rss));
                        peaks.cpu_percent = Some(peaks.cpu_percent.unwrap_or(0.).max(cpu));
                        on_sample(peaks);
                    }
                }
                if receiver.recv_timeout(SAMPLE_INTERVAL) != Err(RecvTimeoutError::Timeout) {
                    return peaks;
                }
            }
        });
        Self {
            worker: Some((stop, worker)),
        }
    }

    pub fn start(on_sample: impl Fn(ProcessPeaks) + Send + 'static) -> Self {
        let (stop, receiver) = mpsc::channel();
        let initial = cpu_sample();
        let worker = thread::spawn(move || {
            let mut previous = initial;
            let mut peaks = ProcessPeaks::default();
            loop {
                let finished =
                    receiver.recv_timeout(SAMPLE_INTERVAL) != Err(RecvTimeoutError::Timeout);
                let sample = cpu_sample();
                if let Some(((last_wall, last_cpu), (wall, cpu))) = previous.zip(sample) {
                    let elapsed = wall.duration_since(last_wall);
                    // Use the final partial interval for runs shorter than one sample.
                    if !elapsed.is_zero()
                        && (!finished || elapsed >= SAMPLE_INTERVAL || peaks.cpu_percent.is_none())
                    {
                        let percent = 100.0 * cpu.saturating_sub(last_cpu).as_secs_f64()
                            / elapsed.as_secs_f64();
                        peaks.cpu_percent =
                            Some(peaks.cpu_percent.map_or(percent, |p| p.max(percent)));
                    }
                }
                previous = sample;
                let rss = peak_rss();
                peaks.rss_bytes = peaks.rss_bytes.max((rss > 0).then_some(rss));
                if finished {
                    return peaks;
                }
                on_sample(peaks);
            }
        });
        Self {
            worker: Some((stop, worker)),
        }
    }

    pub fn finish(mut self) -> ProcessPeaks {
        self.stop().unwrap_or_default()
    }

    fn stop(&mut self) -> Option<ProcessPeaks> {
        let (stop, worker) = self.worker.take()?;
        drop(stop);
        worker.join().ok()
    }
}

impl Drop for ProcessMonitor {
    fn drop(&mut self) {
        self.stop();
    }
}

pub(super) fn print_machine(environment: &Value, threads: usize) {
    let model = environment["hardware"]
        .as_str()
        .unwrap_or(std::env::consts::ARCH);
    let cpus = environment["logical_cpus"]
        .as_u64()
        .map_or_else(String::new, |n| format!("{n} logical CPUs, "));
    let memory = environment["memory_bytes"]
        .as_str()
        .and_then(|bytes| bytes.parse().ok())
        .map_or_else(
            || "unavailable".into(),
            |bytes| format!("{} total", memory_size(bytes)),
        );
    eprintln!("  CPU   {model} ({cpus}{threads} prover threads)");
    eprintln!("  RAM   {memory}");
}

fn cpu_sample() -> Option<(Instant, Duration)> {
    let mut cpu = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // This clock accounts for user and system CPU across all threads in this process.
    if unsafe { libc::clock_gettime(libc::CLOCK_PROCESS_CPUTIME_ID, &mut cpu) } != 0 {
        return None;
    }
    Some((
        Instant::now(),
        Duration::new(cpu.tv_sec as u64, cpu.tv_nsec as u32),
    ))
}

fn memory_size(bytes: u64) -> String {
    if bytes >= 1 << 30 {
        format!("{:.1} GiB", bytes as f64 / (1 << 30) as f64)
    } else {
        format!("{:.1} MiB", bytes as f64 / (1 << 20) as f64)
    }
}

#[derive(Clone, Copy, Default)]
pub(super) struct ProcessPeaks {
    cpu_percent: Option<f64>,
    rss_bytes: Option<u64>,
}

impl ProcessPeaks {
    pub fn record(&self, output: &mut Value) {
        output["peak_rss_bytes"] = json!(self.rss_bytes);
        output["peak_cpu_percent"] = json!(self.cpu_percent);
    }

    pub fn status_line(&self) -> String {
        let ram = self.rss_bytes.map(memory_size);
        let cpu = self.cpu_percent.map(|p| format!("{p:.0}%"));
        format!(
            "Peak RAM {} · Peak CPU {}",
            ram.as_deref().unwrap_or("—"),
            cpu.as_deref().unwrap_or("—")
        )
    }

    pub fn print(&self) {
        let ram = self.rss_bytes.map(memory_size);
        let cpu = self.cpu_percent.map(|p| format!("{p:.0}%"));
        eprintln!("\nProcess resources");
        eprintln!(
            "  Peak RAM    {} (RSS)",
            ram.as_deref().unwrap_or("unavailable")
        );
        eprintln!(
            "  Peak CPU    {} ({} ms samples, 100% = one core)",
            cpu.as_deref().unwrap_or("unavailable"),
            SAMPLE_INTERVAL.as_millis()
        );
    }
}

#[cfg(test)]
mod tests {
    use std::{sync::mpsc, time::Duration};

    use super::ProcessMonitor;

    #[test]
    fn short_runs_report_process_peaks() {
        let peaks = ProcessMonitor::start(|_| {}).finish();
        assert!(peaks.rss_bytes.is_some_and(|bytes| bytes > 0));
        assert!(peaks.cpu_percent.is_some_and(|p| p.is_finite() && p >= 0.0));
    }

    #[test]
    fn reports_peaks_while_the_run_is_active() {
        let (send, receive) = mpsc::channel();
        let monitor = ProcessMonitor::start(move |peaks| {
            let _ = send.send(peaks);
        });
        let live = receive.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(live.rss_bytes.is_some_and(|bytes| bytes > 0));
        assert!(live.cpu_percent.is_some_and(|p| p.is_finite() && p >= 0.0));
        let final_peaks = monitor.finish();
        assert!(final_peaks.rss_bytes >= live.rss_bytes);
        assert!(final_peaks.cpu_percent >= live.cpu_percent);
    }
}
