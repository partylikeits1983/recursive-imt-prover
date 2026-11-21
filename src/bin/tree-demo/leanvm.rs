use super::resources::ProcessMonitor;
use super::{Args, Input, TreeProgress, TreeStatement, print_machine, schedule};
use anyhow::{Context, Result, ensure};
use rayon::prelude::*;
use recursive_imt_prover::{
    benchmark::environment,
    binary::{
        AggregatePublic, ClientPublic, IMT_DEPTH,
        tree::{Imt, keccak, preimage_leaf},
    },
    files::{read_json, write_json},
};
use serde_json::{Value, json};
use std::{
    fs,
    io::{BufRead, BufReader, IsTerminal, Write},
    path::{Path, PathBuf},
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
    sync::{Arc, Mutex},
    time::Instant,
};

pub(super) const PROTOCOL: &str = "imt-leanvm-preimage-recursion-v1";
const PROGRAM: &str = "d3b8643b2ab18eaaf550327bd359080272c9d893615939039134780d419621a5";

pub(super) const MASKED_PROTOCOL: &str = "imt-leanvm-masked-preimage-recursion-v1";
const MASKED_PROGRAM: &str = "7158a6b4e17788f1b6a6fef2f16b29ec914155515fa030d55de9531b4d1c5507";
fn key(masked: bool) -> &'static str {
    if masked { MASKED_PROGRAM } else { PROGRAM }
}
fn protocol(masked: bool) -> &'static str {
    if masked { MASKED_PROTOCOL } else { PROTOCOL }
}
fn authority(masked: bool) -> Value {
    json!({"protocol": protocol(masked), "program": key(masked)})
}

fn masked_adapter(repo: &Path) -> Result<PathBuf> {
    ensure!(
        Command::new("cargo")
            .current_dir(repo)
            .args([
                "build",
                "--quiet",
                "--release",
                "--locked",
                "-p",
                "imt-leanvm-masked-client",
                "--target-dir",
                "target"
            ])
            .status()?
            .success(),
        "could not build masked client adapter"
    );
    Ok(repo.join("target/release/imt-leanvm-masked-client"))
}

fn binary(adapter: Option<&Path>) -> Result<PathBuf> {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR"));
    let source = tempfile::tempdir()?;
    let guest = source.path().join("masked.py");
    let mut args = Vec::new();
    if let Some(adapter) = adapter {
        ensure!(
            Command::new(adapter)
                .arg("build-guest")
                .arg(&guest)
                .status()?
                .success(),
            "could not generate trusted masked verification program"
        );
        args.extend([Path::new("--masked-guest"), guest.as_path()]);
    }
    let output = Command::new("python3")
        .arg(repo.join("adapters/leanvm/recursion/prepare.py"))
        .args(args)
        .arg("--cached")
        .arg(repo.join("target/leanvm-recursion-cli"))
        .stderr(Stdio::inherit())
        .output()
        .context("prepare LeanVM CLI prover")?;
    ensure!(
        output.status.success(),
        "could not build the pinned LeanVM prover"
    );
    let path = PathBuf::from(std::str::from_utf8(&output.stdout)?.trim());
    ensure!(
        path.is_absolute() && path.is_file(),
        "missing LeanVM executable"
    );
    Ok(path)
}

// Generate the same growing IMT as the recursion benchmark, using the application implementation.
fn fixtures(count: usize, dir: &Path) -> Result<AggregatePublic> {
    let mut tree = Imt::new(IMT_DEPTH)?;
    let mut secrets = Vec::with_capacity(count);
    for index in 0..count as u8 {
        let secret = keccak(&[b"imt-recursion-secret".as_slice(), &[index]].concat());
        tree.append(preimage_leaf(&secret))?;
        secrets.push(secret);
    }
    let mut children = Vec::with_capacity(count);
    for (index, secret) in secrets.iter().enumerate() {
        tree.append(keccak(
            &[b"imt-recursion-append".as_slice(), &[index as u8]].concat(),
        ))?;
        let mut witness = secret.to_vec();
        witness.extend((index as u32).to_le_bytes());
        for sibling in tree.path(index as u32)? {
            witness.extend(sibling);
        }
        fs::write(dir.join(format!("{index}.witness")), witness)?;
        children.push(ClientPublic::membership_root(tree.root()));
    }
    Ok(AggregatePublic { children })
}

struct Worker {
    child: Child,
    input: ChildStdin,
    output: BufReader<ChildStdout>,
}

impl Worker {
    fn new(bin: &Path, directory: &Path, threads: usize, masked: bool) -> Result<Self> {
        let mut child = Command::new(bin)
            .arg("worker")
            .env("IMT_THREADS", threads.to_string())
            .current_dir(directory)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()?;
        let input = child.stdin.take().context("worker stdin")?;
        let output = BufReader::new(child.stdout.take().context("worker stdout")?);
        let mut worker = Self {
            child,
            input,
            output,
        };
        let mut line = String::new();
        worker.output.read_line(&mut line)?;
        ensure!(
            line.trim() == format!("ready {}", key(masked)),
            "unexpected LeanVM guest identity"
        );
        Ok(worker)
    }

    fn prove(&mut self, node: schedule::Node, expected: &TreeStatement) -> Result<Measurement> {
        writeln!(self.input, "{} {}", node.level, node.index)?;
        self.input.flush()?;
        let mut line = String::new();
        ensure!(
            self.output.read_line(&mut line)? > 0,
            "LeanVM worker exited during proof generation"
        );
        let fields: Vec<_> = line.split_whitespace().collect();
        let [digest, bytes, prove_ms, verify_ms] = fields.as_slice() else {
            anyhow::bail!("unexpected LeanVM worker response");
        };
        ensure!(
            *digest == hex::encode(expected.digest),
            "worker returned a different IMT statement"
        );
        Ok(Measurement {
            statement: expected.clone(),
            bytes: bytes.parse()?,
            prove_ms: prove_ms.parse()?,
            verify_ms: verify_ms.parse()?,
        })
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

struct Measurement {
    statement: TreeStatement,
    bytes: usize,
    prove_ms: f64,
    verify_ms: f64,
}

fn verify(bin: &Path, directory: &Path, statement: &TreeStatement, threads: usize) -> Result<()> {
    let output = Command::new(bin)
        .arg("verify")
        .arg(directory.join("root.imt"))
        .arg(hex::encode(statement.digest))
        .arg(statement.count.to_string())
        .env("IMT_THREADS", threads.to_string())
        .stdout(Stdio::null())
        .output()?;
    ensure!(
        output.status.success(),
        "LeanVM rejected the saved root or its expected statement: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

pub(super) fn verify_saved(args: &Args, masked: bool) -> Result<()> {
    let dir = args.out.as_deref().unwrap_or(Path::new("run/cyclic-tree"));
    let trust = args
        .trusted
        .clone()
        .unwrap_or_else(|| dir.join("trusted.json"));
    ensure!(
        read_json::<Value>(&trust)? == authority(masked),
        "unexpected LeanVM verifier authority"
    );
    let statement = match &args.expected_statement {
        Some(statement) => statement.clone(),
        None => TreeStatement::from_public(&read_json(&dir.join("statement.json"))?)?,
    };
    let adapter = masked
        .then(|| masked_adapter(Path::new(env!("CARGO_MANIFEST_DIR"))))
        .transpose()?;
    verify(&binary(adapter.as_deref())?, dir, &statement, args.threads)?;
    println!(
        "{}",
        json!({"verified": true, "protocol": protocol(masked), "statement": hex::encode(statement.bytes()), "children": statement.count})
    );
    Ok(())
}

pub(super) fn run(
    args: &Args,
    scratch: tempfile::TempDir,
    destination: Option<&Path>,
    masked: bool,
) -> Result<()> {
    let adapter = masked
        .then(|| masked_adapter(Path::new(env!("CARGO_MANIFEST_DIR"))))
        .transpose()?;
    let bin = binary(adapter.as_deref())?;
    let out = scratch.path();
    let jobs_dir = tempfile::Builder::new().prefix("nodes-").tempdir_in(out)?;
    let limits = args.proof_limits();
    let slots = limits.jobs.min(args.batch_size);
    eprintln!(
        "LeanVM recursion · {} leaves · {} concurrent proof job(s) · {} total prover threads",
        args.batch_size, slots, args.threads
    );
    print_machine(&environment(), args.threads);
    let idle: Vec<_> = (0..slots)
        .into_par_iter()
        .map(|i| {
            let threads = args.threads / slots + usize::from(i < args.threads % slots);
            Worker::new(&bin, jobs_dir.path(), threads, masked)
        })
        .collect::<Result<_>>()?;
    if args.setup_only {
        println!(
            "{}",
            json!({"setup_only": true, "authority": authority(masked)})
        );
        return Ok(());
    }
    let prep = Instant::now();
    let public = if let Some(adapter) = &adapter {
        let temp = tempfile::tempdir_in(out)?;
        let generated = temp.path().join("clients");
        let dir = if let Some(path) = &args.from_children {
            path
        } else {
            super::prepare_children(args, &generated)?;
            &generated
        };
        let public: AggregatePublic = read_json(&dir.join("statement.json"))?;
        ensure!(
            public.children.len() == args.batch_size,
            "saved masked client count differs from requested batch size"
        );
        for i in 0..args.batch_size {
            let path = jobs_dir.path().join(format!("{i}.masked"));
            ensure!(
                Command::new(adapter)
                    .arg("prepare")
                    .arg(dir)
                    .arg(&path)
                    .arg("--index")
                    .arg(i.to_string())
                    .status()?
                    .success(),
                "could not prepare masked client {i}"
            );
        }
        public
    } else {
        fixtures(args.batch_size, jobs_dir.path())?
    };
    let prep_ms = prep.elapsed().as_secs_f64() * 1000.;
    let expected = TreeStatement::from_public(&public)?;
    let leaves = public.children.iter().map(TreeStatement::leaf).collect();
    let progress = Arc::new(TreeProgress::new(args.batch_size));
    let display = Arc::clone(&progress);
    let pids = idle.iter().map(|w| w.child.id()).collect::<Vec<_>>();
    let monitor = ProcessMonitor::workers(&pids, move |peaks| display.update_peaks(peaks));
    let workers = Mutex::new(idle);
    progress.show(if masked {
        "Verifying masked client proofs in LeanVM"
    } else {
        "Proving synthetic Keccak preimages"
    });
    let start = Instant::now();
    let mut leaf_ms = 0.;
    let mut merge_ms = 0.;
    let root = schedule::run::<TreeStatement, Measurement>(
        leaves,
        limits,
        |node, input| {
            let statement = match input {
                Input::Leaf(statement) => statement,
                Input::Pair([left, right]) => {
                    TreeStatement::merge(&left.statement, &right.statement)?
                }
            };
            let mut worker = workers
                .lock()
                .unwrap()
                .pop()
                .context("worker pool exhausted")?;
            let result = progress.track(node.level, node.index, || worker.prove(node, &statement));
            workers.lock().unwrap().push(worker);
            result
        },
        |node, m: &Measurement, _, _| {
            if node.level == 0 {
                leaf_ms += m.prove_ms;
            } else {
                merge_ms += m.prove_ms;
            }
        },
    )?;
    let wall = start.elapsed();
    let peaks = monitor.finish();
    drop(workers);
    ensure!(
        root.statement == expected,
        "root differs from the ordered client statements"
    );
    fs::rename(
        jobs_dir
            .path()
            .join(format!("{}-0.imt", args.batch_size.ilog2())),
        out.join("root.imt"),
    )?;
    drop(jobs_dir);
    verify(&bin, out, &expected, args.threads)?;
    progress.finish(peaks);
    let mut report = json!({
        "protocol": protocol(masked), "client_privacy": if masked {"experimental statistical masking"}else{"non-hiding"}, "client_preparation_ms":prep_ms, "batch_size": args.batch_size, "depth": IMT_DEPTH,
        "jobs": slots, "threads": args.threads, "leaf_rate": "1/4", "merge_rate": "1/2",
        "merge_count": args.batch_size - 1, "wall_ms": wall.as_secs_f64()*1000., "sum_leaf_prove_ms": leaf_ms,
        "sum_merge_prove_ms": merge_ms, "root_prove_ms": root.prove_ms, "root_proof_bytes": root.bytes,
        "root_verify_ms": root.verify_ms, "statement": hex::encode(expected.bytes()), "fresh_verifier": {"verified": true},
    });
    peaks.record(&mut report);
    eprintln!(
        "{} client proofs and {} merges in {:.2} s · final merge {:.0} ms",
        args.batch_size,
        args.batch_size - 1,
        wall.as_secs_f64(),
        root.prove_ms
    );
    eprintln!(
        "Root: {} proof bytes · native verification {:.2} ms · {} clients",
        root.bytes, root.verify_ms, expected.count
    );
    if let Some(path) = destination {
        write_json(&out.join("trusted.json"), &authority(masked))?;
        write_json(&out.join("statement.json"), &public)?;
        write_json(&out.join("report.json"), &report)?;
        fs::rename(out, path)?;
        eprintln!("Saved verified root to {}", path.display());
    }
    if args.json || !std::io::stdout().is_terminal() {
        println!("{report}");
    }
    Ok(())
}
