#!/usr/bin/env python3
"""Run masked membership child experiments with explicit threads, time and RSS budgets.

Build the masked-child example first. These are unreviewed child-proof experiments, not a
128-bit security certificate or an aggregation benchmark. No compilation runs
inside the measured subprocesses.
"""
import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--depths", type=int, nargs="+", default=[16, 32])
    parser.add_argument("--threads", type=int, default=4)
    parser.add_argument("--samples", type=int, default=3)
    parser.add_argument("--max-rss-gib", type=float, default=10)
    parser.add_argument("--timeout", type=float, default=300)
    args = parser.parse_args()
    if args.threads < 1 or not 1 <= args.samples <= 20:
        parser.error("positive threads and 1..20 samples required")
    if not 0 < args.max_rss_gib <= 12 or args.timeout <= 0:
        parser.error("RSS budget must be in (0,12] GiB and timeout positive")
    if any(depth not in [16, 32] for depth in args.depths):
        parser.error("benchmark depths must be 16 or 32")
    root = Path(__file__).resolve().parent.parent
    binary = root / "target/release/examples/masked-child"
    if not binary.is_file():
        parser.error("first run cargo build --locked --release --example masked-child")
    args.out = args.out.resolve()
    args.out.mkdir(parents=True, exist_ok=False)
    env = dict(os.environ, RAYON_NUM_THREADS=str(args.threads))
    all_ok = True
    for depth in args.depths:
        destination = args.out / f"depth-{depth}"
        command = [str(binary), "--depth", str(depth), "--samples", str(args.samples),
                   "--out", str(destination)]
        start = time.monotonic()
        reason = None
        peak = 0
        with (args.out / f"depth-{depth}.log").open("w") as log:
            process = subprocess.Popen(command, cwd=root, env=env, stdout=log,
                                       stderr=subprocess.STDOUT, start_new_session=True)
            while process.poll() is None:
                sampled = subprocess.run(["ps", "-o", "rss=", "-p", str(process.pid)],
                                         capture_output=True, text=True, check=False)
                if sampled.stdout.strip():
                    peak = max(peak, int(sampled.stdout.strip()) * 1024)
                if peak > args.max_rss_gib * 2**30:
                    reason = "RSS budget exceeded"
                elif time.monotonic() - start > args.timeout:
                    reason = "wall-time budget exceeded"
                if reason:
                    # Only the process group created by this script is stopped.
                    try:
                        os.killpg(process.pid, signal.SIGTERM)
                    except ProcessLookupError:
                        pass
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        os.killpg(process.pid, signal.SIGKILL)
                        process.wait()
                    break
                time.sleep(0.25)
        result = {"command": command, "threads": args.threads,
                  "exit_code": process.returncode, "stop_reason": reason,
                  "wall_seconds": time.monotonic() - start,
                  "sampled_parent_peak_rss_bytes": peak,
                  "max_rss_gib": args.max_rss_gib, "timeout_seconds": args.timeout,
                  "scope": "experimental masked membership child; no aggregate"}
        (args.out / f"depth-{depth}-supervisor.json").write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps(result), flush=True)
        all_ok &= process.returncode == 0
    raise SystemExit(0 if all_ok else 1)


if __name__ == "__main__":
    main()
