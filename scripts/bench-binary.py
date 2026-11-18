#!/usr/bin/env python3
"""Run the bounded binary research matrix sequentially; retain every failure."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--samples", type=int, default=3)
    parser.add_argument("--threads", type=int, default=4)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    environment = dict(os.environ, RAYON_NUM_THREADS=str(args.threads))
    subprocess.run(["cargo", "build", "--locked", "--release", "--bin", "bench"], check=True)
    cases = []
    depth = 32
    for count in [1, 2, 4, 8, 16, 32, 64]:
        base = ["--depth", str(depth), "--batch-size", str(count)]
        cases.append((f"d{depth}-n{count}-children", base + ["--children-only"]))
        cases.append((f"d{depth}-n{count}-aggregate", base +
                      ["--max-codeword-cells", str(1 << 29)]))
    results = []
    for name, parameters in cases:
        command = ["target/release/bench", "--out", str(args.out / name),
                   "--samples", str(args.samples), "--pcs-bits", "152", "--pow-bits", "16",
                   "--min-security-bits", "127", "--min-algebraic-bits", "144"] + parameters
        print(f"Running {name}", flush=True)
        started = time.monotonic()
        with (args.out / f"{name}.log").open("w") as log:
            result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, env=environment)
        results.append({"case": name, "command": command, "threads": args.threads, "exit_code": result.returncode,
                        "process_wall_seconds": time.monotonic() - started})
        (args.out / "runs.json").write_text(json.dumps(results, indent=2) + "\n")
        print(f"  exit={result.returncode}", flush=True)
    print(f"Raw reports and failures: {args.out}")
    return int(any(row["exit_code"] != 0 for row in results))


if __name__ == "__main__":
    raise SystemExit(main())
