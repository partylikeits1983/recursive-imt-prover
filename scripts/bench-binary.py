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
    parser.add_argument("--threads", type=int, default=12)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    environment = dict(os.environ, RAYON_NUM_THREADS=str(args.threads))
    subprocess.run(["cargo", "build", "--locked", "--release", "--bin", "bench"], check=True)
    cases = []
    for count in [1, 2, 4, 8, 16]:
        cases.append((f"d8-n{count}-aggregate", ["--batch-size", str(count),
                      "--max-codeword-cells", str(1 << (28 if count == 4 else 27))]))
    for depth in [8, 16, 32]:
        for count in [1, 2, 4, 8, 16]:
            cases.append((f"d{depth}-n{count}-children", ["--depth", str(depth),
                          "--batch-size", str(count), "--children-only"]))
    for depth in [16, 32]:
        cases.append((f"d{depth}-n2-aggregate", ["--depth", str(depth),
                      "--max-codeword-cells", str(1 << 28)]))
    cases.append(("d8-n2-pcs80-pow16", ["--pcs-bits", "80", "--pow-bits", "16",
                  "--min-security-bits", "64", "--max-codeword-cells", str(1 << 28)]))
    results = []
    for name, parameters in cases:
        command = ["target/release/bench", "--out", str(args.out / name),
                   "--samples", str(args.samples)] + parameters
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
