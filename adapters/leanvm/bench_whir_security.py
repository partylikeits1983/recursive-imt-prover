"""Rebuild LeanVM's bounded WHIR schedules and compare the same IMT witness locally."""

import argparse
import json
from pathlib import Path
import re
import shutil
import statistics
import subprocess
import tempfile

REVISION = "5b43139d50272f996ca884669b1d51555af1f35d"
ADAPTER = Path(__file__).resolve().parent
GRINDS = {"QUERY": 17, "FOLD": 7, "BATCH": 13, "OOD": 15}

SEARCH = """use experimental_pcs::{LOG_PACKING,whir_config::WhirSecurityConfig};
fn main() {
    for rate in verifier::MIN_LOG_INV_RATE..=verifier::MAX_LOG_INV_RATE {
        for log in verifier::MIN_STACKED_LOG..=verifier::MAX_STACKED_LOG {
            let cfg = WhirSecurityConfig::derive_config_with_log_inv_rate(log + LOG_PACKING, rate).unwrap();
            cfg.validate().unwrap();
            println!("{rate} {log} {:?}", cfg.to_config().unwrap().queries);
        }
    }
}
"""


def replace_once(source, previous, new):
    if source.count(previous) != 1:
        raise ValueError(f"unexpected pinned source around {previous!r}")
    return source.replace(previous, new)


def cargo(tree, package, example, *args):
    return subprocess.check_output(
        ["cargo", "run", "--release", "-p", package, "--example", example, "--", *args],
        cwd=tree, text=True,
    )


def fit_table(source, output, baseline):
    lines = source.splitlines()
    start = next(i for i, line in enumerate(lines) if line.startswith("const WHIR_QUERIES:"))
    rows = {}
    for line in output.splitlines():
        rate, log_n, values = line.split(maxsplit=2)
        key = (int(rate), int(log_n))
        if key in rows:
            raise ValueError("repeated parameter row")
        rows[key] = json.loads(values)
    keys = {(r, n) for r in range(1, 5) for n in range(16, 31)}
    if set(rows) != keys:
        raise ValueError("incomplete validated parameter table")
    for (rate, log_n), counts in sorted(rows.items()):
        i = start + rate
        entries = list(re.finditer(r"&\[[0-9,]+\]", lines[i]))
        if len(entries) != 15:
            raise ValueError("unexpected table width")
        pos = entries[log_n - 16]
        entry = "&[" + ",".join(map(str, counts)) + "]"
        if baseline and entry != pos.group():
            raise ValueError("upstream calculator disagrees with its verifier")
        lines[i] = lines[i][:pos.start()] + entry + lines[i][pos.end():]
    return "\n".join(lines) + "\n", rows


def run(tree):
    cpu = tree / "crates/stable_prover/lean_vm_core"
    examples = cpu / "examples"
    (examples / "support").mkdir(parents=True, exist_ok=True)
    shutil.copyfile(ADAPTER / "examples/support/imt.rs", examples / "support/imt.rs")
    guest = (ADAPTER / "examples/imt-leaf.rs").read_text()
    (examples / "security_leaf.rs").write_text(replace_once(guest, "use lean_vm_core::", "use stable_lean_vm_core::"))
    for name in ("imt_preimage.py", "imt_leaf.py"):
        shutil.copyfile(ADAPTER / name, cpu / name)
    manifest = cpu / "Cargo.toml"
    manifest.write_text(replace_once(manifest.read_text(), "[dev-dependencies]", '[dev-dependencies]\nsha3 = "0.10.8"'))
    search = tree / "crates/experimental_prover/pcs/examples/imt_security_diagnostic.rs"
    search.parent.mkdir(exist_ok=True)
    search.write_text(SEARCH)
    verifier = tree / "crates/verifier/src"
    transcript = verifier / "transcript.rs"
    whir = verifier / "whir.rs"
    original, params = transcript.read_text(), whir.read_text()
    for bits, extra_grinding in [(125, 0), (128, 0), (128, 3)]:
        transcript.write_text(replace_once(original, "SECURITY_BITS: u32 = 125;", f"SECURITY_BITS: u32 = {bits};"))
        schedule = params
        for site, amount in GRINDS.items():
            name = f"pub const {site}_GRINDING_BITS: u32 = "
            schedule = replace_once(schedule, f"{name}{amount};", f"{name}{amount + extra_grinding};")
        whir.write_text(schedule)
        output = cargo(tree, "experimental_pcs", "imt_security_diagnostic")
        validated, rows = fit_table(schedule, output, baseline=(bits == 125))
        whir.write_text(validated)
        result = cargo(tree, "stable_lean_vm_core", "security_leaf", "--preimage")
        runs = [dict(pair.split("=") for pair in line.split()) for line in result.splitlines() if line.startswith("sample=")]
        warm = [r for r in runs if r["sample"] != "0" and r["log_inv_rate"] == "4"]
        if len(warm) != 4 or len({r["bytes"] for r in warm}) != 1:
            raise ValueError("incomplete or inconsistent leaf benchmark")
        print(json.dumps({"per_message_target": bits, "extra_whir_grinding_bits": extra_grinding,
                          "arity26_queries": rows[4, 26], "leaf_proof_bytes": int(warm[0]["bytes"]),
                          "warm_prove_ms": 1000 * statistics.median(float(r["prove_s"]) for r in warm),
                          "warm_verify_ms": 1000 * statistics.median(float(r["verify_s"]) for r in warm)}), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", help="LeanVM checkout containing the pinned revision, or its repository URL")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="imt-leanvm-whir-") as tmp:
        tree = Path(tmp) / "leanVM"
        subprocess.run(["git", "clone", "--quiet", "--no-checkout", args.source, str(tree)], check=True)
        subprocess.run(["git", "-C", str(tree), "checkout", "--quiet", "--detach", REVISION], check=True)
        run(tree)
