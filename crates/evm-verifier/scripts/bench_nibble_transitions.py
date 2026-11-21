"""Verify all Keccak rounds, both bit readings and the range of the committed four-bit table."""

import argparse
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

from bench_digit_transitions import measure
from bench_large_prime_opening import checkout
from bench_streamed_digits import expanded


def assemble(fixture, caps, gkr):
    point = (fixture / "opening-point.bin").read_bytes()
    value = (fixture / "digit-value.bin").read_bytes()
    if (fixture / "statement.bin").read_bytes() != point + value:
        raise ValueError("WHIR opened a different evaluation from the digit sumcheck")
    for name in ("node.bin", "root.bin"):
        shutil.copyfile(caps / name, fixture / name)
    shutil.copyfile(gkr, fixture / "rounds.bin")
    public = Path(f"{gkr}.public").read_bytes()
    (fixture / "output-result.bin").write_bytes(expanded(public[32:]))


def generate(work, terminal, caps, row_bits, fixture):
    whir = work / "whir"
    checkout(whir)
    src = Path(__file__).with_name("prime_whir")
    dest = whir / "src/bin"
    for driver in ("stream_digits", "stream_opening", "nibble_relation"):
        shutil.copyfile(src / f"{driver}.rs", dest / f"{driver}.rs")
    (dest / "support").mkdir(exist_ok=True)
    for module in (
        "segments",
        "digits",
        "node",
        "nibble_folds",
        "stream_code",
        "nibble_gate",
        "digit_sumcheck",
        "close_moments",
        "digit_columns",
        "quartets",
    ):
        shutil.copyfile(src / f"support/{module}.rs", dest / f"support/{module}.rs")
    terminal, caps = terminal.resolve(), caps.resolve()
    gkr = caps / "rounds.bin"
    env = {**os.environ, "RAYON_NUM_THREADS": "5"}
    for driver, arguments in [
        ("nibble_relation", [terminal, caps, gkr, str(row_bits), fixture]),
        ("stream_opening", [terminal, caps, str(row_bits), fixture, fixture / "opening-point.bin"]),
    ]:
        subprocess.run(
            ["cargo", "run", "--release", "--locked", "--bin", driver, "--", *arguments],
            cwd=whir,
            check=True,
            env=env,
        )
    assemble(fixture, caps, gkr)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    source = p.add_mutually_exclusive_group(required=True)
    source.add_argument("--terminal", type=Path)
    source.add_argument("--fixture", type=Path)
    p.add_argument("--caps", type=Path, help="Saved output of bench_streamed_digits, including rounds.bin")
    p.add_argument("--row-bits", type=int, choices=(7, 16), default=16)
    p.add_argument("--export-call", type=Path)
    p.add_argument("--save-fixture", type=Path)
    p.add_argument(
        "--hash-profile",
        action="store_true",
        help="Count Keccak-f permutations and field operations in the verifier",
    )
    p.add_argument("--forge", default="forge")
    p.add_argument("--anvil", default="anvil")
    args = p.parse_args()
    if bool(args.terminal) != bool(args.caps):
        p.error("generating a proof requires both --terminal and --caps")
    with tempfile.TemporaryDirectory(prefix="imt-nibble-transitions-") as tmp:
        work = Path(tmp)
        fixture = args.fixture or work / "fixture"
        if args.terminal:
            generate(work, args.terminal, args.caps, args.row_bits, fixture)
        measure(fixture, args.forge, args.anvil, args.export_call, args.row_bits, args.hash_profile)
        if args.save_fixture:
            shutil.copytree(fixture, args.save_fixture)


if __name__ == "__main__":
    main()
