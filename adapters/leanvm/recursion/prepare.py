"""Run genuine binary LeanVM recursion on independently proved depth-32 IMT preimages."""
import argparse
import hashlib
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile

PIN = "73c2cc094c0be4a1c5af6ec613e8021c9e16da87"
SRC = Path(__file__).resolve().parent


def guest(original, masked=None):
    # Retain upstream verification, bytecode-claim batching and its public statement encoding.
    start = original.index("def main():")
    end = original.index("def aggregate_claims(", start)
    standalone = (SRC.parent / "imt_preimage.py").read_text()
    path_start = standalone.index("def main():") + len("def main():")
    path_end = standalone.index("    public = ", path_start)
    leaf = "def imt_path():" + standalone[path_start:path_end] + "    return current[0], current[1]\n"
    if masked is not None:
        constants, leaf = masked.read_text().split("from snark_lib import *", 1)
        # zkDSL collects module constants before the first function.
        original = constants + "\n" + original
        start = original.index("def main():")
        end = original.index("def aggregate_claims(", start)
    # After the 15-byte domain, the digest's low byte occupies the high byte of the first cell.
    split = [
        "def imt_split(word):",
        "    bits = StackBuf(128)",
        '    hint_witness(bits, "word_bits")',
        "    for i in unroll(0, 128):",
        "        assert bits[i] * bits[i] == bits[i]",
    ]
    for name, begin, finish, shift in [("original", 0, 128, 0), ("head", 0, 8, 120), ("tail", 8, 128, -8)]:
        split.append("    " + name + " = 0")
        split.extend(f"    {name} += {1 << (i + shift)} * bits[{i}]" for i in range(begin, finish))
    split.extend(["    assert original == word", "    return head, tail", ""])
    leaf_tag = int.from_bytes(b"IMT-AGG-LEAF-V3", "little")
    pair_tag = int.from_bytes(b"IMT-AGG-NODE-V2", "little")
    recipes = f"""
def imt_hash_leaf(a, b):
    out = StackBuf(2)
    ah, at = imt_split(a)
    bh, bt = imt_split(b)
    keccak([{leaf_tag} + ah, at + bh], [bt, 0], out, tail=[0, 0, 0, 0], len=111)
    return out[0], out[1]

def imt_hash_pair(a, b, right0, right1, half):
    out = StackBuf(2)
    ah, at = imt_split(a)
    bh, bt = imt_split(b)
    keccak([{pair_tag} + ah, at + bh], [bt + {1 << 120} * half, right0], out, tail=[right1, half, 0, 0], len=81)
    return out[0], out[1]
"""
    return "".join([
        original[:start], leaf, "\n".join(split), recipes,
        (SRC / "imt_guest.py").read_text(), "\n", original[end:],
    ])


def build(dest, checkout, target=None, masked=None):
    if checkout:
        src = str(checkout.resolve())
    else:
        sibling = SRC.parents[3] / "leanVM"
        src = "https://github.com/leanEthereum/leanVM.git"
        if (sibling / ".git").exists() and subprocess.run(
            ["git", "-C", str(sibling), "cat-file", "-e", PIN + "^{commit}"],
            stderr=subprocess.DEVNULL,
        ).returncode == 0:
            src = str(sibling)
    if dest.exists():
        raise FileExistsError("the build directory must be fresh")
    subprocess.run(["git", "init", "-q", str(dest)], check=True)
    subprocess.run(["git", "fetch", "-q", "--depth=1", src, PIN], cwd=dest, check=True)
    subprocess.run(["git", "checkout", "-q", "--detach", "FETCH_HEAD"], cwd=dest, check=True)
    subprocess.run(["git", "apply", str(SRC / "terminal-transcript.patch")], cwd=dest, check=True)
    subprocess.run(["git", "apply", str(SRC / "terminal-compact.patch")], cwd=dest, check=True)
    # The isolated directory otherwise picks up the user's global Rust toolchain.
    shutil.copyfile(SRC.parents[2] / "rust-toolchain.toml", dest / "rust-toolchain.toml")
    code = dest / "guests/lean_ethereum.py"
    code.write_text(guest(code.read_text(), masked))
    package = dest / "crates/aggregation"
    prover = (SRC / "prover.rs").read_text().replace("const MASKED_CLIENT: bool = false;", f"const MASKED_CLIENT: bool = {str(masked is not None).lower()};")
    (package / "src/imt.rs").write_text(prover)
    with open(package / "src/lib.rs", "a") as f:
        f.write("\npub mod imt;\n")
    with open(package / "Cargo.toml", "a") as f:
        f.write('\n[dependencies.experimental_lean_vm_core]\npath = "../experimental_prover/lean_vm_core"\n')
    binary = package / "src/bin"
    binary.mkdir(exist_ok=True)
    (binary / "imt-recursion.rs").write_text(
        'fn main() -> Result<(), String> { aggregation::imt::run(&std::env::args().skip(1).collect::<Vec<_>>()) }\n')
    # The experimental prover is already a locked workspace package.
    lock = dest / "Cargo.lock"
    body = lock.read_text()
    deps = body.index(' "fiat_shamir_prover",', body.index('name = "aggregation"'))
    lock.write_text(body[:deps] + ' "experimental_lean_vm_core",\n' + body[deps:])
    subprocess.run(["cargo", "build", "--locked", "--release", "-p", "aggregation", "--bin", "imt-recursion"],
                   cwd=dest, check=True, env=os.environ if target is None else {**os.environ, "CARGO_TARGET_DIR": str(target)})


def cached(directory, checkout, masked=None):
    import fcntl

    inputs = [Path(__file__), SRC / "prover.rs", SRC / "imt_guest.py", SRC.parent / "imt_preimage.py",
              SRC / "terminal-transcript.patch", SRC / "terminal-compact.patch", SRC.parents[2] / "rust-toolchain.toml"]
    if masked is not None:
        inputs.append(masked)
    digest = hashlib.sha256((sys.platform + platform.machine()).encode())
    for path in inputs:
        digest.update(hashlib.sha256(path.read_bytes()).digest())
    directory.mkdir(parents=True, exist_ok=True)
    binary = directory / ("imt-recursion-" + digest.hexdigest())
    if not binary.is_file():
        with (directory / "build.lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            if not binary.is_file():
                print("Building the pinned LeanVM prover for this checkout…", file=sys.stderr, flush=True)
                with tempfile.TemporaryDirectory(dir=directory) as scratch:
                    work = Path(scratch)
                    build(work / "src", checkout, work / "target", masked)
                    (work / "target/release/imt-recursion").replace(binary)
    print(binary)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checkout", type=Path, help="pinned Git object source, such as ../leanVM")
    parser.add_argument("--masked-guest",type=Path,help="trusted subroutine generated by cargo masked-oracle build-guest")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--work", type=Path, help="fresh directory for the specialized prover")
    mode.add_argument("--cached", type=Path, help="reuse the specialized CLI executable across runs")
    args = parser.parse_args()
    if args.cached:
        cached(args.cached.resolve(), args.checkout, args.masked_guest)
    else:
        build(args.work.resolve(), args.checkout, masked=args.masked_guest)


if __name__ == "__main__":
    main()
