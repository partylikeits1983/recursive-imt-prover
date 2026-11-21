"""Measure the hash and modular arithmetic workload of a verifier transaction."""

from replay import rpc

# Geth-style opcode tracer supported by Osaka Anvil. Count only the verifier call,
# including nested modules. Each padded Keccak-256 preimage takes floor(length/136)+1 permutations.
OPERATION_TRACER = """
{
  counts: {},
  step: function(log, db) {
    var op = log.op.toString();
    if (op !== "KECCAK256" && op !== "MULMOD" && op !== "ADDMOD") return;
    var addr = toHex(log.contract.getAddress());
    var c = this.counts[addr] || (this.counts[addr] = [0, 0, 0, 0]);
    if (op === "KECCAK256") {
      c[0]++;
      c[1] += 1 + Math.floor(Number(log.stack.peek(1).toString()) / 136);
    } else if (op === "MULMOD") c[2]++;
    else c[3]++;
  },
  fault: function() {},
  result: function() { return this.counts; }
}
"""


def report(url, tx_hash, labels):
    counts = rpc(
        url, "debug_traceTransaction", [tx_hash, {"tracer": OPERATION_TRACER, "timeout": "20m"}], timeout=1200
    )
    for address, (hashes, permutations, products, sums) in counts.items():
        print(
            f"{labels.get(address.lower(), address)}: {hashes:,} hashes, {permutations:,} Keccak-f permutations, "
            f"{products:,} MULMOD, {sums:,} ADDMOD",
            flush=True,
        )


# Capture the preimage and the VM's result. The opcode after KECCAK256
# executes in the same frame and has its 256-bit result on the stack.
HASH_TRACER = """
{
  hashes: [], pending: false,
  step: function(log, db) {
    if (this.pending) {
      this.hashes[this.hashes.length - 1].push(log.stack.peek(0).toString(16));
      this.pending = false;
    }
    if (log.op.toString() !== "KECCAK256") return;
    var offset = Number(log.stack.peek(0).toString());
    var length = Number(log.stack.peek(1).toString());
    var data = length === 0 ? "0x" : toHex(log.memory.slice(offset, offset + length));
    this.hashes.push([toHex(log.contract.getAddress()), log.getPC(), data]);
    this.pending = true;
  },
  fault: function() {},
  result: function() { return this.hashes; }
}
"""


def export_hashes(url, tx_hash, output):
    import json
    from pathlib import Path

    rows = rpc(
        url, "debug_traceTransaction", [tx_hash, {"tracer": HASH_TRACER, "timeout": "20m"}], timeout=1200
    )
    permutations = 0
    for _, _, raw, result in rows:
        if not raw.startswith("0x") or len(raw) % 2 or not 0 <= int(result, 16) < 2**256:
            raise ValueError("Invalid Keccak trace record")
        permutations += (len(raw) - 2) // (2 * 136) + 1
    Path(output).write_text(json.dumps(rows, separators=(",", ":")))
    print(f"Exported {len(rows):,} Keccak inputs and results, {permutations:,} total permutations", flush=True)
