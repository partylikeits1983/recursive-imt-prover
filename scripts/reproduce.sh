#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
export RAYON_NUM_THREADS="${RAYON_NUM_THREADS:-4}"
cargo build --locked --release --bins
cargo test --locked --release
run_parent=$(mktemp -d "${TMPDIR:-/tmp}/recursive-imt-poc.XXXXXX")
target/release/demo --depth 8 --diagnostic-transition-only --out "$run_parent/same-root"
target/release/demo --depth 8 --historical-roots --diagnostic-transition-only --out "$run_parent/historical"
cp "$run_parent/same-root/state.json" "$run_parent/state-before.json"
if target/release/verify --state "$run_parent/same-root/state.json" \
    --statement "$run_parent/same-root/statement.json" \
    --proof "$run_parent/same-root/transition-diagnostic.bin"; then
    echo 'ERROR: incomplete authorization verifier accepted' >&2
    exit 1
fi
cmp "$run_parent/state-before.json" "$run_parent/same-root/state.json"
echo "Diagnostics passed; authorization remains disabled. Artifacts: $run_parent"
