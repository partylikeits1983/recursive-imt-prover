# Experimental binary outer prover

Final, non-hiding proof backend. Uses the official Plonky3
[PR #2582](https://github.com/Plonky3/Plonky3/pull/2582) at
`708900d7a730d6ce4d5421d43e2193f2301920fa` (package version 0.8.0).
This is an open experimental upstream change, not a released recursion backend.
Two narrow upstream prover patches avoid retaining all temporary bus blocks and
restrict deferred opening sweeps to their nonzero support. Their proof equations
and verifier are unchanged; see [sumcheck](../../vendor/p3-sumcheck/LOCAL_CHANGES.md)
and [multi-STARK](../../vendor/p3-multi-stark/LOCAL_CHANGES.md).

The application and native circuit compiler stay on 0.9.0-rc.2. `air.rs` imports
that compiler's actual symbolic constraints, public values, bus declarations and
preprocessing. Both versions use the same Poly64 representation; tests compare
field multiplication and Keccak port outputs. There is no non-native arithmetic
or Boolean verifier-result input.

Local adaptations:

- `keccak.rs`: upstream Flock Keccak-f1600 gadget with 16-bit ports, including
  the native circuit's byte-swapped digest limbs. Port padding constrains the
  high bits. Both full permutation boundaries join the native Keccak bus.
- `mixed.rs`: upstream mixed dense/Boolean trace adapter, extended to forward
  Flock weighted claims **only** on unchanged Boolean columns. Dense coordinates
  use linear expansion and recombination; WHIR and Flock are unchanged.
- `encoding.rs`: trusted per-column coordinate widths. Keccak bridge values use
  16 coordinates; each preprocessing column uses the highest bit present in the
  fixed trusted table. Zero-width columns reconstruct the constant zero; the
  prover rejects any nonzero value in them. An entirely zero table has one
  dummy committed bit column. Unbounded arithmetic values retain
  all 64 coordinates. The prover rejects values outside the declared subspace instead
  of truncating them, and the verifier recombines exactly the declared bits.
  Widths are bound into the verifier identity. They never come from the witness.
- `fanout.rs` partitions whole witness-ID groups into 1-, 16- and 64-coordinate
  tables. Bounds come from constants, Boolean constraints, Keccak ports and a
  forward pass over actual polynomial-coordinate arithmetic. Unknown values
  retain 64 coordinates; hint execution never supplies a bound. Each original
  witness-bus occurrence appears exactly once. Each partition has an inactive
  leading zero row, linked to the zero-sentinel group when present.
- `gates.rs` groups independent arithmetic rows by their per-column bounds.
  All selectors, constants and witness IDs remain fixed and unchanged. The
  grouping retains every live row; padding has inactive selectors. A group is
  split once when that saves at least 25% of its padded cells. Groups are merged
  to reduce opening work, allowing at most 10% more gate coordinates than the
  initial fine partition. Compact
  byte storage for fixed preprocessing expands losslessly before proving.
  Preprocessing columns that are identically zero are substituted with zero;
  bus entries are removed only when their activation is provably zero from
  that fixed preprocessing. No witness-dependent entry is pruned.
- The native fanout table's successor read is an extra current-row column.
  A product bus matches `(next row address, next value)` to the following row's
  `(row address, value)`; the final value repeats locally. Public row addresses
  are periodic polynomials with closed-form evaluations. Each partition has a
  distinct successor bus, preventing cross-table cancellation. This avoids materializing
  next-row ring-switch tensors. The extra bus arguments are included in the
  security report; successor values are authenticated by those arguments.
- Public-copy tables are eliminated by exact substitution. Import first checks
  that every original main column has the equation `main[i] = public[i]`, with
  no preprocessing or successor reads. All imported bus fields then read the
  supplied public values directly. One constrained-zero placeholder column
  remains for the PCS table interface. This removes redundant public openings
  while preserving their wiring checks; altered public values still unbalance
  the witness bus.
- The transcript seed binds imported constraints, bus declarations, dimensions,
  preprocessing, periodic definitions, Flock circuit, protocol and caller domain.

The optional `Prepared::new_checkpoint` path encodes one aggregate containing a
Plonky3 arithmetic multi-STARK and a Keccak GKR subargument, linked through
authenticated port openings. The final verifier requires no child proofs.
`Prepared::new` retains Flock as the default. Both load an
authenticated compact verifier-only key. See the snapshot trust model below.

The coordinate map is injective on each declared binary linear subspace. Shorter
widths restrict the witness domain and preserve every original AIR equation;
they do not add a probabilistic test or a new soundness-error term. The opening
tests compare reconstructed evaluations with direct dense multilinear evaluation,
including successor rows, and reject high-bit values and altered coordinates.
This is a local encoding argument, not a full proof-system security theorem.
Tests check exact occurrence preservation, actual AIR equations and product-bus
multisets; they reject a changed copy, a nonzero zero sentinel and a successor
swap across partitions. The checkpoint aggregate uses protocol v7 / backend
identity v1; Flock retains protocol v6 / backend identity v8. Both export verifier
snapshot v2, rejecting older key snapshots. Child proof formats and security
parameters are unchanged.

Arithmetic partitions omit preprocessing columns that are identically zero.
The trusted compiler records the original-to-compact column map, substitutes
zero into every affected constraint and bus expression, and serializes only the
remaining columns into the preprocessing commitment. Tests compare every retained
cell and omitted zero against the original native table, then check the imported
constraints and complete bus multisets. No witness-dependent column is removed.

Parameters are fixed: Johnson, 152 PCS bits, 16-bit grinding ceiling, rate 1/2,
folding factor 4, Poly192 challenges, Keccak-256, and a required 144-bit conditional
algebraic floor. The 128-bit generic classical hash work factor is reported
separately. These figures do not establish ROM/knowledge/recursive composition,
post-quantum security or child privacy.

Adapted upstream code retains its MIT / Apache-2.0 licenses beside this file.

Product-bus leaves are regenerated in bounded chunks through the pinned
[GKR](../../vendor/p3-gkr/LOCAL_CHANGES.md),
[bus](../../vendor/p3-bus/LOCAL_CHANGES.md) and
[multi-STARK](../../vendor/p3-multi-stark/LOCAL_CHANGES.md) patches. Complete-proof
and transcript differential tests preserve the original verifier relation.

## Trusted verifier snapshots

`Prepared::export_verifier` exports a compact verifier-only snapshot. It contains
the complete ordered symbolic constraints, bus declarations, table shapes,
coordinate encodings, preprocessing commitment and authority transcript seed.
The fixed Keccak circuit is reconstructed from this pinned implementation.
Original proving tables, child proofs and witnesses are absent.

`Verifier::from_bytes` checks a domain-separated Keccak-256 digest against an
independently trusted digest **before** deserialization, then checks the supplied
configuration binding and authority identity. Loading rechecks the existing
144-bit conditional algebraic floor. The snapshot has a 4 MiB byte limit.
The snapshot and its digest must not both be accepted from an untrusted prover.
The demo provisions `verifier.key` and its digest in `trusted.json` locally;
independent verification treats that JSON as trusted verifier data.

The symbolic list already includes bus activation Booleanity constraints, in
their original positions. Bus replay emits the recorded declarations without
adding those checks a second time. Tests compare the complete ordered expression
trees (including cached degrees) and bus declarations with the original AIR,
then verify an actual proof through both implementations. Negative cases cover
changed public inputs, key bytes, key digest, configuration binding, authority
identity and proof bytes. This preserves the original relation; it is not a
new proof system or a substitute for child privacy analysis.

## Linked Keccak GKR

`checkpoint_keccak::CommittedBatch` proves an ordered batch of Keccak-f
permutations using cubic sumcheck and the existing additive-WHIR PCS. It commits
only the padded input/output states, recomputes intermediate rounds, and
authenticates both boundary claims. The standalone component remains useful for
permutation benchmarks. Its raw reduction API requires its caller to authenticate
both boundaries.
See the [protocol, conditional bound and benchmark command](../../docs/binary-veil.md#committed-keccak-gkr-component).

`Prepared::new_checkpoint` commits those boundaries before the arithmetic
commitment/challenges. The arithmetic proof treats the 232 native ports as an
ordinary table with 16-bit coordinates. After complete arithmetic verification,
the verifier uses its authenticated port readings and row point. A degree-two
sumcheck links a fresh random combination of all ports to four ordinary boundary
PCS openings, shared with the permutation argument. Raw and byte-swapped limbs
are included. The link cannot be replaced by a native verifier Boolean or by two
unrelated valid proofs. `Verifier` replays the same linked checks from a v2 key.

The conditional ledger charges the link over the product of both PCS candidate
sets and combines it with the arithmetic and Keccak budgets. The complete
construction still needs an independent soundness/Fiat–Shamir review; it makes no
additional child privacy claim.
