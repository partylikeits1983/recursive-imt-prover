# Experimental Flock outer prover

Final, non-hiding proof backend. Uses the official Plonky3
[PR #2582](https://github.com/Plonky3/Plonky3/pull/2582) at
`708900d7a730d6ce4d5421d43e2193f2301920fa` (package version 0.8.0).
This is an open experimental upstream change, not a released recursion backend.

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
  use upstream expansion and recombination; WHIR and Flock are unchanged.
- The native fanout table's successor read is an extra current-row column.
  A product bus matches `(next row address, next value)` to the following row's
  `(row address, value)`; the final value repeats locally. Public row addresses
  are periodic polynomials with closed-form evaluations. This avoids materializing
  next-row ring-switch tensors. It adds a bus argument, included in the security
  report, rather than trusting the shifted witness.
- The transcript seed binds imported constraints, bus declarations, dimensions,
  preprocessing, periodic definitions, Flock circuit, protocol and caller domain.

The proof is one Plonky3 multi-STARK containing Flock, product-bus, sumcheck and
WHIR subarguments. The final verifier requires no child proofs. It reconstructs
trusted setup from the fixed circuit; serialization of a compact verifier-only
key is still an optimization to implement.

Parameters are fixed: Johnson, 152 PCS bits, 16-bit grinding ceiling, rate 1/2,
folding factor 4, Poly192 challenges, Keccak-256, and a required 144-bit conditional
algebraic floor. The 128-bit generic classical hash work factor is reported
separately. These figures do not establish ROM/knowledge/recursive composition,
post-quantum security or child privacy.

Adapted upstream code retains its MIT / Apache-2.0 licenses beside this file.
