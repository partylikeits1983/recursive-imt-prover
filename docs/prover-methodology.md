# How the record prover and its recursive circuits work

Given an ordered list of public record statements, the final verifier checks one
proof that **every statement in that list has a valid private opening and
membership path**. Two trees appear along the way. A depth-32 incremental
Merkle tree (IMT) authenticates a record inside a child proof. A second,
balanced tree aggregates child proofs and binds the order of their public
statements. Children can refer to different IMT roots.

| Stage | What the prover receives | What the proof binds publicly |
| --- | --- | --- |
| Record child | Two private record openings, one shared quantity, a leaf index and 32 siblings | An IMT root, an input tag and an output commitment |
| First aggregation | Two masked child proofs and their public statements | An ordered pair digest, count 2, left/right roles and the carried merge authority |
| Recursive merge | Two aggregate proofs and the statements they cover | An ordered subtree digest, doubled count, left/right roles and the same merge authority |

The child witness stays with the client. The aggregator publishes the ordered
statements alongside the final proof. This walkthrough follows the recursive
path selected by `cargo prove`. [Tree driver](../src/bin/tree-demo.rs)

## 1. Define what one child must prove

Write $K$ for Keccak-256 and $\parallel$ for byte concatenation. The strings in
the table are literal ASCII bytes. Each digest, label and nonce is exactly
32 bytes. The quantity $q$ is an unsigned 64-bit integer.

| Function | Bytes passed to $K$ |
| --- | --- |
| Record commitment $C(L,n,q)$ | `IMT-RECORD-OPEN1` $\parallel L \parallel n \parallel \mathrm{LE64}(q)$ |
| Input tag $T(n)$ | `IMT-RECORD-USED1` $\parallel n$ |
| IMT parent $P(a,b)$ | `IMT-KECCAK-NODE1` $\parallel a \parallel b$ |

The public statement is $S=(R,T_{\rm in},C_{\rm out})$, serialized in that
order as 96 bytes. The witness consists of the input and output labels and
nonces $(L_i,n_i,L_o,n_o)$, the single quantity $q$, a 32-bit index $k$, and
sibling digests $s_0,\ldots,s_{31}$ in leaf-to-root order.

Start with $h_0=C(L_i,n_i,q)$. At level $j$, let $b_j$ be bit $j$ of $k$,
counting from the least significant bit. Compute

$$
h_{j+1} =
\begin{cases}
P(h_j,s_j) & b_j=0,\\
P(s_j,h_j) & b_j=1.
\end{cases}
$$

The verifier's relation requires all three equalities

$$
h_{32}=R,\qquad T(n_i)=T_{\rm in},\qquad C(L_o,n_o,q)=C_{\rm out}.
$$

The same $q$ occurs in both commitments, so a replacement preserves the
quantity. The tag depends only on the input nonce, so reusing that nonce
repeats the public tag even across different roots. The application decides
which roots it accepts, checks for previously used tags and appends accepted
outputs. The public statement contains no post-update root. [Record encoding](../src/binary/tree.rs) · [Statement and witness types](../src/binary/relation.rs)

## 2. Turn the child computation into row constraints

The client builds a trace, a matrix whose rows describe successive states.
An algebraic intermediate representation (AIR) specifies equations over a
row, its successor and the public inputs. Here the base field is
$F=\mathrm{GF}(2^{64})$ (`Poly64`). Its addition is XOR. A byte or a
64-bit word is encoded using its bits as polynomial-basis coordinates.

Each of the 35 hash preimages fits one 136-byte rate block. The trace uses
Keccak's `0x01` delimiter, the final `0x80` padding bit and one full
24-round Keccak-f[1600] permutation per hash. Each permutation occupies 25
rows, including its boundary states.

| Zero-based rows | Computation | What ties it to the rest of the witness |
| --- | --- | --- |
| 0–24 | Input record commitment | The first state contains the input nonce and quantity. The digest feeds the path. |
| 25–824 | 32 IMT parent hashes | A Boolean direction routes the previous digest into the left or right input. The last digest equals the public root. |
| 825–849 | Input tag | Its nonce matches the input record's nonce. Its digest equals the public tag. |
| 850–874 | Output record commitment | Its quantity matches the input record's quantity. Its digest equals the public output commitment. |
| 875–1023 | Padding to a power of two | Fixed preprocessing determines the flags on these rows. |

At a path link, let $v$ be one bit of the previous digest and $\ell,r$ the
corresponding bits in the next hash's left and right slots. The AIR enforces
$b(b-1)=0$ and $\ell+b(\ell+r)=v$. Substituting $b=0$ gives $\ell=v$.
Substituting $b=1$ gives $r=v$.

Four private 64-bit columns carry the input nonce and a fifth carries $q$.
Transition constraints keep them constant. At the designated hash inputs,
the AIR packs 64 Boolean state bits and equates the result to the
corresponding column. This is what prevents combining a valid membership
path for one record with the tag or quantity of another. Fixed preprocessing
also pins the domain tags, sponge padding, round selectors and digest-check
rows. [Membership trace and AIR](../src/binary/veil/membership_air.rs)

## 3. Prove the child AIR while masking the witness

1. **Commit to the trace.** The client groups 128 trace columns at a time.
   It places their row values in aligned coefficient blocks, fills earlier
   coefficients with fresh randomness, adds an independent random auxiliary
   column, encodes the vectors on a binary additive domain and commits to
   the encoded rows with Keccak. The public statement, trace root, circuit
   identity and parameters bind the child transcript.
2. **Commit to message masks.** Before the online challenges, the client
   commits to a fresh vector of field masks. For a private algebraic message
   $m_i$ the transmitted value is $y_i=m_i+\mu_i$. Both parties derive the
   same Fiat–Shamir challenges by hashing the prescribed transcript. The
   extension field $E=\mathrm{GF}(2^{192})$ (`Poly192`) supplies those
   algebraic challenges.
3. **Reduce all row checks to one point.** Identify the 1,024 rows with
   $x\in\{0,1\}^{10}$. Let $C_\alpha(x)$ combine the AIR residuals in
   their fixed order by Horner evaluation at challenge $\alpha$. A valid
   trace has zero residual on every row. The verifier tests the identity

   $$
   \sum_{x\in\{0,1\}^{10}}\operatorname{eq}(\tau,x)\, C_\alpha(x)=0,
   \qquad
   \operatorname{eq}(u,v)=\prod_j\big((1-u_j)(1-v_j)+u_jv_j\big)
   $$

   for a transcript-derived $\tau$. Sumcheck eliminates one row coordinate
   per round. If the running claim is $s$, the round polynomial $g$ must
   satisfy $g(0)+g(1)=s$. A fresh challenge $r$ sets the next claim to
   $g(r)$. In the child these checks run through the masked transcript.
4. **Authenticate the endpoint.** At the final point, the verifier needs
   actual trace column evaluations. For a column $W$ its current value is
   the multilinear extension
   $\widetilde W(r)=\sum_x\operatorname{eq}(r,x)W(x)$. The successor view
   uses the next row's values and repeats the last row at the boundary.
   The prover supplies masked claims for both views. A random combination
   including the auxiliary column goes into WHIR. A functional-opening
   sumcheck ties the evaluations and queried codeword rows to that opening.
   The verifier derives the fixed preprocessing evaluations itself.
5. **Check the hidden arithmetic.** The verifier replays the AIR endpoint
   and the opening checks as linear and multiplication constraints on the
   hidden messages. The child proof establishes that the transmitted values
   admit openings to the committed masks satisfying those constraints. The
   client sends the trace-oracle root, masking proof and stacked opening to
   the aggregator together with $S$.

The masking construction adapts VEIL to these binary fields. A formal
zero-knowledge argument for the complete child transcript remains open.
The aggregate proofs are non-ZK. [Child prover and replay](../src/binary/veil/child.rs) · [Message masking](../src/binary/veil/compiler.rs) · [Trace openings](../src/binary/veil/stacked_oracle.rs) · [VEIL paper](https://eprint.iacr.org/2026/683)

## 4. Verify two children and bind their order

For one public child statement define its aggregation-tree leaf as
$D(S)=(K(\texttt{IMT-AGG-LEAF-V3}\parallel R\parallel T_{\rm in}\parallel C_{\rm out}),1)$.
For two nodes $a=(d_a,n)$ and $b=(d_b,n)$ with equal counts, define

$$
M(a,b)=\big(
K(\texttt{IMT-AGG-NODE-V2}\parallel d_a\parallel\mathrm{u8}(n)
  \parallel d_b\parallel\mathrm{u8}(n)),\,2n
\big).
$$

Each count in the hash preimage occupies **one byte**, immediately after its
own digest. The parent count $2n$ is ordinary integer doubling. The circuit
enforces a one-hot binary representation of the input count and shifts the
selected bit up one position. Allowed input counts are $1,2,4,8,16,32$.

The first parent runs two copies of the child-verifier circuit under one fixed
child authority. Each copy receives one child proof, its 96 statement bytes
and the sibling digest as private inputs. It replays the child's verification,
hashes its own statement, places the two leaf digests according to its public
role (0 for left, 1 for right), and constrains the result to the public parent
digest and count 2. Both copies must reach the same parent. Supplying a
conflicting sibling while preserving that digest would require a Keccak
collision. [Pair circuit](../src/binary/veil/aggregate.rs) · [Digest and count gadgets](../src/binary/aggregation_tree.rs)

## 5. Prove the parent verifier circuit

The following procedure proves both first aggregations and higher merges.
Its witness is the execution of the appropriate verifier circuit. Keccak is
expensive here because verifying a child or an aggregate proof itself
requires many transcript and Merkle hashes.

1. **Commit the arithmetic and the Keccak boundaries together.** The prover
   executes the two verifier instances, records their gate and wiring tables,
   and gathers the 1,600-bit input and output of every Keccak permutation.
   Call the two boundary tables $I$ and $O$. Boolean columns use packed bits.
   Arithmetic columns use the binary coordinates specified by the trusted
   layout. One main commitment covers the arithmetic witness, $I$ and $O$.
   For example, if $W$ is an arithmetic word with bit-coordinate columns
   $W_j$ and basis elements $\beta_j$, its evaluation is reconstructed as
   $\widetilde W(r)=\sum_j\beta_j\widetilde W_j(r)$. This follows from
   linearity of multilinear evaluation and explains how one commitment can
   serve both kinds of claim. Fixed preprocessing has its own commitment
   bound to the verifier key. [Coordinate encoding and reconstruction](../crates/flock-backend/src/mixed.rs)
2. **Prove gates and wiring.** The arithmetic AIR checks each gate equation.
   A FLOCK-style product bus checks that values agree across tables. For
   example, a wire identifier and value emitted by one table must match the
   identifier and value consumed elsewhere, with matching multiplicities.
   The bus compresses tuples using transcript challenges and compares products
   for the two multisets. Its terminal claims join the arithmetic zerocheck.
   This produces evaluations of the circuit's Keccak ports at a random point.
   [Product bus](../vendor/p3-bus/README.md)
3. **Prove the Keccak permutations.** A layered sumcheck argument (GKR)
   starts from a random evaluation of $O$ and works backward through all
   24 rounds to a claim about $I$. Keccak's $\theta,\rho,\pi$ steps are
   linear over bits, and $\iota$ adds a public round constant. The nonlinear
   step $\chi$ maps three neighboring bits to $a+(1+b)c$. The prover groups
   the same bit position across **16 independent permutations**. Fixed
   binary-linear maps $e$ (encode) and $p$ (project) satisfy

   $$
   p\big(e(u)e(v)\big)=(u_0v_0,\ldots,u_{15}v_{15}),
   \qquad u,v\in\{0,1\}^{16}.
   $$

   The encoded operands have polynomial degree at most 23. One carry-less
   product has degree at most 46 and recovers all 16 bitwise ANDs by
   projection. For each round the prover sends 47 weighted coefficients.
   The verifier checks their projection against the round's output claim,
   absorbs the coefficients, then samples a Poly192 evaluation point. A
   degree-three sumcheck ties that evaluation to the preceding layer. The
   live parent uses a six-round checkpoint stride to recompute intermediate
   states during proving. [Packed chi reduction](../crates/flock-backend/src/checkpoint_keccak/packed/reduction.rs)
4. **Tie the circuit ports to those same permutations.** The arithmetic
   proof uses packed limbs for the Keccak call inputs and outputs. The
   verifier reconstructs a random linear combination of those limbs from
   the boundary bits. At the final link point $z$, with side selector $s$,
   the boundary value is $(1-s)\widetilde I(z)+s\widetilde O(z)$. The link
   sumcheck compares its weighted value with the arithmetic port claim.
   This binds each side of the argument to the computation the other side
   used. [Port layout](../crates/flock-backend/src/checkpoint_keccak/ports.rs) · [Boundary authentication](../crates/flock-backend/src/checkpoint_keccak/linked.rs)
5. **Authenticate the joint opening.** The Keccak reduction asks for $I$ at
   the permutation input endpoint, $O$ at the initial output point, and both
   at the common port-link point. The arithmetic
   evaluations and all four boundary evaluations are authenticated in **one
   main WHIR opening proof**. WHIR reduces evaluation claims against a
   Reed–Solomon encoding. Fixing a multilinear variable at challenge $r$
   folds two entries $u,v$ to $(1-r)u+rv$. The prover commits to smaller
   encoded tables as the rounds proceed. The verifier derives query positions
   from the transcript, authenticates the queried entries with Merkle paths
   and checks their consistency with the folds and the final polynomial.
   It also checks the separate preprocessing opening and recomputes the bridge
   point and limb values from the verified arithmetic claims. Acceptance
   requires the output, input and port-link endpoint equations all to hold.
   [Joint prover and verifier](../crates/flock-backend/src/checkpoint.rs) · [WHIR paper](https://eprint.iacr.org/2024/1586)

## 6. Merge recursively using one merge key

The merge circuit verifies two aggregate proofs and applies the same $M$ rule
to their subtree statements. Each of its two verifier instances receives
$(d_{\rm parent},n_{\rm parent},\mathrm{role},A)$ as public inputs.
The 64-byte authority $A$ contains a 32-byte transcript identity followed
by a 32-byte preprocessing commitment. Each instance checks its input proof
under the authority selected by the authenticated input count.

| Leaves covered by an input proof | Verifier authority selected inside the merge |
| --- | --- |
| 2 | The pinned first-aggregation authority |
| 4, 8, 16 or 32 | The carried merge authority $A$ |

Each input proof must carry the same $A$ as the parent. First aggregation
allows the carried value to be supplied so its key can be prepared before
the merge key exists. Final verification fixes $A$ from the trusted merge
key. Counts halve on every descent through a merge, so this chain terminates
at actual child verifications. [Cyclic merge circuit](../src/binary/aggregation_tree/cyclic.rs) · [Authority encoding](../crates/flock-backend/src/verifier/aggregate.rs)

**Four-child example.** Given $S_0,S_1,S_2,S_3$, the two first parents prove
$A_{01}=M(D(S_0),D(S_1))$ and $A_{23}=M(D(S_2),D(S_3))$. Their counts
are both 2. A merge verifies both pair proofs under the pinned authority and
proves $M(A_{01},A_{23})$, with count 4. Swapping $S_1$ and $S_2$ changes
the inputs to both pair hashes. For 64 children, the same construction uses
32 first parents and $16+8+4+2+1=31$ higher merges. All five higher levels
use one merge key.

## 7. Verify the published bundle

1. Obtain the expected protocol, key digest and verifier identity from an
   independently trusted source. The demo stores these expectations in
   `trusted.json`. Authenticate `verifier.key` against them and derive $A$.
2. Read the ordered records from `statement.json`. Recompute each $D(S_i)$,
   then apply $M$ to adjacent pairs until one $(d,n)$ remains. The tree CLI
   accepts 4, 8, 16, 32 or 64 children.
3. Read `aggregate.proof` and verify it against $(d,n,0,A)$ and $(d,n,1,A)$
   as the two public input blocks. This checks the recursive claim for the
   supplied order. The final verifier needs only the root proof, the public
   list and the trusted verifier data.

To see the four-child example end to end, run these commands from the
repository root with a fresh output directory. The second command starts
a verifier that reads the saved bundle.

```sh
cargo prove -n 4 --keep --out run/methodology-four
cargo prove --verify --out run/methodology-four
```

The implementation uses Johnson-bound WHIR parameters. The child code rate is
$1/16$, and the recursive main and preprocessing rates are both $1/2$. The
project targets 128-bit classical security. End-to-end soundness accounting
and a joint privacy proof for the masked child remain open. [Fresh-process verifier](../src/bin/tree-demo.rs) · [Trust assumptions and security accounting](binary-security.md)
