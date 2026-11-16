//! Fixed Plonky3 transition circuit. This diagnostic does NOT verify client
//! proofs and is deliberately not an authorization proof accepted by state.
use crate::{
    gadgets::poseidon::{Arithmetic, hash},
    primitives::{CTX, F, NODE},
    statement::{BATCH_FIELDS, BatchStatement},
    tree::AppendWitness,
};
use anyhow::{Result, ensure};
use p3_circuit::{Circuit, CircuitBuilder, ExprId, StatementExport};
use p3_circuit_prover::{
    BatchStarkProof, BatchStarkProver, ConstraintProfile, PreparedCircuitProver,
    batch_stark_prover::{StatementAirBuilder, StatementPreprocessor, StatementProver},
    common::{NpoAirBuilder, NpoPreprocessor},
    config::{self, KoalaBearConfig},
};
use p3_field::PrimeField32 as _;
use p3_field_outer::{Field, PrimeCharacteristicRing};
use p3_koala_bear_outer::KoalaBear as O;

pub type TransitionProof = BatchStarkProof<KoalaBearConfig>;
pub struct TransitionCircuit {
    pub circuit: Circuit<O>,
    pub schema: p3_circuit::StatementSchema,
    pub depth: u8,
}
pub fn convert(f: F) -> O {
    O::from_u32(f.as_canonical_u32())
}
impl Arithmetic for CircuitBuilder<O> {
    type V = ExprId;
    fn constant(&mut self, f: F) -> ExprId {
        self.alloc_const(convert(f), "app constant")
    }
    fn add(&mut self, a: ExprId, b: ExprId) -> ExprId {
        CircuitBuilder::add(self, a, b)
    }
    fn mul(&mut self, a: ExprId, b: ExprId) -> ExprId {
        CircuitBuilder::mul(self, a, b)
    }
}
// Connecting a Public directly to Const (or another Public) merges creators
// in the pinned lookup compiler. Keep public sources distinct using ALU rows.
// This is the exact equation a+1=c+1, with both sides constrained.
fn equal(b: &mut CircuitBuilder<O>, a: ExprId, c: ExprId) {
    let one = b.alloc_const(O::ONE, "equality shift");
    let left = b.add(a, one);
    let right = b.add(c, one);
    b.connect(left, right);
}
fn nonzero(b: &mut CircuitBuilder<O>, values: &[ExprId]) {
    let mut sum = ExprId::ZERO;
    for &v in values {
        let inv = b.alloc_private_input("private");
        let t = b.mul(v, inv);
        sum = b.add(sum, t);
    }
    let one = b.alloc_const(O::ONE, "one");
    b.connect(sum, one);
}
fn count(b: &mut CircuitBuilder<O>, limbs: &[ExprId]) -> Vec<ExprId> {
    let bits: Vec<_> = (0..33)
        .map(|_| {
            let t = b.alloc_private_input("private");
            b.assert_bool(t);
            t
        })
        .collect();
    for (i, &limb) in limbs.iter().enumerate() {
        let mut sum = ExprId::ZERO;
        for j in 0..16 {
            if let Some(&bit) = bits.get(i * 16 + j) {
                let c = b.alloc_const(O::from_u32(1 << j), "weight");
                let t = b.mul(bit, c);
                sum = b.add(sum, t);
            }
        }
        equal(b, sum, limb);
    }
    bits
}
fn increment(b: &mut CircuitBuilder<O>, bits: &[ExprId]) -> Vec<ExprId> {
    let mut carry = b.alloc_const(O::ONE, "increment");
    let two = b.alloc_const(O::TWO, "two");
    let mut out = Vec::new();
    for &bit in bits {
        let c = b.mul(bit, carry);
        let s = b.add(bit, carry);
        let twice = b.mul(two, c);
        out.push(b.sub(s, twice));
        carry = c;
    }
    b.assert_zero(carry);
    out
}
fn merkle(
    b: &mut CircuitBuilder<O>,
    mut v: Vec<ExprId>,
    bits: &[ExprId],
    path: &[Vec<ExprId>],
) -> Vec<ExprId> {
    for (&bit, sibling) in bits.iter().zip(path) {
        let mut args = Vec::new();
        let mut right = Vec::new();
        for i in 0..8 {
            args.push(b.select(bit, sibling[i], v[i]));
            right.push(b.select(bit, v[i], sibling[i]));
        }
        args.extend(right);
        v = hash(b, NODE, &args);
    }
    v
}
fn connect_digest(b: &mut CircuitBuilder<O>, a: &[ExprId], c: &[ExprId]) {
    for (&x, &y) in a.iter().zip(c) {
        equal(b, x, y);
    }
}
pub fn build_transition(depth: u8) -> Result<TransitionCircuit> {
    crate::primitives::check_depth(depth)?;
    let mut b = CircuitBuilder::<O>::new();
    let p = b.alloc_public_inputs(BATCH_FIELDS, "batch");
    let version = b.alloc_const(O::ONE, "version");
    equal(&mut b, p[0], version);
    let d = b.alloc_const(O::from_u8(depth), "depth");
    equal(&mut b, p[1], d);
    for (i, x) in CTX.fields().into_iter().enumerate() {
        let c = b.alloc_const(convert(x), "ctx");
        equal(&mut b, p[2 + i], c);
    }
    // Public offsets: old_root 10, old_count 18, history 21, child roots 53,
    // nullifiers 69, outputs 85, new root 101, new count 109.
    for child in 0..2 {
        let selectors: Vec<_> = (0..4).map(|_| b.alloc_private_input("private")).collect();
        b.assert_exactly_one(&selectors)?;
        for (j, &selector) in selectors.iter().enumerate() {
            for i in 0..8 {
                let diff = b.sub(p[53 + 8 * child + i], p[21 + 8 * j + i]);
                let t = b.mul(selector, diff);
                b.assert_zero(t);
            }
        }
    }
    let diffs: Vec<_> = (0..8).map(|i| b.sub(p[69 + i], p[77 + i])).collect();
    nonzero(&mut b, &diffs);
    nonzero(&mut b, &p[85..93]);
    nonzero(&mut b, &p[93..101]);
    let n = count(&mut b, &p[18..21]);
    let k = count(&mut b, &p[109..112]);
    let m = increment(&mut b, &n);
    let computed_k = increment(&mut b, &m);
    connect_digest(&mut b, &computed_k, &k);
    for &x in n[depth as usize..].iter().chain(&m[depth as usize..]) {
        b.assert_zero(x);
    }
    for &x in &k[depth as usize + 1..] {
        b.assert_zero(x);
    }
    for &x in &k[..depth as usize] {
        let t = b.mul(x, k[depth as usize]);
        b.assert_zero(t);
    }
    let paths: Vec<Vec<Vec<ExprId>>> = (0..2)
        .map(|_| {
            (0..depth)
                .map(|_| b.alloc_private_inputs(8, "append sibling"))
                .collect()
        })
        .collect();
    let empty = vec![ExprId::ZERO; 8];
    let old = merkle(&mut b, empty.clone(), &n, &paths[0]);
    connect_digest(&mut b, &old, &p[10..18]);
    let middle = merkle(&mut b, p[85..93].to_vec(), &n, &paths[0]);
    let check_middle = merkle(&mut b, empty, &m, &paths[1]);
    connect_digest(&mut b, &middle, &check_middle);
    let new = merkle(&mut b, p[93..101].to_vec(), &m, &paths[1]);
    connect_digest(&mut b, &new, &p[101..109]);
    let exports: Vec<_> = p.iter().copied().map(StatementExport::Base).collect();
    let schema = b.set_statement_exports::<O>(&exports)?;
    let circuit = b.build()?;
    Ok(TransitionCircuit {
        circuit,
        schema,
        depth,
    })
}
fn inverses(values: impl IntoIterator<Item = O>) -> Vec<O> {
    let mut found = false;
    values
        .into_iter()
        .map(|v| {
            if !found && v != O::ZERO {
                found = true;
                v.inverse()
            } else {
                O::ZERO
            }
        })
        .collect()
}
pub fn private_inputs(s: &BatchStatement, w: &AppendWitness) -> Result<Vec<O>> {
    ensure!(
        w.paths.iter().all(|p| p.len() == s.depth as usize),
        "append path length"
    );
    let mut v = Vec::new();
    for root in s.child_roots {
        let index = s.allowed_roots.iter().position(|r| *r == root);
        for i in 0..4 {
            v.push(O::from_bool(index == Some(i)));
        }
    }
    v.extend(inverses((0..8).map(|i| {
        O::from_u32(s.nullifiers[0].0[i]) - O::from_u32(s.nullifiers[1].0[i])
    })));
    for cm in s.new_commitments {
        v.extend(inverses(cm.0.map(O::from_u32)));
    }
    for n in [s.old_leaf_count, s.new_leaf_count] {
        for i in 0..33 {
            v.push(O::from_bool((n >> i) & 1 != 0));
        }
    }
    for path in &w.paths {
        for d in path {
            v.extend(d.0.map(O::from_u32));
        }
    }
    Ok(v)
}
pub fn prepare(c: &TransitionCircuit) -> Result<PreparedCircuitProver<KoalaBearConfig>> {
    // Upstream FRI benchmark configuration: 100 queries, log blowup 1,
    // max log arity 3, batch PoW 10, query PoW 16. No composed claim here.
    let prep: Vec<Box<dyn NpoPreprocessor<O>>> =
        vec![Box::new(StatementPreprocessor::new(c.schema.clone()))];
    let airs: Vec<Box<dyn NpoAirBuilder<KoalaBearConfig, 1>>> =
        vec![Box::new(StatementAirBuilder::<1>::new(c.schema.clone()))];
    let mut prover = BatchStarkProver::new(config::koala_bear());
    prover.register_table_prover(Box::new(StatementProver::<1>::new(c.schema.clone())));
    Ok(prover.prepare_circuit::<O, 1>(&c.circuit, &prep, &airs, ConstraintProfile::Standard)?)
}
pub fn prove_transition(
    c: &TransitionCircuit,
    prepared: &PreparedCircuitProver<KoalaBearConfig>,
    s: &BatchStatement,
    w: &AppendWitness,
) -> Result<TransitionProof> {
    s.validate_encoding()?;
    ensure!(s.depth == c.depth, "depth mismatch");
    let mut runner = c.circuit.runner();
    runner.set_public_inputs(&s.fields().into_iter().map(convert).collect::<Vec<_>>())?;
    runner.set_private_inputs(&private_inputs(s, w)?)?;
    let traces = runner.run()?;
    Ok(prepared.prove(&traces)?)
}
/// Deliberately unconditional until ALL client-verifier checks are constrained.
/// Do not replace this with a native verification result or a transition proof.
pub fn prove_batch(
    _children: [&crate::client::Proof; 2],
    _statement: &BatchStatement,
    _append: &AppendWitness,
) -> Result<Vec<u8>> {
    anyhow::bail!(
        "INCOMPLETE: full-ZK Spartan/SPARK/hiding-WHIR recursive verifier is not implemented; no authorization proof was produced"
    )
}
