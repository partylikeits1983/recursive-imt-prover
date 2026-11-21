//! Compile the native prefix-WHIR verification schedule into LeanVM instructions.
//! Only proof messages and authentication paths enter as advice.
use super::guest::Bytes;
use anyhow::{Result, ensure};
use p3_binary_field::{Poly64, Poly192, TowerLevel};
use recursive_imt_prover::binary::veil::child::checkpoint::{
    BinaryWhirPlan, WhirFoldShape, WhirOracleSite,
};
use std::fmt::Write;
use verifier::E;

pub type Plan = BinaryWhirPlan<Poly64, Poly192>;
pub const DOMAIN: &[u8; 16] = b"IMT-WHIR-CHK--01";
const TRANSCRIPT: &[u8] = b"imt-veil-whir-v1/transcript\0";
const LEAF: &[u8] = b"imt-veil-whir-v1/leaf\0";
const NODE: &[u8] = b"imt-veil-whir-v1/node\0";

pub struct Stream {
    name: String,
    width: usize,
    count: usize,
    digest: bool,
    sibling: bool,
}

pub fn advice(schema: &[Stream], mut raw: &[Poly64]) -> Result<Vec<(String, Vec<Vec<E>>)>> {
    let mut streams = Vec::new();
    for s in schema {
        let len = s
            .width
            .checked_mul(s.count)
            .ok_or_else(|| anyhow::anyhow!("WHIR stream overflow"))?;
        ensure!(raw.len() >= len, "truncated WHIR stream {}", s.name);
        let (values, rest) = raw.split_at(len);
        raw = rest;
        let mut entries = Vec::with_capacity(s.count);
        for row in values.chunks_exact(s.width) {
            let entry = if s.digest {
                let mut words = Vec::with_capacity(4);
                // The node domain displaces every level by three u16s. Rotate
                // siblings before transport so only their two edge fragments
                // need to be split in the guest.
                let packed;
                let row = if s.sibling {
                    packed = [0, 13, 14, 15, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12].map(|j| row[j]);
                    &packed[..]
                } else {
                    row
                };
                for chunk in row.as_chunks::<4>().0 {
                    let mut word = 0;
                    for (i, f) in chunk.iter().enumerate() {
                        word |= u64::from(u16::try_from(f.to_repr())?) << (16 * i);
                    }
                    words.push(E::new(word, 0));
                }
                words
            } else {
                row.iter().map(|f| E::new(f.to_repr(), 0)).collect()
            };
            entries.push(entry);
        }
        streams.push((s.name.clone(), entries));
    }
    ensure!(raw.is_empty(), "trailing WHIR advice");
    Ok(streams)
}

#[derive(Default)]
struct Emitter {
    src: String,
    helpers: String,
    schema: Vec<Stream>,
    observations: Vec<Observation>,
    id: usize,
    hash: usize,
    remaining: usize,
}
enum Observation {
    Fixed(Vec<u8>),
    Lanes(Vec<String>),
}

impl Emitter {
    fn line(&mut self, line: impl AsRef<str>) {
        writeln!(self.src, "    {}", line.as_ref()).unwrap();
    }
    fn name(&mut self, prefix: &str) -> String {
        self.id += 1;
        format!("pcs_{prefix}{}", self.id)
    }
    fn assign(&mut self, expr: impl AsRef<str>) -> String {
        let name = self.name("v");
        self.line(format!("{name} = {}", expr.as_ref()));
        name
    }
    fn stream(&mut self, name: String, width: usize, count: usize, digest: bool) {
        self.schema.push(Stream {
            sibling: false,
            name,
            width,
            count,
            digest,
        });
    }
    fn read(&mut self, width: usize, digest: bool) -> String {
        let n = self.name("msg");
        let size = if digest { 4 } else { width };
        self.stream(n.clone(), width, 1, digest);
        self.line(format!("{n} = StackBuf({size})"));
        self.line(format!("hint_witness({n}, \"{n}\")"));
        for i in (0..size).step_by(2) {
            self.line(format!(
                "assert_in_k({n}[{i}], {n}[{}])",
                (i + 1).min(size - 1)
            ));
        }
        n
    }
    fn fields(&mut self, count: usize) -> Vec<String> {
        if count == 0 {
            return vec![];
        }
        let msg = self.read(3 * count, false);
        (0..count).map(|i| self.ext_at(&msg, 3 * i)).collect()
    }
    fn ext_at(&mut self, name: &str, offset: usize) -> String {
        self.assign(format!(
            "ext({name}[{offset}], {name}[{}], {name}[{}])",
            offset + 1,
            offset + 2
        ))
    }
    fn absorb(&mut self, o: Observation) {
        self.remaining = 0;
        self.observations.push(o);
    }
    fn seed(&mut self, seed: &[Poly64]) {
        let bytes = seed
            .iter()
            .flat_map(|f| f.to_repr().to_le_bytes())
            .collect::<Vec<_>>();
        if !bytes.is_empty() {
            self.absorb(Observation::Fixed(bytes))
        }
    }
    fn observe(&mut self, name: &str, n: usize) {
        self.absorb(Observation::Lanes(
            (0..n).map(|k| format!("{name}[{k}]")).collect(),
        ));
    }
    fn lane(&mut self) -> String {
        if self.remaining == 0 {
            let mut b = Bytes::default();
            b.literal(TRANSCRIPT);
            if self.hash != 0 {
                b.pcs_lanes((0..4).map(|k| format!("pcs_h{}l{k}", self.hash)));
            }
            for o in std::mem::take(&mut self.observations) {
                match o {
                    Observation::Fixed(bytes) => b.literal(&bytes),
                    Observation::Lanes(w) => b.pcs_lanes(w),
                }
            }
            self.hash += 1;
            let n = format!("pcs_h{}", self.hash);
            b.hash(&mut self.src, &n);
            self.line(format!("{n}l0, {n}l1 = limbs({n}[0])"));
            self.line(format!("{n}l2, {n}l3 = limbs({n}[1])"));
            self.remaining = 4;
        }
        self.remaining -= 1;
        self.assign(format!(
            "pcs_reverse_word(tabs, pcs_h{}l{})",
            self.hash, self.remaining
        ))
    }
    fn challenge(&mut self) -> String {
        let a = self.lane();
        let b = self.lane();
        let c = self.lane();
        self.assign(format!("ext({a}, {b}, {c})"))
    }
    fn pow(&mut self, w: String, bits: usize) {
        if bits == 0 {
            self.line(format!("assert {w} == 0"));
            return;
        }
        self.absorb(Observation::Lanes(vec![w]));
        let word = self.lane();
        self.line(format!("assert query_index({word}, {bits}) == 0"));
    }
    fn fold(
        &mut self,
        seed: &[Poly64],
        shape: &WhirFoldShape,
        all: &mut Vec<String>,
    ) -> Vec<String> {
        if shape.rounds == 0 {
            return vec![];
        }
        self.seed(seed);
        let messages = self.fields(2 * shape.rounds);
        let nonces = (shape.pow_bits != 0).then(|| self.read(shape.rounds, false));
        let mut r = Vec::new();
        for i in 0..shape.rounds {
            let (a, b) = (&messages[2 * i], &messages[2 * i + 1]);
            self.observe(a, 3);
            self.observe(b, 3);
            if let Some(w) = &nonces {
                self.pow(format!("{w}[{i}]"), shape.pow_bits);
            }
            let x = self.challenge();
            self.line(format!("pcs_claim = pcs_reduce(pcs_claim, {a}, {b}, {x})"));
            r.push(x);
        }
        all.extend_from_slice(&r);
        r
    }
    fn table(&mut self, mut v: Vec<String>, point: &[String], mle: bool) -> String {
        assert_eq!(v.len(), 1 << point.len());
        for r in point.iter().rev() {
            v = v
                .as_chunks::<2>()
                .0
                .iter()
                .map(|pair| {
                    let (a, b) = (&pair[0], &pair[1]);
                    let slope = if mle {
                        self.assign(format!("plus({a}, {b})"))
                    } else {
                        b.clone()
                    };
                    self.assign(format!("pcs_mac({slope}, {r}, {a})"))
                })
                .collect()
        }
        v.pop().unwrap()
    }
    fn eq(&mut self, a: &[String], b: &[String]) -> String {
        assert_eq!(a.len(), b.len());
        let mut v = "pcs_one".to_owned();
        for (x, y) in a.iter().zip(b) {
            let d = self.assign(format!("plus({x}, {y})"));
            let f = self.assign(format!("plus(pcs_one, {d})"));
            v = self.assign(format!("times({v}, {f})"));
        }
        v
    }
    fn ood(&mut self, answer: &str, variables: usize) -> Vec<String> {
        let mut z = self.challenge();
        let mut powers = vec![z.clone()];
        for _ in 1..variables {
            z = self.assign(format!("times({z}, {z})"));
            powers.push(z.clone())
        }
        powers.reverse();
        self.observe(answer, 3);
        powers
    }
}

impl Emitter {
    fn parent(&mut self) {
        let mut src = String::from(
            "def pcs_parent(tabs, d: StackBuf(2), s: StackBuf(4), side):\n    a0, a1 = limbs(d[0])\n    a2, a3 = limbs(d[1])\n    assert_in_k(s[0], s[1])\n    assert_in_k(s[2], s[3])\n",
        );
        let prefix = u128::from_le_bytes(NODE[..16].try_into().unwrap());
        let mut suffix = [0u8; 8];
        suffix[..6].copy_from_slice(&NODE[16..]);
        for k in 0..4 {
            writeln!(src, "    lo{k}, hi{k} = pcs_split(tabs, a{k}, 2)").unwrap();
        }
        src.push_str("    slo, shi = pcs_split(tabs, s[0], 2)\n");
        let shift = 1u64 << 48;
        let mut cur = vec![format!("{shift} * lo0")];
        cur.extend((1..4).map(|k| format!("{shift} * lo{k} + hi{}", k - 1)));
        cur.push("hi3".into());
        let siblings = [
            format!("{shift} * slo"),
            "s[1]".into(),
            "s[2]".into(),
            "s[3]".into(),
            "shi".into(),
        ];
        for (j, (a, b)) in cur.iter().zip(siblings).enumerate() {
            writeln!(src,"    c{j} = {a}\n    b{j} = {b}\n    swap{j} = side * (c{j} + b{j})\n    l{j} = c{j} + swap{j}\n    r{j} = b{j} + swap{j}").unwrap();
        }
        let suffix = u64::from_le_bytes(suffix);
        writeln!(src,"    y = 18446744073709551616\n    out = StackBuf(2)\n    keccak_cells([{prefix}, {suffix} + l0 + y * l1, l2 + y * l3, l4 + r0 + y * r1, r2 + y * r3, r4], out, len=86)\n    return out\n").unwrap();
        self.helpers.push_str(&src);
    }

    fn row_function(
        &mut self,
        i: usize,
        site: &WhirOracleSite,
        last: &[String],
        base: bool,
        terminal: bool,
    ) -> String {
        let name = format!("pcs_row_{i}");
        let mut f = Emitter::default();
        let arity = if base { 1 } else { 3 };
        let size = arity * site.width;
        let count = site.queries.num_queries();
        let height = site.queries.index_bits();
        assert_eq!(height, site.path_len);
        self.stream(name.clone(), size, count, false);
        if height > 0 {
            self.stream(format!("pcs_path_{i}"), 16, count * height, true);
            self.schema.last_mut().unwrap().sibling = true;
        }
        let params = (0..last.len())
            .map(|j| format!(", r{j}: StackBuf(3)"))
            .collect::<String>();
        let final_size = 1 << site.variables;
        let poly_arg = if terminal {
            format!(", poly: StackBuf({})", 3 * final_size)
        } else {
            String::new()
        };
        writeln!(
            self.helpers,
            "def {name}(tabs, q, cap: StackBuf(4){params}{poly_arg}):"
        )
        .unwrap();
        f.line(format!("row = StackBuf({size})"));
        f.line(format!("hint_witness(row, \"{name}\")"));
        for j in (0..size).step_by(2) {
            f.line(format!(
                "assert_in_k(row[{j}], row[{}])",
                (j + 1).min(size - 1)
            ));
        }
        let mut leaf = Bytes::default();
        leaf.literal(LEAF);
        leaf.pcs_lanes((0..size).map(|j| format!("row[{j}]")));
        leaf.hash(&mut f.src, "node");
        f.line(format!("bits = StackBuf({height})"));
        f.line(format!("hint_decompose_bits(bits, q, {height})"));
        f.line("position = 0");
        f.line("x = 0");
        for j in 0..height {
            f.line(format!("assert bits[{j}] * bits[{j}] == bits[{j}]"));
            f.line(format!("position += {} * bits[{j}]", 1u64 << j));
            f.line(format!(
                "x += {} * bits[{j}]",
                Poly64::cantor_basis(j).to_repr()
            ));
            f.line("sibling = StackBuf(4)");
            f.line(format!("hint_witness(sibling, \"pcs_path_{i}\")"));
            f.line(format!("node = pcs_parent(tabs, node, sibling, bits[{j}])"));
        }
        f.line("assert q == position");
        f.line("assert node[0] == cap[0] + 18446744073709551616 * cap[1]");
        f.line("assert node[1] == cap[2] + 18446744073709551616 * cap[3]");
        let values = (0..site.width)
            .map(|j| {
                if base {
                    f.assign(format!("ext(row[{j}], 0, 0)"))
                } else {
                    f.ext_at("row", 3 * j)
                }
            })
            .collect();
        let point = (0..last.len()).map(|j| format!("r{j}")).collect::<Vec<_>>();
        let folded = f.table(values, &point, true);
        if terminal {
            let mut coords = vec![];
            let mut s = "x".to_string();
            for j in 0..site.variables {
                coords.push(f.assign(format!("ext({s}, 0, 0)")));
                if j + 1 != site.variables {
                    s = f.assign(format!("{s} * {s} + {s}"));
                }
            }
            coords.reverse();
            let v = (0..final_size).map(|k| f.ext_at("poly", 3 * k)).collect();
            let expected = f.table(v, &coords, false);
            f.line(format!("pcs_equal({folded}, {expected})"));
        }
        f.line(format!("return {folded}, x"));
        self.helpers.push_str(&f.src);
        self.helpers.push('\n');
        name
    }
    fn weight_func(&mut self, n: usize) {
        let mut f = Emitter::default();
        let args = (0..n)
            .map(|j| format!(", r{j}: StackBuf(3)"))
            .collect::<String>();
        writeln!(self.helpers, "def pcs_select_{n}(x{args}):").unwrap();
        f.line("out = ext(1, 0, 0)");
        for j in (0..n).rev() {
            f.line("linear = 1 + x");
            f.line(format!(
                "factor = ext(1 + linear * r{j}[0], linear * r{j}[1], linear * r{j}[2])"
            ));
            f.line("out = times(out, factor)");
            f.line("x = x * x + x");
        }
        f.line("return out");
        self.helpers.push_str(&f.src);
        self.helpers.push('\n');
    }
}

enum Term {
    Eq(Vec<String>),
    Select { variables: usize, x: String },
}

pub struct Guest {
    pub body: String,
    pub helpers: String,
    pub schema: Vec<Stream>,
    pub seal: Vec<String>,
}

/// The statement variables come from the preceding reduction in the same guest.
pub fn compile(plan: &Plan, seed_index: usize) -> Guest {
    emit(
        plan,
        (0..4).map(|k| format!("s{seed_index}l{k}")).collect(),
        true,
    )
}

pub fn subroutine(plan: &Plan, name: &str) -> (String, Vec<Stream>) {
    let guest = emit(plan, (0..4).map(|k| format!("seed[{k}]")).collect(), false);
    let mut body = format!(
        "def {name}(tabs, blend: StackBuf(32), opening_point: StackBuf({}), value: StackBuf(3), seed: StackBuf(4)):\n{}",
        3 * (plan.variables - 2),
        guest.body
    );
    body.push_str("    result = StackBuf(4)\n");
    for (i, w) in guest.seal.iter().enumerate() {
        writeln!(body, "    result[{i}] = {w}").unwrap();
    }
    body.push_str("    return result\n\n");
    body.push_str(&guest.helpers);
    // Distinct advice streams are essential when several openings share a program.
    let qualify = |s: &str| {
        ["pcs_msg", "pcs_row_", "pcs_path_", "pcs_select_"]
            .iter()
            .fold(s.to_owned(), |s, from| {
                s.replace(from, &format!("{name}_{from}"))
            })
    };
    let mut schema = guest.schema;
    for s in &mut schema {
        s.name = qualify(&s.name);
    }
    (qualify(&body), schema)
}

fn emit(plan: &Plan, seed: Vec<String>, main: bool) -> Guest {
    let mut g = Emitter::default();
    if main {
        g.parent();
        g.line("tabs = pcs_byte_table()");
    }
    g.line("pcs_one = ext(1, 0, 0)");
    g.line("pcs_zero = ext(0, 0, 0)");
    let mut cap = g.assign("StackBuf(4)");
    for j in 0..4 {
        let word = (0..8)
            .map(|b| format!("{} * blend[{}]", 1u64 << (8 * b), 8 * j + b))
            .collect::<Vec<_>>()
            .join(" + ");
        g.line(format!("{cap}[{j}] = {word}"));
    }
    g.absorb(Observation::Lanes(seed));
    g.seed(&plan.commitment_seed);
    g.observe(&cap, 4);
    let evals = g.fields(3);
    g.line("pcs_y = ext(0, 1, 0)");
    g.line("pcs_y2 = ext(0, 0, 1)");
    let t = g.assign(format!("pcs_mac(pcs_y, {}, {})", evals[1], evals[0]));
    let reconstructed = g.assign(format!("pcs_mac(pcs_y2, {}, {t})", evals[2]));
    g.line(format!("pcs_equal(value, {reconstructed})"));
    let mut values = evals.clone();
    let oods = g.fields(plan.initial_ood);
    let mut init = vec![];
    for (sep, a) in plan.virtual_seeds.iter().zip(&oods) {
        g.seed(sep);
        init.push(g.ood(a, plan.variables));
    }
    values.extend(oods);
    assert_eq!(plan.opening_seeds.len(), 1);
    g.seed(&plan.opening_seeds[0]);
    for a in &evals {
        g.observe(a, 3);
    }
    g.seed(&plan.engine_seed);
    g.seed(&plan.batching_seed);
    let alpha = g.challenge();
    g.line("pcs_claim = pcs_zero");
    for a in values.iter().rev() {
        g.line(format!("pcs_claim = pcs_mac(pcs_claim, {alpha}, {a})"));
    }
    let mut all = vec![];
    let mut last = g.fold(&plan.fold_seeds[0], &plan.initial_fold, &mut all);
    let mut terms = vec![];
    let mut final_poly = vec![];
    for (i, site) in plan.sites.iter().enumerate() {
        let terminal = i + 1 == plan.sites.len();
        let new_cap = (!terminal).then(|| g.read(16, true));
        let mut claims = vec![];
        let mut poly_arg = String::new();
        if let Some(cap) = &new_cap {
            g.observe(cap, 4);
            for a in g.fields(site.ood) {
                let p = g.ood(&a, site.variables);
                claims.push((a, Term::Eq(p)));
            }
        } else {
            let msg = g.read(3 * plan.final_len, false);
            g.observe(&msg, 3 * plan.final_len);
            poly_arg = format!(", {msg}");
            final_poly = (0..plan.final_len).map(|j| g.ext_at(&msg, 3 * j)).collect();
        }
        let nonce = g.read(1, false);
        g.pow(format!("{nonce}[0]"), site.query_pow_bits);
        let check = g.row_function(i, site, &last, i == 0, terminal);
        let args = last.iter().map(|r| format!(", {r}")).collect::<String>();
        for (range, depth) in site.queries.groups() {
            let low = site.queries.index_bits() - depth;
            for stratum in 0..range.len() {
                let q = if low == 0 {
                    stratum.to_string()
                } else {
                    let coin = g.lane();
                    g.assign(format!("{} + query_index({coin}, {low})", stratum << low))
                };
                let (v, x) = (g.name("row"), g.name("x"));
                g.line(format!(
                    "{v}, {x} = {check}(tabs, {q}, {cap}{args}{poly_arg})"
                ));
                if !terminal {
                    claims.push((
                        v,
                        Term::Select {
                            variables: site.variables,
                            x,
                        },
                    ));
                }
            }
        }
        if let Some(next) = new_cap {
            let gamma = g.challenge();
            let mut power = gamma.clone();
            for (a, w) in claims {
                g.line(format!("pcs_claim = pcs_mac({power}, {a}, pcs_claim)"));
                terms.push((power.clone(), w));
                power = g.assign(format!("times({power}, {gamma})"));
            }
            cap = next;
        }
        last = g.fold(&plan.fold_seeds[i + 1], &site.fold, &mut all);
    }

    assert_eq!(all.len(), plan.variables);
    let n = plan.variables - 2;
    let p = (0..n)
        .map(|j| g.ext_at("opening_point", 3 * j))
        .collect::<Vec<_>>();
    let local = g.eq(&p, &all[..n]);
    let mut weights = vec![];
    assert_eq!(plan.placements.len(), 1);
    for selector in plan.placements[0].selectors() {
        assert_eq!(selector.num_variables(), 2);
        // The native prefix layout bit-reverses the slot and the two selector coordinates.
        let mut w = local.clone();
        for (k, r) in all[n..].iter().enumerate() {
            let bit = (selector.index() >> (1 - k)) & 1;
            let factor = if bit == 1 {
                r.clone()
            } else {
                g.assign(format!("plus(pcs_one, {r})"))
            };
            w = g.assign(format!("times({w}, {factor})"));
        }
        weights.push(w);
    }
    for v in init {
        weights.push(g.eq(&v, &all));
    }
    g.line("pcs_weight = pcs_zero");
    for w in weights.iter().rev() {
        g.line(format!("pcs_weight = pcs_mac(pcs_weight, {alpha}, {w})"));
    }
    let mut generated = std::collections::BTreeSet::new();
    for (power, w) in terms {
        let w = match w {
            Term::Eq(p) => g.eq(&p, &all[all.len() - p.len()..]),
            Term::Select { variables, x } => {
                if generated.insert(variables) {
                    g.weight_func(variables);
                }
                let args = all[all.len() - variables..]
                    .iter()
                    .map(|r| format!(", {r}"))
                    .collect::<String>();
                g.assign(format!("pcs_select_{variables}({x}{args})"))
            }
        };
        g.line(format!("pcs_weight = pcs_mac({w}, {power}, pcs_weight)"));
    }
    let final_value = g.table(final_poly, &last, true);
    let endpoint = g.assign(format!("times(pcs_weight, {final_value})"));
    g.line(format!("pcs_equal(pcs_claim, {endpoint})"));
    g.absorb(Observation::Fixed(b"IMTVPC03".to_vec()));
    let seal = (0..4).map(|_| g.lane()).collect();
    Guest {
        body: g.src,
        helpers: g.helpers,
        schema: g.schema,
        seal,
    }
}
