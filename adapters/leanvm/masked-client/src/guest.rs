//! Generate zkDSL only from the fixed verifier profile. No proof data enters the bytecode.
use isa::Program;
use p3_binary_field::TowerLevel;
use recursive_imt_prover::binary::veil::{
    child::PreparedMembership, native::Operation, parameters::Parameters,
};
use std::fmt::Write;

pub const CHECKPOINT_DOMAIN: &[u8; 16] = b"IMT-AIR-CHECK-01";
pub(super) const TRANSCRIPT_DOMAIN: &[u8] = b"imt-veil-v3/transcript\0\0";
const ONLINE_PROTOCOL: &[u8] = b"experimental-binary-veil-online-v3";

/// All symbolic terms span either one range-checked byte or one aligned K limb.
/// Constants are literal byte strings, including the padding in the Rust transcript.
#[derive(Default)]
pub(super) struct Bytes {
    len: usize,
    cells: Vec<(u128, Vec<String>)>,
    setup: String,
}

impl Bytes {
    fn slot(&mut self) -> &mut (u128, Vec<String>) {
        if self.len.is_multiple_of(16) {
            self.cells.push((0, vec![]));
        }
        self.cells.last_mut().unwrap()
    }

    pub(super) fn literal(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            let shift = 8 * (self.len % 16);
            self.slot().0 |= u128::from(byte) << shift;
            self.len += 1;
        }
    }

    pub(super) fn term(&mut self, width: usize, term: String) {
        assert!(matches!(width, 1 | 8 | 16) && self.len.is_multiple_of(width));
        self.fragment(width, term);
    }

    fn fragment(&mut self, width: usize, term: String) {
        let shift = 8 * (self.len % 16);
        let term = if shift == 0 {
            term
        } else {
            format!("{} * {term}", 1u128 << shift)
        };
        self.slot().1.push(term);
        self.len += width;
    }

    /// Append canonical K limbs even when a native frame header ends mid-lane.
    pub(super) fn lanes(&mut self, words: impl IntoIterator<Item = String>) {
        self.lanes_with(words, "split_lane_bytes", "");
    }

    pub(super) fn pcs_lanes(&mut self, words: impl IntoIterator<Item = String>) {
        self.lanes_with(words, "pcs_split", "tabs, ");
    }

    fn lanes_with(&mut self, words: impl IntoIterator<Item = String>, split: &str, args: &str) {
        let skew = self.len % 8;
        for word in words {
            if skew == 0 {
                self.term(8, word);
            } else {
                let at = self.len;
                writeln!(
                    self.setup,
                    "    lo{at}, hi{at} = {split}({args}{word}, {})",
                    8 - skew
                )
                .unwrap();
                self.fragment(8 - skew, format!("lo{at}"));
                self.fragment(skew, format!("hi{at}"));
            }
        }
    }

    pub(super) fn input(&mut self, name: &str, from: usize, len: usize) {
        for i in from..from + len {
            self.term(1, format!("{name}[{i}]"));
        }
    }

    pub(super) fn state(&mut self, index: usize, count: usize) {
        for limb in 0..count {
            self.term(8, format!("s{index}l{limb}"));
        }
    }

    pub(super) fn words(self) -> Vec<String> {
        self.cells
            .into_iter()
            .map(|(literal, mut terms)| {
                if literal != 0 || terms.is_empty() {
                    terms.push(literal.to_string());
                }
                terms.join(" + ")
            })
            .collect::<Vec<_>>()
    }

    pub(super) fn hash(self, src: &mut String, out: &str) {
        let n = self.len;
        src.push_str(&self.setup);
        let cells = self.words().join(", ");
        writeln!(
            src,
            "    {out} = StackBuf(2)\n    keccak_cells([{cells}], {out}, len={n})"
        )
        .unwrap();
    }
}

pub(super) struct Transcript {
    pub(super) src: String,
    pub(super) index: usize,
    pub(super) challenges: Vec<usize>,
}

impl Transcript {
    pub(super) fn frame(&mut self, label: &[u8], len: usize, payload: impl FnOnce(&mut Bytes)) {
        let mut data = Bytes::default();
        data.literal(TRANSCRIPT_DOMAIN);
        if self.index == 0 {
            data.literal(&[0; 32]);
        } else {
            data.state(self.index, 4);
        }
        data.literal(&(label.len() as u64).to_le_bytes());
        data.literal(label);
        if label.len() % 2 == 1 {
            data.literal(&[0]);
        }
        data.literal(&(len as u64).to_le_bytes());
        let start = data.len;
        payload(&mut data);
        assert_eq!(data.len - start, len);
        if len % 2 == 1 {
            data.literal(&[0]);
        }
        self.index += 1;
        let i = self.index;
        data.hash(&mut self.src, &format!("s{i}"));
        writeln!(
            self.src,
            "    s{i}l0, s{i}l1 = limbs(s{i}[0])\n    s{i}l2, s{i}l3 = limbs(s{i}[1])"
        )
        .unwrap();
    }

    pub(super) fn fixed(&mut self, label: &[u8], value: &[u8]) {
        self.frame(label, value.len(), |f| f.literal(value));
    }

    pub(super) fn integers(&mut self, label: &[u8], values: &[usize]) {
        let bytes: Vec<_> = values
            .iter()
            .flat_map(|&v| (v as u64).to_le_bytes())
            .collect();
        self.fixed(label, &bytes);
    }

    pub(super) fn coin(&mut self, label: &[u8]) {
        self.fixed(label, &[0; 8]);
        let i = self.index;
        // Poly192 takes the first 24 bytes. Exactly the two native abort values are excluded.
        writeln!(
            self.src,
            "    if s{i}l2 == 0:\n        assert s{i}[0] != 0\n        assert s{i}[0] != 1"
        )
        .unwrap();
    }
}

/// A masked round value is a formal witness wire. Its final coefficient is its
/// interpolation weight times every subsequent previous-claim weight.
fn reduce(t: &mut Transcript, child: &PreparedMembership, output: &mut Bytes) {
    let polynomials = child.air_program().round_weight_polynomials();
    let degree = polynomials.len() - 1;
    let rounds = child.air_program().message_count() / degree;
    assert_eq!(t.challenges.len(), 2 + 2 * rounds);
    t.src
        .push_str("    product0 = 1\n    product1 = 0\n    product2 = 0\n");
    for round in (0..rounds).rev() {
        let point = t.challenges[2 + rounds + round];
        for (i, polynomial) in polynomials.iter().enumerate() {
            t.src.push_str("    w0 = 0\n    w1 = 0\n    w2 = 0\n");
            for coef in polynomial.iter().rev() {
                let [c0, c1, c2] = coef.coefficients().map(|x| x.to_repr());
                writeln!(t.src, "    z0, z1, z2 = poly192_mul(w0, w1, w2, s{point}l0, s{point}l1, s{point}l2)\n    w0 = z0 + {c0}\n    w1 = z1 + {c1}\n    w2 = z2 + {c2}").unwrap();
            }
            let dest = if i == 0 {
                "next".to_string()
            } else {
                format!("weight{}l", round * degree + i - 1)
            };
            writeln!(t.src, "    {dest}0, {dest}1, {dest}2 = poly192_mul(w0, w1, w2, product0, product1, product2)").unwrap();
        }
        t.src
            .push_str("    product0 = next0\n    product1 = next1\n    product2 = next2\n");
    }
    for i in 0..rounds * degree {
        for limb in 0..3 {
            output.term(8, format!("weight{i}l{limb}"));
        }
    }
}

#[cfg(test)]
pub fn program(child: &PreparedMembership, parameters: &Parameters, blend: bool) -> Program {
    compile(child, parameters, blend, None, false, false).0
}

pub fn compile(
    child: &PreparedMembership,
    parameters: &Parameters,
    blend: bool,
    plan: Option<&super::whir::Plan>,
    products: bool,
    full: bool,
) -> (
    Program,
    Vec<super::whir::Stream>,
    Vec<Vec<super::whir::Stream>>,
) {
    let (source, schema, vectors) = source(child, parameters, blend, plan, products, full, false);
    let ast = zkdsl_compiler::parse(&source).expect("trusted AIR guest source");
    (zkdsl_compiler::compile(&ast).into(), schema, vectors)
}

pub fn source(
    child: &PreparedMembership,
    parameters: &Parameters,
    blend: bool,
    plan: Option<&super::whir::Plan>,
    products: bool,
    full: bool,
    recursion: bool,
) -> (
    String,
    Vec<super::whir::Stream>,
    Vec<Vec<super::whir::Stream>>,
) {
    let (_, node) = child.stacked_row_domains();
    let merkle = if node.len() == 16 {
        include_str!("merkle_aligned.py")
    } else {
        include_str!("merkle_original.py")
    };
    let prefix = u128::from_le_bytes(node[..16].try_into().expect("fixed domain prefix"));
    let mut t = Transcript {
        src: format!(
            "{}\n\n{}\n\ndef main():\n",
            include_str!("transcript.py"),
            merkle.replace("NODE_PREFIX", &prefix.to_string())
        ),
        index: 0,
        challenges: vec![],
    };
    if blend {
        let (prelude, helpers) = super::blend::helpers(child, parameters);
        t.src = format!(
            "{prelude}\n{}\n{helpers}\n\ndef main():\n",
            t.src.strip_suffix("def main():\n").unwrap()
        );
    }
    for (name, n) in [
        ("root", 32),
        ("oracle", 32),
        ("mask", 32),
        ("rounds", child.air_program().message_count() * 24),
    ] {
        writeln!(t.src, "    {name} = StackBuf({n})\n    hint_witness({name}, \"{name}\")\n    for j in unroll(0, {n}):\n        check_byte({name}[j])").unwrap();
    }
    t.fixed(b"protocol", ONLINE_PROTOCOL);
    let prefix = child.binding_prefix();
    t.frame(b"statement", prefix.len() + 128, |f| {
        f.literal(&prefix);
        f.input("root", 0, 32);
        f.literal(&[0; 64]); // root-only ClientPublic
        f.input("oracle", 0, 32);
    });
    let config: Vec<_> = [
        parameters.query_bits,
        parameters.min_algebraic_bits,
        parameters.log_inv_rate,
        parameters.max_message_len,
        child.masked_messages(),
    ]
    .into_iter()
    .flat_map(|n| (n as u64).to_le_bytes())
    .collect();
    t.fixed(b"online-parameters", &config);
    t.frame(b"mask-commitment", 32, |f| f.input("mask", 0, 32));
    let mut at = 0;
    for op in child.air_program().operations() {
        match op {
            Operation::Public(value) => {
                let mut bytes = [0; 24];
                bytes[..8].copy_from_slice(&value.to_repr().to_le_bytes());
                t.fixed(b"native-public", &bytes);
            }
            Operation::Message(n) => {
                let len = 24 * n;
                t.frame(b"native-message", len, |f| f.input("rounds", at, len));
                at += len;
            }
            Operation::Challenge => {
                t.coin(b"native-challenge");
                t.challenges.push(t.index);
            }
        }
    }
    assert_eq!(at, child.air_program().message_count() * 24);
    let mut summary = Bytes::default();
    summary.literal(if products {
        super::vector::DOMAIN
    } else if plan.is_some() {
        super::whir::DOMAIN
    } else if blend {
        super::blend::DOMAIN
    } else {
        CHECKPOINT_DOMAIN
    });
    summary.input("root", 0, 32);
    summary.state(t.index, 4);
    for &i in &t.challenges {
        summary.state(i, 3);
    }
    reduce(&mut t, child, &mut summary);
    super::oracle::queries(
        &mut t,
        child,
        &mut summary,
        if blend { Some(parameters) } else { None },
        full,
    );
    let mut schema = vec![];
    let mut helpers = String::new();
    let mut vector_schemas = Vec::new();
    if let Some(plan) = plan {
        let guest = super::whir::compile(plan, t.index);
        helpers = format!("{}\n{}", include_str!("whir.py"), guest.helpers);
        t.src.push_str(&guest.body);
        summary.lanes(guest.seal.iter().cloned());
        if products {
            let mut product = super::vector::compile(&mut t, child, parameters, &guest.seal);
            if full {
                super::vector::finish_mask(&mut t, child, parameters, &mut product);
            }
            vector_schemas = product.schemas;
            helpers.push_str(&product.helpers);
            summary.state(t.index, 4);
        }
        schema = guest.schema;
    }
    if full {
        let mut root = Bytes::default();
        root.input("root", 0, 32);
        let words = root.words();
        writeln!(
            t.src,
            "    digest = StackBuf(2)\n    digest[0] = {}\n    digest[1] = {}",
            words[0], words[1]
        )
        .unwrap();
    } else {
        summary.hash(&mut t.src, "digest");
    }
    if recursion {
        assert!(full);
        t.src = t.src.replacen("def main():", "def imt_path():", 1);
        t.src.push_str("    return digest[0], digest[1]\n");
    } else {
        t.src.push_str("    public = GEN ** 0\n    assert public[1] == digest[0]\n    assert public[GEN] == digest[1]\n    return\n");
    }
    super::oracle::row_verifier(&mut t.src, child, blend);
    t.src.push_str(&helpers);
    (t.src, schema, vector_schemas)
}
