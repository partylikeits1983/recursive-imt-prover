//! The first oracle's Fiat–Shamir queries, starting at the verified AIR point.
use super::guest::{Bytes, Transcript};
use recursive_imt_prover::binary::veil::{child::PreparedMembership, parameters::Parameters};
use std::fmt::Write;
use verifier::E;

pub(super) const COLUMNS: &[u8] = b"stacked-column-evaluations";

/// Supply full aligned 128-bit cells directly to Keccak. Only the bytes that share
/// a cell with the frame header or final padding need separate range checks.
struct Packed {
    head: usize,
    cells: usize,
    tail: usize,
}

impl Packed {
    fn new(label: &[u8], len: usize) -> Self {
        let header =
            super::guest::TRANSCRIPT_DOMAIN.len() + 32 + 16 + label.len().next_multiple_of(2);
        Self::after(header, len)
    }

    fn after(header: usize, len: usize) -> Self {
        let head = ((16 - header % 16) % 16).min(len);
        Self {
            head,
            cells: (len - head) / 16,
            tail: (len - head) % 16,
        }
    }

    fn declare(&self, src: &mut String, name: &str) {
        let words = self.head + self.cells + self.tail;
        writeln!(
            src,
            "    {name} = StackBuf({words})\n    hint_witness({name}, \"{name}\")"
        )
        .unwrap();
        for i in (0..self.head).chain(self.head + self.cells..words) {
            writeln!(src, "    check_byte({name}[{i}])").unwrap();
        }
    }

    fn append(&self, f: &mut Bytes, name: &str) {
        f.input(name, 0, self.head);
        for i in 0..self.cells {
            f.term(16, format!("{name}[{}]", self.head + i));
        }
        f.input(name, self.head + self.cells, self.tail);
    }

    fn pack(&self, bytes: &[u8]) -> Vec<E> {
        let (prefix, rest) = bytes.split_at(self.head);
        let (body, suffix) = rest.split_at(16 * self.cells);
        let byte = |&b: &u8| E::new(u64::from(b), 0);
        prefix
            .iter()
            .map(byte)
            .chain(body.as_chunks::<16>().0.iter().map(|c| {
                E::new(
                    u64::from_le_bytes(c[..8].try_into().unwrap()),
                    u64::from_le_bytes(c[8..].try_into().unwrap()),
                )
            }))
            .chain(suffix.iter().map(byte))
            .collect()
    }
}
pub(super) fn packed_columns(bytes: &[u8]) -> Vec<E> {
    Packed::new(COLUMNS, bytes.len()).pack(bytes)
}
pub(super) fn packed_row(bytes: &[u8], domain: &[u8]) -> Vec<E> {
    Packed::after(domain.len(), bytes.len()).pack(bytes)
}

/// Layout used by oracle_parent: store the six leading and two trailing bytes
/// in the two parts of a single lane. The middle 24 bytes are three whole lanes.
pub(super) fn sibling(bytes: &[u8; 32], aligned: bool) -> Vec<E> {
    if aligned {
        let (a, b) = verifier::Digest(*bytes).halves();
        return vec![a, b];
    }
    let mut edges = [0u8; 8];
    edges[..6].copy_from_slice(&bytes[..6]);
    edges[6..].copy_from_slice(&bytes[30..]);
    let lane = |i| u64::from_le_bytes(bytes[i..i + 8].try_into().unwrap());
    vec![
        E::new(u64::from_le_bytes(edges), lane(6)),
        E::new(lane(14), lane(22)),
    ]
}

pub(super) fn queries(
    t: &mut Transcript,
    child: &PreparedMembership,
    summary: &mut Bytes,
    blend: Option<&Parameters>,
    full: bool,
) {
    let rounds = child.trace_height().ilog2() as usize;
    let columns = child.trace_width();
    let (count, height) = child
        .stacked_query_geometry()
        .expect("fixed masked profile");
    for (name, n) in [
        ("point", rounds * 24),
        ("masks", 48),
        ("blend", 32),
        ("evaluations", 48),
    ] {
        writeln!(t.src, "    {name} = StackBuf({n})\n    hint_witness({name}, \"{name}\")\n    for j in unroll(0, {n}):\n        check_byte({name}[j])").unwrap();
    }
    for (i, challenge) in t.challenges[2 + rounds..].iter().enumerate() {
        for limb in 0..3 {
            let start = i * 24 + limb * 8;
            let expr = (0..8)
                .map(|j| format!("{} * point[{}]", 1u64 << (8 * j), start + j))
                .collect::<Vec<_>>()
                .join(" + ");
            writeln!(t.src, "    assert s{challenge}l{limb} == {expr}").unwrap();
        }
    }
    t.integers(
        b"stacked-coefficient-oracle-v2",
        &[rounds, columns, child.stacking_factor().ilog2() as usize],
    );
    t.frame(b"stacked-oracle-root", 32, |f| f.input("oracle", 0, 32));
    t.integers(b"stacked-oracle-view-count", &[2]);
    for view in 0..2 {
        t.integers(b"stacked-oracle-view", &[view, rounds]);
        t.frame(b"stacked-oracle-point", rounds * 24, |f| {
            f.input("point", 0, rounds * 24)
        });
    }
    if full {
        t.src.push_str("    tabs = pcs_byte_table()\n");
        super::vector::read(t, "column_fields", 6 * columns, false);
        super::vector::field_frame(t, COLUMNS, "column_fields", 6 * columns);
    } else {
        let packing = Packed::new(COLUMNS, 48 * columns);
        packing.declare(&mut t.src, "columns");
        t.frame(COLUMNS, 48 * columns, |f| packing.append(f, "columns"));
    }
    t.coin(b"stacked-slot-combination");
    if blend.is_some() {
        let i = t.index;
        writeln!(t.src, "    theta = ext(s{i}l0, s{i}l1, s{i}l2)").unwrap();
    }
    t.frame(b"stacked-mask-evaluations", 48, |f| f.input("masks", 0, 48));
    t.coin(b"stacked-column-combination");
    if blend.is_some() {
        let i = t.index;
        writeln!(t.src, "    alpha = ext(s{i}l0, s{i}l1, s{i}l2)").unwrap();
    }
    t.frame(b"stacked-blend-commitment", 32, |f| f.input("blend", 0, 32));
    t.frame(b"stacked-blend-evaluations", 48, |f| {
        f.input("evaluations", 0, 48)
    });
    let mut index = 0;
    for depth in (0..height).rev().filter(|b| (count >> b) & 1 == 1) {
        let low = height - depth;
        for stratum in 0..1usize << depth {
            t.integers(b"query", &[index]);
            writeln!(
                t.src,
                "    q{index} = query_index(s{}l0, {low}) + {}",
                t.index,
                stratum << low
            )
            .unwrap();
            index += 1;
        }
    }
    assert_eq!(index, count);
    summary.state(t.index, 4);
    for i in 0..count {
        summary.term(8, format!("q{i}"));
    }
    let mut root = Bytes::default();
    root.input("oracle", 0, 32);
    let root = root.words();
    writeln!(
        t.src,
        "    oracle0 = {}\n    oracle1 = {}",
        root[0], root[1]
    )
    .unwrap();
    for i in 0..count {
        if blend.is_some() {
            writeln!(
                t.src,
                "    leaf{i}a, leaf{i}b, v{i} = check_row(q{i}, oracle0, oracle1, alpha)"
            )
            .unwrap();
        } else {
            writeln!(
                t.src,
                "    leaf{i}a, leaf{i}b = check_row(q{i}, oracle0, oracle1)"
            )
            .unwrap();
        }
        summary.term(16, format!("leaf{i}a"));
        summary.term(16, format!("leaf{i}b"));
    }
    if let Some(params) = blend {
        super::blend::reduction(t, child, params, summary);
    }
}

pub(super) fn row_verifier(src: &mut String, child: &PreparedMembership, blend: bool) {
    let (_, height) = child
        .stacked_query_geometry()
        .expect("fixed masked profile");
    let width = (child.oracle_columns() + 2) * 24;
    let (leaf, node) = child.stacked_row_domains();
    let parent = if node.len() == 16 {
        "aligned_parent"
    } else {
        "oracle_parent"
    };
    let mut salted = Bytes::default();
    salted.literal(leaf);
    if blend {
        let cells = width.div_ceil(16);
        let lanes = width / 8;
        src.push_str("\n\ndef check_row(q, oracle0, oracle1, alpha: StackBuf(3)):\n");
        writeln!(src, "    raw = StackBuf({cells})\n    hint_witness(raw, \"row\")\n    flat = StackBuf({})\n    for i in unroll(0, {cells}):\n        a, b = limbs(raw[i])\n        flat[2*i] = a\n        flat[2*i+1] = b",2*cells).unwrap();
        if lanes % 2 == 1 {
            writeln!(src, "    assert flat[{lanes}] == 0").unwrap();
        }
        salted.lanes((0..lanes).map(|i| format!("flat[{i}]")));
        let data = child.oracle_columns();
        writeln!(src, "    val = ext(0, 0, 0)\n    for i in unroll(0, {data}):\n        k = 3 * ({data} - 1 - i)\n        elem = ext(flat[k], flat[k+1], flat[k+2])\n        part = times(val, alpha)\n        val = plus(elem, part)").unwrap();
    } else {
        let row = Packed::after(leaf.len(), width);
        src.push_str("\n\ndef check_row(q, oracle0, oracle1):\n");
        row.declare(src, "row");
        row.append(&mut salted, "row");
    }
    salted.hash(src, "leaf");
    let extra = if blend { ", val" } else { "" };
    writeln!(src, "    bits = StackBuf({height})\n    hint_decompose_bits(bits, q, {height})\n    pos = 0\n    a = leaf[0]\n    b = leaf[1]\n    for j in unroll(0, {height}):\n        assert bits[j] * bits[j] == bits[j]\n        pos += (2 ** j) * bits[j]\n        a, b = {parent}(a, b, bits[j])\n    assert pos == q\n    assert a == oracle0\n    assert b == oracle1\n    return leaf[0], leaf[1]{extra}").unwrap();
}
