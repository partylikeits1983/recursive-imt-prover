//! Verify the masked client's product-vector dot and Hadamard openings.
use super::{
    guest::{Bytes, Transcript},
    whir,
};
use anyhow::Result;
use p3_binary_field::{Poly64, Poly192, TowerLevel};
use recursive_imt_prover::binary::veil::{
    child::{
        PreparedMembership,
        checkpoint::{ConstraintMessages, CoordinateMessages},
    },
    parameters::Parameters,
};
use std::fmt::Write;
use verifier::E;
const ROW_DOMAIN: &[u8] = b"imt-veil-v3/leaf\0\0";
const NODE_DOMAIN: &[u8] = b"imt-veil-v3/node\0\0";
pub const DOMAIN: &[u8; 16] = b"IMT-PRODUCTS--01";

pub struct ProductGuest {
    pub helpers: String,
    pub schemas: Vec<Vec<whir::Stream>>,
}

fn fields(v: &[Poly192]) -> Vec<E> {
    v.iter()
        .flat_map(|x| x.coefficients().map(|f| E::new(f.to_repr(), 0)))
        .collect()
}
pub fn advice(
    c: &ConstraintMessages,
    schemas: &[Vec<whir::Stream>],
) -> Result<Vec<(String, Vec<Vec<E>>)>> {
    let p = &c.product;
    let mut out = vec![
        ("product_wires".into(), vec![fields(&c.product_wires)]),
        ("padding".into(), vec![fields(&c.padding)]),
        super::stream("product_root", &p.root),
        ("product_gamma".into(), vec![fields(&[p.gamma.unwrap()])]),
        ("product_claims".into(), vec![fields(&p.claims)]),
        ("mask_dot".into(), vec![fields(&[p.mask_dot])]),
    ];
    let full = schemas.len() == 3;
    if full {
        out.push(("mask_claim".into(), vec![fields(&c.mask.claims)]));
        out.push(("mask_mask_dot".into(), vec![fields(&[c.mask.mask_dot])]));
    }
    for (kind, v) in [("product", p), ("mask", &c.mask)]
        .into_iter()
        .take(if full { 2 } else { 1 })
    {
        let raw = |bytes: &[u8]| {
            bytes
                .as_chunks::<8>()
                .0
                .iter()
                .map(|v| E::new(u64::from_le_bytes(*v), 0))
                .collect()
        };
        out.push((
            format!("{kind}_row"),
            v.rows.iter().map(|r| raw(&r.salted_row)).collect(),
        ));
        out.push((
            format!("{kind}_sibling"),
            v.rows
                .iter()
                .flat_map(|r| r.siblings.iter().map(|d| raw(d)))
                .collect(),
        ));
    }
    for ((name, c), schema) in ["dot", "had", "masked"]
        .into_iter()
        .zip(p.coordinates.iter().chain(&c.mask.coordinates))
        .zip(schemas)
    {
        let CoordinateMessages {
            root, blend, raw, ..
        } = c;
        out.push(super::stream(&format!("{name}_root"), root));
        out.push((
            format!("{name}_rounds"),
            blend.rounds.iter().map(|r| fields(r)).collect(),
        ));
        out.push((format!("{name}_value"), vec![fields(&[blend.value])]));
        out.extend(whir::advice(schema, raw)?);
    }
    Ok(out)
}

pub(super) fn read(t: &mut Transcript, n: &str, len: usize, bytes: bool) {
    writeln!(
        t.src,
        "    {n} = StackBuf({len})\n    hint_witness({n}, \"{n}\")"
    )
    .unwrap();
    if bytes {
        writeln!(
            t.src,
            "    for j in unroll(0, {len}):\n        check_byte({n}[j])"
        )
        .unwrap();
    } else {
        writeln!(
            t.src,
            "    for j in unroll(0, {}):\n        assert_in_k({n}[2*j], {n}[2*j+1])",
            len / 2
        )
        .unwrap();
        if len % 2 == 1 {
            writeln!(t.src, "    assert_in_k({n}[{}],{n}[{}])", len - 1, len - 1).unwrap();
        }
    }
}
pub(super) fn field_frame(t: &mut Transcript, label: &[u8], n: &str, len: usize) {
    t.frame(label, 8 * len, |f| {
        f.pcs_lanes((0..len).map(|j| format!("{n}[{j}]")))
    })
}
fn coin(t: &mut Transcript, label: &[u8], n: &str) {
    t.coin(label);
    let i = t.index;
    writeln!(t.src, "    {n} = ext(s{i}l0, s{i}l1, s{i}l2)").unwrap();
}

fn row_helpers(height: usize, product: bool) -> String {
    let mut s = String::from(
        "def product_parent(tabs, d: StackBuf(2), s: StackBuf(4), b):\n    d0, d1 = limbs(d[0])\n    d2, d3 = limbs(d[1])\n    assert_in_k(s[0], s[1])\n    assert_in_k(s[2], s[3])\n",
    );
    for i in 0..4 {
        writeln!(s,"    swap{i} = b * (s[{i}] + d{i})\n    l{i} = d{i} + swap{i}\n    r{i} = s[{i}] + swap{i}").unwrap();
    }
    let mut frame = Bytes::default();
    frame.literal(NODE_DOMAIN);
    frame.pcs_lanes(
        ["l", "r"]
            .into_iter()
            .flat_map(|n| (0..4).map(move |i| format!("{n}{i}"))),
    );
    frame.hash(&mut s, "parent");
    s.push_str("    return parent\n\n");
    let (name, size) = if product {
        ("product", 21)
    } else {
        s.clear();
        ("mask", 12)
    };
    let extra = if product {
        ", had_rho: StackBuf(3)"
    } else {
        ""
    };
    writeln!(s,"def check_{name}_row(tabs, q, cap: StackBuf(2), dot_rho: StackBuf(3){extra}):\n    row = StackBuf({size})\n    hint_witness(row, \"{name}_row\")\n    for j in unroll(0, {}):\n        assert_in_k(row[2*j], row[2*j+1])",size/2).unwrap();
    if product {
        s.push_str("    assert_in_k(row[20],row[20])\n");
    }
    let mut leaf = Bytes::default();
    leaf.literal(ROW_DOMAIN);
    leaf.pcs_lanes((0..size).map(|j| format!("row[{j}]")));
    leaf.hash(&mut s, "d");
    writeln!(s,"    bits = StackBuf({height})\n    hint_decompose_bits(bits,q,{height})\n    pos = 0\n    x = {} ",Poly64::cantor_basis(height).to_repr()).unwrap();
    for j in 0..height {
        writeln!(s,"    assert bits[{j}] * bits[{j}] == bits[{j}]\n    pos += {} * bits[{j}]\n    x += {} * bits[{j}]\n    sibling = StackBuf(4)\n    hint_witness(sibling, \"{name}_sibling\")\n    d = product_parent(tabs, d, sibling, bits[{j}])",1u64<<j,Poly64::cantor_basis(j).to_repr()).unwrap();
    }
    s.push_str("    assert q == pos\n    assert cap[0] == d[0]\n    assert cap[1] == d[1]\n");
    for j in 0..if product { 5 } else { 2 } {
        writeln!(
            s,
            "    v{j} = ext(row[{}], row[{}], row[{}])",
            3 * j,
            3 * j + 1,
            3 * j + 2
        )
        .unwrap();
    }
    if !product {
        s.push_str("    dot = pcs_mac(v1,dot_rho,v0)\n    return dot, x\n\n");
        return s;
    }
    s.push_str("    dot = v3\n    dot = pcs_mac(dot,dot_rho,v2)\n    dot = pcs_mac(dot,dot_rho,v1)\n    dot = pcs_mac(dot,dot_rho,v0)\n    tmp = pcs_mac(v0,v1,v2)\n    had = pcs_mac(v4,had_rho,tmp)\n    return dot, had, x\n\n");
    s
}

fn cantor(i: usize) -> u64 {
    (0..usize::BITS as usize)
        .filter(|j| i & (1usize << j) != 0)
        .fold(0, |v, j| v ^ Poly64::cantor_basis(j).to_repr())
}

fn prefix_helpers(n: usize, name: &str, length: usize) -> String {
    let mut source = String::new();
    let mut counts = vec![32];
    if !length.is_multiple_of(32) {
        counts.push(length % 32);
    }
    for count in counts {
        writeln!(source,"def {name}_prefix_{count}(x, p, base: StackBuf(3), power: StackBuf(3), total: StackBuf(3)):").unwrap();
        for j in 0..count {
            writeln!(source,"    v = vector_generator(x + {}, p, {n})\n    total = pcs_mac(power, v, total)\n    power = times(power, base)",cantor(j)).unwrap();
        }
        source.push_str("    return total, power\n\n");
    }
    source
}

#[allow(clippy::too_many_arguments)]
fn verify_blend(
    t: &mut Transcript,
    name: &str,
    prefix: &str,
    message_len: usize,
    input_len: usize,
    codeword_len: usize,
    count: usize,
    product: bool,
) {
    let length = input_len << usize::from(product);
    let n = length.ilog2() as usize;
    t.frame(b"vector-functional-rows-v1", count * 24, |f| {
        f.pcs_lanes((0..count).flat_map(|j| (0..3).map(move |k| format!("{name}row{j}[{k}]"))))
    });
    coin(t, b"vector-functional-batch-v1", "vbeta");
    t.src.push_str("    sum = ext(0,0,0)\n");
    for j in (0..count).rev() {
        writeln!(t.src, "    sum = pcs_mac(sum,vbeta,{name}row{j})").unwrap();
    }
    writeln!(t.src, "    sum = pcs_mac(sum,vbeta,{name}_expected)").unwrap();
    t.frame(b"blend-whir-commitment", 32, |f| {
        f.input(&format!("{name}_root"), 0, 32)
    });
    t.integers(
        b"vector-coefficient-functional-v1",
        &[
            message_len,
            input_len,
            codeword_len,
            count,
            usize::from(product),
        ],
    );
    t.frame(b"vector-functional-indices", count * 8, |f| {
        f.pcs_lanes((0..count).map(|j| format!("vq{j}")))
    });
    field_frame(t, b"vector-functional-beta", "vbeta", 3);
    field_frame(t, b"blend-functional-sum", "sum", 3);
    writeln!(
        t.src,
        "    vp = StackBuf({})\n    vh = HeapBuf({})\n    cv = sum",
        3 * n,
        3 * n
    )
    .unwrap();
    for j in 0..n {
        writeln!(t.src,"    vm = StackBuf(6)\n    hint_witness(vm, \"{name}_rounds\")\n    for k in unroll(0,3):\n        assert_in_k(vm[2*k],vm[2*k+1])").unwrap();
        field_frame(t, b"blend-sumcheck-round", "vm", 6);
        coin(t, b"blend-sumcheck-challenge", "vr");
        t.src.push_str("    c0 = ext(vm[0],vm[1],vm[2])\n    ci = ext(vm[3],vm[4],vm[5])\n    cv = pcs_reduce(cv,c0,ci,vr)\n");
        for k in 0..3 {
            let idx = 3 * j + k;
            writeln!(
                t.src,
                "    vp[{idx}] = vr[{k}]\n    vh[GEN ** {idx}] = vr[{k}]"
            )
            .unwrap();
        }
    }
    // Transpose the public interpolation evaluation: each prefix position
    // contributes its expected power times its Cantor generator at vp.
    t.src.push_str("    wt = ext(0,0,0)\n    pw = ext(1,0,0)\n");
    if name == "masked" {
        for j in (0..message_len).step_by(32) {
            let n = (message_len - j).min(32);
            writeln!(
                t.src,
                "    wt = mask_prefix_{n}({},vh,mask_weights * GEN ** {},wt)",
                cantor(j),
                3 * j
            )
            .unwrap();
        }
    } else {
        for j in (0..message_len).step_by(32) {
            writeln!(
                t.src,
                "    wt, pw = {name}_prefix_{}({},vh,{prefix},pw,wt)",
                (message_len - j).min(32),
                cantor(j)
            )
            .unwrap();
        }
    }
    t.src.push_str("    pw = vbeta\n");
    for j in 0..count {
        writeln!(t.src,"    gen = vector_generator(vx{j},vh,{n})\n    wt = pcs_mac(pw,gen,wt)\n    pw = times(pw,vbeta)").unwrap();
    }
    let value = format!("{name}_value");
    read(t, &value, 3, false);
    writeln!(
        t.src,
        "    endpoint = times(wt,{value})\n    pcs_equal(cv,endpoint)"
    )
    .unwrap();
    field_frame(t, b"blend-sumcheck-terminal", &value, 3);
    let i = t.index;
    t.src.push_str("    seed = StackBuf(4)\n");
    for k in 0..4 {
        writeln!(t.src, "    seed[{k}] = s{i}l{k}").unwrap();
    }
    writeln!(
        t.src,
        "    vseal = open_{name}(tabs, {name}_root, vp, {value}, seed)"
    )
    .unwrap();
    field_frame(t, b"blend-whir-seal-v3", "vseal", 4);
}

pub fn compile(
    t: &mut Transcript,
    child: &PreparedMembership,
    params: &Parameters,
    seal: &[String],
) -> ProductGuest {
    let length = child.verifier_products() + 2;
    let code = params.code(length, true).unwrap();
    let count = code.queries;
    let h = code.codeword_len.ilog2() as usize;
    t.frame(b"blend-whir-seal-v3", 32, |f| {
        f.pcs_lanes(seal.iter().cloned())
    });
    for (name, label, len) in [
        (
            "product_wires",
            &b"air-verifier-products"[..],
            3 * child.verifier_products(),
        ),
        ("padding", b"multiplication-padding", 18),
    ] {
        read(t, name, len, false);
        field_frame(t, label, name, len);
    }
    t.integers(
        b"verifier-constraint-shape-v1",
        &[child.masked_messages(), 3, child.verifier_products()],
    );
    read(t, "product_root", 32, true);
    t.frame(b"product-commitment", 32, |f| {
        f.input("product_root", 0, 32)
    });
    coin(t, b"product-link", "vlink");
    t.frame(b"vectors", 32, |f| f.input("product_root", 0, 32));
    coin(t, b"product-test", "vtest");
    read(t, "product_gamma", 3, false);
    field_frame(t, b"product-gamma", "product_gamma", 3);
    coin(t, b"product-mask", "had_rho");
    read(t, "had_root", 32, true);
    t.frame(b"product-blend-commitment-v1", 32, |f| {
        f.input("had_root", 0, 32)
    });
    read(t, "product_claims", 9, false);
    field_frame(t, b"dot-claims", "product_claims", 9);
    read(t, "mask_dot", 3, false);
    field_frame(t, b"dot-mask", "mask_dot", 3);
    coin(t, b"dot-blend", "dot_rho");
    read(t, "dot_root", 32, true);
    t.frame(b"dot-blend-commitment-v1", 32, |f| {
        f.input("dot_root", 0, 32)
    });
    t.src
        .push_str("    had_expected = times(had_rho,product_gamma)\n    dot_expected = mask_dot\n");
    for j in (0..3).rev() {
        writeln!(t.src,"    item = ext(product_claims[{}],product_claims[{}],product_claims[{}])\n    dot_expected = pcs_mac(dot_expected,dot_rho,item)",3*j,3*j+1,3*j+2).unwrap();
    }
    let mut idx = 0;
    for depth in (0..h).rev().filter(|b| (count >> b) & 1 != 0) {
        let low = h - depth;
        for stratum in 0..1usize << depth {
            t.integers(b"query", &[idx]);
            writeln!(
                t.src,
                "    vq{idx} = {} + query_index(s{}l0,{low})",
                stratum << low,
                t.index
            )
            .unwrap();
            idx += 1;
        }
    }
    let mut cap = Bytes::default();
    cap.input("product_root", 0, 32);
    let halves = cap.words();
    writeln!(
        t.src,
        "    vcap = StackBuf(2)\n    vcap[0] = {}\n    vcap[1] = {}",
        halves[0], halves[1]
    )
    .unwrap();
    for j in 0..count {
        writeln!(t.src,"    dotrow{j}, hadrow{j}, vx{j} = check_product_row(tabs, vq{j}, vcap, dot_rho, had_rho)").unwrap();
    }
    let mut helpers = format!("{}\n{}", include_str!("vector.py"), row_helpers(h, true));
    let mut schemas = vec![];
    for (name, prefix, product) in [("dot", "vlink", false), ("had", "vtest", true)] {
        let len = code.input_len << usize::from(product);
        helpers.push_str(&prefix_helpers(len.ilog2() as usize, name, length));
        let (sub, schema) = whir::subroutine(
            &child.coordinate_plan(len).unwrap(),
            &format!("open_{name}"),
        );
        helpers.push_str(&sub);
        schemas.push(schema);
        verify_blend(
            t,
            name,
            prefix,
            length,
            code.input_len,
            code.codeword_len,
            count,
            product,
        );
    }
    ProductGuest { helpers, schemas }
}

pub fn finish_mask(
    t: &mut Transcript,
    child: &PreparedMembership,
    params: &Parameters,
    guest: &mut ProductGuest,
) {
    coin(t, b"linear-batch", "linear_batch");
    read(t, "mask_claim", 3, false);
    super::endpoint::weights(t, child);
    t.frame(b"vectors", 32, |f| f.input("mask", 0, 32));
    field_frame(t, b"dot-claims", "mask_claim", 3);
    read(t, "mask_mask_dot", 3, false);
    field_frame(t, b"dot-mask", "mask_mask_dot", 3);
    coin(t, b"dot-blend", "mask_rho");
    read(t, "masked_root", 32, true);
    t.frame(b"dot-blend-commitment-v1", 32, |f| {
        f.input("masked_root", 0, 32)
    });
    t.src
        .push_str("    masked_expected = pcs_mac(mask_rho,mask_mask_dot,mask_claim)\n");
    let code = params.code(child.masked_messages() + 6, false).unwrap();
    let h = code.codeword_len.ilog2() as usize;
    let mut idx = 0;
    for depth in (0..h).rev().filter(|b| (code.queries >> b) & 1 != 0) {
        let low = h - depth;
        for stratum in 0..1usize << depth {
            t.integers(b"query", &[idx]);
            writeln!(
                t.src,
                "    vq{idx} = {} + query_index(s{}l0,{low})",
                stratum << low,
                t.index
            )
            .unwrap();
            idx += 1;
        }
    }
    let mut cap = Bytes::default();
    cap.input("mask", 0, 32);
    let halves = cap.words();
    writeln!(
        t.src,
        "    mcap = StackBuf(2)\n    mcap[0] = {}\n    mcap[1] = {}",
        halves[0], halves[1]
    )
    .unwrap();
    for j in 0..code.queries {
        writeln!(
            t.src,
            "    maskedrow{j}, vx{j} = check_mask_row(tabs,vq{j},mcap,mask_rho)"
        )
        .unwrap();
    }
    guest.helpers.push_str(&row_helpers(h, false));
    let n = code.input_len.ilog2() as usize;
    for count in [32, code.message_len % 32].into_iter().filter(|c| *c != 0) {
        writeln!(
            guest.helpers,
            "def mask_prefix_{count}(x, p, weights, total: StackBuf(3)):"
        )
        .unwrap();
        for j in 0..count {
            writeln!(guest.helpers,"    v = vector_generator(x + {},p,{n})\n    w = ext(weights[GEN ** {}],weights[GEN ** {}],weights[GEN ** {}])\n    total = pcs_mac(w,v,total)",cantor(j),3*j,3*j+1,3*j+2).unwrap();
        }
        guest.helpers.push_str("    return total\n\n");
    }
    let (sub, schema) = whir::subroutine(
        &child.coordinate_plan(code.input_len).unwrap(),
        "open_masked",
    );
    guest.helpers.push_str(&sub);
    guest.schemas.push(schema);
    verify_blend(
        t,
        "masked",
        "",
        code.message_len,
        code.input_len,
        code.codeword_len,
        code.queries,
        false,
    );
}
