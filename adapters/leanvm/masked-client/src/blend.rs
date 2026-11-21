//! Verify the public quadratic sumcheck leading into the stacked oracle WHIR opening.
use super::guest::{Bytes, Transcript};
use p3_binary_field::{Poly64, TowerLevel};
use recursive_imt_prover::binary::veil::{child::PreparedMembership, parameters::Parameters};
use std::fmt::Write;

pub(super) const DOMAIN: &[u8; 16] = b"IMT-BLEND-CHK-01";

pub(super) fn helpers(
    child: &PreparedMembership,
    parameters: &Parameters,
) -> (String, &'static str) {
    let (_, h) = child
        .stacked_query_geometry()
        .expect("fixed oracle geometry");
    let cantor = (0..h)
        .map(|i| Poly64::cantor_basis(i).to_repr().to_string())
        .collect::<Vec<_>>()
        .join(", ");
    let prelude = format!(
        "ORACLE_HEIGHT = {h}\nBLEND_VARS = {}\nSTACK_VARS = {}\nAIR_VARS = {}\nCANTOR_SHIFT = {}\nCANTOR = [{cantor}]\n",
        h - parameters.log_inv_rate,
        child.stacking_factor().ilog2(),
        child.trace_height().ilog2(),
        Poly64::cantor_basis(h).to_repr()
    );
    (prelude, include_str!("blend.py"))
}

fn field(name: &str) -> impl Iterator<Item = String> + '_ {
    (0..3).map(move |k| format!("{name}[{k}]"))
}

fn coin(t: &mut Transcript, label: &[u8], name: &str) {
    t.coin(label);
    let i = t.index;
    writeln!(t.src, "    {name} = ext(s{i}l0, s{i}l1, s{i}l2)").unwrap();
}

fn from_bytes(name: &str, first: usize) -> String {
    let words = (0..3)
        .map(|k| {
            (0..8)
                .map(|b| format!("{} * {name}[{}]", 1u64 << (8 * b), first + 8 * k + b))
                .collect::<Vec<_>>()
                .join(" + ")
        })
        .collect::<Vec<_>>()
        .join(", ");
    format!("ext({words})")
}

pub(super) fn reduction(
    t: &mut Transcript,
    child: &PreparedMembership,
    params: &Parameters,
    summary: &mut Bytes,
) {
    let (count, h) = child
        .stacked_query_geometry()
        .expect("fixed oracle geometry");
    let air = child.trace_height().ilog2() as usize;
    let vars = h - params.log_inv_rate;
    let log_stack = child.stacking_factor().ilog2() as usize;
    t.frame(b"stacked-blend-rows", 24 * count, |f| {
        f.lanes((0..count).flat_map(|i| field(&format!("v{i}")).collect::<Vec<_>>()));
    });
    coin(t, b"stacked-functional-batch", "beta");
    t.src.push_str("    total = ext(0, 0, 0)\n");
    for i in (0..count).rev() {
        writeln!(
            t.src,
            "    part = times(total, beta)\n    total = plus(v{i}, part)"
        )
        .unwrap();
    }
    for i in (0..2).rev() {
        writeln!(
            t.src,
            "    item = {}\n    part = times(total, beta)\n    total = plus(item, part)",
            from_bytes("evaluations", 24 * i)
        )
        .unwrap();
    }
    t.frame(b"blend-whir-commitment", 32, |f| f.input("blend", 0, 32));
    t.integers(
        b"coefficient-functional-v2",
        &[
            air,
            child.trace_width(),
            log_stack,
            1 << vars,
            1 << h,
            count,
        ],
    );
    t.integers(b"stacked-oracle-view-count", &[2]);
    for view in 0..2 {
        t.integers(b"stacked-oracle-view", &[view, air]);
        t.frame(b"stacked-oracle-point", 24 * air, |f| {
            f.input("point", 0, 24 * air)
        });
    }
    t.frame(b"coefficient-functional-indices", 8 * count, |f| {
        f.lanes((0..count).map(|i| format!("q{i}")))
    });
    t.frame(b"coefficient-functional-challenges", 48, |f| {
        f.lanes(field("theta").chain(field("beta")))
    });
    t.frame(b"blend-functional-sum", 24, |f| f.lanes(field("total")));
    t.src.push_str("    claim = total\n");
    writeln!(t.src, "    opening_point = StackBuf({})", 3 * vars).unwrap();
    for j in 0..vars {
        t.src.push_str("    msg = StackBuf(6)\n    hint_witness(msg, \"sumcheck\")\n    for k in unroll(0, 3):\n        assert_in_k(msg[2*k], msg[2*k+1])\n");
        t.frame(b"blend-sumcheck-round", 48, |f| {
            f.lanes((0..6).map(|k| format!("msg[{k}]")))
        });
        coin(t, b"blend-sumcheck-challenge", "r");
        t.src.push_str("    c0 = ext(msg[0], msg[1], msg[2])\n    cinf = ext(msg[3], msg[4], msg[5])\n    one = ext(1, 0, 0)\n    r1 = plus(one, r)\n    quad = times(r1, cinf)\n    linear = plus(claim, quad)\n    sr = times(r, linear)\n    claim = plus(c0, sr)\n");
        for k in 0..3 {
            writeln!(t.src, "    opening_point[{}] = r[{k}]", 3 * j + k).unwrap();
        }
    }
    writeln!(t.src, "    air_point = StackBuf({})", 3 * air).unwrap();
    for (j, &i) in t.challenges[2 + air..].iter().enumerate() {
        for k in 0..3 {
            writeln!(t.src, "    air_point[{}] = s{i}l{k}", 3 * j + k).unwrap();
        }
    }
    t.src.push_str("    weight = view_weight(air_point, opening_point, theta, beta)\n    power = times(beta, beta)\n");
    for i in 0..count {
        writeln!(t.src,"    generated = generator_weight(q{i}, opening_point)\n    part = times(power, generated)\n    weight = plus(weight, part)\n    power = times(power, beta)").unwrap();
    }
    t.src.push_str("    value = StackBuf(3)\n    hint_witness(value, \"blend_value\")\n    assert_in_k(value[0], value[1])\n    assert_in_k(value[2], value[2])\n    endpoint = times(weight, value)\n    check_blend_endpoint(claim, endpoint)\n");
    t.frame(b"blend-sumcheck-terminal", 24, |f| f.lanes(field("value")));
    summary.state(t.index, 4);
    summary.lanes(
        (0..3 * vars)
            .map(|k| format!("opening_point[{k}]"))
            .chain(field("value")),
    );
}
