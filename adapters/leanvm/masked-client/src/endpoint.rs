//! Compile the native AIR's affine and product relations. A reverse pass
//! collects each wire's coefficient in the batched linear constraint.
use super::guest::Transcript;
use p3_binary_field::TowerLevel;
use recursive_imt_prover::binary::veil::child::{
    PreparedMembership, checkpoint::EndpointGate as Gate,
};
use std::{collections::BTreeMap, fmt::Write};

struct Algebra<'a> {
    src: &'a mut String,
    next: usize,
}
impl Algebra<'_> {
    fn bind(&mut self, expr: String) -> String {
        let n = format!("ep{}", self.next);
        self.next += 1;
        writeln!(self.src, "    {n} = {expr}").unwrap();
        n
    }
    fn mul(&mut self, x: &str, y: &str) -> String {
        if x == "zero" || y == "zero" {
            return "zero".into();
        }
        if x == "one" {
            return y.into();
        }
        if y == "one" {
            return x.into();
        }
        self.bind(format!("times({x},{y})"))
    }
    fn add(&mut self, x: &str, y: &str) -> String {
        if x == "zero" {
            return y.into();
        }
        if y == "zero" {
            return x.into();
        }
        if x == y {
            return "zero".into();
        }
        self.bind(format!("plus({x},{y})"))
    }
    fn powers(&mut self, x: &str, n: usize) -> Vec<String> {
        let mut p = vec!["one".to_owned()];
        for _ in 1..n {
            p.push(self.mul(p.last().unwrap(), x));
        }
        p
    }
    fn at(&mut self, buf: &str, j: usize) -> String {
        let i = 3 * j;
        self.bind(format!("ext({buf}[{i}],{buf}[{}],{buf}[{}])", i + 1, i + 2))
    }
    fn field_from_bytes(&mut self, buf: &str, j: usize) -> String {
        let words = (0..3)
            .map(|k| {
                (0..8)
                    .map(|b| format!("{} * {buf}[{}]", 1u64 << (8 * b), 24 * j + 8 * k + b))
                    .collect::<Vec<_>>()
                    .join(" + ")
            })
            .collect::<Vec<_>>()
            .join(",");
        self.bind(format!("ext({words})"))
    }
}

/// The returned heap table holds the coefficients used again by the mask opening.
pub fn weights(t: &mut Transcript, c: &PreparedMembership) {
    let program = c.endpoint_program();
    let mut a = Algebra {
        src: &mut t.src,
        next: 0,
    };
    a.src
        .push_str("    zero = ext(0,0,0)\n    one = ext(1,0,0)\n");
    let height = c.trace_height().ilog2() as usize;
    let air_alpha = a.bind(format!(
        "ext(s{}l0,s{}l1,s{}l2)",
        t.challenges[0], t.challenges[0], t.challenges[0]
    ));
    let mut boolean = vec!["one".to_string()];
    let mut eq = "one".to_owned();
    for j in 0..height {
        let p = a.at("air_point", j);
        let tau = t.challenges[2 + j];
        let tau = a.bind(format!("ext(s{tau}l0,s{tau}l1,s{tau}l2)"));
        let d = a.add(&tau, &p);
        let e = a.add("one", &d);
        eq = a.mul(&eq, &e);
        let mut layer = Vec::with_capacity(2 * boolean.len());
        for w in boolean {
            let hi = a.mul(&w, &p);
            layer.push(a.add(&w, &hi));
            layer.push(hi);
        }
        boolean = layer;
    }
    let first = &boolean[0];
    let last = boolean.last().unwrap();
    let transition = a.add("one", last);
    let mut prep = vec![];
    for col in program.preprocessing {
        let mut groups = BTreeMap::<[u64; 3], String>::new();
        for (v, w) in col.iter().zip(&boolean) {
            let limbs = v.coefficients().map(|k| k.to_repr());
            if limbs != [0; 3] {
                let sum = groups.entry(limbs).or_insert_with(|| "zero".to_string());
                *sum = a.add(sum, w);
            }
        }
        let mut value = "zero".to_string();
        for ([x, y, z], w) in groups {
            let f = if [x, y, z] == [1, 0, 0] {
                w
            } else {
                let k = a.bind(format!("ext({x},{y},{z})"));
                a.mul(&w, &k)
            };
            value = a.add(&value, &f);
        }
        prep.push(value);
    }
    let mut publics = vec![String::new(); program.gates.len()];
    for (i, &gate) in program.gates.iter().enumerate() {
        if program.private[i] {
            continue;
        }
        publics[i] = match gate {
            Gate::Main(..) => unreachable!(),
            Gate::Add(l, r) => a.add(&publics[l], &publics[r]),
            Gate::Mul(l, r) => a.mul(&publics[l], &publics[r]),
            Gate::Constant(v) => match v.to_repr() {
                0 => "zero".into(),
                1 => "one".into(),
                k => a.bind(format!("ext({k},0,0)")),
            },
            Gate::Public(j) if j < 32 => a.bind(format!("ext(root[{j}],0,0)")),
            Gate::Public(_) | Gate::Preprocessed(1, _) => "zero".into(),
            Gate::Preprocessed(0, j) => prep[j].clone(),
            Gate::Preprocessed(..) => unreachable!(),
            Gate::First => first.clone(),
            Gate::Last => last.clone(),
            Gate::Transition => transition.clone(),
        };
    }
    let n = c.masked_messages();
    let rounds = c.air_program().message_count();
    let cols = c.trace_width();
    let stack = c.stacking_factor();
    let width = cols.div_ceil(stack);
    let powers = a.powers("alpha", width + 1);
    let slots = a.powers("theta", stack);
    let batch = a.powers("linear_batch", 6);
    let mut wire = vec!["zero".to_string(); n + 6];
    let mut constant = "zero".to_string();
    // Two stacked views, followed by the native AIR sumcheck endpoint.
    for view in 0..2 {
        let evaluation = a.field_from_bytes("evaluations", view);
        let cv = a.mul(&batch[view], &evaluation);
        constant = a.add(&constant, &cv);
        wire[rounds + 2 * cols + view] = a.mul(&batch[view], &powers[width]);
        for j in 0..cols {
            let w = a.mul(&powers[j / stack], &slots[j % stack]);
            wire[rounds + view * cols + j] = a.mul(&batch[view], &w);
        }
    }
    for (j, w) in wire.iter_mut().take(rounds).enumerate() {
        let v = a.bind(format!("ext(weight{j}l0,weight{j}l1,weight{j}l2)"));
        *w = a.mul(&batch[2], &v);
    }
    let mut adj = vec!["zero".to_string(); program.gates.len()];
    let mut scale = a.mul(&eq, &batch[2]);
    for &gate in program.outputs.iter().rev() {
        adj[gate] = a.add(&adj[gate], &scale);
        scale = a.mul(&scale, &air_alpha);
    }
    let start = n - c.verifier_products();
    assert_eq!(start, rounds + 2 * cols + 2);
    let mut idx = 0;
    let mut product_wire = vec![None; program.gates.len()];
    let mut link = "one".to_string();
    for (i, &gate) in program.gates.iter().enumerate() {
        if let Gate::Mul(l, r) = gate
            && program.private[l]
            && program.private[r]
        {
            for (j, dest) in [l, r, i].into_iter().enumerate() {
                let w = a.mul(&batch[3 + j], &link);
                adj[dest] = a.add(&adj[dest], &w);
            }
            product_wire[i] = Some(start + idx);
            idx += 1;
            link = a.mul(&link, "vlink");
        }
    }
    assert_eq!(idx, c.verifier_products());
    for triple in 0..2 {
        for j in 0..3 {
            wire[n + 3 * triple + j] = a.mul(&batch[3 + j], &link);
        }
        link = a.mul(&link, "vlink");
    }
    for j in 0..3 {
        let v = a.at("product_claims", j);
        let term = a.mul(&v, &batch[3 + j]);
        constant = a.add(&constant, &term);
    }
    for (i, &gate) in program.gates.iter().enumerate().rev() {
        let w = adj[i].clone();
        if w == "zero" {
            continue;
        }
        if !program.private[i] {
            let term = a.mul(&w, &publics[i]);
            constant = a.add(&constant, &term);
            continue;
        }
        match gate {
            Gate::Main(view, j) => {
                let j = rounds + cols * view + j;
                wire[j] = a.add(&wire[j], &w);
            }
            Gate::Add(l, r) => {
                adj[l] = a.add(&adj[l], &w);
                adj[r] = a.add(&adj[r], &w);
            }
            Gate::Mul(l, r) => {
                if let Some(j) = product_wire[i] {
                    wire[j] = a.add(&wire[j], &w);
                } else {
                    let (scalar, other) = if program.private[l] {
                        (&publics[r], l)
                    } else {
                        (&publics[l], r)
                    };
                    let term = a.mul(&w, scalar);
                    adj[other] = a.add(&adj[other], &term);
                }
            }
            _ => unreachable!(),
        }
    }
    writeln!(
        a.src,
        "    mask_weights = HeapBuf({})\n    affine = {constant}",
        3 * wire.len()
    )
    .unwrap();
    for (j, w) in wire.iter().enumerate() {
        let v = if j < rounds {
            a.field_from_bytes("rounds", j)
        } else if j < rounds + 2 * cols {
            a.at("column_fields", j - rounds)
        } else if j < start {
            a.field_from_bytes("masks", j - rounds - 2 * cols)
        } else if j < n {
            a.at("product_wires", j - start)
        } else {
            a.at("padding", j - n)
        };
        writeln!(a.src, "    affine = pcs_mac({w},{v},affine)").unwrap();
        for k in 0..3 {
            writeln!(a.src, "    mask_weights[GEN ** {}] = {w}[{k}]", 3 * j + k).unwrap();
        }
    }
    a.src.push_str("    pcs_equal(affine,mask_claim)\n");
}
