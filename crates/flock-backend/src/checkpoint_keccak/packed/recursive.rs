//! Replay the component with the parent circuit's Poly192 and Keccak gadgets.
//! Only the commitment is public. Every reduction ends at a checked WHIR opening.
use super::super::recursive::{
    Weights, connect, equality_weights, observe, observe_base, sample, sumcheck_values,
};
use super::{
    BITS, Batch, E, Kernel, Layer, Openings, POSITION_LOG, Proof, Schedule, Statement,
    circuit::{dot, product, sum},
    closing,
};
use anyhow::{Result, ensure};
use old_binary_field::Poly64 as CF;
use p3_circuit::{CircuitBuilder, ops::NativePoly192Target as T};
use p3_recursion::{
    BinaryTower128Challenger as Ch, pcs::binary::BinaryPolyGenericSumcheckVerifier,
};

type Builder = CircuitBuilder<CF>;

pub(crate) struct Terminals {
    pub points: Vec<Vec<T>>,
    products: Vec<(T, T)>,
    words: Vec<T>,
}

impl Terminals {
    pub(crate) fn authenticate(
        &self,
        b: &mut Builder,
        opened: &[old_sumcheck::OpeningBatch<T>],
    ) -> Result<()> {
        ensure!(
            opened.len() == self.products.len() + 1,
            "incorrect recursive boundary count"
        );
        for ((weight, product), batch) in self.products.iter().zip(opened) {
            ensure!(
                batch.current().len() == 1,
                "incorrect recursive bit column count"
            );
            let value = b.native_poly192_mul(weight, &batch.current()[0]);
            connect(b, &value, product);
        }
        let output = opened.last().unwrap().current();
        ensure!(
            output.len() == self.words.len(),
            "incorrect recursive word count"
        );
        for (a, w) in output.iter().zip(&self.words) {
            connect(b, a, w);
        }
        Ok(())
    }
}

fn input(b: &mut Builder, data: &mut Vec<CF>, v: E) -> T {
    data.extend(v.coefficients().map(|c| CF::new(c.to_bits())));
    let cells = b.alloc_private_input_array::<3>("Keccak reduction value");
    b.native_poly192_from_coefficients(cells)
}

fn check_sum(
    b: &mut Builder,
    private: &mut Vec<CF>,
    rounds: usize,
    degree: usize,
    proof: &closing::Proof,
    expected: &T,
    ch: Ch,
) -> Result<(Vec<T>, T, Ch)> {
    let verifier = BinaryPolyGenericSumcheckVerifier::new(rounds, degree, 0)?;
    let targets = verifier.input_shape().allocate_native_targets(b)?;
    private.extend(sumcheck_values(proof, rounds, degree)?);
    let reduction = verifier.verify_reduction_native(b, ch, expected, &targets)?;
    Ok((reduction.point, reduction.claim, reduction.challenger))
}

impl Batch {
    pub fn recursive_cost(
        &self,
        statement: &Statement,
        proof: &Proof,
        context: &[u8],
    ) -> Result<crate::opening_bench::CircuitCost> {
        ensure!(
            self.mode == Openings::Joint,
            "expected joint WHIR for the closed component circuit"
        );
        self.verify(statement, proof, context)?;
        let entry = crate::verifier::CircuitInput {
            log_inv_rate: crate::WHIR_LOG_INV_RATE,
            root: statement.commitments[0].clone(),
            proof: proof.openings[0].clone(),
            protocol: self.groups[0].1.clone(),
            widths: vec![vec![1], vec![64; 25]],
            points: vec![],
            opened: vec![],
        };
        crate::verifier::check_component(entry, &self.seed(context), self, proof)
    }

    pub(crate) fn circuit_reduction(
        &self,
        b: &mut Builder,
        private: &mut Vec<CF>,
        mut ch: Ch,
        proof: &Proof,
    ) -> Result<(Terminals, Ch)> {
        let row = (0..self.log)
            .map(|_| sample(b, &mut ch))
            .collect::<Result<Vec<_>>>()?;
        let words = proof.output.map(|v| input(b, private, v));
        for word in &words {
            observe(b, &mut ch, word)?;
        }
        let pos = (0..5)
            .map(|_| sample(b, &mut ch))
            .collect::<Result<Vec<_>>>()?;
        let word_weights = equality_weights(b, &pos);
        let mut value = dot(b, &words, &word_weights[..25]);
        let mut weights = Weights::Dense(
            (0..BITS)
                .map(|j| {
                    let bit = b.native_poly192_constant([1 << (j % 64), 0, 0]);
                    b.native_poly192_mul(&word_weights[j / 64], &bit)
                })
                .collect(),
        );
        let one = b.native_poly192_constant([1, 0, 0]);
        let packed = self.kernel == Kernel::Packed16;
        let mut instance = row.clone();
        let mut lanes = if packed {
            equality_weights(b, &instance.split_off(self.log - 4))
        } else {
            vec![one.clone()]
        };
        let mut points = Vec::new();
        let mut products = Vec::new();
        if let Some(mid) = &proof.midpoint {
            let middle = input(b, private, mid.claimed_sum);
            let (position, product, next) =
                check_sum(b, private, POSITION_LOG, 2, mid, &middle, ch)?;
            ch = next;
            products.push((weights.evaluate(b, &position), product));
            points.push([vec![one.clone()], row.clone(), position].concat());
            observe(b, &mut ch, &middle)?;
            let segment = sample(b, &mut ch)?;
            let diff = b.native_poly192_add(&middle, &value);
            let term = b.native_poly192_mul(&segment, &diff);
            value = b.native_poly192_add(&middle, &term);
            instance.insert(0, segment);
        }
        for (round, layer) in (0..self.schedule.depth()).rev().zip(&proof.layers) {
            let index = b.define_const(CF::new(round as u64));
            observe_base(b, &mut ch, index)?;
            let mut constant = weights.iota(b, crate::keccak::RC[round]);
            if self.schedule == Schedule::Midpoint {
                let other = weights.iota(b, crate::keccak::RC[round + 12]);
                let diff = b.native_poly192_add(&constant, &other);
                let term = b.native_poly192_mul(&instance[0], &diff);
                constant = b.native_poly192_add(&constant, &term);
            }
            let lane_sum = sum(b, lanes.iter().cloned());
            let iota = b.native_poly192_mul(&constant, &lane_sum);
            let expected = b.native_poly192_add(&value, &iota);
            let (initial, sc, values) = match layer {
                Layer::Packed(p) => {
                    ensure!(
                        p.coefficients.len() == 47 && packed,
                        "incorrect recursive RMFE shape"
                    );
                    let coeff: Vec<_> = p
                        .coefficients
                        .iter()
                        .map(|&v| input(b, private, v))
                        .collect();
                    let (initial, next_lanes) = product(b, &mut ch, &coeff, &lanes, &expected)?;
                    lanes = next_lanes;
                    (initial, &p.sumcheck, p.values)
                }
                Layer::Scalar(p) => {
                    ensure!(!packed, "incorrect recursive scalar shape");
                    (expected, &p.sumcheck, p.values)
                }
            };
            let (q, claim, next) = check_sum(
                b,
                private,
                instance.len() + POSITION_LOG,
                3,
                sc,
                &initial,
                ch,
            )?;
            ch = next;
            let (r, z) = q.split_at(instance.len());
            let mut eq = one.clone();
            for (a, c) in instance.iter().zip(r) {
                let diff = b.native_poly192_add(a, c);
                let factor = b.native_poly192_add(&one, &diff);
                eq = b.native_poly192_mul(&eq, &factor);
            }
            let abc = values.map(|v| input(b, private, v));
            let [a, y, c] = &abc;
            let product = b.native_poly192_mul(y, c);
            let linear = b.native_poly192_add(a, c);
            let k = sum(b, lanes.iter().cloned());
            let scaled = b.native_poly192_mul(&k, &linear);
            let chi = b.native_poly192_add(&scaled, &product);
            let w = weights.evaluate(b, z);
            let scale = b.native_poly192_mul(&eq, &w);
            let terminal = b.native_poly192_mul(&scale, &chi);
            connect(b, &terminal, &claim);
            for v in &abc {
                observe(b, &mut ch, v)?;
            }
            let beta = sample(b, &mut ch)?;
            let square = b.native_poly192_square(&beta);
            weights = Weights::linear_chi(b, z, &beta, &square);
            let y = b.native_poly192_mul(&beta, y);
            let c = b.native_poly192_mul(&square, c);
            value = sum(b, [a.clone(), y, c]);
            instance = r.to_vec();
        }
        let lane_log = if packed { 4 } else { 0 };
        let (q, product, ch) = check_sum(
            b,
            private,
            lane_log + POSITION_LOG,
            2,
            &proof.closing,
            &value,
            ch,
        )?;
        let (i, z) = q.split_at(lane_log);
        let mut weight = weights.evaluate(b, z);
        if packed {
            let eq = equality_weights(b, i);
            let scale = dot(b, &lanes, &eq);
            weight = b.native_poly192_mul(&scale, &weight);
        }
        products.push((weight, product));
        instance.extend(q);
        points.extend([instance, row]);
        Ok((
            Terminals {
                points,
                products,
                words: words.to_vec(),
            },
            ch,
        ))
    }
}
