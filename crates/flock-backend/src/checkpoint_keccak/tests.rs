use p3_binary_field::TowerLevel;
use p3_challenger::FieldChallenger;
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};
use p3_keccak::KeccakF;
use p3_multilinear_util::point::Point;
use p3_multilinear_util::poly::Poly;
use p3_sumcheck::generic_degree::{RoundPolyInterpolator, RoundProver};
use p3_symmetric::Permutation;
use sha3::{Digest, Keccak256};

use super::{
    BITS, Claim, E, F, MAX_BATCH_LOG, POSITION_LOG, POSITIONS, Proof, State,
    algebraic_error_degree, linear, prove, rounds::ChiSumcheck, verify,
};
use crate::config::{Challenger, challenger};

struct DenseChi {
    columns: [Poly<E>; 3],
    weights: Poly<E>,
}

impl RoundProver<E> for DenseChi {
    fn fold(&mut self, challenge: E) {
        for column in &mut self.columns {
            column.fix_prefix_var_mut(challenge);
        }
        self.weights.fix_prefix_var_mut(challenge);
    }

    fn round_poly(&self) -> Vec<E> {
        let half = self.weights.num_evals() / 2;
        (0..3)
            .map(|index| {
                let node: E = RoundPolyInterpolator::transmitted_node(index);
                let line = |poly: &Poly<E>, i: usize| {
                    poly.as_slice()[i] + node * (poly.as_slice()[i + half] - poly.as_slice()[i])
                };
                (0..half)
                    .map(|i| {
                        let [a, b, c] = self.columns.each_ref().map(|p| line(p, i));
                        line(&self.weights, i) * (a + c + b * c)
                    })
                    .sum()
            })
            .collect()
    }
}

#[test]
fn compact_chi_rounds_match_dense_sumcheck() {
    let mut ch = challenger(b"checkpoint-chi-differential");
    for (log, coordinate, first_challenge) in [
        (0, None, None),
        (1, None, None),
        (2, None, None),
        (3, None, None),
        (4, None, None), // exercise both the index-to-field transition and the next dense fold
        (3, Some(E::ZERO), Some(E::ZERO)),
        (3, Some(E::ONE), Some(E::ONE)),
        (3, Some(E::ZERO), Some(E::ONE)), // zero equality scale after the first fold
    ] {
        let states = inputs(1 << log);
        let target = Point::new(
            (0..log)
                .map(|_| coordinate.unwrap_or_else(|| ch.sample_algebra_element::<E>()))
                .collect::<Vec<_>>(),
        );
        let eq = target.equality_weights_msb();
        let weights = (0..BITS)
            .map(|_| ch.sample_algebra_element::<E>())
            .collect::<Vec<_>>();
        let mut compact = ChiSumcheck::new(states.clone(), target.as_slice(), weights.clone());
        let mut dense = DenseChi {
            columns: core::array::from_fn(|offset| {
                Poly::new(
                    (0..states.len() * POSITIONS)
                        .map(|i| {
                            let j = i % POSITIONS;
                            if j >= BITS {
                                E::ZERO
                            } else {
                                let shifted = linear::shift(j, offset);
                                E::from_bool(
                                    (states[i / POSITIONS][shifted / 64] >> (shifted % 64)) & 1
                                        != 0,
                                )
                            }
                        })
                        .collect(),
                )
            }),
            weights: Poly::new(
                (0..states.len() * POSITIONS)
                    .map(|i| {
                        if i % POSITIONS >= BITS {
                            E::ZERO
                        } else {
                            eq[i / POSITIONS] * weights[i % POSITIONS]
                        }
                    })
                    .collect(),
            ),
        };
        for round in 0..log + POSITION_LOG {
            let expected = dense.round_poly();
            let sum = (0..dense.weights.num_evals())
                .map(|i| {
                    let [a, b, c] = dense.columns.each_ref().map(|p| p.as_slice()[i]);
                    dense.weights.as_slice()[i] * (a + c + b * c)
                })
                .sum();
            assert_eq!(compact.round_poly(), expected, "log={log}, round={round}");
            assert_eq!(
                compact.round_poly_with_sum(sum),
                expected,
                "claimed: log={log}, round={round}"
            );
            let challenge = match round {
                0 => first_challenge.unwrap_or_else(|| ch.sample_algebra_element()),
                r if r % 5 == 3 => E::ZERO,
                r if r % 5 == 4 => E::ONE,
                _ => ch.sample_algebra_element(),
            };
            compact.fold(challenge);
            dense.fold(challenge);
        }
        assert_eq!(
            compact.terminal(),
            dense.columns.each_ref().map(|c| c.as_constant().unwrap())
        );
    }
}

pub(super) fn inputs(count: usize) -> Vec<State> {
    (0..count)
        .map(|i| {
            core::array::from_fn(|j| {
                ((i * 25 + j + 1) as u64)
                    .wrapping_mul(0x9e3779b97f4a7c15)
                    .rotate_left((j * 11) as u32)
            })
        })
        .collect()
}

fn evaluate(claim: &Claim, states: &[State]) -> E {
    let weights = Point::new(claim.instance.as_slice()).equality_weights_msb();
    states
        .iter()
        .zip(weights)
        .map(|(state, weight)| {
            weight
                * (0..BITS)
                    .filter(|&j| (state[j / 64] >> (j % 64)) & 1 != 0)
                    .map(|j| claim.weights[j])
                    .sum::<E>()
        })
        .sum()
}

fn context(inputs: &[State], outputs: &[State]) -> (Challenger, Claim) {
    let mut hash = Keccak256::new();
    hash.update(b"checkpoint-keccak-reduction-test");
    hash.update((inputs.len() as u64).to_le_bytes());
    for state in inputs.iter().chain(outputs) {
        for word in state {
            hash.update(word.to_le_bytes());
        }
    }
    let mut ch = challenger(&hash.finalize());
    let instance = (0..inputs.len().trailing_zeros())
        .map(|_| ch.sample_algebra_element())
        .collect();
    let point = Point::new(
        (0..POSITION_LOG)
            .map(|_| ch.sample_algebra_element::<E>())
            .collect::<Vec<_>>(),
    );
    let mut weights = point.equality_weights_msb();
    weights.truncate(BITS);
    let mut claim = Claim {
        instance,
        weights,
        value: E::ZERO,
    };
    claim.value = evaluate(&claim, outputs);
    (ch, claim)
}

fn closes(proof: &Proof, claim: &Claim, states: &[State], ch: &Challenger) -> bool {
    verify(
        proof,
        claim,
        states.len().trailing_zeros() as usize,
        &mut ch.clone(),
    )
    .is_ok_and(|input| input.value == evaluate(&input, states))
}

#[test]
fn keccak_linear_transpose_and_rounds_match_reference() {
    let weights = (0..BITS)
        .map(|j| {
            E::from_basis_coefficients_fn(|k| {
                F::from_repr(
                    (j as u64 + 1)
                        .wrapping_mul(0x123456789abcdef1)
                        .rotate_left(19 * k as u32),
                )
            })
        })
        .collect::<Vec<_>>();
    let transposed = linear::transpose(&weights);
    for input in inputs(8) {
        let claim = Claim {
            instance: vec![],
            weights: weights.clone(),
            value: E::ZERO,
        };
        let before = evaluate(&claim, &[linear::forward(&input)]);
        let original = Claim {
            weights: transposed.clone(),
            ..claim
        };
        assert_eq!(before, evaluate(&original, &[input]));
        let mut actual = input;
        for round in 0..24 {
            actual = linear::finish_round(&linear::forward(&actual), round);
        }
        assert_eq!(actual, KeccakF.permute(input));
    }
}

#[test]
fn checkpoint_reduction_closes_on_original_inputs_and_rejects_tampering() {
    for count in [1, 2, 8] {
        let states = inputs(count);
        let outputs = states
            .iter()
            .map(|&s| KeccakF.permute(s))
            .collect::<Vec<_>>();
        let (ch, claim) = context(&states, &outputs);
        let (proof, input) = prove(&states, &claim, &mut ch.clone()).unwrap();
        assert_eq!(input.value, evaluate(&input, &states));
        let bytes = postcard::to_allocvec(&proof).unwrap();
        let restored: Proof = postcard::from_bytes(&bytes).unwrap();
        assert!(closes(&restored, &claim, &states, &ch));
        assert_eq!(
            verify(
                &restored,
                &claim,
                count.trailing_zeros() as usize,
                &mut ch.clone()
            )
            .unwrap(),
            input
        );
        for layer in [0, 12, 23] {
            let mut changed = proof.clone();
            changed.layers[layer].sumcheck.round_polys[0][0] += E::ONE;
            assert!(!closes(&changed, &claim, &states, &ch));
            changed = proof.clone();
            changed.layers[layer].values[1] += E::ONE;
            assert!(!closes(&changed, &claim, &states, &ch));
        }
        let mut changed = proof.clone();
        changed.layers.pop();
        assert!(!closes(&changed, &claim, &states, &ch));
        changed = proof.clone();
        changed.layers[0].sumcheck.pow_witnesses.push(F::ONE);
        assert!(!closes(&changed, &claim, &states, &ch));
        changed = proof.clone();
        changed.layers[0].sumcheck.round_polys.pop();
        assert!(!closes(&changed, &claim, &states, &ch));
        let mut wrong_input = states.clone();
        wrong_input[0][0] ^= 1;
        assert!(!closes(&proof, &claim, &wrong_input, &ch));
        let mut wrong_claim = claim.clone();
        wrong_claim.value += E::ONE;
        assert!(!closes(&proof, &wrong_claim, &states, &ch));
        wrong_claim = claim.clone();
        wrong_claim.weights[0] += E::ONE;
        assert!(!closes(&proof, &wrong_claim, &states, &ch));
        assert!(!closes(
            &proof,
            &claim,
            &states,
            &challenger(b"wrong-context")
        ));

        // No native validity gate prevents a forged output claim reaching the prover.
        // Closing the actual reduction must still reject it.
        let mut forged = claim.clone();
        forged.value += E::ONE;
        let (forged_proof, _) = prove(&states, &forged, &mut ch.clone()).unwrap();
        assert!(!closes(&forged_proof, &forged, &states, &ch));
    }
}

#[test]
fn checkpoint_shapes_and_conditional_error_budget_are_bounded() {
    let states = inputs(2);
    let outputs = states
        .iter()
        .map(|&s| KeccakF.permute(s))
        .collect::<Vec<_>>();
    let (ch, mut claim) = context(&states, &outputs);
    claim.weights.pop();
    assert!(prove(&states, &claim, &mut ch.clone()).is_err());
    claim.weights.push(E::ZERO);
    claim.instance.clear();
    assert!(prove(&states, &claim, &mut ch.clone()).is_err());
    assert!(prove(&[], &claim, &mut ch.clone()).is_err());
    let degree = algebraic_error_degree(MAX_BATCH_LOG).unwrap();
    assert_eq!(degree, 2568);
    assert!(192.0 - (degree as f64).log2() > 180.0);
    assert!(algebraic_error_degree(MAX_BATCH_LOG + 1).is_err());
}
