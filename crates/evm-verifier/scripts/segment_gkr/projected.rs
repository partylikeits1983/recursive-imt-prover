//! Witness-side projection for gates linear in the coordinates they preserve.
use super::sumcheck::{
    iota::{IotaProof, prove_sumcheck_iota},
    rho::{RhoProof, prove_sumcheck_rho},
    util::{
        calculate_evaluations_over_boolean_hypercube_for_eq as eq_table,
        calculate_evaluations_over_boolean_hypercube_for_rot as rot_table, eval_mle, to_poly,
    },
};
use super::transcript::Prover;
use crate::scalar::Fr;
use ark_ff::{AdditiveGroup, Zero};
use rayon::prelude::*;

/// Project the row coordinates of each lane, retaining 'groups' segments and 64 bit positions.
pub fn bits(words: &[u64], prefix: &[Fr], groups: usize) -> Vec<Vec<Fr>> {
    let weights = eq_table(prefix);
    let stride = weights.len() * groups;
    assert_eq!(words.len() % stride, 0);
    words
        .par_chunks_exact(stride)
        .map(|lane| {
            let mut result = vec![Fr::ZERO; groups * 64];
            for group in 0..groups {
                let mut bins = vec![[Fr::ZERO; 256]; 8];
                for (&word, &weight) in lane[group..].iter().step_by(groups).zip(&weights) {
                    for (hist, byte) in bins.iter_mut().zip(word.to_le_bytes()) {
                        hist[byte as usize] += weight;
                    }
                }
                for (i, hist) in bins.iter().enumerate() {
                    for bit in 0..8 {
                        result[64 * group + 8 * i + bit] = hist
                            .iter()
                            .enumerate()
                            .filter(|(v, _)| v & (1 << bit) != 0)
                            .map(|(_, x)| *x)
                            .sum();
                    }
                }
            }
            result
        })
        .collect()
}

pub fn readings(lanes: &[u64], point: &[Fr]) -> Vec<Fr> {
    let last = point.len() - 6;
    bits(lanes, &point[..last], 1)
        .iter()
        .map(|lane| eval_mle(lane, &point[last..]))
        .collect()
}

pub fn iota(
    p: &mut Prover,
    r: &[Fr],
    beta: &[Fr],
    chi: &[u64],
    sum: Fr,
    rc: &[u64; 8],
) -> IotaProof {
    let prefix = r.len() - 9;
    let mut state = bits(chi, &r[..prefix], 8);
    let mut rest = vec![Fr::zero(); 512];
    for (word, b) in state[1..].iter().zip(&beta[1..]) {
        for (z, v) in rest.iter_mut().zip(word) {
            *z += *b * v;
        }
    }
    let mut proof = prove_sumcheck_iota(
        p,
        9,
        beta[0],
        &mut eq_table(&r[prefix..]),
        &mut state[0],
        &mut to_poly(rc),
        &mut rest,
        sum,
    );
    proof.r = [&r[..prefix], &proof.r].concat();
    proof
}

pub fn rho(p: &mut Prover, r: &[Fr], beta: &[Fr], theta: &[u64], sum: Fr) -> RhoProof {
    let prefix = r.len() - 6;
    let mut state = bits(theta, &r[..prefix], 1);
    let mut rotations = (0..25).map(|lane| rot_table(&r[prefix..], lane)).collect();
    let mut proof = prove_sumcheck_rho(p, 6, beta, &mut rotations, &mut state, sum);
    proof.r = [&r[..prefix], &proof.r].concat();
    proof
}

use crate::{
    keccacheck_og::{prover::prove_round, verifier::verify_round},
    reference::{KeccakRoundState, ROUND_CONSTANTS, keccak_round},
    transcript::Verifier,
};
use ark_ff::{Field, PrimeField};

/// Rebuild just the round needed by the backward reduction from the packed input.
fn layer(data: &[u64], step: usize) -> KeccakRoundState {
    let instances = data.len() / 25;
    let mut words = data.to_vec();
    for k in 0..=step {
        let mut state = keccak_round(&words, k);
        for (i, value) in state.iota[..instances].iter_mut().enumerate() {
            *value = state.pi_chi[i] ^ ROUND_CONSTANTS[3 * (i % 8) + k];
        }
        if k == step {
            return state;
        }
        words = state.iota;
    }
    unreachable!()
}

fn messages(instance: &[u8; 32], point: &[Fr], lanes: &[Fr]) -> Vec<Fr> {
    assert_eq!(lanes.len(), 25);
    let mut messages: Vec<_> = instance
        .chunks_exact(16)
        .map(Fr::from_be_bytes_mod_order)
        .collect();
    messages.push(Fr::from(point.len() as u64));
    messages.extend(point);
    messages.extend(lanes);
    messages
}

pub fn prove_bits(input: &[u64], instance: &[u8; 32], point: &[Fr], lanes: &[Fr]) -> Vec<Fr> {
    let mut p = Prover::bit_claims();
    for value in messages(instance, point, lanes) {
        p.absorb(value);
    }
    let mut b: Vec<_> = (0..25).map(|_| p.read()).collect();
    let mut s = b.iter().zip(lanes).map(|(a, x)| *a * x).sum();
    let n = point.len();
    assert_eq!(input.len(), 25 * (1 << (n - 6)));
    let mut r = point.to_vec();
    for step in (0..3).rev() {
        let start = std::time::Instant::now();
        let state = layer(input, step);
        let rc = std::array::from_fn(|i| ROUND_CONSTANTS[3 * i + step]);
        let result = prove_round(&mut p, n, &state, &r, &mut b, s, &rc, true);
        r = result.r;
        if step != 0 {
            s = Fr::ZERO;
            for (w, h) in b.iter_mut().zip(result.iota_hat) {
                *w = p.read();
                s += *w * ((Fr::ONE - h) * crate::sumcheck::util::HALF);
            }
        }
        println!("segment step {step} proved in {:.2?}", start.elapsed());
    }
    p.finish()
}

pub fn verify_bits(
    input: &[u64],
    instance: &[u8; 32],
    point: &[Fr],
    lanes: &[Fr],
    proof: &[Fr],
) -> (Vec<Fr>, Vec<Fr>) {
    let mut v = Verifier::bit_claims(proof);
    for value in messages(instance, point, lanes) {
        v.absorb(value);
    }
    let mut beta: Vec<_> = (0..25).map(|_| v.generate()).collect();
    let mut s = beta.iter().zip(lanes).map(|(a, x)| *a * x).sum();
    let mut r = point.to_vec();
    let mut bits = Vec::new();
    for step in (0..3).rev() {
        (r, bits) = verify_round(
            &mut v,
            point.len(),
            &r,
            &mut beta,
            s,
            &std::array::from_fn(|i| ROUND_CONSTANTS[3 * i + step]),
            true,
        );
        if step != 0 {
            s = Fr::ZERO;
            for (b, x) in beta.iter_mut().zip(&bits) {
                *b = v.generate();
                s += *b * x;
            }
        }
    }
    assert!(v.remaining().is_empty());
    assert_eq!(bits, readings(input, &r));
    (r, bits)
}
