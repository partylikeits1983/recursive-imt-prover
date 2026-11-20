//! Full 24-round packed permutation reduction for an authenticated bit output.
use super::{
    Claim, E, F, LayerProof, POSITION_LOG, PackedClaim, State, closing, packed_closing, reduction,
};
use crate::{
    checkpoint_keccak::{Proof, ROUNDS},
    config::Challenger,
};
use anyhow::{Result, ensure};
use p3_binary_field::TowerLevel;
use p3_challenger::{CanObserve, FieldChallenger, GrindingChallenger};
use p3_multilinear_util::point::Point;

fn start(output: &Claim, ch: &mut impl FieldChallenger<F>) -> Result<PackedClaim> {
    ensure!(output.instance.len() >= 4, "packed chi requires 16 lanes");
    // The enclosing verifier sampled the entire row and position itself and
    // fixed the joint root before either. Only the output value is a new message.
    ch.observe_algebra_element(output.value);
    let mut claim = output.clone();
    let lanes =
        Point::new(claim.instance.split_off(claim.instance.len() - 4)).equality_weights_msb();
    Ok(PackedClaim {
        claim,
        lanes: lanes
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid packed lane count"))?,
    })
}

pub(super) type Coefficients = Vec<Vec<E>>;

pub(in crate::checkpoint_keccak) fn prove(
    states: &[State],
    output: &Claim,
    ch: &mut Challenger,
) -> Result<(Proof, Coefficients, closing::Proof, Point<E>, E)> {
    let mut claim = start(output, ch)?;
    let mut layers = Vec::with_capacity(ROUNDS);
    let mut coefficients = Vec::with_capacity(ROUNDS);
    let checkpoints = super::Checkpoints::new(states, ROUNDS, 6, states.len());
    for round in (0..ROUNDS).rev() {
        ch.observe(F::from_repr(round as u64));
        let (states, before_chi) = checkpoints.before_chi(round);
        let (layer, next) =
            reduction::prove(states, |group, s| before_chi(group * 16, s), &claim, ch);
        layers.push(LayerProof {
            sumcheck: layer.sumcheck,
            values: layer.values,
        });
        coefficients.push(layer.coefficients);
        claim = next;
    }
    let (closing, point, bit) = packed_closing(states, &claim, ch);
    Ok((Proof { layers }, coefficients, closing, point, bit))
}

pub(in crate::checkpoint_keccak) fn verify(
    proof: &Proof,
    coefficients: &[Vec<E>],
    closing: &closing::Proof,
    output: &Claim,
    ch: &mut (impl FieldChallenger<F> + GrindingChallenger<Witness = F>),
) -> Result<closing::Closing> {
    ensure!(
        proof.layers.len() == ROUNDS && coefficients.len() == ROUNDS,
        "incorrect packed Keccak round count"
    );
    let mut claim = start(output, ch)?;
    for ((round, layer), coeff) in (0..ROUNDS).rev().zip(&proof.layers).zip(coefficients) {
        ch.observe(F::from_repr(round as u64));
        claim = reduction::verify_parts(
            coeff,
            &layer.sumcheck,
            layer.values,
            &claim,
            reduction::iota(&claim, round),
            ch,
        )?;
    }
    ensure!(
        closing.claimed_sum == claim.claim.value,
        "incorrect packed input claim"
    );
    let (position, product) = closing.verify(ch, POSITION_LOG + 4, 2, 0)?;
    let (i, z) = position.as_slice().split_at(4);
    let weight = closing::evaluate_folded(&claim.lanes, i)
        * closing::evaluate_folded(&claim.claim.weights, z);
    let mut point = claim.claim.instance;
    point.extend_from_slice(position.as_slice());
    Ok(closing::Closing {
        point: Point::new(point),
        product,
        weight,
    })
}
