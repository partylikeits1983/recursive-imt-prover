//! Record the rest of the typed transcript after the paired first query.
//! The caller has already verified the entire WHIR proof.
use super::{E, Prefix, WhirConfig, scalar};
use crate::{F, terminal_opening::PairedTree};
use p3_binary_field::TowerLevel;
use p3_binary_pcs::whir::BinaryWhirDomain;
use p3_challenger::FieldChallenger;
use p3_multilinear_util::point::Point;
use p3_multilinear_util::poly::Poly;
use p3_sumcheck::constraints::{
    Constraint, Statements,
    statement::{EqStatement, SelectStatement},
};
use p3_sumcheck::ring_switch::bits::DeferredClosing;
use p3_sumcheck::strategy::VariableOrder;
use p3_sumcheck::{SumcheckData, strategy::Basis, transcript::SumcheckShape};
use p3_whir::{
    QueryOpenings, WhirDomain, WhirProof, WhirQueryPoint, transcript::WhirVerifierTranscript,
};
use serde::Serialize;

#[derive(Serialize)]
pub(super) struct Tail {
    steps: Vec<Step>,
    final_fold: Fold,
    cantor_basis: Vec<String>,
    closing: Identity,
}

pub(super) struct Weights<'a, 'b> {
    pub points: Vec<E>,
    pub constraints: Vec<Constraint<F, E>>,
    pub oods: Vec<E>,
    pub indices: Vec<usize>,
    pub closing: &'a DeferredClosing<'b, F, E>,
    pub scale: E,
    pub ring_points: (&'a Point<E>, &'a Point<E>),
}

#[derive(Serialize)]
struct Identity {
    certificate_prove_us: u128,
    ring_certificate: String,
    ring_weight: String,
    ordinary_weight: String,
    final_value: String,
}

#[derive(Serialize)]
struct Step {
    alpha: String,
    fold: Fold,
    /// Next commitment and OOD answers, or the final polynomial.
    next_message: String,
    next_witness: String,
    query_bits: usize,
    depth: usize,
    indices: Vec<usize>,
    folded_rows: Vec<String>,
}

#[derive(Serialize)]
struct Fold {
    wire: String,
    domain: String,
    pow_bits: usize,
    point: Vec<String>,
    sum: String,
    next_challenge: String,
}

fn check_fold(
    ch: &mut crate::config::Challenger,
    proof: &SumcheckData<F, E>,
    sum: &mut E,
    rounds: usize,
    bits: usize,
) -> (Fold, p3_multilinear_util::point::Point<E>) {
    let point = proof
        .verify_rounds(ch, sum, rounds, bits, Basis::Evaluation)
        .expect("verified WHIR sumcheck");
    let mut ds = Prefix(Vec::new());
    SumcheckShape::new(rounds, bits, Basis::Evaluation)
        .domain_separator::<F, E>()
        .seed(&mut ds);
    let mut wire = String::new();
    for (i, &[lo, hi]) in proof.polynomial_evaluations.iter().enumerate() {
        wire += &scalar(lo);
        wire += &scalar(hi);
        if bits != 0 {
            wire += &hex::encode(proof.pow_witnesses[i].to_bits().to_le_bytes());
        }
    }
    let fold = Fold {
        wire,
        domain: hex::encode(ds.0),
        pow_bits: bits,
        point: point.as_slice().iter().copied().map(scalar).collect(),
        sum: scalar(*sum),
        next_challenge: scalar(ch.clone().sample_algebra_element()),
    };
    (fold, point)
}

pub(super) fn capture(
    mut transcript: WhirVerifierTranscript<'_, crate::config::Challenger, F, E>,
    config: &WhirConfig,
    proof: &WhirProof<F, E, PairedTree>,
    mut sum: E,
    mut rows: Vec<E>,
    mut weights: Weights<'_, '_>,
) -> Tail {
    let mut steps = Vec::new();
    for (i, round) in proof.rounds.iter().enumerate() {
        let alpha = transcript.round_batching();
        let params = &config.round_parameters()[i];
        let n = params.num_variables;
        let mut eq = EqStatement::initialize(n);
        for (t, &answer) in weights.oods.drain(..).zip(&round.ood_answers) {
            eq.add_evaluated_constraint(Point::expand_from_univariate(t, n), answer);
        }
        let mut selections = SelectStatement::initialize(n);
        let domain = BinaryWhirDomain::<F>::default();
        for (&index, &value) in weights.indices.iter().zip(&rows) {
            let WhirQueryPoint::Multilinear(point) =
                <BinaryWhirDomain<F> as WhirDomain<F, E>>::query_point(
                    &domain,
                    params.log_folded_domain_size,
                    n,
                    index,
                )
            else {
                unreachable!("binary additive query")
            };
            selections.add_point_constraint(point, value);
        }
        weights
            .constraints
            .push(Constraint::new_with_existing_claim(
                alpha,
                n,
                vec![Statements::Eq(eq), Statements::Select(selections)],
            ));
        let mut power = alpha;
        for &v in round.ood_answers.iter().chain(&rows) {
            sum += power * v;
            power *= alpha;
        }
        let (fold, point) = transcript.delegate_round_fold(|ch| {
            check_fold(
                ch,
                &round.sumcheck,
                &mut sum,
                config.round_folding_factor(i + 1),
                config.round_parameters()[i].folding_pow_bits,
            )
        });
        weights.points.extend_from_slice(point.as_slice());
        let (next_message, witness, openings, params) = if let Some(next) = proof.rounds.get(i + 1)
        {
            let cap = next.commitment.clone().expect("verified commitment");
            let mut message = hex::encode(cap[0]);
            transcript.commitment(cap);
            for &answer in &next.ood_answers {
                weights.oods.push(transcript.ood_point());
                transcript.ood_answer(answer);
                message += &scalar(answer);
            }
            (
                message,
                next.pow_witness,
                &next.openings,
                config.round_parameters()[i + 1].clone(),
            )
        } else {
            let poly = proof
                .final_poly
                .as_ref()
                .expect("verified final polynomial")
                .as_slice();
            transcript
                .final_poly(poly)
                .expect("verified final polynomial shape");
            (
                poly.iter().copied().map(scalar).collect(),
                proof.final_pow_witness,
                &proof.final_openings,
                config.final_round_config(),
            )
        };
        transcript
            .query_pow(i + 1, witness)
            .expect("verified query PoW");
        let indices = transcript.query_indices(i + 1);
        weights.indices.clone_from(&indices);
        let QueryOpenings::Extension(opening) = openings else {
            unreachable!("verified extension rows")
        };
        let suffix = point.reversed();
        rows = opening
            .rows
            .iter()
            .map(|r| Poly::new(r.as_slice()).eval_ext::<F>(&suffix))
            .collect();
        steps.push(Step {
            alpha: scalar(alpha),
            fold,
            next_message,
            next_witness: hex::encode(witness.to_bits().to_le_bytes()),
            query_bits: params.pow_bits,
            depth: params.log_folded_domain_size,
            indices,
            folded_rows: rows.iter().copied().map(scalar).collect(),
        });
    }
    let (final_fold, last) = transcript
        .delegate_final_fold(|ch| {
            check_fold(
                ch,
                proof
                    .final_sumcheck
                    .as_ref()
                    .expect("verified final sumcheck"),
                &mut sum,
                config.final_sumcheck_rounds(),
                config.final_folding_pow_bits(),
            )
        })
        .expect("terminal shape has a closing fold");
    transcript.finish();
    weights.points.extend_from_slice(last.as_slice());
    let randomness = Point::new(weights.points);
    let ordinary = VariableOrder::Suffix.eval_constraints_poly(&weights.constraints, &randomness);
    let ring = weights
        .closing
        .weight_at(&randomness.reversed())
        .expect("checked arity");
    let value = proof
        .final_poly
        .as_ref()
        .expect("verified final polynomial")
        .eval_ext::<F>(&last.reversed());
    assert_eq!((ordinary + weights.scale * ring) * value, sum);
    let reading = weights
        .ring_points
        .0
        .as_slice()
        .try_into()
        .expect("32 bit coordinates");
    let draw = randomness
        .as_slice()
        .try_into()
        .expect("26 packed coordinates");
    let batching = weights
        .ring_points
        .1
        .as_slice()
        .try_into()
        .expect("8 tensor coordinates");
    let start = std::time::Instant::now();
    let certificate =
        crate::terminal_opening::ring_certificate::prove(reading, draw, batching, ring)
            .expect("verified ring weight");
    let certificate_prove_us = start.elapsed().as_micros();
    assert_eq!(
        crate::terminal_opening::ring_certificate::verify(reading, draw, batching, &certificate)
            .expect("valid ring certificate"),
        ring
    );
    let closing = Identity {
        ring_certificate: hex::encode(certificate),
        certificate_prove_us,
        ring_weight: scalar(ring),
        ordinary_weight: scalar(ordinary),
        final_value: scalar(value),
    };
    let cantor_basis = (0..26)
        .map(|i| format!("{:016x}", F::cantor_basis(i).to_bits()))
        .collect();
    Tail {
        steps,
        final_fold,
        cantor_basis,
        closing,
    }
}
