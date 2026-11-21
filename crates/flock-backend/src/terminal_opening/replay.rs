//! Replay the checked native terminal bit claims against a shared opening.
//! The comparison transcript has no authority to accept an IMT statement.
use anyhow::{Result, ensure};
use p3_binary_field::Poly192 as E;
use p3_binary_pcs::{BooleanMultilinearPcs, WeightedClaim, whir::BooleanWhirPcs};
use p3_field::PrimeCharacteristicRing;
use p3_multilinear_util::point::Point;
use serde::Serialize;
use std::time::Instant;

mod whir_tail;

use super::{Cap, FIRST, PairedOpening, capture::Recorded};
use crate::{Prepared, Profile, config::challenger};

impl Prepared {
    pub fn terminal_wiring_root(&self) -> Result<[u8; 32]> {
        ensure!(
            matches!(
                self.profile,
                Profile::Terminal | Profile::TerminalWideWitness
            ),
            "expected terminal setup"
        );
        let cap = self
            .vk
            .preprocessed_commitment()
            .ok_or_else(|| anyhow::anyhow!("missing terminal wiring"))?;
        ensure!(
            cap.num_roots() == 1,
            "unexpected terminal wiring commitment"
        );
        Ok(cap[0])
    }
}

#[derive(Serialize)]
pub struct BatchTrace {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) ring_switch: Option<RingSwitchTrace>,
    prefix: String,
    claims: String,
    proof: String,
    endpoint: String,
}

struct Prefix(Vec<u8>);
impl p3_challenger::CanObserve<crate::F> for Prefix {
    fn observe(&mut self, word: crate::F) {
        self.0.extend(word.to_bits().to_le_bytes());
    }
}

#[derive(Serialize)]
pub(super) struct RingSwitchTrace {
    pub separator: String,
    pub rows: String,
    pub sum: String,
    pub next_challenge: String,
    pub initial_fold: InitialFoldTrace,
}

#[derive(Serialize)]
pub(super) struct InitialFoldTrace {
    virtual_domain: String,
    whir_domain: String,
    batching_domain: String,
    sumcheck_domain: String,
    ood_answers: Vec<String>,
    messages: Vec<[String; 2]>,
    pow_bits: usize,
    pow_witnesses: Vec<String>,
    fold_point: Vec<String>,
    sum: String,
    next_challenge: String,
    next_cap: String,
    round_answers: Vec<String>,
    query_pow_bits: usize,
    query_witness: String,
    query_indices: Vec<usize>,
    folded_rows: Vec<String>,
    tail: whir_tail::Tail,
    stratified: bool,
    log_query_domain: usize,
}

fn scalar(v: E) -> String {
    hex::encode(
        v.coefficients()
            .iter()
            .flat_map(|c| c.to_bits().to_le_bytes())
            .collect::<Vec<_>>(),
    )
}

type WhirConfig = p3_whir::WhirConfig<E, crate::F, super::Challenger>;

impl InitialFoldTrace {
    fn from_verified(
        config: &WhirConfig,
        whir: &p3_whir::WhirProof<crate::F, E, super::PairedTree>,
        closing: &p3_sumcheck::ring_switch::bits::DeferredClosing<'_, crate::F, E>,
        ring_points: (&Point<E>, &Point<E>),
        mut ch: super::Challenger,
    ) -> Self {
        use p3_challenger::{
            FieldChallenger,
            fs::{DomainSeparator, FieldUnit},
        };
        use p3_sumcheck::{
            TableShape,
            layout::{Layout, Verifier},
            strategy::Basis,
            transcript::SumcheckShape,
        };
        let domain_bytes = |domain: DomainSeparator<FieldUnit<crate::F>>| {
            let mut bytes = Prefix(Vec::new());
            domain.seed(&mut bytes);
            hex::encode(bytes.0)
        };
        let strategy = <super::Binding as Layout<crate::F, E>>::strategy();
        let mut layout =
            Verifier::<crate::F, E>::new(&[TableShape::new(config.num_variables(), 1)], strategy);
        let virtual_domain = domain_bytes(layout.virtual_domain());
        for &answer in &whir.initial_ood_answers {
            layout.add_virtual_eval(answer, &mut ch);
        }
        let shape = p3_whir::WhirShape::new(config, 0);
        let whir_domain = shape.domain_separator::<crate::F, E>();
        let mut transcript =
            p3_whir::transcript::WhirVerifierTranscript::<_, crate::F, E>::new(&mut ch, shape);
        let batching_domain = domain_bytes(layout.batching_domain());
        let rounds = config.round_folding_factor(0);
        let pow_bits = config.starting_folding_pow_bits();
        let basis = Basis::Evaluation;
        let (sum, point, next, constraint, scale) = transcript.delegate_initial_fold(|ch| {
            let alpha = layout.batching_challenge(ch);
            let mut sum = E::ZERO;
            let constraint = layout.constraint(alpha);
            constraint.combine_evals(&mut sum);
            let scale = layout.extra_weight_scale(alpha);
            sum += scale * closing.claimed_sum();
            let point = whir
                .initial_sumcheck
                .verify_rounds(ch, &mut sum, rounds, pow_bits, basis)
                .expect("verified initial fold");
            (
                sum,
                point,
                ch.clone().sample_algebra_element(),
                constraint,
                scale,
            )
        });
        let first = &whir.rounds[0];
        let cap = first.commitment.clone().expect("verified first round");
        transcript.commitment(cap.clone());
        let mut oods = Vec::new();
        for &eval in &first.ood_answers {
            oods.push(transcript.ood_point());
            transcript.ood_answer(eval);
        }
        transcript
            .query_pow(0, first.pow_witness)
            .expect("verified grinding");
        let query_indices = transcript.query_indices(0);
        let p3_whir::QueryOpenings::Base(opening) = &first.openings else {
            unreachable!("verified initial base rows")
        };
        let suffix_point = point.reversed();
        let rows: Vec<E> = opening
            .rows
            .iter()
            .map(|row| {
                p3_multilinear_util::poly::Poly::new(row.as_slice()).eval_base(&suffix_point)
            })
            .collect();
        let folded_rows = rows.iter().copied().map(scalar).collect();
        let weights = whir_tail::Weights {
            points: point.as_slice().to_vec(),
            constraints: vec![constraint],
            oods,
            indices: query_indices.clone(),
            closing,
            scale,
            ring_points,
        };
        let tail = whir_tail::capture(transcript, config, whir, sum, rows, weights);
        Self {
            virtual_domain,
            whir_domain: domain_bytes(whir_domain),
            batching_domain,
            sumcheck_domain: domain_bytes(
                SumcheckShape::new(rounds, pow_bits, basis).domain_separator::<crate::F, E>(),
            ),
            ood_answers: whir
                .initial_ood_answers
                .iter()
                .copied()
                .map(scalar)
                .collect(),
            messages: whir
                .initial_sumcheck
                .polynomial_evaluations
                .iter()
                .map(|pair| pair.map(scalar))
                .collect(),
            pow_bits,
            pow_witnesses: whir
                .initial_sumcheck
                .pow_witnesses
                .iter()
                .map(|w| hex::encode(w.to_bits().to_le_bytes()))
                .collect(),
            fold_point: point.as_slice().iter().copied().map(scalar).collect(),
            sum: scalar(sum),
            next_challenge: scalar(next),
            next_cap: hex::encode(cap[0]),
            round_answers: first.ood_answers.iter().copied().map(scalar).collect(),
            query_pow_bits: config.round_parameters()[0].pow_bits,
            query_witness: hex::encode(first.pow_witness.to_bits().to_le_bytes()),
            log_query_domain: config.round_parameters()[0].log_folded_domain_size,
            stratified: config.stratified_queries(),
            query_indices,
            folded_rows,
            tail,
        }
    }
}

impl RingSwitchTrace {
    pub(super) fn from_verified(
        point: &Point<E>,
        value: E,
        proof: &p3_binary_pcs::whir::BooleanWhirOpening<crate::F, E, super::PairedTree>,
        mut ch: super::Challenger,
        config: &WhirConfig,
    ) -> Self {
        use p3_binary_pcs::whir::BooleanWhirOpening;
        use p3_challenger::FieldChallenger;
        use p3_sumcheck::ring_switch::bits::{
            BitRingSwitch, BitRingSwitchClaims,
            transcript::{
                BitRingSwitchClaimsShape, BitRingSwitchClaimsVerifierTranscript,
                BitRingSwitchShape, ClaimStatement,
            },
        };
        let BooleanWhirOpening::Deferred(proof) = proof else {
            unreachable!("native verification requires a deferred opening")
        };
        let batch =
            BitRingSwitchClaims::new(vec![BitRingSwitch::new(point).expect("verified arity")])
                .expect("one reading");
        let shape = BitRingSwitchClaimsShape {
            deferred: true,
            claims: vec![BitRingSwitchShape::new(point.num_variables())],
        };
        let mut fork = ch.clone();
        let mut transcript = BitRingSwitchClaimsVerifierTranscript::new(&mut fork, shape.clone());
        let draws = transcript
            .statement(&[ClaimStatement {
                point,
                low_weights: None,
                rows: proof.reduction.claims[0].tensor.rows(),
                successor: None,
            }])
            .expect("verified ring shape");
        transcript.finish();
        let closing = batch
            .verify_deferred(&proof.reduction, &[value], &mut ch)
            .expect("verified ring switch");
        let mut separator = Prefix(Vec::new());
        shape.domain_separator::<crate::F, E>().seed(&mut separator);
        let next_challenge: E = ch.clone().sample_algebra_element();
        Self {
            separator: hex::encode(separator.0),
            rows: hex::encode(
                proof.reduction.claims[0]
                    .tensor
                    .rows()
                    .iter()
                    .flat_map(|r| r.to_bits().to_le_bytes())
                    .collect::<Vec<_>>(),
            ),
            sum: scalar(closing.claimed_sum()),
            next_challenge: scalar(next_challenge),
            initial_fold: InitialFoldTrace::from_verified(
                config,
                &proof.opening,
                &closing,
                (point, &draws.batching_point),
                ch,
            ),
        }
    }
}

impl BatchTrace {
    pub(super) fn new(
        seed: &[u8],
        roots: &[[u8; 32]; 2],
        batch: &super::batch::Claims<'_>,
        proof: &super::batch::BatchProof,
        point: &Point<E>,
    ) -> Self {
        let mut prefix = Prefix(seed.to_vec());
        p3_sumcheck::layout::commitment_domain_separator::<crate::F>().seed(&mut prefix);
        prefix.0.extend(roots.iter().flatten());
        let encode = |fields: Vec<E>| {
            hex::encode(
                fields
                    .iter()
                    .flat_map(|x| x.coefficients())
                    .flat_map(|v| v.to_bits().to_le_bytes())
                    .collect::<Vec<_>>(),
            )
        };
        Self {
            ring_switch: None,
            prefix: hex::encode(prefix.0),
            claims: encode(
                batch
                    .points
                    .iter()
                    .zip(batch.values)
                    .flat_map(|(p, v)| p.as_slice().iter().chain([v]).copied())
                    .collect(),
            ),
            proof: encode(
                proof
                    .rounds
                    .iter()
                    .flatten()
                    .copied()
                    .chain([proof.value])
                    .collect(),
            ),
            endpoint: encode(point.as_slice().to_vec()),
        }
    }
}

#[derive(Serialize)]
pub struct OpeningComparison {
    #[serde(skip)]
    pub batch_trace: Option<BatchTrace>,
    #[serde(skip)]
    pub opening_bytes: Vec<u8>,
    reduced_readings: bool,
    variables: usize,
    readings: usize,
    weighted: usize,
    roots: [String; 2],
    proof_bytes: usize,
    compressed_bytes: usize,
    compressed_calldata_floor: usize,
    commit_s: f64,
    open_s: f64,
    verify_s: f64,
}

pub fn compare_recorded(
    mut recorded: Recorded,
    fixed_root: [u8; 32],
    reduce_readings: bool,
) -> Result<OpeningComparison> {
    ensure!(
        recorded.0.len() == 2,
        "expected two recorded bit openings, got {}",
        recorded.0.len()
    );
    recorded
        .0
        .sort_by_key(|m| std::cmp::Reverse(m.table.num_variables()));
    let [main, fixed]: [_; 2] = recorded.0.try_into().ok().unwrap();
    let variables = main.table.num_variables() + 1;
    ensure!(
        fixed.table.num_variables() + 2 == variables,
        "unexpected terminal shapes"
    );
    let pair = PairedOpening::new(variables, fixed_root)?;
    let split = variables - FIRST;
    let mut openings = vec![];
    let mut expected = vec![];
    let mut weighted = vec![];
    for (member, selector) in [(&main, &[E::ZERO][..]), (&fixed, &[E::ONE, E::ZERO][..])] {
        let lift = |p: &Point<E>| {
            let (row, col) = p.as_slice().split_at(split);
            Point::new([row, selector, col].concat())
        };
        for (opening, reading) in member.openings.iter().zip(&member.readings) {
            ensure!(
                !opening.next || opening.row_variables <= opening.point.num_variables() - split,
                "successor crosses the selected face"
            );
            let mut joint = opening.clone();
            joint.point = lift(&joint.point);
            openings.push(joint);
            expected.push(*reading);
        }
        for claim in &member.weighted {
            let mut opening = claim.opening.clone();
            opening.high = lift(&opening.high);
            weighted.push(WeightedClaim {
                opening,
                value: claim.value,
            });
        }
    }
    let seed = b"imt-terminal-paired-bit-opening-comparison-v1";
    let mut ch = challenger(seed);
    let start = Instant::now();
    let commitment = pair.commit(
        main.table.poly(0).into_slice(),
        fixed.table.poly(0).into_slice(),
        &mut ch,
    )?;
    let commit_s = start.elapsed().as_secs_f64();
    let mut verifier = challenger(seed);
    pair.observe(commitment.roots, &mut verifier)?;
    let cap = Cap::new(commitment.roots.to_vec());
    let backend = BooleanWhirPcs::new(pair.pcs, variables + 6)?;
    let start = Instant::now();
    let claims: Vec<_> = weighted.iter().map(|c| c.opening.clone()).collect();
    let encoding = bincode::config::standard().with_fixed_int_encoding();
    let mut batch_trace = None;
    let (bytes, open_s, verify_s) = if reduce_readings {
        ensure!(
            weighted.is_empty() && openings.iter().all(|o| o.current && !o.next),
            "expected current-only terminal bit claims"
        );
        let points: Vec<_> = openings.iter().map(|o| o.point.clone()).collect();
        let values: Vec<_> = expected
            .iter()
            .map(|r| r.current.expect("current terminal reading"))
            .collect();
        let planes: Vec<_> = main.planes.into_iter().chain(fixed.planes).collect();
        let batch = super::batch::Claims {
            points: &points,
            values: &values,
            variables: variables + 6,
        };
        let (reduction, point) = super::batch::prove(
            &batch,
            commitment.data.table(0).poly(0).into_slice(),
            &planes,
            &mut ch,
        )?;
        let (readings, pcs_proof) =
            backend.open_at_points(commitment.data, std::slice::from_ref(&point), &mut ch)?;
        ensure!(
            readings == [reduction.value],
            "incorrect final prover reading"
        );
        let open_s = start.elapsed().as_secs_f64();
        let start = Instant::now();
        let point = batch.verify(&reduction, &mut verifier)?;
        backend.verify_at_points(
            &cap,
            std::slice::from_ref(&point),
            &[reduction.value],
            &pcs_proof,
            &mut verifier,
        )?;
        let verify_s = start.elapsed().as_secs_f64();
        batch_trace = Some(BatchTrace::new(
            seed,
            &commitment.roots,
            &batch,
            &reduction,
            &point,
        ));
        (
            bincode::serde::encode_to_vec((&reduction, &pcs_proof), encoding)?,
            open_s,
            verify_s,
        )
    } else {
        let (readings, values, proof) =
            backend.open_weighted_readings(commitment.data, &openings, &claims, &[], &mut ch)?;
        let open_s = start.elapsed().as_secs_f64();
        ensure!(
            readings == expected && values.iter().copied().eq(weighted.iter().map(|c| c.value)),
            "paired readings disagree with original proof"
        );
        let start = Instant::now();
        backend.verify_weighted_readings(
            &cap,
            &openings,
            &expected,
            &weighted,
            &proof,
            &mut verifier,
        )?;
        let verify_s = start.elapsed().as_secs_f64();
        (
            bincode::serde::encode_to_vec(&proof, encoding)?,
            open_s,
            verify_s,
        )
    };
    let compressed = miniz_oxide::deflate::compress_to_vec(&bytes, 6);
    let tokens: usize = compressed.iter().map(|&b| if b == 0 { 1 } else { 4 }).sum();
    Ok(OpeningComparison {
        batch_trace,
        reduced_readings: reduce_readings,
        variables,
        readings: expected.len(),
        weighted: weighted.len(),
        roots: commitment.roots.map(hex::encode),
        proof_bytes: bytes.len(),
        opening_bytes: bytes,
        compressed_bytes: compressed.len(),
        compressed_calldata_floor: 21_000 + 10 * tokens,
        commit_s,
        open_s,
        verify_s,
    })
}

#[derive(Serialize)]
pub struct TerminalBodyCost {
    original_bit_openings_bytes: [usize; 2],
    arithmetic_body_bytes: usize,
    keccak_reduction_bytes: usize,
    bridge_bytes: usize,
    remaining_raw_bytes: usize,
    remaining_compressed_bytes: usize,
    remaining_calldata_floor: usize,
}

/// Size the original aggregate fields outside its two innermost bit PCS
/// openings. The resulting subtotal also includes all trace column readings.
pub fn terminal_body_cost(original: &[u8]) -> Result<TerminalBodyCost> {
    let (p, coefficients) = crate::checkpoint::JointProof::decode(original, true)?;
    let a = &p.arithmetic;
    let pp = a
        .preprocessed_opening
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("missing preprocessing opening"))?;
    let cfg = bincode::config::standard().with_fixed_int_encoding();
    let bits = [
        bincode::serde::encode_to_vec(&a.opening.opening, cfg)?.len(),
        bincode::serde::encode_to_vec(&pp.opening, cfg)?.len(),
    ];
    // Bincode structs serialize their fields in order. The unit field encodes to
    // zero bytes. Verify exact accounting against the complete canonical proof.
    let body = (
        &a.commitment,
        &a.lookup,
        &a.indexed,
        &a.bus,
        &a.sumcheck,
        &a.circuits,
        (&a.opening.values, ()),
        Some((&pp.values, ())),
    );
    let original_len = bincode::serde::encode_to_vec((&p, &coefficients), cfg)?.len();
    let arithmetic_body_bytes = bincode::serde::encode_to_vec(body, cfg)?.len();
    let keccak_reduction_bytes =
        bincode::serde::encode_to_vec((&p.keccak, &coefficients), cfg)?.len();
    let bridge_bytes = bincode::serde::encode_to_vec(&p.ports, cfg)?.len();
    let remaining =
        bincode::serde::encode_to_vec(((body, &p.keccak, &p.ports), &coefficients), cfg)?;
    ensure!(
        remaining.len() + bits.iter().sum::<usize>() == original_len
            && remaining.len() == arithmetic_body_bytes + keccak_reduction_bytes + bridge_bytes,
        "native serialization differs from proof layout"
    );
    let compressed = miniz_oxide::deflate::compress_to_vec(&remaining, 6);
    let floor = 21_000
        + compressed
            .iter()
            .map(|&b| if b == 0 { 10usize } else { 40 })
            .sum::<usize>();
    Ok(TerminalBodyCost {
        original_bit_openings_bytes: bits,
        arithmetic_body_bytes,
        keccak_reduction_bytes,
        bridge_bytes,
        remaining_raw_bytes: remaining.len(),
        remaining_compressed_bytes: compressed.len(),
        remaining_calldata_floor: floor,
    })
}
