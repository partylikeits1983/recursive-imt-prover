//! Terminal proof with both bit-opening obligations discharged by a single WHIR
//! proof. Each call owns fresh PCS accumulators; they cannot cross proof runs.
use std::{sync::Arc, time::Instant};

use super::{
    Cap, Challenger, E, F, OpeningSchedule, PairedOpening,
    bound::{Readings, SharedProof},
    side::{Face, Pending, Side},
};
use crate::{
    Metrics, OldF, Prepared, Profile,
    checkpoint::bridge_ports,
    checkpoint_keccak::linked::{LinkedBatch, LinkedClaims, PortOpening},
    config::{self, Config, Data, MainCode, challenger},
    mixed::MixedTraceCommitment,
    proof_codec,
};
use anyhow::{Result, ensure};
use p3_binary_pcs::{BooleanTraceCommitment, whir::BooleanWhirPcs};
use p3_commit::MultilinearPcs;
use p3_multi_stark::{
    MultiStarkProof, ProverInstance, ProverInstances, VerifierInstance, VerifierInstances,
    VerifyingKey, config::MultiStarkConfig,
};
use p3_sumcheck::{TableSpec, layout::Table};
use serde::{Deserialize, Serialize};

const DOMAIN: &[u8] = b"imt-terminal-shared-bit-opening-v1";
type Pcs = MixedTraceCommitment<E, Face>;
struct JointConfig {
    main: Pcs,
    fixed: Pcs,
    sides: [Arc<Side>; 2],
    extra: Vec<TableSpec>,
    #[cfg(feature = "opening-bench")]
    query_counts: Vec<usize>,
    variables: usize,
}

impl JointConfig {
    fn new(config: &Config, schedule: OpeningSchedule) -> Result<Self> {
        let policy = schedule.security();
        Self::with_work_factors(config, schedule, policy.local_bits, policy.max_grind)
    }

    fn with_work_factors(
        config: &Config,
        schedule: OpeningSchedule,
        local_bits: usize,
        max_grind: usize,
    ) -> Result<Self> {
        let variables = config
            .main
            .num_vars()
            .checked_sub(5)
            .ok_or_else(|| anyhow::anyhow!("invalid main arity"))?;
        ensure!(
            (7..=26).contains(&variables) && config.preprocessed.num_vars() == variables + 4,
            "wrong terminal layout"
        );
        // All reductions refer to the same virtual word polynomial. Price its
        // WHIR run and its final bit ring switch with the actual fold schedule.
        let paired =
            PairedOpening::with_work_factors(variables, [0; 32], schedule, local_bits, max_grind)?;
        #[cfg(feature = "opening-bench")]
        let query_counts = {
            let shape = p3_whir::WhirShape::new(&paired.pcs, 0);
            shape
                .rounds
                .iter()
                .map(|r| r.query_draws)
                .chain([shape.final_query_draws])
                .collect()
        };
        let bit_pcs = BooleanWhirPcs::new(paired.pcs, variables + 6)?;
        let shared = bit_pcs
            .readings_security(1, false)
            .ok_or_else(|| anyhow::anyhow!("missing joint PCS bound"))?;
        let side = |pcs: &config::Pcs, fold| -> Result<_> {
            let side = Arc::new(Side::new(
                config::native_bits(
                    pcs.num_vars(),
                    MainCode {
                        log_inv_rate: config::TERMINAL_LOG_INV_RATE,
                        first_fold: fold,
                    },
                )?,
                shared.clone(),
                variables + 6,
            ));
            let wrapped = MixedTraceCommitment::new(
                BooleanTraceCommitment::from_commitment(Face(side.clone())),
                pcs.encodings.clone(),
            );
            Ok((wrapped, side))
        };
        let (main, m) = side(&config.main, 5)?;
        let (fixed, f) = side(&config.preprocessed, 4)?;
        Ok(Self {
            main,
            fixed,
            sides: [m, f],
            #[cfg(feature = "opening-bench")]
            query_counts,
            extra: if schedule.midpoint() {
                let input = config
                    .auxiliary_tables
                    .first()
                    .ok_or_else(|| anyhow::anyhow!("missing input boundary"))?;
                crate::checkpoint_keccak::linked::midpoint_specs(input.shape().num_variables())
            } else {
                config.auxiliary_tables.clone()
            },
            variables,
        })
    }
    fn finish(&self) -> Result<([Pending; 2], Readings)> {
        let faces = [self.sides[0].take()?, self.sides[1].take()?];
        let readings = Readings::new(
            self.variables,
            faces
                .each_ref()
                .map(|f| (f.points.as_slice(), f.values.as_slice())),
        )?;
        Ok((faces, readings))
    }
}
impl MultiStarkConfig for JointConfig {
    type Val = F;
    type Challenge = E;
    type Challenger = Challenger;
    type Pcs = Pcs;
    fn pcs(&self) -> &Pcs {
        &self.main
    }
    fn preprocessed_pcs(&self) -> &Pcs {
        &self.fixed
    }
    fn auxiliary_tables(&self) -> &[TableSpec] {
        &self.extra
    }
    fn min_num_variables(&self) -> usize {
        4
    }
    fn collision_resistance_bits(&self) -> Option<usize> {
        Some(128)
    }
    fn build_witness(&self, tables: Vec<Table<F>>) -> Vec<Table<F>> {
        tables
    }
    fn committed_table<'a>(&self, data: &'a Data, index: usize) -> &'a Table<F> {
        data.table(index)
    }
}

#[derive(Serialize, Deserialize)]
struct RootProof {
    arithmetic: MultiStarkProof<JointConfig>,
    keccak: LinkedClaims,
    coefficients: Vec<Vec<E>>,
    ports: PortOpening,
    opening: SharedProof,
}

fn singleton(cap: &Cap) -> Result<[u8; 32]> {
    ensure!(cap.num_roots() == 1, "invalid terminal commitment");
    Ok(cap[0])
}

fn opening_seed(authority: &[u8]) -> Vec<u8> {
    [DOMAIN, authority].concat()
}

impl Prepared {
    pub fn prove_shared_terminal(
        &self,
        public: &[OldF],
        private: &[OldF],
    ) -> Result<(Vec<u8>, Metrics)> {
        self.prove_shared_terminal_with_schedule(
            public,
            private,
            OpeningSchedule::ThreeVariableFolds,
        )
    }

    pub fn prove_shared_terminal_with_schedule(
        &self,
        public: &[OldF],
        private: &[OldF],
        schedule: OpeningSchedule,
    ) -> Result<(Vec<u8>, Metrics)> {
        ensure!(
            self.profile == Profile::TerminalWideWitness,
            "invalid shared terminal profile"
        );
        let start = Instant::now();
        let (tables, witness) = self.witness_tables(public, private)?;
        let public = self.public(public)?;
        let witness_ms = crate::elapsed(start);
        let start = Instant::now();
        let config = JointConfig::new(&self.config, schedule)?;
        let pinned = self
            .vk
            .preprocessed_commitment()
            .ok_or_else(|| anyhow::anyhow!("missing pinned wiring"))?;
        let airs: Vec<_> = self.airs.iter().collect();
        let pk = self.pk.with_opening_strategy::<JointConfig>();
        let instances = tables
            .into_iter()
            .enumerate()
            .map(|(i, t)| {
                Ok(ProverInstance::new(
                    airs[i],
                    t.ok_or_else(|| anyhow::anyhow!("missing terminal table"))?,
                    &pk,
                    &public[i],
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        let scheme = self
            .checkpoint
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("missing checkpoint scheme"))?;
        let segments = schedule.midpoint().then(|| witness.segment_inputs());
        let inputs = segments.as_deref().unwrap_or(&witness.inputs);
        let mut linked = None;
        let arithmetic = p3_multi_stark::prover::prove_with_extra_tables::<
            _,
            _,
            p3_multi_stark::GenericBackend,
        >(
            &config,
            ProverInstances::new(instances),
            0,
            &mut challenger(&self.seed),
            scheme.segment_tables(&witness, inputs, schedule.midpoint()),
            |cap, point, hints| {
                let result = (|| -> Result<_> {
                    let row = hints
                        .get(self.hash_index)
                        .and_then(Option::as_ref)
                        .ok_or_else(|| anyhow::anyhow!("missing terminal bridge batch"))?;
                    let ports = bridge_ports(scheme, point, row.current())?;
                    let mut ch = challenger(&scheme.transcript_seed(&self.seed));
                    config.main.observe_commitment(cap, &mut ch);
                    let opened = scheme.prove_segments(&witness, inputs, &ports, &mut ch)?;
                    linked = Some((ports, opened.claims, opened.coefficients, opened.middle));
                    Ok((opened.points, opened.hints))
                })();
                result.map_err(|e| e.to_string())
            },
        )
        .map_err(|e| anyhow::anyhow!("{e}"))?;
        drop(segments);
        drop(pk);
        let (faces, readings) = config.finish()?;
        let [(main, mut planes), (fixed, other)] =
            faces.map(|f| f.witness.expect("prover side has witness"));
        planes.extend(other);
        let roots = [singleton(&arithmetic.commitment)?, singleton(pinned)?];
        let pcs = PairedOpening::with_schedule(config.variables, roots[1], schedule)?;
        let words = pcs.words(main.poly(0).into_slice(), fixed.poly(0).into_slice())?;
        drop((main, fixed));
        let opening =
            pcs.prove_readings(words, roots, &readings, &planes, &opening_seed(&self.seed))?;
        let (ports, keccak, coefficients, middle) =
            linked.ok_or_else(|| anyhow::anyhow!("missing terminal bridge reduction"))?;
        let proof = RootProof {
            arithmetic,
            keccak,
            coefficients,
            ports,
            opening,
        };
        let bytes = match middle {
            Some(value) => proof_codec::encode(&(&proof, value))?,
            None => proof_codec::encode(&proof)?,
        };
        let prove_ms = crate::elapsed(start);
        let start = Instant::now();
        verify(
            &self.config,
            &self.vk,
            &self.airs,
            &self.log_heights,
            &public,
            scheme,
            self.hash_index,
            &self.seed,
            schedule,
            &bytes,
        )?;
        let proof_bytes = bytes.len();
        Ok((
            bytes,
            Metrics {
                proof_bytes,
                witness_ms,
                prove_ms,
                verify_ms: crate::elapsed(start),
            },
        ))
    }
}

fn conditional_algebraic_bits<A: p3_multi_stark::folder::VerifierAir<F, E>>(
    config: &JointConfig,
    instances: &VerifierInstances<'_, JointConfig, A>,
    scheme: &LinkedBatch,
) -> Result<f64> {
    let assessment = p3_multi_stark::security_report(config, instances)?;
    ensure!(
        assessment.unassessed_components().is_empty(),
        "joint terminal assessment is incomplete"
    );
    // Each face conservatively charges the full shared opening. The union of
    // their batching numerators covers powers 0..(main_count+fixed_count-1).
    let mut shared = config.sides[0]
        .evidence(1)
        .ok_or_else(|| anyhow::anyhow!("missing joint opening evidence"))?;
    let midpoint = config.extra[0].point_schedule().len() == 3;
    if midpoint {
        // Charge the two segment claims on the committed midpoint table at the
        // sampled output row/bit position, then their random affine batching.
        let candidates = p3_security::CandidateSet::from_log2(2.0 * shared.log2_max_candidates)
            .ok_or_else(|| anyhow::anyhow!("invalid midpoint candidate bound"))?;
        shared.terms.push(
            p3_security::SecurityTerm::new(
                "terminal midpoint linkage",
                p3_security::ErrorBits::from_numerator(
                    192,
                    (2 * (scheme.log_batch + 11) + 1) as u128,
                ),
            )
            .over_candidates(candidates),
        );
    }
    // The full 24-layer degree bound at the enlarged instance dimension also
    // upper-bounds the 12-layer reduction, including its selector-dependent iota.
    let linked_bound = LinkedBatch::link_security(
        scheme.log_batch + usize::from(midpoint),
        true,
        shared.log2_max_candidates,
        shared,
    )?;
    let combined_error = assessment
        .terms()
        .iter()
        .filter(|t| t.label != "commitment-and-transcript-collision")
        .map(|t| 2f64.powf(-t.bits.bits()))
        .sum::<f64>()
        + 2f64.powf(-linked_bound);
    Ok(-combined_error.log2())
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn verify<A: p3_multi_stark::folder::VerifierAir<F, E>>(
    source: &Config,
    trusted: &VerifyingKey<Config>,
    airs: &[A],
    heights: &[usize],
    public: &[Vec<F>],
    scheme: &LinkedBatch,
    hash_index: usize,
    authority: &[u8],
    schedule: OpeningSchedule,
    bytes: &[u8],
) -> Result<f64> {
    let (proof, middle): (RootProof, Option<E>) = if schedule.midpoint() {
        let (proof, middle): (RootProof, E) = proof_codec::decode(bytes)?;
        (proof, Some(middle))
    } else {
        (proof_codec::decode(bytes)?, None)
    };
    let config = JointConfig::new(source, schedule)?;
    let key = trusted.with_opening_strategy::<JointConfig>();
    let roots = [
        singleton(&proof.arithmetic.commitment)?,
        singleton(
            key.preprocessed_commitment()
                .ok_or_else(|| anyhow::anyhow!("missing trusted fixed cap"))?,
        )?,
    ];
    ensure!(
        airs.len() == public.len() && public.len() == heights.len(),
        "invalid trusted terminal shape"
    );
    let instances = VerifierInstances::new(
        airs.iter()
            .zip(heights)
            .zip(public)
            .map(|((air, &height), p)| VerifierInstance::new(air, &key, height, p))
            .collect(),
    );
    let algebraic_bits = conditional_algebraic_bits(&config, &instances, scheme)?;
    let floor = schedule.security().conditional_floor;
    ensure!(
        algebraic_bits >= f64::from(floor),
        "joint terminal conditional algebraic margin {algebraic_bits} below {floor} bits"
    );
    #[cfg(feature = "opening-bench")]
    crate::opening_trace::record_shared_security(algebraic_bits);
    #[cfg(feature = "opening-bench")]
    crate::opening_trace::record_security_sweep(|local_bits, max_grind| {
        let candidate = JointConfig::with_work_factors(source, schedule, local_bits, max_grind)?;
        Ok((
            conditional_algebraic_bits(&candidate, &instances, scheme)?,
            candidate.query_counts,
        ))
    })?;
    let mut linked = challenger(&scheme.transcript_seed(authority));
    config
        .main
        .observe_commitment(&proof.arithmetic.commitment, &mut linked);
    let reduction = scheme.reduce_segments(
        &proof.keccak,
        &proof.coefficients,
        &proof.ports,
        middle,
        &mut linked,
    )?;
    let opened = p3_multi_stark::verifier::verify_with_extra_tables(
        &config,
        instances,
        &proof.arithmetic,
        0,
        &mut challenger(authority),
        |_| Ok(reduction.points.clone()),
    )?;
    let ports = bridge_ports(
        scheme,
        &opened.point,
        opened
            .current
            .get(hash_index)
            .ok_or_else(|| anyhow::anyhow!("missing terminal hash bridge"))?,
    )?;
    ensure!(
        ports.instance == proof.ports.instance && ports.values == proof.ports.values,
        "incorrect terminal hash bridge"
    );
    reduction.authenticate(&opened.auxiliary)?;
    #[cfg(feature = "opening-bench")]
    crate::opening_trace::record_arithmetic(
        airs,
        heights,
        public,
        authority,
        key.preprocessed_commitment().expect("checked fixed cap"),
        |ch| {
            config
                .main
                .observe_commitment(&proof.arithmetic.commitment, ch)
        },
        proof.arithmetic.bus.as_ref(),
        &proof.arithmetic.sumcheck,
        opened.point.as_slice(),
        [&config.main.encodings, &config.fixed.encodings],
        &config.extra,
        [
            &proof.arithmetic.opening.values,
            &proof
                .arithmetic
                .preprocessed_opening
                .as_ref()
                .expect("verified fixed opening")
                .values,
        ],
    )?;
    #[cfg(feature = "opening-bench")]
    crate::opening_trace::record_linked_closing(
        opened.point.as_slice(),
        &opened.current[hash_index],
        proof.keccak.closing_proofs(),
        &reduction.points,
        &opened.auxiliary,
    );
    #[cfg(feature = "opening-bench")]
    crate::opening_trace::record_linked_prefix(
        authority,
        &roots[0],
        &proof.ports,
        &proof.keccak,
        &proof.coefficients[0],
        reduction.points[2 + usize::from(middle.is_some())].as_slice(),
        middle,
    );
    let (faces, readings) = config.finish()?;
    for (face, root) in faces.iter().zip(roots) {
        ensure!(
            face.verified_cap
                .as_ref()
                .is_some_and(|cap| cap.roots() == [root]),
            "incorrect shared opening cap"
        );
    }
    PairedOpening::with_schedule(config.variables, roots[1], schedule)?.verify_readings(
        roots,
        &readings,
        &proof.opening,
        &opening_seed(authority),
    )?;
    Ok(algebraic_bits)
}
