//! Native reference for the transition from the public statement to the bus claims.
use anyhow::{Result, ensure};
use p3_air::symbolic::AirLayout;
use p3_binary_field::{Poly64 as F, Poly192 as E};
use p3_bus::{BusPlan, BusPlanInput, BusProof, BusSymbolicBuilder, ProductGkrLayerProof};
use p3_challenger::{CanObserve, CanSample};
use p3_multi_stark::folder::VerifierAir;
use p3_multi_stark::transcript::{MultiStarkShape, MultiStarkVerifierTranscript};
use p3_multi_stark::zerocheck::{
    get_air_degrees,
    transcript::{ZerocheckShape, ZerocheckVerifierTranscript},
};
use p3_sumcheck::generic_degree::{GenericDegreeProof, GenericDegreeShape};
use serde::Serialize;

use super::{OPENINGS, encode};
use crate::config::{Challenger, challenger};
use p3_symmetric::MerkleCap;

#[derive(Serialize)]
pub struct ArithmeticPrefix {
    key: super::arithmetic_key::ArithmeticKey,
    columns: [String; 2],
    statement_domain: String,
    bus_domain: String,
    public_widths: Vec<usize>,
    fingerprint: String,
    offset: String,
    product_domain: String,
    product_wire: String,
    product_point: String,
    product_values: String,
    next_challenge: String,
    air_domain: String,
    sumcheck_domain: String,
    degree: usize,
    sumcheck_wire: String,
    air_challenges: String,
    air_point: String,
    final_sum: String,
    post_air_challenge: String,
}

pub(super) struct Words(pub(super) Vec<u8>);
impl CanObserve<F> for Words {
    fn observe(&mut self, v: F) {
        self.0.extend(v.to_bits().to_le_bytes());
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn record_arithmetic<A: VerifierAir<F, E>>(
    airs: &[A],
    heights: &[usize],
    public: &[Vec<F>],
    authority: &[u8],
    fixed: &MerkleCap<F, [u8; 32]>,
    observe_main: impl FnOnce(&mut Challenger),
    proof: Option<&BusProof<E>>,
    sumcheck: &GenericDegreeProof<F, E>,
    verified_point: &[E],
    encodings: [&[crate::encoding::TableEncoding]; 2],
    auxiliary: &[p3_sumcheck::TableSpec],
    column_evals: [&[E]; 2],
) -> Result<()> {
    if OPENINGS.with_borrow(Option::is_none) {
        return Ok(());
    }
    let declarations = airs
        .iter()
        .map(|air| BusSymbolicBuilder::<F, E>::from_air(air, AirLayout::from_air(air)))
        .collect::<Vec<_>>();
    let inputs = declarations
        .iter()
        .zip(heights)
        .map(|(air, &log_height)| BusPlanInput {
            log_height,
            interactions: air.interactions(),
        })
        .collect::<Vec<_>>();
    let plan =
        BusPlan::build(&inputs)?.ok_or_else(|| anyhow::anyhow!("missing terminal bus plan"))?;
    let bus_degree = declarations
        .iter()
        .flat_map(|a| a.interactions())
        .map(|i| i.factor_degree_multiple_with_transition(1))
        .max()
        .unwrap_or(0)
        + 1;
    let degrees = airs
        .iter()
        .map(get_air_degrees::<F, E, A>)
        .collect::<Vec<_>>();
    let degree = bus_degree.max(1 + degrees.iter().map(|d| d.max()).max().unwrap_or(1).max(1));
    let height = *heights
        .iter()
        .max()
        .ok_or_else(|| anyhow::anyhow!("empty arithmetic key"))?;
    let air_shape = ZerocheckShape::new(&degrees, height, 0, 0).with_bus(bus_degree);
    let mut air_domain = Words(Vec::new());
    air_shape.domain_separator::<F, E>().seed(&mut air_domain);
    let mut sumcheck_domain = Words(Vec::new());
    GenericDegreeShape::new(height, degree, 0)
        .domain_separator::<F, E>()
        .seed(&mut sumcheck_domain);
    let proof = proof.ok_or_else(|| anyhow::anyhow!("missing terminal bus proof"))?;
    let key = super::arithmetic_key::ArithmeticKey::from_airs(
        airs,
        heights,
        &declarations,
        &plan,
        encodings[0],
        encodings[1],
        auxiliary,
    )?;
    let shape =
        MultiStarkShape::new::<F, _>(&airs.iter().collect::<Vec<_>>(), heights, 0, false, true);
    let mut statement_domain = Words(Vec::new());
    shape.domain_separator::<F>().seed(&mut statement_domain);
    let mut bus_domain = Words(Vec::new());
    plan.domain_separator::<F, E>().seed(&mut bus_domain);
    let mut product_domain = Words(Vec::new());
    plan.product_shape()
        .domain_separator::<F, E>()
        .seed(&mut product_domain);
    let mut ch = challenger(authority);
    let mut transcript = MultiStarkVerifierTranscript::<_, F>::new(&mut ch, shape);
    transcript.preprocessed_commitment(Some(fixed.clone()))?;
    transcript.main_commitment(observe_main);
    transcript.public_values(&public.iter().map(Vec::as_slice).collect::<Vec<_>>())?;
    let checked = transcript
        .bus_argument(|ch| plan.verify::<F, E, _>(proof, ch))
        .expect("bus shape");
    transcript.abort();
    drop(transcript);
    let checked = checked?;
    let next_challenge = ch.clone().sample();
    let mut reduction = ZerocheckVerifierTranscript::<_, F, E>::new(&mut ch, air_shape);
    let challenges = reduction.challenges(&[]);
    let initial = checked.batched_terminal_claim(challenges.lambda)? * challenges.lambda;
    let reduced = reduction.constraint_sumcheck(|ch| sumcheck.verify(ch, height, degree, 0));
    reduction.finish();
    let (air_point, final_sum) = reduced?;
    ensure!(
        sumcheck.claimed_sum == initial && air_point.as_slice() == verified_point,
        "inconsistent arithmetic reduction"
    );
    ensure!(
        checked.product.roots.len() == 2,
        "unexpected bus tree count"
    );
    let mut wire = proof.product.roots.clone();
    for layer in &proof.product.layers {
        match layer {
            ProductGkrLayerProof::Binary { children } => wire.extend(children.iter().flatten()),
            ProductGkrLayerProof::RadixFour {
                round_polys,
                children,
            } => {
                wire.extend(round_polys.iter().flatten());
                wire.extend(children.iter().flatten());
            }
            ProductGkrLayerProof::BinarySumcheck { .. } => {
                anyhow::bail!("unexpected terminal bus shape")
            }
        }
    }
    OPENINGS.with_borrow_mut(|slot| {
        slot.as_mut().unwrap().arithmetic_prefix = Some(ArithmeticPrefix {
            key,
            columns: column_evals.map(|e| encode(e.iter().copied())),
            statement_domain: hex::encode(statement_domain.0),
            bus_domain: hex::encode(bus_domain.0),
            public_widths: public.iter().map(Vec::len).collect(),
            fingerprint: encode(checked.challenges.fingerprint),
            offset: encode([checked.challenges.offset]),
            product_domain: hex::encode(product_domain.0),
            product_wire: encode(wire),
            product_point: encode(checked.product.point),
            product_values: encode(checked.product.values),
            next_challenge: encode([next_challenge]),
            air_domain: hex::encode(air_domain.0),
            sumcheck_domain: hex::encode(sumcheck_domain.0),
            degree,
            sumcheck_wire: encode(
                [initial]
                    .into_iter()
                    .chain(sumcheck.round_polys.iter().flatten().copied()),
            ),
            air_challenges: encode(
                [challenges.alpha, challenges.beta, challenges.lambda]
                    .into_iter()
                    .chain(challenges.tau),
            ),
            air_point: encode(air_point.as_slice().iter().copied()),
            final_sum: encode([final_sum]),
            post_air_challenge: encode([ch.sample()]),
        });
    });
    Ok(())
}
