//! Public terminal key geometry and expressions for independent arithmetic replay.
use anyhow::{Result, ensure};
use p3_air::symbolic::SymbolicExpression;
use p3_binary_field::{Poly64 as F, Poly192 as E};
use p3_bus::{BusActivation, BusBoundary, BusDirection, BusPlan, BusSymbolicBuilder, BusTupleSlot};
use p3_challenger::fs::{
    DomainSeparator, FieldUnit, Hierarchy, Interaction, InteractionPattern, Kind, Length,
};
use p3_multi_stark::folder::VerifierAir;
use p3_sumcheck::{TableShape, layout::plan_stacked_layout};
use serde::Serialize;

use crate::encoding::TableEncoding;

#[derive(Serialize)]
pub(super) struct TableColumns {
    height: usize,
    batches: usize,
    widths: Vec<usize>,
    committed: usize,
    suffix: Vec<u64>,
    scale: u64,
    digit_bits: usize,
    slot: usize,
    domain: String,
}

fn columns(encodings: &[TableEncoding], heights: &[(usize, usize)]) -> Result<Vec<TableColumns>> {
    ensure!(encodings.len() == heights.len(), "invalid column layout");
    let shapes: Vec<_> = encodings
        .iter()
        .zip(heights)
        .map(|(e, &(h, _))| {
            TableShape::new(
                h + e.word.as_ref().map_or(0, |w| w.suffix.len()),
                e.committed_width,
            )
        })
        .collect();
    let (_, placements) = plan_stacked_layout(&shapes);
    let mut slots = vec![0; shapes.len()];
    for placement in placements {
        slots[placement.idx()] = placement.selectors()[0].index();
    }
    Ok(encodings
        .iter()
        .enumerate()
        .map(|(i, e)| {
            let rows = shapes[i].num_variables();
            let width = e.committed_width;
            let batches = heights[i].1;
            let steps = (0..batches)
                .flat_map(|_| {
                    [
                        (Kind::Message, "row_point", rows),
                        (Kind::Message, "column_values", width),
                        (
                            Kind::Challenge,
                            "column_point",
                            width.next_power_of_two().ilog2() as usize,
                        ),
                    ]
                })
                .map(|(kind, label, len)| {
                    Interaction::algebra::<F, E>(Hierarchy::Atomic, kind, label, Length::Fixed(len))
                })
                .collect();
            let mut separator = DomainSeparator::<FieldUnit<F>>::new(
                1,
                b"p3-boolean-trace-column-batching",
                InteractionPattern::new(steps).expect("valid column transcript"),
            );
            for n in [rows, width, batches] {
                separator.instance(&(n as u64).to_be_bytes());
            }
            let mut words = super::arithmetic::Words(vec![]);
            separator.seed(&mut words);
            TableColumns {
                height: heights[i].0,
                batches,
                widths: e.widths.clone(),
                committed: e.committed_width,
                suffix: e.word.as_ref().map_or_else(Vec::new, |w| w.suffix.clone()),
                scale: e.word.as_ref().map_or(1, |w| w.scale),
                digit_bits: e.word.as_ref().map_or(1, |w| w.digit_bits()),
                slot: slots[i],
                domain: hex::encode(words.0),
            }
        })
        .collect())
}

#[derive(Serialize)]
struct Share {
    air: usize,
    pull: bool,
    prefix_index: usize,
    prefix_variables: usize,
    domain_slots: Vec<usize>,
    payload: Vec<SymbolicExpression<F>>,
    activation: Option<SymbolicExpression<F>>,
}

#[derive(Serialize)]
pub(crate) struct ArithmeticKey {
    heights: Vec<usize>,
    fixed_widths: Vec<usize>,
    basis: Vec<u64>,
    constraints: Vec<Vec<SymbolicExpression<F>>>,
    periodic: Vec<bool>,
    main: Vec<TableColumns>,
    fixed: Vec<TableColumns>,
    shares: Vec<Share>,
}

impl ArithmeticKey {
    pub(super) fn from_airs<A: VerifierAir<F, E>>(
        airs: &[A],
        heights: &[usize],
        declarations: &[BusSymbolicBuilder<F, E>],
        plan: &BusPlan,
        main: &[TableEncoding],
        fixed: &[TableEncoding],
        auxiliary: &[p3_sumcheck::TableSpec],
    ) -> Result<Self> {
        for a in airs {
            ensure!(
                a.public_boundary_io().is_empty()
                    && a.main_next_row_columns().is_empty()
                    && a.preprocessed_next_row_columns().is_empty(),
                "unsupported terminal opening window"
            );
        }
        let mut shares = Vec::new();
        for dir in BusDirection::ALL {
            for s in plan.terminal_shares(dir) {
                let i = &declarations[s.owner.air].interactions()[s.owner.declaration];
                let activation = match &i.activation {
                    BusActivation::Always => None,
                    BusActivation::Boundary(BusBoundary::First) => Some(SymbolicExpression::Leaf(
                        p3_air::symbolic::BaseLeaf::IsFirstRow,
                    )),
                    BusActivation::Boundary(BusBoundary::Last) => Some(SymbolicExpression::Leaf(
                        p3_air::symbolic::BaseLeaf::IsLastRow,
                    )),
                    BusActivation::Boolean(e) => Some(e.clone()),
                };
                shares.push(Share {
                    air: s.owner.air,
                    pull: dir == BusDirection::Pull,
                    prefix_index: s.prefix_index,
                    prefix_variables: s.prefix_variables,
                    domain_slots: (0..plan.fingerprint_width())
                        .filter(|&slot| {
                            matches!(
                                plan.tuple_slot(s.bus, slot),
                                Some(BusTupleSlot::DomainBit(true))
                            )
                        })
                        .collect(),
                    payload: i.fields.clone(),
                    activation,
                });
            }
        }
        let periodic = airs
            .iter()
            .zip(heights)
            .map(|(a, h)| -> Result<bool> {
                let statement = a.periodic_statement();
                ensure!(
                    statement.is_empty()
                        || statement
                            == [
                                b"imt-successor-address-v1".as_slice(),
                                &(*h as u64).to_le_bytes()
                            ]
                            .concat(),
                    "unsupported periodic column formula"
                );
                Ok(!statement.is_empty())
            })
            .collect::<Result<Vec<_>>>()?;
        let main_heights = heights
            .iter()
            .map(|&h| (h, 1))
            .chain(
                auxiliary
                    .iter()
                    .map(|t| (t.shape().num_variables(), t.point_schedule().len())),
            )
            .collect::<Vec<_>>();
        let fixed_heights = heights
            .iter()
            .zip(airs)
            .filter(|(_, a)| a.preprocessed_width() > 0)
            .map(|(&h, _)| (h, 1))
            .collect::<Vec<_>>();
        Ok(Self {
            heights: heights.to_vec(),
            fixed_widths: airs.iter().map(|a| a.preprocessed_width()).collect(),
            basis: crate::mixed::coordinate_basis::<F>()
                .into_iter()
                .map(|v| v.to_bits())
                .collect(),
            periodic,
            constraints: declarations.iter().map(|a| a.base_constraints()).collect(),
            main: columns(main, &main_heights)?,
            fixed: columns(fixed, &fixed_heights)?,
            shares,
        })
    }
}
