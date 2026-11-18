//! Import native AIRs and exact linear packing replacements.
use crate::{
    F,
    copies::{CopyPruner, CopySelectors},
    fanout::FanoutShard,
    gates::GateShard,
    packing::{self, PackedShard},
    recursive_layout,
};
use anyhow::{Result, ensure};
use old_air::symbolic::{BaseEntry, BaseLeaf, SymbolicExpr, SymbolicExpression, SymbolicVariable};
use old_air::{AirLayout as OldLayout, BaseAir as OldBaseAir};
use old_binary_field::Poly64 as OldF;
use old_binary_field::TowerLevel as OldTowerLevel;
use old_bus::{
    BusActivation as OldActivation, BusBoundary as OldBoundary, BusDirection as OldDirection,
    BusSymbolicBuilder, SymbolicBusInteraction,
};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_binary_field::TowerLevel;
use p3_bus::{BusActivation, BusBoundary, BusDirection, BusInteractionBuilder, BusName};
use p3_circuit_prover::native_bus::NativeBusCircuitAir;
use p3_field::{ExtensionField, Field, PrimeCharacteristicRing};
use p3_matrix::dense::RowMajorMatrix;
use std::{borrow::Cow, sync::Arc};

pub enum Chip {
    Native(Box<ImportedAir>),
    Keccak { preprocessing: RowMajorMatrix<F> },
}

pub struct ImportedAir {
    copies: CopySelectors,
    instances: usize,
    hash_stride: usize,
    bindings: Vec<InstanceBinding>,
    source: Source,
    successor: bool,
    public_table: bool,
    public_ids: Option<Vec<F>>,
    shard: Option<Arc<FanoutShard>>,
    gates: Option<Arc<GateShard>>,
    successor_bus: String,
    preprocessed_map: Vec<Option<usize>>,
    log_height: usize,
    constraints: Vec<SymbolicExpression<OldF>>,
    interactions: Vec<SymbolicBusInteraction<OldF>>,
}

struct InstanceBinding {
    successor_bus: String,
    bus_names: Vec<String>,
}

enum Source {
    Native(NativeBusCircuitAir<OldF>),
    Packed(Arc<PackedShard>),
}

impl Source {
    fn width(&self) -> usize {
        match self {
            Self::Native(a) => a.width(),
            Self::Packed(_) => packing::WIDTH,
        }
    }

    fn num_public_values(&self) -> usize {
        match self {
            Self::Native(a) => a.num_public_values(),
            Self::Packed(_) => 0,
        }
    }

    fn preprocessing(&self) -> Option<RowMajorMatrix<F>> {
        match self {
            Self::Native(a) => a
                .preprocessed_trace()
                .map(|m| RowMajorMatrix::new(m.values.into_iter().map(convert).collect(), m.width)),
            Self::Packed(shard) => Some(shard.preprocessing()),
        }
    }
}

impl Chip {
    pub fn packed(shard: Arc<PackedShard>) -> Self {
        let main =
            |i| SymbolicExpression::from(SymbolicVariable::new(BaseEntry::Main { offset: 0 }, i));
        let pp = |i| {
            SymbolicExpression::from(SymbolicVariable::new(
                BaseEntry::Preprocessed { offset: 0 },
                i,
            ))
        };
        let mut equation = main(packing::TERMS + 1) - main(packing::TERMS);
        let mut constraints = Vec::new();
        let active = shard.active_offset();
        if shard.geometric {
            let mut word = SymbolicExpression::from(OldF::from_repr(0));
            for i in 0..packing::TERMS {
                word += main(i) * OldF::from_repr(1 << i);
                // Inactive trailing bits must be zero even when the scale is nonzero.
                constraints.push(main(i) * (main(i) - pp(active + i)));
            }
            equation -= pp(packing::COEFFICIENTS) * word;
        } else {
            for i in 0..packing::TERMS {
                equation -= main(i) * pp(packing::COEFFICIENTS + i);
                constraints.push(main(i) * (main(i) - OldF::from_repr(1)));
            }
        }
        constraints.push(equation);
        Self::Native(Box::new(ImportedAir {
            copies: CopySelectors {
                columns: vec![],
                replacements: vec![],
            },
            instances: 1,
            hash_stride: 0,
            bindings: vec![],
            successor: false,
            public_table: false,
            public_ids: None,
            shard: None,
            gates: None,
            successor_bus: String::new(),
            preprocessed_map: (0..shard.pp_width()).map(Some).collect(),
            log_height: shard.log_height,
            constraints,
            interactions: (0..packing::WIDTH)
                .map(|i| SymbolicBusInteraction {
                    bus_name: "imt.witness".to_owned(),
                    direction: OldDirection::Push,
                    fields: vec![pp(i), main(i)],
                    activation: OldActivation::Boolean(pp(active + i)),
                })
                .collect(),
            source: Source::Packed(shard),
        }))
    }

    pub fn repeat(&mut self, instances: usize, hash_stride: usize) {
        if let Self::Native(a) = self {
            a.instances = instances;
            a.hash_stride = hash_stride;
            a.bindings = (0..instances)
                .map(|instance| InstanceBinding {
                    successor_bus: format!("{}.{}", a.successor_bus, instance),
                    bus_names: a
                        .interactions
                        .iter()
                        .map(|i| {
                            if i.bus_name == "imt.keccak" {
                                i.bus_name.clone()
                            } else {
                                format!("{}.{}", i.bus_name, instance)
                            }
                        })
                        .collect(),
                })
                .collect();
        }
    }

    pub fn instance_width(&self) -> usize {
        match self {
            Self::Native(a) if a.public_table => 1,
            Self::Native(a) => a.source.width() + usize::from(a.successor),
            Self::Keccak { .. } => 232,
        }
    }

    pub fn prune_copies(&mut self, pruner: &mut CopyPruner) -> Result<()> {
        if !matches!(self, Self::Native(a) if a.shard.is_none()) {
            return Ok(());
        }
        let pp = self.preprocessed_trace();
        if let Self::Native(a) = self {
            ensure!(
                a.copies.columns.is_empty()
                    && a.copies.replacements.is_empty()
                    && a.bindings.is_empty(),
                "copies already pruned"
            );
            a.copies = pruner.prune(
                &mut a.interactions,
                pp.as_ref(),
                &a.preprocessed_map,
                a.log_height,
            )?;
        }
        Ok(())
    }

    pub fn has_successor(&self) -> bool {
        matches!(self, Self::Native(a) if a.successor)
    }
    pub fn is_public_table(&self) -> bool {
        matches!(self, Self::Native(a) if a.public_table)
    }

    pub fn fix_fanout_zero(&mut self) -> Result<()> {
        let Self::Native(a) = self else {
            anyhow::bail!("expected a fanout table");
        };
        ensure!(a.shard.is_some(), "expected partitioned fanout");
        a.constraints.retain(|c| !is_first_zero(c));
        let first = SymbolicExpression::Leaf(BaseLeaf::IsFirstRow);
        let main =
            SymbolicExpression::from(SymbolicVariable::new(BaseEntry::Main { offset: 0 }, 0));
        a.constraints.push(first * main);
        Ok(())
    }

    pub fn commit_public_ids(&mut self) -> Result<()> {
        let Self::Native(a) = self else {
            anyhow::bail!("expected a public table");
        };
        ensure!(
            a.public_table
                && a.public_ids.is_none()
                && a.copies.columns.is_empty()
                && a.bindings.is_empty()
                && a.preprocessed_map.is_empty()
                && a.interactions.len() == a.source.num_public_values(),
            "unexpected public table layout"
        );
        let ids = a
            .interactions
            .iter()
            .enumerate()
            .map(|(column, interaction)| {
                ensure!(
                    interaction.bus_name == "imt.witness"
                        && interaction.direction == OldDirection::Push
                        && interaction.fields.len() == 2
                        && is_column(
                            &interaction.fields[1],
                            BaseEntry::Main { offset: 0 },
                            column
                        )
                        && matches!(
                            interaction.activation,
                            OldActivation::Boundary(OldBoundary::First)
                        ),
                    "unexpected public wire binding"
                );
                let SymbolicExpr::Leaf(BaseLeaf::Constant(id)) = &interaction.fields[0] else {
                    anyhow::bail!("public wire ID is not constant");
                };
                Ok(convert(*id))
            })
            .collect::<Result<Vec<_>>>()?;
        for (column, interaction) in a.interactions.iter_mut().enumerate() {
            interaction.fields[0] =
                SymbolicVariable::new(BaseEntry::Preprocessed { offset: 0 }, column).into();
        }
        a.preprocessed_map = (0..ids.len()).map(Some).collect();
        a.public_ids = Some(ids);
        Ok(())
    }

    pub fn pad_keccak_bridge(&mut self, log_height: usize) -> Result<()> {
        let Self::Native(a) = self else {
            anyhow::bail!("expected a native Keccak bridge");
        };
        ensure!(
            a.source.width() == 116
                && a.preprocessed_map.len() == 120
                && a.constraints.iter().all(|c| is_fixed_zero(c, &[true; 120]))
                && !a.successor
                && a.copies.columns.is_empty()
                && a.bindings.is_empty()
                && (a.log_height..=26).contains(&log_height),
            "unexpected Keccak bridge layout or capacity: main {}, preprocessing {}, log height {} -> {log_height}",
            a.source.width(),
            a.preprocessed_map.len(),
            a.log_height
        );
        a.log_height = log_height;
        Ok(())
    }

    pub fn recursive_preprocessed_widths(&self) -> Result<Vec<usize>> {
        let Self::Native(a) = self else {
            return Ok(vec![
                recursive_layout::HASH_ROLE_BITS,
                recursive_layout::HASH_ROLE_BITS,
                1,
            ]);
        };
        ensure!(
            a.preprocessed_map
                .iter()
                .enumerate()
                .all(|(i, &column)| column == Some(i)),
            "recursive preprocessing must retain every column"
        );
        let id = recursive_layout::WITNESS_ID_BITS;
        let mut widths = if let Some(shard) = &a.shard {
            let mut widths = vec![1; shard.preprocessed_width()];
            widths[0] = id;
            widths
        } else if a.gates.is_some() {
            ensure!(
                a.preprocessed_map.len() == 14,
                "unexpected recursive gate schema"
            );
            let mut widths = vec![1; 14];
            widths[..5].fill(id);
            widths[5] = 64;
            widths
        } else if a.public_table {
            ensure!(
                a.public_ids.is_some(),
                "recursive public IDs must be committed"
            );
            vec![id; a.source.num_public_values()]
        } else if let Source::Packed(shard) = &a.source {
            let mut widths = vec![1; shard.pp_width()];
            widths[..packing::WIDTH].fill(id);
            widths[packing::COEFFICIENTS..shard.active_offset()].fill(64);
            widths
        } else {
            ensure!(
                a.source.width() == 116 && a.preprocessed_map.len() == 120,
                "unsupported recursive table"
            );
            let mut widths = vec![1; 120];
            widths[..116].fill(id);
            widths[116] = recursive_layout::HASH_ROWS_LOG + 1;
            widths
        };
        widths.extend(vec![1; a.copies.columns.len()]);
        ensure!(
            widths.len() == self.preprocessed_width(),
            "recursive preprocessing width mismatch"
        );
        Ok(widths)
    }
    pub fn import(source: NativeBusCircuitAir<OldF>, log_height: usize) -> Result<Self> {
        Self::import_shard(source, log_height, None)
    }
    pub fn import_gates(source: NativeBusCircuitAir<OldF>, shard: Arc<GateShard>) -> Result<Self> {
        ensure!(
            source.main_next_row_columns().is_empty(),
            "arithmetic partition has successor access"
        );
        let Self::Native(mut air) = Self::import(source, shard.log_height)? else {
            unreachable!()
        };
        ensure!(
            shard.zero_columns.len() == air.preprocessed_map.len(),
            "gate preprocessing width mismatch"
        );
        let mut next = 0;
        air.preprocessed_map = shard
            .zero_columns
            .iter()
            .map(|&zero| {
                if zero {
                    None
                } else {
                    let column = next;
                    next += 1;
                    Some(column)
                }
            })
            .collect();
        ensure!(next > 0, "empty arithmetic preprocessing");
        air.constraints = air
            .constraints
            .iter()
            .map(|c| specialize(c, &shard.zero_columns))
            .collect();
        air.interactions.retain(|i| {
            !matches!(&i.activation, OldActivation::Boolean(v)
            if is_fixed_zero(v, &shard.zero_columns))
        });
        air.gates = Some(shard);
        Ok(Self::Native(air))
    }
    pub fn import_shard(
        source: NativeBusCircuitAir<OldF>,
        log_height: usize,
        shard: Option<Arc<FanoutShard>>,
    ) -> Result<Self> {
        let symbolic =
            BusSymbolicBuilder::<OldF, OldF>::from_air(&source, OldLayout::from_air(&source));
        ensure!(
            symbolic.extension_constraints().is_empty(),
            "unexpected extension AIR"
        );
        ensure!(
            source.num_periodic_columns() == 0,
            "unexpected periodic AIR"
        );
        let next = source.main_next_row_columns();
        let mut successor = !next.is_empty();
        ensure!(
            !successor || (source.width() == 1 && next == [0]),
            "unsupported successor table"
        );
        ensure!(
            source.preprocessed_next_row_columns().is_empty(),
            "unsupported preprocessing successor"
        );
        let mut constraints = symbolic.base_constraints();
        if shard.is_some() {
            let interactions = symbolic.interactions();
            ensure!(
                successor
                    && source.preprocessed_width() == 3
                    && interactions.len() == 1
                    && interactions[0].direction == OldDirection::Pull
                    && interactions[0].fields.len() == 2
                    && is_column(
                        &interactions[0].fields[0],
                        BaseEntry::Preprocessed { offset: 0 },
                        0
                    )
                    && is_column(&interactions[0].fields[1], BaseEntry::Main { offset: 0 }, 0)
                    && matches!(&interactions[0].activation, OldActivation::Boolean(v)
                        if is_column(v, BaseEntry::Preprocessed { offset: 0 }, 1)),
                "unexpected native fanout interaction"
            );
        }
        let public_table = source.num_public_values() > 0;
        if public_table {
            ensure!(
                source.width() == source.num_public_values()
                    && source.preprocessed_width() == 0
                    && !successor
                    && constraints.len() == source.width()
                    && constraints
                        .iter()
                        .enumerate()
                        .all(|(i, e)| is_public_copy(e, i)),
                "unexpected native public-copy table"
            );
        }
        if shard.as_ref().is_some_and(|s| !s.needs_successor()) {
            // Every ID is represented by one row and is nonzero. The
            // same-ID selector is therefore identically zero. Remove only
            // equations that vanish by this trusted substitution, then check
            // that no remaining equation can read a successor value.
            constraints.retain(|c| !is_fixed_zero(c, &[false, false, true]));
            ensure!(
                constraints.iter().all(|c| !uses_next_main(c)),
                "remaining fanout successor constraint"
            );
            successor = false;
        }
        Ok(Self::Native(Box::new(ImportedAir {
            instances: 1,
            hash_stride: 0,
            bindings: vec![],
            copies: CopySelectors {
                columns: vec![],
                replacements: vec![],
            },
            successor,
            public_table,
            public_ids: None,
            successor_bus: shard.as_ref().map_or_else(
                || "imt.successor".to_owned(),
                |s| {
                    format!(
                        "imt.successor.{}.{}",
                        s.coordinate_width,
                        s.copies_per_row()
                    )
                },
            ),
            shard,
            gates: None,
            preprocessed_map: (0..source.preprocessed_width()).map(Some).collect(),
            log_height,
            source: Source::Native(source),
            constraints,
            interactions: symbolic.interactions().to_vec(),
        })))
    }
}

impl BaseAir<F> for Chip {
    fn width(&self) -> usize {
        match self {
            Self::Native(a) if a.public_table => 1,
            Self::Native(a) => self.instance_width() * a.instances,
            Self::Keccak { .. } => 232,
        }
    }
    fn preprocessed_width(&self) -> usize {
        match self {
            Self::Native(a) if a.shard.is_some() => a.shard.as_ref().unwrap().preprocessed_width(),
            Self::Native(a) => {
                a.preprocessed_map.iter().filter(|c| c.is_some()).count() + a.copies.columns.len()
            }
            Self::Keccak { .. } => 3,
        }
    }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        let mut original = match self {
            Self::Native(a) if a.public_ids.is_some() => {
                let ids = a.public_ids.as_ref().unwrap();
                let mut values = vec![F::ZERO; ids.len() * (1 << a.log_height)];
                values[..ids.len()].copy_from_slice(ids);
                Some(RowMajorMatrix::new(values, ids.len()))
            }
            Self::Native(a) if a.gates.is_some() => {
                Some(a.gates.as_ref().unwrap().compact_preprocessing())
            }
            Self::Native(a) if a.shard.is_some() => Some(a.shard.as_ref().unwrap().preprocessing()),
            Self::Native(a) => a.source.preprocessing(),
            Self::Keccak { preprocessing } => Some(preprocessing.clone()),
        };
        let Self::Native(a) = self else {
            return original;
        };
        if let Some(pp) = &mut original {
            let cells = pp.width * (1 << a.log_height);
            assert!(
                pp.values.len() <= cells,
                "preprocessing exceeds table capacity"
            );
            pp.values.resize(cells, F::ZERO);
        }
        if a.copies.columns.is_empty() {
            return original;
        }
        let width = self.preprocessed_width();
        let mut values = vec![F::ZERO; width * (1 << a.log_height)];
        for (row, output) in values.chunks_exact_mut(width).enumerate() {
            let old_width = original.as_ref().map_or(0, |pp| pp.width);
            if let Some(pp) = &original {
                output[..old_width]
                    .copy_from_slice(&pp.values[row * old_width..(row + 1) * old_width]);
            }
            for (column, selector) in a.copies.columns.iter().enumerate() {
                output[old_width + column] = F::from_bool(selector[row]);
            }
        }
        Some(RowMajorMatrix::new(values, width))
    }
    fn num_public_values(&self) -> usize {
        match self {
            Self::Native(a) => a.source.num_public_values() * a.instances,
            Self::Keccak { .. } => 0,
        }
    }
    fn num_periodic_columns(&self) -> usize {
        2 * usize::from(self.has_successor())
    }
    fn periodic_periods(&self) -> Vec<usize> {
        match self {
            Self::Native(a) if a.successor => vec![1 << a.log_height; 2],
            _ => vec![],
        }
    }
    fn periodic_columns(&self) -> Cow<'_, [Vec<F>]> {
        match self {
            Self::Native(a) if a.successor => {
                let height = 1 << a.log_height;
                Cow::Owned(vec![
                    (0..height).map(|i| F::from_repr(i as u64)).collect(),
                    (0..height)
                        .map(|i| F::from_repr(((i + 1) % height) as u64))
                        .collect(),
                ])
            }
            _ => Cow::Borrowed(&[]),
        }
    }
    fn periodic_statement(&self) -> Vec<u8>
    where
        F: Field,
    {
        match self {
            Self::Native(a) if a.successor => [
                b"imt-successor-address-v1".as_slice(),
                &(a.log_height as u64).to_le_bytes(),
            ]
            .concat(),
            _ => vec![],
        }
    }
    fn periodic_evaluations<EF: ExtensionField<F>>(&self, point: &[EF]) -> Option<Vec<EF>> {
        match self {
            Self::Native(a) if a.successor => {
                assert_eq!(point.len(), a.log_height);
                Some(successor_values(point))
            }
            _ => Some(vec![]),
        }
    }
    fn main_next_row_columns(&self) -> Vec<usize> {
        vec![]
    }
    fn preprocessed_next_row_columns(&self) -> Vec<usize> {
        vec![]
    }
}

impl<AB: BusInteractionBuilder<F = F>> Air<AB> for Chip {
    fn eval(&self, b: &mut AB) {
        match self {
            Self::Native(a) => {
                for instance in 0..a.instances {
                    let main_offset = instance * self.instance_width();
                    let binding = a.bindings.get(instance);
                    let successor_bus =
                        binding.map_or(a.successor_bus.as_str(), |b| &b.successor_bus);
                    let bus = |index: usize| {
                        binding.map_or(a.interactions[index].bus_name.as_str(), |b| {
                            &b.bus_names[index]
                        })
                    };
                    if a.successor {
                        let row = [
                            b.main().current(main_offset).unwrap(),
                            b.main().current(main_offset + 1).unwrap(),
                        ];
                        let first = b.is_first_row();
                        let last = b.is_last_row();
                        b.push_bus_interaction_with(
                            BusName::new(successor_bus),
                            BusDirection::Push,
                            |b| vec![b.periodic_values()[0].into(), row[0].into()],
                            BusActivation::Boolean(AB::Expr::ONE - first),
                        );
                        b.push_bus_interaction_with(
                            BusName::new(successor_bus),
                            BusDirection::Pull,
                            |b| vec![b.periodic_values()[1].into(), row[1].into()],
                            BusActivation::Boolean(AB::Expr::ONE - last.clone()),
                        );
                        b.when(last).assert_eq(row[0], row[1]);
                    }
                    if a.public_table {
                        // The only committed column is a zero placeholder. Original
                        // main columns were uniquely fixed to public values.
                        b.assert_zero(b.main().current(0).unwrap());
                    }
                    for c in &a.constraints {
                        let value = resolve(c, b, a, instance);
                        b.assert_zero(value);
                    }
                    for (index, i) in a.interactions.iter().enumerate() {
                        let activation = if let Some(Some(column)) =
                            a.copies.replacements.get(index)
                        {
                            let offset = a.preprocessed_map.iter().filter(|c| c.is_some()).count();
                            BusActivation::Boolean(
                                b.preprocessed().current(offset + column).unwrap().into(),
                            )
                        } else {
                            match &i.activation {
                                OldActivation::Always => BusActivation::Always,
                                OldActivation::Boundary(v) => BusActivation::Boundary(match v {
                                    OldBoundary::First => BusBoundary::First,
                                    OldBoundary::Last => BusBoundary::Last,
                                }),
                                OldActivation::Boolean(v) => {
                                    BusActivation::Boolean(resolve(v, b, a, instance))
                                }
                            }
                        };
                        b.push_bus_interaction_with(
                            BusName::new(bus(index)),
                            match i.direction {
                                OldDirection::Push => BusDirection::Push,
                                OldDirection::Pull => BusDirection::Pull,
                            },
                            |b| {
                                let mut fields: Vec<_> = i
                                    .fields
                                    .iter()
                                    .map(|v| resolve(v, b, a, instance))
                                    .collect();
                                if i.bus_name == "imt.keccak" {
                                    fields[0] += F::from_repr((instance * a.hash_stride) as u64);
                                }
                                fields
                            },
                            activation,
                        );
                    }
                    if let Some(shard) = &a.shard {
                        // The first occurrence is the original imported pull.
                        // Additional occurrences use the SAME constrained value,
                        // with trusted Boolean selectors for the exact count.
                        for copy in 1..shard.copies_per_row() {
                            let active = b.preprocessed().current(2 + copy).unwrap();
                            b.push_bus_interaction_with(
                                BusName::new(bus(0)),
                                BusDirection::Pull,
                                |b| {
                                    vec![
                                        b.preprocessed().current(0).unwrap().into(),
                                        b.main().current(main_offset).unwrap().into(),
                                    ]
                                },
                                BusActivation::Boolean(active.into()),
                            );
                        }
                    }
                }
            }
            Self::Keccak { .. } => {
                let pp = core::array::from_fn::<_, 3, _>(|i| b.preprocessed().current(i).unwrap());
                for boundary in 0..2 {
                    b.push_bus_interaction_with(
                        BusName::new("imt.keccak"),
                        BusDirection::Push,
                        |b| {
                            let row = b.main();
                            core::iter::once(pp[boundary].into())
                                .chain(
                                    (boundary * 100..boundary * 100 + 100)
                                        .map(|i| row.current(i).unwrap().into()),
                                )
                                .chain(
                                    (200 + boundary * 16..216 + boundary * 16)
                                        .map(|i| row.current(i).unwrap().into()),
                                )
                                .collect::<Vec<AB::Expr>>()
                        },
                        BusActivation::Boolean(pp[2].into()),
                    );
                }
            }
        }
    }
}

pub fn convert(v: OldF) -> F {
    F::from_repr(v.to_repr())
}

fn is_column(e: &SymbolicExpression<OldF>, entry: BaseEntry, index: usize) -> bool {
    matches!(e, SymbolicExpr::Leaf(BaseLeaf::Variable(v)) if v.entry == entry && v.index == index)
}

fn is_first_zero(e: &SymbolicExpression<OldF>) -> bool {
    let SymbolicExpr::Mul { x, y, .. } = e else {
        return false;
    };
    (matches!(x.as_ref(), SymbolicExpr::Leaf(BaseLeaf::IsFirstRow))
        && is_column(y, BaseEntry::Main { offset: 0 }, 0))
        || (matches!(y.as_ref(), SymbolicExpr::Leaf(BaseLeaf::IsFirstRow))
            && is_column(x, BaseEntry::Main { offset: 0 }, 0))
}

fn uses_next_main(e: &SymbolicExpression<OldF>) -> bool {
    match e {
        SymbolicExpr::Leaf(BaseLeaf::Variable(v)) => {
            matches!(v.entry, BaseEntry::Main { offset: 1 })
        }
        SymbolicExpr::Add { x, y, .. }
        | SymbolicExpr::Sub { x, y, .. }
        | SymbolicExpr::Mul { x, y, .. } => uses_next_main(x) || uses_next_main(y),
        SymbolicExpr::Neg { x, .. } => uses_next_main(x),
        _ => false,
    }
}

fn resolve<AB: BusInteractionBuilder<F = F>>(
    e: &SymbolicExpression<OldF>,
    b: &AB,
    air: &ImportedAir,
    instance: usize,
) -> AB::Expr {
    let main_offset = instance * (air.source.width() + usize::from(air.successor));
    let public_offset = instance * air.source.num_public_values();
    match e {
        SymbolicExpr::Leaf(leaf) => match leaf {
            BaseLeaf::Constant(v) => AB::Expr::from(convert(*v)),
            BaseLeaf::IsFirstRow => b.is_first_row(),
            BaseLeaf::IsLastRow => b.is_last_row(),
            BaseLeaf::IsTransition => b.is_transition(),
            BaseLeaf::Variable(v) => match v.entry {
                BaseEntry::Main { offset: 0 } => {
                    if air.public_table {
                        b.public_values()[public_offset + v.index].into()
                    } else {
                        b.main().current(main_offset + v.index).unwrap().into()
                    }
                }
                BaseEntry::Main { offset: 1 } => {
                    assert!(air.successor && v.index == 0);
                    b.main().current(main_offset + 1).unwrap().into()
                }
                BaseEntry::Preprocessed { offset: 0 } => match air.preprocessed_map[v.index] {
                    Some(column) => b.preprocessed().current(column).unwrap().into(),
                    None => AB::Expr::ZERO,
                },
                BaseEntry::Preprocessed { offset: 1 } => match air.preprocessed_map[v.index] {
                    Some(column) => b.preprocessed().next(column).unwrap().into(),
                    None => AB::Expr::ZERO,
                },
                BaseEntry::Public => b.public_values()[public_offset + v.index].into(),
                _ => panic!("unsupported trusted AIR variable"),
            },
        },
        SymbolicExpr::Add { x, y, .. } => {
            resolve(x, b, air, instance) + resolve(y, b, air, instance)
        }
        SymbolicExpr::Sub { x, y, .. } => {
            resolve(x, b, air, instance) - resolve(y, b, air, instance)
        }
        SymbolicExpr::Mul { x, y, .. } => {
            resolve(x, b, air, instance) * resolve(y, b, air, instance)
        }
        SymbolicExpr::Neg { x, .. } => -resolve(x, b, air, instance),
    }
}

// Both address polynomials use most-significant-first multilinear coordinates.
pub(crate) fn successor_values<EF: ExtensionField<F>>(point: &[EF]) -> Vec<EF> {
    let mut current = EF::ZERO;
    let mut next = EF::ZERO;
    let mut carry = EF::ONE;
    for (bit, &x) in point.iter().rev().enumerate() {
        let basis = F::from_repr(1u64 << bit);
        current += x * basis;
        next += (x + carry) * basis;
        carry *= x;
    }
    vec![current, next]
}

// Substitute only trusted zero preprocessing columns. Keep the ordered constraint
// list intact, including zero equations, so sumcheck weights remain unchanged.
fn specialize(e: &SymbolicExpression<OldF>, zero_columns: &[bool]) -> SymbolicExpression<OldF> {
    match e {
        SymbolicExpr::Leaf(BaseLeaf::Variable(v))
            if v.entry == (BaseEntry::Preprocessed { offset: 0 })
                && zero_columns.get(v.index) == Some(&true) =>
        {
            OldF::from_repr(0).into()
        }
        SymbolicExpr::Add { x, y, .. } => specialize(x, zero_columns) + specialize(y, zero_columns),
        SymbolicExpr::Sub { x, y, .. } => specialize(x, zero_columns) - specialize(y, zero_columns),
        SymbolicExpr::Mul { x, y, .. } => specialize(x, zero_columns) * specialize(y, zero_columns),
        SymbolicExpr::Neg { x, .. } => -specialize(x, zero_columns),
        _ => e.clone(),
    }
}

fn is_fixed_zero(e: &SymbolicExpression<OldF>, zero_columns: &[bool]) -> bool {
    matches!(specialize(e, zero_columns), SymbolicExpr::Leaf(BaseLeaf::Constant(v))
        if v == OldF::from_repr(0))
}

// Only eliminate columns whose imported equation is exactly main[i] = public[i].
// This is substitution of a uniquely fixed value, not dropping a proof obligation.
fn is_public_copy(e: &SymbolicExpression<OldF>, i: usize) -> bool {
    let SymbolicExpr::Sub { x, y, .. } = e else {
        return false;
    };
    matches!(x.as_ref(), SymbolicExpr::Leaf(BaseLeaf::Variable(v))
        if v.entry == (BaseEntry::Main { offset: 0 }) && v.index == i)
        && matches!(y.as_ref(), SymbolicExpr::Leaf(BaseLeaf::Variable(v))
            if v.entry == BaseEntry::Public && v.index == i)
}
