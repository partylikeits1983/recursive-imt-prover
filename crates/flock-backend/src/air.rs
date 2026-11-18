//! Translate the pinned native circuit AIR without changing its constraints.
use crate::{F, fanout::FanoutShard, gates::GateShard};
use anyhow::{Result, ensure};
use old_air::symbolic::{BaseEntry, BaseLeaf, SymbolicExpr, SymbolicExpression};
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
    source: NativeBusCircuitAir<OldF>,
    successor: bool,
    public_table: bool,
    shard: Option<Arc<FanoutShard>>,
    gates: Option<Arc<GateShard>>,
    successor_bus: String,
    preprocessed_map: Vec<Option<usize>>,
    log_height: usize,
    constraints: Vec<SymbolicExpression<OldF>>,
    interactions: Vec<SymbolicBusInteraction<OldF>>,
}

impl Chip {
    pub fn has_successor(&self) -> bool {
        matches!(self, Self::Native(a) if a.successor)
    }
    pub fn is_public_table(&self) -> bool {
        matches!(self, Self::Native(a) if a.public_table)
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
        air.interactions.retain(|i| {
            !matches!(&i.activation, OldActivation::Boolean(v)
            if fixed_value(v, &shard.zero_columns) == Some(OldF::from_repr(0)))
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
        let successor = !next.is_empty();
        ensure!(
            !successor || (source.width() == 1 && next == [0]),
            "unsupported successor table"
        );
        ensure!(
            source.preprocessed_next_row_columns().is_empty(),
            "unsupported preprocessing successor"
        );
        let constraints = symbolic.base_constraints();
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
        Ok(Self::Native(Box::new(ImportedAir {
            successor,
            public_table,
            successor_bus: shard.as_ref().map_or_else(
                || "imt.successor".to_owned(),
                |s| format!("imt.successor.{}", s.coordinate_width),
            ),
            shard,
            gates: None,
            preprocessed_map: (0..source.preprocessed_width()).map(Some).collect(),
            log_height,
            source,
            constraints,
            interactions: symbolic.interactions().to_vec(),
        })))
    }
}

impl BaseAir<F> for Chip {
    fn width(&self) -> usize {
        match self {
            Self::Native(a) if a.public_table => 1,
            Self::Native(a) => a.source.width() + usize::from(a.successor),
            Self::Keccak { .. } => 232,
        }
    }
    fn preprocessed_width(&self) -> usize {
        match self {
            Self::Native(a) => a.preprocessed_map.iter().filter(|c| c.is_some()).count(),
            Self::Keccak { .. } => 3,
        }
    }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        match self {
            Self::Native(a) if a.gates.is_some() => {
                Some(a.gates.as_ref().unwrap().compact_preprocessing())
            }
            Self::Native(a) if a.shard.is_some() => Some(a.shard.as_ref().unwrap().preprocessing()),
            Self::Native(a) => a
                .source
                .preprocessed_trace()
                .map(|m| RowMajorMatrix::new(m.values.into_iter().map(convert).collect(), m.width)),
            Self::Keccak { preprocessing } => Some(preprocessing.clone()),
        }
    }
    fn num_public_values(&self) -> usize {
        match self {
            Self::Native(a) => a.source.num_public_values(),
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
                if a.successor {
                    let row = b.main().current_slice().to_vec();
                    let addresses = b.periodic_values().to_vec();
                    // Every next-value is matched to the following row at its unique
                    // trusted address. The repeat-last endpoint is constrained locally.
                    let first = b.is_first_row();
                    let last = b.is_last_row();
                    b.push_bus_interaction(
                        BusName::new(&a.successor_bus),
                        BusDirection::Push,
                        [addresses[0].into(), row[0].into()],
                        BusActivation::Boolean(AB::Expr::ONE - first),
                    );
                    b.push_bus_interaction(
                        BusName::new(&a.successor_bus),
                        BusDirection::Pull,
                        [addresses[1].into(), row[1].into()],
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
                    let value = resolve(c, b, a.successor, &a.preprocessed_map, a.public_table);
                    b.assert_zero(value);
                }
                for i in &a.interactions {
                    let fields: Vec<_> = i
                        .fields
                        .iter()
                        .map(|v| resolve(v, b, a.successor, &a.preprocessed_map, a.public_table))
                        .collect();
                    let activation = match &i.activation {
                        OldActivation::Always => BusActivation::Always,
                        OldActivation::Boundary(v) => BusActivation::Boundary(match v {
                            OldBoundary::First => BusBoundary::First,
                            OldBoundary::Last => BusBoundary::Last,
                        }),
                        OldActivation::Boolean(v) => BusActivation::Boolean(resolve(
                            v,
                            b,
                            a.successor,
                            &a.preprocessed_map,
                            a.public_table,
                        )),
                    };
                    b.push_bus_interaction(
                        BusName::new(&i.bus_name),
                        match i.direction {
                            OldDirection::Push => BusDirection::Push,
                            OldDirection::Pull => BusDirection::Pull,
                        },
                        fields,
                        activation,
                    );
                }
            }
            Self::Keccak { .. } => {
                let row = b.main().current_slice().to_vec();
                let pp = b.preprocessed().current_slice().to_vec();
                for boundary in 0..2 {
                    let fields = core::iter::once(pp[boundary].into())
                        .chain(
                            row[boundary * 100..boundary * 100 + 100]
                                .iter()
                                .map(|v| (*v).into()),
                        )
                        .chain(
                            row[200 + boundary * 16..216 + boundary * 16]
                                .iter()
                                .map(|v| (*v).into()),
                        );
                    b.push_bus_interaction(
                        BusName::new("imt.keccak"),
                        BusDirection::Push,
                        fields,
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

fn resolve<AB: BusInteractionBuilder<F = F>>(
    e: &SymbolicExpression<OldF>,
    b: &AB,
    successor: bool,
    preprocessed_map: &[Option<usize>],
    public_table: bool,
) -> AB::Expr {
    match e {
        SymbolicExpr::Leaf(leaf) => match leaf {
            BaseLeaf::Constant(v) => AB::Expr::from(convert(*v)),
            BaseLeaf::IsFirstRow => b.is_first_row(),
            BaseLeaf::IsLastRow => b.is_last_row(),
            BaseLeaf::IsTransition => b.is_transition(),
            BaseLeaf::Variable(v) => match v.entry {
                BaseEntry::Main { offset: 0 } => {
                    if public_table {
                        b.public_values()[v.index].into()
                    } else {
                        b.main().current(v.index).unwrap().into()
                    }
                }
                BaseEntry::Main { offset: 1 } => {
                    assert!(successor && v.index == 0);
                    b.main().current(1).unwrap().into()
                }
                BaseEntry::Preprocessed { offset: 0 } => match preprocessed_map[v.index] {
                    Some(column) => b.preprocessed().current(column).unwrap().into(),
                    None => AB::Expr::ZERO,
                },
                BaseEntry::Preprocessed { offset: 1 } => match preprocessed_map[v.index] {
                    Some(column) => b.preprocessed().next(column).unwrap().into(),
                    None => AB::Expr::ZERO,
                },
                BaseEntry::Public => b.public_values()[v.index].into(),
                _ => panic!("unsupported trusted AIR variable"),
            },
        },
        SymbolicExpr::Add { x, y, .. } => {
            resolve(x, b, successor, preprocessed_map, public_table)
                + resolve(y, b, successor, preprocessed_map, public_table)
        }
        SymbolicExpr::Sub { x, y, .. } => {
            resolve(x, b, successor, preprocessed_map, public_table)
                - resolve(y, b, successor, preprocessed_map, public_table)
        }
        SymbolicExpr::Mul { x, y, .. } => {
            resolve(x, b, successor, preprocessed_map, public_table)
                * resolve(y, b, successor, preprocessed_map, public_table)
        }
        SymbolicExpr::Neg { x, .. } => -resolve(x, b, successor, preprocessed_map, public_table),
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

// Partial evaluation uses only fixed preprocessing; witness-dependent terms
// remain unknown. Removing a bus declaration is permitted only for exact zero.
fn fixed_value(e: &SymbolicExpression<OldF>, zero_columns: &[bool]) -> Option<OldF> {
    match e {
        SymbolicExpr::Leaf(BaseLeaf::Constant(v)) => Some(*v),
        SymbolicExpr::Leaf(BaseLeaf::Variable(v))
            if v.entry == (BaseEntry::Preprocessed { offset: 0 })
                && zero_columns.get(v.index) == Some(&true) =>
        {
            Some(OldF::from_repr(0))
        }
        SymbolicExpr::Add { x, y, .. } => {
            Some(fixed_value(x, zero_columns)? + fixed_value(y, zero_columns)?)
        }
        SymbolicExpr::Sub { x, y, .. } => {
            Some(fixed_value(x, zero_columns)? - fixed_value(y, zero_columns)?)
        }
        SymbolicExpr::Mul { x, y, .. } => {
            let x = fixed_value(x, zero_columns);
            let y = fixed_value(y, zero_columns);
            if x == Some(OldF::from_repr(0)) || y == Some(OldF::from_repr(0)) {
                Some(OldF::from_repr(0))
            } else {
                Some(x? * y?)
            }
        }
        SymbolicExpr::Neg { x, .. } => Some(-fixed_value(x, zero_columns)?),
        _ => None,
    }
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
