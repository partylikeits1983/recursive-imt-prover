//! Eliminate auxiliary fanout values for wires used once or twice.
//!
//! Singletons need no equality; pairs match their two actual uses directly.
//! Higher-fanout wires and the zero sentinel retain their copy table. Equations and Keccak ports
//! remain unchanged. Classification and selectors use only trusted preprocessing.
use crate::F;
use anyhow::{Result, bail, ensure};
use old_air::symbolic::{BaseEntry, BaseLeaf, SymbolicExpr, SymbolicExpression};
use old_binary_field::{Poly64 as OldF, TowerLevel as OldTowerLevel};
use old_bus::{BusActivation, BusBoundary, BusDirection, SymbolicBusInteraction};
use p3_binary_field::TowerLevel;
use p3_matrix::dense::RowMajorMatrix;

pub struct CopyPruner {
    states: Vec<CopyState>,
    stats: CopyStats,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CopyState {
    Retain,
    Single,
    SingleDone,
    PairFirst,
    PairSecond,
    PairDone,
}

pub struct CopyStats {
    pub single_use: usize,
    pub pairs: usize,
}

pub struct CopySelectors {
    pub columns: Vec<Vec<bool>>,
    // One entry per retained interaction, indexing `columns` when replaced.
    pub replacements: Vec<Option<usize>>,
}

impl CopyPruner {
    pub fn new(witness_ids: usize) -> Self {
        Self {
            states: vec![CopyState::Retain; witness_ids],
            stats: CopyStats {
                single_use: 0,
                pairs: 0,
            },
        }
    }

    pub fn remove_group(&mut self, id: usize, count: usize) -> bool {
        if id == 0 || count > 2 {
            return false;
        }
        assert!(self.states[id] == CopyState::Retain);
        self.states[id] = match count {
            1 => CopyState::Single,
            2 => CopyState::PairFirst,
            _ => panic!("empty fanout group"),
        };
        true
    }

    pub fn finish(self) -> Result<CopyStats> {
        ensure!(
            self.states.iter().all(|s| matches!(
                s,
                CopyState::Retain | CopyState::SingleDone | CopyState::PairDone
            )),
            "eliminated fanout entry has missing pushes"
        );
        Ok(self.stats)
    }

    pub fn prune(
        &mut self,
        interactions: &mut Vec<SymbolicBusInteraction<OldF>>,
        preprocessing: Option<&RowMajorMatrix<F>>,
        column_map: &[Option<usize>],
        log_height: usize,
    ) -> Result<CopySelectors> {
        let height = 1 << log_height;
        if let Some(pp) = preprocessing {
            ensure!(
                pp.values.len() == pp.width * height,
                "copy selector height mismatch"
            );
        }
        let mut result = CopySelectors {
            columns: vec![],
            replacements: vec![],
        };
        let mut retained = Vec::with_capacity(interactions.len());
        for interaction in interactions.drain(..) {
            if interaction.bus_name != "imt.witness" || interaction.direction != BusDirection::Push
            {
                result.replacements.push(None);
                retained.push(interaction);
                continue;
            }
            ensure!(
                interaction.fields.len() == 2,
                "unexpected witness bus tuple"
            );
            let mut selectors = Vec::with_capacity(height);
            let mut pulls = Vec::with_capacity(height);
            let mut changed = false;
            let mut singleton_removed = false;
            for row in 0..height {
                let pp = preprocessing.map_or(&[][..], |pp| {
                    &pp.values[row * pp.width..(row + 1) * pp.width]
                });
                let active = match &interaction.activation {
                    BusActivation::Always => true,
                    BusActivation::Boundary(BusBoundary::First) => row == 0,
                    BusActivation::Boundary(BusBoundary::Last) => row + 1 == height,
                    BusActivation::Boolean(value) => {
                        let value = fixed_row(value, pp, column_map)?.to_repr();
                        ensure!(value <= 1, "non-Boolean witness bus selector");
                        value == 1
                    }
                };
                let (remove, reverse) = if active {
                    let id = usize::try_from(
                        fixed_row(&interaction.fields[0], pp, column_map)?.to_repr(),
                    )?;
                    let state = self
                        .states
                        .get_mut(id)
                        .ok_or_else(|| anyhow::anyhow!("witness bus ID out of range"))?;
                    match state {
                        CopyState::Single => {
                            *state = CopyState::SingleDone;
                            self.stats.single_use += 1;
                            (true, false)
                        }
                        CopyState::PairFirst => {
                            *state = CopyState::PairSecond;
                            (false, true)
                        }
                        CopyState::PairSecond => {
                            *state = CopyState::PairDone;
                            self.stats.pairs += 1;
                            (false, false)
                        }
                        CopyState::Retain => (false, false),
                        _ => bail!("eliminated fanout ID has too many pushes"),
                    }
                } else {
                    (false, false)
                };
                singleton_removed |= remove;
                changed |= remove || reverse;
                selectors.push(active && !remove && !reverse);
                pulls.push(reverse);
            }
            if !changed {
                result.replacements.push(None);
                retained.push(interaction);
                continue;
            }
            let has_pushes = selectors.iter().any(|&v| v);
            if has_pushes {
                result.add(&mut retained, interaction.clone(), selectors);
            }
            if pulls.iter().any(|&v| v) {
                let mut pull = interaction;
                pull.direction = BusDirection::Pull;
                if !has_pushes && !singleton_removed {
                    // Every original active row became a pull; preserve the
                    // original selector, including public boundary activations.
                    result.replacements.push(None);
                    retained.push(pull);
                } else {
                    result.add(&mut retained, pull, pulls);
                }
            }
        }
        *interactions = retained;
        Ok(result)
    }
}

impl CopySelectors {
    fn add(
        &mut self,
        retained: &mut Vec<SymbolicBusInteraction<OldF>>,
        interaction: SymbolicBusInteraction<OldF>,
        selectors: Vec<bool>,
    ) {
        // The full activation is a committed Boolean column. This avoids
        // increasing the degree by multiplying two preprocessing selectors.
        let column = self
            .columns
            .iter()
            .position(|c| c == &selectors)
            .unwrap_or_else(|| {
                self.columns.push(selectors);
                self.columns.len() - 1
            });
        self.replacements.push(Some(column));
        retained.push(interaction);
    }
}

fn fixed_row(e: &SymbolicExpression<OldF>, pp: &[F], map: &[Option<usize>]) -> Result<OldF> {
    Ok(match e {
        SymbolicExpr::Leaf(BaseLeaf::Constant(v)) => *v,
        SymbolicExpr::Leaf(BaseLeaf::Variable(v))
            if v.entry == (BaseEntry::Preprocessed { offset: 0 }) =>
        {
            match map
                .get(v.index)
                .ok_or_else(|| anyhow::anyhow!("copy preprocessing column out of range"))?
            {
                Some(column) => OldF::from_repr(
                    pp.get(*column)
                        .ok_or_else(|| anyhow::anyhow!("missing copy preprocessing"))?
                        .to_repr(),
                ),
                None => OldF::from_repr(0),
            }
        }
        SymbolicExpr::Add { x, y, .. } => fixed_row(x, pp, map)? + fixed_row(y, pp, map)?,
        SymbolicExpr::Sub { x, y, .. } => fixed_row(x, pp, map)? - fixed_row(y, pp, map)?,
        SymbolicExpr::Mul { x, y, .. } => fixed_row(x, pp, map)? * fixed_row(y, pp, map)?,
        SymbolicExpr::Neg { x, .. } => -fixed_row(x, pp, map)?,
        _ => bail!("witness-dependent copy selector or ID"),
    })
}
