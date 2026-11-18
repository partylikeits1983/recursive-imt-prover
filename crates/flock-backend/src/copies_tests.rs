use crate::{F, copies::CopyPruner};
use old_air::symbolic::{BaseEntry, SymbolicExpression, SymbolicVariable};
use old_binary_field::{Poly64 as OldF, TowerLevel as OldTowerLevel};
use old_bus::{BusActivation, BusBoundary, BusDirection, SymbolicBusInteraction};
use p3_binary_field::TowerLevel;
use p3_matrix::dense::RowMajorMatrix;

fn variable(entry: BaseEntry, index: usize) -> SymbolicExpression<OldF> {
    SymbolicVariable::new(entry, index).into()
}

fn push() -> SymbolicBusInteraction<OldF> {
    SymbolicBusInteraction {
        bus_name: "imt.witness".to_owned(),
        direction: BusDirection::Push,
        fields: vec![
            variable(BaseEntry::Preprocessed { offset: 0 }, 0),
            variable(BaseEntry::Main { offset: 0 }, 0),
        ],
        activation: BusActivation::Boolean(variable(BaseEntry::Preprocessed { offset: 0 }, 1)),
    }
}

#[test]
fn singleton_pruning_keeps_zero_and_repeated_ids_and_uses_fixed_selectors() {
    let mut pruner = CopyPruner::new(4, false);
    assert!(!pruner.remove_group(0, 1));
    assert!(pruner.remove_group(1, 1));
    assert!(!pruner.remove_group(2, 4));
    assert!(!pruner.remove_group(3, 3));
    let pp = RowMajorMatrix::new([0, 1, 1, 1, 2, 1, 3, 0].map(F::from_repr).to_vec(), 2);
    let mut interactions = vec![push()];
    let result = pruner
        .prune(&mut interactions, Some(&pp), &[Some(0), Some(1)], 2)
        .unwrap();
    assert_eq!(result.columns, [vec![true, false, true, false]]);
    assert_eq!(result.replacements, [Some(0)]);
    assert_eq!(interactions.len(), 1);
    assert_eq!(pruner.finish().unwrap().single_use, 1);
}

#[test]
fn singleton_pruning_rejects_missing_duplicate_and_witness_dependent_entries() {
    let mut pruner = CopyPruner::new(2, false);
    pruner.remove_group(1, 1);
    assert!(pruner.finish().is_err());
    let pp = RowMajorMatrix::new([1, 1].map(F::from_repr).to_vec(), 2);
    let mut pruner = CopyPruner::new(2, false);
    pruner.remove_group(1, 1);
    assert!(
        pruner
            .prune(&mut vec![push(), push()], Some(&pp), &[Some(0), Some(1)], 0)
            .is_err()
    );
    for activation in [false, true] {
        let mut pruner = CopyPruner::new(2, false);
        let mut interaction = push();
        if activation {
            interaction.activation =
                BusActivation::Boolean(variable(BaseEntry::Main { offset: 0 }, 0));
        } else {
            interaction.fields[0] = variable(BaseEntry::Main { offset: 0 }, 0);
        }
        assert!(
            pruner
                .prune(&mut vec![interaction], Some(&pp), &[Some(0), Some(1)], 0)
                .is_err()
        );
    }
    let pp = RowMajorMatrix::new([1, 2].map(F::from_repr).to_vec(), 2);
    assert!(
        CopyPruner::new(2, false)
            .prune(&mut vec![push()], Some(&pp), &[Some(0), Some(1)], 0)
            .is_err()
    );
}

#[test]
fn singleton_pruning_handles_boundaries_without_touching_other_buses() {
    for boundary in [BusBoundary::First, BusBoundary::Last] {
        let mut pruner = CopyPruner::new(2, false);
        pruner.remove_group(1, 1);
        let mut interaction = push();
        interaction.fields[0] = SymbolicExpression::from(OldF::from_repr(1));
        interaction.activation = BusActivation::Boundary(boundary);
        let mut other = interaction.clone();
        other.bus_name = "imt.keccak".to_owned();
        let mut interactions = vec![other, interaction];
        let result = pruner.prune(&mut interactions, None, &[], 4).unwrap();
        assert!(result.columns.is_empty());
        assert_eq!(result.replacements, [None]);
        assert_eq!(interactions[0].bus_name, "imt.keccak");
        assert_eq!(pruner.finish().unwrap().single_use, 1);
    }
}

#[test]
fn paired_copies_match_two_actual_values_and_reject_incomplete_counts() {
    let mut pruner = CopyPruner::new(3, false);
    assert!(pruner.remove_group(1, 2));
    assert!(pruner.remove_group(2, 2));
    let pp = RowMajorMatrix::new([1, 1, 2, 1, 2, 1, 1, 1].map(F::from_repr).to_vec(), 2);
    let mut interactions = vec![push()];
    let result = pruner
        .prune(&mut interactions, Some(&pp), &[Some(0), Some(1)], 2)
        .unwrap();
    assert_eq!(
        result.columns,
        [
            vec![false, false, true, true],
            vec![true, true, false, false]
        ]
    );
    assert_eq!(result.replacements, [Some(0), Some(1)]);
    assert_eq!(interactions[0].direction, BusDirection::Push);
    assert_eq!(interactions[1].direction, BusDirection::Pull);
    assert_eq!(pruner.finish().unwrap().pairs, 2);
    // For each ID exactly one original value is pushed and one pulled.
    // Changing either value breaks the tuple equality; no auxiliary copy can
    // be altered to compensate. Different IDs remain distinct tuple fields.
    let values = [31u64, 41, 41, 31];
    let tuples = |values: &[u64; 4], selector: &[bool]| {
        let mut tuples: Vec<_> = (0..4)
            .filter(|&row| selector[row])
            .map(|row| (pp.values[2 * row].to_repr(), values[row]))
            .collect();
        tuples.sort_unstable();
        tuples
    };
    assert_eq!(
        tuples(&values, &result.columns[0]),
        tuples(&values, &result.columns[1])
    );
    for row in 0..4 {
        let mut changed = values;
        changed[row] ^= 1;
        assert_ne!(
            tuples(&changed, &result.columns[0]),
            tuples(&changed, &result.columns[1])
        );
    }
    for uses in [1, 3] {
        let mut pruner = CopyPruner::new(2, false);
        pruner.remove_group(1, 2);
        let pp = RowMajorMatrix::new([1, 1].map(F::from_repr).to_vec(), 2);
        let mut interactions = vec![push(); uses];
        let result = pruner.prune(&mut interactions, Some(&pp), &[Some(0), Some(1)], 0);
        if uses == 1 {
            assert!(result.is_ok());
            assert!(pruner.finish().is_err());
        } else {
            assert!(result.is_err());
        }
    }
}

#[test]
fn fixed_copy_layout_keeps_both_directions_and_inactive_slots() {
    for count in [0, 1, 2, 3] {
        let mut pruner = CopyPruner::new(2, true);
        if count != 0 {
            pruner.remove_group(1, count);
        }
        let mut values = vec![F::from_repr(0); 8];
        for row in values.as_chunks_mut::<2>().0.iter_mut().take(count) {
            *row = [F::from_repr(1), F::from_repr(1)];
        }
        let pp = RowMajorMatrix::new(values, 2);
        let mut interactions = vec![push()];
        let selectors = pruner
            .prune(&mut interactions, Some(&pp), &[Some(0), Some(1)], 2)
            .unwrap();
        assert_eq!(interactions.len(), 2);
        assert_eq!(interactions[0].direction, BusDirection::Push);
        assert_eq!(interactions[1].direction, BusDirection::Pull);
        assert_eq!(selectors.replacements, [Some(0), Some(1)]);
        assert_eq!(selectors.columns.len(), 2);
        let pushes: Vec<_> = selectors.columns[0]
            .iter()
            .enumerate()
            .filter_map(|(i, &v)| v.then_some(i))
            .collect();
        let pulls: Vec<_> = selectors.columns[1]
            .iter()
            .enumerate()
            .filter_map(|(i, &v)| v.then_some(i))
            .collect();
        match count {
            0 | 1 => {
                assert!(pushes.is_empty());
                assert!(pulls.is_empty());
            }
            2 => {
                assert_eq!(pushes, [1]);
                assert_eq!(pulls, [0]);
            }
            _ => {
                assert_eq!(pushes, [0, 1, 2]);
                assert!(pulls.is_empty());
            }
        }
        pruner.finish().unwrap();
    }
}
