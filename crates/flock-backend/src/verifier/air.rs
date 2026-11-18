//! Compact verifier-only AIR descriptions, exported from the trusted native AIRs.
use anyhow::{Result, ensure};
use p3_air::symbolic::{AirLayout, SymbolicExpression};
use p3_air::{Air, BaseAir};
use p3_bus::{
    BusActivation, BusBoundary, BusDirection, BusInteractionBuilder, BusName, BusSymbolicBuilder,
};
use p3_field::ExtensionField;
use serde::{Deserialize, Serialize};

use super::replay::RecordedBus;
use crate::{
    F,
    air::{Chip, successor_values},
};

#[derive(Serialize, Deserialize)]
pub(super) struct VerifierAir {
    pub width: usize,
    pub preprocessed_width: usize,
    pub public_count: usize,
    pub log_height: usize,
    successor: bool,
    constraints: Vec<SymbolicExpression<F>>,
    interactions: Vec<Interaction>,
}

#[derive(Serialize, Deserialize)]
struct Interaction {
    name: String,
    push: bool,
    fields: Vec<SymbolicExpression<F>>,
    activation: Activation,
}

#[derive(Serialize, Deserialize)]
enum Activation {
    Always,
    First,
    Last,
    Boolean(SymbolicExpression<F>),
}

impl VerifierAir {
    pub fn capture(air: &Chip, log_height: usize) -> Result<Self> {
        ensure!(
            air.main_next_row_columns().is_empty()
                && air.preprocessed_next_row_columns().is_empty(),
            "verifier AIR has successor-window access"
        );
        let builder = BusSymbolicBuilder::<F, F>::from_air(air, AirLayout::from_air(air));
        ensure!(
            builder.extension_constraints().is_empty(),
            "unexpected extension constraints"
        );
        Ok(Self {
            width: air.width(),
            preprocessed_width: air.preprocessed_width(),
            public_count: air.num_public_values(),
            log_height,
            successor: air.has_successor(),
            constraints: builder.base_constraints(),
            interactions: builder
                .interactions()
                .iter()
                .map(|i| Interaction {
                    name: i.bus_name.clone(),
                    push: i.direction == BusDirection::Push,
                    fields: i.fields.clone(),
                    activation: match &i.activation {
                        BusActivation::Always => Activation::Always,
                        BusActivation::Boundary(BusBoundary::First) => Activation::First,
                        BusActivation::Boundary(BusBoundary::Last) => Activation::Last,
                        BusActivation::Boolean(e) => Activation::Boolean(e.clone()),
                    },
                })
                .collect(),
        })
    }
}

impl BaseAir<F> for VerifierAir {
    fn width(&self) -> usize {
        self.width
    }
    fn preprocessed_width(&self) -> usize {
        self.preprocessed_width
    }
    fn num_public_values(&self) -> usize {
        self.public_count
    }
    fn main_next_row_columns(&self) -> Vec<usize> {
        vec![]
    }
    fn preprocessed_next_row_columns(&self) -> Vec<usize> {
        vec![]
    }
    fn num_periodic_columns(&self) -> usize {
        2 * usize::from(self.successor)
    }
    fn periodic_periods(&self) -> Vec<usize> {
        if self.successor {
            vec![1 << self.log_height; 2]
        } else {
            vec![]
        }
    }
    fn periodic_statement(&self) -> Vec<u8> {
        if self.successor {
            [
                b"imt-successor-address-v1".as_slice(),
                &(self.log_height as u64).to_le_bytes(),
            ]
            .concat()
        } else {
            vec![]
        }
    }
    fn periodic_evaluations<EF: ExtensionField<F>>(&self, point: &[EF]) -> Option<Vec<EF>> {
        if self.successor {
            assert_eq!(point.len(), self.log_height);
            Some(successor_values(point))
        } else {
            Some(vec![])
        }
    }
}

impl<AB: BusInteractionBuilder<F = F>> Air<AB> for VerifierAir {
    fn eval(&self, builder: &mut AB) {
        for constraint in &self.constraints {
            builder.assert_zero(constraint.resolve(builder));
        }
        if !AB::RECORDS_BUS_INTERACTIONS {
            return;
        }
        let mut recorded = RecordedBus(builder);
        for interaction in &self.interactions {
            let activation = match &interaction.activation {
                Activation::Always => BusActivation::Always,
                Activation::First => BusActivation::Boundary(BusBoundary::First),
                Activation::Last => BusActivation::Boundary(BusBoundary::Last),
                Activation::Boolean(e) => BusActivation::Boolean(e.resolve(&recorded)),
            };
            let fields: Vec<_> = interaction
                .fields
                .iter()
                .map(|e| e.resolve(&recorded))
                .collect();
            recorded.push_bus_interaction(
                BusName::new(&interaction.name),
                if interaction.push {
                    BusDirection::Push
                } else {
                    BusDirection::Pull
                },
                fields,
                activation,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use old_binary_field::Poly64 as OldF;
    use p3_air::{AirLayout, BaseAir};
    use p3_bus::BusSymbolicBuilder;
    use p3_circuit::CircuitBuilder;
    use p3_circuit_prover::{
        direct::DirectCircuitLimits,
        native_bus::{KeccakCommitment, NativeBusCircuit},
    };

    use super::VerifierAir;
    use crate::{F, air::Chip};

    #[test]
    fn serialized_air_preserves_constraint_order_and_activation_checks() {
        let mut builder = CircuitBuilder::<OldF>::new();
        let bit = builder.alloc_private_input("bit");
        builder.assert_bool(bit);
        let value = builder.alloc_private_input("value");
        let result = builder.mul(bit, value);
        let public = builder.alloc_public_input("result");
        builder.connect(result, public);
        let circuit = builder.build().unwrap();
        let bus = NativeBusCircuit::with_compact_options(
            &circuit,
            "imt",
            4,
            DirectCircuitLimits {
                max_witnesses: 1024,
                max_operations: 1024,
                max_trace_cells: 1 << 20,
            },
            KeccakCommitment::Bits,
        )
        .unwrap();
        for (source, &log) in bus.airs().iter().zip(bus.log_heights()) {
            let mut air = Chip::import(source.clone(), log).unwrap();
            air.repeat(3, 8);
            let original = BusSymbolicBuilder::<F, F>::from_air(&air, AirLayout::from_air(&air));
            let snapshot = VerifierAir::capture(&air, log).unwrap();
            let bytes = postcard::to_allocvec(&snapshot).unwrap();
            let restored: VerifierAir = postcard::from_bytes(&bytes).unwrap();
            let replay =
                BusSymbolicBuilder::<F, F>::from_air(&restored, AirLayout::from_air(&restored));
            // Resolving an expression may duplicate shared Arc nodes. Compare
            // the complete ordered trees, including cached degrees, rather than
            // the serializer's pointer-sharing layout.
            assert_eq!(
                format!("{:?}", original.base_constraints()),
                format!("{:?}", replay.base_constraints())
            );
            assert_eq!(
                format!("{:?}", original.interactions()),
                format!("{:?}", replay.interactions())
            );
            assert_eq!(air.periodic_statement(), restored.periodic_statement());
            assert_eq!(air.periodic_periods(), restored.periodic_periods());
        }
    }
}
