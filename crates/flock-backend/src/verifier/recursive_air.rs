use std::borrow::Cow;

use anyhow::Result;
use old_air::{Air, AirBuilder, BaseAir, symbolic::SymbolicExpression};
use old_binary_field::Poly64 as F;
use old_bus::{
    BusActivation, BusBoundary, BusDirection, BusInteractionBuilder, BusInteractionRecorder,
    BusName, RecordToken,
};
use serde::Deserialize;

#[derive(Deserialize)]
pub(super) struct RecursiveAir {
    width: usize,
    preprocessed_width: usize,
    public_count: usize,
    log_height: usize,
    successor: bool,
    constraints: Vec<SymbolicExpression<F>>,
    interactions: Vec<Interaction>,
}

#[derive(Deserialize)]
struct Interaction {
    name: String,
    push: bool,
    fields: Vec<SymbolicExpression<F>>,
    activation: Activation,
}

#[derive(Deserialize)]
enum Activation {
    Always,
    First,
    Last,
    Boolean(SymbolicExpression<F>),
}

struct Recorded<'a, B>(&'a mut B);

pub(super) fn convert(airs: &[super::air::VerifierAir]) -> Result<Vec<RecursiveAir>> {
    Ok(postcard::from_bytes(&postcard::to_allocvec(airs)?)?)
}

impl BaseAir<F> for RecursiveAir {
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
    fn periodic_columns(&self) -> Cow<'_, [Vec<F>]> {
        if !self.successor {
            return Cow::Owned(vec![]);
        }
        let size = 1usize << self.log_height;
        Cow::Owned(vec![
            (0..size).map(|i| F::new(i as u64)).collect(),
            (0..size)
                .map(|i| F::new(((i + 1) & (size - 1)) as u64))
                .collect(),
        ])
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
}

impl<B: BusInteractionBuilder<F = F>> Air<B> for RecursiveAir {
    fn eval(&self, b: &mut B) {
        for constraint in &self.constraints {
            b.assert_zero(constraint.resolve(b));
        }
        let mut b = Recorded(b);
        for interaction in &self.interactions {
            let activation = match &interaction.activation {
                Activation::Always => BusActivation::Always,
                Activation::First => BusActivation::Boundary(BusBoundary::First),
                Activation::Last => BusActivation::Boundary(BusBoundary::Last),
                Activation::Boolean(e) => BusActivation::Boolean(e.resolve(&b)),
            };
            let fields: Vec<_> = interaction.fields.iter().map(|e| e.resolve(&b)).collect();
            b.push_bus_interaction(
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

impl<B: AirBuilder> AirBuilder for Recorded<'_, B> {
    type F = B::F;
    type Expr = B::Expr;
    type Var = B::Var;
    type PreprocessedWindow = B::PreprocessedWindow;
    type MainWindow = B::MainWindow;
    type PublicVar = B::PublicVar;
    type PeriodicVar = B::PeriodicVar;
    fn main(&self) -> Self::MainWindow {
        self.0.main()
    }
    fn preprocessed(&self) -> &Self::PreprocessedWindow {
        self.0.preprocessed()
    }
    fn is_first_row(&self) -> Self::Expr {
        self.0.is_first_row()
    }
    fn is_last_row(&self) -> Self::Expr {
        self.0.is_last_row()
    }
    fn is_transition(&self) -> Self::Expr {
        self.0.is_transition()
    }
    fn public_values(&self) -> &[Self::PublicVar] {
        self.0.public_values()
    }
    fn periodic_values(&self) -> &[Self::PeriodicVar] {
        self.0.periodic_values()
    }
    // The complete recorded constraint list already contains activation checks.
    fn assert_zero<I: Into<Self::Expr>>(&mut self, _: I) {}
}

impl<B: BusInteractionRecorder> BusInteractionRecorder for Recorded<'_, B> {
    fn record_bus_interaction<T: Into<Self::Expr>>(
        &mut self,
        token: RecordToken,
        name: BusName<'_>,
        direction: BusDirection,
        fields: impl IntoIterator<Item = T>,
        activation: BusActivation<Self::Expr>,
    ) {
        self.0
            .record_bus_interaction(token, name, direction, fields, activation);
    }
}
