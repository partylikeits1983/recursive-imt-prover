//! Replay bus declarations whose activation checks are already in the recorded AIR.
use p3_air::AirBuilder;
use p3_bus::{BusActivation, BusDirection, BusInteractionRecorder, BusName, RecordToken};

/// Used only after replaying the complete, ordered symbolic constraint list.
/// That list includes every activation Booleanity check emitted during export.
pub(super) struct RecordedBus<'a, B>(pub &'a mut B);

impl<B: AirBuilder> AirBuilder for RecordedBus<'_, B> {
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
    fn assert_zero<I: Into<Self::Expr>>(&mut self, _: I) {
        // push_bus_interaction would duplicate the activation check here.
        // Its original check has already been replayed, in its original position.
    }
}

impl<B: BusInteractionRecorder> BusInteractionRecorder for RecordedBus<'_, B> {
    fn record_bus_interaction<E: Into<Self::Expr>>(
        &mut self,
        token: RecordToken,
        bus: BusName<'_>,
        direction: BusDirection,
        fields: impl IntoIterator<Item = E>,
        activation: BusActivation<Self::Expr>,
    ) {
        self.0
            .record_bus_interaction(token, bus, direction, fields, activation);
    }
}
