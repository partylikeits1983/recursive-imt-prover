//! Route each proof family to its upstream checked verifier implementation.
use crate::legacy::air::ImtAir;
use crate::legacy::config::{ChildBackend, Config, E, F, OuterBackend, ZkConfig};
use p3_circuit::ops::NpoTypeId;
use p3_circuit::{CircuitBuilder, CircuitRunner, NonPrimitiveOpId, VerifiedStatementTargets};
use p3_circuit_prover::batch_stark_prover::TableProver;
use p3_circuit_prover::common::{NpoAirBuilder, NpoPreprocessor};
use p3_circuit_prover::{BatchStarkProof, CircuitVerifier};
use p3_recursion::backend::WhirRecursionBackend;
use p3_recursion::prepared::{
    NativeCommitment, PreparedInput, PreparedPcsRecursionBackend, TrustedChildStatementLayout,
    TrustedPcsRecursionBackend,
};
use p3_recursion::{
    BatchOnly, FriRecursionBackend, PcsRecursionBackend, Poseidon2Config, RecursionInput,
    VerificationError,
};

/// Children are hiding FRI; recursive outputs are ordinary WHIR.
#[derive(Clone)]
pub struct Backend {
    fri: ChildBackend,
    whir: OuterBackend,
}

impl Backend {
    pub(crate) fn new() -> Self {
        Self {
            fri: FriRecursionBackend::new(Poseidon2Config::KOALA_BEAR_D4_W16)
                .for_extension_degree::<4>(),
            whir: WhirRecursionBackend::new(Poseidon2Config::KOALA_BEAR_D4_W16)
                .for_extension_degree::<4>(),
        }
    }
}

// Forward every check, including resource preflight, replacement-proof authority,
// statement binding and preprocessing pins. No verification logic is reimplemented.
macro_rules! route {
    ($config:ty, $air:ty, $inner:ty, $member:ident) => {
        impl PcsRecursionBackend<$config, $air, 4> for Backend {
            type VerifierResult = <$inner as PcsRecursionBackend<$config, $air, 4>>::VerifierResult;

            fn preflight_input(&self, config: &$config, input: &RecursionInput<'_, $config, $air>) -> Result<(), VerificationError> {
                <$inner as PcsRecursionBackend<$config, $air, 4>>::preflight_input(&self.$member, config, input)
            }

            fn validate_input(&self, config: &$config, input: &RecursionInput<'_, $config, $air>) -> Result<(), VerificationError> {
                <$inner as PcsRecursionBackend<$config, $air, 4>>::validate_input(&self.$member, config, input)
            }

            fn prepare_circuit(&self, config: &$config, circuit: &mut CircuitBuilder<E>) -> Result<(), VerificationError> {
                <$inner as PcsRecursionBackend<$config, $air, 4>>::prepare_circuit(&self.$member, config, circuit)
            }

            fn build_verifier_circuit(&self, input: &RecursionInput<'_, $config, $air>, config: &$config, circuit: &mut CircuitBuilder<E>) -> Result<Self::VerifierResult, VerificationError> {
                <$inner as PcsRecursionBackend<$config, $air, 4>>::build_verifier_circuit(&self.$member, input, config, circuit)
            }

            fn set_private_data(&self, config: &$config, runner: &mut CircuitRunner<'_, E>, op_ids: &[NonPrimitiveOpId], input: &RecursionInput<'_, $config, $air>) -> Result<(), &'static str> {
                <$inner as PcsRecursionBackend<$config, $air, 4>>::set_private_data(&self.$member, config, runner, op_ids, input)
            }

            fn set_private_data_for_result(&self, config: &$config, runner: &mut CircuitRunner<'_, E>, result: &Self::VerifierResult, input: &RecursionInput<'_, $config, $air>) -> Result<(), &'static str> {
                <$inner as PcsRecursionBackend<$config, $air, 4>>::set_private_data_for_result(&self.$member, config, runner, result, input)
            }

            fn non_primitive_preprocessors(&self) -> Vec<Box<dyn NpoPreprocessor<F>>> {
                <$inner as PcsRecursionBackend<$config, $air, 4>>::non_primitive_preprocessors(&self.$member)
            }

            fn non_primitive_provers(&self, degree: usize) -> Vec<Box<dyn TableProver<$config>>> {
                <$inner as PcsRecursionBackend<$config, $air, 4>>::non_primitive_provers(&self.$member, degree)
            }

            fn non_primitive_input_provers(&self, degree: usize, op_types: &[NpoTypeId]) -> Vec<Box<dyn TableProver<$config>>> {
                <$inner as PcsRecursionBackend<$config, $air, 4>>::non_primitive_input_provers(&self.$member, degree, op_types)
            }

            fn non_primitive_air_builders(&self) -> Vec<Box<dyn NpoAirBuilder<$config, 4>>> {
                <$inner as PcsRecursionBackend<$config, $air, 4>>::non_primitive_air_builders(&self.$member)
            }

            fn input_table_provers(&self, degree: usize, op_types: &[NpoTypeId]) -> Vec<Box<dyn TableProver<$config>>> {
                <$inner as PcsRecursionBackend<$config, $air, 4>>::input_table_provers(&self.$member, degree, op_types)
            }
        }

        impl PreparedPcsRecursionBackend<$config, $air, 4> for Backend {
            type InputContract = <$inner as PreparedPcsRecursionBackend<$config, $air, 4>>::InputContract;

            fn preflight_input(&self, config: &$config, input: &PreparedInput<'_, $config>) -> Result<(), VerificationError> {
                <$inner as PreparedPcsRecursionBackend<$config, $air, 4>>::preflight_input(&self.$member, config, input)
            }

            fn capture_input_contract(&self, config: &$config, input: &RecursionInput<'_, $config, $air>) -> Result<Self::InputContract, VerificationError> {
                <$inner as PreparedPcsRecursionBackend<$config, $air, 4>>::capture_input_contract(&self.$member, config, input)
            }

            fn validate_prepared_input(&self, config: &$config, contract: &Self::InputContract, input: &PreparedInput<'_, $config>) -> Result<(), VerificationError> {
                <$inner as PreparedPcsRecursionBackend<$config, $air, 4>>::validate_prepared_input(&self.$member, config, contract, input)
            }
        }

        impl TrustedPcsRecursionBackend<$config, $air, 4> for Backend {
            fn preflight_trusted_batch(&self, verifier: &CircuitVerifier<$config>, proof: &BatchStarkProof<$config>) -> Result<(), VerificationError> {
                <$inner as TrustedPcsRecursionBackend<$config, $air, 4>>::preflight_trusted_batch(&self.$member, verifier, proof)
            }

            fn capture_trusted_batch_input_contract(&self, verifier: &CircuitVerifier<$config>, proof: &BatchStarkProof<$config>, statement: &[F]) -> Result<Self::InputContract, VerificationError> {
                <$inner as TrustedPcsRecursionBackend<$config, $air, 4>>::capture_trusted_batch_input_contract(&self.$member, verifier, proof, statement)
            }

            fn validate_trusted_batch_input(&self, verifier: &CircuitVerifier<$config>, contract: &Self::InputContract, proof: &BatchStarkProof<$config>, statement: &[F]) -> Result<(), VerificationError> {
                <$inner as TrustedPcsRecursionBackend<$config, $air, 4>>::validate_trusted_batch_input(&self.$member, verifier, contract, proof, statement)
            }

            fn build_trusted_batch_verifier_circuit(&self, verifier: &CircuitVerifier<$config>, proof: &BatchStarkProof<$config>, statement: &[F], circuit: &mut CircuitBuilder<E>) -> Result<Self::VerifierResult, VerificationError> {
                <$inner as TrustedPcsRecursionBackend<$config, $air, 4>>::build_trusted_batch_verifier_circuit(&self.$member, verifier, proof, statement, circuit)
            }

            fn set_private_data_for_trusted_batch(&self, verifier: &CircuitVerifier<$config>, proof: &BatchStarkProof<$config>, statement: &[F], runner: &mut CircuitRunner<'_, E>, op_ids: &[NonPrimitiveOpId]) -> Result<(), VerificationError> {
                <$inner as TrustedPcsRecursionBackend<$config, $air, 4>>::set_private_data_for_trusted_batch(&self.$member, verifier, proof, statement, runner, op_ids)
            }

            fn verified_statement_targets(&self, result: &Self::VerifierResult, source: &TrustedChildStatementLayout, builder: &CircuitBuilder<E>) -> Result<VerifiedStatementTargets<E>, VerificationError> {
                <$inner as TrustedPcsRecursionBackend<$config, $air, 4>>::verified_statement_targets(&self.$member, result, source, builder)
            }

            fn constrain_trusted_preprocessing(&self, circuit: &mut CircuitBuilder<E>, result: &Self::VerifierResult, expected: Option<&NativeCommitment<$config>>) -> Result<(), VerificationError> {
                <$inner as TrustedPcsRecursionBackend<$config, $air, 4>>::constrain_trusted_preprocessing(&self.$member, circuit, result, expected)
            }
        }
    };
}

route!(ZkConfig, ImtAir, ChildBackend, fri);
route!(Config, BatchOnly, OuterBackend, whir);
