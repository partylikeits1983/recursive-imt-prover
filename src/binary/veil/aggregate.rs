//! One non-hiding proof of a fixed ordered batch of complete masked verifiers.
use std::time::Instant;

use anyhow::{Result, ensure};
use imt_flock_backend::{Geometry, HashBackend, Metrics, Prepared, Verifier};
use p3_circuit::{CircuitBuilder, CircuitConstructionLimits};
use serde::{Deserialize, Serialize};

use super::{
    F,
    child::{MaskedMembershipProof, recursive::PreparedMaskedVerifier},
    parameters::Parameters,
};
use crate::{
    benchmark::ms,
    binary::{
        engine::Settings,
        relation::{AggregatePublic, ClientPublic},
    },
};

pub const PROTOCOL: &str = "experimental-binary-masked-flock-aggregate-v6";
pub const CHECKPOINT_PROTOCOL: &str = "experimental-binary-masked-checkpoint-aggregate-v7";

#[derive(Clone, Serialize, Deserialize)]
pub struct MaskedChildInput {
    pub proof: MaskedMembershipProof,
    pub public: ClientPublic,
}

pub struct PreparedMaskedAggregate {
    verifier: PreparedMaskedVerifier,
    outer: Prepared,
    count: usize,
    binding: Vec<u8>,
}

pub struct MaskedAggregateVerifier {
    outer: Verifier,
    count: usize,
}

#[derive(Serialize)]
pub struct AggregationMetrics {
    pub witness_import_ms: Vec<f64>,
    pub aggregate: Metrics,
    pub aggregation_wall_ms: f64,
}

impl PreparedMaskedAggregate {
    pub fn new(settings: &Settings, parameters: Parameters) -> Result<Self> {
        Self::with_backend(settings, parameters, HashBackend::Flock)
    }

    pub fn with_backend(
        settings: &Settings,
        parameters: Parameters,
        backend: HashBackend,
    ) -> Result<Self> {
        validate_configuration(settings, &parameters)?;
        let binding = configuration_binding(settings, &parameters, backend)?;
        let verifier = PreparedMaskedVerifier::new(settings.depth, parameters)?;
        let mut b = CircuitBuilder::<F>::with_construction_limits(CircuitConstructionLimits {
            max_expression_nodes: 1 << 27,
            max_pending_connects: 1 << 26,
            max_non_primitive_calls: 1 << 21,
            max_non_primitive_slots: 1 << 29,
        })?;
        b.enable_native_keccak_f1600()?;
        for _ in 0..settings.batch_size {
            let public = core::array::from_fn(|_| b.public_input());
            verifier.verify_in(&mut b, public)?;
            b.check_construction_limits()?;
        }
        let circuit = b.build()?;
        eprintln!(
            "Complete batch verifier: {} witnesses",
            circuit.witness_count
        );
        let domain = format!(
            "{}/{}/{}",
            protocol(backend),
            settings.depth,
            settings.batch_size
        );
        let outer = match backend {
            HashBackend::Flock => Prepared::new(circuit, domain.as_bytes())?,
            HashBackend::Checkpoint => Prepared::new_checkpoint(circuit, domain.as_bytes())?,
        };
        Ok(Self {
            verifier,
            outer,
            count: settings.batch_size,
            binding,
        })
    }
    pub fn export_verifier_key(&self) -> Result<Vec<u8>> {
        self.outer.export_verifier(&self.binding)
    }
    pub fn identity(&self) -> String {
        self.outer.identity()
    }
    pub fn geometry(&self) -> &Geometry {
        &self.outer.geometry
    }
    pub fn prove(
        &self,
        children: &[MaskedChildInput],
    ) -> Result<(AggregatePublic, Vec<u8>, AggregationMetrics)> {
        ensure!(children.len() == self.count, "incorrect child count");
        let start = Instant::now();
        let mut public = Vec::new();
        let mut private = Vec::new();
        let mut imports = Vec::new();
        for child in children {
            let t = Instant::now();
            private.extend(self.verifier.import(&child.public, &child.proof)?);
            public.extend(child.public.fields());
            imports.push(ms(t));
        }
        let (proof, aggregate) = self.outer.prove(&public, &private)?;
        Ok((
            AggregatePublic {
                children: children.iter().map(|c| c.public.clone()).collect(),
            },
            proof,
            AggregationMetrics {
                witness_import_ms: imports,
                aggregate,
                aggregation_wall_ms: ms(start),
            },
        ))
    }
    pub fn verify(&self, proof: &[u8], public: &AggregatePublic) -> Result<()> {
        ensure!(public.children.len() == self.count, "incorrect child count");
        self.outer.verify(
            proof,
            &public
                .children
                .iter()
                .flat_map(|p| p.fields())
                .collect::<Vec<_>>(),
        )
    }
}

impl MaskedAggregateVerifier {
    pub fn from_bytes(
        settings: &Settings,
        parameters: &Parameters,
        bytes: &[u8],
        digest: &[u8; 32],
        identity: &str,
    ) -> Result<Self> {
        Self::with_backend(
            settings,
            parameters,
            bytes,
            digest,
            identity,
            HashBackend::Flock,
        )
    }

    pub fn with_backend(
        settings: &Settings,
        parameters: &Parameters,
        bytes: &[u8],
        digest: &[u8; 32],
        identity: &str,
        backend: HashBackend,
    ) -> Result<Self> {
        validate_configuration(settings, parameters)?;
        Ok(Self {
            outer: Verifier::from_bytes(
                bytes,
                digest,
                identity,
                &configuration_binding(settings, parameters, backend)?,
            )?,
            count: settings.batch_size,
        })
    }

    pub fn verify(&self, proof: &[u8], public: &AggregatePublic) -> Result<()> {
        ensure!(public.children.len() == self.count, "incorrect child count");
        self.outer.verify(
            proof,
            &public
                .children
                .iter()
                .flat_map(|p| p.fields())
                .collect::<Vec<_>>(),
        )
    }
}

pub const fn protocol(backend: HashBackend) -> &'static str {
    match backend {
        HashBackend::Flock => PROTOCOL,
        HashBackend::Checkpoint => CHECKPOINT_PROTOCOL,
    }
}

fn configuration_binding(
    settings: &Settings,
    parameters: &Parameters,
    backend: HashBackend,
) -> Result<Vec<u8>> {
    Ok(postcard::to_allocvec(&(
        protocol(backend),
        settings,
        parameters,
    ))?)
}

fn validate_configuration(settings: &Settings, parameters: &Parameters) -> Result<()> {
    settings.validate()?;
    ensure!(
        settings.pcs_bits == 152
            && settings.pow_bits == 16
            && settings.log_inv_rate == 1
            && settings.fold == 4,
        "binary outer parameters are fixed: PCS 152, PoW 16, rate 1/2, fold 4"
    );
    ensure!(matches!(settings.depth, 16 | 32), "depth must be 16 or 32");
    ensure!(
        parameters.min_algebraic_bits >= 144,
        "child algebraic budget below 144 bits"
    );
    parameters.validate()?;
    Ok(())
}
