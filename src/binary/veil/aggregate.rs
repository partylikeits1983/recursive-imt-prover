//! One non-hiding proof of a fixed ordered batch of complete masked verifiers.
use std::time::Instant;

use anyhow::{Result, ensure};
use imt_flock_backend::{Geometry, HashBackend, Metrics, Prepared, Verifier};
use p3_circuit::{Circuit, CircuitBuilder, CircuitConstructionLimits};
use serde::{Deserialize, Serialize};

use super::{
    child::{MaskedMembershipProof, recursive::PreparedMaskedVerifier},
    parameters::Parameters,
};
use crate::{
    benchmark::ms,
    binary::{
        aggregation_tree::{STATEMENT_BYTES, TreeStatement, TreeTarget},
        engine::Settings,
        relation::{AggregatePublic, ClientPublic, F, PUBLIC_BYTES},
    },
};

pub const PROTOCOL: &str = "experimental-binary-masked-flock-aggregate-v7";
pub const CHECKPOINT_PROTOCOL: &str = "experimental-binary-masked-checkpoint-aggregate-v9";

#[derive(Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StatementFormat {
    #[default]
    Ordered,
    TreePair,
}

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
    format: StatementFormat,
}

pub struct MaskedAggregateVerifier {
    outer: Verifier,
    count: usize,
    format: StatementFormat,
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
        Self::with_format(settings, parameters, backend, StatementFormat::Ordered)
    }

    pub fn with_format(
        settings: &Settings,
        parameters: Parameters,
        backend: HashBackend,
        format: StatementFormat,
    ) -> Result<Self> {
        validate_configuration(settings, &parameters)?;
        let binding = configuration_binding(settings, &parameters, backend, format)?;
        let verifier = PreparedMaskedVerifier::new(settings.depth, parameters)?;
        let circuit = match format {
            StatementFormat::Ordered => verifier.circuit()?,
            StatementFormat::TreePair => tree_pair_circuit(&verifier)?,
        };
        eprintln!(
            "Child verifier template: {} witnesses, {} instances",
            circuit.witness_count, settings.batch_size
        );
        let domain = format!(
            "{}/{}/{}",
            format.protocol(backend),
            settings.depth,
            settings.batch_size
        );
        let outer = Prepared::repeated(circuit, settings.batch_size, domain.as_bytes(), backend)?;
        Ok(Self {
            verifier,
            outer,
            count: settings.batch_size,
            binding,
            format,
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
        let mut private = Vec::new();
        let mut imports = Vec::new();
        for (index, child) in children.iter().enumerate() {
            let t = Instant::now();
            if self.format == StatementFormat::TreePair {
                private.extend(child.public.fields());
                private.extend(
                    TreeStatement::leaf(&children[1 - index].public)
                        .digest
                        .map(|byte| F::new(u64::from(byte))),
                );
            }
            private.extend(self.verifier.import(&child.public, &child.proof)?);
            imports.push(ms(t));
        }
        let public = AggregatePublic {
            children: children.iter().map(|c| c.public.clone()).collect(),
        };
        let (proof, aggregate) = self.outer.prove(&self.format.fields(&public)?, &private)?;
        Ok((
            public,
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
        self.outer.verify(proof, &self.format.fields(public)?)
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
        Self::with_format(
            settings,
            parameters,
            bytes,
            digest,
            identity,
            backend,
            StatementFormat::Ordered,
        )
    }

    pub fn with_format(
        settings: &Settings,
        parameters: &Parameters,
        bytes: &[u8],
        digest: &[u8; 32],
        identity: &str,
        backend: HashBackend,
        format: StatementFormat,
    ) -> Result<Self> {
        validate_configuration(settings, parameters)?;
        Ok(Self {
            outer: Verifier::from_bytes(
                bytes,
                digest,
                identity,
                &configuration_binding(settings, parameters, backend, format)?,
            )?,
            count: settings.batch_size,
            format,
        })
    }

    pub fn verify(&self, proof: &[u8], public: &AggregatePublic) -> Result<()> {
        ensure!(public.children.len() == self.count, "incorrect child count");
        self.outer.verify(proof, &self.format.fields(public)?)
    }
}

pub const fn protocol(backend: HashBackend) -> &'static str {
    StatementFormat::Ordered.protocol(backend)
}

impl StatementFormat {
    pub const fn protocol(self, backend: HashBackend) -> &'static str {
        match (self, backend) {
            (Self::Ordered, HashBackend::Flock) => PROTOCOL,
            (Self::Ordered, HashBackend::Checkpoint) => CHECKPOINT_PROTOCOL,
            (Self::TreePair, HashBackend::Flock) => "experimental-binary-masked-flock-tree-pair-v2",
            (Self::TreePair, HashBackend::Checkpoint) => {
                "experimental-binary-masked-checkpoint-tree-pair-v3"
            }
        }
    }

    fn fields(self, public: &AggregatePublic) -> Result<Vec<F>> {
        match self {
            Self::Ordered => Ok(public
                .children
                .iter()
                .flat_map(ClientPublic::fields)
                .collect()),
            Self::TreePair => {
                ensure!(
                    public.children.len() == 2,
                    "first aggregation requires two children"
                );
                let statement = TreeStatement::from_public(public)?.fields();
                Ok((0..2)
                    .flat_map(|side| statement.into_iter().chain([F::new(side)]))
                    .collect())
            }
        }
    }
}

fn tree_pair_circuit(verifier: &PreparedMaskedVerifier) -> Result<Circuit<F>> {
    let mut b = CircuitBuilder::with_construction_limits(CircuitConstructionLimits {
        max_expression_nodes: 1 << 27,
        max_pending_connects: 1 << 26,
        max_non_primitive_calls: 1 << 21,
        max_non_primitive_slots: 1 << 29,
    })?;
    b.enable_native_keccak_f1600()?;
    let expected = b.alloc_public_input_array::<STATEMENT_BYTES>("tree-statement");
    let side = b.alloc_public_input("side");
    b.assert_bool(side);
    let public = b.alloc_private_input_array::<PUBLIC_BYTES>("root-and-nullifier-hash");
    let sibling = b.alloc_private_input_array::<32>("sibling-statement-digest");
    verifier.verify_in(&mut b, public)?;
    let leaf = TreeTarget::leaf(&mut b, public)?;
    let left = TreeTarget {
        digest: std::array::from_fn(|i| b.select(side, sibling[i], leaf.digest[i])),
        count: leaf.count,
    };
    let right = TreeTarget {
        digest: std::array::from_fn(|i| b.select(side, leaf.digest[i], sibling[i])),
        count: leaf.count,
    };
    // Both instances bind the same ordered pair digest; the verifier supplies
    // their distinct sides. A conflicting sibling requires a Keccak collision.
    TreeTarget::merge(&mut b, left, right)?.connect(&mut b, expected);
    Ok(b.build()?)
}

fn configuration_binding(
    settings: &Settings,
    parameters: &Parameters,
    backend: HashBackend,
    format: StatementFormat,
) -> Result<Vec<u8>> {
    ensure!(
        format != StatementFormat::TreePair || settings.batch_size == 2,
        "first aggregation requires two children"
    );
    Ok(postcard::to_allocvec(&(
        format.protocol(backend),
        settings,
        parameters,
    ))?)
}

fn validate_configuration(settings: &Settings, parameters: &Parameters) -> Result<()> {
    settings.validate()?;
    ensure!(
        settings.pcs_bits == 152
            && settings.pow_bits == 16
            && settings.log_inv_rate == imt_flock_backend::WHIR_LOG_INV_RATE
            && settings.fold == imt_flock_backend::WHIR_FOLD,
        "binary outer parameters are fixed: PCS 152, PoW 16, inverse-rate log {}, fold {}",
        imt_flock_backend::WHIR_LOG_INV_RATE,
        imt_flock_backend::WHIR_FOLD
    );
    ensure!(
        parameters.min_algebraic_bits >= 144,
        "child algebraic budget below 144 bits"
    );
    parameters.validate()?;
    Ok(())
}
