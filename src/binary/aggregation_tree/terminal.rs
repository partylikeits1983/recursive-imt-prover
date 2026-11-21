//! Final aggregation of two authenticated 32-leaf cyclic proofs.
use std::time::Instant;

use anyhow::{Result, ensure};
use imt_flock_backend::terminal_opening::OpeningSchedule;
use imt_flock_backend::{Geometry, Prepared, RecursiveAggregate, RecursiveAuthority, Verifier};
use p3_circuit::Circuit;

use super::{TreeProof, TreeStatement, TreeTarget, cyclic};
use crate::{
    benchmark::ms,
    binary::{
        MAX_CHILDREN,
        relation::{AggregatePublic, F},
        veil::aggregate::{AggregationMetrics, import_children},
    },
};

pub const PROTOCOL: &str = "experimental-binary-checkpoint-terminal64-v1";

pub const SHARED_PROTOCOL: &str = "experimental-binary-checkpoint-terminal64-shared-v1";

pub const FOLD4_PROTOCOL: &str =
    "experimental-binary-checkpoint-terminal64-shared-fold4-experiment";

pub const MIDPOINT_PROTOCOL: &str =
    "experimental-binary-checkpoint-terminal64-shared-fold4-midpoint-v1";

pub const MIDPOINT_COMPARISON_PROTOCOL: &str =
    "experimental-binary-checkpoint-terminal64-shared-fold4-midpoint-comparison-v1";

/// Terminal verification policy, fixed at setup and authenticated with the verifier key.
#[derive(Clone, Copy, Default, clap::ValueEnum)]
pub enum MidpointProfile {
    #[default]
    Strong,
    Comparison,
}

impl MidpointProfile {
    fn protocol(self) -> &'static str {
        match self {
            Self::Strong => MIDPOINT_PROTOCOL,
            Self::Comparison => MIDPOINT_COMPARISON_PROTOCOL,
        }
    }
}

fn shared_schedule(protocol: &str) -> Option<OpeningSchedule> {
    match protocol {
        SHARED_PROTOCOL => Some(OpeningSchedule::ThreeVariableFolds),
        MIDPOINT_COMPARISON_PROTOCOL => Some(OpeningSchedule::FourVariableMidpointComparison),
        MIDPOINT_PROTOCOL => Some(OpeningSchedule::FourVariableMidpoint),
        FOLD4_PROTOCOL => Some(OpeningSchedule::FourVariableFolds),
        _ => None,
    }
}

pub struct PreparedTerminalMerge {
    protocol: &'static str,
    outer: Prepared,
    source: RecursiveAggregate,
    child_authority: RecursiveAuthority,
}

pub struct TerminalVerifier {
    inner: Verifier,
    schedule: Option<OpeningSchedule>,
}

fn public_inputs(parent: &TreeStatement) -> Result<Vec<F>> {
    ensure!(
        usize::from(parent.count) == MAX_CHILDREN,
        "terminal root requires 64 leaves"
    );
    Ok((0..2)
        .flat_map(|side| {
            parent
                .digest
                .map(|byte| F::new(u64::from(byte)))
                .into_iter()
                .chain([F::new(side)])
        })
        .collect())
}

impl TerminalVerifier {
    #[cfg(feature = "opening-bench")]
    pub fn wiring_root(&self) -> Result<[u8; 32]> {
        self.inner.single_wiring_root()
    }

    pub fn from_bytes(key: &[u8], digest: &[u8; 32], identity: &str) -> Result<Self> {
        Self::load(key, digest, identity, PROTOCOL)
    }

    pub(super) fn load(
        key: &[u8],
        digest: &[u8; 32],
        identity: &str,
        protocol: &str,
    ) -> Result<Self> {
        ensure!(
            matches!(
                protocol,
                PROTOCOL
                    | SHARED_PROTOCOL
                    | FOLD4_PROTOCOL
                    | MIDPOINT_PROTOCOL
                    | MIDPOINT_COMPARISON_PROTOCOL
            ),
            "unknown terminal protocol"
        );
        Ok(Self {
            inner: Verifier::from_bytes(key, digest, identity, protocol.as_bytes())?,
            schedule: shared_schedule(protocol),
        })
    }

    pub fn verify_statement(&self, proof: &[u8], expected: &TreeStatement) -> Result<()> {
        self.verify_statement_with_bound(proof, expected)
            .map(|_| ())
    }

    /// Shared-opening terminals report their conditional bound for this key and statement.
    pub fn verify_statement_with_bound(
        &self,
        proof: &[u8],
        expected: &TreeStatement,
    ) -> Result<Option<f64>> {
        let public = public_inputs(expected)?;
        if let Some(schedule) = self.schedule {
            self.inner
                .verify_shared_terminal_bound(proof, &public, schedule)
                .map(Some)
        } else {
            self.inner.verify(proof, &public)?;
            Ok(None)
        }
    }
}

impl PreparedTerminalMerge {
    /// The child key digest and identity must come from the trusted cyclic setup.
    pub fn new(key: &[u8], child_digest: &[u8; 32], child_identity: &str) -> Result<Self> {
        Self::prepare(key, child_digest, child_identity, false, PROTOCOL)
    }

    /// Commit witness rows with the same width used by the joint terminal opening.
    pub fn with_wide_witness(
        key: &[u8],
        child_digest: &[u8; 32],
        child_identity: &str,
    ) -> Result<Self> {
        Self::prepare(key, child_digest, child_identity, true, PROTOCOL)
    }

    pub fn with_shared_opening(
        key: &[u8],
        child_digest: &[u8; 32],
        child_identity: &str,
    ) -> Result<Self> {
        Self::prepare(key, child_digest, child_identity, true, SHARED_PROTOCOL)
    }

    pub fn protocol(&self) -> &'static str {
        self.protocol
    }

    pub fn with_four_variable_folds(
        key: &[u8],
        child_digest: &[u8; 32],
        child_identity: &str,
    ) -> Result<Self> {
        Self::prepare(key, child_digest, child_identity, true, FOLD4_PROTOCOL)
    }

    pub fn with_midpoint(
        key: &[u8],
        child_digest: &[u8; 32],
        child_identity: &str,
    ) -> Result<Self> {
        Self::with_midpoint_profile(key, child_digest, child_identity, MidpointProfile::Strong)
    }

    pub fn with_midpoint_profile(
        key: &[u8],
        child_digest: &[u8; 32],
        child_identity: &str,
        profile: MidpointProfile,
    ) -> Result<Self> {
        Self::prepare(key, child_digest, child_identity, true, profile.protocol())
    }

    fn prepare(
        key: &[u8],
        child_digest: &[u8; 32],
        child_identity: &str,
        wide_witness: bool,
        protocol: &'static str,
    ) -> Result<Self> {
        let child = Verifier::from_bytes(
            key,
            child_digest,
            child_identity,
            cyclic::PROTOCOL.as_bytes(),
        )?;
        let child_authority = child.recursive_authority()?;
        let source = RecursiveAggregate::new(child)?;
        let circuit = circuit(&source, &child_authority)?;
        let outer = if wide_witness {
            Prepared::terminal_pair_wide_witness(circuit, protocol.as_bytes())?
        } else {
            Prepared::terminal_pair(circuit, protocol.as_bytes())?
        };
        Ok(Self {
            protocol,
            outer,
            source,
            child_authority,
        })
    }

    pub fn identity(&self) -> String {
        self.outer.identity()
    }

    pub fn export_verifier_key(&self) -> Result<Vec<u8>> {
        self.outer.export_verifier(self.protocol.as_bytes())
    }

    #[cfg(feature = "opening-bench")]
    pub fn wiring_root(&self) -> Result<[u8; 32]> {
        self.outer.terminal_wiring_root()
    }

    pub fn geometry(&self) -> &Geometry {
        &self.outer.geometry
    }

    fn witness_inputs(&self, children: &[TreeProof; 2]) -> Result<(Vec<F>, Vec<F>, Vec<f64>)> {
        let statements = [
            TreeStatement::from_public(&children[0].public)?,
            TreeStatement::from_public(&children[1].public)?,
        ];
        let parent = TreeStatement::merge(&statements[0], &statements[1])?;
        let fields = public_inputs(&parent)?;
        let (private, imports) = import_children(children, |side, child, private| {
            for statement in &statements {
                private.extend(statement.digest.map(|byte| F::new(u64::from(byte))));
            }
            private.extend(self.source.private_inputs(
                &child.proof,
                &cyclic::fields(&statements[side], &self.child_authority),
            )?);
            Ok(())
        })?;
        Ok((fields, private, imports))
    }

    /// Export the native Keccak inputs, round-12 states and outputs in circuit row order.
    #[cfg(feature = "opening-bench")]
    pub fn write_keccak_checkpoints(
        &self,
        children: &[TreeProof; 2],
        out: impl std::io::Write,
    ) -> Result<()> {
        let (public, private, _) = self.witness_inputs(children)?;
        self.outer.write_keccak_checkpoints(&public, &private, out)
    }

    pub fn prove(&self, children: &[TreeProof; 2]) -> Result<(TreeProof, AggregationMetrics)> {
        let start = Instant::now();
        let (fields, private, imports) = self.witness_inputs(children)?;
        let (proof, aggregate) = if let Some(schedule) = shared_schedule(self.protocol) {
            self.outer
                .prove_shared_terminal_with_schedule(&fields, &private, schedule)?
        } else {
            self.outer.prove(&fields, &private)?
        };
        let public = AggregatePublic {
            children: children
                .iter()
                .flat_map(|child| child.public.children.iter().cloned())
                .collect(),
        };
        Ok((
            TreeProof { proof, public },
            AggregationMetrics {
                witness_import_ms: imports,
                aggregate,
                aggregation_wall_ms: ms(start),
            },
        ))
    }
}

fn circuit(source: &RecursiveAggregate, authority: &RecursiveAuthority) -> Result<Circuit<F>> {
    let mut b = cyclic::merge_builder()?;
    let parent = b.alloc_public_input_array::<32>("ordered root digest");
    let side = b.alloc_public_input("side");
    b.assert_bool(side);
    let left = b.alloc_private_input_array::<32>("left child digest");
    let right = b.alloc_private_input_array::<32>("right child digest");
    let child: [_; 32] = std::array::from_fn(|i| b.select(side, right[i], left[i]));
    let count = b.define_const(F::new((MAX_CHILDREN / 2) as u64));
    let authority = authority.fields().map(|v| b.define_const(v));
    let public: Vec<_> = (0..2)
        .flat_map(|role| {
            child
                .into_iter()
                .chain([count, b.define_const(F::new(role))])
                .chain(authority)
        })
        .collect();
    source.verify_with_authority(&mut b, &public, &authority)?;
    let actual = TreeTarget::merge_digest(
        &mut b,
        TreeTarget {
            digest: left,
            count,
        },
        TreeTarget {
            digest: right,
            count,
        },
    )?;
    for (actual, expected) in actual.into_iter().zip(parent) {
        b.connect(actual, expected);
    }
    Ok(b.build()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminal_instances_bind_the_same_digest_and_opposite_roles() {
        let mut parent = TreeStatement {
            digest: std::array::from_fn(|i| i as u8),
            count: 64,
        };
        let fields = public_inputs(&parent).unwrap();
        let (left, right) = fields.split_at(33);
        let digest = parent.digest.map(|byte| F::new(u64::from(byte)));
        assert_eq!(&left[..32], &digest);
        assert_eq!(&right[..32], &digest);
        assert_eq!((left[32], right[32]), (F::new(0), F::new(1)));
        for count in [0, 1, 2, 31, 32, 63, 65, 128] {
            parent.count = count;
            assert!(public_inputs(&parent).is_err());
        }
    }
}
