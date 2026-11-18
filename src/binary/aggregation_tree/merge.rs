use std::time::Instant;

use anyhow::{Result, ensure};
use imt_flock_backend::{Geometry, Prepared, RecursiveAggregate, Verifier};
use p3_circuit::{Circuit, CircuitBuilder, CircuitConstructionLimits};

use super::{STATEMENT_BYTES, TreeStatement, TreeTarget};
use crate::{
    benchmark::ms,
    binary::{
        relation::{AggregatePublic, F},
        veil::aggregate::AggregationMetrics,
    },
};

pub const PROTOCOL: &str = "experimental-binary-checkpoint-tree-merge-v1";

pub struct TreeProof {
    pub proof: Vec<u8>,
    pub public: AggregatePublic,
}

pub struct TreeVerifier {
    pub(crate) outer: Verifier,
}

pub struct PreparedMerge {
    source: RecursiveAggregate,
    outer: Prepared,
}

impl TreeVerifier {
    pub fn from_bytes(key: &[u8], digest: &[u8; 32], identity: &str) -> Result<Self> {
        Ok(Self {
            outer: Verifier::from_bytes(key, digest, identity, PROTOCOL.as_bytes())?,
        })
    }

    pub fn verify(&self, proof: &[u8], public: &AggregatePublic) -> Result<()> {
        self.outer.verify(
            proof,
            &TreeStatement::from_public(public)?.verifier_fields(),
        )
    }
}

impl PreparedMerge {
    /// Source authority is fixed in this circuit; cyclic authority is not implemented yet.
    pub fn new(authority: TreeVerifier) -> Result<Self> {
        let source = RecursiveAggregate::new(authority.outer)?;
        let circuit = merge_circuit(&source)?;
        let outer = Prepared::recursive_pair(circuit, PROTOCOL.as_bytes())?;
        source.require_same_layout(&outer)?;
        Ok(Self { source, outer })
    }

    pub fn geometry(&self) -> &Geometry {
        &self.outer.geometry
    }

    pub fn identity(&self) -> String {
        self.outer.identity()
    }

    pub fn export_verifier_key(&self) -> Result<Vec<u8>> {
        self.outer.export_verifier(PROTOCOL.as_bytes())
    }

    pub fn prove(
        &self,
        children: &[TreeProof; 2],
    ) -> Result<(AggregatePublic, Vec<u8>, AggregationMetrics)> {
        let start = Instant::now();
        let statements = [
            TreeStatement::from_public(&children[0].public)?,
            TreeStatement::from_public(&children[1].public)?,
        ];
        let parent = TreeStatement::merge(&statements[0], &statements[1])?;
        let mut private = Vec::new();
        let mut imports = Vec::new();
        for (i, child) in children.iter().enumerate() {
            let t = Instant::now();
            private.extend(statements[i].fields());
            private.extend(statements[1 - i].digest.map(|byte| F::new(u64::from(byte))));
            private.extend(
                self.source
                    .private_inputs(&child.proof, &statements[i].verifier_fields())?,
            );
            imports.push(ms(t));
        }
        let public = AggregatePublic {
            children: children
                .iter()
                .flat_map(|c| c.public.children.clone())
                .collect(),
        };
        ensure!(
            TreeStatement::from_public(&public)? == parent,
            "incorrect merge statement"
        );
        let (proof, aggregate) = self.outer.prove(&parent.verifier_fields(), &private)?;
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
}

fn merge_circuit(source: &RecursiveAggregate) -> Result<Circuit<F>> {
    let mut b = CircuitBuilder::with_construction_limits(CircuitConstructionLimits {
        max_expression_nodes: 1 << 27,
        max_pending_connects: 1 << 26,
        max_non_primitive_calls: 1 << 21,
        max_non_primitive_slots: 1 << 29,
    })?;
    b.enable_native_keccak_f1600()?;
    let expected = b.alloc_public_input_array::<STATEMENT_BYTES>("parent statement");
    let side = b.alloc_public_input("side");
    b.assert_bool(side);
    let child = b.alloc_private_input_array::<STATEMENT_BYTES>("child statement");
    let sibling = b.alloc_private_input_array::<32>("sibling digest");
    let public: Vec<_> = (0..2)
        .flat_map(|role| {
            let role = b.define_const(F::new(role));
            child.into_iter().chain([role])
        })
        .collect();
    source.verify_in(&mut b, &public)?;
    let count = child[32];
    let left = TreeTarget {
        digest: std::array::from_fn(|i| b.select(side, sibling[i], child[i])),
        count,
    };
    let right = TreeTarget {
        digest: std::array::from_fn(|i| b.select(side, child[i], sibling[i])),
        count,
    };
    TreeTarget::merge(&mut b, left, right)?.connect(&mut b, expected);
    Ok(b.build()?)
}
