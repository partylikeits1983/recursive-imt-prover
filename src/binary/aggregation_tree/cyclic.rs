use std::time::Instant;

use anyhow::{Result, ensure};
use imt_flock_backend::{
    AUTHORITY_BYTES, Geometry, Prepared, RecursiveAggregate, RecursiveAuthority, Verifier,
    verifier_key_digest,
};
use p3_circuit::{Circuit, CircuitBuilder, CircuitConstructionLimits, ExprId};

use super::{STATEMENT_BYTES, TreeProof, TreeStatement, TreeTarget};
use crate::{
    benchmark::ms,
    binary::{
        MAX_CHILDREN,
        relation::{AggregatePublic, F},
        veil::aggregate::{AggregationMetrics, import_children},
    },
};

pub const PROTOCOL: &str = "experimental-binary-checkpoint-cyclic-merge-v2";

pub struct PreparedCyclicMerge {
    first: RecursiveAggregate,
    recursive: RecursiveAggregate,
    outer: Prepared,
    authority: RecursiveAuthority,
}

pub struct CyclicVerifier {
    outer: Verifier,
    authority: RecursiveAuthority,
}

impl CyclicVerifier {
    pub fn from_bytes(key: &[u8], digest: &[u8; 32], identity: &str) -> Result<Self> {
        let outer = Verifier::from_bytes(key, digest, identity, PROTOCOL.as_bytes())?;
        let authority = outer.recursive_authority()?;
        Ok(Self { outer, authority })
    }

    pub fn verify(&self, proof: &[u8], public: &AggregatePublic) -> Result<()> {
        ensure!(
            public.children.len() >= 4,
            "merge proof requires at least four leaves"
        );
        self.outer.verify(
            proof,
            &fields(&TreeStatement::from_public(public)?, &self.authority),
        )
    }
}

impl PreparedCyclicMerge {
    pub fn new(first: Verifier) -> Result<Self> {
        let first_authority = first.recursive_authority()?;
        let first = RecursiveAggregate::new(first)?;
        let circuit = circuit(&first, &first_authority)?;
        let outer = Prepared::recursive_pair(circuit, PROTOCOL.as_bytes())?;
        first.require_same_layout(&outer)?;
        let key = outer.export_verifier(PROTOCOL.as_bytes())?;
        let verifier = Verifier::from_bytes(
            &key,
            &verifier_key_digest(&key),
            &outer.identity(),
            PROTOCOL.as_bytes(),
        )?;
        let authority = verifier.recursive_authority()?;
        let recursive = RecursiveAggregate::new(verifier)?;
        Ok(Self {
            first,
            recursive,
            outer,
            authority,
        })
    }

    pub fn authority(&self) -> &RecursiveAuthority {
        &self.authority
    }

    pub fn identity(&self) -> String {
        self.outer.identity()
    }

    #[cfg(feature = "opening-bench")]
    pub fn compare_openings(
        &mut self,
        children: &[TreeProof; 2],
        repetitions: u32,
    ) -> Result<Vec<imt_flock_backend::opening_bench::Sample>> {
        self.outer.record_openings()?;
        let (parent, _) = self.prove(children)?;
        self.outer.verify(
            &parent.proof,
            &fields(
                &TreeStatement::from_public(&parent.public)?,
                &self.authority,
            ),
        )?;
        self.outer.compare_recorded_openings(repetitions)
    }

    pub fn geometry(&self) -> &Geometry {
        &self.outer.geometry
    }

    pub fn export_verifier_key(&self) -> Result<Vec<u8>> {
        self.outer.export_verifier(PROTOCOL.as_bytes())
    }

    pub fn prove(&self, children: &[TreeProof; 2]) -> Result<(TreeProof, AggregationMetrics)> {
        let start = Instant::now();
        let statements = [
            TreeStatement::from_public(&children[0].public)?,
            TreeStatement::from_public(&children[1].public)?,
        ];
        let parent = TreeStatement::merge(&statements[0], &statements[1])?;
        ensure!(
            statements[0].count >= 2,
            "merge inputs must be aggregate proofs"
        );
        let source = if statements[0].count == 2 {
            &self.first
        } else {
            &self.recursive
        };
        let (private, imports) = import_children(children, |i, child, private| {
            private.extend(statements[i].fields());
            private.extend(statements[1 - i].digest.map(|v| F::new(u64::from(v))));
            private.extend(
                source.private_inputs(&child.proof, &fields(&statements[i], &self.authority))?,
            );
            Ok(())
        })?;
        let public = AggregatePublic {
            children: children
                .iter()
                .flat_map(|c| c.public.children.clone())
                .collect(),
        };
        ensure!(
            TreeStatement::from_public(&public)? == parent,
            "incorrect ordered merge statement"
        );
        let (proof, aggregate) = self
            .outer
            .prove(&fields(&parent, &self.authority), &private)?;
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

pub(crate) fn fields(statement: &TreeStatement, authority: &RecursiveAuthority) -> Vec<F> {
    (0..2)
        .flat_map(|side| {
            statement
                .fields()
                .into_iter()
                .chain([F::new(side)])
                .chain(authority.fields())
        })
        .collect()
}

fn circuit(source: &RecursiveAggregate, first: &RecursiveAuthority) -> Result<Circuit<F>> {
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
    let authority = b.alloc_public_input_array::<AUTHORITY_BYTES>("merge authority");
    let child = b.alloc_private_input_array::<STATEMENT_BYTES>("child statement");
    let sibling = b.alloc_private_input_array::<32>("sibling digest");
    let count_bits = b.binary_decompose_coordinates(child[32], MAX_CHILDREN.ilog2() as usize)?;
    b.connect(count_bits[0], ExprId::ZERO);
    let first = first.fields();
    let selected = std::array::from_fn(|i| {
        let first = b.define_const(first[i]);
        b.select(count_bits[1], first, authority[i])
    });
    let public: Vec<_> = (0..2)
        .flat_map(|role| {
            let role = b.define_const(F::new(role));
            child.into_iter().chain([role]).chain(authority)
        })
        .collect();
    source.verify_with_authority(&mut b, &public, &selected)?;
    let left = TreeTarget {
        digest: std::array::from_fn(|i| b.select(side, sibling[i], child[i])),
        count: child[32],
    };
    let right = TreeTarget {
        digest: std::array::from_fn(|i| b.select(side, child[i], sibling[i])),
        count: child[32],
    };
    TreeTarget::merge(&mut b, left, right)?.connect(&mut b, expected);
    Ok(b.build()?)
}
