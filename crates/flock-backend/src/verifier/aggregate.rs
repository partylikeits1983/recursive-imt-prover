use anyhow::{Result, ensure};
use old_binary_field::Poly64 as F;
use p3_circuit::{
    Circuit,
    ops::{ByteHash, binary_encoding::NativeBinaryEncoding},
};
use p3_recursion::BinaryTower128Challenger;

use super::{RecursiveArithmetic, Verifier};
use crate::{
    HashBackend,
    air::convert,
    checkpoint::{self, AggregateProof},
    checkpoint_keccak::recursive::{
        PortTargets, PreparedLinkedVerifier,
        closed::{BoundaryPcs, builder},
    },
};

pub struct RecursiveAggregate {
    pub circuit: Circuit<F>,
    authority: Verifier,
    arithmetic: RecursiveArithmetic,
    boundary: BoundaryPcs,
}

impl RecursiveAggregate {
    /// The authority must already have been checked against independently trusted verifier data.
    pub fn new(authority: Verifier) -> Result<Self> {
        ensure!(
            authority.data.backend == HashBackend::Checkpoint,
            "recursive aggregate requires checkpoint backend"
        );
        let scheme = authority.checkpoint.as_ref().unwrap();
        let arithmetic = authority.recursive_arithmetic()?;
        let boundary = BoundaryPcs::new(scheme.log_batch, 2, scheme.recursive_pcs_seed())?;
        let linked = PreparedLinkedVerifier::new(scheme.log_batch)?;
        let mut b = builder()?;
        let public: Vec<_> = (0..authority.public_count)
            .map(|_| b.alloc_public_input("aggregate statement"))
            .collect();
        let cap = boundary.allocate_cap(&mut b, false);
        let arithmetic_proof = arithmetic.allocate(&mut b)?;
        let keccak_proof = linked.allocate(&mut b)?;
        let opening = boundary.verifier.allocate_native_targets(&mut b)?;
        let identity: Vec<_> = authority
            .data
            .seed
            .iter()
            .map(|&v| b.define_const(F::new(u64::from(v))))
            .collect();
        let seed = linked.arithmetic_seed(&mut b, &identity, &cap)?;
        let ch = BinaryTower128Challenger::with_initial_bytes_with_host::<NativeBinaryEncoding, F>(
            &mut b,
            ByteHash::Keccak256,
            &seed,
        )?;
        let authenticated = arithmetic.verify(&mut b, ch, &public, &arithmetic_proof)?;
        ensure!(
            authenticated.point.len() >= scheme.log_batch,
            "incorrect recursive port point"
        );
        let ports = PortTargets {
            instance: authenticated.point[authenticated.point.len() - scheme.log_batch..].to_vec(),
            values: authenticated.main[authority.data.hash_index]
                .current()
                .to_vec(),
        };
        let seed = scheme.transcript_seed(&authority.data.seed);
        let ch = boundary.challenger(&mut b, &seed, &cap)?;
        let reduced = linked.verify_reduction(&mut b, ch, &ports, &keccak_proof)?;
        let (values, _) = boundary.verifier.verify_at_native(
            &mut b,
            reduced.challenger.clone(),
            &cap,
            &reduced.points,
            &opening,
        )?;
        ensure!(
            values.len() == 4
                && values
                    .iter()
                    .all(|v| v.current().len() == 1 && v.next().is_empty()),
            "incorrect recursive Keccak opening shape"
        );
        reduced.authenticate(&mut b, core::array::from_fn(|i| &values[i].current()[0]));
        Ok(Self {
            circuit: b.build()?,
            authority,
            arithmetic,
            boundary,
        })
    }

    pub fn private_inputs(&self, bytes: &[u8], public: &[F]) -> Result<Vec<F>> {
        ensure!(
            public.len() == self.authority.public_count,
            "incorrect recursive public count"
        );
        let proof: AggregateProof = crate::proof_codec::decode(bytes)?;
        let scheme = self.authority.checkpoint.as_ref().unwrap();
        let values: Vec<Vec<_>> = self
            .authority
            .data
            .airs
            .iter()
            .map(|a| {
                public[..a.public_count]
                    .iter()
                    .copied()
                    .map(convert)
                    .collect()
            })
            .collect();
        let ports = checkpoint::arithmetic_opening(
            &self.authority.config,
            self.authority.instances(&values),
            &proof.arithmetic,
            &proof.statement,
            &self.authority.data.seed,
            self.authority.data.hash_index,
            scheme,
        )?;
        let mut private = self.boundary.public_inputs(&proof.statement)?;
        let seed = scheme.arithmetic_seed(&self.authority.data.seed, &proof.statement)?;
        private.extend(self.arithmetic.private_inputs(bytes, public, &seed)?);
        let seed = scheme.transcript_seed(&self.authority.data.seed);
        let mut ch = self.boundary.native_challenger(&proof.statement, &seed)?;
        let input = scheme.recursive_input(&proof.keccak, &ports, &mut ch)?;
        private.extend(input.private_values);
        private.extend(self.boundary.private_inputs(
            &proof.statement,
            &input.points,
            &input.opening,
            &mut ch,
        )?);
        Ok(private)
    }
}
