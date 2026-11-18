use anyhow::{Result, ensure};
use old_binary_field::Poly64 as F;
use p3_circuit::{
    Circuit, CircuitBuilder, ExprId,
    ops::{ByteHash, binary_encoding::NativeBinaryEncoding, binary_host::BinaryCircuitHost},
};
use p3_recursion::BinaryTower128Challenger;
use serde::{Deserialize, Serialize};

use super::{RecursiveArithmetic, Verifier};
use crate::{
    HashBackend, Prepared,
    air::convert,
    checkpoint::{self, AggregateProof},
    checkpoint_keccak::recursive::{
        PortTargets, PreparedLinkedVerifier,
        closed::{BoundaryPcs, builder},
    },
};

pub struct RecursiveAggregate {
    authority: Verifier,
    arithmetic: RecursiveArithmetic,
    boundary: BoundaryPcs,
    linked: PreparedLinkedVerifier,
}

pub const AUTHORITY_BYTES: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecursiveAuthority {
    pub identity: [u8; 32],
    pub preprocessing: [u8; 32],
}

impl RecursiveAuthority {
    pub fn bytes(&self) -> [u8; AUTHORITY_BYTES] {
        std::array::from_fn(|i| {
            if i < 32 {
                self.identity[i]
            } else {
                self.preprocessing[i - 32]
            }
        })
    }

    pub fn fields(&self) -> [F; AUTHORITY_BYTES] {
        self.bytes().map(|v| F::new(u64::from(v)))
    }
}

impl Verifier {
    pub fn recursive_authority(&self) -> Result<RecursiveAuthority> {
        let cap = self
            .data
            .key
            .preprocessed_commitment()
            .ok_or_else(|| anyhow::anyhow!("missing recursive preprocessing commitment"))?;
        ensure!(
            cap.roots().len() == 1,
            "recursive authority requires a singleton cap"
        );
        Ok(RecursiveAuthority {
            identity: self.data.seed,
            preprocessing: cap.roots()[0],
        })
    }
}

impl RecursiveAggregate {
    pub fn require_same_layout(&self, output: &Prepared) -> Result<()> {
        self.authority.require_same_layout(output)
    }

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
        Ok(Self {
            authority,
            arithmetic,
            boundary,
            linked,
        })
    }

    pub fn circuit(&self) -> Result<Circuit<F>> {
        let mut b = builder()?;
        let public: Vec<_> = (0..self.authority.public_count)
            .map(|_| b.alloc_public_input("aggregate statement"))
            .collect();
        self.verify_in(&mut b, &public)?;
        Ok(b.build()?)
    }

    pub fn verify_in(&self, b: &mut CircuitBuilder<F>, public: &[ExprId]) -> Result<()> {
        let authority = self
            .authority
            .recursive_authority()?
            .fields()
            .map(|v| b.define_const(v));
        self.verify_with_authority(b, public, &authority)
    }

    /// The enclosing circuit must authenticate the selected authority.
    pub fn verify_with_authority(
        &self,
        b: &mut CircuitBuilder<F>,
        public: &[ExprId],
        authority: &[ExprId; AUTHORITY_BYTES],
    ) -> Result<()> {
        ensure!(
            public.len() == self.authority.public_count,
            "incorrect recursive public count"
        );
        let scheme = self.authority.checkpoint.as_ref().unwrap();
        let cap = self.boundary.allocate_cap(b, false);
        let arithmetic_proof = self.arithmetic.allocate(b)?;
        let keccak_proof = self.linked.allocate(b)?;
        let opening = self.boundary.verifier.allocate_native_targets(b)?;
        let identity = &authority[..32];
        let preprocessing = vec![NativeBinaryEncoding::words_from_bytes(b, &authority[32..])?];
        let seed = self.linked.arithmetic_seed(b, identity, &cap)?;
        let ch = BinaryTower128Challenger::with_initial_bytes_with_host::<NativeBinaryEncoding, F>(
            b,
            ByteHash::Keccak256,
            &seed,
        )?;
        let authenticated = self.arithmetic.verify_with_preprocessed(
            b,
            ch,
            public,
            &arithmetic_proof,
            &preprocessing,
        )?;
        ensure!(
            authenticated.point.len() >= scheme.log_batch,
            "incorrect recursive port point"
        );
        let ports = PortTargets {
            instance: authenticated.point[authenticated.point.len() - scheme.log_batch..].to_vec(),
            values: authenticated.main[self.authority.data.hash_index]
                .current()
                .to_vec(),
        };
        let seed = self.linked.transcript_seed(b, identity)?;
        let ch = self.boundary.challenger_with_seed(b, &seed, &cap)?;
        let reduced = self.linked.verify_reduction(b, ch, &ports, &keccak_proof)?;
        let (values, _) = self.boundary.verifier.verify_at_native(
            b,
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
        reduced.authenticate(b, core::array::from_fn(|i| &values[i].current()[0]));
        Ok(())
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
