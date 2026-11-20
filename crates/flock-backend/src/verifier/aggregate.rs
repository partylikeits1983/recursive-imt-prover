use anyhow::{Result, ensure};
use old_binary_field::Poly64 as F;
use p3_circuit::ops::NativePoly192Target;
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
    checkpoint_keccak::ports::BRIDGE_LIMBS,
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
        let linked = PreparedLinkedVerifier::with_packing(
            scheme.log_batch,
            scheme.direct_bridge,
            scheme.packed_chi,
        )?;
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
        if self.authority.config.joint_security.is_some() {
            return self.verify_joint(b, public, authority);
        }
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
        let ports = self.ports(b, &authenticated)?;
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

    fn ports(
        &self,
        b: &mut CircuitBuilder<F>,
        authenticated: &p3_recursion::verifier::AuthenticatedCoordinateOpenings,
    ) -> Result<PortTargets> {
        let scheme = self.authority.checkpoint.as_ref().unwrap();
        let arity = scheme.log_batch + usize::from(scheme.direct_bridge);
        ensure!(
            authenticated.point.len() >= arity,
            "incorrect recursive port point"
        );
        let instance = authenticated.point[authenticated.point.len() - arity..].to_vec();
        let opened = authenticated.main[self.authority.data.hash_index].current();
        let values = if scheme.direct_bridge {
            ensure!(
                opened.len() == 2 * BRIDGE_LIMBS,
                "invalid recursive Keccak bridge"
            );
            opened[..BRIDGE_LIMBS]
                .iter()
                .zip(&opened[BRIDGE_LIMBS..])
                .map(|(left, right)| {
                    let diff = b.native_poly192_add(left, right);
                    let product = b.native_poly192_mul(&instance[0], &diff);
                    b.native_poly192_add(left, &product)
                })
                .collect()
        } else {
            opened.to_vec()
        };
        Ok(PortTargets { instance, values })
    }

    fn verify_joint(
        &self,
        b: &mut CircuitBuilder<F>,
        public: &[ExprId],
        authority: &[ExprId; AUTHORITY_BYTES],
    ) -> Result<()> {
        let scheme = self.authority.checkpoint.as_ref().unwrap();
        let arithmetic = self.arithmetic.allocate(b)?;
        let keccak = self.linked.allocate(b)?;
        let mut alloc_port = || {
            let limbs = b.alloc_private_input_array::<3>("joint Keccak port");
            b.native_poly192_from_coefficients(limbs)
        };
        let ports = PortTargets {
            instance: (0..=scheme.log_batch).map(|_| alloc_port()).collect(),
            values: (0..BRIDGE_LIMBS).map(|_| alloc_port()).collect(),
        };
        let identity = &authority[..32];
        let seed = self.linked.transcript_seed(b, identity)?;
        let mut linked = BinaryTower128Challenger::with_initial_bytes_with_host::<
            NativeBinaryEncoding,
            F,
        >(b, ByteHash::Keccak256, &seed)?;
        self.arithmetic
            .verifier
            .main_pcs()
            .observe_commitment_native(b, &mut linked, &arithmetic.commitment)?;
        let reduced = self.linked.verify_reduction(b, linked, &ports, &keccak)?;
        let ch = BinaryTower128Challenger::with_initial_bytes_with_host::<NativeBinaryEncoding, F>(
            b,
            ByteHash::Keccak256,
            identity,
        )?;
        let preprocessing = vec![NativeBinaryEncoding::words_from_bytes(b, &authority[32..])?];
        let opened = self.arithmetic.verifier.verify_with_auxiliary_points(
            b,
            ch,
            &self.arithmetic.public(public)?,
            &arithmetic,
            Some(&preprocessing),
            &reduced.points,
        )?;
        let verified = self.ports(b, &opened)?;
        for (a, c) in ports
            .instance
            .iter()
            .chain(&ports.values)
            .zip(verified.instance.iter().chain(&verified.values))
        {
            for (&a, &c) in a.coefficients().iter().zip(c.coefficients()) {
                b.connect(a, c);
            }
        }
        let values: [&NativePoly192Target; 4] = opened
            .auxiliary
            .iter()
            .map(|v| {
                ensure!(
                    v.current().len() == 1 && v.next().is_empty(),
                    "invalid joint boundary width"
                );
                Ok(&v.current()[0])
            })
            .collect::<Result<Vec<_>>>()?
            .try_into()
            .map_err(|_| anyhow::anyhow!("expected four boundary openings"))?;
        reduced.authenticate(b, values);
        Ok(())
    }

    pub fn private_inputs(&self, bytes: &[u8], public: &[F]) -> Result<Vec<F>> {
        ensure!(
            public.len() == self.authority.public_count,
            "incorrect recursive public count"
        );
        if self.authority.config.joint_security.is_some() {
            let scheme = self.authority.checkpoint.as_ref().unwrap();
            let (proof, coefficients) = checkpoint::JointProof::decode(bytes, scheme.packed_chi)?;
            let mut linked = super::recursive::Ch::from_hasher(
                scheme.transcript_seed(&self.authority.data.seed).to_vec(),
                old_keccak::Keccak256Hash,
            );
            let cap = old_merkle_tree::MerkleCap::new(proof.arithmetic.commitment.roots().to_vec());
            self.arithmetic
                .verifier
                .main_pcs()
                .observe_native_commitment(&mut linked, &cap)?;
            let (keccak, points) =
                scheme.import_claims(&proof.keccak, &coefficients, &proof.ports, &mut linked)?;
            let mut private = self.arithmetic.import_joint(
                proof.arithmetic,
                public,
                &self.authority.data.seed,
                &points,
            )?;
            private.extend(keccak);
            for value in proof.ports.instance.iter().chain(&proof.ports.values) {
                private.extend(value.coefficients().map(|f| F::new(f.to_bits())));
            }
            return Ok(private);
        }
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
        private.extend(
            self.arithmetic
                .import_proof(proof.arithmetic, public, &seed)?,
        );
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
