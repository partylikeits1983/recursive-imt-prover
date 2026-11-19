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
    checkpoint_keccak::ports::BRIDGE_LIMBS,
    checkpoint_keccak::recursive::{
        PortTargets, PreparedLinkedVerifier,
        closed::{BoundaryPcs, builder},
    },
};

pub struct RecursiveAggregate {
    authority: Verifier,
    arithmetic: RecursiveArithmetic,
    keccak: Option<(BoundaryPcs, PreparedLinkedVerifier)>,
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
            authority.data.backend != HashBackend::Flock,
            "unsupported recursive aggregate backend"
        );
        let arithmetic = authority.recursive_arithmetic()?;
        let keccak = authority
            .checkpoint
            .as_ref()
            .map(|scheme| {
                Ok::<_, anyhow::Error>((
                    BoundaryPcs::new(scheme.log_batch, 2, scheme.recursive_pcs_seed())?,
                    PreparedLinkedVerifier::with_bridge(scheme.log_batch, scheme.direct_bridge)?,
                ))
            })
            .transpose()?;
        Ok(Self {
            authority,
            arithmetic,
            keccak,
        })
    }

    pub fn circuit(&self) -> Result<Circuit<F>> {
        let mut b = builder()?;
        if self.keccak.is_none() {
            b.enable_native_blake3_compress()?;
        }
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
        let identity = &authority[..32];
        let preprocessing = vec![NativeBinaryEncoding::words_from_bytes(b, &authority[32..])?];
        let Some((boundary, linked)) = &self.keccak else {
            let arithmetic_proof = self.arithmetic.allocate(b)?;
            let ch = BinaryTower128Challenger::with_initial_bytes_with_host::<
                NativeBinaryEncoding,
                F,
            >(b, ByteHash::Blake3, identity)?;
            self.arithmetic.verify_with_preprocessed(
                b,
                ch,
                public,
                &arithmetic_proof,
                &preprocessing,
            )?;
            return Ok(());
        };
        let scheme = self.authority.checkpoint.as_ref().unwrap();
        let cap = boundary.allocate_cap(b, false);
        let arithmetic_proof = self.arithmetic.allocate(b)?;
        let keccak_proof = linked.allocate(b)?;
        let opening = boundary.verifier.allocate_native_targets(b)?;
        let seed = linked.arithmetic_seed(b, identity, &cap)?;
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
        let ports = PortTargets { instance, values };
        let seed = linked.transcript_seed(b, identity)?;
        let ch = boundary.challenger_with_seed(b, &seed, &cap)?;
        let reduced = linked.verify_reduction(b, ch, &ports, &keccak_proof)?;
        let (values, _) = boundary.verifier.verify_at_native(
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
        let Some((boundary, _)) = &self.keccak else {
            return self
                .arithmetic
                .private_inputs(bytes, public, &self.authority.data.seed);
        };
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
        let mut private = boundary.public_inputs(&proof.statement)?;
        let seed = scheme.arithmetic_seed(&self.authority.data.seed, &proof.statement)?;
        private.extend(
            self.arithmetic
                .import_proof(proof.arithmetic, public, &seed)?,
        );
        let seed = scheme.transcript_seed(&self.authority.data.seed);
        let mut ch = boundary.native_challenger(&proof.statement, &seed)?;
        let input = scheme.recursive_input(&proof.keccak, &ports, &mut ch)?;
        private.extend(input.private_values);
        private.extend(boundary.private_inputs(
            &proof.statement,
            &input.points,
            &input.opening,
            &mut ch,
        )?);
        Ok(private)
    }
}
