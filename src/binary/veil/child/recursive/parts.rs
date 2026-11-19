//! Three linked verifier relations, splitting the monolithic prover's measured
//! memory bottleneck. The final wrapper must constrain ALL links below.
use anyhow::{Result, bail, ensure};
use p3_circuit::{
    Circuit, CircuitBuilder, ExprId,
    ops::{
        ByteHash, NativePoly192Target, binary_encoding::NativeBinaryEncoding,
        binary_host::BinaryCircuitHost,
    },
};
use p3_field::{BasedVectorSpace, RawDataSerializable};

use super::{MaskedMembershipProof, PreparedMaskedVerifier};
use crate::binary::{
    relation::{ClientPublic, PUBLIC_BYTES},
    veil::{
        E, F,
        compiler::MaskedReader,
        stacked_oracle::recursive::opening::{circuit_dot, circuit_powers, constants, field},
        vector::{powers, recursive::PreparedVector},
        whir::recursive::transcript::CircuitTranscript,
    },
};

const WEIGHTS_DOMAIN: &[u8; 16] = b"IMTVEIL4WEIGHTS\0";
pub const PUBLIC_COUNTS: [usize; 3] = [PUBLIC_BYTES + 114, 79, 99];
// (source part, offset, destination part, offset, length). Shared by the
// recursive linker and the explicit non-succinct component baseline.
const LINKS: [(usize, usize, usize, usize, usize); 6] = [
    (0, PUBLIC_BYTES, 2, 0, 32),
    (0, PUBLIC_BYTES + 32, 1, 0, 32),
    (0, PUBLIC_BYTES + 64, 2, 32, 32),
    (0, PUBLIC_BYTES + 96, 1, 64, 15),
    (0, PUBLIC_BYTES + 111, 2, 96, 3),
    (1, 32, 2, 64, 32),
];

pub struct PartInput {
    pub public: Vec<F>,
    pub private: Vec<F>,
}

impl PreparedMaskedVerifier {
    pub fn part_circuit(&self, part: usize) -> Result<Circuit<F>> {
        ensure!(part < 3, "unknown masked verifier part");
        let mut b = CircuitBuilder::<F>::new();
        b.enable_native_blake3_compress()?;
        let public = b.alloc_public_inputs(PUBLIC_COUNTS[part], "linked-verifier-state");
        match part {
            0 => {
                let (statement, state) = public.split_at(PUBLIC_BYTES);
                let masked: Vec<_> = (0..self.child.messages + 6)
                    .map(|_| field(&mut b))
                    .collect();
                let root = b.alloc_private_input_array::<32>("masked-oracle-root");
                let oracle = self.oracle.allocate(&mut b)?;
                let (relation, transcript) = self.replay_circuit(
                    &mut b,
                    statement.try_into()?,
                    &masked,
                    state[..32].try_into()?,
                    &root,
                    &oracle,
                )?;
                connect(&mut b, transcript.fingerprint(), &state[32..64]);
                let link = target(&b, &state[96..99]);
                let claims: Vec<_> = state[99..108]
                    .as_chunks::<3>()
                    .0
                    .iter()
                    .map(|c| b.native_poly192_from_coefficients(*c))
                    .collect();
                let batch = target(&b, &state[108..111]);
                let (weights, constant) = relation.weights(&mut b, &link, &claims, &batch)?;
                let digest = weights_digest(&mut b, &weights)?;
                connect(&mut b, &digest, &state[64..96]);
                let dot = circuit_dot(&mut b, &weights, &masked)?;
                let check = b.native_poly192_add(&dot, &constant);
                connect(&mut b, check.coefficients(), &state[111..114]);
            }
            1 => {
                let prepared = self.product_part()?;
                let proof = prepared.allocate(&mut b)?;
                let mut transcript = CircuitTranscript::from_state(public[..32].try_into()?);
                transcript.bytes(&mut b, b"product-commitment", &proof.root)?;
                let link = transcript.challenge(&mut b, b"product-link")?;
                connect(&mut b, link.coefficients(), &public[64..67]);
                let weights = circuit_powers(&mut b, &link, self.child.algebra.products + 2);
                transcript = prepared.verify(&mut b, &proof, &weights, transcript)?;
                let batch = transcript.challenge(&mut b, b"linear-batch")?;
                connect(&mut b, batch.coefficients(), &public[76..79]);
                for (claim, expected) in proof.claims.iter().zip(public[67..76].as_chunks::<3>().0)
                {
                    connect(&mut b, claim.coefficients(), expected);
                }
                connect(&mut b, transcript.fingerprint(), &public[32..64]);
            }
            2 => {
                let weights: Vec<_> = (0..self.child.messages + 6)
                    .map(|_| field(&mut b))
                    .collect();
                let prepared = self.mask_part()?;
                let proof = prepared.allocate(&mut b)?;
                connect(&mut b, &proof.root, &public[..32]);
                let digest = weights_digest(&mut b, &weights)?;
                connect(&mut b, &digest, &public[32..64]);
                connect(&mut b, proof.claims[0].coefficients(), &public[96..99]);
                let _ = prepared.verify(
                    &mut b,
                    &proof,
                    &weights,
                    CircuitTranscript::from_state(public[64..96].try_into()?),
                )?;
            }
            _ => bail!("unknown verifier part"),
        }
        Ok(b.build()?)
    }

    pub fn import_parts(
        &self,
        public: &ClientPublic,
        proof: &MaskedMembershipProof,
    ) -> Result<[PartInput; 3]> {
        let binding = self.child.binding(public, &proof.oracle_root)?;
        let mut reader = MaskedReader::new(
            &self.child.parameters,
            &binding,
            self.child.messages,
            &proof.inner.masks.root,
            &proof.inner.masked,
        )?;
        let replay = self.child.program.replay(&mut reader)?;
        let reduction = self.child.program.reduce(replay)?;
        let start = self.child.program.message_count();
        let count = self.child.oracle.messages(2)?;
        let oracle_private = self.oracle.import(
            &proof.opening,
            &proof.oracle_root,
            &reduction.point,
            &proof.inner.masked[start..start + count],
            reader.public_transcript().clone(),
        )?;
        let mut reader = MaskedReader::new(
            &self.child.parameters,
            &binding,
            self.child.messages,
            &proof.inner.masks.root,
            &proof.inner.masked,
        )?;
        let relation =
            self.child
                .replay(public, &proof.oracle_root, &proof.opening, &mut reader)?;
        reader.finish(&relation)?;
        let mut transcript = reader.public_transcript().clone();
        let r0 = transcript.fingerprint();
        transcript.bytes(b"product-commitment", &proof.inner.products.root);
        let link = transcript.challenge(b"product-link")?;
        let products = relation.padded_products();
        let link_weights = powers(link, products.len());
        let product_private = self.product_part()?.import(
            &proof.inner.products,
            &link_weights,
            &self.child.parameters,
            transcript.clone(),
        )?;
        proof.inner.products.verify(
            &self.child.parameters.code(products.len(), true)?,
            &link_weights,
            3,
            true,
            &self.child.parameters,
            &mut transcript,
        )?;
        let batch = transcript.challenge(b"linear-batch")?;
        let r1 = transcript.fingerprint();
        ensure!(
            proof.inner.products.dot.claims.len() == 3 && proof.inner.masks.dot.claims.len() == 1,
            "wrong linked claim counts"
        );
        let (weights, _) = relation.linear_test(
            &[],
            &products,
            &link_weights,
            &proof.inner.products.dot.claims,
            batch,
        );
        let digest = native_weights_digest(&weights);
        let mask_private = self.mask_part()?.import(
            &proof.inner.masks,
            &weights,
            &self.child.parameters,
            transcript,
        )?;
        let mut a_public = public.fields();
        a_public.extend(raw(&proof.inner.masks.root));
        a_public.extend(raw(&r0));
        a_public.extend(raw(&digest));
        a_public.extend(fields(&[link]));
        a_public.extend(fields(&proof.inner.products.dot.claims));
        a_public.extend(fields(&[batch, proof.inner.masks.dot.claims[0]]));
        let mut b_public = raw(&r0);
        b_public.extend(raw(&r1));
        b_public.extend(fields(&[link]));
        b_public.extend(fields(&proof.inner.products.dot.claims));
        b_public.extend(fields(&[batch]));
        let mut c_public = raw(&proof.inner.masks.root);
        c_public.extend(raw(&digest));
        c_public.extend(raw(&r1));
        c_public.extend(fields(&proof.inner.masks.dot.claims));
        let mut a_private = fields(&proof.inner.masked);
        a_private.extend(raw(&proof.oracle_root));
        a_private.extend(oracle_private);
        let mut c_private = fields(&weights);
        c_private.extend(mask_private);
        Ok([
            PartInput {
                public: a_public,
                private: a_private,
            },
            PartInput {
                public: b_public,
                private: product_private,
            },
            PartInput {
                public: c_public,
                private: c_private,
            },
        ])
    }

    fn product_part(&self) -> Result<PreparedVector> {
        PreparedVector::new(
            self.child
                .parameters
                .code(self.child.algebra.products + 2, true)?,
            3,
            true,
            &self.child.parameters,
        )
    }
    fn mask_part(&self) -> Result<PreparedVector> {
        PreparedVector::new(
            self.child.parameters.code(self.child.messages + 6, false)?,
            1,
            false,
            &self.child.parameters,
        )
    }
}

/// Bind every part before the final wrapper accepts the child statement.
pub fn connect_parts(
    b: &mut CircuitBuilder<F>,
    public: &[ExprId; PUBLIC_BYTES],
    parts: &[Vec<ExprId>; 3],
) -> Result<()> {
    ensure!(
        parts.iter().zip(PUBLIC_COUNTS).all(|(p, n)| p.len() == n),
        "wrong linked statement counts"
    );
    connect(b, public, &parts[0][..PUBLIC_BYTES]);
    for (a, i, c, j, n) in LINKS {
        connect(b, &parts[a][i..i + n], &parts[c][j..j + n]);
    }
    Ok(())
}

/// Public equality checks for the component baseline. These checks compose
/// independently verified component proofs; they do not replace their circuits.
pub fn check_parts(public: &[F], parts: [&[F]; 3]) -> Result<()> {
    ensure!(
        public.len() == PUBLIC_BYTES && parts.iter().zip(PUBLIC_COUNTS).all(|(p, n)| p.len() == n),
        "wrong linked statement counts"
    );
    ensure!(
        public == &parts[0][..PUBLIC_BYTES],
        "component child statement differs"
    );
    for (a, i, c, j, n) in LINKS {
        ensure!(
            parts[a][i..i + n] == parts[c][j..j + n],
            "component statements do not link"
        );
    }
    Ok(())
}

fn target(b: &CircuitBuilder<F>, values: &[ExprId]) -> NativePoly192Target {
    b.native_poly192_from_coefficients(values.try_into().expect("fixed coefficient slice"))
}
fn connect(b: &mut CircuitBuilder<F>, a: &[ExprId], c: &[ExprId]) {
    assert_eq!(a.len(), c.len());
    for (&a, &c) in a.iter().zip(c) {
        b.connect(a, c);
    }
}
fn raw(bytes: &[u8]) -> Vec<F> {
    bytes.iter().map(|&v| F::new(u64::from(v))).collect()
}
fn fields(values: &[E]) -> Vec<F> {
    values
        .iter()
        .flat_map(|v| v.as_basis_coefficients_slice().iter().copied())
        .collect()
}
fn native_weights_digest(weights: &[E]) -> [u8; 32] {
    let mut hash = blake3::Hasher::new();
    hash.update(WEIGHTS_DOMAIN);
    hash.update(&(weights.len() as u64).to_le_bytes());
    for value in weights {
        hash.update(&value.into_bytes().into_iter().collect::<Vec<_>>());
    }
    hash.finalize().into()
}
fn weights_digest(
    b: &mut CircuitBuilder<F>,
    weights: &[NativePoly192Target],
) -> Result<[ExprId; 32]> {
    let mut words = constants(b, WEIGHTS_DOMAIN);
    words.extend(constants(b, &(weights.len() as u64).to_le_bytes()));
    for value in weights {
        for &coefficient in value.coefficients() {
            words.extend(b.native_poly64_unchecked_words(coefficient, 4)?);
        }
    }
    let hash = NativeBinaryEncoding::hash_words(b, ByteHash::Blake3, &words)?;
    Ok(NativeBinaryEncoding::bytes_from_words(b, &hash)?
        .try_into()
        .expect("BLAKE3 bytes"))
}

#[cfg(test)]
mod tests;
