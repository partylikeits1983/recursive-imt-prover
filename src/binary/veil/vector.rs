//! VEIL dot-product and Hadamard protocols over the additive interpolation code.
//! Adapted from Succinct VEIL at 749b0c63f226063c471a6238a94101f930c14a13.
use anyhow::{Result, ensure};
use p3_commit::{BatchOpeningRef, Mmcs};
use p3_field::PrimeCharacteristicRing;
use p3_keccak::Keccak256Hash;
use p3_matrix::{Dimensions, dense::RowMajorMatrix};
use p3_merkle_tree::MerkleTreeHidingMmcs;
use p3_symmetric::{CompressionFunctionFromHasher, MerkleCap, SerializingHasher};
use rand::{RngExt, SeedableRng, rngs::StdRng};
use serde::{Deserialize, Serialize};

use super::{E, code::BinaryCode, transcript::Transcript};

type Tree = MerkleTreeHidingMmcs<
    E,
    u8,
    SerializingHasher<Keccak256Hash>,
    CompressionFunctionFromHasher<Keccak256Hash, 2, 32>,
    StdRng,
    2,
    32,
    2,
>;
type TreeData = <Tree as Mmcs<E>>::ProverData<RowMajorMatrix<E>>;
type TreePath = <Tree as Mmcs<E>>::Proof;

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct Opening {
    rows: Vec<Vec<E>>,
    path: TreePath,
}

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct DotProof {
    pub claims: Vec<E>,
    mask_dot: E,
    blend: Vec<E>,
}

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct VectorProof {
    pub root: [u8; 32],
    pub dot: DotProof,
    pub product: Option<ProductProof>,
    openings: Vec<Opening>,
}

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct ProductProof {
    gamma: E,
    phi: Vec<E>,
}

/// Not Clone or Serialize. A commitment is consumed by its sole opening round.
pub(super) struct CommittedVectors {
    pub root: [u8; 32],
    code: BinaryCode,
    padded: Vec<Vec<E>>,
    product_mask: Option<Vec<E>>,
    tree: Tree,
    data: TreeData,
}

impl CommittedVectors {
    pub fn new(
        vectors: &[Vec<E>],
        code: BinaryCode,
        product: bool,
        rng: &mut StdRng,
    ) -> Result<Self> {
        ensure!(!vectors.is_empty(), "empty vector batch");
        ensure!(
            !product || vectors.len() == 3,
            "product requires exactly three vectors"
        );
        ensure!(
            vectors.iter().all(|v| v.len() == code.message_len),
            "inconsistent vector length"
        );
        let mut padded = vectors.to_vec();
        padded.push((0..code.message_len).map(|_| rng.random()).collect());
        for column in &mut padded {
            column.extend((column.len()..code.input_len).map(|_| rng.random::<E>()));
        }
        let mut encoded: Vec<_> = padded
            .iter()
            .map(|v| code.encode(v))
            .collect::<Result<_>>()?;
        let product_mask = if product {
            let mask: Vec<E> = (0..2 * code.input_len).map(|_| rng.random()).collect();
            encoded.push(code.encode_product(&mask)?);
            Some(mask)
        } else {
            None
        };
        let width = encoded.len();
        let mut values = Vec::with_capacity(code.codeword_len * width);
        for row in 0..code.codeword_len {
            values.extend(encoded.iter().map(|column| column[row]));
        }
        drop(encoded);
        let tree = mmcs(StdRng::from_rng(rng));
        let (cap, data) = tree.commit_matrix(RowMajorMatrix::new(values, width));
        Ok(Self {
            root: cap[0],
            code,
            padded,
            product_mask,
            tree,
            data,
        })
    }

    pub fn prove(self, weights: &[E], transcript: &mut Transcript) -> Result<VectorProof> {
        ensure!(
            weights.len() == self.code.message_len,
            "wrong dot-product length"
        );
        transcript.bytes(b"vectors", &self.root);
        let product = if let Some(mask) = &self.product_mask {
            let z = transcript.challenge(b"product-test")?;
            let gamma = dot(&powers(z, weights.len()), &mask[..weights.len()]);
            transcript.fields(b"product-gamma", &[gamma]);
            let rho = transcript.challenge(b"product-mask")?;
            let a = self.code.to_product(&self.padded[0])?;
            let b = self.code.to_product(&self.padded[1])?;
            let c = self.code.to_product(&self.padded[2])?;
            let phi: Vec<_> = (0..a.len())
                .map(|i| a[i] * b[i] + c[i] + rho * mask[i])
                .collect();
            transcript.fields(b"product-phi", &phi);
            Some(ProductProof { gamma, phi })
        } else {
            None
        };

        let claims: Vec<_> = self.padded[..self.padded.len() - 1]
            .iter()
            .map(|v| dot(weights, &v[..weights.len()]))
            .collect();
        let mask_dot = dot(weights, &self.padded.last().unwrap()[..weights.len()]);
        transcript.fields(b"dot-weights", weights);
        transcript.fields(b"dot-claims", &claims);
        transcript.fields(b"dot-mask", &[mask_dot]);
        let rho = transcript.challenge(b"dot-blend")?;
        let blend: Vec<_> = (0..self.code.input_len)
            .map(|i| {
                self.padded
                    .iter()
                    .rev()
                    .fold(E::ZERO, |sum, v| v[i] + rho * sum)
            })
            .collect();
        transcript.fields(b"dot-blend-message", &blend);
        let indices = transcript.indices(self.code.queries, self.code.codeword_len);
        let openings = indices
            .into_iter()
            .map(|i| {
                let (rows, path) = self.tree.open_batch(i, &self.data).unpack();
                Opening { rows, path }
            })
            .collect();
        Ok(VectorProof {
            root: self.root,
            dot: DotProof {
                claims,
                mask_dot,
                blend,
            },
            product,
            openings,
        })
    }
}

impl VectorProof {
    pub fn verify(
        &self,
        code: &BinaryCode,
        weights: &[E],
        columns: usize,
        product: bool,
        transcript: &mut Transcript,
    ) -> Result<()> {
        ensure!(
            weights.len() == code.message_len,
            "wrong verifier dot length"
        );
        ensure!(
            self.dot.claims.len() == columns,
            "wrong number of dot claims"
        );
        ensure!(self.dot.blend.len() == code.input_len, "wrong blend length");
        ensure!(self.openings.len() == code.queries, "wrong opening count");
        ensure!(
            self.product.is_some() == product,
            "unexpected product proof"
        );
        ensure!(!product || columns == 3, "wrong product width");
        transcript.bytes(b"vectors", &self.root);
        let product_check = if let Some(proof) = &self.product {
            ensure!(
                proof.phi.len() == 2 * code.input_len,
                "wrong product blend length"
            );
            let z = transcript.challenge(b"product-test")?;
            transcript.fields(b"product-gamma", &[proof.gamma]);
            let rho = transcript.challenge(b"product-mask")?;
            transcript.fields(b"product-phi", &proof.phi);
            ensure!(
                dot(&powers(z, weights.len()), &proof.phi[..weights.len()]) == rho * proof.gamma,
                "product relation failed"
            );
            Some((rho, code.encode_product(&proof.phi)?))
        } else {
            None
        };
        transcript.fields(b"dot-weights", weights);
        transcript.fields(b"dot-claims", &self.dot.claims);
        transcript.fields(b"dot-mask", &[self.dot.mask_dot]);
        let rho = transcript.challenge(b"dot-blend")?;
        let expected = self
            .dot
            .claims
            .iter()
            .rev()
            .fold(self.dot.mask_dot, |sum, &v| v + rho * sum);
        ensure!(
            dot(weights, &self.dot.blend[..weights.len()]) == expected,
            "dot relation failed"
        );
        transcript.fields(b"dot-blend-message", &self.dot.blend);
        let indices = transcript.indices(code.queries, code.codeword_len);
        let encoded = code.encode(&self.dot.blend)?;
        // Verification never draws salts. The fixed seed exists solely because
        // Plonky3 exposes one shared MMCS type for proving and verification.
        let tree = mmcs(StdRng::from_seed([0; 32]));
        let cap = MerkleCap::new(vec![self.root]);
        let width = columns + 1 + usize::from(product);
        let dimensions = [Dimensions {
            width,
            height: code.codeword_len,
        }];
        for (&index, opening) in indices.iter().zip(&self.openings) {
            ensure!(
                opening.rows.len() == 1 && opening.rows[0].len() == width,
                "wrong opened width"
            );
            ensure!(
                opening.path.0.len() == 1 && opening.path.0[0].len() == 2,
                "wrong salt width"
            );
            ensure!(
                opening.path.1.len() == code.codeword_len.ilog2() as usize,
                "wrong Merkle path length"
            );
            tree.verify_batch(
                &cap,
                &dimensions,
                index,
                BatchOpeningRef::new(&opening.rows, &opening.path),
            )
            .map_err(|e| anyhow::anyhow!("invalid vector opening: {e:?}"))?;
            let row = &opening.rows[0];
            let blend = row[..columns + 1]
                .iter()
                .rev()
                .fold(E::ZERO, |sum, &v| v + rho * sum);
            ensure!(blend == encoded[index], "dot codeword mismatch");
            if let Some((rho, encoded)) = &product_check {
                ensure!(
                    row[0] * row[1] + row[2] + *rho * row[4] == encoded[index],
                    "product codeword mismatch"
                );
            }
        }
        Ok(())
    }
}

fn mmcs(rng: StdRng) -> Tree {
    Tree::new(
        SerializingHasher::new(Keccak256Hash),
        CompressionFunctionFromHasher::new(Keccak256Hash),
        0,
        rng,
    )
}

pub(super) fn dot(a: &[E], b: &[E]) -> E {
    assert_eq!(a.len(), b.len());
    a.iter().zip(b).map(|(&a, &b)| a * b).sum()
}

pub(super) fn powers(base: E, n: usize) -> Vec<E> {
    let mut current = E::ONE;
    (0..n)
        .map(|_| {
            let value = current;
            current *= base;
            value
        })
        .collect()
}
