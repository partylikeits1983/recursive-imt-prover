//! VEIL dot-product and Hadamard protocols over the additive interpolation code.
//! Adapted from Succinct VEIL at 749b0c63f226063c471a6238a94101f930c14a13.
use anyhow::{Result, ensure};
use p3_commit::{BatchOpeningRef, Mmcs};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::{Dimensions, dense::RowMajorMatrix};
use p3_merkle_tree::MerkleTreeHidingMmcs;
use p3_symmetric::{CompressionFunctionFromHasher, MerkleCap, SerializingHasher};
use rand::{RngExt, SeedableRng, rngs::StdRng};
use rayon::prelude::{IntoParallelRefIterator, ParallelIterator};
use serde::{Deserialize, Serialize};

use super::hash::{DomainHash, LEAF_DOMAIN, NODE_DOMAIN};
use super::{
    E,
    code::BinaryCode,
    parameters::Parameters,
    transcript::Transcript,
    whir::{BlendOpening, CommittedBlend},
};
use functional::Functional;

pub(super) mod functional;
pub(super) mod recursive;

type Tree = MerkleTreeHidingMmcs<
    E,
    u8,
    SerializingHasher<DomainHash>,
    CompressionFunctionFromHasher<DomainHash, 2, 32>,
    StdRng,
    2,
    32,
    2,
>;
type TreeData = <Tree as Mmcs<E>>::ProverData<RowMajorMatrix<E>>;
type TreePath = <Tree as Mmcs<E>>::Proof;

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct Opening {
    pub rows: Vec<Vec<E>>,
    pub(super) path: TreePath,
}

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct DotProof {
    pub claims: Vec<E>,
    mask_dot: E,
    root: [u8; 32],
    opening: BlendOpening,
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
    root: [u8; 32],
    opening: BlendOpening,
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
    pub fn columns(&self) -> &[Vec<E>] {
        &self.padded
    }

    pub fn into_openings(self, indices: &[usize]) -> Result<Vec<Opening>> {
        ensure!(indices.len() == self.code.queries, "wrong opening count");
        ensure!(
            indices.iter().all(|&i| i < self.code.codeword_len),
            "query outside codeword"
        );
        Ok(indices
            .iter()
            .map(|&i| {
                let (rows, path) = self.tree.open_batch(i, &self.data).unpack();
                Opening { rows, path }
            })
            .collect())
    }

    pub fn new(
        vectors: &[Vec<E>],
        code: BinaryCode,
        product: bool,
        rng: &mut StdRng,
    ) -> Result<Self> {
        ensure!(!vectors.is_empty(), "empty vector batch");
        ensure!(
            !product || code.is_interpolation(),
            "product requires interpolation code"
        );
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
            let mut full: Vec<E> = (0..code.input_len).map(|_| rng.random()).collect();
            let start = code.message_offset();
            full[start..start + code.message_len].copy_from_slice(column);
            *column = full;
        }
        let mut encoded: Vec<_> = padded
            .par_iter()
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

    pub fn prove(
        self,
        weights: &[E],
        parameters: &Parameters,
        transcript: &mut Transcript,
    ) -> Result<VectorProof> {
        ensure!(
            self.code.is_interpolation() && weights.len() == self.code.message_len,
            "wrong vector proof geometry"
        );
        transcript.bytes(b"vectors", &self.root);
        let product = if let Some(mask) = &self.product_mask {
            let z = transcript.challenge(b"product-test")?;
            let prefix = powers(z, weights.len());
            let gamma = dot(&prefix, &mask[..weights.len()]);
            transcript.fields(b"product-gamma", &[gamma]);
            let rho = transcript.challenge(b"product-mask")?;
            let a = self.code.to_product(&self.padded[0])?;
            let b = self.code.to_product(&self.padded[1])?;
            let c = self.code.to_product(&self.padded[2])?;
            let phi: Vec<_> = (0..a.len())
                .map(|i| a[i] * b[i] + c[i] + rho * mask[i])
                .collect();
            let commitment =
                CommittedBlend::new(self.code.blend_coefficients(&phi, true)?, parameters)?;
            transcript.bytes(b"product-blend-commitment-v1", &commitment.root);
            Some((gamma, rho, prefix, commitment))
        } else {
            None
        };
        let claims: Vec<_> = self.padded[..self.padded.len() - 1]
            .iter()
            .map(|v| dot(weights, &v[..weights.len()]))
            .collect();
        let mask_dot = dot(weights, &self.padded.last().unwrap()[..weights.len()]);
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
        let commitment =
            CommittedBlend::new(self.code.blend_coefficients(&blend, false)?, parameters)?;
        transcript.bytes(b"dot-blend-commitment-v1", &commitment.root);
        let indices = transcript.indices(self.code.queries, self.code.codeword_len);
        let openings: Vec<_> = indices
            .iter()
            .map(|&i| {
                let (rows, path) = self.tree.open_batch(i, &self.data).unpack();
                Opening { rows, path }
            })
            .collect();
        let columns = claims.len();
        let values: Vec<_> = openings
            .iter()
            .map(|o| {
                o.rows[0][..columns + 1]
                    .iter()
                    .rev()
                    .fold(E::ZERO, |sum, &v| v + rho * sum)
            })
            .collect();
        let expected = claims.iter().rev().fold(mask_dot, |sum, &v| v + rho * sum);
        let (functional, sum) = Functional::new(
            &self.code, false, weights, &indices, &values, expected, transcript,
        )?;
        let root = commitment.root;
        let opening = commitment.prove(&functional, sum, transcript)?;
        let product = product
            .map(|(gamma, rho, prefix, commitment)| -> Result<_> {
                let values: Vec<_> = openings
                    .iter()
                    .map(|o| {
                        let row = &o.rows[0];
                        row[0] * row[1] + row[2] + rho * row[4]
                    })
                    .collect();
                let (functional, sum) = Functional::new(
                    &self.code,
                    true,
                    &prefix,
                    &indices,
                    &values,
                    rho * gamma,
                    transcript,
                )?;
                let root = commitment.root;
                let opening = commitment.prove(&functional, sum, transcript)?;
                Ok(ProductProof {
                    gamma,
                    root,
                    opening,
                })
            })
            .transpose()?;
        Ok(VectorProof {
            root: self.root,
            dot: DotProof {
                claims,
                mask_dot,
                root,
                opening,
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
        parameters: &Parameters,
        transcript: &mut Transcript,
    ) -> Result<()> {
        ensure!(
            code.is_interpolation() && weights.len() == code.message_len,
            "wrong vector verifier geometry"
        );
        ensure!(self.dot.claims.len() == columns, "wrong dot claim count");
        ensure!(
            self.product.is_some() == product && (!product || columns == 3),
            "wrong product shape"
        );
        transcript.bytes(b"vectors", &self.root);
        let product_check = if let Some(proof) = &self.product {
            let z = transcript.challenge(b"product-test")?;
            transcript.fields(b"product-gamma", &[proof.gamma]);
            let rho = transcript.challenge(b"product-mask")?;
            transcript.bytes(b"product-blend-commitment-v1", &proof.root);
            Some((rho, powers(z, weights.len())))
        } else {
            None
        };
        transcript.fields(b"dot-claims", &self.dot.claims);
        transcript.fields(b"dot-mask", &[self.dot.mask_dot]);
        let rho = transcript.challenge(b"dot-blend")?;
        let expected = self
            .dot
            .claims
            .iter()
            .rev()
            .fold(self.dot.mask_dot, |sum, &v| v + rho * sum);
        transcript.bytes(b"dot-blend-commitment-v1", &self.dot.root);
        let indices = transcript.indices(code.queries, code.codeword_len);
        let width = columns + 1 + usize::from(product);
        verify_openings(&self.root, code, width, &indices, &self.openings)?;
        let values: Vec<_> = self
            .openings
            .iter()
            .map(|o| {
                o.rows[0][..columns + 1]
                    .iter()
                    .rev()
                    .fold(E::ZERO, |sum, &v| v + rho * sum)
            })
            .collect();
        let (functional, sum) = Functional::new(
            code, false, weights, &indices, &values, expected, transcript,
        )?;
        self.dot
            .opening
            .verify(&self.dot.root, &functional, sum, parameters, transcript)?;
        if let (Some(proof), Some((rho, prefix))) = (&self.product, product_check) {
            let values: Vec<_> = self
                .openings
                .iter()
                .map(|o| {
                    let row = &o.rows[0];
                    row[0] * row[1] + row[2] + rho * row[4]
                })
                .collect();
            let (functional, sum) = Functional::new(
                code,
                true,
                &prefix,
                &indices,
                &values,
                rho * proof.gamma,
                transcript,
            )?;
            proof
                .opening
                .verify(&proof.root, &functional, sum, parameters, transcript)?;
        }
        Ok(())
    }
}

pub(super) fn verify_openings(
    root: &[u8; 32],
    code: &BinaryCode,
    width: usize,
    indices: &[usize],
    openings: &[Opening],
) -> Result<()> {
    ensure!(
        openings.len() == code.queries && indices.len() == code.queries,
        "wrong opening count"
    );
    ensure!(
        indices.iter().all(|&i| i < code.codeword_len),
        "query outside codeword"
    );
    // This verifier never draws salts; the shared MMCS type requires an RNG.
    let tree = mmcs(StdRng::from_seed([0; 32]));
    let cap = MerkleCap::new(vec![*root]);
    let dimensions = [Dimensions {
        width,
        height: code.codeword_len,
    }];
    for (&index, opening) in indices.iter().zip(openings) {
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
    }
    Ok(())
}

fn mmcs(rng: StdRng) -> Tree {
    Tree::new(
        SerializingHasher::new(DomainHash(LEAF_DOMAIN)),
        CompressionFunctionFromHasher::new(DomainHash(NODE_DOMAIN)),
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
