//! VEIL dot-product and Hadamard protocols over the additive interpolation code.
//! Adapted from Succinct VEIL at 749b0c63f226063c471a6238a94101f930c14a13.
use super::hash::RowDomains;
use anyhow::{Result, ensure};
use p3_commit::{BatchOpeningRef, Mmcs};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::{Dimensions, dense::RowMajorMatrix, stack::HorizontalPair};
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{CompressionFunctionFromHasher, MerkleCap, SerializingHasher};
use rand::TryCryptoRng;
use rayon::prelude::{IntoParallelRefIterator, ParallelIterator};
use serde::{Deserialize, Serialize};

use super::hash::DomainHash;
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

type Tree = MerkleTreeMmcs<
    E,
    u8,
    SerializingHasher<DomainHash>,
    CompressionFunctionFromHasher<DomainHash, 2, 32>,
    2,
    32,
>;
type TreeData = <Tree as Mmcs<E>>::ProverData<HorizontalPair<RowMajorMatrix<E>, RowMajorMatrix<E>>>;
type TreePath = (Vec<Vec<E>>, <Tree as Mmcs<E>>::Proof);
const SALT_FIELDS: usize = 2;

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
        Ok(indices.iter().map(|&i| self.open_row(i)).collect())
    }

    fn open_row(&self, index: usize) -> Opening {
        let (mut rows, siblings) = self.tree.open_batch(index, &self.data).unpack();
        let salts = rows
            .iter_mut()
            .map(|row| row.split_off(row.len() - SALT_FIELDS))
            .collect();
        Opening {
            rows,
            path: (salts, siblings),
        }
    }

    pub fn new(
        vectors: &[Vec<E>],
        code: BinaryCode,
        product: bool,
        rng: &mut impl TryCryptoRng,
    ) -> Result<Self> {
        Self::with_domains(vectors, code, product, RowDomains::Original, rng)
    }

    pub fn with_domains(
        vectors: &[Vec<E>],
        code: BinaryCode,
        product: bool,
        domains: RowDomains,
        rng: &mut impl TryCryptoRng,
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
        padded.push(super::coins::fields(rng, code.message_len)?);
        for column in &mut padded {
            let mut full = E::zero_vec(code.input_len);
            let (prefix, tail) = full.split_at_mut(code.message_offset());
            let (message, suffix) = tail.split_at_mut(code.message_len);
            super::coins::fill_fields(rng, prefix)?;
            message.copy_from_slice(column);
            super::coins::fill_fields(rng, suffix)?;
            *column = full;
        }
        let mut encoded: Vec<_> = padded
            .par_iter()
            .map(|v| code.encode(v))
            .collect::<Result<_>>()?;
        let product_mask = if product {
            let mask = super::coins::fields(rng, 2 * code.input_len)?;
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
        // Salt the same row bytes that the recursive verifier hashes.
        let salts = super::coins::fields(rng, code.codeword_len * SALT_FIELDS)?;
        let tree = mmcs(domains);
        let (cap, data) = tree.commit_matrix(HorizontalPair::new(
            RowMajorMatrix::new(values, width),
            RowMajorMatrix::new(salts, SALT_FIELDS),
        ));
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
        let openings: Vec<_> = indices.iter().map(|&i| self.open_row(i)).collect();
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
        self.verify_with(
            code,
            weights,
            columns,
            product,
            transcript,
            |opening, root, functional, sum, transcript| {
                opening.verify(root, functional, sum, parameters, transcript)
            },
        )
    }

    pub(super) fn opening_messages(
        &self,
        code: &BinaryCode,
        weights: &[E],
        params: &Parameters,
        transcript: &mut Transcript,
    ) -> Result<super::child::checkpoint::VectorMessages> {
        use super::child::checkpoint::{
            CoordinateMessages, OracleRowOpening, StackedBlendCheckpoint, VectorMessages,
        };
        use p3_field::RawDataSerializable;
        let product = self.product.is_some();
        let mut coordinates = Vec::new();
        self.verify_with(
            code,
            weights,
            if product { 3 } else { 1 },
            product,
            transcript,
            |opening, root, functional, sum, t| {
                let point = opening.reduce(root, functional, sum, t)?;
                let (rounds, value) = opening.round_messages();
                let blend = StackedBlendCheckpoint {
                    rounds: rounds.to_vec(),
                    value,
                    point: point.as_slice().to_vec(),
                    seed: t.fingerprint(),
                };
                let (raw, seal) = opening.opening_advice(root, &blend, params)?;
                t.bytes(b"blend-whir-seal-v3", &seal);
                coordinates.push(CoordinateMessages {
                    root: *root,
                    blend,
                    raw,
                    seal,
                });
                Ok(())
            },
        )?;
        let rows = self
            .openings
            .iter()
            .map(|r| OracleRowOpening {
                salted_row: r.rows[0]
                    .iter()
                    .chain(&r.path.0[0])
                    .flat_map(|x| x.into_bytes())
                    .collect(),
                siblings: r.path.1.clone(),
            })
            .collect();
        Ok(VectorMessages {
            root: self.root,
            gamma: self.product.as_ref().map(|p| p.gamma),
            claims: self.dot.claims.clone(),
            mask_dot: self.dot.mask_dot,
            rows,
            coordinates,
        })
    }

    fn verify_with(
        &self,
        code: &BinaryCode,
        weights: &[E],
        columns: usize,
        product: bool,
        transcript: &mut Transcript,
        mut verify_opening: impl FnMut(
            &BlendOpening,
            &[u8; 32],
            &Functional,
            E,
            &mut Transcript,
        ) -> Result<()>,
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
        verify_openings(
            &self.root,
            code,
            width,
            &indices,
            &self.openings,
            RowDomains::Original,
        )?;
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
        verify_opening(
            &self.dot.opening,
            &self.dot.root,
            &functional,
            sum,
            transcript,
        )?;
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
            verify_opening(&proof.opening, &proof.root, &functional, sum, transcript)?;
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
    domains: RowDomains,
) -> Result<()> {
    ensure!(
        openings.len() == code.queries && indices.len() == code.queries,
        "wrong opening count"
    );
    ensure!(
        indices.iter().all(|&i| i < code.codeword_len),
        "query outside codeword"
    );
    let tree = mmcs(domains);
    let cap = MerkleCap::new(vec![*root]);
    let dimensions = [Dimensions {
        width: width + SALT_FIELDS,
        height: code.codeword_len,
    }];
    for (&index, opening) in indices.iter().zip(openings) {
        ensure!(
            opening.rows.len() == 1 && opening.rows[0].len() == width,
            "wrong opened width"
        );
        ensure!(
            opening.path.0.len() == 1 && opening.path.0[0].len() == SALT_FIELDS,
            "wrong salt width"
        );
        ensure!(
            opening.path.1.len() == code.codeword_len.ilog2() as usize,
            "wrong Merkle path length"
        );
        let salted = [&opening.rows[0][..], &opening.path.0[0][..]].concat();
        tree.verify_batch(
            &cap,
            &dimensions,
            index,
            BatchOpeningRef::new(&[salted], &opening.path.1),
        )
        .map_err(|e| anyhow::anyhow!("invalid vector opening: {e:?}"))?;
    }
    Ok(())
}

fn mmcs(domains: RowDomains) -> Tree {
    let (leaf, node) = domains.tags();
    Tree::new(
        SerializingHasher::new(DomainHash(leaf)),
        CompressionFunctionFromHasher::new(DomainHash(node)),
        0,
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
