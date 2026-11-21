//! A virtual first WHIR matrix, authenticated by independent witness and fixed roots.
//! All subsequent folded matrices use the ordinary singleton-cap Keccak tree.
use p3_maybe_rayon::prelude::*;
use std::{ops::Deref, sync::Arc};

use anyhow::{Result, ensure};
use p3_commit::{BatchOpening, BatchOpeningRef, Mmcs, MmcsProofGeometry};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::{Dimensions, Matrix};
use p3_symmetric::MerkleCap;

use crate::{F, config::Tree};

type Cap = <Tree as Mmcs<F>>::Commitment;
type Paths = <Tree as Mmcs<F>>::MultiProof;
type TreeData<M> = <Tree as Mmcs<F>>::ProverData<M>;

#[derive(Clone)]
pub(super) struct PairedTree {
    pub(super) tree: crate::config::Mmcs,
    pub(super) first: Dimensions,
    pub(super) fixed_root: [u8; 32],
}

// Retain the full logical matrix once. Each ordinary tree sees its own range
// of columns in exactly the order used by the stand-alone commitment.
pub(super) struct Columns<M> {
    matrix: Arc<M>,
    start: usize,
    width: usize,
}

impl<M: Matrix<F>> Matrix<F> for Columns<M> {
    fn width(&self) -> usize {
        self.width
    }

    fn height(&self) -> usize {
        self.matrix.height()
    }

    unsafe fn row_subslice_unchecked(
        &self,
        row: usize,
        start: usize,
        end: usize,
    ) -> impl Deref<Target = [F]> {
        // SAFETY: the caller bounds the subslice in this view, which lies inside the matrix.
        unsafe {
            self.matrix
                .row_subslice_unchecked(row, self.start + start, self.start + end)
        }
    }

    unsafe fn row_unchecked(
        &self,
        row: usize,
    ) -> impl IntoIterator<Item = F, IntoIter = impl Iterator<Item = F> + Send + Sync> {
        // SAFETY: the caller bounds the row and the constructor bounds this column range.
        unsafe {
            self.matrix
                .row_subseq_unchecked(row, self.start, self.start + self.width)
        }
    }
}

pub(super) enum OracleData<M> {
    Ordinary(TreeData<M>),
    Paired {
        matrix: Arc<M>,
        halves: [TreeData<Columns<M>>; 2],
    },
}

impl Mmcs<F> for PairedTree {
    type ProverData<M> = OracleData<M>;
    type Commitment = Cap;
    type Proof = Vec<Paths>;
    type MultiProof = Vec<Paths>;
    type Error = anyhow::Error;

    fn proof_geometry(&self, log_height: usize) -> Option<MmcsProofGeometry> {
        if log_height == self.first.height.ilog2() as usize {
            return Some(MmcsProofGeometry::new(2, 2 * log_height));
        }
        self.tree.proof_geometry(log_height)
    }

    fn commit<M: Matrix<F>>(&self, mut inputs: Vec<M>) -> (Cap, OracleData<M>) {
        if inputs.len() != 1 || inputs[0].dimensions() != self.first {
            let (cap, data) = self.tree.commit(inputs);
            return (cap, OracleData::Ordinary(data));
        }
        let matrix = Arc::new(inputs.pop().unwrap());
        let witness = self.first.width / 2;
        let fixed = witness / 2;
        assert!((0..self.first.height).into_par_iter().all(|i| {
            // SAFETY: i is in range and the initial matrix has exactly self.first.width columns.
            let pad =
                unsafe { matrix.row_subslice_unchecked(i, witness + fixed, self.first.width) };
            pad.iter().all(|&x| x == F::ZERO)
        }));
        let commit = |start, width| {
            self.tree.commit_matrix(Columns {
                matrix: Arc::clone(&matrix),
                start,
                width,
            })
        };
        let (m, main_data) = commit(0, witness);
        let (p, fixed_data) = commit(witness, fixed);
        (
            MerkleCap::new(vec![m[0], p[0]]),
            OracleData::Paired {
                matrix,
                halves: [main_data, fixed_data],
            },
        )
    }

    fn get_matrices<'a, M: Matrix<F>>(&self, data: &'a OracleData<M>) -> Vec<&'a M> {
        match data {
            OracleData::Ordinary(d) => self.tree.get_matrices(d),
            OracleData::Paired { matrix, .. } => vec![matrix.as_ref()],
        }
    }

    fn open_batch<M: Matrix<F>>(
        &self,
        index: usize,
        data: &OracleData<M>,
    ) -> BatchOpening<F, Self> {
        let (mut rows, proof) = self.open_multi_batch(&[index], data);
        BatchOpening::new(rows.remove(0), proof)
    }

    fn verify_batch(
        &self,
        cap: &Cap,
        dims: &[Dimensions],
        index: usize,
        proof: BatchOpeningRef<'_, F, Self>,
    ) -> Result<()> {
        self.verify_multi_batch(
            cap,
            dims,
            &[index],
            &[proof.opened_values.to_vec()],
            proof.opening_proof,
        )
    }

    fn open_multi_batch<M: Matrix<F>>(
        &self,
        indices: &[usize],
        data: &OracleData<M>,
    ) -> (Vec<Vec<Vec<F>>>, Vec<Paths>) {
        match data {
            OracleData::Ordinary(d) => {
                let (rows, path) = self.tree.open_multi_batch(indices, d);
                (rows, vec![path])
            }
            OracleData::Paired { halves, .. } => {
                let (mut left, lp) = self.tree.open_multi_batch(indices, &halves[0]);
                let (right, rp) = self.tree.open_multi_batch(indices, &halves[1]);
                for (a, b) in left.iter_mut().zip(right) {
                    a[0].extend_from_slice(&b[0]);
                    a[0].resize(self.first.width, F::ZERO);
                }
                (left, vec![lp, rp])
            }
        }
    }

    fn verify_multi_batch<R: AsRef<[F]> + PartialEq>(
        &self,
        cap: &Cap,
        dims: &[Dimensions],
        indices: &[usize],
        values: &[Vec<R>],
        proofs: &Vec<Paths>,
    ) -> Result<()> {
        if dims != [self.first] {
            ensure!(
                cap.num_roots() == 1 && proofs.len() == 1,
                "invalid folded oracle shape"
            );
            return self
                .tree
                .verify_multi_batch(cap, dims, indices, values, &proofs[0])
                .map_err(|e| anyhow::anyhow!("{e:?}"));
        }
        ensure!(
            cap.num_roots() == 2 && cap[1] == self.fixed_root && proofs.len() == 2,
            "invalid initial oracle authority"
        );
        ensure!(
            values.len() == indices.len() && !indices.is_empty(),
            "invalid initial query count"
        );
        let witness = self.first.width / 2;
        let fixed = witness / 2;
        let mut main_rows = Vec::with_capacity(indices.len());
        let mut fixed_rows = Vec::with_capacity(indices.len());
        for row in values {
            ensure!(row.len() == 1, "invalid matrix count");
            let words = row[0].as_ref();
            ensure!(
                words.len() == self.first.width
                    && words[witness + fixed..].iter().all(|&x| x == F::ZERO),
                "invalid virtual row"
            );
            main_rows.push(vec![&words[..witness]]);
            fixed_rows.push(vec![&words[witness..witness + fixed]]);
        }
        for (i, (width, rows)) in [(witness, main_rows), (fixed, fixed_rows)]
            .into_iter()
            .enumerate()
        {
            let shape = Dimensions {
                width,
                height: self.first.height,
            };
            self.tree
                .verify_multi_batch(
                    &MerkleCap::new(vec![cap[i]]),
                    &[shape],
                    indices,
                    &rows,
                    &proofs[i],
                )
                .map_err(|e| anyhow::anyhow!("{e:?}"))?;
        }
        Ok(())
    }
}
