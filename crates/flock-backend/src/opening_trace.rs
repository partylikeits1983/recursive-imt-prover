//! Capture authenticated Merkle queries from a synchronous native verification for differential tests.
use std::cell::RefCell;

use anyhow::{Result, ensure};
use p3_binary_field::{Poly64, Poly192};
use p3_challenger::CanObserve;
use p3_commit::{BatchOpening, BatchOpeningRef, Mmcs, MmcsProofGeometry, RowSink};
use p3_matrix::{Dimensions, Matrix, dense::RowMajorMatrix};
use serde::Serialize;

use crate::config::Tree;

mod arithmetic;
mod arithmetic_key;
pub(crate) use arithmetic::record_arithmetic;

#[derive(Serialize)]
pub struct VerifiedOpening {
    pub roots: Vec<[u8; 32]>,
    pub dimensions: Vec<(usize, usize)>,
    pub indices: Vec<usize>,
    /// Base-field coefficients in hash order, eight little-endian bytes each.
    pub rows: Vec<String>,
    pub siblings: Vec<[u8; 32]>,
}

struct CapturedCap {
    root: [u8; 32],
    nodes: Vec<[u8; 32]>,
}

thread_local! {
    static OPENINGS: RefCell<Option<VerifiedTrace>> = const { RefCell::new(None) };
    static FIXED_CAP: RefCell<Option<Vec<CapturedCap>>> = const { RefCell::new(None) };
}

/// Export reusable public preprocessing for the shared terminal geometry.
/// The caller independently derives the setup root; select only the tree with that root.
pub fn fixed_wiring_cap(setup_root: impl FnOnce() -> Result<[u8; 32]>) -> Result<Vec<[u8; 32]>> {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            FIXED_CAP.take();
        }
    }
    ensure!(
        FIXED_CAP.with_borrow(Option::is_none),
        "nested fixed-cap capture"
    );
    FIXED_CAP.set(Some(Vec::new()));
    let _reset = Reset;
    let root = setup_root()?;
    FIXED_CAP
        .take()
        .unwrap()
        .into_iter()
        .find_map(|cap| (cap.root == root).then_some(cap.nodes))
        .ok_or_else(|| anyhow::anyhow!("trusted fixed wiring tree was not committed during setup"))
}

fn record_fixed_cap<M: Matrix<Poly64>>(
    result: &(
        <Tree as Mmcs<Poly64>>::Commitment,
        <Tree as Mmcs<Poly64>>::ProverData<M>,
    ),
    dimensions: Option<Dimensions>,
) {
    if dimensions
        != Some(Dimensions {
            width: 16,
            height: 1 << 24,
        })
    {
        return;
    }
    FIXED_CAP.with_borrow_mut(|slot| {
        if let Some(trees) = slot {
            trees.push(CapturedCap {
                root: result.0[0],
                nodes: result.1.cap(12).roots().to_vec(),
            });
        }
    });
}

#[derive(Serialize, Default)]
pub struct VerifiedTrace {
    pub openings: Vec<VerifiedOpening>,
    pub linked_prefix: Option<LinkedPrefix>,
    pub linked_closing: Option<LinkedClosing>,
    pub arithmetic_prefix: Option<arithmetic::ArithmeticPrefix>,
    pub shared_algebraic_bits: Option<f64>,
    pub security_sweep: Option<Vec<SecurityEstimate>>,
    #[serde(skip)]
    search: Option<SecuritySearch>,
    pub selected_parameters: Option<SecurityEstimate>,
    pub shared_bit_batch: Option<crate::terminal_opening::BatchTrace>,
    pub chi_cubics: Vec<String>,
    pub chi_layers: Vec<ChiLayer>,
}

/// Search the supported local budgets in ascending order at a fixed grinding cap.
#[derive(Clone, Copy)]
pub struct SecuritySearch {
    pub conditional_bits: u32,
    pub max_grinding_bits: usize,
}

#[derive(Serialize)]
pub struct SecurityEstimate {
    local_whir_bits: usize,
    max_grinding_bits: usize,
    terminal_conditional_algebraic_bits: f64,
    queries_per_site: Vec<usize>,
}

#[derive(Serialize)]
pub struct LinkedClosing {
    arithmetic_point: String,
    bridge_row: String,
    wires: [String; 2],
    domains: [String; 2],
    points: Vec<String>,
    evaluations: String,
}

pub(crate) fn record_linked_closing(
    arithmetic_point: &[Poly192],
    row: &[Poly192],
    proofs: [&p3_sumcheck::generic_degree::GenericDegreeProof<Poly64, Poly192>; 2],
    points: &[p3_multilinear_util::point::Point<Poly192>],
    evals: &[p3_sumcheck::OpeningBatch<Poly192>],
) {
    struct Seed(Vec<u8>);
    impl CanObserve<Poly64> for Seed {
        fn observe(&mut self, word: Poly64) {
            self.0.extend(word.to_bits().to_le_bytes());
        }
    }
    OPENINGS.with_borrow_mut(|slot| {
        if let Some(trace) = slot {
            trace.linked_closing = Some(LinkedClosing {
                arithmetic_point: encode(arithmetic_point.iter().copied()),
                bridge_row: encode(row.iter().copied()),
                wires: proofs.map(|p| {
                    encode(
                        [p.claimed_sum]
                            .into_iter()
                            .chain(p.round_polys.iter().flatten().copied()),
                    )
                }),
                domains: proofs.map(|p| {
                    let mut seed = Seed(vec![]);
                    p3_sumcheck::generic_degree::GenericDegreeShape::new(p.num_rounds(), 2, 0)
                        .domain_separator::<Poly64, Poly192>()
                        .seed(&mut seed);
                    hex::encode(seed.0)
                }),
                points: points
                    .iter()
                    .map(|p| encode(p.as_slice().iter().copied()))
                    .collect(),
                evaluations: encode(evals.iter().map(|v| v.current()[0])),
            });
        }
    });
}

#[derive(Serialize)]
pub struct ChiLayer {
    wire: String,
    beta: String,
    value: String,
}

fn encode(values: impl IntoIterator<Item = Poly192>) -> String {
    hex::encode(
        values
            .into_iter()
            .flat_map(|v| v.coefficients())
            .flat_map(|c| c.to_bits().to_le_bytes())
            .collect::<Vec<_>>(),
    )
}

/// Isolate native field work. Challenge derivation and the endpoint identity
/// have already passed in the caller, and the enclosing verification must succeed.
pub(crate) fn record_chi_cubic(
    proof: &p3_sumcheck::generic_degree::GenericDegreeProof<Poly64, Poly192>,
    point: &[Poly192],
    end: Poly192,
    coefficients: &[Poly192],
    values: [Poly192; 3],
    beta: Poly192,
    next_value: Poly192,
) {
    OPENINGS.with_borrow_mut(|slot| {
        if let Some(trace) = slot {
            trace.chi_layers.push(ChiLayer {
                wire: encode(
                    coefficients
                        .iter()
                        .copied()
                        .chain([proof.claimed_sum])
                        .chain(proof.round_polys.iter().flatten().copied())
                        .chain(values),
                ),
                beta: encode([beta]),
                value: encode([next_value]),
            });
            let words = proof
                .round_polys
                .iter()
                .zip(point)
                .flat_map(|(coeffs, r)| coeffs.iter().chain([r]).copied());
            trace.chi_cubics.push(encode(
                [proof.claimed_sum].into_iter().chain(words).chain([end]),
            ));
        }
    });
}

#[derive(Serialize)]
pub struct LinkedPrefix {
    authority: String,
    cap: String,
    commitment_separator: String,
    bridge: String,
    output: String,
    coefficients: String,
    midpoint: Option<String>,
    output_point: String,
    first_sum: String,
    cubic_separator: String,
    round_polys: String,
    chi_values: String,
}

pub(crate) fn record_linked_prefix(
    authority: &[u8],
    cap: &[u8; 32],
    ports: &crate::checkpoint_keccak::linked::PortOpening,
    claims: &crate::checkpoint_keccak::linked::LinkedClaims,
    coefficients: &[Poly192],
    point: &[Poly192],
    middle: Option<Poly192>,
) {
    struct Seed(Vec<u8>);
    impl CanObserve<Poly64> for Seed {
        fn observe(&mut self, word: Poly64) {
            self.0.extend(word.to_bits().to_le_bytes());
        }
    }
    OPENINGS.with_borrow_mut(|slot| {
        if let Some(trace) = slot {
            let mut seed = Seed(vec![]);
            p3_sumcheck::layout::commitment_domain_separator::<Poly64>().seed(&mut seed);
            let (output, cubic, values) = claims.first_round();
            let mut cubic_seed = Seed(vec![]);
            p3_sumcheck::generic_degree::GenericDegreeShape::new(cubic.num_rounds(), 3, 0)
                .domain_separator::<Poly64, Poly192>()
                .seed(&mut cubic_seed);
            trace.linked_prefix = Some(LinkedPrefix {
                authority: hex::encode(authority),
                cap: hex::encode(cap),
                commitment_separator: hex::encode(seed.0),
                bridge: encode(ports.instance.iter().chain(&ports.values).copied()),
                output: encode([output]),
                coefficients: encode(coefficients.iter().copied()),
                output_point: encode(point.iter().copied()),
                midpoint: middle.map(|m| encode([m])),
                first_sum: encode([cubic.claimed_sum]),
                cubic_separator: hex::encode(cubic_seed.0),
                round_polys: encode(cubic.round_polys.iter().flatten().copied()),
                chi_values: encode(values),
            });
        }
    });
}

/// Return the recorded queries only after the supplied native verification succeeds.
pub(crate) fn record_shared_security(bits: f64) {
    OPENINGS.with_borrow_mut(|slot| {
        if let Some(trace) = slot {
            trace.shared_algebraic_bits = Some(bits);
        }
    });
}

/// Assess the same statement and key with alternative WHIR parameters. Only
/// the actual protocol configured by the key gets to verify the proof.
pub(crate) fn record_security_sweep(
    assess: impl Fn(usize, usize) -> Result<(f64, Vec<usize>)>,
) -> Result<()> {
    OPENINGS.with_borrow_mut(|slot| {
        let Some(trace) = slot.as_mut() else {
            return Ok(());
        };
        if let Some(search) = trace.search {
            ensure!(
                (16..=17).contains(&search.max_grinding_bits),
                "supported search grinding caps are 16 and 17"
            );
            for local in 120..=152 {
                let (bits, queries_per_site) = assess(local, search.max_grinding_bits)?;
                if bits >= f64::from(search.conditional_bits) {
                    trace.selected_parameters = Some(SecurityEstimate {
                        local_whir_bits: local,
                        max_grinding_bits: search.max_grinding_bits,
                        terminal_conditional_algebraic_bits: bits,
                        queries_per_site,
                    });
                    break;
                }
            }
            ensure!(
                trace.selected_parameters.is_some(),
                "no supported local budget reaches the requested conditional floor"
            );
        }
        if let Some(rows) = trace.security_sweep.as_mut() {
            for (bits, grind) in [
                (125, 17),
                (128, 16),
                (128, 20),
                (130, 16),
                (130, 17),
                (131, 16),
                (131, 17),
                (132, 16),
                (132, 17),
                (133, 16),
                (133, 17),
                (134, 16),
                (134, 17),
                (135, 16),
                (144, 16),
                (149, 16),
                (150, 16),
                (151, 16),
                (152, 16),
                (152, 20),
            ] {
                let (bound, queries_per_site) = assess(bits, grind)?;
                rows.push(SecurityEstimate {
                    local_whir_bits: bits,
                    max_grinding_bits: grind,
                    terminal_conditional_algebraic_bits: bound,
                    queries_per_site,
                });
            }
        }
        Ok(())
    })
}
pub(crate) fn record_bit_batch(make: impl FnOnce() -> crate::terminal_opening::BatchTrace) {
    OPENINGS.with_borrow_mut(|slot| {
        if let Some(trace) = slot {
            trace.shared_bit_batch = Some(make());
        }
    });
}

pub fn capture(verify: impl FnOnce() -> Result<()>) -> Result<VerifiedTrace> {
    capture_with_security_sweep(false, verify)
}

pub fn capture_with_security_sweep(
    sweep: bool,
    verify: impl FnOnce() -> Result<()>,
) -> Result<VerifiedTrace> {
    capture_with_search(sweep, None, verify)
}

pub fn capture_with_search(
    sweep: bool,
    search: Option<SecuritySearch>,
    verify: impl FnOnce() -> Result<()>,
) -> Result<VerifiedTrace> {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            OPENINGS.take();
        }
    }
    ensure!(
        OPENINGS.with_borrow(Option::is_none),
        "nested opening capture"
    );
    OPENINGS.set(Some(VerifiedTrace {
        security_sweep: sweep.then(Vec::new),
        search,
        ..Default::default()
    }));
    let _reset = Reset;
    verify()?;
    Ok(OPENINGS.take().unwrap())
}

#[derive(Clone)]
pub struct TraceTree(pub(crate) Tree);

impl Mmcs<Poly64> for TraceTree {
    type ProverData<M> = <Tree as Mmcs<Poly64>>::ProverData<M>;
    type Commitment = <Tree as Mmcs<Poly64>>::Commitment;
    type Proof = <Tree as Mmcs<Poly64>>::Proof;
    type MultiProof = <Tree as Mmcs<Poly64>>::MultiProof;
    type Error = <Tree as Mmcs<Poly64>>::Error;

    fn proof_geometry(&self, log_height: usize) -> Option<MmcsProofGeometry> {
        self.0.proof_geometry(log_height)
    }
    fn commit<M: Matrix<Poly64>>(&self, inputs: Vec<M>) -> (Self::Commitment, Self::ProverData<M>) {
        let dims = inputs
            .first()
            .filter(|_| inputs.len() == 1)
            .map(Matrix::dimensions);
        let result = self.0.commit(inputs);
        record_fixed_cap(&result, dims);
        result
    }
    fn commit_matrix_streamed<Fill>(
        &self,
        dimensions: Dimensions,
        fill: Fill,
    ) -> (Self::Commitment, Self::ProverData<RowMajorMatrix<Poly64>>)
    where
        Fill: FnOnce(&RowSink<'_, Poly64>) -> RowMajorMatrix<Poly64>,
    {
        let result = self.0.commit_matrix_streamed(dimensions, fill);
        record_fixed_cap(&result, Some(dimensions));
        result
    }
    fn get_matrices<'a, M: Matrix<Poly64>>(&self, data: &'a Self::ProverData<M>) -> Vec<&'a M> {
        self.0.get_matrices(data)
    }
    fn open_batch<M: Matrix<Poly64>>(
        &self,
        index: usize,
        data: &Self::ProverData<M>,
    ) -> BatchOpening<Poly64, Self> {
        let (rows, path) = self.0.open_batch(index, data).unpack();
        BatchOpening::new(rows, path)
    }
    fn verify_batch(
        &self,
        root: &Self::Commitment,
        dims: &[Dimensions],
        index: usize,
        opening: BatchOpeningRef<'_, Poly64, Self>,
    ) -> Result<(), Self::Error> {
        self.0.verify_batch(
            root,
            dims,
            index,
            BatchOpeningRef::new(opening.opened_values, opening.opening_proof),
        )
    }
    fn open_multi_batch<M: Matrix<Poly64>>(
        &self,
        indices: &[usize],
        data: &Self::ProverData<M>,
    ) -> (Vec<Vec<Vec<Poly64>>>, Self::MultiProof) {
        self.0.open_multi_batch(indices, data)
    }
    fn verify_multi_batch<R: AsRef<[Poly64]> + PartialEq>(
        &self,
        cap: &Self::Commitment,
        dims: &[Dimensions],
        indices: &[usize],
        values: &[Vec<R>],
        proof: &Self::MultiProof,
    ) -> Result<(), Self::Error> {
        self.0
            .verify_multi_batch(cap, dims, indices, values, proof)?;
        OPENINGS.with_borrow_mut(|slot| {
            if let Some(calls) = slot {
                calls.openings.push(VerifiedOpening {
                    roots: cap.roots().to_vec(),
                    dimensions: dims.iter().map(|d| (d.width, d.height)).collect(),
                    indices: indices.to_vec(),
                    rows: values
                        .iter()
                        .map(|mats| {
                            let bytes: Vec<_> = mats
                                .iter()
                                .flat_map(|row| row.as_ref())
                                .flat_map(|v| v.to_bits().to_le_bytes())
                                .collect();
                            hex::encode(bytes)
                        })
                        .collect(),
                    siblings: proof.sibling_hashes.clone(),
                });
            }
        });
        Ok(())
    }
}
