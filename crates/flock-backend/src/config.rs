use crate::{
    encoding::{TableEncoding, committed_shapes},
    mixed::{MixedTraceCommitment, MixedTraceData},
};
use anyhow::{Result, ensure};
use p3_binary_field::{BinaryChallenger, Poly64, Poly192};
use p3_binary_pcs::whir::{BinaryWhirDomain, BooleanWhirData, BooleanWhirPcs, BooleanWhirProver};
use p3_challenger::HashChallenger;
use p3_keccak::Keccak256Hash;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_multi_stark::config::MultiStarkConfig;
use p3_sumcheck::{
    OpeningBatch, OpeningProtocol, PrescribedPointPcs, TableShape, TableSpec,
    layout::{Table, plan_stacked_layout},
};
use p3_symmetric::{CompressionFunctionFromHasher, SerializingHasher};
use p3_whir::{FoldingFactor, ProtocolParameters, SecurityAssumption, WhirConfig};

type Hash = SerializingHasher<Keccak256Hash>;
pub const WHIR_FOLD: usize = 4;
pub const WHIR_LOG_INV_RATE: usize = 2;
pub(crate) const RECURSIVE_PP_LOG_INV_RATE: usize = 1;
pub(crate) const TERMINAL_LOG_INV_RATE: usize = 4;
pub const WHIR_CAP_HEIGHT: usize = 0;
type Compress = CompressionFunctionFromHasher<Keccak256Hash, 2, 32>;
pub(crate) type Tree = MerkleTreeMmcs<Poly64, u8, Hash, Compress, 2, 32>;
#[cfg(not(feature = "opening-bench"))]
pub type Mmcs = Tree;
#[cfg(feature = "opening-bench")]
pub type Mmcs = crate::opening_trace::TraceTree;
pub type Challenger = BinaryChallenger<Poly64, HashChallenger<u8, Keccak256Hash, 32>>;
pub(crate) type NativeBits =
    BooleanWhirPcs<Poly64, Poly192, BinaryWhirDomain<Poly64>, Mmcs, Challenger>;
#[cfg(not(feature = "opening-bench"))]
type Bits = NativeBits;
#[cfg(feature = "opening-bench")]
type Bits = crate::terminal_opening::capture::CaptureBits;
pub(crate) type Pcs = MixedTraceCommitment<Poly192, Bits>;
pub type Data = MixedTraceData<Poly64, BooleanWhirData<Poly64, Poly192, Mmcs>>;

/// Initial row width is part of the committed Merkle leaf format. The paired
/// terminal witness uses 32 words per row alongside the fixed 16-word rows.
#[derive(Clone, Copy)]
pub(crate) struct MainCode {
    pub log_inv_rate: usize,
    pub first_fold: usize,
}

pub struct Config {
    pub(crate) main: Pcs,
    pub(crate) preprocessed: Pcs,
    pub(crate) auxiliary_tables: Vec<TableSpec>,
    pub(crate) joint_security: Option<p3_sumcheck::PrescribedOpeningSecurity>,
    pub initial_codeword_cells: usize,
    pub(crate) main_log_inv_rate: usize,
    pub main_codeword_cells: usize,
    pub preprocessed_codeword_cells: usize,
    pub main_log2_candidates: f64,
}

impl Config {
    pub fn with_boundary(
        main: &[TableShape],
        mut main_encoding: Vec<TableEncoding>,
        pp: &[TableShape],
        pp_encoding: Vec<TableEncoding>,
        pp_log_inv_rate: usize,
        log_batch: Option<usize>,
        main_code: MainCode,
    ) -> Result<Self> {
        let main_log_inv_rate = main_code.log_inv_rate;
        let mut shapes = main.to_vec();
        let extra = log_batch
            .map(crate::checkpoint_keccak::linked::boundary_specs)
            .unwrap_or_default();
        for spec in &extra {
            shapes.push(*spec.shape());
            main_encoding.push(TableEncoding::new(vec![1])?);
        }
        let cells = |shapes: &[TableShape], encoding: &[TableEncoding], log_inv_rate| {
            let (arity, _) = plan_stacked_layout(&committed_shapes(shapes, encoding));
            1usize
                .checked_shl((arity - 6 + log_inv_rate) as u32)
                .ok_or_else(|| anyhow::anyhow!("codeword size overflow"))
        };
        let main_codeword_cells = cells(&shapes, &main_encoding, main_log_inv_rate)?;
        let preprocessed_codeword_cells = cells(pp, &pp_encoding, pp_log_inv_rate)?;
        let initial_codeword_cells = main_codeword_cells
            .checked_add(preprocessed_codeword_cells)
            .ok_or_else(|| anyhow::anyhow!("codeword budget overflow"))?;
        ensure!(
            initial_codeword_cells <= 1 << 30,
            "binary initial codeword cells {initial_codeword_cells} exceed this prototype's 2^30 budget"
        );
        let main_pcs = pcs_with_code(&shapes, main_encoding, main_code)?;
        let protocol = OpeningProtocol::new(
            main.iter()
                .map(|&shape| {
                    TableSpec::new(
                        shape,
                        vec![OpeningBatch::new((0..shape.width()).collect(), vec![])],
                    )
                })
                .collect(),
        );
        let protocol = p3_multi_stark::auxiliary::append_protocol(protocol, &extra);
        let security = main_pcs
            .prescribed_security(&protocol)
            .ok_or_else(|| anyhow::anyhow!("missing main PCS candidate bound"))?;
        ensure!(
            security.candidates().is_some(),
            "invalid main PCS candidate bound"
        );
        Ok(Self {
            joint_security: log_batch.map(|_| security.clone()),
            main: main_pcs,
            auxiliary_tables: extra,
            preprocessed: pcs_with_rate(pp, pp_encoding, pp_log_inv_rate)?,
            initial_codeword_cells,
            main_log_inv_rate,
            main_codeword_cells,
            preprocessed_codeword_cells,
            main_log2_candidates: security.log2_max_candidates,
        })
    }
}

pub(crate) fn pcs(shapes: &[TableShape], encoding: Vec<TableEncoding>) -> Result<Pcs> {
    pcs_with_rate(shapes, encoding, WHIR_LOG_INV_RATE)
}

pub(crate) fn pcs_with_rate(
    shapes: &[TableShape],
    encoding: Vec<TableEncoding>,
    log_inv_rate: usize,
) -> Result<Pcs> {
    pcs_with_code(
        shapes,
        encoding,
        MainCode {
            log_inv_rate,
            first_fold: WHIR_FOLD,
        },
    )
}

fn pcs_with_code(
    shapes: &[TableShape],
    encoding: Vec<TableEncoding>,
    code: MainCode,
) -> Result<Pcs> {
    let (arity, _) = plan_stacked_layout(&committed_shapes(shapes, &encoding));
    let bits = native_bits(arity, code)?;
    #[cfg(feature = "opening-bench")]
    let bits = crate::terminal_opening::capture::CaptureBits(bits);
    Ok(MixedTraceCommitment::new(
        p3_binary_pcs::BooleanTraceCommitment::from_commitment(bits),
        encoding,
    ))
}

pub(crate) fn native_bits(arity: usize, code: MainCode) -> Result<NativeBits> {
    let domain = BinaryWhirDomain::default();
    let config = WhirConfig::<Poly192, Poly64, Challenger>::new_with_domain(
        arity - 6,
        ProtocolParameters {
            security_level: 152,
            pow_bits: 16,
            round_log_inv_rates: vec![],
            folding_factor: if code.first_fold == WHIR_FOLD {
                FoldingFactor::Constant(WHIR_FOLD)
            } else {
                FoldingFactor::ConstantFromSecondRound(code.first_fold, WHIR_FOLD)
            },
            soundness_type: SecurityAssumption::JohnsonBound,
            starting_log_inv_rate: code.log_inv_rate,
        },
        &domain,
    )?;
    let mmcs = merkle_tree();
    #[cfg(feature = "opening-bench")]
    let mmcs = crate::opening_trace::TraceTree(mmcs);
    Ok(BooleanWhirPcs::new(
        BooleanWhirProver::new(config, domain, mmcs),
        arity,
    )?)
}

impl MultiStarkConfig for Config {
    type Val = Poly64;
    type Challenge = Poly192;
    type Challenger = Challenger;
    type Pcs = Pcs;
    fn pcs(&self) -> &Pcs {
        &self.main
    }
    fn preprocessed_pcs(&self) -> &Pcs {
        &self.preprocessed
    }
    fn auxiliary_tables(&self) -> &[TableSpec] {
        &self.auxiliary_tables
    }
    fn collision_resistance_bits(&self) -> Option<usize> {
        Some(128)
    }
    fn min_num_variables(&self) -> usize {
        4
    }
    fn build_witness(&self, tables: Vec<Table<Poly64>>) -> Vec<Table<Poly64>> {
        tables
    }
    fn committed_table<'a>(&self, data: &'a Data, index: usize) -> &'a Table<Poly64> {
        data.table(index)
    }
}

pub(crate) fn merkle_tree() -> Tree {
    Tree::new(
        Hash::new(Keccak256Hash),
        Compress::new(Keccak256Hash),
        WHIR_CAP_HEIGHT,
    )
}

pub fn challenger(seed: &[u8]) -> Challenger {
    Challenger::from_hasher(seed.to_vec(), Keccak256Hash)
}
