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
pub const WHIR_CAP_HEIGHT: usize = 0;
type Compress = CompressionFunctionFromHasher<Keccak256Hash, 2, 32>;
pub type Mmcs = MerkleTreeMmcs<Poly64, u8, Hash, Compress, 2, 32>;
pub type Challenger = BinaryChallenger<Poly64, HashChallenger<u8, Keccak256Hash, 32>>;
type Bits = BooleanWhirPcs<Poly64, Poly192, BinaryWhirDomain<Poly64>, Mmcs, Challenger>;
pub(crate) type Pcs = MixedTraceCommitment<Poly192, Bits>;
pub type Data = MixedTraceData<Poly64, BooleanWhirData<Poly64, Poly192, Mmcs>>;

pub struct Config {
    main: Pcs,
    preprocessed: Pcs,
    pub initial_codeword_cells: usize,
    pub main_codeword_cells: usize,
    pub preprocessed_codeword_cells: usize,
    pub main_log2_candidates: f64,
}

impl Config {
    pub fn new(
        main: &[TableShape],
        main_encoding: Vec<TableEncoding>,
        pp: &[TableShape],
        pp_encoding: Vec<TableEncoding>,
    ) -> Result<Self> {
        let cells = |shapes: &[TableShape], encoding: &[TableEncoding]| {
            let (arity, _) = plan_stacked_layout(&committed_shapes(shapes, encoding));
            1usize
                .checked_shl((arity - 6 + WHIR_LOG_INV_RATE) as u32)
                .ok_or_else(|| anyhow::anyhow!("codeword size overflow"))
        };
        let main_codeword_cells = cells(main, &main_encoding)?;
        let preprocessed_codeword_cells = cells(pp, &pp_encoding)?;
        let initial_codeword_cells = main_codeword_cells
            .checked_add(preprocessed_codeword_cells)
            .ok_or_else(|| anyhow::anyhow!("codeword budget overflow"))?;
        ensure!(
            initial_codeword_cells <= 1 << 30,
            "binary initial codeword cells {initial_codeword_cells} exceed this prototype's 2^30 budget"
        );
        let main_pcs = pcs(main, main_encoding)?;
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
        let security = main_pcs
            .prescribed_security(&protocol)
            .ok_or_else(|| anyhow::anyhow!("missing main PCS candidate bound"))?;
        ensure!(
            security.candidates().is_some(),
            "invalid main PCS candidate bound"
        );
        Ok(Self {
            main: main_pcs,
            preprocessed: pcs(pp, pp_encoding)?,
            initial_codeword_cells,
            main_codeword_cells,
            preprocessed_codeword_cells,
            main_log2_candidates: security.log2_max_candidates,
        })
    }
}

pub(crate) fn pcs(shapes: &[TableShape], encoding: Vec<TableEncoding>) -> Result<Pcs> {
    let (arity, _) = plan_stacked_layout(&committed_shapes(shapes, &encoding));
    let domain = BinaryWhirDomain::default();
    let config = WhirConfig::<Poly192, Poly64, Challenger>::new_with_domain(
        arity - 6,
        ProtocolParameters {
            security_level: 152,
            pow_bits: 16,
            round_log_inv_rates: vec![],
            folding_factor: FoldingFactor::Constant(WHIR_FOLD),
            soundness_type: SecurityAssumption::JohnsonBound,
            starting_log_inv_rate: WHIR_LOG_INV_RATE,
        },
        &domain,
    )?;
    let mmcs = Mmcs::new(
        Hash::new(Keccak256Hash),
        Compress::new(Keccak256Hash),
        WHIR_CAP_HEIGHT,
    );
    let bits = BooleanWhirPcs::new(BooleanWhirProver::new(config, domain, mmcs), arity)?;
    Ok(MixedTraceCommitment::new(
        p3_binary_pcs::BooleanTraceCommitment::from_commitment(bits),
        encoding,
    ))
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

pub fn challenger(seed: &[u8]) -> Challenger {
    Challenger::from_hasher(seed.to_vec(), Keccak256Hash)
}
