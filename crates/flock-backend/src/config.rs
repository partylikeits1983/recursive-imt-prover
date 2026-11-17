use crate::{
    encoding::{TableEncoding, committed_shapes},
    mixed::{MixedTraceCommitment, MixedTraceData},
};
use anyhow::{Result, ensure};
use p3_binary_field::{BinaryChallenger, Poly64, Poly192};
use p3_binary_pcs::whir::{
    BinaryWhirDomain, BooleanWhirData, BooleanWhirPcs, BooleanWhirProver, recommended_cap_height,
};
use p3_challenger::HashChallenger;
use p3_keccak::Keccak256Hash;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_multi_stark::config::MultiStarkConfig;
use p3_sumcheck::{
    TableShape,
    layout::{Table, plan_stacked_layout},
};
use p3_symmetric::{CompressionFunctionFromHasher, SerializingHasher};
use p3_whir::{FoldingFactor, ProtocolParameters, SecurityAssumption, WhirConfig};

type Hash = SerializingHasher<Keccak256Hash>;
type Compress = CompressionFunctionFromHasher<Keccak256Hash, 2, 32>;
pub type Mmcs = MerkleTreeMmcs<Poly64, u8, Hash, Compress, 2, 32>;
pub type Challenger = BinaryChallenger<Poly64, HashChallenger<u8, Keccak256Hash, 32>>;
type Bits = BooleanWhirPcs<Poly64, Poly192, BinaryWhirDomain<Poly64>, Mmcs, Challenger>;
type Pcs = MixedTraceCommitment<Poly192, Bits, Poly64>;
pub type Data = MixedTraceData<Poly64, BooleanWhirData<Poly64, Poly192, Mmcs>>;

pub struct Config {
    main: Pcs,
    preprocessed: Pcs,
    pub initial_codeword_cells: usize,
    pub main_codeword_cells: usize,
    pub preprocessed_codeword_cells: usize,
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
                .checked_shl((arity - 6 + 1) as u32)
                .ok_or_else(|| anyhow::anyhow!("codeword size overflow"))
        };
        let main_codeword_cells = cells(main, &main_encoding)?;
        let preprocessed_codeword_cells = cells(pp, &pp_encoding)?;
        let initial_codeword_cells = main_codeword_cells
            .checked_add(preprocessed_codeword_cells)
            .ok_or_else(|| anyhow::anyhow!("codeword budget overflow"))?;
        ensure!(
            initial_codeword_cells <= 1 << 30,
            "Flock initial codeword cells {initial_codeword_cells} exceed this prototype's 2^30 budget"
        );
        Ok(Self {
            main: pcs(main, main_encoding)?,
            preprocessed: pcs(pp, pp_encoding)?,
            initial_codeword_cells,
            main_codeword_cells,
            preprocessed_codeword_cells,
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
            folding_factor: FoldingFactor::Constant(4),
            soundness_type: SecurityAssumption::JohnsonBound,
            starting_log_inv_rate: 1,
        },
        &domain,
    )?;
    let cap = recommended_cap_height(&config);
    let mmcs = Mmcs::new(Hash::new(Keccak256Hash), Compress::new(Keccak256Hash), cap);
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
