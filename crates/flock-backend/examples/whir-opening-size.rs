//! Estimate the wire cost of plain Poly64 WHIR openings before building a terminal key.
//! Pass the stacked arities to compare, e.g. 25 24 (packed) or 29 27 (whole words).
use anyhow::{Result, ensure};
use p3_binary_field::{BinaryChallenger, Poly64, Poly192};
use p3_binary_pcs::whir::BinaryWhirDomain;
use p3_challenger::HashChallenger;
use p3_keccak::Keccak256Hash;
use p3_whir::{
    FoldingFactor, ProtocolParameters, SecurityAssumption, WhirConfig, transcript::WhirShape,
};

type Challenger = BinaryChallenger<Poly64, HashChallenger<u8, Keccak256Hash, 32>>;

/// Expected occupied nodes in a layer of the stratified query tree. For a group with
/// 2^s queries, each depth-d node has one possible draw in its enclosing stratum
/// when d > s. Different groups draw independently in the random-oracle model.
fn occupied(depth: usize, strata: &[usize]) -> f64 {
    let width = (1u64 << depth) as f64;
    if strata.is_empty() || strata.iter().any(|&s| s >= depth) {
        return width; // zero draws enumerate the full domain
    }
    let log_empty: f64 = strata
        .iter()
        .map(|&s| (-((1u64 << s) as f64) / width).ln_1p())
        .sum();
    -width * log_empty.exp_m1()
}

/// Wire data that depends directly on the proximity-query schedule. The two
/// caps of the shared terminal opening authenticate the same first-round indices.
fn query_cost(
    shape: &WhirShape,
    config: &WhirConfig<Poly192, Poly64, Challenger>,
    shared: bool,
) -> (f64, f64) {
    let sites = shape
        .rounds
        .iter()
        .map(|r| (r.index_bits, &r.query_summand_depths))
        .chain([(shape.final_index_bits, &shape.final_query_summand_depths)]);
    let mut rows = 0.0;
    let mut hashes = 0.0;
    for (site, (height, strata)) in sites.enumerate() {
        let mut parents = 1.0;
        let mut siblings = 0.0;
        for depth in 1..=height {
            let children = occupied(depth, strata);
            siblings += 2.0 * parents - children;
            parents = children;
        }
        let paired = site == 0 && shared;
        let width = if paired {
            48
        } else {
            1 << config.round_folding_factor(site)
        };
        rows += parents * (width * if site == 0 { 8 } else { 24 }) as f64;
        hashes += (if paired { 64.0 } else { 32.0 }) * siblings;
    }
    (rows, hashes)
}

fn compare_shared_security(later_fold: usize) -> Result<()> {
    println!("target_bits,max_pow_bits,queries_per_site,expected_row_bytes,expected_sibling_bytes");
    for (bits, pow_bits) in [
        (152, 16),
        (152, 20),
        (151, 16),
        (150, 16),
        (149, 16),
        (144, 16),
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
        (128, 16),
        (128, 20),
        (125, 16),
        (125, 17),
    ] {
        let params = ProtocolParameters {
            security_level: bits,
            pow_bits,
            starting_log_inv_rate: 4,
            round_log_inv_rates: if later_fold == 4 {
                vec![8, 11, 14, 17]
            } else {
                vec![]
            },
            folding_factor: FoldingFactor::ConstantFromSecondRound(6, later_fold),
            soundness_type: SecurityAssumption::JohnsonBound,
        };
        let config = WhirConfig::<Poly192, Poly64, Challenger>::new_with_domain(
            26,
            params,
            &BinaryWhirDomain::<Poly64>::default(),
        )?;
        ensure!(config.check_pow_bits(), "invalid grinding schedule");
        let shape = WhirShape::new(&config, 0);
        ensure!(
            shape.stratified_queries,
            "expected stratified terminal domain"
        );
        let (rows, siblings) = query_cost(&shape, &config, true);
        let draws = shape
            .rounds
            .iter()
            .map(|r| r.query_draws)
            .chain([shape.final_query_draws])
            .map(|n| n.to_string())
            .collect::<Vec<_>>()
            .join("+");
        println!("{bits},{pow_bits},{draws},{rows:.0},{siblings:.0}");
    }
    Ok(())
}

/// Compare folded codewords while preserving both initial commitments, the
/// native 152-bit per-term target, and the 16-bit grinding budget. The two
/// contraction parameters give the log decrease in RS domain size after the
/// first fold and each later fold. The report excludes the unaffected initial
/// codeword, and counts extension cells before their packing into base words.
fn compare_shared_schedules() -> Result<()> {
    println!(
        "later_fold,first_contraction,later_contraction,folded_ext_cells,expected_packed_whir_bytes,queries"
    );
    for later in 2..=6 {
        let folding = FoldingFactor::ConstantFromSecondRound(6, later);
        let factors = folding.compute_folding_schedule(26)?;
        for initial_drop in 0..=5 {
            for later_drop in 0..=3 {
                let mut rate = 4usize;
                let rates = factors[..factors.len() - 1]
                    .iter()
                    .enumerate()
                    .map(|(i, &k)| {
                        rate = (rate + k)
                            .saturating_sub(if i == 0 { initial_drop } else { later_drop })
                            .max(1);
                        rate
                    })
                    .collect();
                let params = ProtocolParameters {
                    security_level: 152,
                    pow_bits: 16,
                    starting_log_inv_rate: 4,
                    round_log_inv_rates: rates,
                    folding_factor: folding.clone(),
                    soundness_type: SecurityAssumption::JohnsonBound,
                };
                let Ok(config) = WhirConfig::<Poly192, Poly64, Challenger>::new_with_domain(
                    26,
                    params,
                    &BinaryWhirDomain::<Poly64>::default(),
                ) else {
                    continue;
                };
                if !config.check_pow_bits() {
                    continue;
                }
                let shape = WhirShape::new(&config, 0);
                let (rows, paths) = query_cost(&shape, &config, true);
                let cells: usize = config
                    .round_parameters()
                    .iter()
                    .map(|r| 1usize << (r.num_variables + r.log_inv_rate))
                    .sum();
                let mut fixed = 24 * (shape.final_poly_len + config.commitment_ood_samples());
                fixed += 6 * 56 + config.final_sumcheck_rounds() * 48 + 8;
                for (i, r) in config.round_parameters().iter().enumerate() {
                    fixed += 32
                        + 24 * r.ood_samples
                        + 8
                        + config.round_folding_factor(i + 1)
                            * (48 + if r.folding_pow_bits == 0 { 0 } else { 8 });
                }
                let bytes = rows + paths + fixed as f64;
                let queries = shape
                    .rounds
                    .iter()
                    .map(|r| r.query_draws)
                    .chain([shape.final_query_draws])
                    .map(|q| q.to_string())
                    .collect::<Vec<_>>()
                    .join("+");
                println!("{later},{initial_drop},{later_drop},{cells},{bytes:.0},{queries}");
            }
        }
    }
    Ok(())
}

fn main() -> Result<()> {
    if std::env::args().skip(1).eq(["--shared-security"]) {
        return compare_shared_security(3);
    }
    if std::env::args().skip(1).eq(["--shared-security-four"]) {
        return compare_shared_security(4);
    }
    if std::env::args().skip(1).eq(["--shared-schedules"]) {
        return compare_shared_schedules();
    }
    let arities = std::env::args()
        .skip(1)
        .map(|a| a.parse())
        .collect::<Result<Vec<usize>, _>>()?;
    ensure!(!arities.is_empty(), "supply stacked polynomial arities");
    println!(
        "variables,log_inv_rate,first_fold,later_fold,initial_cells,expected_row_bytes,expected_sibling_bytes,final_poly_bytes"
    );
    for variables in arities {
        ensure!(
            (8..=40).contains(&variables),
            "arity must be between 8 and 40"
        );
        for rate in 1..=8 {
            for first in 1..=6 {
                for later in 2..=6 {
                    let params = ProtocolParameters {
                        security_level: 152,
                        pow_bits: 16,
                        starting_log_inv_rate: rate,
                        round_log_inv_rates: vec![],
                        folding_factor: FoldingFactor::ConstantFromSecondRound(first, later),
                        soundness_type: SecurityAssumption::JohnsonBound,
                    };
                    let Ok(config) = WhirConfig::<Poly192, Poly64, Challenger>::new_with_domain(
                        variables,
                        params,
                        &BinaryWhirDomain::<Poly64>::default(),
                    ) else {
                        continue;
                    };
                    if !config.check_pow_bits() {
                        continue;
                    }
                    // The prescribed reading count does not enter query geometry.
                    let shape = WhirShape::new(&config, 1);
                    ensure!(shape.stratified_queries, "expected stratified domain");
                    let (row_bytes, sibling_bytes) = query_cost(&shape, &config, false);
                    let cells = config.starting_domain_size();
                    let final_bytes = 24 * shape.final_poly_len;
                    println!(
                        "{variables},{rate},{first},{later},{cells},{row_bytes:.0},{sibling_bytes:.0},{final_bytes}"
                    );
                }
            }
        }
    }
    Ok(())
}
