//! Estimate the cost of committing the 64-client Keccak checkpoints as 4-bit digits.
//! Run in the pinned WHIR checkout. This sizes messages without generating a proof.
use ark_ff::PrimeField;
use whir::{
    algebra::{
        embedding::Identity,
        fields::{Field192, Field256},
    },
    bits::Bits,
    hash::KECCAK,
    parameters::ProtocolParameters,
    protocols::{params::DecodingRegime, whir::Config},
};

// Expected distinct prefixes among q independent draws into n buckets.
fn occupied(n: f64, q: f64) -> f64 {
    if n == 1.0 {
        1.0
    } else {
        -n * (q * (-1.0 / n).ln_1p()).exp_m1()
    }
}

// Expected multiproof traffic at fixed geometry under independent uniform row queries.
fn opening_bytes<F: PrimeField>(
    cfg: &Config<Identity<F>>,
    scalar_bytes: usize,
) -> (usize, Vec<usize>) {
    let mut queries = Vec::new();
    let mut hints = 0.0;
    for tree in std::iter::once(&cfg.initial_committer)
        .chain(cfg.round_configs.iter().map(|r| &r.irs_committer))
    {
        let depth = tree.codeword_length().ilog2();
        assert!(depth <= F::TWO_ADICITY);
        queries.push(tree.in_domain_samples());
        let q = tree.in_domain_samples() as f64;
        // Each occupied parent needs both children. Subtract the children
        // reconstructed from the queried rows. Merkle digests stay 32 bytes.
        let siblings: f64 = (0..depth)
            .map(|d| {
                let n = 2.0_f64.powi(d as i32);
                2.0 * occupied(n, q) - occupied(2.0 * n, q)
            })
            .sum();
        hints += 8.0 + q * (tree.num_cols() * scalar_bytes) as f64 + 32.0 * siblings;
    }
    (hints.round() as usize, queries)
}

fn compare_targets() {
    for (local, grind) in [
        (125, 17),
        (128, 16),
        (135, 16),
        (135, 20),
        (142, 16),
        (152, 16),
    ] {
        let cfg = Config::<Identity<Field192>>::new(
            1 << 28,
            &ProtocolParameters {
                security_level: local,
                pow_bits: grind,
                initial_folding_factor: 4,
                folding_factor: 5,
                decoding_regime: DecodingRegime::Johnson,
                starting_log_inv_rate: 5,
                batch_size: 1,
                hash_id: KECCAK,
            },
        );
        let actual = cfg.security_level(1, 1);
        let accepted =
            cfg.check_max_pow_bits(Bits::new(grind as f64)) && actual + 1e-8 >= local as f64;
        let (hints, queries) = opening_bytes(&cfg, 24);
        println!("fixed four-bit terminal: local={local} max_grind={grind} accepted={accepted} min_round_bits={actual:.2} queries={queries:?} expected_hint_bytes={hints}");
    }
}

fn size<F: PrimeField>(scalar_bytes: usize) {
    // Sixteen row coordinates, three segment coordinates, five lane coordinates,
    // four positions within each lane. The 56 unused lane slots hold the 25 final lanes.
    let arity = 28;
    for rate in 2..=6 {
        let mut best = None;
        for first in 2..=6 {
            for later in 2..=5 {
                let largest_domain = (arity + rate - first).max(arity + rate - 1 - later);
                if largest_domain > F::TWO_ADICITY as usize {
                    continue;
                }
                let cfg = Config::<Identity<F>>::new(
                    1 << arity,
                    &ProtocolParameters {
                        security_level: 135,
                        pow_bits: 16,
                        initial_folding_factor: first,
                        folding_factor: later,
                        decoding_regime: DecodingRegime::Johnson,
                        starting_log_inv_rate: rate,
                        batch_size: 1,
                        hash_id: KECCAK,
                    },
                );
                if !cfg.check_max_pow_bits(Bits::new(16.0))
                    || cfg.security_level(1, 1) + 1e-8 < 135.0
                {
                    continue;
                }
                let (hints, _) = opening_bytes(&cfg, scalar_bytes);
                let result = (hints, first, later);
                if best.is_none_or(|old| result < old) {
                    best = Some(result);
                }
            }
        }
        if let Some((hints, first, later)) = best {
            let initial_gib =
                (1_usize << (arity + rate)) as f64 * scalar_bytes as f64 / 2.0_f64.powi(30);
            // These three summands exclude the WHIR transcript, terminal arithmetic,
            // application inputs, ABI framing and on-chain execution.
            let round_bytes = 1833 * scalar_bytes;
            let digit_bytes = 17 * arity * scalar_bytes;
            println!("scalar_bytes={scalar_bytes} rate=1/{} folds={first}/{later} expected_hints={hints} round_bytes={round_bytes} digit_coeff_bytes={digit_bytes} subtotal={} initial_code_GiB={initial_gib:.0}", 1 << rate, hints + round_bytes + digit_bytes);
        }
    }
}

fn main() {
    size::<Field256>(32);
    size::<Field192>(24);
    compare_targets();
}
