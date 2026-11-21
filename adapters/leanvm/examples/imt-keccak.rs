//! Benchmark the fixed Keccak circuit at the terminal IMT merge's active permutation count.
use bench_harness::Plan;
use primitives::test_rng::Rng;
use std::{
    fs::File,
    io::{BufWriter, Write},
};

fn main() -> std::io::Result<()> {
    parallel::set_num_threads(5);
    let permutations = 43_342;
    if let Some(path) = std::env::args_os().nth(1) {
        // Reproduce batch_bench::run's input stream at the pinned revision.
        let mut rng = Rng::new(0x9E37_79B9_7F4A_7C15 ^ permutations as u64);
        let mut out = BufWriter::new(File::create_new(path)?);
        for _ in 0..permutations * 25 {
            out.write_all(&rng.next_u64().to_le_bytes())?;
        }
        out.flush()?;
    }
    for depth in [24, 12] {
        for log_inverse_rate in [1, 4] {
            println!(
                "Active permutations {permutations}, segment depth {depth}, code rate 2^-{log_inverse_rate}"
            );
            keccak_gkr::batch_bench::run(permutations, depth, log_inverse_rate, Plan::new(1, 0))
                .print();
        }
    }
    Ok(())
}
