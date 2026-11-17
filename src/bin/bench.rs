use anyhow::Result;
use clap::Parser;
use recursive_imt_prover::binary::cli::{Args, run};

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn main() -> Result<()> {
    run(Args::parse(), false)
}
