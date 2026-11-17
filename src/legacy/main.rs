mod cli;

use anyhow::Result;
use clap::{Parser, Subcommand};
use cli::{
    BenchmarkOptions, TreeOptions, aggregate_files, benchmark, client, demo, fixtures, setup,
    verify_files,
};
use recursive_imt_prover::legacy::Profile;
use std::path::PathBuf;

#[derive(Parser)]
#[command(about = "ZK IMT note membership and N-to-one recursive aggregation")]
struct Args {
    #[command(subcommand)]
    command: Action,
}

#[derive(Subcommand)]
enum Action {
    /// Prove N notes against later roots, aggregate, then verify in a fresh process.
    Demo {
        #[arg(long)]
        out: PathBuf,
        #[arg(long, default_value_t = 2)]
        count: usize,
        #[arg(long, value_enum, default_value = "reference")]
        profile: Profile,
        #[command(flatten)]
        tree: TreeOptions,
        /// Public amounts in user order; defaults to 100, 200, ...
        #[arg(long, value_delimiter = ',')]
        amounts: Vec<u64>,
    },
    /// Measure repeated native runs, provisioning each batch size once.
    Benchmark(BenchmarkOptions),
    /// Provision trusted child and outer verifiers for a fixed batch size and depth.
    Setup {
        #[arg(long)]
        out: PathBuf,
        #[arg(long, default_value_t = 2)]
        count: usize,
        #[arg(long, default_value_t = 32)]
        depth: u8,
        #[arg(long, value_enum, default_value = "reference")]
        profile: Profile,
    },
    /// Generate a hiding proof from a private note and its membership path.
    Client {
        #[arg(long)]
        trusted_dir: PathBuf,
        #[arg(long)]
        out: PathBuf,
        #[arg(long)]
        witness: PathBuf,
    },
    /// Aggregate child proofs and their public roots and amounts.
    Aggregate {
        #[arg(long)]
        trusted_dir: PathBuf,
        #[arg(long, required = true, num_args = 1..)]
        children: Vec<PathBuf>,
        #[arg(long)]
        out: PathBuf,
    },
    /// Verify one outer proof and check independently supplied accepted roots.
    Verify {
        #[arg(long)]
        trusted_dir: PathBuf,
        #[arg(long)]
        statement: PathBuf,
        #[arg(long)]
        proof: PathBuf,
        #[arg(long)]
        allowed_roots: PathBuf,
    },
    /// Populate a tree and write private notes with paths against later roots.
    Fixtures {
        #[arg(long)]
        out: PathBuf,
        #[arg(long, default_value_t = 2)]
        count: usize,
        #[command(flatten)]
        tree: TreeOptions,
        #[arg(long, value_delimiter = ',')]
        amounts: Vec<u64>,
    },
}

fn main() -> Result<()> {
    match Args::parse().command {
        Action::Demo {
            out,
            count,
            profile,
            tree,
            amounts,
        } => demo(&out, count, profile, tree.config(), &amounts),
        Action::Benchmark(options) => benchmark(options),
        Action::Setup {
            out,
            count,
            depth,
            profile,
        } => setup(&out, count, depth, profile),
        Action::Client {
            trusted_dir,
            out,
            witness,
        } => client(&trusted_dir, &out, &witness),
        Action::Aggregate {
            trusted_dir,
            children,
            out,
        } => aggregate_files(&trusted_dir, &children, &out),
        Action::Verify {
            trusted_dir,
            statement,
            proof,
            allowed_roots,
        } => verify_files(&trusted_dir, &statement, &proof, &allowed_roots),
        Action::Fixtures {
            out,
            count,
            tree,
            amounts,
        } => fixtures(&out, count, tree.config(), &amounts).map(|_| ()),
    }
}
