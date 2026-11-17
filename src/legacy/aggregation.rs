//! Fixed-topology recursive aggregation of ordered membership proofs.
use crate::legacy::air::ImtAir;
use crate::legacy::backend::Backend;
use crate::legacy::client::Child;
use crate::legacy::config::{Config, EXTENSION_DEGREE, F, Profile, Proof, ZkConfig};
use crate::legacy::statement::check_count;
use crate::legacy::verification::{encode_proof, encode_verifier};
use anyhow::{Context, Result, ensure};
use p3_circuit_prover::CircuitVerifier;
use p3_recursion::{
    BatchOnly, ProveNextLayerParams, TrustedPreparedAggregation, TrustedPreparedInput,
    TrustedPreparedLayer, TrustedPreparedSource,
};
use serde::{Deserialize, Serialize};
use std::{iter::once, time::Instant};

pub type Aggregator = TrustedPreparedAggregation<
    'static,
    'static,
    Config,
    Config,
    BatchOnly,
    BatchOnly,
    Backend,
    EXTENSION_DEGREE,
>;

/// No secrets in this input: only child proofs, statements and retained authority.
pub struct Node {
    proof: Proof,
    verifier: CircuitVerifier<Config>,
    statement: Vec<F>,
}

#[derive(Default, Debug, Deserialize, Serialize)]
pub struct AggregationMetrics {
    pub recursive_proofs: usize,
    pub prepare_ms: f64,
    pub prove_ms: f64,
}

impl Node {
    pub fn source(&self) -> TrustedPreparedSource<'static, '_, Config, BatchOnly> {
        TrustedPreparedSource::BatchStark {
            proof: &self.proof,
            verifier: self.verifier.clone(),
            statement: &self.statement,
        }
    }

    pub fn input(&self) -> TrustedPreparedInput<'_, Config> {
        TrustedPreparedInput::BatchStark {
            proof: &self.proof,
            statement: &self.statement,
        }
    }

    pub fn statement(&self) -> &[F] {
        &self.statement
    }

    pub fn encode(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        Ok((
            encode_verifier(&self.verifier)?,
            encode_proof(&self.verifier, &self.proof)?,
        ))
    }
}

/// Wrap every hiding child, then merge ordinary proofs while preserving root order.
pub fn aggregate(
    children: Vec<Child>,
    profile: Profile,
    pin: Option<&[u8]>,
) -> Result<(Node, AggregationMetrics)> {
    check_count(children.len())?;
    let mut metrics = AggregationMetrics::default();
    let mut nodes = Vec::new();
    let (pairs, remainder) = children.as_chunks::<2>();
    if let Some((first, rest)) = pairs.split_first() {
        let start = Instant::now();
        let owner = TrustedPreparedAggregation::<
            ZkConfig,
            Config,
            ImtAir,
            ImtAir,
            _,
            EXTENSION_DEGREE,
        >::new(
            first[0].as_source(),
            first[1].as_source(),
            profile.config()?,
            backend(),
            ProveNextLayerParams::default(),
        )?;
        metrics.prepare_ms += start.elapsed().as_secs_f64() * 1e3;
        // Every pair uses the same trusted child relation. Reuse its prepared
        // circuit; the upstream owner checks replacement proofs and authority.
        for pair in once(first).chain(rest) {
            let start = Instant::now();
            let proof = owner.prove(pair[0].as_input(), pair[1].as_input())?.0;
            metrics.prove_ms += start.elapsed().as_secs_f64() * 1e3;
            metrics.recursive_proofs += 1;
            nodes.push(Node {
                proof,
                verifier: owner.verifier(),
                statement: [pair[0].statement(), pair[1].statement()].concat(),
            });
        }
    }
    if let [last] = remainder {
        let start = Instant::now();
        let owner = TrustedPreparedLayer::<ZkConfig, Config, ImtAir, _, EXTENSION_DEGREE>::new(
            last.as_source(),
            profile.config()?,
            backend(),
            ProveNextLayerParams::default(),
        )?;
        metrics.prepare_ms += start.elapsed().as_secs_f64() * 1e3;
        let start = Instant::now();
        let proof = owner.prove(last.as_input())?.0;
        metrics.prove_ms += start.elapsed().as_secs_f64() * 1e3;
        metrics.recursive_proofs += 1;
        nodes.push(Node {
            proof,
            verifier: owner.verifier(),
            statement: last.statement().to_vec(),
        });
    }
    let (node, rest) = aggregate_outer(nodes, profile, pin)?;
    metrics.recursive_proofs += rest.recursive_proofs;
    metrics.prepare_ms += rest.prepare_ms;
    metrics.prove_ms += rest.prove_ms;
    Ok((node, metrics))
}

pub fn backend() -> Backend {
    Backend::new()
}

fn aggregate_outer(
    mut nodes: Vec<Node>,
    profile: Profile,
    root_pin: Option<&[u8]>,
) -> Result<(Node, AggregationMetrics)> {
    check_count(nodes.len())?;
    let mut metrics = AggregationMetrics::default();
    if nodes.len() == 1 {
        let node = nodes.pop().context("aggregation produced no nodes")?;
        check_pin(&node.verifier, root_pin)?;
        return Ok((node, metrics));
    }
    while nodes.len() > 1 {
        let final_level = nodes.len() == 2;
        let mut next = Vec::new();
        let mut iter = nodes.into_iter();
        while let Some(left) = iter.next() {
            let Some(right) = iter.next() else {
                next.push(left);
                break;
            };
            let statement = [left.statement(), right.statement()].concat();
            let start = Instant::now();
            let owner = Aggregator::new(
                left.source(),
                right.source(),
                profile.config()?,
                backend(),
                ProveNextLayerParams::default(),
            )?;
            let verifier = owner.verifier();
            if final_level {
                check_pin(&verifier, root_pin)?;
            }
            metrics.prepare_ms += start.elapsed().as_secs_f64() * 1e3;
            let start = Instant::now();
            let proof = owner.prove(left.input(), right.input())?.0;
            metrics.prove_ms += start.elapsed().as_secs_f64() * 1e3;
            metrics.recursive_proofs += 1;
            next.push(Node {
                proof,
                verifier,
                statement,
            });
        }
        nodes = next;
    }
    Ok((
        nodes.pop().context("aggregation produced no nodes")?,
        metrics,
    ))
}

fn check_pin(verifier: &CircuitVerifier<Config>, pin: Option<&[u8]>) -> Result<()> {
    if let Some(pin) = pin {
        ensure!(
            encode_verifier(verifier)? == pin,
            "root verifier differs from independently provisioned setup"
        );
    }
    Ok(())
}
