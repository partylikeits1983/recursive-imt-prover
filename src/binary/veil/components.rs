//! Memory-bounded correctness baseline: three linked outer proofs per child.
//! This is deliberately NOT a succinct N-to-one aggregate. Each outer circuit
//! verifies actual masked proof data; the original witnesses never enter here.
use std::time::Instant;

use anyhow::{Result, ensure};
use p3_binary_field::TowerLevel;
use serde::Serialize;

use super::{
    F,
    aggregate::MaskedChildInput,
    child::recursive::{
        PreparedMaskedVerifier,
        parts::{PUBLIC_COUNTS, check_parts},
    },
    parameters::Parameters,
};
use crate::{
    benchmark::ms,
    binary::{
        engine::{Authority, Geometry, PreparedCircuit, ProofMetrics, Settings, decode},
        relation::AggregatePublic,
    },
};

const MAGIC: &[u8; 8] = b"IMTCMP01";
const MAX_PART_BYTES: usize = 8 << 20;

pub const PROTOCOL: &str = "experimental-masked-component-batch-v1";

pub struct PreparedComponentBatch {
    verifier: PreparedMaskedVerifier,
    settings: Settings,
    authorities: [Authority; 3],
    pub geometry: Vec<Geometry>,
}

struct Component {
    public: Vec<F>,
    proof: Vec<u8>,
}

#[derive(Serialize)]
pub struct ComponentMetrics {
    pub witness_import_ms: Vec<f64>,
    pub rebuild_setup_ms: Vec<f64>,
    pub children: Vec<Vec<ProofMetrics>>,
    pub proof_count: usize,
    pub wall_ms: f64,
}

impl PreparedComponentBatch {
    pub fn new(settings: &Settings, parameters: Parameters) -> Result<Self> {
        settings.validate()?;
        ensure!(matches!(settings.depth, 16 | 32), "depth must be 16 or 32");
        ensure!(
            parameters.min_algebraic_bits >= 144 && settings.min_algebraic_bits >= 144,
            "component baseline requires the conservative 144-bit algebraic floor"
        );
        let verifier = PreparedMaskedVerifier::new(settings.depth, parameters)?;
        let settings = Settings {
            packed_log_inv_rate: 1,
            ..settings.clone()
        };
        let mut authorities = Vec::new();
        let mut geometry = Vec::new();
        for part in 0..3 {
            let prepared = prepare(&verifier, &settings, part)?;
            authorities.push(prepared.authority.clone());
            geometry.push(prepared.geometry.clone());
            // Drop the circuit, preprocessing codeword and prover key before
            // preparing the next part. Retained authorities contain no key.
        }
        Ok(Self {
            verifier,
            settings,
            authorities: authorities.try_into().ok().unwrap(),
            geometry,
        })
    }

    pub fn identities(&self) -> Vec<String> {
        self.authorities
            .iter()
            .map(|a| hex::encode(crate::binary::tree::keccak(a.canonical_verifier_bytes())))
            .collect()
    }

    pub fn prove(
        &self,
        children: &[MaskedChildInput],
    ) -> Result<(AggregatePublic, Vec<u8>, ComponentMetrics)> {
        ensure!(
            children.len() == self.settings.batch_size,
            "wrong child count"
        );
        let start = Instant::now();
        let mut imports = Vec::new();
        let mut import_ms = Vec::new();
        for child in children {
            let t = Instant::now();
            imports.push(self.verifier.import_parts(&child.public, &child.proof)?);
            import_ms.push(ms(t));
        }
        let mut components: Vec<Vec<Component>> = (0..children.len()).map(|_| Vec::new()).collect();
        let mut metrics: Vec<Vec<ProofMetrics>> = (0..children.len()).map(|_| Vec::new()).collect();
        let mut rebuild_setup_ms = Vec::new();
        for part in 0..3 {
            let t = Instant::now();
            let prepared = prepare(&self.verifier, &self.settings, part)?;
            ensure!(
                prepared.authority.canonical_verifier_bytes()
                    == self.authorities[part].canonical_verifier_bytes(),
                "rebuilt authority differs"
            );
            rebuild_setup_ms.push(ms(t));
            for (i, inputs) in imports.iter().enumerate() {
                let (proof, timing) =
                    prepared.prove(&inputs[part].public, &inputs[part].private)?;
                eprintln!(
                    "  Child {} component {part}: prove {:.3} ms, verify {:.3} ms, {} bytes",
                    i + 1,
                    timing.prove_ms,
                    timing.verify_ms,
                    proof.len()
                );
                components[i].push(Component {
                    public: inputs[part].public.clone(),
                    proof,
                });
                metrics[i].push(timing);
            }
        }
        let public = AggregatePublic {
            children: children.iter().map(|c| c.public.clone()).collect(),
        };
        let bytes = encode(&components)?;
        self.verify(&bytes, &public)?;
        Ok((
            public,
            bytes,
            ComponentMetrics {
                witness_import_ms: import_ms,
                rebuild_setup_ms,
                children: metrics,
                proof_count: 3 * children.len(),
                wall_ms: ms(start),
            },
        ))
    }

    pub fn verify(&self, bytes: &[u8], public: &AggregatePublic) -> Result<()> {
        ensure!(
            public.children.len() == self.settings.batch_size,
            "wrong public child count"
        );
        let components = decode_components(bytes, self.settings.batch_size)?;
        for (statement, components) in public.children.iter().zip(components) {
            check_parts(
                &statement.fields(),
                std::array::from_fn(|i| components[i].public.as_slice()),
            )?;
            for (authority, component) in self.authorities.iter().zip(components) {
                let mut offset = 0;
                let tables: Vec<_> = authority
                    .recursive_verifier()
                    .input_shape()
                    .public_value_counts()
                    .map(|n| {
                        let result = component.public[offset..offset + n].to_vec();
                        offset += n;
                        result
                    })
                    .collect();
                ensure!(offset == component.public.len(), "unexpected public shape");
                decode(authority, &component.proof, &tables)?;
            }
        }
        Ok(())
    }
}

fn prepare(
    verifier: &PreparedMaskedVerifier,
    settings: &Settings,
    part: usize,
) -> Result<PreparedCircuit> {
    let circuit = verifier.part_circuit(part)?;
    eprintln!(
        "Preparing component {part}: {} witnesses",
        circuit.witness_count
    );
    PreparedCircuit::new(
        circuit,
        settings,
        format!("imt-masked-verifier-part-v1/{part}").as_bytes(),
    )
}

fn encode(children: &[Vec<Component>]) -> Result<Vec<u8>> {
    let mut bytes = MAGIC.to_vec();
    bytes.extend((children.len() as u32).to_le_bytes());
    for child in children {
        ensure!(child.len() == 3, "wrong component count");
        for (part, &count) in child.iter().zip(&PUBLIC_COUNTS) {
            ensure!(
                part.public.len() == count && part.proof.len() <= MAX_PART_BYTES,
                "wrong component shape"
            );
            for value in &part.public {
                bytes.extend(value.to_repr().to_le_bytes());
            }
            bytes.extend((part.proof.len() as u32).to_le_bytes());
            bytes.extend(&part.proof);
        }
    }
    Ok(bytes)
}

fn decode_components(mut bytes: &[u8], count: usize) -> Result<Vec<[Component; 3]>> {
    ensure!(
        take(&mut bytes, 8)? == MAGIC,
        "unsupported component format"
    );
    ensure!(
        u32::from_le_bytes(take(&mut bytes, 4)?.try_into()?) as usize == count,
        "wrong encoded child count"
    );
    let mut children = Vec::with_capacity(count);
    for _ in 0..count {
        let mut parts = Vec::new();
        for length in PUBLIC_COUNTS {
            let public = take(&mut bytes, 8 * length)?
                .as_chunks::<8>()
                .0
                .iter()
                .map(|v| F::new(u64::from_le_bytes(*v)))
                .collect();
            let length = u32::from_le_bytes(take(&mut bytes, 4)?.try_into()?) as usize;
            ensure!(
                length > 0 && length <= MAX_PART_BYTES,
                "component proof exceeds bound"
            );
            let proof = take(&mut bytes, length)?.to_vec();
            parts.push(Component { public, proof });
        }
        children.push(parts.try_into().ok().unwrap());
    }
    ensure!(bytes.is_empty(), "trailing component bytes");
    Ok(children)
}

fn take<'a>(bytes: &mut &'a [u8], n: usize) -> Result<&'a [u8]> {
    ensure!(n <= bytes.len(), "truncated component artifact");
    let (head, tail) = bytes.split_at(n);
    *bytes = tail;
    Ok(head)
}
