use std::time::Instant;

use crate::benchmark::ms;
use anyhow::{Result, ensure};
use p3_air::{AirLayout, BaseAir};
use p3_binary_field::{BinaryField2, Ghash128, TowerLevel};
use p3_binary_pcs::whir::BinaryWhirDomain;
use p3_bus::BusSymbolicBuilder;
use p3_circuit::ops::ByteHash;
use p3_circuit::ops::binary_encoding::NativeBinaryEncoding;
use p3_circuit::{Circuit, CircuitBuilder, CircuitConstructionLimits};
use p3_circuit_prover::direct::DirectCircuitLimits;
use p3_circuit_prover::native_bus::{KeccakCommitment, NativeBusCircuit, NativeBusCircuitAir};
use p3_multi_stark::{MultiStarkProof, ReprBackend};
use p3_recursion::BinaryTower128Challenger;
use p3_recursion::artifact::{
    BinaryNativeChallenger, BinaryNativeMixedWhirAuthority, BinaryNativeMixedWhirConfig,
    BinaryNativeMixedWhirPcsParameters, BinaryNativeMixedWhirProver, BinaryNativeVerifierSpec,
    BinaryNativeWhirPcsParameters, CanonicalBinaryStatement, ExpectedVerifierArtifact,
    VerifiedBinaryNativeMixedWhirProof,
};
use p3_recursion::pcs::binary::MerkleArity;
use p3_recursion::verifier::VerifierLimits;
use p3_whir::{FoldingFactor, ProtocolParameters, SecurityAssumption, WhirConfig};
use serde::{Deserialize, Serialize};

use super::relation::{
    AggregatePublic, ClientPublic, ClientWitness, F, PUBLIC_BYTES, membership_circuit,
};
use super::tree::keccak;

pub type Authority = BinaryNativeMixedWhirAuthority<NativeBusCircuitAir<F>>;
type Prover = BinaryNativeMixedWhirProver<NativeBusCircuitAir<F>>;
type Proof = MultiStarkProof<BinaryNativeMixedWhirConfig>;

/// Explicit research parameters. A PCS target is not a composed security claim.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    pub depth: usize,
    pub batch_size: usize,
    pub pcs_bits: usize,
    #[serde(default)]
    pub pow_bits: usize,
    pub min_security_bits: usize,
    pub log_inv_rate: usize,
    pub packed_log_inv_rate: usize,
    pub fold: usize,
    pub max_codeword_cells: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Geometry {
    pub witnesses: u32,
    pub table_widths: Vec<usize>,
    pub log_heights: Vec<usize>,
    pub constraints: Vec<usize>,
    pub initial_codeword_cells: usize,
    pub security_bits: Option<f64>,
    pub security_terms: Vec<(String, f64)>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofMetrics {
    pub witness_ms: f64,
    pub prove_ms: f64,
    pub verify_ms: f64,
    pub encode_ms: f64,
    pub proof_bytes: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChildInput {
    pub proof: Vec<u8>,
    pub public: ClientPublic,
}

pub struct PreparedCircuit {
    pub circuit: Circuit<F>,
    pub bus: NativeBusCircuit<F>,
    pub authority: Authority,
    prover: Prover,
    pub geometry: Geometry,
}

pub struct PreparedChild {
    pub inner: PreparedCircuit,
    depth: usize,
}

pub struct PreparedAggregate {
    pub inner: PreparedCircuit,
    child: Authority,
    batch_size: usize,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            depth: 8,
            batch_size: 2,
            pcs_bits: 32,
            pow_bits: 0,
            min_security_bits: 16,
            log_inv_rate: 1,
            packed_log_inv_rate: 3,
            fold: 4,
            max_codeword_cells: 1 << 27,
        }
    }
}

impl Settings {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.pow_bits <= 16,
            "grinding ceiling must be at most 16 bits"
        );
        ensure!((1..=32).contains(&self.depth), "depth must be in 1..=32");
        ensure!(
            [1, 2, 4, 8, 16, 32].contains(&self.batch_size),
            "unsupported fixed batch size"
        );
        ensure!(
            (8..=128).contains(&self.pcs_bits),
            "PCS bits must be in 8..=128"
        );
        ensure!(
            (1..=128).contains(&self.min_security_bits),
            "invalid composed security floor"
        );
        ensure!((1..=4).contains(&self.log_inv_rate), "invalid rate");
        ensure!(
            (1..=5).contains(&self.packed_log_inv_rate),
            "invalid packed rate"
        );
        ensure!((1..=4).contains(&self.fold), "invalid folding factor");
        ensure!(
            self.max_codeword_cells <= 1 << 29,
            "codeword budget too large for this PoC"
        );
        Ok(())
    }

    fn protocol(&self, packed: bool) -> ProtocolParameters {
        ProtocolParameters {
            security_level: self.pcs_bits,
            pow_bits: self.pow_bits,
            round_log_inv_rates: vec![],
            folding_factor: FoldingFactor::Constant(self.fold),
            soundness_type: SecurityAssumption::JohnsonBound,
            starting_log_inv_rate: if packed {
                self.packed_log_inv_rate
            } else {
                self.log_inv_rate
            },
        }
    }
}

impl PreparedCircuit {
    pub fn new(circuit: Circuit<F>, settings: &Settings, domain: &[u8]) -> Result<Self> {
        let bus = NativeBusCircuit::with_compact_options(
            &circuit,
            "imt",
            settings.fold,
            DirectCircuitLimits {
                max_witnesses: 1 << 23,
                max_operations: 1 << 23,
                max_trace_cells: 1 << 28,
            },
            KeccakCommitment::Bits,
        )?;
        let packed_table = bus
            .packed_table_index()
            .ok_or_else(|| anyhow::anyhow!("missing Keccak table"))?;
        let bit_variables = bus
            .packed_bit_variables()
            .ok_or_else(|| anyhow::anyhow!("missing packed geometry"))?;
        let cells = (1usize << (bus.main_variables() + settings.log_inv_rate))
            + (1usize << (bit_variables - 7 + settings.packed_log_inv_rate))
            + bus
                .preprocessed_variables()
                .map_or(0, |n| 1usize << (n + settings.log_inv_rate));
        ensure!(
            cells <= settings.max_codeword_cells,
            "initial codeword cells {cells} exceed budget {}; reduce batch size or increase --max-codeword-cells",
            settings.max_codeword_cells
        );
        let limits = VerifierLimits {
            max_rounds: 2048,
            max_metadata_entries: 1 << 24,
            ..Default::default()
        };
        let whir = |n, packed| {
            BinaryNativeWhirPcsParameters::<F>::with_limits(
                n,
                settings.protocol(packed),
                ByteHash::Keccak256,
                MerkleArity::Four,
                2,
                &limits,
            )
            .map_err(|error| {
                let detail = WhirConfig::<F, F, BinaryNativeChallenger<F>>::new_with_domain(
                    n,
                    settings.protocol(packed),
                    &BinaryWhirDomain::<F>::default(),
                )
                .err();
                anyhow::anyhow!("{error}; variables={n}, packed={packed}, upstream={detail:?}")
            })
        };
        let main = BinaryNativeMixedWhirPcsParameters::with_packed_table(
            whir(bus.main_variables(), false)?,
            whir(bit_variables - 7, true)?,
            packed_table,
            bit_variables,
        )?;
        let pp = bus
            .preprocessed_variables()
            .map(|n| whir(n, false).map(BinaryNativeMixedWhirPcsParameters::dense))
            .transpose()?;
        let spec = BinaryNativeVerifierSpec {
            main,
            preprocessed: pp,
            transcript_hash: ByteHash::Keccak256,
            initial_bytes: domain.to_vec(),
            sumcheck_pow_bits: 0,
            max_tau_draws: 32,
            security_bits: settings.min_security_bits,
        };
        let (prover, authority) = Authority::setup(
            bus.airs().to_vec(),
            bus.log_heights().to_vec(),
            spec,
            &limits,
        )?;
        let report = authority.security_report();
        let geometry = Geometry {
            witnesses: circuit.witness_count,
            table_widths: bus.airs().iter().map(BaseAir::width).collect(),
            log_heights: bus.log_heights().to_vec(),
            constraints: bus
                .airs()
                .iter()
                .map(|air| {
                    BusSymbolicBuilder::<F, F>::from_air(air, AirLayout::from_air(air))
                        .constraint_layout()
                        .total_constraints()
                })
                .collect(),
            initial_codeword_cells: cells,
            security_bits: report.security_bits(),
            security_terms: report
                .terms()
                .iter()
                .map(|t| (format!("{} {:?}", t.label, t.component), t.bits.bits()))
                .collect(),
        };
        Ok(Self {
            circuit,
            bus,
            authority,
            prover,
            geometry,
        })
    }

    pub fn prove(&self, public: &[F], private: &[F]) -> Result<(Vec<u8>, ProofMetrics)> {
        let start = Instant::now();
        let mut runner = self.circuit.runner();
        runner.set_public_inputs(public)?;
        runner.set_private_inputs(private)?;
        let witness = runner.run_witness()?;
        let tables = self.bus.column_major_tables(&witness)?;
        drop(witness);
        let witness_ms = ms(start);
        let public_tables = self.bus.public_values(public)?;
        let start = Instant::now();
        let proof: Proof = self
            .prover
            .prove_tables_with_backend::<ReprBackend<BinaryField2, Ghash128, true>>(
                &public_tables,
                tables,
            )?;
        let prove_ms = ms(start);
        let start = Instant::now();
        self.authority.verify_native(&proof, &public_tables)?;
        let verify_ms = ms(start);
        let start = Instant::now();
        // Upstream encoding intentionally verifies again; report that cost separately.
        let bytes = self.authority.encode_native_proof(&proof, &public_tables)?;
        let encode_ms = ms(start);
        let proof_bytes = bytes.len();
        Ok((
            bytes,
            ProofMetrics {
                witness_ms,
                prove_ms,
                verify_ms,
                encode_ms,
                proof_bytes,
            },
        ))
    }

    pub fn verify(&self, bytes: &[u8], public: &[F]) -> Result<()> {
        decode(&self.authority, bytes, &self.bus.public_values(public)?)?;
        Ok(())
    }

    pub fn identity(&self) -> String {
        hex::encode(keccak(self.authority.canonical_verifier_bytes()))
    }
}

impl PreparedChild {
    pub fn new(settings: &Settings) -> Result<Self> {
        settings.validate()?;
        let circuit = membership_circuit(settings.depth)?;
        let inner = PreparedCircuit::new(circuit, settings, b"binary-keccak-imt-child-v1")?;
        Ok(Self {
            inner,
            depth: settings.depth,
        })
    }

    pub fn prove(
        &self,
        public: ClientPublic,
        witness: &ClientWitness,
    ) -> Result<(ChildInput, ProofMetrics)> {
        let (proof, metrics) = self
            .inner
            .prove(&public.fields(), &witness.fields(self.depth)?)?;
        Ok((ChildInput { proof, public }, metrics))
    }

    pub fn verify(&self, input: &ChildInput) -> Result<()> {
        self.inner.verify(&input.proof, &input.public.fields())
    }
}

impl PreparedAggregate {
    pub fn new(child: &PreparedChild, settings: &Settings) -> Result<Self> {
        settings.validate()?;
        ensure!(
            child.depth == settings.depth,
            "child depth differs from settings"
        );
        let authority = &child.inner.authority;
        let verifier = authority.recursive_verifier();
        let shape = verifier.input_shape();
        let counts: Vec<_> = shape.public_value_counts().collect();
        ensure!(
            counts.iter().sum::<usize>() == PUBLIC_BYTES,
            "unexpected child public shape"
        );
        let mut builder =
            CircuitBuilder::<F>::with_construction_limits(CircuitConstructionLimits {
                max_expression_nodes: 1 << 24,
                max_pending_connects: 1 << 24,
                max_non_primitive_calls: 1 << 20,
                max_non_primitive_slots: 1 << 28,
            })?;
        builder.enable_native_keccak_f1600()?;
        for _ in 0..settings.batch_size {
            let public: Vec<Vec<_>> = counts
                .iter()
                .map(|&n| {
                    (0..n)
                        .map(|_| {
                            let value = builder.public_input();
                            builder.native_tower128_from_expr(value)
                        })
                        .collect()
                })
                .collect();
            let proof = shape.allocate_native_targets(&mut builder)?;
            let initial: Vec<_> = authority
                .initial_bytes()
                .iter()
                .map(|&byte| builder.define_const(F::from_repr(u128::from(byte))))
                .collect();
            let challenger = BinaryTower128Challenger::with_initial_bytes_with_host::<
                NativeBinaryEncoding,
                F,
            >(&mut builder, ByteHash::Keccak256, &initial)?;
            // This emits the entire verifier relation, including Fiat-Shamir,
            // Merkle openings, sumcheck, AIR evaluation and product-bus checks.
            verifier.verify_native(&mut builder, challenger, &public, &proof)?;
            builder.check_construction_limits()?;
        }
        let circuit = builder.build()?;
        let domain = format!("binary-keccak-imt-aggregate-v1/{:02}", settings.batch_size);
        let inner = PreparedCircuit::new(circuit, settings, domain.as_bytes())?;
        Ok(Self {
            inner,
            child: authority.clone(),
            batch_size: settings.batch_size,
        })
    }

    pub fn prove(
        &self,
        children: &[ChildInput],
    ) -> Result<(AggregatePublic, Vec<u8>, ProofMetrics)> {
        ensure!(
            children.len() == self.batch_size,
            "incorrect number of children"
        );
        let shape = self.child.recursive_verifier().input_shape();
        let counts: Vec<_> = shape.public_value_counts().collect();
        let mut private = Vec::new();
        let mut fields = Vec::new();
        for child in children {
            let values = child.public.fields();
            let mut offset = 0;
            let tables: Vec<_> = counts
                .iter()
                .map(|&n| {
                    let table = values[offset..offset + n].to_vec();
                    offset += n;
                    table
                })
                .collect();
            let checked = decode(&self.child, &child.proof, &tables)?;
            private.extend(checked.native_input().private_native_values(&shape)?);
            fields.extend(values);
        }
        let (proof, metrics) = self.inner.prove(&fields, &private)?;
        Ok((
            AggregatePublic {
                children: children.iter().map(|c| c.public.clone()).collect(),
            },
            proof,
            metrics,
        ))
    }

    pub fn verify(&self, proof: &[u8], public: &AggregatePublic) -> Result<()> {
        ensure!(
            public.children.len() == self.batch_size,
            "incorrect number of children"
        );
        let fields: Vec<_> = public
            .children
            .iter()
            .flat_map(ClientPublic::fields)
            .collect();
        self.inner.verify(proof, &fields)
    }
}

fn decode(
    authority: &Authority,
    proof: &[u8],
    public: &[Vec<F>],
) -> Result<VerifiedBinaryNativeMixedWhirProof> {
    let statement = authority.encode_statement(public)?;
    let identity = authority.canonical_verifier_bytes();
    Ok(authority.decode_and_verify(
        identity,
        ExpectedVerifierArtifact::from_trusted_bytes(identity),
        proof,
        CanonicalBinaryStatement::new(&statement, public.iter().map(Vec::len).sum()),
    )?)
}
