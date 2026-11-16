//! Two real Plonky3 proofs of y = x² + x, verified inside one Plonky3 circuit.
//! Uses upstream trusted aggregation and portable artifacts, with no custom verifier.
//! Proofs are non-hiding: there is no zero-knowledge claim.
use anyhow::{Result, ensure};
use p3_circuit::{Circuit, CircuitBuilder, StatementExport};
use p3_circuit_prover::common::{NpoAirBuilder, NpoPreprocessor};
use p3_circuit_prover::{
    BatchStarkProof, BatchStarkProver, CircuitVerifier, ConstraintProfile, PreparedCircuitProver,
    StatementAirBuilder, StatementPreprocessor, StatementProver, TablePacking,
};
use p3_field::{PrimeCharacteristicRing, PrimeField32, extension::QuinticTrinomialExtensionField};
use p3_recursion::artifact::{
    ArtifactLimits, CanonicalStatement, ExpectedVerifierArtifact, PortableArtifactExport,
    PortableVerifier,
};
use p3_recursion::builtin_config::{
    FriConfigV1, KoalaBearD5Poseidon2BinaryConfig, SuiteIdV1, koala_bear_d5_poseidon2_binary,
};
use p3_recursion::{
    BatchOnly, FriRecursionBackend, FriRecursionBackendD5, Poseidon2Config, ProveNextLayerParams,
    TrustedPreparedAggregation, TrustedPreparedInput, TrustedPreparedSource,
};
use serde::{Deserialize, Serialize};

pub type F = p3_koala_bear::KoalaBear;
pub type E = QuinticTrinomialExtensionField<F>;
pub type Config = KoalaBearD5Poseidon2BinaryConfig;
pub type Proof = BatchStarkProof<Config>;
pub type Backend = FriRecursionBackendD5<16, 8, Poseidon2Config>;
pub type Aggregator =
    TrustedPreparedAggregation<'static, 'static, Config, Config, BatchOnly, BatchOnly, Backend, 5>;
pub const MODULUS: u32 = 2_130_706_433;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub enum Profile {
    /// Reference parameters; no asserted composed bit-security bound.
    Reference,
    /// Four queries, no grinding. LOW SECURITY, tests only.
    Smoke,
}
impl Profile {
    pub fn descriptor(self) -> FriConfigV1 {
        let (blowup, queries, pow) = match self {
            Self::Reference => (2, 128, 16),
            Self::Smoke => (1, 4, 0),
        };
        FriConfigV1::new(
            SuiteIdV1::KoalaBearD5Poseidon2BinaryFri,
            blowup,
            0,
            2,
            queries,
            0,
            pow,
            0,
            0,
            0,
            0,
        )
    }
    pub fn config(self) -> Result<Config> {
        Ok(koala_bear_d5_poseidon2_binary(
            &self.descriptor(),
            &ArtifactLimits::default().verifier,
        )?)
    }
}

/// The ordered concatenation of BOTH child public statements, all canonical u32s.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Statement {
    pub version: u32,
    pub children: [[u32; 2]; 2],
}
impl Statement {
    pub fn from_inputs(left: u32, right: u32) -> Result<Self> {
        Ok(Self {
            version: 1,
            children: [child_statement(left)?, child_statement(right)?],
        })
    }
    pub fn fields(&self) -> Result<[F; 4]> {
        ensure!(self.version == 1, "unsupported statement version");
        ensure!(
            self.children.iter().flatten().all(|x| *x < MODULUS),
            "noncanonical statement element"
        );
        let [[a, b], [c, d]] = self.children;
        Ok([a, b, c, d].map(F::from_u32))
    }
    pub fn bytes(&self) -> Result<Vec<u8>> {
        Ok(self
            .fields()?
            .iter()
            .flat_map(|f| f.as_canonical_u32().to_le_bytes())
            .collect())
    }
    pub fn child_fields(&self) -> Result<[[F; 2]; 2]> {
        let [a, b, c, d] = self.fields()?;
        Ok([[a, b], [c, d]])
    }
}

pub fn child_statement(x: u32) -> Result<[u32; 2]> {
    ensure!(x < MODULUS, "input is not a canonical KoalaBear element");
    let f = F::from_u32(x);
    Ok([x, (f * f + f).as_canonical_u32()])
}

pub struct Leaf {
    pub circuit: Circuit<E>,
    pub prepared: PreparedCircuitProver<Config>,
}
impl Leaf {
    pub fn prepare(profile: Profile) -> Result<Self> {
        Self::prepare_with_coefficient(profile, 1)
    }
    /// Exposed to exercise same-shape/different-relation rejection in tests.
    pub fn prepare_with_coefficient(profile: Profile, coefficient: u32) -> Result<Self> {
        ensure!(coefficient < MODULUS, "noncanonical coefficient");
        let mut b = CircuitBuilder::<E>::new();
        let x = b.public_input();
        let y = b.public_input();
        let c = b.alloc_const(E::from_u32(coefficient), "fixed coefficient");
        let squared = b.mul(x, x);
        let linear = b.mul(c, x);
        let result = b.add(squared, linear);
        b.connect(result, y);
        let schema =
            b.set_statement_exports::<F>(&[StatementExport::Base(x), StatementExport::Base(y)])?;
        let circuit = b.build()?;
        let preprocessors: Vec<Box<dyn NpoPreprocessor<F>>> =
            vec![Box::new(StatementPreprocessor::new(schema.clone()))];
        let airs: Vec<Box<dyn NpoAirBuilder<Config, 5>>> =
            vec![Box::new(StatementAirBuilder::<5>::new(schema.clone()))];
        let mut prover = BatchStarkProver::new(profile.config()?)
            .with_table_packing(TablePacking::new(4, 4).with_min_trace_height(32));
        prover.register_table_prover(Box::new(StatementProver::<5>::new(schema)));
        let prepared = prover.prepare_circuit::<E, 5>(
            &circuit,
            &preprocessors,
            &airs,
            ConstraintProfile::Standard,
        )?;
        Ok(Self { circuit, prepared })
    }
    /// No native verifier prefilter: the leaf circuit constrains the supplied pair.
    pub fn prove(&self, statement: [F; 2]) -> Result<Proof> {
        let mut runner = self.circuit.runner();
        runner.set_public_inputs(&statement.map(E::from))?;
        Ok(self.prepared.prove(&runner.run()?)?)
    }
    pub fn verifier(&self) -> CircuitVerifier<Config> {
        self.prepared.verifier()
    }
}

pub fn backend() -> Backend {
    FriRecursionBackend::<16, 8, _>::new_d5(Poseidon2Config::KOALA_BEAR_D1_W16)
}
pub fn prepare_aggregator(
    profile: Profile,
    leaf_verifier: CircuitVerifier<Config>,
    proofs: [&Proof; 2],
    statements: &[[F; 2]; 2],
) -> Result<Aggregator> {
    Ok(TrustedPreparedAggregation::new(
        TrustedPreparedSource::BatchStark {
            verifier: leaf_verifier.clone(),
            proof: proofs[0],
            statement: &statements[0],
        },
        TrustedPreparedSource::BatchStark {
            verifier: leaf_verifier,
            proof: proofs[1],
            statement: &statements[1],
        },
        profile.config()?,
        backend(),
        ProveNextLayerParams::default(),
    )?)
}
pub fn aggregate(
    owner: &Aggregator,
    proofs: [&Proof; 2],
    statements: &[[F; 2]; 2],
) -> Result<Proof> {
    Ok(owner
        .prove(
            TrustedPreparedInput::BatchStark {
                proof: proofs[0],
                statement: &statements[0],
            },
            TrustedPreparedInput::BatchStark {
                proof: proofs[1],
                statement: &statements[1],
            },
        )?
        .0)
}

pub fn encode_verifier(verifier: &CircuitVerifier<Config>) -> Result<Vec<u8>> {
    Ok(verifier.encode_verifier_artifact(ArtifactLimits::default())?)
}
pub fn encode_proof(verifier: &CircuitVerifier<Config>, proof: &Proof) -> Result<Vec<u8>> {
    Ok(verifier.encode_proof_artifact(proof, ArtifactLimits::default())?)
}
/// Only the independently provisioned verifier, exact expected statement and ONE
/// outer proof are needed. There is no child proof or original witness argument.
pub fn verify(trusted_verifier: &[u8], statement: &Statement, proof: &[u8]) -> Result<()> {
    let verifier = PortableVerifier::decode(
        trusted_verifier,
        ExpectedVerifierArtifact::from_trusted_bytes(trusted_verifier),
        ArtifactLimits::default(),
    )?;
    verifier.verify_encoded(proof, CanonicalStatement::new(&statement.bytes()?, 4))?;
    Ok(())
}
