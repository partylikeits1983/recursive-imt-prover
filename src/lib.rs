//! SHA3-256 preimage proofs and a tree of stock Plonky3 recursive verifiers.
//! Both layers currently use non-hiding FRI: private inputs are NOT a ZK guarantee.
use anyhow::{Result, ensure};
use p3_circuit::{Circuit, CircuitBuilder, StatementExport};
use p3_circuit_prover::common::{NpoAirBuilder, NpoPreprocessor};
use p3_circuit_prover::{
    BatchStarkProof, BatchStarkProver, CircuitVerifier, ConstraintProfile, KeccakF1600AirBuilder,
    KeccakF1600Preprocessor, KeccakF1600Prover, PreparedCircuitProver, StatementAirBuilder,
    StatementPreprocessor, StatementProver, TablePacking,
};
use p3_field::{PrimeCharacteristicRing, PrimeField32, extension::QuinticTrinomialExtensionField};
use p3_recursion::artifact::{
    ArtifactLimits, CanonicalStatement, ExpectedVerifierArtifact, PortableArtifactExport,
    PortableArtifactImport, PortableVerifier, TypedArtifactVerifier, VerifiedArtifactProof,
};
use p3_recursion::builtin_config::{
    FriConfigV1, KoalaBearD5Poseidon2BinaryConfig, SuiteIdV1, koala_bear_d5_poseidon2_binary,
};
use p3_recursion::{
    BatchOnly, FriRecursionBackend, FriRecursionBackendD5, Poseidon2Config, ProveNextLayerParams,
    TrustedPreparedAggregation, TrustedPreparedInput, TrustedPreparedLayer, TrustedPreparedSource,
};
use serde::{Deserialize, Serialize};
use sha3::{Digest as _, Sha3_256};
use std::time::Instant;

pub type F = p3_koala_bear::KoalaBear;
pub type E = QuinticTrinomialExtensionField<F>;
pub type Config = KoalaBearD5Poseidon2BinaryConfig;
pub type Proof = BatchStarkProof<Config>;
pub type Backend = FriRecursionBackendD5<16, 8, Poseidon2Config>;
pub type Aggregator =
    TrustedPreparedAggregation<'static, 'static, Config, Config, BatchOnly, BatchOnly, Backend, 5>;
pub const PREIMAGE_BYTES: usize = 32;
pub const DIGEST_LIMBS: usize = 16;
pub const MAX_BATCH: usize = 8;
pub const RELATION: &str = "sha3-256-preimage-32-bytes-v1";

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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Digest(pub [u8; 32]);
impl TryFrom<String> for Digest {
    type Error = anyhow::Error;
    fn try_from(s: String) -> Result<Self> {
        ensure!(
            s.len() == 64
                && s.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "digest must be 64 lowercase hexadecimal characters"
        );
        Ok(Self(
            hex::decode(s)?
                .try_into()
                .map_err(|_| anyhow::anyhow!("digest length"))?,
        ))
    }
}
impl From<Digest> for String {
    fn from(d: Digest) -> Self {
        hex::encode(d.0)
    }
}
impl Digest {
    pub fn fields(self) -> [F; DIGEST_LIMBS] {
        core::array::from_fn(|i| {
            F::from_u16(u16::from_le_bytes([self.0[2 * i], self.0[2 * i + 1]]))
        })
    }
}
pub fn hash(preimage: &[u8; PREIMAGE_BYTES]) -> Digest {
    Digest(Sha3_256::digest(preimage).into())
}
pub fn check_count(count: usize) -> Result<()> {
    ensure!(
        (1..=MAX_BATCH).contains(&count),
        "batch size must be 1..={MAX_BATCH}"
    );
    Ok(())
}
/// Ordered digest list; count and order are authenticated by the fixed root verifier.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Statement {
    pub version: u32,
    pub relation: String,
    pub digests: Vec<Digest>,
}
impl Statement {
    pub fn new(digests: Vec<Digest>) -> Result<Self> {
        check_count(digests.len())?;
        Ok(Self {
            version: 1,
            relation: RELATION.into(),
            digests,
        })
    }
    pub fn fields(&self) -> Result<Vec<F>> {
        ensure!(
            self.version == 1 && self.relation == RELATION,
            "wrong statement relation/version"
        );
        check_count(self.digests.len())?;
        Ok(self.digests.iter().flat_map(|d| d.fields()).collect())
    }
    pub fn bytes(&self) -> Result<Vec<u8>> {
        Ok(field_bytes(&self.fields()?))
    }
}
pub fn field_bytes(fields: &[F]) -> Vec<u8> {
    fields
        .iter()
        .flat_map(|f| f.as_canonical_u32().to_le_bytes())
        .collect()
}

pub struct Leaf {
    pub circuit: Circuit<E>,
    pub prepared: PreparedCircuitProver<Config>,
}
impl Leaf {
    pub fn prepare(profile: Profile) -> Result<Self> {
        Self::prepare_with_suffix(profile, 0x06)
    }
    /// Test hook: suffix 0x01 gives Keccak-256, a distinct same-shape relation.
    pub fn prepare_with_suffix(profile: Profile, suffix: u16) -> Result<Self> {
        let mut b = CircuitBuilder::<E>::new();
        b.enable_keccak_f1600::<F>();
        let public = b.alloc_public_inputs(DIGEST_LIMBS, "SHA3-256 digest limbs");
        let mut state = b.alloc_private_inputs(PREIMAGE_BYTES / 2, "preimage limbs");
        // The ALU must create the private-input bus entries. Identity operations
        // fold away, so route each limb through the constrained identity 2*x/2.
        let two = b.alloc_const(E::TWO, "two");
        for limb in &mut state {
            let doubled = b.add(*limb, *limb);
            *limb = b.div(doubled, two);
        }
        // SHA3-256: 136-byte rate, 64-byte capacity, suffix 0x06, final bit 0x80.
        // Fixed 32-byte message: exactly ONE permutation, zero initial state.
        state.resize(100, b.alloc_const(E::ZERO, "zero state"));
        state[16] = b.alloc_const(E::from_u16(suffix), "domain suffix");
        state[67] = b.alloc_const(E::from_u16(0x8000), "final padding bit");
        let output = b.add_keccak_f1600(&state)?;
        for (&actual, &expected) in output[..DIGEST_LIMBS].iter().zip(&public) {
            b.connect(actual, expected);
        }
        let schema = b.set_statement_exports::<F>(
            &public
                .into_iter()
                .map(StatementExport::Base)
                .collect::<Vec<_>>(),
        )?;
        let circuit = b.build()?;
        let preprocessors: Vec<Box<dyn NpoPreprocessor<F>>> = vec![
            Box::new(KeccakF1600Preprocessor),
            Box::new(StatementPreprocessor::new(schema.clone())),
        ];
        let airs: Vec<Box<dyn NpoAirBuilder<Config, 5>>> = vec![
            Box::new(KeccakF1600AirBuilder::<5>),
            Box::new(StatementAirBuilder::<5>::new(schema.clone())),
        ];
        let mut prover = BatchStarkProver::new(profile.config()?)
            .with_table_packing(TablePacking::new(4, 4).with_min_trace_height(32));
        prover.register_table_prover(Box::new(KeccakF1600Prover::<5>));
        prover.register_table_prover(Box::new(StatementProver::<5>::new(schema)));
        let prepared = prover.prepare_circuit::<E, 5>(
            &circuit,
            &preprocessors,
            &airs,
            ConstraintProfile::Standard,
        )?;
        Ok(Self { circuit, prepared })
    }
    pub fn private_inputs(preimage: &[u8; PREIMAGE_BYTES]) -> Vec<E> {
        preimage
            .as_chunks::<2>()
            .0
            .iter()
            .map(|p| E::from_u16(u16::from_le_bytes([p[0], p[1]])))
            .collect()
    }
    /// There is deliberately no host hash/preimage check here: the circuit enforces it.
    pub fn prove(&self, preimage: &[u8; PREIMAGE_BYTES], digest: Digest) -> Result<Proof> {
        let mut runner = self.circuit.runner();
        runner.set_public_inputs(&digest.fields().map(E::from))?;
        runner.set_private_inputs(&Self::private_inputs(preimage))?;
        Ok(self.prepared.prove(&runner.run()?)?)
    }
    pub fn verifier(&self) -> CircuitVerifier<Config> {
        self.prepared.verifier()
    }
}

pub fn backend() -> Backend {
    FriRecursionBackend::<16, 8, _>::new_d5(Poseidon2Config::KOALA_BEAR_D1_W16)
}
/// No secrets in this input: only child proofs, statements and retained authority.
pub enum Node {
    Imported(Box<VerifiedArtifactProof<Config>>),
    Proved {
        proof: Box<Proof>,
        verifier: Box<CircuitVerifier<Config>>,
        statement: Vec<F>,
    },
}
impl Node {
    pub fn source(&self) -> TrustedPreparedSource<'static, '_, Config, BatchOnly> {
        match self {
            Self::Imported(p) => p.as_source(),
            Self::Proved {
                proof,
                verifier,
                statement,
            } => TrustedPreparedSource::BatchStark {
                proof,
                verifier: (**verifier).clone(),
                statement,
            },
        }
    }
    pub fn input(&self) -> TrustedPreparedInput<'_, Config> {
        match self {
            Self::Imported(p) => p.as_input(),
            Self::Proved {
                proof, statement, ..
            } => TrustedPreparedInput::BatchStark { proof, statement },
        }
    }
    pub fn statement(&self) -> &[F] {
        match self {
            Self::Imported(p) => p.statement(),
            Self::Proved { statement, .. } => statement,
        }
    }
    pub fn encode(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        match self {
            Self::Proved {
                proof, verifier, ..
            } => Ok((encode_verifier(verifier)?, encode_proof(verifier, proof)?)),
            Self::Imported(_) => anyhow::bail!("expected a freshly proved root"),
        }
    }
}
#[derive(Default, Debug, Serialize)]
pub struct AggregationMetrics {
    pub recursive_proofs: usize,
    pub prepare_ms: f64,
    pub prove_ms: f64,
}
/// Fixed topology for the trusted batch size: pair adjacent nodes, carry an odd
/// last node, repeat. Each merge verifies BOTH proofs and concatenates statements.
/// One child is wrapped in a one-child recursive circuit, never returned directly.
pub fn aggregate(
    mut nodes: Vec<Node>,
    profile: Profile,
    root_pin: Option<&[u8]>,
) -> Result<(Node, AggregationMetrics)> {
    check_count(nodes.len())?;
    ensure!(
        nodes.iter().all(|n| n.statement().len() == DIGEST_LIMBS),
        "expected leaf statements"
    );
    let mut metrics = AggregationMetrics::default();
    if nodes.len() == 1 {
        let child = nodes.pop().unwrap();
        let start = Instant::now();
        let owner = TrustedPreparedLayer::<Config, Config, BatchOnly, _, 5>::new(
            child.source(),
            profile.config()?,
            backend(),
            ProveNextLayerParams::default(),
        )?;
        let verifier = owner.verifier();
        check_pin(&verifier, root_pin)?;
        metrics.prepare_ms += start.elapsed().as_secs_f64() * 1e3;
        let start = Instant::now();
        let proof = owner.prove(child.input())?.0;
        metrics.prove_ms += start.elapsed().as_secs_f64() * 1e3;
        metrics.recursive_proofs = 1;
        return Ok((
            Node::Proved {
                proof: Box::new(proof),
                verifier: Box::new(verifier),
                statement: child.statement().to_vec(),
            },
            metrics,
        ));
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
            next.push(Node::Proved {
                proof: Box::new(proof),
                verifier: Box::new(verifier),
                statement,
            });
        }
        nodes = next;
    }
    Ok((nodes.pop().unwrap(), metrics))
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
pub fn importer(profile: Profile, pin: &[u8]) -> Result<TypedArtifactVerifier<Config>> {
    Ok(TypedArtifactVerifier::decode_with_config(
        profile.config()?,
        pin,
        ExpectedVerifierArtifact::from_trusted_bytes(pin),
        ArtifactLimits::default(),
    )?)
}
pub fn import_child(
    importer: &TypedArtifactVerifier<Config>,
    digest: Digest,
    bytes: &[u8],
) -> Result<Node> {
    let fields = digest.fields();
    Ok(Node::Imported(Box::new(importer.import_proof(
        bytes,
        CanonicalStatement::new(&field_bytes(&fields), DIGEST_LIMBS),
    )?)))
}
pub fn encode_verifier(verifier: &CircuitVerifier<Config>) -> Result<Vec<u8>> {
    Ok(verifier.encode_verifier_artifact(ArtifactLimits::default())?)
}
pub fn encode_proof(verifier: &CircuitVerifier<Config>, proof: &Proof) -> Result<Vec<u8>> {
    Ok(verifier.encode_proof_artifact(proof, ArtifactLimits::default())?)
}
pub fn verify(pin: &[u8], statement: &Statement, proof: &[u8]) -> Result<()> {
    let verifier = PortableVerifier::decode(
        pin,
        ExpectedVerifierArtifact::from_trusted_bytes(pin),
        ArtifactLimits::default(),
    )?;
    let fields = statement.fields()?;
    verifier.verify_encoded(
        proof,
        CanonicalStatement::new(&field_bytes(&fields), fields.len()),
    )?;
    Ok(())
}
