use anyhow::Result;
use clap::ValueEnum;
use p3_circuit_prover::BatchStarkProof;
use p3_field::extension::BinomialExtensionField;
use p3_koala_bear::KoalaBear;
use p3_recursion::artifact::ArtifactLimits;
use p3_recursion::backend::WhirRecursionBackendForExt;
use p3_recursion::builtin_config::{
    FriConfigV1, KoalaBearD4Poseidon2SaltedConfig, KoalaBearD4Poseidon2WhirConfig, SuiteIdV1,
    WhirConfigV1, WhirRateModeV1, WhirSecurityAssumptionV1, koala_bear_d4_poseidon2_salted,
    koala_bear_d4_poseidon2_whir,
};
use p3_recursion::{FriRecursionBackendForExt, Poseidon2Config};
use p3_uni_stark::Proof as UniStarkProof;
use rand::{SeedableRng, rngs::StdRng};
use serde::{Deserialize, Serialize};

pub const EXTENSION_DEGREE: usize = 4;
pub const OUTER_PROTOCOL: &str = "koalabear-d4-whir-johnson-v1";

pub type F = KoalaBear;
pub type E = BinomialExtensionField<F, EXTENSION_DEGREE>;
pub type Config = KoalaBearD4Poseidon2WhirConfig;
pub type ZkConfig = KoalaBearD4Poseidon2SaltedConfig<StdRng>;
pub type Proof = BatchStarkProof<Config>;
pub type ZkProof = UniStarkProof<ZkConfig>;
pub type ChildBackend = FriRecursionBackendForExt<EXTENSION_DEGREE, 16, 8, Poseidon2Config>;
pub type OuterBackend = WhirRecursionBackendForExt<EXTENSION_DEGREE, 16, 8>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub enum Profile {
    /// Reference parameters; no asserted composed bit-security bound.
    Reference,
    /// Four queries, no grinding. LOW SECURITY, tests only.
    Smoke,
}

impl Profile {
    pub fn descriptor(self, hiding: bool) -> FriConfigV1 {
        let (blowup, queries, pow) = match self {
            Self::Reference => (2, 128, 16),
            Self::Smoke => (1, 4, 0),
        };
        FriConfigV1::new(
            if hiding {
                SuiteIdV1::KoalaBearD4Poseidon2SaltedFri
            } else {
                SuiteIdV1::KoalaBearD4Poseidon2BinaryFri
            },
            blowup,
            0,
            2,
            queries,
            0,
            pow,
            0,
            0,
            if hiding { 4 } else { 0 },
            if hiding { 4 } else { 0 },
        )
    }

    pub fn config(self) -> Result<Config> {
        Ok(koala_bear_d4_poseidon2_whir(
            &self.whir_descriptor(),
            &ArtifactLimits::default().verifier,
        )?)
    }

    pub fn whir_descriptor(self) -> WhirConfigV1 {
        let (target, pow) = match self {
            Self::Reference => (88, 16),
            Self::Smoke => (8, 0),
        };
        WhirConfigV1::new(
            SuiteIdV1::KoalaBearD4Poseidon2Whir,
            2,
            WhirRateModeV1::Auto,
            4,
            WhirSecurityAssumptionV1::JohnsonBound.as_u16(),
            target,
            pow,
            24,
            0,
        )
    }

    /// Three independent OS-seeded CSPRNGs: input salts, FRI salts, masks.
    pub fn zk_config(self) -> Result<ZkConfig> {
        Ok(koala_bear_d4_poseidon2_salted(
            &self.descriptor(true),
            &ArtifactLimits::default().verifier,
            StdRng::from_rng(&mut rand::rng()),
            StdRng::from_rng(&mut rand::rng()),
            StdRng::from_rng(&mut rand::rng()),
        )?)
    }

    pub fn hiding_min_height(self) -> usize {
        // Reserve two extension-field opening points per masked column.
        (2 * (self.descriptor(true).num_queries() as usize + EXTENSION_DEGREE * 2))
            .next_power_of_two()
    }
}
