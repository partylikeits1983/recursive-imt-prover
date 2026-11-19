//! Authenticated verifier-only snapshots. No proving tables or child proofs are stored.
mod aggregate;
mod air;
pub use aggregate::{AUTHORITY_BYTES, RecursiveAggregate, RecursiveAuthority};
mod recursive;
mod recursive_air;
mod replay;
pub use recursive::RecursiveArithmetic;

use anyhow::{Result, ensure};
use old_binary_field::Poly64 as OldF;
use p3_field::PrimeCharacteristicRing;
use p3_flock::Circuit as BooleanCircuit;
use p3_multi_stark::{VerifierInstance, VerifierInstances, VerifyingKey, security_report, verify};
use p3_recursion::pcs::binary::CoordinateEncoding;
use p3_sumcheck::TableShape;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};

use self::air::VerifierAir;
use crate::{
    F, HashBackend, Prepared, Proof, WHIR_LOG_INV_RATE,
    air::convert,
    checkpoint,
    checkpoint_keccak::linked::LinkedBatch,
    config::{Config, RECURSIVE_PP_LOG_INV_RATE, challenger},
    encoding::TableEncoding,
    keccak,
};

pub const MAX_VERIFIER_BYTES: usize = 4 << 20;
const HALF_RATE_PP_FORMAT: &str = "imt-binary-trusted-verifier-v8";
const DIGIT_FORMAT: &str = "imt-binary-trusted-verifier-v7";
const BRIDGE_FORMAT: &str = "imt-binary-trusted-verifier-v6";
const WORD_FORMAT: &str = "imt-binary-trusted-verifier-v5";
const FORMAT: &str = "imt-binary-trusted-verifier-v4";

#[derive(Serialize, Deserialize)]
struct VerifierData<K> {
    format: String,
    backend: HashBackend,
    binding: Vec<u8>,
    seed: [u8; 32],
    airs: Vec<VerifierAir>,
    hash_index: usize,
    main_coordinates: Vec<Vec<usize>>,
    preprocessed_coordinates: Vec<Vec<usize>>,
    key: K,
}

impl<K> VerifierData<K> {
    fn preprocessed_encoding(&self) -> CoordinateEncoding {
        if matches!(self.format.as_str(), DIGIT_FORMAT | HALF_RATE_PP_FORMAT) {
            CoordinateEncoding::PreprocessedDigits
        } else {
            CoordinateEncoding::Bits
        }
    }

    fn preprocessed_log_inv_rate(&self) -> usize {
        if self.format == HALF_RATE_PP_FORMAT {
            RECURSIVE_PP_LOG_INV_RATE
        } else {
            WHIR_LOG_INV_RATE
        }
    }
}

pub struct Verifier {
    data: VerifierData<VerifyingKey<Config>>,
    hash: BooleanCircuit,
    config: Config,
    public_count: usize,
    checkpoint: Option<LinkedBatch>,
}

/// The expected digest must come from trusted verifier data, never from the proof.
pub fn verifier_key_digest(bytes: &[u8]) -> [u8; 32] {
    let mut hash = Keccak256::new();
    hash.update(FORMAT.as_bytes());
    hash.update((bytes.len() as u64).to_le_bytes());
    hash.update(bytes);
    hash.finalize().into()
}

impl Prepared {
    pub fn export_verifier(&self, binding: &[u8]) -> Result<Vec<u8>> {
        let airs = self
            .airs
            .iter()
            .zip(&self.log_heights)
            .map(|(air, &log)| VerifierAir::capture(air, log))
            .collect::<Result<Vec<_>>>()?;
        // Borrow the succinct commitment; no proving tables are serialized.
        let data = VerifierData {
            format: if self.direct_bridge {
                HALF_RATE_PP_FORMAT
            } else {
                FORMAT
            }
            .to_owned(),
            backend: self.backend,
            binding: binding.to_vec(),
            seed: self
                .seed
                .as_slice()
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid seed length"))?,
            airs,
            hash_index: self.hash_index,
            main_coordinates: self.geometry.main_coordinate_widths.clone(),
            preprocessed_coordinates: self.geometry.preprocessed_coordinate_widths.clone(),
            key: &self.vk,
        };
        let bytes = postcard::to_allocvec(&data)?;
        ensure!(
            bytes.len() <= MAX_VERIFIER_BYTES,
            "oversized trusted verifier"
        );
        Ok(bytes)
    }
}

impl Verifier {
    pub fn require_same_layout(&self, output: &Prepared) -> Result<()> {
        ensure!(
            self.data.backend == output.backend
                && self.data.format
                    == if output.direct_bridge {
                        HALF_RATE_PP_FORMAT
                    } else {
                        FORMAT
                    }
                && self.data.hash_index == output.hash_index
                && self.data.main_coordinates == output.geometry.main_coordinate_widths
                && self.data.preprocessed_coordinates
                    == output.geometry.preprocessed_coordinate_widths
                && self.data.airs.len() == output.airs.len(),
            "recursive proof layouts differ"
        );
        for (index, ((air, &height), expected)) in output
            .airs
            .iter()
            .zip(&output.log_heights)
            .zip(&self.data.airs)
            .enumerate()
        {
            let actual = VerifierAir::capture(air, height)?;
            ensure!(
                postcard::to_allocvec(&actual)? == postcard::to_allocvec(expected)?,
                "recursive verifier equations or shape differ at table {index}"
            );
        }
        Ok(())
    }

    /// Load only after checking an independently trusted digest and authority identity.
    /// A matching digest authenticates the AIR, preprocessing commitment, layout and binding.
    pub fn from_bytes(
        bytes: &[u8],
        expected_digest: &[u8; 32],
        expected_identity: &str,
        binding: &[u8],
    ) -> Result<Self> {
        ensure!(
            bytes.len() <= MAX_VERIFIER_BYTES,
            "oversized trusted verifier"
        );
        ensure!(
            &verifier_key_digest(bytes) == expected_digest,
            "trusted verifier digest mismatch"
        );
        let (data, rest): (VerifierData<VerifyingKey<Config>>, _) =
            postcard::take_from_bytes(bytes)?;
        ensure!(rest.is_empty(), "trailing trusted verifier data");
        ensure!(
            (data.format == FORMAT
                || (matches!(
                    data.format.as_str(),
                    WORD_FORMAT | BRIDGE_FORMAT | DIGIT_FORMAT | HALF_RATE_PP_FORMAT
                ) && data.backend == HashBackend::Checkpoint))
                && data.binding == binding,
            "trusted verifier configuration mismatch"
        );
        ensure!(
            hex::encode(data.seed) == expected_identity,
            "trusted verifier identity mismatch"
        );
        ensure!(
            !data.airs.is_empty() && data.airs.len() <= 128 && data.hash_index < data.airs.len(),
            "invalid trusted AIR count"
        );
        ensure!(
            data.main_coordinates.len() == data.airs.len(),
            "invalid main encoding count"
        );
        for air in &data.airs {
            ensure!(
                air.log_height <= 30
                    && (1..=8192).contains(&air.width)
                    && air.preprocessed_width <= 1024
                    && air.public_count <= 4096,
                "invalid trusted AIR shape"
            );
        }
        let hash = keccak::circuit();
        let shapes: Vec<_> = data
            .airs
            .iter()
            .enumerate()
            .map(|(i, air)| {
                if i == data.hash_index && data.backend == HashBackend::Flock {
                    TableShape::new(air.log_height + hash.k_log(), 1)
                } else {
                    TableShape::new(air.log_height, air.width)
                }
            })
            .collect();
        let pp: Vec<_> = data
            .airs
            .iter()
            .filter(|a| a.preprocessed_width > 0)
            .map(|a| TableShape::new(a.log_height, a.preprocessed_width))
            .collect();
        ensure!(
            data.preprocessed_coordinates.len() == pp.len(),
            "invalid preprocessing encoding count"
        );
        for (shape, widths) in shapes
            .iter()
            .zip(&data.main_coordinates)
            .chain(pp.iter().zip(&data.preprocessed_coordinates))
        {
            ensure!(shape.width() == widths.len(), "invalid encoding width");
        }
        let config = Config::new(
            &shapes,
            data.main_coordinates
                .iter()
                .cloned()
                .map(|w| TableEncoding::with_word_openings(w, data.format != FORMAT))
                .collect::<Result<_>>()?,
            &pp,
            data.preprocessed_coordinates
                .iter()
                .cloned()
                .zip(&pp)
                .map(|(widths, shape)| {
                    TableEncoding::with_encoding(
                        widths,
                        shape.num_variables(),
                        data.preprocessed_encoding(),
                    )
                })
                .collect::<Result<_>>()?,
            data.preprocessed_log_inv_rate(),
        )?;
        let public_count = data.airs.iter().map(|a| a.public_count).max().unwrap();
        ensure!(
            data.airs
                .iter()
                .all(|a| a.public_count == 0 || a.public_count == public_count),
            "inconsistent public input mapping"
        );
        let checkpoint = if data.backend == HashBackend::Checkpoint {
            ensure!(
                data.airs[data.hash_index].width == 232,
                "invalid native Keccak port count"
            );
            let scheme = LinkedBatch::with_bridge(
                data.airs[data.hash_index].log_height,
                config.main_log2_candidates,
                matches!(
                    data.format.as_str(),
                    BRIDGE_FORMAT | DIGIT_FORMAT | HALF_RATE_PP_FORMAT
                ),
            )?;
            ensure!(
                config.initial_codeword_cells + scheme.initial_codeword_cells <= 1 << 30,
                "arithmetic and checkpoint codewords exceed this prototype's budget"
            );
            Some(scheme)
        } else {
            None
        };
        let verifier = Self {
            data,
            hash,
            config,
            public_count,
            checkpoint,
        };
        let public: Vec<Vec<F>> = verifier
            .data
            .airs
            .iter()
            .map(|a| vec![F::ZERO; a.public_count])
            .collect();
        let report = security_report(&verifier.config, &verifier.instances(&public))?;
        ensure!(
            report.unassessed_components().is_empty(),
            "unassessed cached verifier security component"
        );
        let mut error: f64 = report
            .terms()
            .iter()
            .filter(|term| term.label != "commitment-and-transcript-collision")
            .map(|term| 2f64.powf(-term.bits.bits()))
            .sum();
        if let Some(checkpoint) = &verifier.checkpoint {
            error += 2f64.powf(-checkpoint.conditional_algebraic_bits);
        }
        ensure!(
            -error.log2() >= 144.0,
            "cached verifier algebraic bound below 144 bits"
        );
        Ok(verifier)
    }

    pub fn verify(&self, bytes: &[u8], public: &[OldF]) -> Result<()> {
        ensure!(
            public.len() == self.public_count,
            "incorrect public input count"
        );
        ensure!(bytes.len() <= 16 << 20, "oversized aggregate proof");
        let public: Vec<Vec<F>> = self
            .data
            .airs
            .iter()
            .map(|a| {
                if a.public_count == 0 {
                    vec![]
                } else {
                    public.iter().copied().map(convert).collect()
                }
            })
            .collect();
        if let Some(scheme) = &self.checkpoint {
            return checkpoint::verify(
                &self.config,
                self.instances(&public),
                scheme,
                &self.data.seed,
                self.data.hash_index,
                bytes,
            );
        }
        let proof: Proof = crate::proof_codec::decode(bytes)?;
        verify(
            &self.config,
            self.instances(&public),
            &proof,
            0,
            &mut challenger(&self.data.seed),
        )?;
        Ok(())
    }
    fn instances<'a>(&'a self, public: &'a [Vec<F>]) -> VerifierInstances<'a, Config, VerifierAir> {
        VerifierInstances::new(
            self.data
                .airs
                .iter()
                .enumerate()
                .map(|(i, air)| {
                    if i == self.data.hash_index && self.data.backend == HashBackend::Flock {
                        VerifierInstance::circuit(
                            air,
                            &self.hash,
                            &self.data.key,
                            air.log_height,
                            &public[i],
                        )
                    } else {
                        VerifierInstance::new(air, &self.data.key, air.log_height, &public[i])
                    }
                })
                .collect(),
        )
    }
}
