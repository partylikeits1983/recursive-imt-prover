use alloc::vec::Vec;

use p3_air::Air;
use p3_binary_field::{Poly64 as F, Poly192 as E};
use p3_bus::{BusProof, BusSymbolicBuilder};
use p3_challenger::{CanObserve, FieldChallenger, GrindingChallenger};
use p3_circuit::{
    CircuitBuilder, ExprId,
    ops::{ByteHash, NativePoly192Target, binary_encoding::NativeBinaryEncoding, bytes_to_limbs},
};
use p3_lookup::InteractionSymbolicBuilder;
use p3_merkle_tree::MerkleCap;
use p3_multilinear_util::point::Point;
use p3_sumcheck::{OpeningBatch, generic_degree::GenericDegreeProof};
use p3_whir::WhirConfig;

use super::super::{
    BinaryPolyProductGkrProofTargets, VerificationError, VerifierLimits,
    binary_field_policy::NativePoly64Relation,
};
use super::relation::{PolyMultiStarkRelation, PolyRelationProof};
use crate::{
    BinaryTower128Challenger,
    pcs::binary::{
        BinaryPolyCoordinateOpeningPlan, BinaryPolyDeferredWhirTraceVerifier,
        BinaryPolyGenericSumcheckProofTargets, DeferredWhirTargets,
    },
};

pub struct CoordinatePcsParameters<'a, C> {
    pub config: &'a WhirConfig<E, F, C>,
    pub widths: &'a [Vec<usize>],
    pub cap_height: usize,
    pub ring_seed: Vec<F>,
}

struct OpeningVerifier {
    columns: BinaryPolyCoordinateOpeningPlan,
    pcs: BinaryPolyDeferredWhirTraceVerifier,
}

pub struct BinaryPolyCoordinateWhirVerifier {
    relation: PolyMultiStarkRelation,
    main: OpeningVerifier,
    preprocessed: Option<(OpeningVerifier, MerkleCap<F, [u8; 32]>)>,
    cap_roots: usize,
}

pub struct CoordinateWhirTargets {
    pub commitment: Vec<Vec<ExprId>>,
    pub bus: Option<BinaryPolyProductGkrProofTargets<NativePoly192Target>>,
    pub sumcheck: BinaryPolyGenericSumcheckProofTargets<NativePoly192Target, ExprId>,
    pub main: DeferredWhirTargets,
    pub preprocessed: Option<DeferredWhirTargets>,
}

pub struct CoordinateWhirInput {
    pub private_values: Vec<F>,
    pub main_points: Vec<Point<E>>,
    pub preprocessed_points: Option<Vec<Point<E>>>,
}

pub struct AuthenticatedCoordinateOpenings {
    pub point: Vec<NativePoly192Target>,
    pub main: Vec<OpeningBatch<NativePoly192Target>>,
    pub challenger: BinaryTower128Challenger,
}

impl BinaryPolyCoordinateWhirVerifier {
    pub fn new<A, C>(
        airs: &[&A],
        heights: &[usize],
        main: CoordinatePcsParameters<'_, C>,
        preprocessing: Option<(CoordinatePcsParameters<'_, C>, MerkleCap<F, [u8; 32]>)>,
        limits: &VerifierLimits,
    ) -> Result<Self, VerificationError>
    where
        A: Air<InteractionSymbolicBuilder<F, E>> + Air<BusSymbolicBuilder<F, E>>,
        C: FieldChallenger<F> + GrindingChallenger<Witness = F>,
    {
        Self::with_word_openings(airs, heights, main, preprocessing, limits, false)
    }

    pub fn with_word_openings<A, C>(
        airs: &[&A],
        heights: &[usize],
        main: CoordinatePcsParameters<'_, C>,
        preprocessing: Option<(CoordinatePcsParameters<'_, C>, MerkleCap<F, [u8; 32]>)>,
        limits: &VerifierLimits,
        fold_main: bool,
    ) -> Result<Self, VerificationError>
    where
        A: Air<InteractionSymbolicBuilder<F, E>> + Air<BusSymbolicBuilder<F, E>>,
        C: FieldChallenger<F> + GrindingChallenger<Witness = F>,
    {
        let (relation, main_protocol, pp_protocol) = PolyMultiStarkRelation::build(
            airs,
            heights,
            0,
            heights.iter().copied().max().unwrap_or(0).saturating_add(2),
            preprocessing.is_some(),
            limits,
        )?;
        if relation.indexed.is_some() {
            return Err(invalid(
                "coordinate verifier does not support indexed lookups",
            ));
        }
        let build = |protocol, parameters: CoordinatePcsParameters<'_, C>, fold| {
            let columns = BinaryPolyCoordinateOpeningPlan::with_word_openings(
                &protocol,
                parameters.widths,
                fold,
            )?;
            let pcs = BinaryPolyDeferredWhirTraceVerifier::new(
                parameters.config,
                columns.protocol().clone(),
                ByteHash::Keccak256,
                parameters.cap_height,
                parameters.ring_seed,
            )?;
            Ok::<_, VerificationError>(OpeningVerifier { columns, pcs })
        };
        let cap_roots = 1usize
            .checked_shl(main.cap_height as u32)
            .filter(|&n| n <= limits.max_cap_roots)
            .ok_or_else(|| invalid("invalid coordinate cap height"))?;
        let main = build(main_protocol, main, fold_main)?;
        let preprocessed = match (preprocessing, pp_protocol) {
            (Some((parameters, cap)), Some(protocol)) => {
                if parameters.cap_height >= usize::BITS as usize
                    || cap.roots().len() != 1 << parameters.cap_height
                {
                    return Err(invalid("incorrect preprocessing cap size"));
                }
                Some((build(protocol, parameters, false)?, cap))
            }
            (None, None) => None,
            _ => return Err(invalid("coordinate preprocessing mismatch")),
        };
        Ok(Self {
            relation,
            main,
            preprocessed,
            cap_roots,
        })
    }

    pub fn allocate(
        &self,
        b: &mut CircuitBuilder<F>,
    ) -> Result<CoordinateWhirTargets, VerificationError> {
        Ok(CoordinateWhirTargets {
            commitment: (0..self.cap_roots)
                .map(|_| {
                    b.alloc_private_input_array::<16>("arithmetic commitment")
                        .to_vec()
                })
                .collect(),
            bus: self
                .relation
                .input
                .bus
                .as_ref()
                .map(|v| v.product.allocate_native_targets(b))
                .transpose()?,
            sumcheck: self.relation.input.sumcheck.allocate_native_targets(b)?,
            main: self.main.pcs.allocate_native_targets(b)?,
            preprocessed: self
                .preprocessed
                .as_ref()
                .map(|(v, _)| v.pcs.allocate_native_targets(b))
                .transpose()?,
        })
    }

    pub fn main_pcs(&self) -> &BinaryPolyDeferredWhirTraceVerifier {
        &self.main.pcs
    }

    pub fn preprocessed_pcs(
        &self,
    ) -> Option<(
        &BinaryPolyDeferredWhirTraceVerifier,
        &MerkleCap<F, [u8; 32]>,
    )> {
        self.preprocessed.as_ref().map(|(v, c)| (&v.pcs, c))
    }

    pub fn verify_native(
        &self,
        b: &mut CircuitBuilder<F>,
        ch: BinaryTower128Challenger,
        public: &[Vec<ExprId>],
        proof: &CoordinateWhirTargets,
    ) -> Result<AuthenticatedCoordinateOpenings, VerificationError> {
        let pp_cap = self.preprocessed.as_ref().map(|(_, cap)| {
            cap.roots()
                .iter()
                .map(|r| {
                    bytes_to_limbs(r)
                        .into_iter()
                        .map(|v| b.define_const(F::new(u64::from(v))))
                        .collect()
                })
                .collect::<Vec<Vec<_>>>()
        });
        self.verify_native_with_preprocessed(b, ch, public, proof, pp_cap.as_deref())
    }

    /// The caller must authenticate `pp_cap`; the AIR and PCS layouts remain fixed.
    pub fn verify_native_with_preprocessed(
        &self,
        b: &mut CircuitBuilder<F>,
        mut ch: BinaryTower128Challenger,
        public: &[Vec<ExprId>],
        proof: &CoordinateWhirTargets,
        pp_cap: Option<&[Vec<ExprId>]>,
    ) -> Result<AuthenticatedCoordinateOpenings, VerificationError> {
        let common = PolyRelationProof {
            bus: proof.bus.as_ref(),
            sumcheck: &proof.sumcheck,
            indexed: None,
        };
        self.relation.check_targets(public, &common)?;
        if proof.commitment.len() != self.cap_roots
            || self.preprocessed.is_some() != proof.preprocessed.is_some()
            || self.preprocessed.is_some() != pp_cap.is_some()
            || self
                .preprocessed
                .as_ref()
                .zip(pp_cap)
                .is_some_and(|((_, expected), cap)| {
                    cap.len() != expected.roots().len() || cap.iter().any(|root| root.len() != 16)
                })
        {
            return Err(invalid(
                "coordinate proof or preprocessing cap shape mismatch",
            ));
        }
        self.relation
            .observe_prefix_with_host::<NativeBinaryEncoding, F>(b, &mut ch, pp_cap)?;
        self.main
            .pcs
            .observe_commitment_native(b, &mut ch, &proof.commitment)?;
        let mut reduction = self
            .relation
            .reduce_common::<NativePoly64Relation, NativeBinaryEncoding, F>(
                b, ch, public, &common,
            )?;
        self.relation.set_unindexed_points(&mut reduction);
        let points = self
            .main
            .columns
            .opening_points(&reduction.main_points, |raw| {
                b.native_poly192_constant([raw, 0, 0])
            })?;
        let (coordinates, mut ch) = self.main.pcs.verify_at_native(
            b,
            reduction.challenger.clone(),
            &proof.commitment,
            &points,
            &proof.main,
        )?;
        let main = self.main.columns.recombine_native(b, &coordinates)?;
        let pp = if let (Some((verifier, _)), Some(cap), Some(proof), Some(points)) = (
            &self.preprocessed,
            pp_cap,
            proof.preprocessed.as_ref(),
            reduction.preprocessed_points.as_ref(),
        ) {
            let (coordinates, next) = verifier.pcs.verify_at_native(b, ch, cap, points, proof)?;
            ch = next;
            Some(verifier.columns.recombine_native(b, &coordinates)?)
        } else {
            None
        };
        self.relation.finish_common::<NativePoly64Relation, F>(
            b,
            public,
            &reduction,
            &main,
            pp.as_deref(),
        )?;
        Ok(AuthenticatedCoordinateOpenings {
            point: reduction.point,
            main,
            challenger: ch,
        })
    }

    /// Import arithmetic messages, then append main and preprocessing PCS witnesses in order.
    /// The circuit, not this import, authenticates the reduced AIR and bus claims.
    pub fn import_reduction<C>(
        &self,
        cap: &MerkleCap<F, [u8; 32]>,
        public: &[Vec<F>],
        bus: Option<&BusProof<E>>,
        sumcheck: &GenericDegreeProof<F, E>,
        ch: &mut C,
    ) -> Result<CoordinateWhirInput, VerificationError>
    where
        C: FieldChallenger<F>
            + GrindingChallenger<Witness = F>
            + CanObserve<MerkleCap<F, [u8; 32]>>
            + Clone,
    {
        self.relation
            .observe_native_prefix(ch, self.preprocessed.as_ref().map(|(_, cap)| cap));
        self.main.pcs.observe_native_commitment(ch, cap)?;
        let reduction = self
            .relation
            .reduce_native_parts(public, bus, sumcheck, ch)?;
        let mut private_values: Vec<_> = cap
            .roots()
            .iter()
            .flat_map(|r| bytes_to_limbs(r).into_iter().map(|v| F::new(u64::from(v))))
            .collect();
        if let (Some(bus), Some(shape)) = (reduction.bus, &self.relation.input.bus) {
            private_values.extend(bus.private_native_values(&shape.product)?);
        }
        private_values.extend(
            reduction
                .sumcheck
                .private_native_values(&self.relation.input.sumcheck)?,
        );
        let heights: Vec<_> = self
            .relation
            .input
            .airs
            .iter()
            .map(|a| a.log_height())
            .collect();
        let logical =
            self.relation
                .input
                .main_schedule
                .points(&heights, reduction.point.as_slice(), None);
        let main_points = self
            .main
            .columns
            .opening_points(&logical, |v| E::from(F::new(v)))?
            .into_iter()
            .map(Point::new)
            .collect();
        let preprocessed_points = self.relation.input.preprocessed_schedule.as_ref().map(|s| {
            s.points(&heights, reduction.point.as_slice(), None)
                .into_iter()
                .map(Point::new)
                .collect()
        });
        Ok(CoordinateWhirInput {
            private_values,
            main_points,
            preprocessed_points,
        })
    }
}

fn invalid(message: &'static str) -> VerificationError {
    VerificationError::InvalidProofShape(message.into())
}
