//! Deferred current-only ring switching closed by WHIR's initial sumcheck.
use alloc::{vec, vec::Vec};

use p3_binary_field::{Poly64 as F, Poly192 as E};
use p3_challenger::{CanObserve, CanSampleUniformBits, FieldChallenger, GrindingChallenger};
use p3_circuit::ops::{ByteHash, NativePoly192Target, binary_encoding::NativeBinaryEncoding};
use p3_circuit::{CircuitBuilder, ExprId};
use p3_field::PrimeCharacteristicRing;
use p3_merkle_tree::MerkleCap;
use p3_multilinear_util::point::Point;
use p3_sumcheck::ring_switch::bits::BitTensor;
use p3_sumcheck::strategy::VariableOrder;
use p3_sumcheck::{OpeningBatch, OpeningProtocol, TableShape, TableSpec};
use p3_whir::{WhirConfig, pcs::proof::PcsProof};

use super::trace_native::route;
use super::trace_plan::TracePlan;
use super::trace_routing::TraceRouting;
use super::whir_kernel::{InitialWeight, verify_relation};
use super::whir_plan::invalid;
use super::{
    BinaryPolyWhirProofTargets, BinaryPolyWhirVerifier, ByteDigestMmcs, NativePolyBitTensorTarget,
    closing_weight_native_poly,
};
use crate::BinaryTower128Challenger;
use crate::verifier::binary_field_policy::{
    BinaryPolyPolicy, BinaryProtocolPolicy, BinaryRelationPolicy, NativePoly64Relation as P,
    poly_observe_seed_with_host,
};
use crate::verifier::{InputResourceUsage, VerificationError, VerifierLimits};

type H = NativeBinaryEncoding;

pub struct BinaryPolyDeferredWhirTraceVerifier {
    routing: TraceRouting<F, E>,
    opening: BinaryPolyWhirVerifier,
    seed: Vec<F>,
    usage: InputResourceUsage,
}

pub struct DeferredWhirTargets {
    pub values: Vec<NativePoly192Target>,
    pub tensors: Vec<NativePolyBitTensorTarget>,
    pub opening: BinaryPolyWhirProofTargets<NativePoly192Target, ExprId>,
}

impl BinaryPolyDeferredWhirTraceVerifier {
    /// `seed` must come from the trusted deferred ring-switch configuration, never the proof.
    /// Authenticate the compiled circuit, which binds this seed and the complete routing plan.
    pub fn new<C>(
        config: &WhirConfig<E, F, C>,
        protocol: OpeningProtocol,
        hash: ByteHash,
        cap_height: usize,
        seed: Vec<F>,
    ) -> Result<Self, VerificationError>
    where
        C: FieldChallenger<F> + GrindingChallenger<Witness = F>,
    {
        let limits = VerifierLimits::default();
        let variables = config
            .num_variables()
            .checked_add(6)
            .ok_or_else(|| invalid("deferred WHIR arity overflow"))?;
        let plan = TracePlan::with_value_limbs(protocol, variables, 12, &limits)?;
        if seed.is_empty()
            || plan
                .specs
                .iter()
                .any(|s| !s.current || s.next_rows.is_some())
        {
            return Err(invalid(
                "deferred WHIR requires current-only claims and a trusted seed",
            ));
        }
        config
            .validate_initial_claims(config.commitment_ood_samples() + 1)
            .map_err(|_| invalid("deferred WHIR initial claim security budget exceeded"))?;
        let opening = BinaryPolyWhirVerifier::new(
            config,
            OpeningProtocol::new(vec![TableSpec::new(
                TableShape::new(config.num_variables(), 1),
                vec![],
            )]),
            VariableOrder::Suffix,
            hash,
            cap_height,
        )?;
        let mut usage = plan.usage;
        usage.add_scalar_elements(
            &limits,
            plan.specs
                .len()
                .checked_mul(192 * 4)
                .ok_or_else(|| invalid("deferred tensor budget overflow"))?,
        )?;
        usage.add_metadata_entries(&limits, seed.len())?;
        usage.merge(&limits, opening.input_resource_usage())?;
        let routing = TraceRouting::new(plan)?;
        routing.native_runs()?;
        Ok(Self {
            routing,
            opening,
            seed,
            usage,
        })
    }

    pub const fn input_resource_usage(&self) -> InputResourceUsage {
        self.usage
    }

    pub fn allocate_native_targets(
        &self,
        b: &mut CircuitBuilder<F>,
    ) -> Result<DeferredWhirTargets, VerificationError> {
        let values = (0..self.routing.plan.value_count)
            .map(|_| {
                let coefficients = b.alloc_private_input_array::<3>("deferred trace value");
                b.check_construction_limits()?;
                Ok(b.native_poly192_from_coefficients(coefficients))
            })
            .collect::<Result<_, VerificationError>>()?;
        let tensors = (0..self.routing.plan.specs.len())
            .map(|_| {
                let rows = b
                    .alloc_private_input_array::<192>("deferred ring tensor")
                    .to_vec();
                b.check_construction_limits()?;
                Ok(NativePolyBitTensorTarget::from_rows(rows)?)
            })
            .collect::<Result<_, VerificationError>>()?;
        Ok(DeferredWhirTargets {
            values,
            tensors,
            opening: self.opening.input_shape().allocate_native_targets(b)?,
        })
    }

    pub fn observe_native_commitment<Ch>(
        &self,
        ch: &mut Ch,
        commitment: &MerkleCap<F, [u8; 32]>,
    ) -> Result<(), VerificationError>
    where
        Ch: CanObserve<F> + CanObserve<MerkleCap<F, [u8; 32]>>,
    {
        if commitment.roots().len() != self.opening.plan.cap_roots {
            return Err(invalid("incorrect deferred WHIR cap height"));
        }
        ch.observe_slice(&self.opening.plan.commitment_seed);
        ch.observe(commitment.clone());
        Ok(())
    }

    pub fn observe_commitment_native(
        &self,
        b: &mut CircuitBuilder<F>,
        ch: &mut BinaryTower128Challenger,
        cap: &[Vec<ExprId>],
    ) -> Result<(), VerificationError> {
        self.opening
            .observe_commitment_with_host::<H, F>(b, ch, cap)
    }

    pub fn verify_at_native(
        &self,
        b: &mut CircuitBuilder<F>,
        ch: BinaryTower128Challenger,
        cap: &[Vec<ExprId>],
        points: &[Vec<NativePoly192Target>],
        proof: &DeferredWhirTargets,
    ) -> Result<
        (
            Vec<OpeningBatch<NativePoly192Target>>,
            BinaryTower128Challenger,
        ),
        VerificationError,
    > {
        self.routing
            .check_points(points.iter().map(Vec::len), proof.values.len())?;
        if proof.tensors.len() != self.routing.plan.specs.len() {
            return Err(invalid("incorrect deferred tensor count"));
        }
        self.opening.check_targets(cap, &[], &proof.opening)?;
        let (readings, mut ch) = self.routing.bind_native(b, ch, points, &proof.values)?;
        poly_observe_seed_with_host::<H, F>(b, &mut ch, &self.seed)?;
        for (reading, tensor) in readings.iter().zip(&proof.tensors) {
            P::observe::<H>(b, &mut ch, &reading.point)?;
            P::observe_base::<H>(b, &mut ch, tensor.rows())?;
        }
        let batch = (0..8)
            .map(|_| P::sample::<H>(b, &mut ch))
            .collect::<Result<Vec<_>, _>>()?;
        let lambda = if readings.len() > 1 {
            P::sample::<H>(b, &mut ch)?
        } else {
            P::constant(b, 1)?
        };
        let high = self.routing.plan.num_variables - 6;
        let mut sums = Vec::with_capacity(readings.len());
        for (reading, tensor) in readings.iter().zip(&proof.tensors) {
            let current = tensor.clone().evaluate_columns(b, &reading.point[high..])?;
            P::assert_equal(
                b,
                reading.current.as_ref().expect("current-only route"),
                &current,
            );
            sums.push(tensor.evaluate_rows(b, &batch)?);
        }
        let sum = combine(b, &sums, &lambda);
        let weight = |b: &mut CircuitBuilder<F>, point: &[NativePoly192Target]| {
            let weights = readings
                .iter()
                .map(|reading| {
                    closing_weight_native_poly(b, &reading.point[..high], point, &batch, None)
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok(combine(b, &weights, &lambda))
        };
        let (_, ch) = verify_relation::<P, H, F>(
            &self.opening.plan,
            b,
            ch,
            cap,
            &[],
            &proof.opening,
            None,
            Some(InitialWeight {
                sum: &sum,
                evaluate: &weight,
            }),
        )?;
        Ok((self.routing.evals(&proof.values), ch))
    }

    /// Native replay extracts messages and authentication paths; the circuit enforces acceptance.
    pub fn import_native<C, Ch, M>(
        &self,
        config: &WhirConfig<E, F, C>,
        mmcs: &M,
        commitment: &MerkleCap<F, [u8; 32]>,
        points: &[Point<E>],
        values: &[E],
        tensors: &[BitTensor<E, F>],
        proof: &PcsProof<F, E, M>,
        target: &mut Ch,
    ) -> Result<Vec<F>, VerificationError>
    where
        C: FieldChallenger<F> + GrindingChallenger<Witness = F>,
        Ch: Clone
            + FieldChallenger<F>
            + CanSampleUniformBits<F>
            + GrindingChallenger<Witness = F>
            + CanObserve<MerkleCap<F, [u8; 32]>>,
        M: ByteDigestMmcs<F>,
    {
        self.routing
            .check_points(points.iter().map(Point::num_variables), values.len())?;
        if tensors.len() != self.routing.plan.specs.len()
            || tensors.iter().any(|t| !t.is_well_formed())
        {
            return Err(invalid("incorrect deferred tensor shape"));
        }
        self.opening.check_native_with_usage(
            config,
            mmcs,
            commitment,
            &[],
            proof,
            &mut InputResourceUsage::default(),
        )?;
        let mut ch = target.clone();
        let plan = &self.routing.plan;
        let captured =
            route::<F, E, _>(plan.num_variables, &plan.protocol, points, values, &mut ch)?;
        ch.observe_slice(&self.seed);
        for (opening, tensor) in captured.openings.iter().zip(tensors) {
            ch.observe_algebra_slice(opening.point.as_slice());
            ch.observe_slice(tensor.rows());
        }
        let batch = Point::new(
            (0..8)
                .map(|_| ch.sample_algebra_element::<E>())
                .collect::<Vec<_>>(),
        );
        let lambda: E = if tensors.len() > 1 {
            ch.sample_algebra_element()
        } else {
            E::ONE
        };
        let weights = batch.equality_weights_msb();
        let mut sum = E::ZERO;
        for ((opening, reading), tensor) in captured
            .openings
            .iter()
            .zip(&captured.readings)
            .zip(tensors)
            .rev()
        {
            let low = Point::new(&opening.point.as_slice()[plan.num_variables - 6..]);
            let current: E = tensor
                .columns()
                .iter()
                .zip(low.equality_weights_msb())
                .map(|(&v, w)| v * w)
                .sum();
            if reading.current != Some(current) || reading.next.is_some() {
                return Err(invalid("deferred tensor reading mismatch"));
            }
            let value: E = tensor
                .rows()
                .iter()
                .zip(&weights)
                .map(|(&v, &w)| w * v)
                .sum();
            sum = sum * lambda + value;
        }
        let packed = self.opening.import_native_with_weight(
            config,
            mmcs,
            commitment,
            &[],
            proof,
            &mut ch,
            Some(sum),
        )?;
        let mut private: Vec<_> = values.iter().flat_map(|v| v.coefficients()).collect();
        private.extend(tensors.iter().flat_map(|t| t.rows().iter().copied()));
        private.extend(packed.private_native_values(&self.opening.input_shape())?);
        *target = ch;
        Ok(private)
    }
}

fn combine(
    b: &mut CircuitBuilder<F>,
    values: &[NativePoly192Target],
    lambda: &NativePoly192Target,
) -> NativePoly192Target {
    values
        .iter()
        .rev()
        .fold(b.native_poly192_constant([0; 3]), |sum, value| {
            let product = b.native_poly192_mul(&sum, lambda);
            b.native_poly192_add(&product, value)
        })
}
