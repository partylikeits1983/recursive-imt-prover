use old_binary_field::Poly192;

use super::{
    BITS, BinaryPolyGenericSumcheckProofTargets, BinaryPolyGenericSumcheckVerifier,
    BinaryTower128Challenger, CF, CircuitBuilder, ClaimTarget, ExprId, NativePoly192Target,
    POSITION_LOG, PreparedVerifier, ProofTargets, Result, connect, equality_weights, sample,
};

pub struct CommittedInput {
    pub private_values: Vec<CF>,
    pub points: [Vec<Poly192>; 2],
    pub opening: Vec<u8>,
}

pub struct CommittedTargets {
    output: NativePoly192Target,
    reduction: ProofTargets,
    closing: BinaryPolyGenericSumcheckProofTargets<NativePoly192Target, ExprId>,
}

/// These claims require a PCS check against the commitment observed before reduction.
#[must_use]
pub struct BoundaryReduction {
    pub points: [Vec<NativePoly192Target>; 2],
    pub challenger: BinaryTower128Challenger,
    output: NativePoly192Target,
    weight: NativePoly192Target,
    product: NativePoly192Target,
}

pub struct PreparedCommittedVerifier {
    log_batch: usize,
    reduction: PreparedVerifier,
    closing: BinaryPolyGenericSumcheckVerifier,
}

impl PreparedCommittedVerifier {
    pub fn new(log_batch: usize) -> Result<Self> {
        Self::with_packing(log_batch, false)
    }

    pub(super) fn with_packing(log_batch: usize, packed: bool) -> Result<Self> {
        Ok(Self {
            log_batch,
            reduction: PreparedVerifier::with_packing(log_batch, packed)?,
            closing: BinaryPolyGenericSumcheckVerifier::new(
                POSITION_LOG + 4 * usize::from(packed),
                2,
                0,
            )?,
        })
    }

    pub fn allocate(&self, b: &mut CircuitBuilder<CF>) -> Result<CommittedTargets> {
        let coefficients = b.alloc_private_input_array::<3>("committed Keccak output");
        Ok(CommittedTargets {
            output: b.native_poly192_from_coefficients(coefficients),
            reduction: self.reduction.allocate(b)?,
            closing: self.closing.input_shape().allocate_native_targets(b)?,
        })
    }

    /// The caller must already have observed the input/output commitment in `ch`.
    pub fn verify_reduction(
        &self,
        b: &mut CircuitBuilder<CF>,
        mut ch: BinaryTower128Challenger,
        proof: &CommittedTargets,
    ) -> Result<BoundaryReduction> {
        let instance = (0..self.log_batch)
            .map(|_| sample(b, &mut ch))
            .collect::<Result<Vec<_>>>()?;
        let position = (0..POSITION_LOG)
            .map(|_| sample(b, &mut ch))
            .collect::<Result<Vec<_>>>()?;
        let mut weights = equality_weights(b, &position);
        weights.truncate(BITS);
        let output = ClaimTarget {
            instance: instance.clone(),
            weights,
            value: proof.output.clone(),
        };
        let super::FactoredReduction {
            instance: mut input_point,
            weights,
            lanes,
            value,
            challenger: ch,
        } = self
            .reduction
            .verify_factored(b, ch, &output, &proof.reduction)?;
        let closing = self
            .closing
            .verify_reduction_native(b, ch, &value, &proof.closing)?;
        let weight = if lanes.is_empty() {
            weights.evaluate(b, &closing.point)
        } else {
            let (i, z) = closing.point.split_at(4);
            let eq = equality_weights(b, i);
            let lane = crate::checkpoint_keccak::packed::circuit::dot(b, &lanes, &eq);
            let bit = weights.evaluate(b, z);
            b.native_poly192_mul(&lane, &bit)
        };
        input_point.extend(closing.point);
        let mut output_point = instance;
        output_point.extend(position);
        Ok(BoundaryReduction {
            points: [input_point, output_point],
            challenger: closing.challenger,
            output: proof.output.clone(),
            weight,
            product: closing.claim,
        })
    }
}

impl BoundaryReduction {
    pub fn authenticate(
        &self,
        b: &mut CircuitBuilder<CF>,
        input: &NativePoly192Target,
        output: &NativePoly192Target,
    ) {
        let product = b.native_poly192_mul(&self.weight, input);
        connect(b, &product, &self.product);
        connect(b, output, &self.output);
    }
}
