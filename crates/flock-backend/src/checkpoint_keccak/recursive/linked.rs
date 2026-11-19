use old_binary_field::Poly192;
use p3_circuit::ops::{binary_encoding::NativeBinaryEncoding, binary_host::BinaryCircuitHost};

use super::{
    BinaryPolyGenericSumcheckProofTargets, BinaryPolyGenericSumcheckVerifier,
    BinaryTower128Challenger, BoundaryReduction, CF, CircuitBuilder, CommittedTargets, ExprId,
    NativePoly192Target, POSITION_LOG, PreparedCommittedVerifier, Result, connect,
    equality_weights, observe, sample,
};
use crate::checkpoint_keccak::{
    linked::port_domain,
    ports::{BRIDGE_LIMBS, PORT_LOG, PORTS, location},
};
use anyhow::ensure;

pub struct PortTargets {
    pub instance: Vec<NativePoly192Target>,
    pub values: Vec<NativePoly192Target>,
}

pub struct LinkedInput {
    pub private_values: Vec<CF>,
    pub points: [Vec<Poly192>; 4],
    pub opening: Vec<u8>,
}

pub struct LinkedTargets {
    boundary: CommittedTargets,
    ports: BinaryPolyGenericSumcheckProofTargets<NativePoly192Target, ExprId>,
}

/// The caller must authenticate the port inputs through the arithmetic proof.
pub struct PreparedLinkedVerifier {
    direct_bridge: bool,
    log_batch: usize,
    boundary: PreparedCommittedVerifier,
    closing: BinaryPolyGenericSumcheckVerifier,
}

#[must_use]
pub struct LinkedReduction {
    pub points: [Vec<NativePoly192Target>; 4],
    pub challenger: BinaryTower128Challenger,
    boundary: BoundaryReduction,
    selector: NativePoly192Target,
    weight: NativePoly192Target,
    product: NativePoly192Target,
}

impl PreparedLinkedVerifier {
    pub fn new(log_batch: usize) -> Result<Self> {
        Self::with_bridge(log_batch, false)
    }

    pub(crate) fn with_bridge(log_batch: usize, direct_bridge: bool) -> Result<Self> {
        Ok(Self {
            direct_bridge,
            log_batch,
            boundary: PreparedCommittedVerifier::new(log_batch)?,
            closing: BinaryPolyGenericSumcheckVerifier::new(POSITION_LOG + 1, 2, 0)?,
        })
    }

    /// The enclosing verifier uses this seed before its arithmetic commitment and row challenges.
    /// It must separately authenticate the authority bytes.
    pub fn arithmetic_seed(
        &self,
        b: &mut CircuitBuilder<CF>,
        authority: &[ExprId],
        cap: &[Vec<ExprId>],
    ) -> Result<[ExprId; 32]> {
        ensure!(
            !cap.is_empty() && cap.len().is_power_of_two() && cap.iter().all(|r| r.len() == 16),
            "incorrect boundary cap shape"
        );
        let prefix = [
            port_domain(self.direct_bridge),
            &(authority.len() as u64).to_le_bytes(),
        ]
        .concat();
        let suffix = [
            (self.log_batch as u64).to_le_bytes(),
            (cap.len() as u64).to_le_bytes(),
        ]
        .concat();
        let mut bytes: Vec<_> = prefix
            .iter()
            .map(|&v| b.define_const(CF::new(u64::from(v))))
            .collect();
        bytes.extend_from_slice(authority);
        bytes.extend(
            suffix
                .iter()
                .map(|&v| b.define_const(CF::new(u64::from(v)))),
        );
        bytes.extend(NativeBinaryEncoding::bytes_from_words(b, &cap.concat())?);
        Ok(b.native_keccak256_bytes(&bytes)?)
    }

    pub fn transcript_seed(
        &self,
        b: &mut CircuitBuilder<CF>,
        authority: &[ExprId],
    ) -> Result<[ExprId; 32]> {
        ensure!(
            authority.len() == 32,
            "incorrect recursive authority length"
        );
        let prefix = [
            port_domain(self.direct_bridge),
            &(self.log_batch as u64).to_le_bytes(),
        ]
        .concat();
        let mut bytes: Vec<_> = prefix
            .iter()
            .map(|&byte| b.define_const(CF::new(u64::from(byte))))
            .collect();
        bytes.extend_from_slice(authority);
        Ok(b.native_keccak256_bytes(&bytes)?)
    }

    pub fn allocate(&self, b: &mut CircuitBuilder<CF>) -> Result<LinkedTargets> {
        Ok(LinkedTargets {
            boundary: self.boundary.allocate(b)?,
            ports: self.closing.input_shape().allocate_native_targets(b)?,
        })
    }

    /// The boundary commitment must enter `ch` before this reduction.
    pub fn verify_reduction(
        &self,
        b: &mut CircuitBuilder<CF>,
        mut ch: BinaryTower128Challenger,
        ports: &PortTargets,
        proof: &LinkedTargets,
    ) -> Result<LinkedReduction> {
        ensure!(
            ports.instance.len() == self.log_batch + usize::from(self.direct_bridge)
                && ports.values.len()
                    == if self.direct_bridge {
                        BRIDGE_LIMBS
                    } else {
                        PORTS
                    },
            "incorrect port input shape"
        );
        for value in ports.instance.iter().chain(&ports.values) {
            observe(b, &mut ch, value)?;
        }
        let boundary = self.boundary.verify_reduction(b, ch, &proof.boundary)?;
        let mut ch = boundary.challenger.clone();
        let port_point = (0..PORT_LOG - usize::from(self.direct_bridge))
            .map(|_| sample(b, &mut ch))
            .collect::<Result<Vec<_>>>()?;
        let coefficients = equality_weights(b, &port_point);
        let mut value = b.native_poly192_constant([0; 3]);
        for (coefficient, port) in coefficients.iter().zip(&ports.values) {
            let term = b.native_poly192_mul(coefficient, port);
            value = b.native_poly192_add(&value, &term);
        }
        let link = self
            .closing
            .verify_reduction_native(b, ch, &value, &proof.ports)?;
        let direction = ports.instance.get(self.log_batch);
        let weight = port_weight(b, &coefficients, &link.point, direction);
        let mut point = ports.instance[..self.log_batch].to_vec();
        point.extend_from_slice(&link.point[1..]);
        Ok(LinkedReduction {
            points: [
                boundary.points[0].clone(),
                point.clone(),
                boundary.points[1].clone(),
                point,
            ],
            challenger: link.challenger,
            selector: link.point[0].clone(),
            weight,
            product: link.claim,
            boundary,
        })
    }
}

impl LinkedReduction {
    pub fn authenticate(&self, b: &mut CircuitBuilder<CF>, values: [&NativePoly192Target; 4]) {
        self.boundary.authenticate(b, values[0], values[2]);
        let difference = b.native_poly192_add(values[1], values[3]);
        let selected = b.native_poly192_mul(&self.selector, &difference);
        let blended = b.native_poly192_add(values[1], &selected);
        let product = b.native_poly192_mul(&self.weight, &blended);
        connect(b, &product, &self.product);
    }
}

fn port_weight(
    b: &mut CircuitBuilder<CF>,
    coefficients: &[NativePoly192Target],
    point: &[NativePoly192Target],
    direction: Option<&NativePoly192Target>,
) -> NativePoly192Target {
    let high = equality_weights(b, &point[usize::from(direction.is_some())..8]);
    let low = equality_weights(b, &point[8..]);
    let zero = b.native_poly192_constant([0; 3]);
    let mut words = [zero.clone(), zero.clone()];
    for bit in 0..16 {
        let basis = b.native_poly192_constant([1 << bit, 0, 0]);
        for (swapped, word) in words.iter_mut().enumerate() {
            let term = b.native_poly192_mul(&basis, &low[bit ^ (8 * swapped)]);
            *word = b.native_poly192_add(word, &term);
        }
    }
    let mut sums = [zero.clone(), zero];
    let count = if direction.is_some() {
        BRIDGE_LIMBS
    } else {
        PORTS
    };
    for (port, coefficient) in coefficients.iter().take(count).enumerate() {
        let (word, swapped) = if direction.is_some() {
            (if port < 100 { port } else { port - 100 }, port >= 100)
        } else {
            let (side, start, swapped) = location(port);
            (side * 128 + start / 16, swapped)
        };
        let term = b.native_poly192_mul(coefficient, &high[word]);
        let sum = &mut sums[usize::from(swapped)];
        *sum = b.native_poly192_add(sum, &term);
    }
    let a = b.native_poly192_mul(&sums[0], &words[0]);
    let c = b.native_poly192_mul(&sums[1], &words[1]);
    let weight = b.native_poly192_add(&a, &c);
    if let Some(direction) = direction {
        // eq(direction, point[0]) = 1 + direction + point[0] in characteristic two.
        let one = b.native_poly192_constant([1, 0, 0]);
        let delta = b.native_poly192_add(direction, &point[0]);
        let equality = b.native_poly192_add(&one, &delta);
        b.native_poly192_mul(&weight, &equality)
    } else {
        weight
    }
}

#[cfg(test)]
mod tests;
