//! Public sumcheck certificate for the deferred ring-switch weight of a
//! 26-variable shared terminal opening. All inputs are verifier challenges.
use anyhow::{Result, ensure};
use p3_binary_field::{Poly64 as F, Poly192 as E};
use p3_field::PrimeCharacteristicRing;
use sha3::{Digest, Keccak256};

const DOMAIN: &[u8] = b"imt-terminal-ring-product-sumcheck-v1";
const FACTORS: usize = 28;
const DIM: usize = 192;
pub const PROOF_BYTES: usize = 24 * (1 + 8 * FACTORS + DIM);

fn encode(v: E) -> [u8; 24] {
    let mut bytes = [0; 24];
    for (chunk, limb) in bytes
        .as_chunks_mut::<8>()
        .0
        .iter_mut()
        .zip(v.coefficients().into_iter().rev())
    {
        chunk.copy_from_slice(&limb.to_bits().to_be_bytes());
    }
    bytes
}

fn challenge(digest: &[u8; 32]) -> E {
    decode(&digest[8..])
}

fn seed(reading: &[E; 32], draw: &[E; 26], batching: &[E; 8], claim: E) -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update(Keccak256::digest(DOMAIN));
    for &v in reading.iter().chain(draw).chain(batching).chain([&claim]) {
        h.update([0; 8]);
        h.update(encode(v));
    }
    h.finalize().into()
}

fn dual_basis() -> [E; DIM] {
    // Coefficient of X^i in (f(X)-f(x))/(X-x), divided by f'(x).
    let mut base = [F::ZERO; 64];
    let x = F::new(2);
    let inv = F::new(0x5555555555555552);
    let mut quotient = F::ONE;
    for i in (0..64).rev() {
        base[i] = quotient * inv;
        quotient = quotient * x + F::new(u64::from(matches!(i, 1 | 3 | 4)));
    }
    core::array::from_fn(|u| {
        let mut c = [F::ZERO; 3];
        c[[0, 2, 1][u / 64]] = base[u % 64];
        E::new(c)
    })
}

fn fold(values: &mut [E], r: E) {
    for i in 0..values.len() / 2 {
        let a = values[2 * i];
        values[i] = a + r * (values[2 * i + 1] + a);
    }
}

fn linear_image(mut a: E, eq: &[E]) -> E {
    let mut image = E::ZERO;
    for &w in eq {
        image += w * a;
        a = a.square();
    }
    image
}

fn eq_table(low_first: &[E]) -> Vec<E> {
    let mut out = vec![E::ONE];
    for &r in low_first {
        let n = out.len();
        out.resize(2 * n, E::ZERO);
        for i in 0..n {
            let high = out[i] * r;
            out[i + n] = high;
            out[i] += high;
        }
    }
    out
}

/// Encode the claimed scalar, eight compressed degree-28 polynomials and
/// the 192 images of the trace-dual basis. No private prover data is used.
pub fn prove(reading: &[E; 32], draw: &[E; 26], batching: &[E; 8], claim: E) -> Result<Vec<u8>> {
    let dual = dual_basis();
    let batch = eq_table(&batching.iter().rev().copied().collect::<Vec<_>>());
    let mut conjugates = dual;
    let mut columns = vec![vec![E::ZERO; 256]; FACTORS];
    for ((col, &a), &b) in columns[..26].iter_mut().zip(reading).zip(draw.iter().rev()) {
        let mut power = a;
        for v in col {
            *v = E::ONE + b + power;
            power = power.square();
        }
    }
    for v in &mut columns[26] {
        *v = batch.iter().zip(&conjugates).map(|(&w, &c)| w * c).sum();
        for c in &mut conjugates {
            *c = c.square();
        }
    }
    columns[27][..DIM].fill(E::ONE);
    let mut carried = claim;
    let mut wire = Vec::with_capacity(PROOF_BYTES);
    wire.extend(encode(claim));
    let mut state = seed(reading, draw, batching, claim);
    let mut point = [E::ZERO; 8];
    for (d, r) in point.iter_mut().enumerate() {
        let width = 256 >> d;
        let mut message = [E::ZERO; FACTORS + 1];
        for i in 0..width / 2 {
            let mut product = [E::ZERO; FACTORS + 1];
            product[0] = E::ONE;
            for (k, col) in columns.iter().enumerate() {
                let lo = col[2 * i];
                let slope = lo + col[2 * i + 1];
                for t in (1..=k + 1).rev() {
                    product[t] = lo * product[t] + slope * product[t - 1];
                }
                product[0] *= lo;
            }
            for (h, p) in message.iter_mut().zip(product) {
                *h += p;
            }
        }
        ensure!(
            message[1..].iter().copied().sum::<E>() == carried,
            "incorrect ring-product claim"
        );
        let offset = wire.len();
        for &h in core::iter::once(&message[0]).chain(&message[2..]) {
            wire.extend(encode(h));
        }
        state = observe(&state, &wire[offset..]);
        *r = challenge(&state);
        carried = message.iter().rev().fold(E::ZERO, |v, &c| v * *r + c);
        for col in &mut columns {
            fold(&mut col[..width], *r);
        }
    }
    ensure!(
        columns.iter().map(|col| col[0]).product::<E>() == carried,
        "incorrect final product"
    );
    let eq = eq_table(&point);
    for basis in dual {
        wire.extend(encode(linear_image(basis, &eq)));
    }
    debug_assert_eq!(wire.len(), PROOF_BYTES);
    Ok(wire)
}

fn decode(bytes: &[u8]) -> E {
    E::new(core::array::from_fn(|i| {
        F::new(u64::from_be_bytes(
            bytes[16 - 8 * i..24 - 8 * i].try_into().unwrap(),
        ))
    }))
}

fn observe(state: &[u8; 32], data: &[u8]) -> [u8; 32] {
    let mut hash = Keccak256::new();
    hash.update(state);
    hash.update(data);
    hash.finalize().into()
}

fn coordinate_image(a: E, images: &[E]) -> E {
    // In the dual basis, coordinate i equals Tr(a*e_i). Over Poly64 this
    // trace is the leading coefficient of a*x^i*f'(x) modulo f(x).
    let [c0, c1, c2] = a.coefficients();
    let mut value = E::ZERO;
    for (&c, block) in [c0, c2, c1].iter().zip(images.as_chunks::<64>().0) {
        let mut b = c * F::new(5);
        for image in block {
            if b.to_bits() >> 63 != 0 {
                value += *image;
            }
            b *= F::new(2);
        }
    }
    value
}

/// Verify the certificate independently of the target execution platform.
/// The final projection uses the dual basis directly. All 256 conjugates
/// (including the repeated 64) belong to the multilinear map table check.
pub fn verify(reading: &[E; 32], draw: &[E; 26], batching: &[E; 8], proof: &[u8]) -> Result<E> {
    ensure!(
        proof.len() == PROOF_BYTES,
        "invalid ring certificate length"
    );
    let weight = decode(&proof[..24]);
    let mut sum = weight;
    let mut state = seed(reading, draw, batching, weight);
    let mut q = [E::ZERO; 8];
    let map_offset = 24 * (1 + 8 * FACTORS);
    for (r, wire) in q
        .iter_mut()
        .zip(proof[24..map_offset].as_chunks::<{ FACTORS * 24 }>().0)
    {
        state = observe(&state, wire);
        *r = challenge(&state);
        let mut h = [E::ZERO; FACTORS + 1];
        h[0] = decode(&wire[..24]);
        for (v, bytes) in h[2..].iter_mut().zip(wire[24..].as_chunks::<24>().0) {
            *v = decode(bytes);
        }
        h[1] = sum + h[2..].iter().copied().sum::<E>();
        sum = h.iter().rev().fold(E::ZERO, |acc, &v| acc * *r + v);
    }
    let eq = eq_table(&q);
    let wire = &proof[map_offset..];
    let images: Vec<_> = wire.as_chunks::<24>().0.iter().map(|c| decode(c)).collect();
    let tau = challenge(&observe(&state, wire));
    let projection = images.iter().rev().fold(E::ZERO, |acc, &v| acc * tau + v);
    let expected = dual_basis()
        .into_iter()
        .rev()
        .fold(E::ZERO, |acc, basis| acc * tau + linear_image(basis, &eq));
    ensure!(projection == expected, "incorrect ring map projection");
    let mask = E::ONE + q[6] * q[7];
    let dual = eq_table(&batching.iter().rev().copied().collect::<Vec<_>>())
        .iter()
        .zip(&images)
        .map(|(w, m)| *w * *m)
        .sum::<E>();
    let product = reading[..26]
        .iter()
        .zip(draw.iter().rev())
        .map(|(&a, &b)| E::ONE + b + coordinate_image(a, &images))
        .product::<E>();
    ensure!(
        sum == mask * dual * product,
        "incorrect ring product evaluation"
    );
    Ok(weight)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_one_and_rejects_invalid_ring_certificates() -> Result<()> {
        // The tensor is 1 tensor 1. On a Boolean batching point selecting
        // the constant basis element its requested weight is one.
        let reading = [E::ZERO; 32];
        let draw = [E::ZERO; 26];
        let batching = [E::ZERO; 8];
        let mut proof = prove(&reading, &draw, &batching, E::ONE)?;
        assert_eq!(verify(&reading, &draw, &batching, &proof)?, E::ONE);
        assert!(prove(&reading, &draw, &batching, E::ZERO).is_err());
        assert!(verify(&reading, &draw, &batching, &proof[..proof.len() - 1]).is_err());
        for at in [
            0,
            24,
            24 * (1 + 4 * FACTORS),
            24 * (1 + 8 * FACTORS),
            PROOF_BYTES - 1,
        ] {
            proof[at] ^= 1;
            assert!(verify(&reading, &draw, &batching, &proof).is_err());
            proof[at] ^= 1;
        }
        Ok(())
    }
}
