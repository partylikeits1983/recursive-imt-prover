//! Application arithmetic profile shared by R1CS and Plonky3 circuits.
//! Linear layers adapted from spartan-whir/src/withdrawal.rs at the pinned revision.
use p3_field::{Field, PrimeCharacteristicRing};
use p3_koala_bear::{
    KOALABEAR_POSEIDON2_RC_24_EXTERNAL_FINAL as FINAL,
    KOALABEAR_POSEIDON2_RC_24_EXTERNAL_INITIAL as INITIAL,
    KOALABEAR_POSEIDON2_RC_24_INTERNAL as INTERNAL,
};
use spartan_whir::engine::F;

pub trait Arithmetic {
    type V: Clone;
    fn constant(&mut self, f: F) -> Self::V;
    fn add(&mut self, a: Self::V, b: Self::V) -> Self::V;
    fn mul(&mut self, a: Self::V, b: Self::V) -> Self::V;
    fn compact(&mut self, x: Self::V) -> Self::V {
        x
    }
    fn scale(&mut self, x: Self::V, f: F) -> Self::V {
        let c = self.constant(f);
        self.mul(x, c)
    }
}
fn cube<B: Arithmetic>(b: &mut B, x: B::V) -> B::V {
    let square = b.mul(x.clone(), x.clone());
    b.mul(square, x)
}
fn external<B: Arithmetic, const W: usize>(b: &mut B, s: &mut [B::V; W]) {
    let matrix = [[2, 3, 1, 1], [1, 2, 3, 1], [1, 1, 2, 3], [3, 1, 1, 2]];
    for chunk in s.as_chunks_mut::<4>().0 {
        let old = chunk.to_vec();
        for row in 0..4 {
            let mut sum = b.constant(F::ZERO);
            for col in 0..4 {
                let term = b.scale(old[col].clone(), F::from_u32(matrix[row][col]));
                sum = b.add(sum, term);
            }
            chunk[row] = b.compact(sum);
        }
    }
    let sums: [B::V; 4] = core::array::from_fn(|i| {
        let mut sum = b.constant(F::ZERO);
        for j in (i..W).step_by(4) {
            sum = b.add(sum, s[j].clone());
        }
        b.compact(sum)
    });
    for i in 0..W {
        let x = b.add(s[i].clone(), sums[i % 4].clone());
        s[i] = b.compact(x);
    }
}
pub fn permute24<B: Arithmetic>(b: &mut B, s: &mut [B::V; 24]) {
    external(b, s);
    for rc in INITIAL {
        for i in 0..24 {
            let c = b.constant(rc[i]);
            let x = b.add(s[i].clone(), c);
            s[i] = cube(b, x);
        }
        external(b, s);
    }
    let h = F::TWO.inverse();
    let d = [
        -F::TWO,
        F::ONE,
        F::TWO,
        h,
        F::from_u32(3),
        F::from_u32(4),
        -h,
        -F::from_u32(3),
        -F::from_u32(4),
        h.exp_u64(8),
        h.exp_u64(2),
        h.exp_u64(3),
        h.exp_u64(4),
        h.exp_u64(5),
        h.exp_u64(6),
        h.exp_u64(24),
        -h.exp_u64(8),
        -h.exp_u64(3),
        -h.exp_u64(4),
        -h.exp_u64(5),
        -h.exp_u64(6),
        -h.exp_u64(7),
        -h.exp_u64(9),
        -h.exp_u64(24),
    ];
    for rc in INTERNAL {
        let c = b.constant(rc);
        let x = b.add(s[0].clone(), c);
        s[0] = cube(b, x);
        let mut sum = b.constant(F::ZERO);
        for x in s.iter() {
            sum = b.add(sum, x.clone());
        }
        let sum = b.compact(sum);
        for i in 0..24 {
            let t = b.scale(s[i].clone(), d[i]);
            let x = b.add(sum.clone(), t);
            s[i] = b.compact(x);
        }
    }
    for rc in FINAL {
        for i in 0..24 {
            let c = b.constant(rc[i]);
            let x = b.add(s[i].clone(), c);
            s[i] = cube(b, x);
        }
        external(b, s);
    }
}
pub fn hash<B: Arithmetic>(b: &mut B, domain: u32, input: &[B::V]) -> Vec<B::V> {
    let mut s: [B::V; 24] = core::array::from_fn(|_| b.constant(F::ZERO));
    s[16] = b.constant(F::from_u32(domain));
    s[17] = b.constant(F::from_usize(input.len()));
    s[18] = b.constant(F::ONE);
    for block in input.chunks(16) {
        for (i, x) in block.iter().enumerate() {
            s[i] = b.add(s[i].clone(), x.clone());
        }
        permute24(b, &mut s);
    }
    if input.is_empty() {
        permute24(b, &mut s);
    }
    s[..8].to_vec()
}

/// EXACT pinned proof-transcript permutation; separate from application sponge.
pub fn permute16<B: Arithmetic>(b: &mut B, s: &mut [B::V; 16]) {
    use p3_koala_bear::{
        KOALABEAR_POSEIDON2_RC_16_EXTERNAL_FINAL as E,
        KOALABEAR_POSEIDON2_RC_16_EXTERNAL_INITIAL as I, KOALABEAR_POSEIDON2_RC_16_INTERNAL as P,
    };
    external(b, s);
    for rc in I {
        for i in 0..16 {
            let c = b.constant(rc[i]);
            let x = b.add(s[i].clone(), c);
            s[i] = cube(b, x);
        }
        external(b, s);
    }
    let h = F::TWO.inverse();
    let d = [
        -F::TWO,
        F::ONE,
        F::TWO,
        h,
        F::from_u32(3),
        F::from_u32(4),
        -h,
        -F::from_u32(3),
        -F::from_u32(4),
        h.exp_u64(8),
        h.exp_u64(3),
        h.exp_u64(24),
        -h.exp_u64(8),
        -h.exp_u64(3),
        -h.exp_u64(4),
        -h.exp_u64(24),
    ];
    for rc in P {
        let c = b.constant(rc);
        let x = b.add(s[0].clone(), c);
        s[0] = cube(b, x);
        let mut sum = b.constant(F::ZERO);
        for x in s.iter() {
            sum = b.add(sum, x.clone());
        }
        let sum = b.compact(sum);
        for i in 0..16 {
            let t = b.scale(s[i].clone(), d[i]);
            let v = b.add(sum.clone(), t);
            s[i] = b.compact(v);
        }
    }
    for rc in E {
        for i in 0..16 {
            let c = b.constant(rc[i]);
            let x = b.add(s[i].clone(), c);
            s[i] = cube(b, x);
        }
        external(b, s);
    }
}
