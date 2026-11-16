//! KoalaBear quintic extension F[X]/(X^5+X^2-1), ascending coefficients.
use crate::outer::convert;
use p3_circuit::{CircuitBuilder, ExprId};
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing as _};
use p3_koala_bear_outer::KoalaBear as O;
use spartan_whir::QuinticExtension as E;
#[derive(Clone, Copy, Debug)]
pub struct Ext(pub [ExprId; 5]);
impl Ext {
    pub fn constant(b: &mut CircuitBuilder<O>, x: E) -> Self {
        Self(core::array::from_fn(|i| {
            b.alloc_const(
                convert(x.as_basis_coefficients_slice()[i]),
                "extension constant",
            )
        }))
    }
    pub fn private(b: &mut CircuitBuilder<O>) -> Self {
        Self(b.alloc_private_input_array("extension"))
    }
    pub fn add(self, b: &mut CircuitBuilder<O>, r: Self) -> Self {
        Self(core::array::from_fn(|i| b.add(self.0[i], r.0[i])))
    }
    pub fn sub(self, b: &mut CircuitBuilder<O>, r: Self) -> Self {
        Self(core::array::from_fn(|i| b.sub(self.0[i], r.0[i])))
    }
    pub fn mul(self, b: &mut CircuitBuilder<O>, r: Self) -> Self {
        let mut c = [ExprId::ZERO; 9];
        for i in 0..5 {
            for j in 0..5 {
                let t = b.mul(self.0[i], r.0[j]);
                c[i + j] = b.add(c[i + j], t);
            }
        }
        for k in (5..9).rev() {
            c[k - 5] = b.add(c[k - 5], c[k]);
            c[k - 3] = b.sub(c[k - 3], c[k]);
        }
        Self(c[..5].try_into().unwrap())
    }
    pub fn scale(self, b: &mut CircuitBuilder<O>, x: O) -> Self {
        let c = b.alloc_const(x, "scale");
        Self(self.0.map(|v| b.mul(v, c)))
    }
    pub fn connect(self, b: &mut CircuitBuilder<O>, r: Self) {
        for i in 0..5 {
            b.connect(self.0[i], r.0[i]);
        }
    }
    /// Inversion is an equation, never a host-only division. At zero this is unsatisfiable.
    pub fn assert_inverse(self, b: &mut CircuitBuilder<O>, inv: Self) {
        let one = Self::constant(b, E::ONE);
        self.mul(b, inv).connect(b, one);
    }
}
