//! Prefix-free width-16/rate-8 DuplexChallenger at the CLIENT fork revision.
//! Implements field observe/sample only. Bit sampling, resampling, and PoW are
//! deliberately unsupported here; this is not a complete WHIR transcript gadget.
use super::{poseidon::permute16, quintic::Ext};
use p3_circuit::{CircuitBuilder, ExprId};
use p3_field_outer::PrimeCharacteristicRing;
use p3_koala_bear_outer::KoalaBear as O;
pub struct Transcript {
    state: [ExprId; 16],
    input: Vec<ExprId>,
    output: Vec<ExprId>,
}
impl Transcript {
    pub fn new() -> Self {
        Self {
            state: [ExprId::ZERO; 16],
            input: vec![],
            output: vec![],
        }
    }
    fn duplex(&mut self, b: &mut CircuitBuilder<O>) {
        let len = self.input.len();
        for (i, x) in self.input.drain(..).enumerate() {
            self.state[i] = x;
        }
        if len > 0 {
            self.state[len..8].fill(ExprId::ZERO);
            let tag = b.alloc_const(O::from_usize(len), "absorb length");
            self.state[8] = b.add(self.state[8], tag);
        }
        permute16(b, &mut self.state);
        self.output = self.state[..8].to_vec();
    }
    pub fn observe(&mut self, b: &mut CircuitBuilder<O>, x: ExprId) {
        self.output.clear();
        self.input.push(x);
        if self.input.len() == 8 {
            self.duplex(b);
        }
    }
    pub fn observe_ext(&mut self, b: &mut CircuitBuilder<O>, x: Ext) {
        for v in x.0 {
            self.observe(b, v);
        }
    }
    pub fn sample(&mut self, b: &mut CircuitBuilder<O>) -> ExprId {
        if !self.input.is_empty() || self.output.is_empty() {
            self.duplex(b);
        }
        self.output.pop().unwrap()
    }
    pub fn sample_ext(&mut self, b: &mut CircuitBuilder<O>) -> Ext {
        Ext(core::array::from_fn(|_| self.sample(b)))
    }
}

impl Default for Transcript {
    fn default() -> Self {
        Self::new()
    }
}
