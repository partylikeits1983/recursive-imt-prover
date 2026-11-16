use p3_challenger::{CanObserve, CanSample};
use p3_circuit::CircuitBuilder;
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing};
use p3_koala_bear_outer::KoalaBear as O;
use recursive_imt_poc::{
    gadgets::{quintic::Ext, transcript::Transcript},
    outer::convert,
    primitives::F,
};
use spartan_whir::QuinticExtension as E;
#[test]
fn quintic_arithmetic_matches_native_and_inverse_is_constrained() {
    let a = E::from_basis_coefficients_fn(|i| F::from_usize(i + 3));
    let c = E::from_basis_coefficients_fn(|i| F::from_usize(i * 3 + 1));
    let mut b = CircuitBuilder::<O>::new();
    let x = Ext::private(&mut b);
    let y = Ext::private(&mut b);
    let inv = Ext::private(&mut b);
    x.assert_inverse(&mut b, inv);
    let product = x.mul(&mut b, y);
    let expected = Ext::constant(&mut b, a * c);
    product.connect(&mut b, expected);
    let circuit = b.build().unwrap();
    let inputs: Vec<_> = [a, c, a.inverse()]
        .iter()
        .flat_map(|x| x.as_basis_coefficients_slice().iter().copied().map(convert))
        .collect();
    let mut r = circuit.runner();
    r.set_private_inputs(&inputs).unwrap();
    assert!(r.run().is_ok());
    let mut bad = inputs.clone();
    bad[10] = convert(F::ZERO);
    let mut r = circuit.runner();
    assert!(r.set_private_inputs(&bad).and_then(|_| r.run()).is_err());
    let mut bad = inputs;
    bad[..5].fill(convert(F::ZERO));
    let mut r = circuit.runner();
    assert!(r.set_private_inputs(&bad).and_then(|_| r.run()).is_err());
}
#[test]
fn transcript_differential_partial_absorbs_and_squeeze_order() {
    let mut native = spartan_whir::poseidon_challenger();
    let mut b = CircuitBuilder::<O>::new();
    let mut t = Transcript::new();
    let mut inputs = Vec::new();
    for len in [0, 1, 8, 17, 2, 0, 33] {
        for i in 0..len {
            let v = F::from_usize(i * 17 + len);
            native.observe(v);
            inputs.push(convert(v));
            let x = b.alloc_private_input("observe");
            t.observe(&mut b, x);
        }
        for _ in 0..3 {
            let expected: E = native.sample();
            let actual = t.sample_ext(&mut b);
            let c = Ext::constant(&mut b, expected);
            actual.connect(&mut b, c);
        }
    }
    let c = b.build().unwrap();
    let mut r = c.runner();
    r.set_private_inputs(&inputs).unwrap();
    assert!(r.run().is_ok());
    inputs[0] = convert(F::ZERO);
    let mut r = c.runner();
    assert!(r.set_private_inputs(&inputs).and_then(|_| r.run()).is_err());
}
