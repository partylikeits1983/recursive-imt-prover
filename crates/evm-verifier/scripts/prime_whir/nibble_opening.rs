//! Dense interoperability control for the 192-bit WHIR digit-opening verifier.
#[path = "support/digits.rs"]
mod digits;
#[allow(dead_code)]
#[path = "support/segments.rs"]
mod segments;
use ark_ff::{BigInteger, PrimeField};
use sha3::{Digest, Keccak256};
use spongefish::instantiations::Hash;
use std::{env, fs, path::Path};
use whir::{
    algebra::{
        embedding::Identity,
        fields::Field192 as F,
        linear_form::{Evaluate, MultilinearExtension},
    },
    bits::Bits,
    buffer::Buffer,
    hash::KECCAK,
    parameters::ProtocolParameters,
    protocols::{params::DecodingRegime, whir::Config},
    transcript::{DomainSeparator, ProverState, VerifierState},
};
fn main() {
    let args: Vec<_> = env::args().collect();
    assert_eq!(args.len(), 3);
    let bundle = Path::new(&args[1]);
    let out = Path::new(&args[2]);
    fs::create_dir_all(out).unwrap();
    let table = digits::table(bundle, 7, 4);
    let vector: Vec<F> = table.iter().map(|&d| F::from(d)).collect();
    let cfg = Config::<Identity<F>>::new(
        vector.len(),
        &ProtocolParameters {
            security_level: 135,
            pow_bits: 16,
            initial_folding_factor: 4,
            folding_factor: 5,
            decoding_regime: DecodingRegime::Johnson,
            starting_log_inv_rate: 5,
            batch_size: 1,
            hash_id: KECCAK,
        },
    );
    assert!(cfg.check_max_pow_bits(Bits::new(16.0)) && cfg.security_level(1, 1) + 1e-8 >= 135.0);
    let ctx: [u8; 32] = Keccak256::digest(b"recursive-imt/field192-opening-control/v1").into();
    let point: Vec<_> = (0..19u8)
        .map(|i| {
            F::from_be_bytes_mod_order(
                &Keccak256::new()
                    .chain_update(ctx)
                    .chain_update([i])
                    .finalize(),
            )
        })
        .collect();
    let form = MultilinearExtension::new(point.clone());
    let value = form.evaluate(&Identity::new(), &vector);
    // Static ABI words for context, point coordinates and value.
    let mut statement = ctx.to_vec();
    for x in point.iter().chain([&value]) {
        statement.extend([0; 8]);
        statement.extend(x.into_bigint().to_bytes_be());
    }
    let instance: [u8; 32] = Keccak256::digest(&statement).into();
    let ds = DomainSeparator::protocol(&cfg)
        .session(&"recursive-imt/prime-whir-opening/v1")
        .instance(&instance);
    let mut prover = ProverState::new(&ds, Hash::<Keccak256>::default());
    let v = Buffer::from(vector);
    let w = cfg.commit(&mut prover, &[&v]);
    let _ = cfg.prove(
        &mut prover,
        &[&v],
        vec![&w],
        vec![Box::new(form.clone())],
        Buffer::from(vec![value]),
    );
    let proof = prover.proof();
    let mut verifier = VerifierState::new(&ds, &proof, Hash::<Keccak256>::default());
    let commitment = cfg.receive_commitment(&mut verifier).unwrap();
    cfg.verify(&mut verifier, &[&commitment], &[value])
        .unwrap()
        .verify([&form as _])
        .unwrap();
    verifier.check_eof().unwrap();
    fs::write(out.join("proof.bin"), proof.narg_string).unwrap();
    fs::write(out.join("hints.bin"), proof.hints).unwrap();
    fs::write(out.join("statement.bin"), statement).unwrap();
}
