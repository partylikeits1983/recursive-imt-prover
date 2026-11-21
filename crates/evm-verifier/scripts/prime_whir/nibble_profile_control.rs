//! Full-arity WHIR interoperability test. The table is 1 at the origin and 0 elsewhere.
//! This is a polynomial-opening test vector. It contains no IMT witness.
use ark_ff::{AdditiveGroup, BigInteger, Field, PrimeField};
use sha3::{Digest, Keccak256};
use spongefish::instantiations::Hash as Sponge;
use std::{env, fs, path::Path};
use whir::{
    algebra::{embedding::Identity, fields::Field192 as F, linear_form::MultilinearExtension},
    bits::Bits,
    hash::{Hash, KECCAK},
    parameters::ProtocolParameters,
    protocols::{
        challenge_indices::challenge_indices, irs_commit, merkle_tree, params::DecodingRegime,
        proof_of_work, whir::Config,
    },
    transcript::{DomainSeparator, ProverState, VerifierMessage, VerifierState},
};
type Transcript = ProverState<Sponge<Keccak256>>;

struct Term {
    coeff: F,
    // Tail coordinate first so each fold consumes the last element.
    factors: Vec<[F; 2]>,
}
impl Term {
    fn univariate(coeff: F, mut z: F, arity: usize) -> Self {
        let factors = (0..arity)
            .map(|_| {
                let v = z;
                z.square_in_place();
                [F::ONE, v]
            })
            .collect();
        Self { coeff, factors }
    }
}
fn fold(
    p: &mut Transcript,
    amplitude: &mut F,
    terms: &mut [Term],
    rounds: usize,
    work: proof_of_work::Config,
) {
    for _ in 0..rounds {
        let mut low = F::ZERO;
        let mut high = F::ZERO;
        for t in terms.iter() {
            let (last, rest) = t.factors.split_last().unwrap();
            let tail = rest.iter().fold(t.coeff, |v, f| v * f[0]);
            low += tail * last[0];
            high += tail * last[1];
        }
        p.prover_messages(&[*amplitude * low, *amplitude * (low - high)]);
        work.prove(p);
        let r: F = p.verifier_message();
        *amplitude *= F::ONE - r;
        for term in terms.iter_mut() {
            let [a, b] = term.factors.pop().unwrap();
            term.coeff *= a + r * (b - a);
        }
    }
}

struct ConstantRows {
    row: Vec<F>,
    levels: Vec<Hash>,
}
impl ConstantRows {
    fn new(cfg: &irs_commit::Config<Identity<F>>, a: F) -> Self {
        let mut row = vec![F::ZERO; cfg.num_cols()];
        row[0] = a;
        let bytes: Vec<_> = row
            .iter()
            .flat_map(|x| x.into_bigint().to_bytes_le())
            .collect();
        let mut levels = vec![Hash(Keccak256::digest(bytes).into())];
        for _ in 0..cfg.codeword_length().ilog2() {
            let h = levels.last().unwrap().0;
            levels.push(Hash(
                Keccak256::new()
                    .chain_update(h)
                    .chain_update(h)
                    .finalize()
                    .into(),
            ));
        }
        Self { row, levels }
    }
    fn commit(&self, p: &mut Transcript, a: F) -> F {
        p.prover_message(self.levels.last().unwrap());
        let z = p.verifier_message();
        p.prover_message(&a);
        z
    }
    fn open(
        &self,
        p: &mut Transcript,
        cfg: &irs_commit::Config<Identity<F>>,
        work: proof_of_work::Config,
    ) -> Vec<F> {
        work.prove(p);
        let leaves = cfg.codeword_length();
        let indices = challenge_indices(p, leaves, cfg.in_domain_samples(), false);
        let rows = self.row.repeat(indices.len());
        p.prover_hint_ark(&rows);
        for pos in merkle_tree::opening_sibling_indices(leaves, leaves.ilog2() as usize, &indices) {
            let mut size = leaves;
            let mut offset = 0;
            let mut level = 0;
            while pos >= offset + size {
                offset += size;
                size /= 2;
                level += 1;
            }
            p.prover_hint(&self.levels[level]);
        }
        cfg.evaluation_points(&indices)
    }
}

fn main() {
    let out = env::args().nth(1).unwrap();
    let out = Path::new(&out);
    fs::create_dir_all(out).unwrap();
    let n = 28;
    let cfg = Config::<Identity<F>>::new(
        1 << n,
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
    let context: [u8; 32] =
        Keccak256::digest(b"recursive-imt/field192-single-coefficient-control/v1").into();
    let point: Vec<_> = (0..n)
        .map(|i| {
            F::from_be_bytes_mod_order(
                &Keccak256::new()
                    .chain_update(context)
                    .chain_update([i as u8])
                    .finalize(),
            )
        })
        .collect();
    let value = point.iter().fold(F::ONE, |v, r| v * (F::ONE - r));
    let mut statement = context.to_vec();
    for x in point.iter().chain([&value]) {
        statement.extend([0; 8]);
        statement.extend(x.into_bigint().to_bytes_be());
    }
    let instance: [u8; 32] = Keccak256::digest(&statement).into();
    let domain = DomainSeparator::protocol(&cfg)
        .session(&"recursive-imt/prime-whir-opening/v1")
        .instance(&instance);
    let mut p = ProverState::new(&domain, Sponge::<Keccak256>::default());
    let mut a = F::ONE;
    let mut prev_cfg = &cfg.initial_committer;
    let mut prev = ConstantRows::new(prev_cfg, a);
    assert_eq!(cfg.initial_out_domain_samples, 1);
    let z = prev.commit(&mut p, a);
    let mix = p.verifier_message();
    let mut terms = vec![
        Term {
            coeff: F::ONE,
            factors: point.iter().rev().map(|r| [F::ONE - r, *r]).collect(),
        },
        Term::univariate(mix, z, n),
    ];
    fold(
        &mut p,
        &mut a,
        &mut terms,
        cfg.initial_sumcheck.num_rounds(),
        cfg.initial_sumcheck.round_pow(),
    );
    for round in &cfg.round_configs {
        let arity = round.initial_num_variables();
        assert_eq!(round.out_domain_samples, 1);
        let current = ConstantRows::new(&round.irs_committer, a);
        let z = current.commit(&mut p, a);
        let points = prev.open(&mut p, prev_cfg, round.pow);
        let mix: F = p.verifier_message();
        terms.push(Term::univariate(F::ONE, z, arity));
        let mut coeff = mix;
        for z in points {
            terms.push(Term::univariate(coeff, z, arity));
            coeff *= mix;
        }
        fold(
            &mut p,
            &mut a,
            &mut terms,
            round.sumcheck.num_rounds(),
            round.sumcheck.round_pow(),
        );
        prev = current;
        prev_cfg = &round.irs_committer;
    }
    let mut final_vector = vec![F::ZERO; cfg.final_sumcheck.initial_size()];
    final_vector[0] = a;
    p.prover_messages(&final_vector);
    prev.open(&mut p, prev_cfg, cfg.final_pow);
    fold(
        &mut p,
        &mut a,
        &mut terms,
        cfg.final_sumcheck.num_rounds(),
        cfg.final_sumcheck.round_pow(),
    );
    let proof = p.proof();
    let mut v = VerifierState::new(&domain, &proof, Sponge::<Keccak256>::default());
    let c = cfg.receive_commitment(&mut v).unwrap();
    cfg.verify(&mut v, &[&c], &[value])
        .unwrap()
        .verify([&MultilinearExtension::new(point) as _])
        .unwrap();
    v.check_eof().unwrap();
    fs::write(out.join("proof.bin"), proof.narg_string).unwrap();
    fs::write(out.join("hints.bin"), proof.hints).unwrap();
    fs::write(out.join("statement.bin"), statement).unwrap();
}
