//! Full-ZK degree-seven Spartan outer sumcheck COMPONENT.
//! Supports an authenticated-key prefix plus a raw prefix harness for differential tests.
//! It does not constitute a client verifier: missing inner sumcheck, SPARK and
//! hiding WHIR must be constrained before it can authorize anything.
use super::{quintic::Ext, transcript::Transcript};
use crate::{
    client::{Proof, VerifyingKey},
    outer::convert,
    primitives::F,
};
use anyhow::{Result, ensure};
use p3_challenger::{CanObserve, CanSample, FieldChallenger};
use p3_circuit::{Circuit, CircuitBuilder};
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing as _};
use p3_field_outer::{Field as _, PrimeCharacteristicRing};
use p3_koala_bear_outer::KoalaBear as O;
use spartan_whir::{PoseidonTranscriptEvent as Event, QuinticExtension as E};

/// Component circuit shape is fixed by prefix length and trusted round count.
/// The current supported shape has no rejection-resampling of the last point:
/// both 0 and 1 are explicitly unsatisfiable, rather than silently accepted.
pub fn build(prefix_len: usize, rounds: usize) -> Result<Circuit<O>> {
    ensure!(rounds > 0, "empty sumcheck");
    let mut b = CircuitBuilder::<O>::new();
    let mut t = Transcript::new();
    for _ in 0..prefix_len {
        let x = b.alloc_private_input("prefix field");
        t.observe(&mut b, x);
    }
    constrain(&mut b, &mut t, rounds)?;
    Ok(b.build()?)
}
/// Append the degree-seven verifier to an already constructed transcript.
fn constrain(b: &mut CircuitBuilder<O>, t: &mut Transcript, rounds: usize) -> Result<()> {
    ensure!(rounds > 0, "empty sumcheck");
    let mu = Ext::private(b);
    t.observe_ext(b, mu);
    let epsilon = t.sample_ext(b);
    let tau: Vec<_> = (0..rounds).map(|_| t.sample_ext(b)).collect();
    let mut claim = mu;
    let mut point = Vec::new();
    for _ in 0..rounds {
        let wire: Vec<_> = (0..7).map(|_| Ext::private(b)).collect();
        for &x in &wire {
            t.observe_ext(b, x);
        }
        let r = t.sample_ext(b);
        point.push(r);
        let h1 = claim.sub(b, wire[0]);
        let values = [vec![wire[0], h1], wire[1..].to_vec()].concat();
        let mut next = Ext::constant(b, E::ZERO);
        // Polynomial interpolation with CONSTANT denominators, safe at all r.
        for (i, &value) in values.iter().enumerate() {
            let mut numerator = Ext::constant(b, E::ONE);
            let mut denominator = O::ONE;
            for j in 0..8 {
                if j != i {
                    let c = Ext::constant(b, E::from_u32(j as u32));
                    let factor = r.sub(b, c);
                    numerator = numerator.mul(b, factor);
                    denominator *= O::from_usize(i) - O::from_usize(j);
                }
            }
            let term = value.mul(b, numerator).scale(b, denominator.inverse());
            next = next.add(b, term);
        }
        claim = next;
    }
    let inv_r = Ext::private(b);
    point[rounds - 1].assert_inverse(b, inv_r);
    let one = Ext::constant(b, E::ONE);
    let rm1 = point[rounds - 1].sub(b, one);
    let inv_rm1 = Ext::private(b);
    rm1.assert_inverse(b, inv_rm1);
    let a = Ext::private(b);
    let c = Ext::private(b);
    let d = Ext::private(b);
    let mut expected = a.mul(b, c).sub(b, d).mul(b, epsilon);
    for (&tau, &r) in tau.iter().zip(&point) {
        let x = one.sub(b, tau);
        let y = one.sub(b, r);
        let xy = x.mul(b, y);
        let tr = tau.mul(b, r);
        let eq = xy.add(b, tr);
        expected = expected.mul(b, eq);
    }
    for _ in 0..rounds {
        let mask = Ext::private(b);
        expected = expected.add(b, mask);
    }
    claim.connect(b, expected);
    Ok(())
}
/// Construct a fixed prefix from an authenticated, independently supplied VK.
/// Uses only the existing upstream configuration exporter, never a VM or guest.
/// This pins the initial relation/config transcript, but does NOT verify SPARK or WHIR.
pub fn build_pinned_component(vk: &VerifyingKey) -> Result<Circuit<O>> {
    let cfg =
        spartan_whir::full_zk_spark_guest_verifier_config::<spartan_whir::PoseidonEngine<E>>(vk)
            .map_err(|e| anyhow::anyhow!("authenticated config: {e:?}"))?;
    ensure!(
        cfg.common.canonical_shape.public_inputs == 32,
        "unsupported statement shape"
    );
    let mut b = CircuitBuilder::<O>::new();
    let mut t = Transcript::new();
    for v in cfg.common.context_prefix {
        let x = b.alloc_const(O::from_u32(v), "fixed client context");
        t.observe(&mut b, x);
    }
    for _ in 0..32 {
        let x = b.public_input();
        t.observe(&mut b, x);
    }
    for _ in 0..8 {
        let x = b.alloc_private_input("application mask cap");
        t.observe(&mut b, x);
    }
    for v in cfg.common.relation_domain_separator {
        let x = b.alloc_const(O::from_u32(v), "fixed relation separator");
        t.observe(&mut b, x);
    }
    for _ in 0..8 {
        let x = b.alloc_private_input("witness cap");
        t.observe(&mut b, x);
    }
    constrain(&mut b, &mut t, cfg.common.num_outer_rounds)?;
    Ok(b.build()?)
}
pub fn pinned_assignment(vk: &VerifyingKey, proof: &Proof) -> Result<Vec<O>> {
    let cfg =
        spartan_whir::full_zk_spark_guest_verifier_config::<spartan_whir::PoseidonEngine<E>>(vk)
            .map_err(|e| anyhow::anyhow!("authenticated config: {e:?}"))?;
    ensure!(
        proof.instance.public_inputs.len() == 32
            && proof.proof.outer_sumcheck.rounds.len() == cfg.common.num_outer_rounds,
        "unsupported component shape"
    );
    let app = proof.proof.application_mask_commitment.roots();
    let witness = proof.instance.witness_commitment.roots();
    ensure!(
        app.len() == 1 && witness.len() == 1,
        "unsupported non-singleton cap"
    );
    let mut prefix: Vec<F> = cfg
        .common
        .context_prefix
        .into_iter()
        .map(F::from_u32)
        .collect();
    prefix.extend_from_slice(&proof.instance.public_inputs);
    prefix.extend(app[0]);
    prefix.extend(
        cfg.common
            .relation_domain_separator
            .into_iter()
            .map(F::from_u32),
    );
    prefix.extend(witness[0]);
    let mut out: Vec<O> = app[0]
        .iter()
        .chain(&witness[0])
        .copied()
        .map(convert)
        .collect();
    out.extend_from_slice(&assignment(&prefix, proof)?[prefix.len()..]);
    Ok(out)
}
/// Extract an actual transcript prefix for DIFFERENTIAL TESTS ONLY. It is not
/// a trusted verifier-key import API and is never used for state acceptance.
pub fn test_prefix(vk: &VerifyingKey, proof: &Proof) -> Result<Vec<F>> {
    let mut challenger = spartan_whir::poseidon_challenger().with_trace();
    spartan_whir::PoseidonZkSpartanProtocol::<E>::verify(
        vk,
        &proof.instance,
        &proof.proof,
        &mut challenger,
    )
    .map_err(|e| anyhow::anyhow!("native: {e:?}"))?;
    let mut prefix = Vec::new();
    for event in challenger.transcript_trace() {
        match event {
            Event::Observe { values } | Event::ObserveCommitment { values, .. } => {
                prefix.extend(values.into_iter().map(F::from_u32))
            }
            Event::Sample { .. } => break,
            _ => anyhow::bail!("unexpected prefix operation"),
        }
    }
    ensure!(
        prefix.ends_with(
            proof
                .proof
                .outer_sumcheck
                .mu_tilde
                .as_basis_coefficients_slice()
        ),
        "prefix shape mismatch"
    );
    prefix.truncate(prefix.len() - 5);
    Ok(prefix)
}
pub fn assignment(prefix: &[F], proof: &Proof) -> Result<Vec<O>> {
    let p = &proof.proof;
    let mut t = spartan_whir::poseidon_challenger();
    t.observe_slice(prefix);
    let mut out: Vec<_> = prefix.iter().copied().map(convert).collect();
    let mut push = |x: E| out.extend(x.as_basis_coefficients_slice().iter().copied().map(convert));
    push(p.outer_sumcheck.mu_tilde);
    t.observe_algebra_element(p.outer_sumcheck.mu_tilde);
    let _: E = t.sample();
    for _ in &p.outer_sumcheck.rounds {
        let _: E = t.sample();
    }
    let mut last = E::ZERO;
    for round in &p.outer_sumcheck.rounds {
        ensure!(round.len() == 7, "bad polynomial");
        for &x in round {
            push(x);
            t.observe_algebra_element(x);
        }
        last = t.sample();
    }
    ensure!(
        last != E::ZERO && last != E::ONE,
        "unsupported rejection-resampling shape"
    );
    push(last.inverse());
    push((last - E::ONE).inverse());
    for x in [p.outer_claims.0, p.outer_claims.1, p.outer_claims.2] {
        push(x);
    }
    for &x in &p.outer_mask_evals {
        push(x);
    }
    Ok(out)
}
