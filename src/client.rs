use crate::{
    primitives::*,
    r1cs::{Builder, Circuit, Linear, Wire},
    statement::ClientStatement,
};
use anyhow::{Result, ensure};
use p3_field::PrimeCharacteristicRing;
use serde::{Deserialize, Serialize};
use spartan_whir::{
    PoseidonZkProof, PoseidonZkProvingKey, PoseidonZkSetupConfig, PoseidonZkVerifyingKey,
    QuinticExtension,
};
pub type ProvingKey = PoseidonZkProvingKey<QuinticExtension>;
pub type VerifyingKey = PoseidonZkVerifyingKey<QuinticExtension>;
pub type Proof = PoseidonZkProof<QuinticExtension>;
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Note {
    pub secret: Digest,
    pub randomness: Digest,
}
impl Note {
    pub fn random() -> Self {
        let mut rng = rand::rng();
        Self {
            secret: Digest::random(&mut rng),
            randomness: Digest::random(&mut rng),
        }
    }
    pub fn commitment(&self) -> Digest {
        note(CTX, self.secret, self.randomness)
    }
    pub fn nullifier(&self) -> Digest {
        nullifier(CTX, self.secret, self.randomness)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientWitness {
    pub old: Note,
    pub old_leaf_index: u64,
    pub old_authentication_path: Vec<Digest>,
    pub new: Note,
}
pub fn statement(w: &ClientWitness) -> Result<ClientStatement> {
    Ok(ClientStatement {
        ctx: CTX,
        membership_root: root_from_path(
            w.old.commitment(),
            w.old_leaf_index,
            &w.old_authentication_path,
        )?,
        nullifier: w.old.nullifier(),
        new_commitment: w.new.commitment(),
    })
}
fn synthesize(depth: u8, s: &ClientStatement, w: &ClientWitness, record: bool) -> Result<Builder> {
    check_depth(depth)?;
    ensure!(
        w.old_authentication_path.len() == depth as usize,
        "wrong path length"
    );
    let mut b = Builder::new(s.fields(), record);
    let p: Vec<_> = (0..32).map(|i| Linear::wire(Wire::Public(i))).collect();
    for (a, c) in p[..8].iter().zip(CTX.fields()) {
        b.equal(a.clone(), Linear::constant(c));
    }
    let old_secret = b.private_digest(w.old.secret.fields());
    let old_randomness = b.private_digest(w.old.randomness.fields());
    let new_secret = b.private_digest(w.new.secret.fields());
    let new_randomness = b.private_digest(w.new.randomness.fields());
    let old_args = [p[..8].to_vec(), old_secret, old_randomness].concat();
    let old_cm = b.hash(NOTE, &old_args);
    let nf = b.hash(NULLIFIER, &old_args);
    let new_cm = b.hash(
        NOTE,
        &[p[..8].to_vec(), new_secret, new_randomness].concat(),
    );
    b.nonzero_digest(&old_cm);
    b.nonzero_digest(&new_cm);
    let bits: Vec<_> = (0..64)
        .map(|i| b.boolean((w.old_leaf_index >> i) & 1 != 0))
        .collect();
    for bit in &bits[depth as usize..] {
        b.equal(bit.clone(), Linear::constant(F::ZERO));
    }
    let mut root = old_cm;
    for (sibling, bit) in w.old_authentication_path.iter().zip(&bits) {
        let sib = b.private_digest(sibling.fields());
        let mut left = Vec::new();
        let mut right = Vec::new();
        for i in 0..8 {
            let d = b.mul(bit.clone(), sib[i].sub(&root[i]));
            left.push(root[i].add(&d));
            right.push(sib[i].sub(&d));
        }
        root = b.hash(NODE, &[left, right].concat());
    }
    for (computed, expected) in [(root, &p[8..16]), (nf, &p[16..24]), (new_cm, &p[24..32])] {
        for (a, c) in computed.into_iter().zip(expected) {
            b.equal(a, c.clone());
        }
    }
    Ok(b)
}
pub fn build(depth: u8, s: &ClientStatement, w: &ClientWitness) -> Result<Circuit> {
    Ok(synthesize(depth, s, w, true)?.finish())
}
pub fn assignment(
    depth: u8,
    s: &ClientStatement,
    w: &ClientWitness,
) -> Result<spartan_whir::R1csWitness<F>> {
    Ok(spartan_whir::R1csWitness {
        w: synthesize(depth, s, w, false)?.witness,
    })
}
pub fn config() -> PoseidonZkSetupConfig {
    // Preserve explicit upstream Johnson-bound full-ZK SPARK schedule. This is
    // 116-bit configured/composed CLIENT security, not a 128-bit claim.
    {
        let mut config = spartan_whir::withdrawal::config::withdrawal_spark_config();
        // Smaller note circuits need more codeword slack than the upstream
        // depth-32 withdrawal schedule. Increase redundancy, keep security.
        config.whir_params.starting_log_inv_rate = 2;
        config.whir_params.pow_bits = 22;
        config
    }
}
pub fn setup(shape: spartan_whir::R1csShape<F>) -> Result<(ProvingKey, VerifyingKey)> {
    ProvingKey::setup(shape, config()).map_err(|e| anyhow::anyhow!("client setup: {e:?}"))
}
pub fn prove(pk: &ProvingKey, depth: u8, s: &ClientStatement, w: &ClientWitness) -> Result<Proof> {
    pk.prove(assignment(depth, s, w)?, s.fields())
        .map_err(|e| anyhow::anyhow!("client proving: {e:?}"))
}
pub fn verify(vk: &VerifyingKey, s: &ClientStatement, proof: &Proof) -> Result<()> {
    vk.verify(&s.fields(), proof)
        .map_err(|e| anyhow::anyhow!("client verification: {e:?}"))
}
