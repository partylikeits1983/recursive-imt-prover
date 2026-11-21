//! Private-oracle integration fixture for the VEIL/WHIR bridge. This is not
//! yet the Keccak membership child, nor a certified full-ZK construction.

use anyhow::{Result, ensure};
use p3_multilinear_util::poly::Poly;
use p3_sumcheck::strategy::VariableOrder;
use rand::rngs::SysRng;
use serde::{Deserialize, Serialize};

use super::{
    E,
    compiler::{MaskedProver, MaskedReader},
    constraints::{ExperimentalProof, Relation},
    native::OraclePoint,
    oracle::{CommittedOracle, OracleOpening, OracleSpec},
    parameters::Parameters,
    sumcheck::replay_rounds,
};

const PROOF_MAGIC: &[u8; 8] = b"IMTVPO03";
const PROGRAM: &[u8] = b"binary-private-product-sumcheck-v3";
const MAX_PROOF_BYTES: usize = 16 << 20;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateSumcheckStatement {
    pub variables: usize,
    pub opening_points: usize,
    pub claimed_sum: E,
    pub oracle_root: [u8; 32],
}

#[derive(Clone, Serialize, Deserialize)]
pub struct PrivateSumcheckProof {
    inner: ExperimentalProof,
    opening: OracleOpening,
}

impl PrivateSumcheckStatement {
    /// Commit two private vectors and prove their dot product. `opening_points`
    /// exercises one or two points within the commitment's SINGLE opening batch.
    pub fn prove(
        left: Vec<E>,
        right: Vec<E>,
        opening_points: usize,
        parameters: &Parameters,
    ) -> Result<(Self, PrivateSumcheckProof)> {
        ensure!(
            left.len().is_power_of_two() && left.len() >= 2 && right.len() == left.len(),
            "invalid private polynomial tables"
        );
        let variables = left.len().ilog2() as usize;
        let spec = OracleSpec {
            variables,
            columns: 2,
        };
        spec.messages(opening_points)?;
        let mut rng = SysRng;
        let claimed_sum = left.iter().zip(&right).map(|(&a, &b)| a * b).sum();
        let data =
            CommittedOracle::new(spec, &[left.clone(), right.clone()], parameters, &mut rng)?;
        let statement = Self {
            variables,
            opening_points,
            claimed_sum,
            oracle_root: data.root(),
        };
        let mut ctx = MaskedProver::new(
            parameters,
            &statement.binding()?,
            statement.messages()?,
            &mut rng,
        )?;
        let mut left = Poly::new(left);
        let mut right = Poly::new(right);
        let mut point = Vec::with_capacity(variables);
        for _ in 0..variables {
            let round =
                VariableOrder::Prefix.sumcheck_coefficients(left.as_slice(), right.as_slice());
            ctx.send(b"round-polynomial", &[round.c_a, round.c_inf])?;
            let r = ctx.challenge(b"round-challenge")?;
            point.push(r);
            VariableOrder::Prefix.fix_var(&mut left, r);
            VariableOrder::Prefix.fix_var(&mut right, r);
        }
        ctx.send(
            b"terminal-evaluations",
            &[left.as_slice()[0], right.as_slice()[0]],
        )?;
        let mut points = vec![point];
        if opening_points == 2 {
            points.push(
                (0..variables)
                    .map(|_| ctx.challenge(b"second-oracle-point"))
                    .collect::<Result<_>>()?,
            );
        }
        let views: Vec<_> = points.iter().map(|p| OraclePoint::Current(p)).collect();
        let opening = data.open(&views, &mut ctx)?;
        let inner = ctx.finish(
            |reader| statement.replay(parameters, &opening, reader),
            &mut rng,
        )?;
        Ok((statement, PrivateSumcheckProof { inner, opening }))
    }

    pub fn verify(&self, parameters: &Parameters, proof: &PrivateSumcheckProof) -> Result<()> {
        self.spec().code(parameters)?;
        let mut reader = MaskedReader::new(
            parameters,
            &self.binding()?,
            self.messages()?,
            &proof.inner.masks.root,
            &proof.inner.masked,
        )?;
        let relation = self.replay(parameters, &proof.opening, &mut reader)?;
        reader.verify(parameters, &proof.inner, &relation)
    }

    fn spec(&self) -> OracleSpec {
        OracleSpec {
            variables: self.variables,
            columns: 2,
        }
    }

    fn messages(&self) -> Result<usize> {
        ensure!(
            (1..=20).contains(&self.variables),
            "invalid private sumcheck arity"
        );
        Ok(2 * self.variables + 2 + self.spec().messages(self.opening_points)?)
    }

    fn binding(&self) -> Result<Vec<u8>> {
        Ok(postcard::to_allocvec(&(PROGRAM, self))?)
    }

    fn replay(
        &self,
        parameters: &Parameters,
        opening: &OracleOpening,
        reader: &mut MaskedReader<'_>,
    ) -> Result<Relation> {
        let (claim, point) = replay_rounds(reader, self.variables, self.claimed_sum)?;
        let terminal = reader.read(b"terminal-evaluations", 2)?;
        let mut points = vec![point];
        if self.opening_points == 2 {
            points.push(
                (0..self.variables)
                    .map(|_| reader.challenge(b"second-oracle-point"))
                    .collect::<Result<_>>()?,
            );
        }
        let views: Vec<_> = points.iter().map(|p| OraclePoint::Current(p)).collect();
        let oracle = opening.verify(&self.spec(), &self.oracle_root, &views, parameters, reader)?;
        let mut linear = oracle.consistency;
        for (terminal, actual) in terminal.iter().zip(&oracle.values[0]) {
            let mut check = terminal.clone();
            check.terms.extend(actual.terms.iter().copied());
            linear.push(check);
        }
        Ok(Relation {
            variables: self.messages()?,
            public_wires: vec![],
            linear,
            products: vec![[terminal[0].clone(), terminal[1].clone(), claim]],
        })
    }
}

impl PrivateSumcheckProof {
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = PROOF_MAGIC.to_vec();
        bytes.extend(postcard::to_allocvec(self)?);
        ensure!(
            bytes.len() <= MAX_PROOF_BYTES,
            "private oracle proof exceeds transport limit"
        );
        Ok(bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() <= MAX_PROOF_BYTES,
            "private oracle proof exceeds transport limit"
        );
        let payload = bytes
            .strip_prefix(PROOF_MAGIC)
            .ok_or_else(|| anyhow::anyhow!("unsupported private oracle format"))?;
        let (proof, rest) = postcard::take_from_bytes(payload)?;
        ensure!(rest.is_empty(), "trailing private oracle proof bytes");
        Ok(proof)
    }
}
