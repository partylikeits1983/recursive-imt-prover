//! Experimental complete masked AIR/WHIR membership child. This closes the
//! arithmetic and oracle relation. Its recursive verifier is enforced by the
//! aggregate; a full adaptive ZK/ROM composition analysis is outstanding.

use anyhow::{Result, ensure};
use p3_air::{AirLayout, BaseAir, get_symbolic_constraints};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use p3_multi_stark::{
    rounds::AirDegrees,
    selectors::BoundaryEvals,
    zerocheck::{AirZerocheck, transcript::ZerocheckShape},
};
use p3_multilinear_util::point::Point;
use p3_sumcheck::layout::Table;
use rand::{SeedableRng, rngs::StdRng};
use serde::{Deserialize, Serialize};

use super::{
    E, F,
    air_algebra::{AirAlgebra, PublicEvaluation, add, scale},
    compiler::{MaskedProver, MaskedReader},
    constraints::{ExperimentalProof, Linear, Relation},
    membership_air::{MembershipAir, PREPROCESSED_WIDTH, WIDTH},
    native::{NativeAirProgram, OraclePoint},
    parameters::Parameters,
    stacked_oracle::{StackedOpening, StackedOracle, StackedSpec},
    vector::dot,
};
use crate::binary::{
    IMT_DEPTH,
    relation::{ClientPublic, ClientWitness},
};

pub const PROTOCOL: &str = "experimental-binary-blake3-masked-imt-v7";
const PROOF_MAGIC: &[u8; 8] = b"IMTVCA07";
const MAX_PROOF_BYTES: usize = 64 << 20;

pub mod recursive;
#[cfg(test)]
mod tests;

pub struct PreparedMembership {
    air: MembershipAir,
    algebra: AirAlgebra,
    program: NativeAirProgram,
    parameters: Parameters,
    prep: Table<F>,
    prep_columns: Vec<Vec<E>>,
    oracle: StackedSpec,
    identity: [u8; 32],
    messages: usize,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct MaskedMembershipProof {
    oracle_root: [u8; 32],
    inner: ExperimentalProof,
    opening: StackedOpening,
}

struct PendingChild {
    root: [u8; 32],
    ctx: MaskedProver,
    opening: StackedOpening,
    rng: StdRng,
}

impl PreparedMembership {
    pub fn new(depth: usize, parameters: Parameters) -> Result<Self> {
        parameters.validate()?;
        let air = MembershipAir::new(depth)?;
        let expressions = get_symbolic_constraints::<F, _>(&air, AirLayout::from_air::<F>(&air));
        let degree = expressions
            .iter()
            .map(|e| e.poly_degree(2, &[]))
            .max()
            .unwrap();
        let variables = air.height().ilog2() as usize;
        let program = NativeAirProgram::new(ZerocheckShape::new(
            &[AirDegrees {
                constraints: degree,
                interactions: 0,
            }],
            variables,
            0,
            0,
        ))?;
        let algebra = AirAlgebra::new(&expressions)?;
        let oracle = StackedSpec {
            variables,
            columns: WIDTH,
            log_stack: 7,
        };
        oracle.code(&parameters)?;
        let messages = program.message_count() + oracle.messages(2)? + algebra.products;
        ensure!(
            messages + 6 <= parameters.max_message_len,
            "masked AIR exceeds message budget"
        );
        let preprocessed = air.preprocessed_trace().unwrap().transpose();
        let identity = blake3::hash(&postcard::to_allocvec(&(
            PROTOCOL,
            depth,
            algebra.identity,
            program.binding()?,
            &oracle,
            &preprocessed.values,
        ))?)
        .into();
        let prep_columns = preprocessed
            .values
            .chunks_exact(air.height())
            .map(|c| c.iter().copied().map(E::from).collect())
            .collect();
        let prep = Table::new(preprocessed);
        Ok(Self {
            air,
            algebra,
            program,
            parameters,
            prep,
            prep_columns,
            oracle,
            identity,
            messages,
        })
    }

    pub fn identity(&self) -> [u8; 32] {
        self.identity
    }
    pub fn depth(&self) -> usize {
        IMT_DEPTH
    }
    pub fn trace_height(&self) -> usize {
        self.air.height()
    }
    pub fn trace_width(&self) -> usize {
        WIDTH
    }
    pub fn masked_messages(&self) -> usize {
        self.messages
    }
    pub fn verifier_products(&self) -> usize {
        self.algebra.products
    }

    pub fn oracle_columns(&self) -> usize {
        WIDTH.div_ceil(1 << self.oracle.log_stack) + 1
    }

    pub fn stacking_factor(&self) -> usize {
        1 << self.oracle.log_stack
    }

    pub fn retained_oracle_bytes(&self) -> Result<usize> {
        self.oracle.retained_bytes(&self.parameters)
    }

    pub fn witness(
        &self,
        public: &ClientPublic,
        witness: &ClientWitness,
    ) -> Result<RowMajorMatrix<F>> {
        self.air.trace(public, witness)
    }

    pub fn prove(
        &self,
        public: &ClientPublic,
        witness: &ClientWitness,
    ) -> Result<MaskedMembershipProof> {
        self.prove_trace(public, self.witness(public, witness)?)
    }

    /// Trace preparation can be measured separately. Invalid traces still have
    /// to satisfy the proof relation; the verifier never trusts a native check.
    pub fn prove_trace(
        &self,
        public: &ClientPublic,
        trace: RowMajorMatrix<F>,
    ) -> Result<MaskedMembershipProof> {
        let PendingChild {
            root,
            ctx,
            opening,
            mut rng,
        } = self.prepare(public, trace)?;
        let inner = ctx.finish(
            |reader| self.replay(public, &root, &opening, reader),
            &mut rng,
        )?;
        Ok(MaskedMembershipProof {
            oracle_root: root,
            inner,
            opening,
        })
    }

    fn prepare(&self, public: &ClientPublic, trace: RowMajorMatrix<F>) -> Result<PendingChild> {
        ensure!(
            trace.width == WIDTH && trace.values.len() == WIDTH * self.air.height(),
            "wrong membership trace shape"
        );
        let mut rng = StdRng::from_rng(&mut rand::rng());
        let transposed = trace.transpose();
        let columns: Vec<Vec<E>> = transposed
            .values
            .chunks_exact(self.air.height())
            .map(|c| c.iter().copied().map(E::from).collect())
            .collect();
        let data = StackedOracle::new(self.oracle.clone(), &columns, &self.parameters, &mut rng)?;
        drop(columns);
        let root = data.root();
        let mut ctx = MaskedProver::new(
            &self.parameters,
            &self.binding(public, &root)?,
            self.messages,
            &mut rng,
        )?;
        let table = Table::new(transposed);
        let values = MembershipAir::public_values(public);
        let airs = [&self.air];
        let mut channel = self.program.prover(&mut ctx);
        let (private_proof, point) = AirZerocheck::new(&airs, 0).prove::<F, E, _>(
            &[Some(&self.prep)],
            &[&table],
            &[&values],
            &mut channel,
        );
        channel.finish()?;
        // The ordinary native proof is private intermediate state. Only the
        // corresponding masked messages, oracle proof and consistency argument
        // below enter the transport format.
        let mut next = vec![E::ZERO; WIDTH];
        for (column, &value) in self
            .air
            .main_next_row_columns()
            .into_iter()
            .zip(&private_proof.next[0])
        {
            next[column] = value;
        }
        let main = [private_proof.local[0].clone(), next];
        let prep = self.public_preprocessing(point.as_slice());
        let products = self.algebra.witness(
            &main,
            &PublicEvaluation {
                inputs: &values,
                preprocessed: &prep,
                boundary: BoundaryEvals::at(point.as_slice()),
            },
        )?;
        drop(private_proof);
        let opening = data.open(
            &[
                OraclePoint::Current(point.as_slice()),
                OraclePoint::Next(point.as_slice()),
            ],
            &mut ctx,
        )?;
        ctx.send(b"air-verifier-products", &products)?;
        Ok(PendingChild {
            root,
            ctx,
            opening,
            rng,
        })
    }

    pub fn verify(&self, public: &ClientPublic, proof: &MaskedMembershipProof) -> Result<()> {
        let mut reader = MaskedReader::new(
            &self.parameters,
            &self.binding(public, &proof.oracle_root)?,
            self.messages,
            &proof.inner.masks.root,
            &proof.inner.masked,
        )?;
        let relation = self.replay(public, &proof.oracle_root, &proof.opening, &mut reader)?;
        reader.verify(&self.parameters, &proof.inner, &relation)
    }

    fn replay(
        &self,
        public: &ClientPublic,
        root: &[u8; 32],
        opening: &StackedOpening,
        reader: &mut MaskedReader<'_>,
    ) -> Result<Relation> {
        let replay = self.program.replay(reader)?;
        let reduction = self.program.reduce(replay)?;
        let oracle = opening.verify(
            &self.oracle,
            root,
            &[
                OraclePoint::Current(&reduction.point),
                OraclePoint::Next(&reduction.point),
            ],
            &self.parameters,
            reader,
        )?;
        let inputs = MembershipAir::public_values(public);
        let prep = self.public_preprocessing(&reduction.point);
        let endpoint = self.algebra.constrain(
            &oracle.values,
            &PublicEvaluation {
                inputs: &inputs,
                preprocessed: &prep,
                boundary: BoundaryEvals::at(&reduction.point),
            },
            reader,
        )?;
        // Native AIR folders use descending alpha powers (Horner order). There
        // is one AIR, so the AIR batching coefficient is beta^0 = 1.
        let combined = endpoint
            .outputs
            .iter()
            .fold(Linear::constant(E::ZERO), |acc, expression| {
                add(&scale(&acc, reduction.alpha), expression)
            });
        let expected = scale(&combined, Point::eval_eq(&reduction.tau, &reduction.point));
        let mut linear = oracle.consistency;
        linear.push(add(&expected, &reduction.claim));
        Ok(Relation {
            variables: self.messages,
            public_wires: vec![],
            linear,
            products: endpoint.products,
        })
    }

    fn public_preprocessing(&self, point: &[E]) -> [Vec<E>; 2] {
        let weights = OraclePoint::Current(point).weights();
        let current = self.prep_columns.iter().map(|c| dot(c, &weights)).collect();
        // This fixed AIR declares no next-row preprocessing references.
        [current, vec![E::ZERO; PREPROCESSED_WIDTH]]
    }

    fn binding(&self, public: &ClientPublic, root: &[u8; 32]) -> Result<Vec<u8>> {
        let mut bytes = PROTOCOL.as_bytes().to_vec();
        bytes.extend(self.identity);
        for value in [
            self.parameters.query_bits,
            self.parameters.min_algebraic_bits,
            self.parameters.log_inv_rate,
            self.parameters.max_message_len,
        ] {
            bytes.extend((value as u64).to_le_bytes());
        }
        bytes.extend(public.root);
        bytes.extend(public.nullifier_hash);
        bytes.extend(root);
        Ok(bytes)
    }
}

impl MaskedMembershipProof {
    /// Serialized components, excluding the outer root and format header.
    pub fn component_bytes(&self) -> Result<(usize, usize)> {
        Ok((
            postcard::to_allocvec(&self.opening)?.len(),
            postcard::to_allocvec(&self.inner)?.len(),
        ))
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = PROOF_MAGIC.to_vec();
        bytes.extend(postcard::to_allocvec(self)?);
        ensure!(
            bytes.len() <= MAX_PROOF_BYTES,
            "masked membership proof exceeds transport cap"
        );
        Ok(bytes)
    }
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() <= MAX_PROOF_BYTES,
            "masked membership proof exceeds transport cap"
        );
        let payload = bytes
            .strip_prefix(PROOF_MAGIC)
            .ok_or_else(|| anyhow::anyhow!("unsupported masked membership format"))?;
        let (proof, rest) = postcard::take_from_bytes(payload)?;
        ensure!(rest.is_empty(), "trailing masked membership proof bytes");
        Ok(proof)
    }
}
