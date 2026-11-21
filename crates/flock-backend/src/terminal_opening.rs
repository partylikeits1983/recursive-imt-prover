//! One ordinary additive WHIR run on a packed polynomial with two independently
//! authenticated faces. The fixed face uses the existing terminal preprocessing root.
mod batch;
mod bound;
#[cfg(feature = "opening-bench")]
pub(crate) mod capture;
pub(crate) mod integrated;
mod mmcs;
#[cfg(feature = "opening-bench")]
mod replay;
pub mod ring_certificate;
mod side;
#[cfg(feature = "opening-bench")]
pub use capture::{Recorded, record};
#[cfg(feature = "opening-bench")]
pub use replay::{BatchTrace, OpeningComparison, compare_recorded, terminal_body_cost};

use anyhow::{Result, ensure};
use p3_binary_field::Poly192 as E;
use p3_binary_pcs::whir::BinaryWhirDomain;
use p3_commit::MultilinearPcs;
use p3_field::PrimeCharacteristicRing;
use p3_matrix::{Dimensions, dense::RowMajorMatrix};
use p3_multilinear_util::point::Point;
use p3_sumcheck::{
    OpeningBatch, OpeningProtocol, PrescribedPointPcs, TableShape, TableSpec,
    commit::commit_borrowed_base,
    layout::{Layout, SuffixProver, Table},
};
use p3_symmetric::MerkleCap;
use p3_whir::{
    FoldingFactor, PcsProof, ProtocolParameters, SecurityAssumption, WhirConfig, WhirProver,
};

use crate::{
    F,
    config::{Challenger, TERMINAL_LOG_INV_RATE, merkle_tree},
};
use mmcs::PairedTree;

const FIRST: usize = 6;
const WIDTH: usize = 1 << FIRST;
const MAIN: usize = WIDTH / 2;
const FIXED: usize = WIDTH / 4;
/// Trusted terminal policy. The composed floor is checked against the actual verifier key.
#[derive(Clone, Copy, Debug)]
pub struct TerminalSecurity {
    pub local_bits: usize,
    pub max_grind: usize,
    pub conditional_floor: u32,
}

impl TerminalSecurity {
    const STRONG: Self = Self {
        local_bits: 152,
        max_grind: 16,
        conditional_floor: 144,
    };
    const COMPARISON: Self = Self {
        local_bits: 125,
        max_grind: 17,
        conditional_floor: 121,
    };
}
type Binding = SuffixProver<F, E>;
type Pcs = WhirProver<E, F, BinaryWhirDomain<F>, PairedTree, Challenger, Binding>;
type Cap = MerkleCap<F, [u8; 32]>;
type Proof = PcsProof<F, E, PairedTree>;

/// Pinned by the terminal verifier's trusted protocol identity.
#[derive(Clone, Copy)]
pub enum OpeningSchedule {
    ThreeVariableFolds,
    FourVariableFolds,
    FourVariableMidpoint,
    FourVariableMidpointComparison,
}

impl OpeningSchedule {
    pub fn security(self) -> TerminalSecurity {
        match self {
            Self::FourVariableMidpointComparison => TerminalSecurity::COMPARISON,
            _ => TerminalSecurity::STRONG,
        }
    }

    pub(crate) fn midpoint(self) -> bool {
        matches!(
            self,
            Self::FourVariableMidpoint | Self::FourVariableMidpointComparison
        )
    }
}

pub struct PairedOpening {
    pcs: Pcs,
    variables: usize,
    fixed_root: [u8; 32],
    protocol: OpeningProtocol,
}

pub struct CommittedPair {
    pub roots: [[u8; 32]; 2],
    data: p3_whir::WhirProverData<F, E, PairedTree, Binding>,
}

pub struct OpeningProof(Proof);

impl OpeningProof {
    pub fn encoded(&self) -> Result<Vec<u8>> {
        Ok(bincode::serde::encode_to_vec(
            &self.0,
            bincode::config::standard().with_fixed_int_encoding(),
        )?)
    }
}

impl PairedOpening {
    /// `variables` counts the virtual polynomial's variables. The two source
    /// polynomials have one and two fewer variables respectively.
    pub fn new(variables: usize, fixed_root: [u8; 32]) -> Result<Self> {
        Self::with_schedule(variables, fixed_root, OpeningSchedule::ThreeVariableFolds)
    }

    fn with_schedule(
        variables: usize,
        fixed_root: [u8; 32],
        schedule: OpeningSchedule,
    ) -> Result<Self> {
        let policy = schedule.security();
        Self::with_work_factors(
            variables,
            fixed_root,
            schedule,
            policy.local_bits,
            policy.max_grind,
        )
    }

    fn with_work_factors(
        variables: usize,
        fixed_root: [u8; 32],
        schedule: OpeningSchedule,
        local_bits: usize,
        max_grind: usize,
    ) -> Result<Self> {
        ensure!(
            (FIRST + 1..=26).contains(&variables),
            "unsupported paired geometry"
        );
        let (later_fold, round_log_inv_rates) = match schedule {
            OpeningSchedule::ThreeVariableFolds => (3, vec![]),
            OpeningSchedule::FourVariableFolds
            | OpeningSchedule::FourVariableMidpoint
            | OpeningSchedule::FourVariableMidpointComparison => {
                ensure!(
                    variables == 26,
                    "four-variable schedule requires the 26-variable terminal"
                );
                // Divide the encoded domain by four after the first fold, then by two each time.
                (4, vec![8, 11, 14, 17])
            }
        };
        let domain = BinaryWhirDomain::default();
        let config = WhirConfig::<E, F, Challenger>::new_with_domain(
            variables,
            ProtocolParameters {
                security_level: local_bits,
                pow_bits: max_grind,
                starting_log_inv_rate: TERMINAL_LOG_INV_RATE,
                round_log_inv_rates,
                folding_factor: FoldingFactor::ConstantFromSecondRound(FIRST, later_fold),
                soundness_type: SecurityAssumption::JohnsonBound,
            },
            &domain,
        )?;
        ensure!(
            config.check_pow_bits(),
            "unsupported paired folding schedule"
        );
        let height = 1 << (variables - FIRST + TERMINAL_LOG_INV_RATE);
        let tree = merkle_tree();
        #[cfg(feature = "opening-bench")]
        let tree = crate::opening_trace::TraceTree(tree);
        let tree = PairedTree {
            tree,
            first: Dimensions {
                width: WIDTH,
                height,
            },
            fixed_root,
        };
        let pcs = WhirProver::new(config, domain, tree);
        let batch = OpeningBatch::new(vec![0], vec![]);
        let protocol = OpeningProtocol::new(vec![TableSpec::new(
            TableShape::new(variables, 1),
            vec![batch.clone(), batch],
        )]);
        Ok(Self {
            pcs,
            variables,
            fixed_root,
            protocol,
        })
    }

    /// The fixed authority is calculated solely from the setup polynomial. Its
    /// row width and code rate match the original terminal preprocessing PCS.
    pub fn fixed_root(fixed: &[F]) -> Result<[u8; 32]> {
        ensure!(
            fixed.len().is_power_of_two() && fixed.len() >= FIXED && fixed.len() <= 1 << 24,
            "invalid wiring length"
        );
        let (cap, _) = commit_borrowed_base(
            &BinaryWhirDomain::<F>::default(),
            &merkle_tree(),
            FIRST - 2,
            TERMINAL_LOG_INV_RATE,
            fixed,
        );
        Ok(cap[0])
    }

    pub fn commit(&self, main: &[F], fixed: &[F], ch: &mut Challenger) -> Result<CommittedPair> {
        self.commit_words(self.words(main, fixed)?, ch)
    }

    fn words(&self, main: &[F], fixed: &[F]) -> Result<Vec<F>> {
        ensure!(
            main.len() == 1 << (self.variables - 1) && fixed.len() == 1 << (self.variables - 2),
            "incorrect paired witness lengths"
        );
        let mut union = F::zero_vec(1 << self.variables);
        for ((row, main), fixed) in union
            .as_chunks_mut::<WIDTH>()
            .0
            .iter_mut()
            .zip(main.as_chunks::<MAIN>().0)
            .zip(fixed.as_chunks::<FIXED>().0)
        {
            row[..MAIN].copy_from_slice(main);
            row[MAIN..MAIN + FIXED].copy_from_slice(fixed);
        }
        Ok(union)
    }

    fn commit_words(&self, union: Vec<F>, ch: &mut Challenger) -> Result<CommittedPair> {
        ensure!(
            union.len() == 1 << self.variables,
            "incorrect virtual polynomial length"
        );
        let len = union.len();
        let table = Table::new(RowMajorMatrix::new(union, len));
        let witness = Binding::new_witness(vec![table], FIRST);
        let (cap, data) = self.pcs.commit(witness, ch)?;
        ensure!(
            cap.num_roots() == 2 && cap[1] == self.fixed_root,
            "wrong setup wiring root"
        );
        Ok(CommittedPair {
            roots: [cap[0], cap[1]],
            data,
        })
    }

    /// Supply the two externally derived reading points separately. A role
    /// selector addresses each source in the same virtual multilinear polynomial.
    fn points(&self, main: &Point<E>, fixed: &Point<E>) -> Result<[Point<E>; 2]> {
        ensure!(
            main.num_variables() + 1 == self.variables
                && fixed.num_variables() + 2 == self.variables,
            "wrong reading arity"
        );
        let split = self.variables - FIRST;
        let insert = |p: &Point<E>, selection: &[E]| {
            let (row, col) = p.as_slice().split_at(split);
            Point::new([row, selection, col].concat())
        };
        Ok([insert(main, &[E::ZERO]), insert(fixed, &[E::ONE, E::ZERO])])
    }

    pub fn open(
        &self,
        pair: CommittedPair,
        points: [&Point<E>; 2],
        ch: &mut Challenger,
    ) -> Result<OpeningProof> {
        Ok(OpeningProof(self.pcs.open_at(
            pair.data,
            &self.protocol,
            &self.points(points[0], points[1])?,
            ch,
        )?))
    }

    pub fn observe(&self, roots: [[u8; 32]; 2], ch: &mut Challenger) -> Result<()> {
        ensure!(roots[1] == self.fixed_root, "wrong setup wiring root");
        self.pcs.observe_commitment(&Cap::new(roots.to_vec()), ch);
        Ok(())
    }

    pub fn verify(
        &self,
        roots: [[u8; 32]; 2],
        points: [&Point<E>; 2],
        expected: [E; 2],
        proof: &OpeningProof,
        ch: &mut Challenger,
    ) -> Result<()> {
        ensure!(roots[1] == self.fixed_root, "wrong setup wiring root");
        let evals = self.pcs.verify_at(
            &Cap::new(roots.to_vec()),
            &proof.0,
            &self.protocol,
            &self.points(points[0], points[1])?,
            ch,
        )?;
        ensure!(
            evals
                .iter()
                .zip(expected)
                .all(|(v, e)| v.current() == [e] && v.next().is_empty())
                && evals.len() == 2,
            "incorrect paired readings"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests;
