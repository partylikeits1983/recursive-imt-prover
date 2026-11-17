//! Fixed Keccak IMT relation for the masked child compiler. A public schedule
//! places each hash directly after the previous one, so path links are ordinary
//! next-row constraints and need no separate product-bus argument.

use anyhow::{Result, ensure};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_keccak_air::{KeccakBinaryAir, NUM_KECCAK_BINARY_COLS, generate_binary_trace_rows};
use p3_matrix::dense::RowMajorMatrix;

use super::F;
use crate::binary::{
    relation::{ClientPublic, ClientWitness},
    tree::{LEAF_DOMAIN, NODE_DOMAIN, commitment, parent},
};

pub(super) const ROWS_PER_HASH: usize = 25;
pub(super) const STATE_START: usize = 25;
pub(super) const DIRECTION: usize = NUM_KECCAK_BINARY_COLS;
pub(super) const WIDTH: usize = DIRECTION + 1;
const NODE_START: usize = 25;
const LINK: usize = 26;
const ROOT: usize = 27;
const NEXT_FLAGS: usize = 28;
pub(super) const PREPROCESSED_WIDTH: usize = NEXT_FLAGS + ROWS_PER_HASH;

pub(super) struct MembershipAir {
    pub depth: usize,
}

struct KeccakBuilder<'a, AB: AirBuilder> {
    inner: &'a mut AB,
}

#[derive(Clone)]
struct KeccakWindow<T> {
    current: Vec<T>,
    next: Vec<T>,
}

impl MembershipAir {
    pub fn new(depth: usize) -> Result<Self> {
        ensure!(depth <= 32, "membership depth exceeds 32");
        Ok(Self { depth })
    }

    pub fn height(&self) -> usize {
        ((self.depth + 1) * ROWS_PER_HASH).next_power_of_two()
    }

    pub fn public_values(public: &ClientPublic) -> Vec<F> {
        public
            .root
            .iter()
            .chain(public.amount.to_le_bytes().iter())
            .flat_map(|&byte| (0..8).map(move |bit| F::from_bool((byte >> bit) & 1 == 1)))
            .collect()
    }

    pub fn trace(
        &self,
        public: &ClientPublic,
        witness: &ClientWitness,
    ) -> Result<RowMajorMatrix<F>> {
        ensure!(
            witness.merkle_path.len() == self.depth,
            "incorrect Merkle path length"
        );
        ensure!(
            u64::from(witness.leaf_index) < 1u64 << self.depth,
            "leaf index outside tree"
        );
        let mut message = Vec::from(LEAF_DOMAIN.as_slice());
        message.extend(witness.secret);
        message.extend(public.amount.to_le_bytes());
        message.extend(witness.nonce);
        let mut inputs = vec![sponge_input(&message)];
        let mut digest = commitment(&witness.secret, public.amount, &witness.nonce);
        for (level, sibling) in witness.merkle_path.iter().enumerate() {
            let (left, right) = if (witness.leaf_index >> level) & 1 == 0 {
                (&digest, sibling)
            } else {
                (sibling, &digest)
            };
            let mut message = Vec::from(NODE_DOMAIN.as_slice());
            message.extend(left);
            message.extend(right);
            inputs.push(sponge_input(&message));
            digest = parent(left, right);
        }
        // Do not turn this reference computation into a native-verifier Boolean.
        // The AIR binds the final hash to the supplied public root.
        let keccak = generate_binary_trace_rows::<F>(inputs, 0);
        let mut values = Vec::with_capacity(self.height() * WIDTH);
        for (row, state) in keccak
            .values
            .as_chunks::<NUM_KECCAK_BINARY_COLS>()
            .0
            .iter()
            .enumerate()
        {
            values.extend_from_slice(state);
            let hash = row / ROWS_PER_HASH;
            let direction = row % ROWS_PER_HASH == 24
                && hash < self.depth
                && (witness.leaf_index >> hash) & 1 == 1;
            values.push(F::from_bool(direction));
        }
        Ok(RowMajorMatrix::new(values, WIDTH))
    }
}

impl BaseAir<F> for MembershipAir {
    fn width(&self) -> usize {
        WIDTH
    }
    fn num_public_values(&self) -> usize {
        320
    }
    fn preprocessed_width(&self) -> usize {
        PREPROCESSED_WIDTH
    }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        let used = (self.depth + 1) * ROWS_PER_HASH;
        let mut values = vec![F::ZERO; self.height() * PREPROCESSED_WIDTH];
        for (row, prep) in values
            .as_chunks_mut::<PREPROCESSED_WIDTH>()
            .0
            .iter_mut()
            .enumerate()
        {
            let round = if row < used { row % ROWS_PER_HASH } else { 24 };
            prep[round] = F::ONE;
            prep[NODE_START] = F::from_bool(row > 0 && row < used && round == 0);
            prep[LINK] = F::from_bool(row < self.depth * ROWS_PER_HASH && round == 24);
            prep[ROOT] = F::from_bool(row == used - 1);
            let next = (row + 1).min(self.height() - 1);
            let next_round = if next < used {
                next % ROWS_PER_HASH
            } else {
                24
            };
            prep[NEXT_FLAGS + next_round] = F::ONE;
        }
        Some(RowMajorMatrix::new(values, PREPROCESSED_WIDTH))
    }
    fn preprocessed_next_row_columns(&self) -> Vec<usize> {
        vec![]
    }
    fn main_next_row_columns(&self) -> Vec<usize> {
        (0..NUM_KECCAK_BINARY_COLS).collect()
    }
}

impl<AB: AirBuilder<F = F>> Air<AB> for MembershipAir {
    fn eval(&self, builder: &mut AB) {
        // Expose only the original columns to the existing Keccak AIR, while
        // forwarding its optimized array assertions to the native folder.
        KeccakBinaryAir::default().eval(&mut KeccakBuilder { inner: builder });
        let main = builder.main();
        let local = main.current_slice();
        let next = main.next_slice();
        let prep = builder.preprocessed().clone();
        let prep = prep.current_slice();
        for i in 0..ROWS_PER_HASH {
            builder.assert_eq(local[i], prep[i]);
        }
        let d = local[DIRECTION];
        builder.assert_bool(d);
        // Non-link direction cells are fixed, so they are not unconstrained
        // witness channels. Each of the depth actual link bits remains private.
        builder.assert_zero((AB::Expr::ONE - prep[LINK]) * d);
        for bit in 0..256 {
            let value = local[STATE_START + bit];
            let left = next[STATE_START + 16 * 8 + bit];
            let right = next[STATE_START + 48 * 8 + bit];
            // In characteristic two, left + d*(left + right) selects the
            // authenticated child. Booleanity of d is enforced above.
            builder.assert_zero(prep[LINK] * (left.into() + d * (left + right) - value));
            let expected = builder.public_values()[bit];
            builder.assert_zero(prep[ROOT] * (value.into() - expected.into()));
        }
        for bit in 0..64 {
            let expected = builder.public_values()[256 + bit];
            builder
                .when_first_row()
                .assert_zero(local[STATE_START + 48 * 8 + bit].into() - expected.into());
        }
        for (domain, length, leaf) in [(LEAF_DOMAIN, 88, true), (NODE_DOMAIN, 80, false)] {
            let gate = if leaf {
                builder.is_first_row()
            } else {
                prep[NODE_START].into()
            };
            for byte in 0..200 {
                let fixed = if byte < domain.len() {
                    Some(domain[byte])
                } else if byte == length {
                    Some(1)
                } else if byte == 135 {
                    Some(128)
                } else if byte > length {
                    Some(0)
                } else {
                    None
                };
                if let Some(fixed) = fixed {
                    for bit in 0..8 {
                        builder.assert_zero(
                            gate.clone()
                                * (local[STATE_START + 8 * byte + bit]
                                    - F::from_bool((fixed >> bit) & 1 == 1)),
                        );
                    }
                }
            }
        }
    }
}

impl<T> WindowAccess<T> for KeccakWindow<T> {
    fn current_slice(&self) -> &[T] {
        &self.current
    }
    fn next_slice(&self) -> &[T] {
        &self.next
    }
}

impl<AB: AirBuilder> AirBuilder for KeccakBuilder<'_, AB> {
    type F = AB::F;
    type Expr = AB::Expr;
    type Var = AB::Var;
    type PublicVar = AB::PublicVar;
    type PeriodicVar = AB::PeriodicVar;
    type MainWindow = KeccakWindow<AB::Var>;
    type PreprocessedWindow = AB::PreprocessedWindow;
    fn main(&self) -> Self::MainWindow {
        let main = self.inner.main();
        let prep = self.inner.preprocessed().current_slice();
        // The hash schedule is fixed by the circuit. Feed its trusted flags to
        // the upstream AIR directly instead of multiplying hidden flag wires.
        // State bits still come exclusively from the committed private trace.
        KeccakWindow {
            current: prep[..ROWS_PER_HASH]
                .iter()
                .chain(&main.current_slice()[STATE_START..NUM_KECCAK_BINARY_COLS])
                .copied()
                .collect(),
            next: prep[NEXT_FLAGS..]
                .iter()
                .chain(&main.next_slice()[STATE_START..NUM_KECCAK_BINARY_COLS])
                .copied()
                .collect(),
        }
    }
    fn preprocessed(&self) -> &Self::PreprocessedWindow {
        self.inner.preprocessed()
    }
    fn is_first_row(&self) -> Self::Expr {
        self.inner.is_first_row()
    }
    fn is_last_row(&self) -> Self::Expr {
        self.inner.is_last_row()
    }
    fn is_transition(&self) -> Self::Expr {
        self.inner.is_transition()
    }
    fn public_values(&self) -> &[Self::PublicVar] {
        self.inner.public_values()
    }
    fn periodic_values(&self) -> &[Self::PeriodicVar] {
        self.inner.periodic_values()
    }
    fn assert_zero<I: Into<Self::Expr>>(&mut self, x: I) {
        self.inner.assert_zero(x);
    }
    fn assert_zeros<const N: usize, I: Into<Self::Expr>>(&mut self, values: [I; N]) {
        self.inner.assert_zeros(values);
    }
    fn assert_zeros_with_filter<const N: usize, I: Into<Self::Expr>, J: Into<Self::Expr>>(
        &mut self,
        filter: J,
        values: [I; N],
    ) {
        self.inner.assert_zeros_with_filter(filter, values);
    }
}

fn sponge_input(message: &[u8]) -> [u64; 25] {
    let mut state = [0u8; 200];
    state[..message.len()].copy_from_slice(message);
    state[message.len()] = 1;
    state[135] = 128;
    std::array::from_fn(|i| u64::from_le_bytes(state[8 * i..8 * i + 8].try_into().unwrap()))
}
