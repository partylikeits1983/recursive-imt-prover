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
    IMT_DEPTH,
    relation::{ClientPublic, ClientWitness, PUBLIC_BYTES},
    tree::{NODE_DOMAIN, RECORD_DOMAIN, TAG_DOMAIN, commitment, parent},
};

pub(super) const ROWS_PER_HASH: usize = 25;
pub(super) const STATE_START: usize = 25;
pub(super) const DIRECTION: usize = NUM_KECCAK_BINARY_COLS;
pub(super) const NONCE: usize = DIRECTION + 1;
pub(super) const QUANTITY: usize = NONCE + 4;
pub(super) const WIDTH: usize = QUANTITY + 1;
const NODE_START: usize = 25;
const LINK: usize = 26;
const ROOT: usize = 27;
const NONCE_START: usize = 28;
const NONCE_END: usize = 29;
const OUTPUT_START: usize = 30;
const OUTPUT_END: usize = 31;
const NEXT_FLAGS: usize = 32;
pub(super) const PREPROCESSED_WIDTH: usize = NEXT_FLAGS + ROWS_PER_HASH;

pub(super) struct MembershipAir;

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
        ensure!(depth == IMT_DEPTH, "child IMT depth must be 32");
        Ok(Self)
    }

    pub fn height(&self) -> usize {
        ((IMT_DEPTH + 3) * ROWS_PER_HASH).next_power_of_two()
    }

    pub fn public_values(public: &ClientPublic) -> Vec<F> {
        public.fields()
    }

    pub fn trace(
        &self,
        _public: &ClientPublic,
        witness: &ClientWitness,
    ) -> Result<RowMajorMatrix<F>> {
        ensure!(
            witness.merkle_path.len() == IMT_DEPTH,
            "incorrect Merkle path length"
        );
        let mut message = Vec::from(RECORD_DOMAIN.as_slice());
        message.extend(witness.input_label);
        message.extend(witness.input_nonce);
        message.extend(witness.quantity.to_le_bytes());
        let mut inputs = vec![sponge_input(&message)];
        let mut digest = commitment(&witness.input_label, &witness.input_nonce, witness.quantity);
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
        let mut message = Vec::from(TAG_DOMAIN.as_slice());
        message.extend(witness.input_nonce);
        inputs.push(sponge_input(&message));
        let mut message = Vec::from(RECORD_DOMAIN.as_slice());
        message.extend(witness.output_label);
        message.extend(witness.output_nonce);
        message.extend(witness.quantity.to_le_bytes());
        inputs.push(sponge_input(&message));
        let nonce: Vec<_> = witness
            .input_nonce
            .as_chunks::<8>()
            .0
            .iter()
            .map(|bytes| F::new(u64::from_le_bytes(*bytes)))
            .collect();
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
                && hash < IMT_DEPTH
                && (witness.leaf_index >> hash) & 1 == 1;
            values.push(F::from_bool(direction));
            values.extend_from_slice(&nonce);
            values.push(F::new(witness.quantity));
        }
        Ok(RowMajorMatrix::new(values, WIDTH))
    }
}

impl BaseAir<F> for MembershipAir {
    fn width(&self) -> usize {
        WIDTH
    }
    fn num_public_values(&self) -> usize {
        PUBLIC_BYTES
    }
    fn preprocessed_width(&self) -> usize {
        PREPROCESSED_WIDTH
    }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        let path_end = (IMT_DEPTH + 1) * ROWS_PER_HASH;
        let output_start = path_end + ROWS_PER_HASH;
        let used = output_start + ROWS_PER_HASH;
        let mut values = vec![F::ZERO; self.height() * PREPROCESSED_WIDTH];
        for (row, prep) in values
            .as_chunks_mut::<PREPROCESSED_WIDTH>()
            .0
            .iter_mut()
            .enumerate()
        {
            let round = if row < used { row % ROWS_PER_HASH } else { 24 };
            prep[round] = F::ONE;
            prep[NODE_START] = F::from_bool(row > 0 && row < path_end && round == 0);
            prep[LINK] = F::from_bool(row < IMT_DEPTH * ROWS_PER_HASH && round == 24);
            prep[ROOT] = F::from_bool(row == path_end - 1);
            prep[NONCE_START] = F::from_bool(row == path_end);
            prep[NONCE_END] = F::from_bool(row == output_start - 1);
            prep[OUTPUT_START] = F::from_bool(row == output_start);
            prep[OUTPUT_END] = F::from_bool(row == used - 1);
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
        (0..NUM_KECCAK_BINARY_COLS).chain(NONCE..WIDTH).collect()
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
        }
        // KeccakBinaryAir checks each state bit for Booleanity. Packing its
        // eight basis coordinates is therefore an injective byte encoding.
        for byte in 0..32 {
            let value = (0..8).fold(AB::Expr::ZERO, |sum, bit| {
                sum + local[STATE_START + 8 * byte + bit] * F::new(1 << bit)
            });
            let public = builder.public_values();
            let expected = prep[ROOT] * public[byte].into()
                + prep[NONCE_END] * public[32 + byte].into()
                + prep[OUTPUT_END] * public[64 + byte].into();
            builder
                .assert_zero((prep[ROOT] + prep[NONCE_END] + prep[OUTPUT_END]) * value - expected);
        }
        let record_start = builder.is_first_row() + prep[OUTPUT_START];
        let packed_quantity = (0..64).fold(AB::Expr::ZERO, |sum, bit| {
            sum + local[STATE_START + 80 * 8 + bit] * F::new(1u64 << bit)
        });
        builder
            .when_transition()
            .assert_eq(local[QUANTITY], next[QUANTITY]);
        builder.assert_zero(record_start.clone() * (packed_quantity - local[QUANTITY]));
        for limb in 0..4 {
            let carried = local[NONCE + limb];
            builder
                .when_transition()
                .assert_eq(carried, next[NONCE + limb]);
            for (offset, gate) in [(48, builder.is_first_row()), (16, prep[NONCE_START].into())] {
                let packed = (0..64).fold(AB::Expr::ZERO, |sum, bit| {
                    sum + local[STATE_START + offset * 8 + limb * 64 + bit] * F::new(1u64 << bit)
                });
                builder.assert_zero(gate * (packed - carried));
            }
        }
        for (domain, length, gate) in [
            (RECORD_DOMAIN, 88, record_start),
            (NODE_DOMAIN, 80, prep[NODE_START].into()),
            (TAG_DOMAIN, 48, prep[NONCE_START].into()),
        ] {
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
