//! Fixed BLAKE3 IMT relation. A row proves one compression function call.

use std::borrow::Borrow;

use anyhow::{Result, ensure};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_blake3_air::{
    Blake3BinaryAir, Blake3BinaryCols, Blake3CompressionInput, NUM_BLAKE3_BINARY_COLS,
    generate_binary_trace_rows,
};
use p3_circuit::ops::{
    BLAKE3_IV, blake3_compress,
    blake3_flags::{CHUNK_END, CHUNK_START, ROOT as ROOT_FLAG},
};
use p3_field::{Algebra, PrimeCharacteristicRing};
use p3_matrix::dense::RowMajorMatrix;

use super::F;
use crate::binary::{
    IMT_DEPTH,
    relation::{ClientPublic, ClientWitness, PUBLIC_BYTES},
    tree::{LEAF_DOMAIN, NODE_DOMAIN, NULLIFIER_DOMAIN, commitment, parent},
};

pub(super) const ROWS_PER_HASH: usize = 2;
pub(super) const BLOCK_START: usize = 8 * 32;
pub(super) const DIRECTION: usize = NUM_BLAKE3_BINARY_COLS;
pub(super) const RIGHT_TAIL: usize = DIRECTION + 1;
pub(super) const NULLIFIER: usize = RIGHT_TAIL + 128;
pub(super) const WIDTH: usize = NULLIFIER + 4;
const LEAF_START: usize = 0;
const LEAF_END: usize = 1;
const NODE_START: usize = 2;
const NODE_END: usize = 3;
const LINK: usize = 4;
const ROOT: usize = 5;
const NULLIFIER_HASH: usize = 6;
const PADDING: usize = 7;
pub(super) const PREPROCESSED_WIDTH: usize = 8;
const NULLIFIER_ROW: usize = (IMT_DEPTH + 1) * ROWS_PER_HASH;
pub(super) struct MembershipAir;

struct CompressionBuilder<'a, AB>(&'a mut AB);

#[derive(Clone)]
struct CompressionWindow<T>(Vec<T>);

impl MembershipAir {
    pub fn new(depth: usize) -> Result<Self> {
        ensure!(depth == IMT_DEPTH, "child IMT depth must be 32");
        Ok(Self)
    }

    pub fn height(&self) -> usize {
        (NULLIFIER_ROW + 1).next_power_of_two()
    }

    pub fn public_values(public: &ClientPublic) -> Vec<F> {
        public
            .root
            .iter()
            .chain(&public.nullifier_hash)
            .flat_map(|&byte| (0..8).map(move |bit| F::from_bool((byte >> bit) & 1 == 1)))
            .collect()
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
        let mut inputs = Vec::with_capacity(self.height());
        let mut right_tails = Vec::with_capacity(IMT_DEPTH);
        let leaf = [
            LEAF_DOMAIN.as_slice(),
            &witness.secret_num,
            &witness.nullifier,
        ]
        .concat();
        append_message(&mut inputs, &leaf);
        let mut digest = commitment(&witness.secret_num, &witness.nullifier);
        for (level, sibling) in witness.merkle_path.iter().enumerate() {
            let (left, right) = if (witness.leaf_index >> level) & 1 == 0 {
                (&digest, sibling)
            } else {
                (sibling, &digest)
            };
            let message = [NODE_DOMAIN.as_slice(), left, right].concat();
            append_message(&mut inputs, &message);
            right_tails.push(<[u8; 16]>::try_from(&right[16..])?);
            digest = parent(left, right);
        }
        let nullifier_message = [NULLIFIER_DOMAIN.as_slice(), &witness.nullifier].concat();
        append_message(&mut inputs, &nullifier_message);
        inputs.resize(self.height(), Blake3CompressionInput::default());

        let trace = generate_binary_trace_rows::<F>(inputs, 0);
        let nullifier: Vec<_> = witness
            .nullifier
            .as_chunks::<8>()
            .0
            .iter()
            .map(|bytes| F::new(u64::from_le_bytes(*bytes)))
            .collect();
        let mut values = Vec::with_capacity(self.height() * WIDTH);
        for (row, cols) in trace
            .values
            .as_chunks::<NUM_BLAKE3_BINARY_COLS>()
            .0
            .iter()
            .enumerate()
        {
            values.extend_from_slice(cols);
            let link = row < 2 * IMT_DEPTH && row % 2 == 1;
            values.push(F::from_bool(
                link && (witness.leaf_index >> (row / 2)) & 1 == 1,
            ));
            if row > 0 && row < NULLIFIER_ROW && row % 2 == 0 {
                values.extend(
                    right_tails[row / 2 - 1].iter().flat_map(|&byte| {
                        (0..8).map(move |bit| F::from_bool((byte >> bit) & 1 == 1))
                    }),
                );
            } else {
                values.extend([F::ZERO; 128]);
            }
            values.extend_from_slice(&nullifier);
        }
        Ok(RowMajorMatrix::new(values, WIDTH))
    }
}

impl BaseAir<F> for MembershipAir {
    fn width(&self) -> usize {
        WIDTH
    }
    fn num_public_values(&self) -> usize {
        PUBLIC_BYTES * 8
    }
    fn preprocessed_width(&self) -> usize {
        PREPROCESSED_WIDTH
    }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        let mut values = vec![F::ZERO; self.height() * PREPROCESSED_WIDTH];
        for (row, flags) in values
            .as_chunks_mut::<PREPROCESSED_WIDTH>()
            .0
            .iter_mut()
            .enumerate()
        {
            let kind = match row {
                0 => LEAF_START,
                1 => LEAF_END,
                NULLIFIER_ROW => NULLIFIER_HASH,
                n if n > NULLIFIER_ROW => PADDING,
                n if n % 2 == 0 => NODE_START,
                _ => NODE_END,
            };
            flags[kind] = F::ONE;
            flags[LINK] = F::from_bool(row < 2 * IMT_DEPTH && row % 2 == 1);
            flags[ROOT] = F::from_bool(row == NULLIFIER_ROW - 1);
        }
        Some(RowMajorMatrix::new(values, PREPROCESSED_WIDTH))
    }
    fn preprocessed_next_row_columns(&self) -> Vec<usize> {
        vec![]
    }
    fn main_next_row_columns(&self) -> Vec<usize> {
        (0..24 * 32).chain(RIGHT_TAIL..WIDTH).collect()
    }
}

impl<AB: AirBuilder<F = F>> Air<AB> for MembershipAir {
    fn eval(&self, builder: &mut AB) {
        Blake3BinaryAir::default().eval(&mut CompressionBuilder(builder));
        let main = builder.main();
        let local = main.current_slice();
        let next = main.next_slice();
        let prep = builder.preprocessed().clone();
        let prep = prep.current_slice();
        let cols: &Blake3BinaryCols<AB::Var> = local[..NUM_BLAKE3_BINARY_COLS].borrow();
        let start = prep[LEAF_START] + prep[NODE_START];
        let end = prep[LEAF_END] + prep[NODE_END];
        let d = local[DIRECTION];
        builder.assert_bool(d);
        builder.assert_zero((AB::Expr::ONE - prep[LINK]) * d);

        // Every compression lives in chunk zero. Its flags and length follow the fixed schedule.
        builder.assert_zeros(cols.counter_low);
        builder.assert_zeros(cols.counter_high);
        for bit in 0..32 {
            let expected_len: AB::Expr = start.clone() * bit_value(64, bit)
                + end.clone() * bit_value(16, bit)
                + prep[NULLIFIER_HASH] * bit_value(48, bit);
            let expected_flags: AB::Expr = start.clone() * bit_value(CHUNK_START, bit)
                + end.clone() * bit_value(CHUNK_END | ROOT_FLAG, bit)
                + prep[NULLIFIER_HASH] * bit_value(CHUNK_START | CHUNK_END | ROOT_FLAG, bit);
            builder.assert_eq(cols.block_len[bit], expected_len);
            builder.assert_eq(cols.flags[bit], expected_flags);
        }
        let iv = start.clone() + prep[NULLIFIER_HASH];
        let outputs = output_bits::<AB::Var, AB::Expr>(cols);
        for (bit, value) in outputs.into_iter().enumerate() {
            let cv = cols.chaining_value[bit / 32][bit % 32];
            builder.assert_zero(iv.clone() * (cv - bit_value(BLAKE3_IV[bit / 32], bit % 32)));
            builder.assert_zero(prep[PADDING] * cv);
            builder.assert_zero(start.clone() * (AB::Expr::from(next[bit]) - value.clone()));

            let left = next[BLOCK_START + 16 * 8 + bit];
            let right = if bit < 128 {
                next[BLOCK_START + 48 * 8 + bit]
            } else {
                next[RIGHT_TAIL + bit - 128]
            };
            builder.assert_zero(prep[LINK] * (left.into() + d * (left + right) - value.clone()));
            let expected_root = builder.public_values()[bit];
            let expected_nullifier = builder.public_values()[256 + bit];
            builder.assert_zero(prep[ROOT] * (value.clone() - expected_root.into()));
            builder.assert_zero(prep[NULLIFIER_HASH] * (value - expected_nullifier.into()));
        }
        for bit in 0..128 {
            let tail = local[RIGHT_TAIL + bit];
            builder.assert_zero(prep[NODE_START] * (tail - next[BLOCK_START + bit]));
            builder.assert_zero((AB::Expr::ONE - prep[NODE_START]) * tail);
        }
        for limb in 0..4 {
            let carried = local[NULLIFIER + limb];
            builder
                .when_transition()
                .assert_eq(carried, next[NULLIFIER + limb]);
            let pack = |offset| {
                (0..64).fold(AB::Expr::ZERO, |sum, bit| {
                    sum + local[BLOCK_START + offset + bit] * F::new(1u64 << bit)
                })
            };
            let (leaf_kind, leaf_offset) = if limb < 2 {
                (LEAF_START, 48 * 8 + limb * 64)
            } else {
                (LEAF_END, (limb - 2) * 64)
            };
            builder.assert_zero(prep[leaf_kind] * (pack(leaf_offset) - carried));
            builder.assert_zero(prep[NULLIFIER_HASH] * (pack(16 * 8 + limb * 64) - carried));
        }
        for bit in 0..512 {
            let value = local[BLOCK_START + bit];
            if bit < 128 {
                for (kind, tag) in [
                    (LEAF_START, LEAF_DOMAIN),
                    (NODE_START, NODE_DOMAIN),
                    (NULLIFIER_HASH, NULLIFIER_DOMAIN),
                ] {
                    builder.assert_zero(
                        prep[kind] * (value - bit_value(u32::from(tag[bit / 8]), bit % 8)),
                    );
                }
            }
            if bit >= 128 {
                builder.assert_zero(end.clone() * value);
            }
            if bit >= 48 * 8 {
                builder.assert_zero(prep[NULLIFIER_HASH] * value);
            }
            builder.assert_zero(prep[PADDING] * value);
        }
    }
}

impl<T> WindowAccess<T> for CompressionWindow<T> {
    fn current_slice(&self) -> &[T] {
        &self.0
    }
    fn next_slice(&self) -> &[T] {
        &[]
    }
}

impl<AB: AirBuilder> AirBuilder for CompressionBuilder<'_, AB> {
    type F = AB::F;
    type Expr = AB::Expr;
    type Var = AB::Var;
    type PublicVar = AB::PublicVar;
    type PeriodicVar = AB::PeriodicVar;
    type MainWindow = CompressionWindow<AB::Var>;
    type PreprocessedWindow = AB::PreprocessedWindow;
    fn main(&self) -> Self::MainWindow {
        CompressionWindow(self.0.main().current_slice()[..NUM_BLAKE3_BINARY_COLS].to_vec())
    }
    fn preprocessed(&self) -> &Self::PreprocessedWindow {
        self.0.preprocessed()
    }
    fn is_first_row(&self) -> Self::Expr {
        self.0.is_first_row()
    }
    fn is_last_row(&self) -> Self::Expr {
        self.0.is_last_row()
    }
    fn is_transition(&self) -> Self::Expr {
        self.0.is_transition()
    }
    fn public_values(&self) -> &[Self::PublicVar] {
        self.0.public_values()
    }
    fn periodic_values(&self) -> &[Self::PeriodicVar] {
        self.0.periodic_values()
    }
    fn assert_zero<I: Into<Self::Expr>>(&mut self, value: I) {
        self.0.assert_zero(value);
    }
    fn assert_zeros<const N: usize, I: Into<Self::Expr>>(&mut self, values: [I; N]) {
        self.0.assert_zeros(values);
    }
}

fn bit_value(value: u32, bit: usize) -> F {
    F::from_bool((value >> bit) & 1 == 1)
}

// The last four G steps finish each state word. Undo the final rotations of
// a and c, then XOR the top and bottom halves to obtain the chaining value.
fn output_bits<T: Copy, E: Algebra<T>>(cols: &Blake3BinaryCols<T>) -> [E; 256] {
    let last = &cols.rounds[6][4..];
    std::array::from_fn(|i| {
        let (word, bit) = (i / 32, i % 32);
        if word < 4 {
            let a = &last[word];
            let c = &last[(word + 2) % 4];
            E::from(a.d1[bit]) + a.d2[(bit + 24) % 32] + c.b1[bit] + c.b2[(bit + 25) % 32]
        } else {
            let b = &last[(word + 3) % 4];
            let d = &last[(word + 1) % 4];
            E::from(b.b2[bit]) + d.d2[bit]
        }
    })
}

fn append_message(inputs: &mut Vec<Blake3CompressionInput>, message: &[u8]) {
    let mut chaining_value = BLAKE3_IV;
    for (i, bytes) in message.chunks(64).enumerate() {
        let mut block = [0u8; 64];
        block[..bytes.len()].copy_from_slice(bytes);
        let root = (i + 1) * 64 >= message.len();
        let input = Blake3CompressionInput {
            chaining_value,
            block: std::array::from_fn(|i| u32::from_le_bytes(block.as_chunks::<4>().0[i])),
            counter: 0,
            block_len: bytes.len() as u32,
            flags: (if i == 0 { CHUNK_START } else { 0 })
                | (if root { CHUNK_END | ROOT_FLAG } else { 0 }),
        };
        if !root {
            let mut words = [0; 28];
            words[..16].copy_from_slice(&input.block);
            words[16..24].copy_from_slice(&input.chaining_value);
            words[26] = input.block_len;
            words[27] = input.flags;
            chaining_value.copy_from_slice(&blake3_compress(&words)[..8]);
        }
        inputs.push(input);
    }
}
