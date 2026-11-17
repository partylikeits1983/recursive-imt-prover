//! Single membership AIR using upstream Keccak constraints without lookup arguments.
use crate::legacy::config::{F, Profile};
use crate::legacy::note::{AMOUNT_OFFSET, NOTE_BYTES};
use crate::legacy::statement::{AMOUNT_LIMBS, CLAIM_FIELDS, DIGEST_LIMBS};
use crate::legacy::tree::{NODE_TAG, Witness, check_depth, hash_node};
use anyhow::{Result, ensure};
use core::array::from_fn;
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_keccak_air::{
    KeccakAir, KeccakCols, NUM_KECCAK_COLS, NUM_ROUNDS, U64_LIMBS, generate_trace_rows, output_limb,
};
use p3_matrix::{Matrix, dense::RowMajorMatrix};
use std::borrow::Borrow;

const KECCAK_LANES: usize = 25;
const STATE_BYTES: usize = KECCAK_LANES * 8;
const STATE_LIMBS: usize = KECCAK_LANES * U64_LIMBS;
const SHA3_RATE_BYTES: usize = 136;
const SHA3_SUFFIX: u8 = 0x06;
const LEAF_MESSAGE_LIMBS: usize = NOTE_BYTES / 2;
const NODE_TAG_LIMBS: usize = NODE_TAG.len() / 2;
const NODE_MESSAGE_LIMBS: usize = NODE_TAG_LIMBS + 2 * DIGEST_LIMBS;
const FINAL_PADDING_LIMB: usize = SHA3_RATE_BYTES / 2 - 1;

type AirExpr<AB> = <AB as AirBuilder>::Expr;
type AirVar<AB> = <AB as AirBuilder>::Var;

#[derive(Clone, Debug)]
pub struct ImtAir {
    depth: u8,
}

#[derive(Clone)]
struct KeccakWindow<W>(W);

struct KeccakBuilder<'a, AB>(&'a mut AB);

impl<T, W: WindowAccess<T>> WindowAccess<T> for KeccakWindow<W> {
    fn current_slice(&self) -> &[T] {
        &self.0.current_slice()[..NUM_KECCAK_COLS]
    }

    fn next_slice(&self) -> &[T] {
        &self.0.next_slice()[..NUM_KECCAK_COLS]
    }
}

impl<AB: AirBuilder> AirBuilder for KeccakBuilder<'_, AB> {
    type F = AB::F;
    type Expr = AirExpr<AB>;
    type Var = AirVar<AB>;
    type MainWindow = KeccakWindow<AB::MainWindow>;
    type PreprocessedWindow = AB::PreprocessedWindow;
    type PublicVar = AB::PublicVar;
    type PeriodicVar = AB::PeriodicVar;

    fn main(&self) -> Self::MainWindow {
        KeccakWindow(self.0.main())
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

    fn assert_zero<I: Into<Self::Expr>>(&mut self, x: I) {
        self.0.assert_zero(x);
    }

    fn public_values(&self) -> &[Self::PublicVar] {
        self.0.public_values()
    }

    fn periodic_values(&self) -> &[Self::PeriodicVar] {
        self.0.periodic_values()
    }
}

impl ImtAir {
    pub fn new(depth: u8) -> Result<Self> {
        check_depth(depth)?;
        Ok(Self { depth })
    }

    pub fn depth(&self) -> u8 {
        self.depth
    }

    pub fn stage_col(&self, stage: usize) -> usize {
        NUM_KECCAK_COLS + stage
    }

    pub fn direction_col(&self) -> usize {
        NUM_KECCAK_COLS + self.depth as usize + 2
    }

    pub fn inverse_col(&self) -> usize {
        self.direction_col() + 1
    }

    pub fn width(&self) -> usize {
        self.inverse_col() + 1
    }

    pub fn height(&self, profile: Profile) -> usize {
        (NUM_ROUNDS * (self.depth as usize + 1) + 1)
            .next_power_of_two()
            .max(profile.hiding_min_height())
    }

    pub fn trace(&self, witness: &Witness, profile: Profile) -> Result<RowMajorMatrix<F>> {
        ensure!(
            witness.path.len() == self.depth as usize,
            "wrong authentication path depth"
        );
        ensure!(
            witness.index < (1u64 << self.depth),
            "index outside tree capacity"
        );
        let mut inputs = vec![padded(&witness.note.message())];
        let leaf = witness.note.commitment();
        let mut node = leaf;
        for (i, &sibling) in witness.path.iter().enumerate() {
            let (left, right) = if (witness.index >> i) & 1 == 0 {
                (node, sibling)
            } else {
                (sibling, node)
            };
            let mut message = Vec::from(NODE_TAG);
            message.extend(left.0);
            message.extend(right.0);
            inputs.push(padded(&message));
            node = hash_node(left, right);
        }
        let height = self.height(profile);
        // At least one row after the final real permutation, to constrain DONE.
        // Upstream fills any remaining partial permutation with the zero state.
        inputs.resize(height / NUM_ROUNDS, [0; KECCAK_LANES]);
        let keccak = generate_trace_rows::<F>(inputs, 0);
        ensure!(keccak.height() == height, "unexpected Keccak trace height");
        let mut values = F::zero_vec(height * self.width());
        let sum: F = leaf.fields().into_iter().sum();
        let inverse = sum.try_inverse().unwrap_or(F::ZERO);
        for (row_index, row) in values.chunks_mut(self.width()).enumerate() {
            row[..NUM_KECCAK_COLS].copy_from_slice(&keccak.row_slice(row_index).unwrap());
            let stage = (row_index / NUM_ROUNDS).min(self.depth as usize + 1);
            row[self.stage_col(stage)] = F::ONE;
            if (1..=self.depth as usize).contains(&stage) {
                row[self.direction_col()] = F::from_u8(((witness.index >> (stage - 1)) & 1) as u8);
            }
            if stage == 0 {
                row[self.inverse_col()] = inverse;
            }
        }
        Ok(RowMajorMatrix::new(values, self.width()))
    }
}

impl<F> BaseAir<F> for ImtAir {
    fn width(&self) -> usize {
        self.width()
    }

    fn num_public_values(&self) -> usize {
        CLAIM_FIELDS
    }
}

impl<AB: AirBuilder> Air<AB> for ImtAir {
    fn eval(&self, builder: &mut AB) {
        KeccakAir {}.eval(&mut KeccakBuilder(builder));
        let main = builder.main();
        let local = main.current_slice();
        let next = main.next_slice();
        let current_keccak: &KeccakCols<AirVar<AB>> = local[..NUM_KECCAK_COLS].borrow();
        let next_keccak: &KeccakCols<AirVar<AB>> = next[..NUM_KECCAK_COLS].borrow();
        let round_end: AirExpr<AB> = current_keccak.step_flags[NUM_ROUNDS - 1].into();
        let round_start: AirExpr<AB> = current_keccak.step_flags[0].into();
        let leaf_stage: AirExpr<AB> = local[self.stage_col(0)].into();
        let done_stage: AirExpr<AB> = local[self.stage_col(self.depth as usize + 1)].into();
        let root_stage: AirExpr<AB> = local[self.stage_col(self.depth as usize)].into();

        for i in 0..self.depth as usize + 2 {
            let stage_active: AirExpr<AB> = local[self.stage_col(i)].into();
            builder.assert_bool(local[self.stage_col(i)]);
            builder.when_first_row().assert_eq(
                stage_active.clone(),
                AirExpr::<AB>::from_u8(u8::from(i == 0)),
            );
            let expected = if i == 0 {
                stage_active.clone() * (AirExpr::<AB>::ONE - round_end.clone())
            } else if i == self.depth as usize + 1 {
                stage_active.clone() + root_stage.clone() * round_end.clone()
            } else {
                stage_active.clone() * (AirExpr::<AB>::ONE - round_end.clone())
                    + AirExpr::<AB>::from(local[self.stage_col(i - 1)]) * round_end.clone()
            };
            builder
                .when_transition()
                .assert_eq(next[self.stage_col(i)], expected);
        }
        builder.when_last_row().assert_one(done_stage.clone());

        let direction: AirExpr<AB> = local[self.direction_col()].into();
        builder.assert_bool(local[self.direction_col()]);
        builder
            .when_transition()
            .when(AirExpr::<AB>::ONE - round_end.clone())
            .assert_eq(next[self.direction_col()], direction);

        for limb in 0..AMOUNT_LIMBS {
            let public_amount = builder.public_values()[DIGEST_LIMBS + limb];
            builder
                .when(leaf_stage.clone() * round_start.clone())
                .assert_eq(
                    preimage_limb(current_keccak, AMOUNT_OFFSET / 2 + limb),
                    public_amount,
                );
        }

        let internal_stage = AirExpr::<AB>::ONE - leaf_stage.clone() - done_stage.clone();
        for i in 0..STATE_LIMBS {
            if i >= LEAF_MESSAGE_LIMBS {
                let expected = if i == LEAF_MESSAGE_LIMBS {
                    u16::from(SHA3_SUFFIX)
                } else if i == FINAL_PADDING_LIMB {
                    0x8000
                } else {
                    0
                };
                builder
                    .when(leaf_stage.clone() * round_start.clone())
                    .assert_eq(
                        preimage_limb(current_keccak, i),
                        AirExpr::<AB>::from_u16(expected),
                    );
            }
            if i == 0 || i >= NODE_MESSAGE_LIMBS {
                let expected = if i == 0 {
                    u16::from_le_bytes(NODE_TAG)
                } else if i == NODE_MESSAGE_LIMBS {
                    u16::from(SHA3_SUFFIX)
                } else if i == FINAL_PADDING_LIMB {
                    0x8000
                } else {
                    0
                };
                builder
                    .when(internal_stage.clone() * round_start.clone())
                    .assert_eq(
                        preimage_limb(current_keccak, i),
                        AirExpr::<AB>::from_u16(expected),
                    );
            }
        }

        let link_digest =
            round_end.clone() * (AirExpr::<AB>::ONE - done_stage - root_stage.clone());
        let next_direction: AirExpr<AB> = next[self.direction_col()].into();
        for i in 0..DIGEST_LIMBS {
            let left: AirExpr<AB> = preimage_limb(next_keccak, NODE_TAG_LIMBS + i).into();
            let right: AirExpr<AB> =
                preimage_limb(next_keccak, NODE_TAG_LIMBS + DIGEST_LIMBS + i).into();
            let selected = left.clone() + next_direction.clone() * (right - left);
            builder
                .when_transition()
                .when(link_digest.clone())
                .assert_eq(local[output_limb(i)], selected);
            let public = builder.public_values()[i];
            builder
                .when(round_end.clone() * root_stage.clone())
                .assert_eq(local[output_limb(i)], public);
        }

        // A digest is sixteen bounded u16 limbs, so this sum cannot wrap mod p.
        let sum: AirExpr<AB> = (0..DIGEST_LIMBS)
            .map(|i| AirExpr::<AB>::from(local[output_limb(i)]))
            .sum();
        builder
            .when(round_end * leaf_stage)
            .assert_one(sum * local[self.inverse_col()]);
    }
}

fn padded(message: &[u8]) -> [u64; KECCAK_LANES] {
    let mut bytes = [0u8; STATE_BYTES];
    bytes[..message.len()].copy_from_slice(message);
    bytes[message.len()] = SHA3_SUFFIX;
    bytes[SHA3_RATE_BYTES - 1] |= 0x80;
    let (lanes, _) = bytes.as_chunks::<8>();
    from_fn(|index| u64::from_le_bytes(lanes[index]))
}

fn preimage_limb<T: Copy>(columns: &KeccakCols<T>, index: usize) -> T {
    columns.preimage.as_flattened().as_flattened()[index]
}
