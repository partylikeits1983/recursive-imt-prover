//! Public linear form for the eight three-round segments of the pinned native root.
use ark_ff::{AdditiveGroup, BigInteger, Field, PrimeField};
use sha3::{Digest, Keccak256};
use whir::algebra::{
    embedding::Identity,
    fields::Field256 as F,
    linear_form::{Evaluate, LinearForm},
};

const LAST_ROW: usize = 21670;
const ROWS: usize = 1 << 16;
const WIDTH: usize = 64;
const RC: [u64; 24] = [
    0x1,
    0x8082,
    0x800000000000808a,
    0x8000000080008000,
    0x808b,
    0x80000001,
    0x8000000080008081,
    0x8000000000008009,
    0x8a,
    0x88,
    0x80008009,
    0x8000000a,
    0x8000808b,
    0x800000000000008b,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x800a,
    0x800000008000000a,
    0x8000000080008081,
    0x8000000000008080,
    0x80000001,
    0x8000000080008008,
];
const ROT: [u32; 25] = [
    0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14,
];

fn round(a: &mut [u64; 25], rc: u64) {
    let c: [u64; 5] = std::array::from_fn(|x| a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20]);
    let mut b = [0; 25];
    for y in 0..5 {
        for x in 0..5 {
            let i = x + 5 * y;
            let d = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
            b[y + 5 * ((2 * x + 3 * y) % 5)] = (a[i] ^ d).rotate_left(ROT[i]);
        }
    }
    for y in 0..5 {
        for x in 0..5 {
            a[x + 5 * y] = b[x + 5 * y] ^ ((!b[(x + 1) % 5 + 5 * y]) & b[(x + 2) % 5 + 5 * y]);
        }
    }
    a[0] ^= rc;
}

fn state_bytes(state: &[u64; 25]) -> [u8; 200] {
    let mut bytes = [0; 200];
    for (dest, lane) in bytes.chunks_exact_mut(8).zip(state) {
        dest.copy_from_slice(&lane.to_le_bytes());
    }
    bytes
}

pub fn visit_states(
    input: &[u8],
    reference: Option<&[u8]>,
    mut visit: impl FnMut(usize, &[u8; 200]),
) {
    let mut state =
        std::array::from_fn(|i| u64::from_le_bytes(input[8 * i..8 * i + 8].try_into().unwrap()));
    for segment in 0..=8 {
        let bytes = state_bytes(&state);
        if let Some(checkpoints) = reference {
            if segment == 4 || segment == 8 {
                let offset = if segment == 4 { 200 } else { 400 };
                assert_eq!(
                    &bytes[..],
                    &checkpoints[offset..offset + 200],
                    "native checkpoint mismatch"
                );
            }
        }
        visit(segment, &bytes);
        if segment < 8 {
            for &rc in &RC[3 * segment..3 * segment + 3] {
                round(&mut state, rc);
            }
        }
    }
}

fn encode_row(input: &[u8], reference: Option<&[u8]>) -> [F; WIDTH] {
    let mut words = [F::ZERO; WIDTH];
    visit_states(input, reference, |segment, bytes| {
        for (chunk, data) in bytes.chunks(30).enumerate() {
            let slot = if segment == 8 {
                8 * chunk + 7
            } else {
                8 * segment + chunk
            };
            words[slot] = F::from_le_bytes_mod_order(data);
        }
    });
    words
}

pub fn table(checkpoints: &[u8]) -> Vec<F> {
    assert_eq!(checkpoints.len(), ROWS * 600);
    let mut table = Vec::with_capacity(ROWS * WIDTH);
    for row in checkpoints.chunks_exact(600) {
        table.extend(encode_row(&row[..200], Some(row)));
    }
    table
}

fn eq_table(point: &[F]) -> Vec<F> {
    let mut eq = vec![F::ONE];
    for &r in point {
        let mut next = Vec::with_capacity(2 * eq.len());
        for value in eq {
            let high = value * r;
            next.extend([value - high, high]);
        }
        eq = next;
    }
    eq
}

fn dot(a: &[F], b: &[F]) -> F {
    assert_eq!(a.len(), b.len());
    a.iter().zip(b).map(|(x, y)| *x * y).sum()
}

fn challenge(seed: &[u8], family: u8, index: u8) -> F {
    let prefix = Keccak256::new()
        .chain_update(b"recursive-imt/segment-challenge/v1")
        .chain_update(seed)
        .chain_update([family, index]);
    let wide = [
        prefix.clone().chain_update([0]).finalize(),
        prefix.chain_update([1]).finalize(),
    ]
    .concat();
    F::from_be_bytes_mod_order(&wide)
}

#[derive(Clone)]
struct Factors {
    rows: Vec<F>,
    columns: Vec<F>,
}

impl Factors {
    fn value(&self, table: &[F]) -> F {
        self.rows
            .iter()
            .zip(table.chunks_exact(WIDTH))
            .map(|(w, row)| *w * dot(&self.columns, row))
            .sum()
    }
}

#[derive(Clone)]
pub struct SegmentForm {
    known: Factors,
    inputs: Factors,
    outputs: Factors,
    mix: F,
}

impl SegmentForm {
    pub fn claim(
        table: &[F],
        parent_and_children: &[u8],
        root: &[u8; 32],
    ) -> (Self, F, Vec<u8>, Vec<u8>) {
        assert_eq!(parent_and_children.len(), 96);
        let key = hex::decode("494900e0fa468212ed93087501b2ca91a608331d9a12070b6cc05133943e7405")
            .unwrap();
        let context = Keccak256::new()
            .chain_update(b"recursive-imt/three-round-checkpoints/v1")
            .chain_update(key)
            .chain_update(parent_and_children)
            .chain_update([64])
            .finalize();
        let seed = Keccak256::new()
            .chain_update(context)
            .chain_update(root)
            .finalize();
        let coords = |family| {
            (0..22)
                .map(|i| challenge(&seed, family, i))
                .collect::<Vec<_>>()
        };
        let known_point = coords(0);
        let input_point = coords(1);
        let output_point = coords(2);
        let mut known = Factors {
            rows: eq_table(&known_point[..16]),
            columns: eq_table(&known_point[16..]),
        };
        let mut terminal_mass = F::ZERO;
        let mut padding_mass = F::ZERO;
        for (i, weight) in known.rows.iter_mut().enumerate() {
            match (i % (ROWS / 2)).cmp(&LAST_ROW) {
                std::cmp::Ordering::Less => *weight = F::ZERO,
                std::cmp::Ordering::Equal => terminal_mass += *weight,
                std::cmp::Ordering::Greater => padding_mass += *weight,
            }
        }
        let mut padded = [0; 200];
        let msg = [
            b"IMT-AGG-NODE-V2".as_slice(),
            &parent_and_children[32..64],
            &[32],
            &parent_and_children[64..],
            &[32],
        ]
        .concat();
        assert_eq!(
            Keccak256::digest(&msg).as_slice(),
            &parent_and_children[..32]
        );
        padded[..msg.len()].copy_from_slice(&msg);
        padded[msg.len()] = 1;
        padded[135] = 128;
        let expected = terminal_mass * dot(&known.columns, &encode_row(&padded, None))
            + padding_mass * dot(&known.columns, &encode_row(&[0; 200], None));

        let mut inputs = Factors {
            rows: eq_table(&input_point[..16]),
            columns: eq_table(&input_point[16..]),
        };
        for column in inputs.columns.iter_mut().skip(7).step_by(8) {
            *column = F::ZERO;
        }
        let output_weights = eq_table(&output_point[16..]);
        let mut outputs = Factors {
            rows: eq_table(&output_point[..16]),
            columns: vec![F::ZERO; 64],
        };
        for segment in 0..8 {
            for chunk in 0..7 {
                let actual_slot = if segment == 7 {
                    8 * chunk + 7
                } else {
                    8 * (segment + 1) + chunk
                };
                outputs.columns[actual_slot] += output_weights[8 * segment + chunk];
            }
        }
        let input_value = inputs.value(table);
        let output_value = outputs.value(table);
        let mut readings = input_value.into_bigint().to_bytes_be();
        readings.extend(output_value.into_bigint().to_bytes_be());
        let mix_seed = Keccak256::new()
            .chain_update(seed)
            .chain_update(&readings)
            .finalize();
        let mix = challenge(&mix_seed, 3, 0);
        let claimed = expected + mix * (input_value + mix * output_value);
        (
            Self {
                known,
                inputs,
                outputs,
                mix,
            },
            claimed,
            context.to_vec(),
            readings,
        )
    }
}

impl LinearForm<F> for SegmentForm {
    fn size(&self) -> usize {
        ROWS * WIDTH
    }
    fn mle_evaluate(&self, point: &[F]) -> F {
        let rows = eq_table(&point[..16]);
        let cols = eq_table(&point[16..]);
        let weight = |f: &Factors| dot(&f.rows, &rows) * dot(&f.columns, &cols);
        weight(&self.known) + self.mix * (weight(&self.inputs) + self.mix * weight(&self.outputs))
    }
    fn accumulate(&self, acc: &mut [F], scalar: F) {
        assert_eq!(acc.len(), self.size());
        for (i, row) in acc.chunks_exact_mut(WIDTH).enumerate() {
            let k = scalar * self.known.rows[i];
            let a = scalar * self.mix * self.inputs.rows[i];
            let b = scalar * self.mix.square() * self.outputs.rows[i];
            for (c, value) in row.iter_mut().enumerate() {
                *value += k * self.known.columns[c]
                    + a * self.inputs.columns[c]
                    + b * self.outputs.columns[c];
            }
        }
    }
}
impl Evaluate<Identity<F>> for SegmentForm {
    fn evaluate(&self, _: &Identity<F>, vector: &[F]) -> F {
        self.known.value(vector)
            + self.mix * (self.inputs.value(vector) + self.mix * self.outputs.value(vector))
    }
}

/// Reduce the authenticated packed output at its existing query to 25 lane-bit
/// claims at one point. Histograms keep the 524,288 segment outputs packed.
pub fn output_bits(table: &[F], public: &[u8]) -> (Vec<u8>, Vec<u8>) {
    assert_eq!(public.len(), 160);
    let seed = Keccak256::digest(&public[..64]);
    let point: Vec<_> = (0..22).map(|i| challenge(&seed, 2, i)).collect();
    let row_weights = eq_table(&point[..16]);
    let segment_weights = eq_table(&point[16..19]);
    let chunk_weights = eq_table(&point[19..]);
    let mut bins = vec![[F::ZERO; 256]; 200];
    for (row, &row_weight) in table.chunks_exact(WIDTH).zip(&row_weights) {
        for (s, &segment_weight) in segment_weights.iter().enumerate() {
            let weight = row_weight * segment_weight;
            for c in 0..7 {
                let slot = if s == 7 { 8 * c + 7 } else { 8 * (s + 1) + c };
                let bytes = row[slot].into_bigint().0;
                for k in 0..(200 - 30 * c).min(30) {
                    let v = ((bytes[k / 8] >> (8 * (k % 8))) & 255) as usize;
                    bins[30 * c + k][v] += weight;
                }
            }
        }
    }

    let mut bits = vec![[F::ZERO; 64]; 25];
    let mut weights = vec![[F::ZERO; 64]; 25];
    let mut powers = [F::ONE; 240];
    for i in 1..240 {
        powers[i] = powers[i - 1].double();
    }
    for bit in 0..1600 {
        let mask = 1 << (bit % 8);
        bits[bit / 64][bit % 64] = bins[bit / 8]
            .iter()
            .enumerate()
            .filter(|(v, _)| v & mask != 0)
            .map(|(_, w)| *w)
            .sum();
        weights[bit / 64][bit % 64] = chunk_weights[bit / 240] * powers[bit % 240];
    }
    let mut sum: F = (0..25).map(|lane| dot(&bits[lane], &weights[lane])).sum();
    assert_eq!(sum, F::from_be_bytes_mod_order(&public[96..128]));
    let mut cv = Keccak256::new()
        .chain_update(b"recursive-imt/packed-output-bits/v1")
        .chain_update(public)
        .finalize();
    let mut proof = Vec::new();
    let mut result: Vec<_> = point[..19]
        .iter()
        .flat_map(|x| x.into_bigint().to_bytes_be())
        .collect();
    for k in 0..6 {
        let half = 32 >> k;
        let mut c0 = F::ZERO;
        let mut c2 = F::ZERO;
        for (b, w) in bits.iter().zip(&weights) {
            for i in 0..half {
                c0 += b[i] * w[i];
                c2 += (b[i + half] - b[i]) * (w[i + half] - w[i]);
            }
        }
        let first = c0.into_bigint().to_bytes_be();
        let quadratic = c2.into_bigint().to_bytes_be();
        cv = Keccak256::new()
            .chain_update(cv)
            .chain_update([k])
            .chain_update(&first)
            .chain_update(&quadratic)
            .finalize();
        let r = challenge(&cv, 4, k);
        sum = c0 + r * (sum - c0.double() - c2 + r * c2);
        result.extend(r.into_bigint().to_bytes_be());
        proof.extend(first);
        proof.extend(quadratic);
        for poly in bits.iter_mut().chain(&mut weights) {
            for i in 0..half {
                let delta = poly[i + half] - poly[i];
                poly[i] += r * delta;
            }
        }
    }
    assert_eq!(
        sum,
        (0..25).map(|lane| bits[lane][0] * weights[lane][0]).sum()
    );
    for b in bits {
        let value = b[0].into_bigint().to_bytes_be();
        result.extend(&value);
        proof.extend(value);
    }
    (proof, result)
}
