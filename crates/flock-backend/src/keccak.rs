//! Keccak-f1600 from Plonky3's Flock gadget, with 16-bit ports for native recursion.
//! Adapted from 708900d7a730d6ce4d5421d43e2193f2301920fa (MIT OR Apache-2.0).
use p3_flock::{Builder, Circuit, Word};

pub(crate) const RC: [u64; 24] = [
    0x0000_0000_0000_0001,
    0x0000_0000_0000_8082,
    0x8000_0000_0000_808A,
    0x8000_0000_8000_8000,
    0x0000_0000_0000_808B,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8009,
    0x0000_0000_0000_008A,
    0x0000_0000_0000_0088,
    0x0000_0000_8000_8009,
    0x0000_0000_8000_000A,
    0x0000_0000_8000_808B,
    0x8000_0000_0000_008B,
    0x8000_0000_0000_8089,
    0x8000_0000_0000_8003,
    0x8000_0000_0000_8002,
    0x8000_0000_0000_0080,
    0x0000_0000_0000_800A,
    0x8000_0000_8000_000A,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8080,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8008,
];

/// The rho rotation of lane `x + 5 y` (FIPS 202, Section 3.2.2).
pub(crate) const RHO: [usize; 25] = [
    0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14,
];

pub fn circuit() -> Circuit {
    let mut c = Builder::new(&[16; 100], &[16; 132]);
    let input: Vec<_> = (0..100).flat_map(|i| c.input(i).to_vec()).collect();
    let mut a: [Word; 25] = core::array::from_fn(|i| Word::from(&input[64 * i..64 * (i + 1)]));
    for &rc in &RC {
        // Theta: each lane takes two neighbouring column parities.
        let col: [Word; 5] = core::array::from_fn(|x| {
            (1..5).fold(a[x].clone(), |p, y| c.xor_word(&p, &a[x + 5 * y]))
        });
        for x in 0..5 {
            let d = c.xor_word(&col[(x + 4) % 5], &col[(x + 1) % 5].rotate_left(1));
            for y in 0..5 {
                a[x + 5 * y] = c.xor_word(&a[x + 5 * y], &d);
            }
        }

        // Rho and pi: lane `(x, y)` rotates into `(y, 2x + 3y)`.
        let mut b: [Word; 25] = core::array::from_fn(|_| Word::default());
        for x in 0..5 {
            for y in 0..5 {
                b[y + 5 * ((2 * x + 3 * y) % 5)] = a[x + 5 * y].rotate_left(RHO[x + 5 * y]);
            }
        }

        // Chi: one product per bit.
        for y in 0..5 {
            for x in 0..5 {
                let row = |dx: usize| &b[(x + dx) % 5 + 5 * y];
                let t = c.andn_word(row(1), row(2));
                a[x + 5 * y] = c.xor_word(row(0), &t);
            }
        }

        // Iota: a constant, free.
        let k = c.literal(rc, 64);
        a[0] = c.xor_word(&a[0], &k);
    }

    for (lane, word) in a.iter().enumerate() {
        for (bit, &wire) in word.iter().enumerate() {
            c.output(lane * 4 + bit / 16, bit % 16, wire);
        }
    }
    for limb in 0..16 {
        for bit in 0..16 {
            c.output(100 + limb, bit, input[limb * 16 + (bit ^ 8)]);
            c.output(116 + limb, bit, a[limb / 4][(limb % 4) * 16 + (bit ^ 8)]);
        }
    }
    c.finish()
}
