//! Reverse multiplication-friendly embedding from leanEthereum/leanVM,
//! crates/verifier/src/keccak.rs at 161cb67e1b54f7031b2603b8628f467f2ec92fca.
//! Copyright (c) 2026 leanEthereum. See LICENSE-leanVM.
pub(super) const EMBED: [u32; 16] = [
    0x40c50b, 0x7f79f2, 0x4b4e0a, 0x72740c, 0x5357da, 0x1d1c9e, 0x04be6e, 0x785246, 0x097cdc,
    0x109e7e, 0x1f1454, 0x213cfc, 0x4cfcc8, 0x775770, 0x187386, 0x818a16,
];
pub(super) const PROJECT: [u64; 16] = [
    0x1,
    0x7fffffffffff,
    0x274e9d3a74e9,
    0x1d3a74e9d3a7,
    0x65cb972e5cb9,
    0x5cb972e5cb97,
    0x6690aec7cd21,
    0x5d8f9a42bb1f,
    0x73485763e690,
    0x3750967c6ea1,
    0x12cf8dd4259f,
    0x1ba84b3e3750,
    0x0ad0c9f715a1,
    0x064fb8ad0c9f,
    0x456864fb8ad0,
    0x400000000000,
];
