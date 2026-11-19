use super::KeccakWires;
use crate::{F, air::convert};
use old_air::BaseAir;
use old_binary_field::{Poly64 as OldF, TowerLevel};
use p3_binary_field::TowerLevel as NewTowerLevel;
use p3_circuit::{CircuitBuilder, WitnessId, ops::keccak_limbs_to_state};
use p3_circuit_prover::{
    direct::DirectCircuitLimits,
    native_bus::{KeccakCommitment, NativeBusCircuit},
};
use p3_field::PrimeCharacteristicRing;
use p3_keccak::KeccakF;
use p3_symmetric::Permutation;

#[test]
fn direct_bridge_matches_both_native_output_formats() {
    let limbs = core::array::from_fn(|i| 0xbeef_u16.wrapping_mul(i as u16 + 1));
    let first = KeccakF.permute(keccak_limbs_to_state(&limbs))[0] & 0xffff;
    for short in [false, true] {
        let mut builder = CircuitBuilder::<OldF>::new();
        builder.enable_native_keccak_f1600().unwrap();
        let input = builder.alloc_private_input_array::<100>("input");
        let output = if short {
            builder
                .add_native_keccak_f1600_digest_with_swapped(&input)
                .unwrap()
                .0[0]
        } else {
            builder
                .add_native_keccak_f1600_with_swapped_digest(&input)
                .unwrap()
                .0[0]
        };
        let public = builder.public_input();
        builder.connect(output, public);
        let circuit = builder.build().unwrap();
        let bus = NativeBusCircuit::with_options(
            &circuit,
            "test",
            4,
            DirectCircuitLimits {
                max_witnesses: 1 << 16,
                max_operations: 1 << 16,
                max_trace_cells: 1 << 20,
            },
            KeccakCommitment::Bits,
        )
        .unwrap();
        let mut runner = circuit.runner();
        runner.set_public_inputs(&[OldF::from_repr(first)]).unwrap();
        runner
            .set_private_inputs(&limbs.map(|x| OldF::from_repr(u64::from(x))))
            .unwrap();
        let witness = runner.run_witness().unwrap();
        let bridge = bus.packed_table_index().unwrap() + 1;
        let native = bus.column_major_tables(&witness).unwrap();
        let table = &native[bridge];
        let height = 1 << table.num_variables();
        let pp = bus.airs()[bridge].preprocessed_trace().unwrap();
        let calls =
            KeccakWires::from_bridge(&pp.values, pp.width, 1, circuit.witness_count).unwrap();
        let read = |id: u32| convert(*witness.get_value(WitnessId(id - 1)).unwrap());
        let call = &calls[0];
        let mut direct = F::zero_vec(116 * height);
        let input = keccak_limbs_to_state(&limbs);
        assert_eq!(
            call.fill(&read, &mut direct, height, 0).unwrap(),
            (input, KeccakF.permute(input))
        );
        for (i, values) in direct.chunks_exact(height).enumerate() {
            for (r, &value) in values.iter().enumerate() {
                assert_eq!(value, convert(table.column(i).value(r)));
            }
        }
        let excessive = |id| {
            if id == call.input[0] {
                F::from_repr(1 << 16)
            } else {
                read(id)
            }
        };
        assert!(call.fill(&excessive, &mut direct, height, 0).is_err());
        let altered = |id| {
            if id == call.output[0] {
                read(id) + F::ONE
            } else {
                read(id)
            }
        };
        assert!(call.fill(&altered, &mut direct, height, 0).is_err());
    }
}
