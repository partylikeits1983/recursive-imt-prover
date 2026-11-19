//! Assess the actual BLAKE3 IMT AIR with Poly64/Poly192, without claiming ZK.
use anyhow::Result;
use p3_binary_field::Poly64;
use p3_circuit::ops::ByteHash;
use p3_circuit_prover::direct::DirectCircuitLimits;
use p3_circuit_prover::native_bus::{KeccakCommitment, NativeBusCircuit};
use p3_recursion::artifact::{
    BinaryNativePolyMixedWhirAuthority, BinaryNativePolyMixedWhirPcsParameters,
    BinaryNativePolyWhirPcsParameters, BinaryNativeVerifierSpec,
};
use p3_recursion::pcs::binary::MerkleArity;
use p3_recursion::verifier::VerifierLimits;
use p3_whir::{FoldingFactor, ProtocolParameters, SecurityAssumption};
use recursive_imt_prover::binary::relation::membership_circuit_over;

fn protocol(bits: usize, rate: usize) -> ProtocolParameters {
    ProtocolParameters {
        security_level: bits,
        pow_bits: 16,
        starting_log_inv_rate: rate,
        folding_factor: FoldingFactor::Constant(4),
        round_log_inv_rates: vec![],
        soundness_type: SecurityAssumption::JohnsonBound,
    }
}

fn main() -> Result<()> {
    let mut reports = Vec::new();
    for depth in [8, 16, 32] {
        let circuit = membership_circuit_over::<Poly64>(depth)?;
        let bus = NativeBusCircuit::with_compact_options(
            &circuit,
            "imt",
            4,
            DirectCircuitLimits {
                max_witnesses: 1 << 23,
                max_operations: 1 << 23,
                max_trace_cells: 1 << 28,
            },
            KeccakCommitment::Bits,
        )?;
        let limits = VerifierLimits {
            max_rounds: 2048,
            max_metadata_entries: 1 << 24,
            ..Default::default()
        };
        for bits in [128, 144, 160] {
            let params = |n, rate| {
                BinaryNativePolyWhirPcsParameters::with_limits(
                    n,
                    protocol(bits, rate),
                    ByteHash::Blake3,
                    MerkleArity::Four,
                    2,
                    &limits,
                )
            };
            let bit_variables = bus.packed_bit_variables().expect("BLAKE3 table");
            let main = BinaryNativePolyMixedWhirPcsParameters::with_packed_table(
                params(bus.main_variables(), 1)?,
                params(bit_variables - 6, 3)?,
                bus.packed_table_index().expect("BLAKE3 table"),
                bit_variables,
            )?;
            let pp = bus
                .preprocessed_variables()
                .map(|n| params(n, 1).map(BinaryNativePolyMixedWhirPcsParameters::dense))
                .transpose()?;
            // Low setup gate is for diagnosis only. A separate strict 128-bit
            // check below is recorded; no accepted proof is produced by this tool.
            let spec = BinaryNativeVerifierSpec {
                main,
                preprocessed: pp,
                transcript_hash: ByteHash::Blake3,
                initial_bytes: b"imt-poly-security-v1".to_vec(),
                sumcheck_pow_bits: 0,
                max_tau_draws: 32,
                security_bits: 1,
            };
            let (_, authority) = BinaryNativePolyMixedWhirAuthority::setup(
                bus.airs().to_vec(),
                bus.log_heights().to_vec(),
                spec,
                &limits,
            )?;
            let report = authority.security_report();
            reports.push(serde_json::json!({"depth":depth, "pcs_target":bits,
                "carrier":"GF(2^64)", "challenge":"GF(2^192)", "zk":false,
                "model_bits":report.security_bits(), "strict_128_pass":report.require_security(128).is_ok(),
                "terms":report.terms().iter().map(|t| serde_json::json!({"name":t.label,
                    "component":format!("{:?}",t.component), "bits":t.bits.bits()})).collect::<Vec<_>>()}));
        }
    }
    println!("{}", serde_json::to_string_pretty(&reports)?);
    Ok(())
}
