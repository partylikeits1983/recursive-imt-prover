//! Deterministic PUBLIC test vectors; never proving randomness.
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use recursive_imt_poc::primitives::*;
fn main() {
    let vectors:Vec<_>=[0,1,8,16,17,24,32].into_iter().flat_map(|n|[NOTE,NULLIFIER,NODE].map(move|tag|{
        let input:Vec<_>=(0..n).map(F::from_usize).collect();serde_json::json!({"domain":tag,"input":input.iter().map(|x|x.as_canonical_u32()).collect::<Vec<_>>(),"output":hash(tag,&input)})
    })).collect();
    let mut defaults = vec![EMPTY];
    for i in 0..32 {
        defaults.push(node(defaults[i], defaults[i]));
    }
    println!("{}",serde_json::to_string_pretty(&serde_json::json!({"profile":HASH_PROFILE,"ctx":CTX,"empty":EMPTY,"vectors":vectors,"default_subtrees":defaults,
        "external_initial":p3_koala_bear::KOALABEAR_POSEIDON2_RC_24_EXTERNAL_INITIAL.map(|row|row.map(|x|x.as_canonical_u32())),
        "external_final":p3_koala_bear::KOALABEAR_POSEIDON2_RC_24_EXTERNAL_FINAL.map(|row|row.map(|x|x.as_canonical_u32())),
        "internal":p3_koala_bear::KOALABEAR_POSEIDON2_RC_24_INTERNAL.map(|x|x.as_canonical_u32())})).unwrap());
}
