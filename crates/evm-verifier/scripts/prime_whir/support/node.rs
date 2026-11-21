use sha3::{Digest, Keccak256};
use std::{fs, path::Path};

// Reconstruct the two child digests from the public ordered leaves, independently of the trace.
pub fn node_statement(bundle: &Path) -> (Vec<u8>, [u8; 32]) {
    let inputs: serde_json::Value =
        serde_json::from_slice(&fs::read(bundle.join("statement.json")).unwrap()).unwrap();
    let mut nodes: Vec<[u8; 32]> = inputs["children"]
        .as_array()
        .unwrap()
        .iter()
        .map(|record| {
            let mut hash = Keccak256::new();
            hash.update(b"IMT-AGG-LEAF-V3");
            for field in ["root", "input_tag", "output_commitment"] {
                let word: [u8; 32] = serde_json::from_value(record[field].clone()).unwrap();
                hash.update(word);
            }
            hash.finalize().into()
        })
        .collect();
    assert_eq!(nodes.len(), 64);
    let parent = |a: [u8; 32], b: [u8; 32], count: u8| -> [u8; 32] {
        Keccak256::new()
            .chain_update(b"IMT-AGG-NODE-V2")
            .chain_update(a)
            .chain_update([count])
            .chain_update(b)
            .chain_update([count])
            .finalize()
            .into()
    };
    let mut count = 1;
    while nodes.len() > 2 {
        nodes = nodes
            .chunks_exact(2)
            .map(|v| parent(v[0], v[1], count))
            .collect();
        count *= 2;
    }
    let expected = parent(nodes[0], nodes[1], 32);
    let report: serde_json::Value =
        serde_json::from_slice(&fs::read(bundle.join("report.json")).unwrap()).unwrap();
    assert_eq!(
        report["summary"]["statement"].as_str().unwrap(),
        format!("{}40", hex::encode(expected))
    );

    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(bundle.join("trusted.json")).unwrap()).unwrap();
    let key: [u8; 32] = serde_json::from_value(manifest["verifier_digest"].clone()).unwrap();
    assert_eq!(
        hex::encode(key),
        "494900e0fa468212ed93087501b2ca91a608331d9a12070b6cc05133943e7405"
    );
    ([expected, nodes[0], nodes[1]].concat(), key)
}
