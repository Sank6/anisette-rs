//! Fixed AES-128 block transform used by the proof computation.
//!
//! All initial/final encodings, inverse mixing, routing, and the key schedule
//! have complete-domain checks against the arithmetic reference. The
//! post-decryption XOR is independent of a provisioned identity or session.

use super::aes::Aes128;

const PROOF_KEY: [u8; 16] = [
    124, 48, 183, 147, 64, 131, 95, 185, 203, 40, 40, 26, 229, 242, 61, 196,
];
pub(crate) const OUTPUT_ENCODING: [u8; 16] = [
    119, 185, 112, 19, 2, 134, 222, 101, 233, 135, 227, 171, 47, 10, 93, 20,
];

pub fn proof_block(block: &[u8; 16]) -> [u8; 16] {
    let decoded = Aes128::new(&PROOF_KEY).decrypt(block);
    std::array::from_fn(|i| decoded[i] ^ OUTPUT_ENCODING[i])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn complete_block_matches_original_graph_vectors() {
        for (block, expected) in [
            (
                [0; 16],
                [
                    199, 58, 34, 30, 109, 173, 113, 141, 129, 142, 30, 146, 151, 69, 219, 218,
                ],
            ),
            (
                [255; 16],
                [
                    116, 73, 47, 27, 98, 248, 219, 57, 218, 200, 171, 79, 24, 247, 36, 237,
                ],
            ),
            (
                std::array::from_fn(|i| 192 + i as u8),
                [
                    210, 205, 41, 113, 169, 177, 32, 63, 57, 235, 62, 222, 22, 186, 60, 78,
                ],
            ),
        ] {
            assert_eq!(proof_block(&block), expected);
        }
    }

    #[test]
    #[ignore = "set ANISETTE_RS_PROOF_ORACLE to the local proof JSON"]
    fn complete_block_and_chaining_match_original_oracle() {
        use crate::crypto::circuit::Circuit;
        use serde_json::{Value, json};
        use sha2::{Digest, Sha256};

        let bytes = std::fs::read(std::env::var_os("ANISETTE_RS_PROOF_ORACLE").unwrap()).unwrap();
        assert_eq!(
            format!("{:x}", Sha256::digest(&bytes)),
            "ef5796b978431a75b4f1b012083b1e2025829b87b3ec81d81811416f8117ddc1"
        );
        let profile: Value = serde_json::from_slice(&bytes).unwrap();
        let original = profile["nodes"].as_array().unwrap();
        let words = [11793_usize, 97762, 176059, 200971];
        let mut pending = words.to_vec();
        let mut seen = vec![false; original.len()];
        while let Some(index) = pending.pop() {
            if std::mem::replace(&mut seen[index], true) {
                continue;
            }
            pending.extend(
                original[index]["args"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|child| child.as_u64().unwrap() as usize),
            );
        }
        let codes = [
            ("constant", 0),
            ("input", 1),
            ("lookup", 2),
            ("add", 3),
            ("mul", 5),
            ("xor", 6),
            ("or", 8),
            ("not", 10),
            ("extract", 13),
            ("concat", 14),
            ("array_new", 26),
        ];
        let mut mapping = vec![usize::MAX; original.len()];
        let mut nodes = Vec::new();
        for (old, node) in original
            .iter()
            .enumerate()
            .filter(|(index, _)| seen[*index])
        {
            mapping[old] = nodes.len();
            let args: Vec<_> = node["args"]
                .as_array()
                .unwrap()
                .iter()
                .map(|child| mapping[child.as_u64().unwrap() as usize])
                .collect();
            let code = codes
                .iter()
                .find(|(name, _)| node["op"] == *name)
                .unwrap()
                .1;
            nodes.push(json!([node["bits"], code, args, node["value"]]));
        }
        let mut outputs = Vec::new();
        for word in words {
            for shift in [0, 8, 16, 24] {
                outputs.push(nodes.len());
                nodes.push(json!([8, 13, [mapping[word]], shift]));
            }
        }
        let circuit = Circuit::from_json(
            &serde_json::to_vec(&json!({
                "input_bytes": 336, "nodes": nodes, "outputs": outputs,
                "tables": profile["tables"], "guards": [],
            }))
            .unwrap(),
        )
        .unwrap();
        let encodings: [[u8; 8]; 4] = [
            [129, 2, 142, 139, 186, 20, 209, 96],
            [123, 197, 204, 246, 195, 161, 182, 66],
            [205, 250, 244, 15, 254, 44, 176, 169],
            [251, 1, 111, 88, 106, 219, 172, 8],
        ];
        let mut random = 0x78ad_921b_u32;
        for case in 0..67 {
            let input: [u8; 336] = std::array::from_fn(|i| match case {
                0 => 0,
                1 => 255,
                2 => i as u8,
                _ => {
                    random ^= random << 13;
                    random ^= random >> 17;
                    random ^= random << 5;
                    random as u8
                }
            });
            let decoded = proof_block(input[192..208].try_into().unwrap());
            let observed = circuit.evaluate(&input).unwrap();
            for (word, base) in [188, 176, 180, 184].into_iter().enumerate() {
                for (slot, columns) in encodings.iter().enumerate() {
                    let predecessor = base + 3 - slot;
                    let plain = decoded[predecessor - 176] ^ input[predecessor];
                    let expected = columns.iter().enumerate().fold(0, |value, (bit, column)| {
                        value ^ (column & 0_u8.wrapping_sub((plain >> bit) & 1))
                    });
                    assert_eq!(
                        observed[word * 4 + slot],
                        expected,
                        "synthetic case {case}, chained word {word}, byte {slot}"
                    );
                }
            }
        }
    }
}
