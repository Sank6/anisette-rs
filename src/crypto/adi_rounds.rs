//! Nine-round core of the encoded proof block computation.
//!
//! Inputs can be a raw sixteen-byte block or the encoded first-round cuts.
//! Outputs are four encoded words after the ninth main round. The final stage is
//! implemented by the complete proof outside this module.
//! This core uses only field equations and static routing/XOR constants.

use super::adi_field::proof_column;

struct Round {
    sources: [[usize; 4]; 4],
    input_xor: [[u8; 4]; 4],
    output_xor: [u32; 4],
}

const BYTE_SHIFTS: [u32; 4] = [0, 16, 24, 8];
const FIRST_OUTPUT_XOR: [u32; 4] = [0, 880384333, 3620939741, 877964016];

const ROUNDS: [Round; 8] = [
    Round {
        sources: [[3, 0, 2, 1], [1, 2, 3, 0], [0, 3, 1, 2], [2, 1, 0, 3]],
        input_xor: [
            [145, 232, 89, 139],
            [70, 88, 18, 15],
            [19, 66, 91, 57],
            [4, 111, 255, 183],
        ],
        output_xor: [159768704, 1883390027, 1911062892, 214481083],
    },
    Round {
        sources: [[2, 0, 1, 3], [3, 1, 2, 0], [0, 2, 3, 1], [1, 3, 0, 2]],
        input_xor: [
            [211, 17, 243, 206],
            [118, 228, 91, 154],
            [159, 31, 255, 57],
            [184, 193, 27, 229],
        ],
        output_xor: [1755328946, 755668328, 1579866468, 329645338],
    },
    Round {
        sources: [[2, 0, 1, 3], [3, 1, 2, 0], [0, 2, 3, 1], [1, 3, 0, 2]],
        input_xor: [
            [195, 121, 231, 154],
            [29, 172, 228, 234],
            [224, 35, 145, 227],
            [241, 207, 158, 160],
        ],
        output_xor: [1807627641, 576823101, 1373002543, 1416669417],
    },
    Round {
        sources: [[2, 0, 1, 3], [0, 2, 3, 1], [3, 1, 2, 0], [1, 3, 0, 2]],
        input_xor: [
            [90, 54, 49, 252],
            [103, 66, 95, 251],
            [18, 57, 10, 243],
            [214, 164, 52, 46],
        ],
        output_xor: [716311027, 1770202604, 729004314, 1289532606],
    },
    Round {
        sources: [[1, 0, 2, 3], [3, 2, 1, 0], [2, 3, 0, 1], [0, 1, 3, 2]],
        input_xor: [
            [177, 149, 0, 77],
            [142, 72, 222, 192],
            [81, 119, 5, 74],
            [211, 107, 123, 195],
        ],
        output_xor: [2864481928, 3628723077, 712446570, 162713684],
    },
    Round {
        sources: [[3, 0, 1, 2], [2, 1, 3, 0], [0, 3, 2, 1], [1, 2, 0, 3]],
        input_xor: [
            [236, 87, 73, 73],
            [175, 41, 234, 94],
            [54, 6, 81, 98],
            [241, 12, 205, 45],
        ],
        output_xor: [1209282100, 2049663260, 1066191852, 1815615833],
    },
    Round {
        sources: [[2, 0, 1, 3], [3, 1, 2, 0], [0, 2, 3, 1], [1, 3, 0, 2]],
        input_xor: [
            [68, 10, 107, 241],
            [247, 8, 196, 171],
            [202, 180, 19, 126],
            [5, 95, 184, 6],
        ],
        output_xor: [1342219268, 1265257741, 2118195094, 242955026],
    },
    Round {
        sources: [[2, 0, 1, 3], [3, 1, 2, 0], [1, 3, 0, 2], [0, 2, 3, 1]],
        input_xor: [
            [69, 202, 194, 32],
            [56, 134, 153, 85],
            [105, 149, 210, 89],
            [54, 233, 81, 244],
        ],
        output_xor: [120280458, 1102341735, 1536746498, 2389769524],
    },
];

pub fn proof_main_rounds(encoded_columns: [[u8; 4]; 4]) -> [u32; 4] {
    let mut words = std::array::from_fn(|column| {
        proof_column(encoded_columns[column]) ^ FIRST_OUTPUT_XOR[column]
    });
    for round in &ROUNDS {
        words = std::array::from_fn(|column| {
            let bytes = std::array::from_fn(|lane| {
                (words[round.sources[column][lane]] >> BYTE_SHIFTS[lane]) as u8
                    ^ round.input_xor[column][lane]
            });
            proof_column(bytes) ^ round.output_xor[column]
        });
    }
    words
}

const INITIAL_INPUT_COLUMNS: [[u8; 8]; 4] = [
    [129, 2, 142, 139, 186, 20, 209, 96],
    [205, 250, 244, 15, 254, 44, 176, 169],
    [251, 1, 111, 88, 106, 219, 172, 8],
    [123, 197, 204, 246, 195, 161, 182, 66],
];
const INITIAL_INPUT_SOURCES: [[usize; 4]; 4] =
    [[15, 5, 8, 2], [11, 1, 4, 14], [3, 9, 12, 6], [7, 13, 0, 10]];
const INITIAL_INPUT_XOR: [[u8; 4]; 4] = [
    [235, 15, 19, 110],
    [211, 37, 127, 253],
    [205, 40, 233, 131],
    [255, 126, 233, 43],
];

pub fn proof_block_core(block: &[u8; 16]) -> [u32; 4] {
    proof_main_rounds(encode_block(block))
}

fn encode_block(block: &[u8; 16]) -> [[u8; 4]; 4] {
    std::array::from_fn(|column| {
        std::array::from_fn(|lane| {
            let byte = block[INITIAL_INPUT_SOURCES[column][lane]];
            INITIAL_INPUT_COLUMNS[lane].iter().enumerate().fold(
                INITIAL_INPUT_XOR[column][lane],
                |value, (bit, coefficient)| {
                    value ^ (coefficient & 0_u8.wrapping_sub((byte >> bit) & 1))
                },
            )
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nine_round_core_matches_independent_synthetic_oracle_vectors() {
        // The reference graph uses all-zero, all-one, and incrementing synthetic
        // payloads. The fixture contains only non-secret intermediate cuts.
        for (input, expected) in [
            (
                [
                    [235, 15, 19, 110],
                    [211, 37, 127, 253],
                    [205, 40, 233, 131],
                    [255, 126, 233, 43],
                ],
                [2876500011, 1253287477, 2259169135, 2411233002],
            ),
            (
                [
                    [114, 8, 203, 124],
                    [74, 34, 167, 239],
                    [84, 47, 49, 145],
                    [102, 121, 49, 57],
                ],
                [2777193376, 4237754731, 1422246483, 1323431739],
            ),
            (
                [
                    [220, 47, 239, 95],
                    [106, 241, 180, 246],
                    [255, 243, 122, 126],
                    [67, 81, 77, 236],
                ],
                [3962766746, 3084876114, 2761149586, 2764348458],
            ),
        ] {
            assert_eq!(proof_main_rounds(input), expected);
        }
    }

    /// Reads the expression graph only in this opt-in developer check.
    /// Synthetic payloads exercise its initial encodings and all nine rounds.
    #[test]
    #[ignore = "set ANISETTE_RS_PROOF_ORACLE to the local proof JSON"]
    fn nine_round_core_matches_original_oracle_on_synthetic_payloads() {
        use crate::crypto::circuit::Circuit;
        use serde_json::{Value, json};
        use sha2::{Digest, Sha256};

        let path = std::env::var_os("ANISETTE_RS_PROOF_ORACLE").expect("local proof oracle path");
        let bytes = std::fs::read(path).unwrap();
        assert_eq!(
            format!("{:x}", Sha256::digest(&bytes)),
            "ef5796b978431a75b4f1b012083b1e2025829b87b3ec81d81811416f8117ddc1"
        );
        let profile: Value = serde_json::from_slice(&bytes).unwrap();
        // The conversion is local to this test and does not affect production parsing.
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
        let mut nodes: Vec<Value> = profile["nodes"].as_array().unwrap()[..11173]
            .iter()
            .map(|node| {
                let code = codes
                    .iter()
                    .find(|(name, _)| node["op"] == *name)
                    .unwrap()
                    .1;
                json!([node["bits"], code, node["args"], node["value"]])
            })
            .collect();
        let cuts = [
            [653, 763, 820, 1382],
            [2156, 1580, 2110, 2297],
            [2364, 2710, 2538, 2510],
            [3070, 2900, 2933, 3036],
        ];
        let mut outputs = Vec::new();
        for cut in cuts.into_iter().flatten() {
            outputs.push(nodes.len());
            nodes.push(json!([8, 13, [cut], 0]));
        }
        for word in [9865, 10533, 10848, 11172] {
            for shift in [0, 8, 16, 24] {
                outputs.push(nodes.len());
                nodes.push(json!([8, 13, [word], shift]));
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
        let mut random = 0x93a4_7129_u32;
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
            let observed = circuit.evaluate(&input).unwrap();
            let encoded = std::array::from_fn(|column| {
                std::array::from_fn(|lane| observed[column * 4 + lane])
            });
            let expected: [u32; 4] = std::array::from_fn(|column| {
                let start = 16 + column * 4;
                u32::from_le_bytes(observed[start..start + 4].try_into().unwrap())
            });
            assert_eq!(
                proof_main_rounds(encoded),
                expected,
                "synthetic case {case}"
            );
        }
    }
}
