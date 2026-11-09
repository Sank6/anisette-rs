//! Complete 336-byte to 16-byte anisette proof computation.
//!
//! The encrypted material carries an encoded AES round schedule and IV.
//! Six context blocks are encrypted in CBC mode; the result is XORed with
//! that IV. Context words use little-endian byte order. The separate 32-byte
//! mask input cancels algebraically and is not used by the native algorithm.
//!
//! Offline checks certify every table identity, substitution input, byte route,
//! and output equation over its complete domain.

use zeroize::Zeroizing;

use super::{
    adi_key::{UPDATE_ORDER, decode_key_material},
    aes::Aes128,
};

const DECODE_COLUMNS: [u8; 8] = [76, 165, 130, 104, 13, 126, 250, 26];
const SEED_POSITIONS: [usize; 16] = [
    147, 207, 8, 123, 31, 60, 131, 145, 128, 114, 134, 29, 78, 81, 139, 45,
];
const ROUND_XOR: [[u8; 16]; 9] = [
    [
        172, 101, 25, 103, 162, 109, 149, 103, 21, 141, 188, 111, 18, 134, 42, 13,
    ],
    [
        26, 172, 33, 121, 76, 95, 14, 174, 41, 91, 42, 71, 119, 202, 69, 162,
    ],
    [
        178, 113, 82, 198, 28, 13, 42, 77, 211, 154, 28, 235, 56, 108, 41, 55,
    ],
    [
        75, 209, 244, 202, 126, 84, 45, 46, 65, 94, 161, 111, 225, 213, 94, 60,
    ],
    [
        132, 197, 197, 244, 251, 142, 36, 161, 190, 187, 63, 124, 129, 56, 6, 95,
    ],
    [
        39, 46, 120, 60, 18, 92, 143, 251, 64, 217, 16, 249, 191, 88, 122, 39,
    ],
    [
        202, 197, 37, 208, 175, 75, 30, 142, 79, 32, 211, 198, 23, 107, 79, 233,
    ],
    [
        24, 226, 13, 96, 171, 134, 184, 112, 223, 120, 242, 182, 209, 139, 66, 175,
    ],
    [
        67, 230, 19, 231, 47, 68, 46, 10, 91, 255, 161, 74, 110, 77, 148, 27,
    ],
];
const INITIAL_XOR: [u8; 16] = [
    151, 228, 187, 86, 64, 111, 34, 251, 231, 185, 242, 14, 155, 132, 41, 124,
];
const CHAIN_XOR: [u8; 16] = [
    182, 212, 4, 128, 250, 205, 156, 29, 89, 113, 147, 147, 56, 33, 89, 182,
];

fn decode_byte(byte: u8) -> u8 {
    DECODE_COLUMNS
        .iter()
        .enumerate()
        .fold(0, |value, (bit, column)| {
            value ^ (column & 0_u8.wrapping_sub((byte >> bit) & 1))
        })
}

pub fn proof(input: &[u8; 336]) -> [u8; 16] {
    let ciphertext = Zeroizing::new(std::array::from_fn(|i| input[i]));
    let material = decode_key_material(&ciphertext);
    let mut keys = Zeroizing::new([0; 176]);
    let iv = Zeroizing::new(std::array::from_fn::<_, 16, _>(|i| {
        material[UPDATE_ORDER[144 + i]]
    }));
    for i in 0..16 {
        keys[i] = decode_byte(material[UPDATE_ORDER[160 + i]]) ^ INITIAL_XOR[i];
        keys[160 + i] = keys[i] ^ decode_byte(material[UPDATE_ORDER[128 + i]]) ^ CHAIN_XOR[i];
    }
    for (round, bias) in ROUND_XOR.iter().enumerate() {
        for i in 0..16 {
            let position = match round {
                0 => UPDATE_ORDER[176 + i],
                1 => SEED_POSITIONS[i],
                _ => UPDATE_ORDER[(round - 2) * 16 + i],
            };
            keys[(round + 1) * 16 + i] = decode_byte(material[position]) ^ bias[i];
        }
    }
    let aes = Aes128::from_round_keys(keys);
    let mut chain = Zeroizing::new(*iv);
    for block in input[240..].chunks_exact(16) {
        let plain = Zeroizing::new(std::array::from_fn(|i| {
            block[(i / 4) * 4 + 3 - i % 4] ^ chain[i]
        }));
        *chain = aes.encrypt(&plain);
    }
    std::array::from_fn(|i| chain[i] ^ iv[i])
}

#[cfg(test)]
mod tests {
    use super::proof;

    #[test]
    fn complete_proof_matches_independent_original_vectors() {
        for (input, expected) in [
            (
                [0; 336],
                [
                    0xd2, 0x11, 0x05, 0x32, 0x2a, 0xcf, 0x45, 0xbc, 0xa1, 0x48, 0x8e, 0xa9, 0x7b,
                    0xfa, 0x49, 0xb9,
                ],
            ),
            (
                [255; 336],
                [
                    0xa7, 0x0e, 0x95, 0xfa, 0x6d, 0x0c, 0xdc, 0xf0, 0x01, 0xb3, 0xee, 0xaa, 0x20,
                    0x46, 0xa9, 0x5b,
                ],
            ),
            (
                std::array::from_fn(|i| i as u8),
                [
                    0x9b, 0xcd, 0x15, 0xea, 0x35, 0x3a, 0x35, 0x2d, 0x85, 0xb9, 0x29, 0x93, 0x77,
                    0x12, 0x53, 0xd7,
                ],
            ),
        ] {
            assert_eq!(proof(&input), expected);
        }
    }

    #[test]
    #[ignore = "set ANISETTE_RS_PROOF_ORACLE to the local proof JSON"]
    fn complete_proof_matches_unreduced_original() {
        use crate::crypto::circuit::Circuit;
        use serde_json::{Value, json};
        use sha2::{Digest, Sha256};

        let bytes = std::fs::read(std::env::var_os("ANISETTE_RS_PROOF_ORACLE").unwrap()).unwrap();
        assert_eq!(
            format!("{:x}", Sha256::digest(&bytes)),
            "ef5796b978431a75b4f1b012083b1e2025829b87b3ec81d81811416f8117ddc1"
        );
        let original: Value = serde_json::from_slice(&bytes).unwrap();
        // This test converts the reference format; production does not parse or
        // evaluate its graph nodes.
        let operations = [
            "constant",
            "input",
            "lookup",
            "add",
            "sub",
            "mul",
            "xor",
            "and",
            "or",
            "neg",
            "not",
            "resize",
            "sign_extend",
            "extract",
            "concat",
            "shift_left",
            "shift_right",
            "arithmetic_right",
            "rotate_left",
            "rotate_right",
            "equal",
            "unsigned_less",
            "unsigned_less_equal",
            "signed_less",
            "signed_less_equal",
            "select",
            "array_new",
            "array_store",
            "array_load",
            "unsigned_divide",
            "unsigned_remainder",
            "multiply_high_signed",
            "multiply_high_unsigned",
            "bit_scan_reverse",
        ];
        let nodes: Vec<_> = original["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|n| {
                let code = operations.iter().position(|&name| n["op"] == name).unwrap();
                json!([n["bits"], code, n["args"], n["value"]])
            })
            .collect();
        let oracle = Circuit::from_json(
            &serde_json::to_vec(&json!({
                "input_bytes": 336, "nodes": nodes, "outputs": original["outputs"],
                "tables": original["tables"], "guards": [],
            }))
            .unwrap(),
        )
        .unwrap();
        let mut random = 0x12345678_u32;
        let mut digest = Sha256::new();
        for case in 0..1027 {
            let input = std::array::from_fn(|i| match case {
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
            let native = proof(&input);
            assert_eq!(
                native.as_slice(),
                oracle.evaluate(&input).unwrap().as_slice(),
                "case {case}"
            );
            digest.update(native);
        }
        assert_eq!(
            format!("{:x}", digest.finalize()),
            "28b298c98ecb81304d8b008ab954369fea4bc9ca75eb2c8a05d49c1e3dd1bee6"
        );
    }
}
