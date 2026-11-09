//! Fixed CBC decryption and feedback decoding of the proof-key material.
//!
//! The decoded round schedule and IV are unpacked by `adi_proof`.

use super::adi_block::{OUTPUT_ENCODING, proof_block};
use zeroize::Zeroizing;

const KEY_IV: [u8; 16] = [
    0x22, 0x42, 0x2d, 0x54, 0xd3, 0xfd, 0xbf, 0x20, 0xe7, 0xc4, 0x7e, 0xc9, 0xff, 0xa9, 0x60, 0xd1,
];

// A permutation of the 192 conditional updates. Byte 31 has a seed correction.
pub(crate) const UPDATE_ORDER: [usize; 192] = [
    159, 50, 19, 192, 58, 95, 24, 84, 99, 185, 34, 77, 173, 174, 154, 75, 172, 187, 165, 88, 125,
    11, 160, 92, 83, 54, 26, 143, 82, 55, 146, 149, 162, 76, 33, 194, 93, 196, 135, 190, 0, 89,
    141, 129, 87, 14, 102, 120, 126, 204, 111, 49, 72, 189, 97, 43, 79, 96, 30, 177, 153, 63, 73,
    107, 195, 104, 27, 35, 170, 148, 37, 113, 80, 116, 51, 62, 48, 181, 142, 21, 70, 98, 4, 41,
    144, 6, 186, 108, 2, 67, 25, 46, 65, 85, 115, 179, 47, 138, 94, 118, 64, 68, 106, 201, 182, 86,
    203, 140, 22, 158, 71, 91, 193, 105, 127, 74, 117, 133, 197, 42, 121, 52, 61, 119, 166, 151,
    17, 101, 13, 110, 23, 12, 205, 59, 169, 112, 109, 200, 152, 103, 16, 191, 175, 156, 5, 56, 3,
    180, 100, 32, 163, 199, 157, 18, 176, 1, 28, 130, 188, 161, 122, 124, 206, 137, 171, 36, 39,
    40, 132, 136, 167, 38, 15, 57, 20, 69, 198, 183, 155, 9, 178, 184, 66, 7, 10, 168, 90, 202, 53,
    150, 164, 44,
];

pub fn decode_key_material(ciphertext: &[u8; 208]) -> Zeroizing<[u8; 208]> {
    let mut bytes = Zeroizing::new([0_u8; 208]);
    for base in (0..208).step_by(16) {
        let ciphertext_block = std::array::from_fn(|byte| ciphertext[base + byte]);
        let block = Zeroizing::new(proof_block(&ciphertext_block));
        for byte in 0..16 {
            let predecessor = if base == 0 {
                KEY_IV[byte]
            } else {
                ciphertext[base - 16 + byte]
            };
            bytes[base + byte] = block[byte] ^ OUTPUT_ENCODING[byte] ^ predecessor;
        }
    }
    let mut feedback = [8, 123, 147, 207]
        .into_iter()
        .fold(0_u8, |sum, index| sum.wrapping_add(bytes[index]));
    bytes[31] = bytes[31].wrapping_sub(feedback);
    for index in UPDATE_ORDER {
        let mixed = mix_byte(feedback, bytes[index]);
        bytes[index] = mixed ^ feedback;
        feedback = mixed.wrapping_add(110);
    }
    bytes
}

pub fn mix_byte(value: u8, byte: u8) -> u8 {
    match value & 7 {
        3 => byte.wrapping_sub(value) ^ value,
        5 => byte.wrapping_add(value) ^ value,
        6 | 7 => byte,
        _ => byte ^ value,
    }
}

#[cfg(test)]
mod tests {
    use super::{decode_key_material, mix_byte};
    use sha2::{Digest, Sha256};

    #[test]
    fn complete_key_material_matches_graph_vectors() {
        // Each digest covers all 208 bytes from an independent graph evaluation,
        // including its seed and final update.
        for (ciphertext, expected) in [
            (
                [0; 208],
                "dc607fb951e2d2f4bbb538153066f26ba4bf5397d9c61d8bbfd3a09637567d4d",
            ),
            (
                [255; 208],
                "ac4c246cb8f2ca01787c0a820756e5506405ef7cf2fa390198b6c0ba95c4b252",
            ),
            (
                std::array::from_fn(|i| i as u8),
                "4318f649200407e6251bc43834dd6d2fd6fd8b10dd1817b6608d9646fbca8cc9",
            ),
        ] {
            let decoded = decode_key_material(&ciphertext);
            assert_eq!(
                format!("{:x}", Sha256::digest(decoded.as_slice())),
                expected
            );
        }
    }

    #[test]
    fn every_byte_pair_matches_the_independent_oracle_digest() {
        // Digest of all 65,536 outputs of an independent scalar reference
        // (normalized cuts 69326 and 70259,
        // output 81718). The first cut encodes the feedback sum as x + 17.
        // Oracle SHA256:
        // ef5796b978431a75b4f1b012083b1e2025829b87b3ec81d81811416f8117ddc1
        let mut digest = Sha256::new();
        for encoded in 0_u16..256 {
            for byte in 0_u16..256 {
                digest.update([mix_byte((encoded as u8).wrapping_add(17), byte as u8)]);
            }
        }
        assert_eq!(
            format!("{:x}", digest.finalize()),
            "b0042e97f22b1cc899553bd8f364542f736fcde5ffb08274d9a0fc7ee2023e89"
        );
    }
}
