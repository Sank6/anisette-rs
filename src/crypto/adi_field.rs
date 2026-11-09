//! Byte substitutions expressed as binary maps and field inversion.
//!
//! These operations support the complete native proof in `adi_proof`.
//! The equations use no profile files or external code at runtime.

/// Multiplication modulo x^8 + x^4 + x^3 + x + 1.
pub fn multiply(mut a: u8, mut b: u8) -> u8 {
    let mut product = 0;
    for _ in 0..8 {
        product ^= a & 0_u8.wrapping_sub(b & 1);
        a = (a << 1) ^ (0x1b & 0_u8.wrapping_sub(a >> 7));
        b >>= 1;
    }
    product
}

/// The field inverse, extended by inverse(0) = 0.
pub fn inverse(x: u8) -> u8 {
    let x2 = multiply(x, x);
    let x3 = multiply(x2, x);
    let x6 = multiply(x3, x3);
    let x12 = multiply(x6, x6);
    let x15 = multiply(x12, x3);
    let x30 = multiply(x15, x15);
    let x60 = multiply(x30, x30);
    let x120 = multiply(x60, x60);
    let x240 = multiply(x120, x120);
    let x252 = multiply(x240, x12);
    multiply(x252, x2)
}

/// A byte-to-word substitution with affine encodings on both sides.
pub struct EncodedInverse {
    pub input_columns: [u8; 8],
    pub input_bias: u8,
    pub output_columns: [u32; 8],
    pub output_bias: u32,
}

impl EncodedInverse {
    pub fn evaluate(&self, byte: u8) -> u32 {
        let mut input = self.input_bias;
        for (bit, &column) in self.input_columns.iter().enumerate() {
            input ^= column & 0_u8.wrapping_sub((byte >> bit) & 1);
        }
        let value = inverse(input);
        let mut output = self.output_bias;
        for (bit, &column) in self.output_columns.iter().enumerate() {
            output ^= column & 0_u32.wrapping_sub(u32::from((value >> bit) & 1));
        }
        output
    }
}

/// The four word contributions to a post-hash proof column.
///
/// These constants describe static byte encodings and contain no provisioned
/// identity or captured session state.
pub const PROOF_COLUMN_SUBSTITUTIONS: [EncodedInverse; 4] = [
    EncodedInverse {
        input_columns: [1, 78, 33, 160, 93, 28, 130, 38],
        input_bias: 119,
        output_columns: [
            1001946016, 375113010, 4039167070, 2396386965, 2375074771, 3392381422, 4158043705,
            625230488,
        ],
        output_bias: 4193471189,
    },
    EncodedInverse {
        input_columns: [1, 151, 23, 20, 90, 141, 161, 171],
        input_bias: 106,
        output_columns: [
            546525176, 3037876839, 2832004389, 4291540208, 3583345577, 645522485, 3665025099,
            67438131,
        ],
        output_bias: 1460134092,
    },
    EncodedInverse {
        input_columns: [1, 91, 33, 141, 142, 50, 45, 59],
        input_bias: 142,
        output_columns: [
            709526703, 3720960106, 4081817272, 2954105946, 4236119206, 3433541792, 3727543134,
            3463710675,
        ],
        output_bias: 2192536210,
    },
    EncodedInverse {
        input_columns: [1, 219, 109, 154, 66, 38, 121, 19],
        input_bias: 229,
        output_columns: [
            3834804500, 3282675873, 2735957596, 977661326, 2633921350, 3700702794, 2430836708,
            2314881682,
        ],
        output_bias: 3534919670,
    },
];

pub fn proof_column(bytes: [u8; 4]) -> u32 {
    PROOF_COLUMN_SUBSTITUTIONS
        .iter()
        .zip(bytes)
        .fold(0, |word, (substitution, byte)| {
            word ^ substitution.evaluate(byte)
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn field_matches_public_aes_vectors_and_all_inverses() {
        assert_eq!(multiply(0x57, 0x13), 0xfe);
        assert_eq!(multiply(0x57, 0x83), 0xc1);
        assert_eq!(inverse(0), 0);
        assert_eq!(inverse(0x53), 0xca);
        for x in 1..=255 {
            assert_eq!(multiply(x, inverse(x)), 1);
            assert_eq!(inverse(inverse(x)), x);
        }
    }

    #[test]
    fn encoded_inverse_matches_public_aes_substitution() {
        let aes = EncodedInverse {
            input_columns: [1, 2, 4, 8, 16, 32, 64, 128],
            input_bias: 0,
            output_columns: [0x1f, 0x3e, 0x7c, 0xf8, 0xf1, 0xe3, 0xc7, 0x8f],
            output_bias: 0x63,
        };
        for (input, expected) in [
            (0x00, 0x63),
            (0x01, 0x7c),
            (0x02, 0x77),
            (0x03, 0x7b),
            (0x10, 0xca),
            (0x53, 0xed),
            (0x7c, 0x10),
            (0xff, 0x16),
        ] {
            assert_eq!(aes.evaluate(input), expected);
        }
    }

    /// Developer-only differential check; ordinary builds need no local oracle.
    #[test]
    #[ignore = "set ANISETTE_RS_PROOF_ORACLE to the local proof JSON"]
    fn substitutions_match_every_local_oracle_input() {
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        let path = std::env::var_os("ANISETTE_RS_PROOF_ORACLE").expect("local proof oracle path");
        let profile: serde_json::Value =
            serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        let image = STANDARD
            .decode(profile["tables"][0]["data_b64"].as_str().unwrap())
            .unwrap();
        let word = |base: usize, byte: u8| {
            let offset = base + usize::from(byte) * 4;
            u32::from_le_bytes(image[offset..offset + 4].try_into().unwrap())
        };
        for byte in 0..=255_u8 {
            let x = u32::from(byte);
            let first = word(162304, byte)
                .wrapping_add(x * x)
                .wrapping_add(1354293768);
            let raw = word(227904, byte).wrapping_add(x * x);
            let masked = raw.wrapping_add(25496834) & 0x03f5_6095;
            let fourth = raw
                .wrapping_sub(2 * (masked ^ (raw & 1)))
                .wrapping_add(1568304534);
            let expected = [
                first ^ ((first >> 4) & 0x07a1_fd19) ^ 0xdca4_f180,
                word(1136, byte).wrapping_add(x * x).rotate_left(11) ^ 1290288108,
                word(55088, byte).wrapping_sub((x & 0xf0) | 0x0f),
                fourth,
            ];
            for (equation, reference) in PROOF_COLUMN_SUBSTITUTIONS.iter().zip(expected) {
                assert_eq!(equation.evaluate(byte), reference, "input {byte}");
            }
        }
    }
}
