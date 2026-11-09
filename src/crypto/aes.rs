//! AES-128 using field arithmetic, with no lookup images or external code.
//!
//! State layout, key expansion, and inverse rounds follow NIST FIPS 197.

use zeroize::Zeroizing;

use super::adi_field::{inverse, multiply};

pub struct Aes128 {
    round_keys: Zeroizing<[u8; 176]>,
}

fn substitute(byte: u8) -> u8 {
    let value = inverse(byte);
    value
        ^ value.rotate_left(1)
        ^ value.rotate_left(2)
        ^ value.rotate_left(3)
        ^ value.rotate_left(4)
        ^ 0x63
}

fn inverse_substitute(byte: u8) -> u8 {
    inverse(byte.rotate_left(1) ^ byte.rotate_left(3) ^ byte.rotate_left(6) ^ 0x05)
}

fn shift_rows(state: &[u8; 16], reverse: bool) -> [u8; 16] {
    std::array::from_fn(|index| {
        let row = index % 4;
        let column = index / 4;
        let source = if reverse {
            column + 4 - row
        } else {
            column + row
        } % 4;
        state[source * 4 + row]
    })
}

fn mix_columns(state: &mut [u8; 16], reverse: bool) {
    let coefficients = if reverse {
        [
            [14, 11, 13, 9],
            [9, 14, 11, 13],
            [13, 9, 14, 11],
            [11, 13, 9, 14],
        ]
    } else {
        [[2, 3, 1, 1], [1, 2, 3, 1], [1, 1, 2, 3], [3, 1, 1, 2]]
    };
    for column in state.chunks_exact_mut(4) {
        let input: [u8; 4] = std::array::from_fn(|i| column[i]);
        for (target, row) in column.iter_mut().zip(coefficients) {
            *target = row
                .into_iter()
                .zip(input)
                .fold(0, |value, (coefficient, byte)| {
                    value ^ multiply(coefficient, byte)
                });
        }
    }
}

impl Aes128 {
    pub(crate) fn matches_round_keys(&self, expected: &[u8; 176]) -> bool {
        self.round_keys
            .iter()
            .zip(expected)
            .fold(0_u8, |out, (a, b)| out | (a ^ b))
            == 0
    }
    pub(crate) fn from_round_keys(round_keys: Zeroizing<[u8; 176]>) -> Self {
        Self { round_keys }
    }

    pub fn new(key: &[u8; 16]) -> Self {
        let mut round_keys = Zeroizing::new([0; 176]);
        round_keys[..16].copy_from_slice(key);
        let mut rcon = 1;
        for offset in (16..176).step_by(4) {
            let mut word: [u8; 4] = std::array::from_fn(|i| round_keys[offset - 4 + i]);
            if offset % 16 == 0 {
                word.rotate_left(1);
                word = word.map(substitute);
                word[0] ^= rcon;
                rcon = multiply(rcon, 2);
            }
            for i in 0..4 {
                round_keys[offset + i] = round_keys[offset - 16 + i] ^ word[i];
            }
        }
        Self { round_keys }
    }

    fn add_key(&self, state: &mut [u8; 16], round: usize) {
        for (byte, key) in state
            .iter_mut()
            .zip(&self.round_keys[round * 16..round * 16 + 16])
        {
            *byte ^= key;
        }
    }

    pub fn encrypt(&self, input: &[u8; 16]) -> [u8; 16] {
        let mut state = *input;
        self.add_key(&mut state, 0);
        for round in 1..=10 {
            state = shift_rows(&state.map(substitute), false);
            if round < 10 {
                mix_columns(&mut state, false);
            }
            self.add_key(&mut state, round);
        }
        state
    }

    pub fn decrypt(&self, input: &[u8; 16]) -> [u8; 16] {
        let mut state = *input;
        self.add_key(&mut state, 10);
        for round in (1..10).rev() {
            state = shift_rows(&state, true).map(inverse_substitute);
            self.add_key(&mut state, round);
            mix_columns(&mut state, true);
        }
        state = shift_rows(&state, true).map(inverse_substitute);
        self.add_key(&mut state, 0);
        state
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes(hex: &str) -> [u8; 16] {
        std::array::from_fn(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap())
    }

    #[test]
    fn matches_fips_197_appendix_b_and_public_zero_vector() {
        for (key, plain, cipher) in [
            (
                "2b7e151628aed2a6abf7158809cf4f3c",
                "3243f6a8885a308d313198a2e0370734",
                "3925841d02dc09fbdc118597196a0b32",
            ),
            (
                "00000000000000000000000000000000",
                "00000000000000000000000000000000",
                "66e94bd4ef8a2c3b884cfa59ca342b2e",
            ),
            (
                "000102030405060708090a0b0c0d0e0f",
                "00112233445566778899aabbccddeeff",
                "69c4e0d86a7b0430d8cdb78070b4c55a",
            ),
        ] {
            let aes = Aes128::new(&bytes(key));
            assert_eq!(aes.encrypt(&bytes(plain)), bytes(cipher));
            assert_eq!(aes.decrypt(&bytes(cipher)), bytes(plain));
        }
    }

    #[test]
    fn all_substitutions_and_inverse_mixing_are_invertible() {
        for byte in 0..=255 {
            assert_eq!(inverse_substitute(substitute(byte)), byte);
        }
        for position in 0..16 {
            for bit in 0..8 {
                let mut state = [0; 16];
                state[position] = 1 << bit;
                let expected = state;
                mix_columns(&mut state, false);
                mix_columns(&mut state, true);
                assert_eq!(state, expected);
            }
        }
    }
}
