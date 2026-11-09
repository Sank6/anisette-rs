//! Self-contained ADI protocol formulas adapted from apple-auth under the MIT license.

/*
Copyright (c) 2026 yummy1gay

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

mod adjustments;
mod byte_math;
mod data;
mod engine;
mod mutation;
mod otp;
mod primitives;
pub(crate) mod provisioning;
mod state;

pub use engine::NativeEngine;
pub use state::{Profile, decode_file, encode_file, hardware_binding};

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    #[test]
    fn file_key_mutation_matches_independent_cpp_on_1027_inputs() {
        let mut rng = 0x8ad91e73_u32;
        let mut hash = Sha256::new();
        for sample in 0..1027 {
            let mut next = |i: usize| -> u8 {
                match sample {
                    0 => 0,
                    1 => 255,
                    2 => i as u8,
                    _ => {
                        rng ^= rng << 13;
                        rng ^= rng >> 17;
                        rng ^= rng << 5;
                        rng as u8
                    }
                }
            };
            let state = std::array::from_fn(&mut next);
            let table = std::array::from_fn(|i| next(i + 319));
            let (a, b, c) = mutation::mutate(&state, &table);
            hash.update(a);
            hash.update(b);
            hash.update(c);
        }
        assert_eq!(
            crate::identity::hex(&hash.finalize(), false),
            "c91483842eb3e5d4b07f819a490e8b6048d1ff017ea1568114e5e8ead104188a"
        );
    }

    #[test]
    fn forty_files_and_240_boundary_otps_match_independent_cpp() {
        let mut rng = 0xcbd82173_u32;
        let mut hash = Sha256::new();
        for sample in 0..40 {
            let mut next = |i: usize| -> u8 {
                match sample {
                    0 => 0,
                    1 => 255,
                    2 => i as u8,
                    _ => {
                        rng ^= rng << 13;
                        rng ^= rng >> 17;
                        rng ^= rng << 5;
                        rng as u8
                    }
                }
            };
            let hardware = std::array::from_fn(&mut next);
            let prefix_len = [0, 1, 31, 32, 35, 64, 227][sample % 7];
            let prefix: Vec<u8> = (0..prefix_len).map(|i| next(i + 20)).collect();
            let iv = std::array::from_fn(|i| next(i + 20 + prefix_len));
            let profile = Profile {
                machine: std::array::from_fn(|i| next(i + 300)),
                secondary: std::array::from_fn(|i| next(i + 400)),
                encrypted_seed: std::array::from_fn(|i| next(i + 700)),
                extra: std::array::from_fn(|i| next(i + 800)),
                option: if sample % 2 == 1 {
                    Some(0x9abc1357)
                } else {
                    None
                },
            };
            let file = encode_file(&profile, &hardware, &prefix, &iv).unwrap();
            hash.update(&file);
            let decoded = decode_file(&file, &hardware).unwrap();
            assert_eq!(decoded.machine, profile.machine);
            assert_eq!(decoded.secondary, profile.secondary);
            assert_eq!(decoded.encrypted_seed, profile.encrypted_seed);
            assert_eq!(decoded.extra, profile.extra);
            assert_eq!(decoded.option, profile.option);
            for counter in [0_u32, 1, 65535, 65536, 0x7fffffff, 0xffffffff] {
                let otp = decoded.otp_at(u64::from(counter) * 30).unwrap();
                hash.update(&otp[8..24]);
            }
        }
        assert_eq!(
            crate::identity::hex(&hash.finalize(), false),
            "ccf0506612d572c023c8e44e96034106b0dd4134404b479f60b21f91ba117cc4"
        );
    }

    #[test]
    fn file_authentication_rejects_corruption_and_wrong_hardware() {
        let profile = Profile {
            machine: [0; 60],
            secondary: [0; 208],
            encrypted_seed: [0; 32],
            extra: [0; 8],
            option: None,
        };
        let file = encode_file(&profile, &[1; 20], &[3; 35], &[5; 16]).unwrap();
        assert!(decode_file(&file, &[2; 20]).is_err());
        for index in [4, 8, 42, 43, 58, 59, 300, file.len() - 1] {
            let mut corrupt = file.clone();
            corrupt[index] ^= 1;
            assert!(decode_file(&corrupt, &[1; 20]).is_err(), "index {index}");
        }
        for length in [0, 1, 7, 8, 59, 60, file.len() - 1] {
            assert!(decode_file(&file[..length], &[1; 20]).is_err());
        }
    }
}
