use super::{
    Profile, data,
    primitives::{array, cbc, linear, recover_key},
};
use crate::{
    Error, Result,
    crypto::{adi_compression, adi_schedule, aes::Aes128},
};
use zeroize::Zeroizing;

fn hash(message: &[u8]) -> [u8; 32] {
    let mut bytes = message.to_vec();
    bytes.push(0x80);
    while bytes.len() % 64 != 56 {
        bytes.push(0);
    }
    bytes.extend_from_slice(&(message.len() as u64 * 8).to_be_bytes());
    let mut state = data::GSA_HASH_INITIAL_STATE;
    for bytes in bytes.chunks_exact(64) {
        let mut block = [0; 64];
        block.copy_from_slice(bytes);
        let initial = state;
        for (word, constant) in adi_schedule::expand(&block)
            .into_iter()
            .zip(data::GSA_HASH_ROUND_CONSTANTS)
        {
            state = adi_compression::round(state, word, constant);
        }
        state = [
            state[0].wrapping_sub(initial[0]),
            state[1].wrapping_add(initial[1]),
            state[2] ^ initial[2],
            state[3] ^ initial[3],
            state[4].wrapping_sub(initial[4]),
            state[5].wrapping_sub(initial[5]),
            state[6].wrapping_sub(initial[6]),
            state[7].wrapping_add(initial[7]),
        ];
    }
    let mut digest = [0; 32];
    for (bytes, word) in digest.chunks_exact_mut(4).zip(state) {
        bytes.copy_from_slice(&word.to_be_bytes());
    }
    digest
}

impl Profile {
    fn key(&self) -> Result<[u8; 16]> {
        let mut previous = array::<16>(&data::STATE_DATA[140..156])?;
        let aes = Aes128::new(&array(&data::STATE_DATA[124..140])?);
        let mut state = Zeroizing::new([0_u8; 208]);
        for (offset, chunk) in self.secondary.chunks_exact(16).enumerate() {
            let ciphertext = array(chunk)?;
            let plain = aes.decrypt(&ciphertext);
            for i in 0..16 {
                let byte = plain[i] ^ previous[i] ^ data::STATE_DATA[156 + i];
                state[offset * 16 + i] = linear(
                    &data::STATE_DATA[172 + (i % 4) * 8..180 + (i % 4) * 8],
                    byte,
                );
            }
            previous = ciphertext;
        }
        for byte in state.iter_mut() {
            *byte ^= 5;
        }
        let mut feedback = state[207]
            .wrapping_add(state[147])
            .wrapping_add(state[8])
            .wrapping_add(state[123]);
        state[31] = state[31].wrapping_sub(feedback);
        for index in data::GSA_KEY_MIX_POSITIONS {
            let byte = &mut state[usize::from(index)];
            *byte = match feedback & 7 {
                3 => byte.wrapping_sub(feedback),
                5 => byte.wrapping_add(feedback),
                6 | 7 => *byte ^ feedback,
                _ => *byte,
            };
            feedback = (feedback ^ *byte).wrapping_add(0x6e);
        }
        for byte in state.iter_mut() {
            *byte ^= 5;
        }
        let mut last = [0; 16];
        for (i, output) in last.iter_mut().enumerate() {
            let at = 204 + 3 * i;
            let sources = &data::STATE_DATA[at..at + 3];
            if sources.iter().any(|&s| usize::from(s) >= state.len()) {
                return Err(Error::Protocol);
            }
            *output = data::STATE_DATA[252 + i]
                ^ state[usize::from(sources[0])]
                ^ linear(
                    &data::STATE_DATA[268..276],
                    state[usize::from(sources[1])] ^ state[usize::from(sources[2])],
                );
        }
        Ok(recover_key(last))
    }

    pub fn otp_at(&self, seconds: u64) -> Result<[u8; 28]> {
        let counter =
            u32::try_from(seconds / 30).map_err(|_| Error::State("unsupported OTP clock"))?;
        let seed = Zeroizing::new(cbc(
            &self.encrypted_seed,
            &array(&data::STATE_DATA[92..108])?,
            &array(&data::STATE_DATA[108..124])?,
            false,
        )?);
        let first = Zeroizing::new(hash(&seed));
        let expanded: [u8; 64] = std::array::from_fn(|i| {
            first[(5 * i + 7) % 32] ^ first[(5 * i * i + 9) % 32].wrapping_add(42)
        });
        let second = Zeroizing::new(hash(&expanded));
        let mut message = [0_u8; 55];
        for (i, modulus) in data::COUNTER_MODULI.into_iter().enumerate() {
            let residue = counter % modulus;
            message[i * 2] = (residue >> 8) as u8;
            message[i * 2 + 1] = residue as u8;
        }
        let mut rolling = 0x6b532d89_u32;
        for i in 0..96 {
            let at = (i + 7) % 55;
            message[at] ^= ((rolling ^ 0x1a).wrapping_add(u32::from(seed[(i * 2 + 1) % 32]))) as u8;
            rolling ^= u32::from(message[at]).wrapping_mul(0x5d809044);
        }
        let third = Zeroizing::new(hash(&message));
        let key = Zeroizing::new(self.key()?);
        let aes = Aes128::new(&key);
        let mut mac = [0_u8; 16];
        for digest in [&*first, &*second, &*third] {
            for block in digest.chunks_exact(16) {
                for i in 0..16 {
                    mac[i] ^= block[i];
                }
                mac = aes.encrypt(&mac);
            }
        }
        let mut otp = [0; 28];
        otp[..8].copy_from_slice(&[0, 0, 0, 5, 0, 0, 0, 16]);
        otp[8..24].copy_from_slice(&mac);
        otp[27] = 2;
        Ok(otp)
    }

    pub fn machine(&self) -> &[u8; 60] {
        &self.machine
    }
}
