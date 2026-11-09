use super::{
    Profile, adjustments, data,
    primitives::{array, cbc, linear, same, sha1},
    state::authenticated_digest,
};
use crate::{Error, Result, crypto::aes::Aes128};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

pub(crate) struct Start {
    pub(crate) challenge: [u8; 347],
    pub(crate) body: [u8; 160],
    pub(crate) cpim: [u8; 276],
}
impl Drop for Start {
    fn drop(&mut self) {
        self.body.zeroize();
    }
}

fn word(input: &[u8], at: usize) -> Result<u32> {
    Ok(u32::from_be_bytes(array(
        input.get(at..at + 4).ok_or(Error::Protocol)?,
    )?))
}

pub(super) fn invert(columns: &[u8]) -> Result<[u8; 256]> {
    let mut inverse = [0; 256];
    let mut seen = [false; 256];
    for value in 0..=255_u8 {
        let target = usize::from(linear(columns, value));
        if seen[target] {
            return Err(Error::Protocol);
        }
        seen[target] = true;
        inverse[target] = value;
    }
    Ok(inverse)
}

pub(super) fn response_key(material: &[u8], parameters: &[u8]) -> Result<[u8; 16]> {
    if material.len() != 240 || parameters.len() != 596 {
        return Err(Error::Protocol);
    }
    let mut inverses = [[0; 256]; 4];
    for (row, inverted) in inverses.iter_mut().enumerate() {
        let base = row * 89;
        let mut columns = array::<8>(&parameters[base + 1..base + 9])?;
        for col in 0..8 {
            let at = base + 9 + col * 10;
            let source = usize::from(parameters[at]);
            if source >= 64 {
                return Err(Error::Protocol);
            }
            let image = linear(&parameters[at + 2..at + 10], material[176 + source]);
            for (bit, column) in columns.iter_mut().enumerate() {
                if parameters[at + 1] >> (bit) & 1 != 0 {
                    *column ^= image;
                }
            }
        }
        *inverted = invert(&columns)?;
    }
    let mut schedule = Zeroizing::new([0_u8; 176]);
    for position in 0..176 {
        let row = position % 4;
        let encoded = linear(
            &parameters[356 + row * 8..364 + row * 8],
            material[position],
        ) ^ parameters[420 + position];
        schedule[position] = linear(
            &parameters[388 + row * 8..396 + row * 8],
            inverses[row][usize::from(encoded)],
        );
    }
    let key = array(&schedule[..16])?;
    if !Aes128::new(&key).matches_round_keys(&schedule) {
        return Err(Error::Protocol);
    }
    Ok(key)
}

pub(super) fn hardware_tag(hardware: &[u8; 20], parameters: &[u8]) -> Result<[u8; 20]> {
    if parameters.len() != 272 {
        return Err(Error::Protocol);
    }
    let mut length_sum = 43_usize;
    for i in 0..146 {
        length_sum = (length_sum + 14 * usize::from(hardware[i % 20] % 177)) % 177;
    }
    let mut seed = Zeroizing::new(vec![0xe5_u8; 80 + length_sum]);
    let mut state: [u8; 384] = std::array::from_fn(|i| hardware[i % 20]);
    for i in 0..1536_usize {
        let first = state[(i + 384 - 13) % 384].rotate_left(3);
        let second = state[(i + 384 - 57) % 384].rotate_left(5);
        let third = state[(i + 384 - 155) % 384].rotate_left(7);
        state[i % 384] = (state[i % 384] ^ first)
            .wrapping_add(second)
            .wrapping_sub(third);
    }
    adjustments::adjust_seed(&mut state, &mut seed, &array(&parameters[..128])?)?;
    let size = seed.len();
    for (i, b) in state.iter().enumerate() {
        seed[i % size] ^= b;
    }
    for i in 0..256 {
        let a = seed[(i + size - 7 % size) % size].rotate_left(1);
        let b = seed[(i + size - 37 % size) % size].rotate_left(6);
        let c = seed[(i + size - 177 % size) % size].rotate_left(5);
        seed[i % size] ^= a ^ b ^ c;
    }
    for byte in seed.iter_mut() {
        *byte = byte.wrapping_sub(0x92);
    }
    let mut length_sum = 11_usize;
    for i in 0..seed.len() + 172 {
        length_sum =
            (length_sum + 34 * usize::from(seed[i % seed.len()].wrapping_add(0x92) % 41)) % 41;
    }
    let mut mixed = Zeroizing::new(vec![0x87_u8; 20 + length_sum]);
    let mut state: [u8; 384] = std::array::from_fn(|i| seed[i % seed.len()].wrapping_add(0x92));
    for i in 0..1536_u32 {
        let a = state[i.wrapping_sub(13) as usize % 384].rotate_left(3);
        let b = state[i.wrapping_sub(57) as usize % 384].rotate_left(5);
        let c = state[i.wrapping_sub(155) as usize % 384].rotate_left(7);
        state[i as usize % 384] = (state[i as usize % 384] ^ a)
            .wrapping_add(b)
            .wrapping_sub(c);
    }
    adjustments::adjust_mixer(&mut state, &mut mixed, &array(&parameters[128..256])?)?;
    let size = mixed.len();
    for (i, b) in state.iter().enumerate() {
        mixed[i % size] ^= b;
    }
    for i in 0..256_u32 {
        let a = mixed[i.wrapping_sub(7) as usize % size].rotate_left(1);
        let b = mixed[i.wrapping_sub(37) as usize % size].rotate_left(6);
        let c = mixed[i.wrapping_sub(177) as usize % size].rotate_left(5);
        mixed[i as usize % size] ^= a ^ b ^ c;
    }
    let digest = sha1(&mixed);
    let key = array(&parameters[256..272])?;
    let mut out = digest;
    out[..16].copy_from_slice(&Aes128::new(&key).encrypt(&array(&digest[..16])?));
    Ok(out)
}

pub(crate) fn verify_challenge(challenge: &[u8]) -> Result<()> {
    if challenge.len() != 347
        || word(challenge, 0)? != 4
        || word(challenge, 4)? != 240
        || word(challenge, 264)? != 52
        || word(challenge, 268)? != 4
        || word(challenge, 320)? != 0xed9281d8
    {
        return Err(Error::Protocol);
    }
    let digest = authenticated_digest(&challenge[4..324], &array(&data::END_DATA[644..660])?);
    if !same(&digest, &challenge[324..344]) {
        return Err(Error::Protocol);
    }
    Ok(())
}

pub(crate) fn begin(
    challenge: &[u8],
    hardware: &[u8; 20],
    selector: &[u8; 32],
    entropy: &[u8; 84],
    seconds: u32,
    nonce: &[u8; 16],
) -> Result<Start> {
    verify_challenge(challenge)?;
    if selector.contains(&0) {
        return Err(Error::Protocol);
    }
    let request = &data::REQUEST_DATA;
    let mut input = Zeroizing::new(cbc(
        selector,
        &array(&request[988..1004])?,
        &array(&request[1004..1020])?,
        true,
    )?);
    for (i, b) in input.iter_mut().enumerate() {
        *b ^= request[32 + i % 16];
    }
    // The selector input mask is deliberately applied at both stage boundaries.
    let plaintext: Vec<u8> = input
        .iter()
        .enumerate()
        .map(|(i, b)| b ^ request[32 + i % 16])
        .collect();
    let encrypted = cbc(
        &plaintext,
        &array(&request[..16])?,
        &array(&request[16..32])?,
        true,
    )?;
    let tag = hardware_tag(hardware, &request[48..320])?;
    let mut body = [0; 160];
    body[..4].copy_from_slice(&32_u32.to_be_bytes());
    body[4..36].copy_from_slice(&encrypted);
    body[36..40].copy_from_slice(&32_u32.to_be_bytes());
    body[40..72].copy_from_slice(&entropy[..32]);
    body[72..92].copy_from_slice(&tag);
    body[92..132].copy_from_slice(&entropy[32..72]);
    body[132..140].copy_from_slice(&(u64::MAX - 1).to_be_bytes());
    body[140..144].copy_from_slice(&seconds.to_be_bytes());
    body[144..148].copy_from_slice(&2_u32.to_be_bytes());
    body[148..160].copy_from_slice(&entropy[72..84]);
    let material = Zeroizing::new(cbc(
        &challenge[8..248],
        &array(&request[320..336])?,
        &array(&request[336..352])?,
        false,
    )?);
    let key = Zeroizing::new(response_key(&material, &request[352..948])?);
    let ciphertext = cbc(&body, &key, nonce, true)?;
    let digest_parameter =
        Aes128::new(&array(&request[972..988])?).decrypt(&array(&challenge[248..264])?);
    let mut digest = Sha256::new();
    digest.update(&ciphertext);
    digest.update(digest_parameter);
    digest.update(&request[948..972]);
    let mut cpim = [0; 276];
    cpim[..4].copy_from_slice(&5_u32.to_be_bytes());
    cpim[4..20].copy_from_slice(nonce);
    cpim[20..24].copy_from_slice(&160_u32.to_be_bytes());
    cpim[24..184].copy_from_slice(&ciphertext);
    cpim[184..216].copy_from_slice(&digest.finalize());
    cpim[216..276].copy_from_slice(&challenge[264..324]);
    Ok(Start {
        challenge: array(challenge)?,
        body,
        cpim,
    })
}

pub(crate) fn finish(start: &Start, packet: &[u8], trust_key: &[u8]) -> Result<Profile> {
    verify_challenge(&start.challenge)?;
    if packet.len() != 311
        || trust_key.len() != 16
        || word(packet, 0)? != 4
        || word(packet, 20)? != 256
        || word(packet, 280)? != 0xed9281d8
    {
        return Err(Error::Protocol);
    }
    let parameters = &data::END_DATA;
    let digest = authenticated_digest(&packet[4..284], &array(&parameters[644..660])?);
    if !same(&digest, &packet[284..304]) {
        return Err(Error::Protocol);
    }
    let material = Zeroizing::new(cbc(
        &start.challenge[8..248],
        &array(&parameters[..16])?,
        &array(&parameters[16..32])?,
        false,
    )?);
    let response = Zeroizing::new(response_key(&material, &parameters[32..628])?);
    let intermediate = Aes128::new(&response).encrypt(&array(trust_key)?);
    let key = Zeroizing::new(Aes128::new(&array(&parameters[628..644])?).encrypt(&intermediate));
    let plain = Zeroizing::new(cbc(&packet[24..280], &key, &array(&packet[4..20])?, false)?);
    if word(&plain, 0)? != 208
        || word(&plain, 212)? != 32
        || !same(&plain[216..248], &start.body[40..72])
    {
        return Err(Error::Protocol);
    }
    Ok(Profile {
        machine: array(&start.body[72..132])?,
        secondary: array(&plain[4..212])?,
        encrypted_seed: array(&start.body[4..36])?,
        extra: [0; 8],
        option: None,
    })
}
