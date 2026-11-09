use super::{
    data, mutation,
    primitives::{array, cbc, same, sha1},
};
use crate::{Error, Result, crypto::aes::Aes128, identity::WindowsHardware};
use md5::{Digest, Md5};
use zeroize::{Zeroize, Zeroizing};

pub struct Profile {
    pub(crate) machine: [u8; 60],
    pub(crate) secondary: [u8; 208],
    pub(crate) encrypted_seed: [u8; 32],
    pub(crate) extra: [u8; 8],
    pub(crate) option: Option<u32>,
}
impl Drop for Profile {
    fn drop(&mut self) {
        self.secondary.zeroize();
        self.encrypted_seed.zeroize();
    }
}

pub fn hardware_binding(hardware: &WindowsHardware) -> Result<[u8; 20]> {
    hardware.identity()?;
    let mut bytes = b"cache-controlEthernet".to_vec();
    for field in [
        &hardware.volume_serial.to_le_bytes()[..],
        &hardware.bios_version,
        &hardware.processor_name,
    ] {
        bytes.extend_from_slice(&Md5::digest(field)[..7]);
    }
    Ok(sha1(&bytes))
}

pub(super) fn file_digest(hardware: &[u8; 20], prefix: &[u8]) -> Result<[u8; 16]> {
    if prefix.len() > 227 {
        return Err(Error::Protocol);
    }
    let mut prepared = data::FILE_KEY_PREPARATION_BASE;
    for (out, input) in prepared.iter_mut().zip(hardware.iter().chain(prefix)) {
        *out ^= input;
    }
    let input = &prepared[..28 + prefix.len()];
    let mut state: [u8; 319] = std::array::from_fn(|i| input[i % input.len()]);
    for i in 0..1276_u32 {
        let first =
            state[i as usize % 319] ^ state[i.wrapping_sub(13) as usize % 319].rotate_left(3);
        let second = state[i.wrapping_sub(57) as usize % 319].rotate_left(5);
        let third = state[i.wrapping_sub(155) as usize % 319].rotate_left(7);
        state[i as usize % 319] = first.wrapping_add(second).wrapping_sub(third);
    }
    let (state, tables, mut reduced) = mutation::mutate(&state, &data::FILE_KEY_INITIAL_TABLES);
    for part in [&tables[..64], &tables[64..], &state[..]] {
        for (i, byte) in part.iter().enumerate() {
            reduced[i % 16] ^= byte;
        }
    }
    for i in 0..256_u32 {
        let first = reduced[i.wrapping_sub(7) as usize % 16].rotate_left(1);
        let second = reduced[i.wrapping_sub(37) as usize % 16].rotate_left(6);
        let third = reduced[i.wrapping_sub(177) as usize % 16].rotate_left(5);
        reduced[i as usize % 16] ^= first ^ second ^ third;
    }
    for (i, byte) in prepared.iter_mut().enumerate() {
        *byte ^= data::FILE_KEY_INPUT_TO_HASH_MASK[i % 16];
    }
    for i in 0..16 {
        prepared[i] = reduced[i] ^ data::FILE_KEY_REDUCTION_TO_HASH_MASK[i];
    }
    Ok(Md5::digest(prepared).into())
}

fn tag_key(digest: &[u8; 16]) -> [u8; 16] {
    let mut message = data::STATE_FILE_TAG_KEY_BASE_MESSAGE;
    for i in 0..16 {
        message[16 + i] ^= digest[i];
    }
    Md5::digest(message).into()
}

fn body_key(digest: &[u8; 16]) -> [u8; 16] {
    let mut block = *digest;
    for (byte, mask) in block.iter_mut().zip(&data::STATE_DATA[16..32]) {
        *byte ^= mask;
    }
    let mut key = Aes128::new(&array::<16>(&data::STATE_DATA[..16]).expect("fixed key length"))
        .encrypt(&block);
    for (byte, mask) in key.iter_mut().zip(&data::STATE_DATA[32..48]) {
        *byte ^= mask;
    }
    key
}

pub(super) fn authenticated_digest(input: &[u8], key: &[u8; 16]) -> [u8; 20] {
    let mut digest = sha1(input);
    let mut block = [0; 16];
    block.copy_from_slice(&digest[..16]);
    digest[..16].copy_from_slice(&Aes128::new(key).encrypt(&block));
    digest
}

fn number(input: &[u8], at: usize) -> Result<u32> {
    Ok(u32::from_be_bytes(array(
        input.get(at..at + 4).ok_or(Error::Protocol)?,
    )?))
}
fn tag(index: usize) -> u32 {
    let start = 68 + index * 4;
    u32::from_be_bytes([
        data::STATE_DATA[start],
        data::STATE_DATA[start + 1],
        data::STATE_DATA[start + 2],
        data::STATE_DATA[start + 3],
    ])
}
fn serialize(profile: &Profile) -> Vec<u8> {
    let mut area = Vec::new();
    let mut record = |index, value: &[u8]| {
        area.extend_from_slice(&tag(index).to_be_bytes());
        area.extend_from_slice(&(value.len() as u32).to_be_bytes());
        area.extend_from_slice(value);
    };
    record(0, &(u64::MAX - 1).to_be_bytes());
    record(1, &profile.machine);
    record(2, &profile.secondary);
    record(3, &profile.encrypted_seed);
    if let Some(option) = profile.option {
        record(4, &option.to_be_bytes());
    }
    record(5, &profile.extra);
    let mut body = Vec::new();
    body.extend_from_slice(&1_u32.to_be_bytes());
    body.extend_from_slice(&data::STATE_DATA[64..68]);
    body.extend_from_slice(&(area.len() as u32).to_be_bytes());
    body.extend(area);
    body.resize(body.len().div_ceil(16) * 16, 0);
    for (i, byte) in body.iter_mut().enumerate() {
        *byte ^= data::STATE_DATA[48 + i % 16];
    }
    body
}

fn parse(encoded: &[u8]) -> Result<Profile> {
    if encoded.len() < 16 || !encoded.len().is_multiple_of(16) {
        return Err(Error::Protocol);
    }
    let body = Zeroizing::new(
        encoded
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ data::STATE_DATA[48 + i % 16])
            .collect::<Vec<_>>(),
    );
    if number(&body, 0)? != 1 || body[4..8] != data::STATE_DATA[64..68] {
        return Err(Error::Protocol);
    }
    let end = 12_usize
        .checked_add(number(&body, 8)? as usize)
        .ok_or(Error::Protocol)?;
    if end > body.len() || body.len() - end > 15 {
        return Err(Error::Protocol);
    }
    let mut cursor = 12;
    let mut fields: [&[u8]; 6] = [&[]; 6];
    for (index, field) in fields.iter_mut().enumerate() {
        if index == 4 && end.saturating_sub(cursor) >= 8 && number(&body, cursor)? == tag(5) {
            continue;
        }
        if end.saturating_sub(cursor) < 8 || number(&body, cursor)? != tag(index) {
            return Err(Error::Protocol);
        }
        let length = number(&body, cursor + 4)? as usize;
        cursor += 8;
        let next = cursor.checked_add(length).ok_or(Error::Protocol)?;
        if next > end {
            return Err(Error::Protocol);
        }
        *field = &body[cursor..next];
        cursor = next;
    }
    if cursor != end || fields[0] != (u64::MAX - 1).to_be_bytes() {
        return Err(Error::Protocol);
    }
    Ok(Profile {
        machine: array(fields[1])?,
        secondary: array(fields[2])?,
        encrypted_seed: array(fields[3])?,
        option: if fields[4].is_empty() {
            None
        } else {
            Some(u32::from_be_bytes(array(fields[4])?))
        },
        extra: array(fields[5])?,
    })
}

pub fn decode_file(file: &[u8], hardware: &[u8; 20]) -> Result<Profile> {
    if file.len() < 60 || file.len() > crate::MAX_BLOB || !matches!(number(file, 0)?, 1 | 3) {
        return Err(Error::Protocol);
    }
    let prefix_len = number(file, 4)? as usize;
    let iv_start = 8_usize.checked_add(prefix_len).ok_or(Error::Protocol)?;
    if prefix_len > 227
        || iv_start + 16 + 16 + 20 > file.len()
        || !(file.len() - iv_start - 16 - 20).is_multiple_of(16)
    {
        return Err(Error::Protocol);
    }
    let digest = Zeroizing::new(file_digest(hardware, &file[8..iv_start])?);
    let expected = authenticated_digest(&file[4..file.len() - 20], &tag_key(&digest));
    if !same(&expected, &file[file.len() - 20..]) {
        return Err(Error::Protocol);
    }
    let mut plain = Zeroizing::new(cbc(
        &file[iv_start + 16..file.len() - 20],
        &body_key(&digest),
        &array(&file[iv_start..iv_start + 16])?,
        false,
    )?);
    for (i, b) in plain.iter_mut().enumerate() {
        *b ^= data::STATE_BODY_OUTPUT_MASK[i % 16];
    }
    parse(&plain)
}

pub fn encode_file(
    profile: &Profile,
    hardware: &[u8; 20],
    prefix: &[u8],
    iv: &[u8; 16],
) -> Result<Vec<u8>> {
    let digest = Zeroizing::new(file_digest(hardware, prefix)?);
    let mut body = Zeroizing::new(serialize(profile));
    for (i, b) in body.iter_mut().enumerate() {
        *b ^= data::STATE_BODY_OUTPUT_MASK[i % 16];
    }
    let ciphertext = cbc(&body, &body_key(&digest), iv, true)?;
    let mut file = Vec::new();
    file.extend_from_slice(&3_u32.to_be_bytes());
    file.extend_from_slice(&(prefix.len() as u32).to_be_bytes());
    file.extend_from_slice(prefix);
    file.extend_from_slice(iv);
    file.extend(ciphertext);
    let auth = authenticated_digest(&file[4..], &tag_key(&digest));
    file.extend(auth);
    Ok(file)
}
