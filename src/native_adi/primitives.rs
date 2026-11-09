use crate::{
    Error, Result,
    crypto::{adi_field::inverse, aes::Aes128},
};

pub(super) fn sha1(input: &[u8]) -> [u8; 20] {
    let mut message = input.to_vec();
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend_from_slice(&(input.len() as u64 * 8).to_be_bytes());
    let mut state = [
        0x67452301_u32,
        0xefcdab89,
        0x98badcfe,
        0x10325476,
        0xc3d2e1f0,
    ];
    for block in message.chunks_exact(64) {
        let mut schedule = [0_u32; 80];
        for (word, bytes) in schedule.iter_mut().zip(block.chunks_exact(4)) {
            *word = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        }
        for i in 16..80 {
            schedule[i] = (schedule[i - 3] ^ schedule[i - 8] ^ schedule[i - 14] ^ schedule[i - 16])
                .rotate_left(1);
        }
        let [mut a, mut b, mut c, mut d, mut e] = state;
        for (i, word) in schedule.into_iter().enumerate() {
            let (f, k) = match i {
                0..20 => ((b & c) | (!b & d), 0x5a827999),
                20..40 => (b ^ c ^ d, 0x6ed9eba1),
                40..60 => ((b & c) | (b & d) | (c & d), 0x8f1bbcdc),
                _ => (b ^ c ^ d, 0xca62c1d6),
            };
            let next = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(word);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = next;
        }
        for (word, value) in state.iter_mut().zip([a, b, c, d, e]) {
            *word = word.wrapping_add(value);
        }
    }
    let mut output = [0; 20];
    for (bytes, word) in output.chunks_exact_mut(4).zip(state) {
        bytes.copy_from_slice(&word.to_be_bytes());
    }
    output
}

pub(super) fn linear(columns: &[u8], value: u8) -> u8 {
    columns.iter().enumerate().fold(0, |out, (bit, col)| {
        out ^ (col & 0_u8.wrapping_sub((value >> bit) & 1))
    })
}

pub(super) fn cbc(input: &[u8], key: &[u8; 16], iv: &[u8; 16], encrypt: bool) -> Result<Vec<u8>> {
    if input.is_empty() || !input.len().is_multiple_of(16) {
        return Err(Error::Protocol);
    }
    let aes = Aes128::new(key);
    let mut previous = *iv;
    let mut output = Vec::with_capacity(input.len());
    for bytes in input.chunks_exact(16) {
        let mut block = [0; 16];
        block.copy_from_slice(bytes);
        if encrypt {
            for (byte, prev) in block.iter_mut().zip(previous) {
                *byte ^= prev;
            }
            previous = aes.encrypt(&block);
            output.extend_from_slice(&previous);
        } else {
            let decoded = aes.decrypt(&block);
            output.extend(decoded.into_iter().zip(previous).map(|(a, b)| a ^ b));
            previous = block;
        }
    }
    Ok(output)
}

pub(super) fn array<const N: usize>(bytes: &[u8]) -> Result<[u8; N]> {
    bytes.try_into().map_err(|_| Error::Protocol)
}

pub(super) fn recover_key(mut current: [u8; 16]) -> [u8; 16] {
    fn sbox(byte: u8) -> u8 {
        let x = inverse(byte);
        x ^ x.rotate_left(1) ^ x.rotate_left(2) ^ x.rotate_left(3) ^ x.rotate_left(4) ^ 0x63
    }
    for rcon in [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]
        .into_iter()
        .rev()
    {
        let mut previous = [0; 16];
        for i in 4..16 {
            previous[i] = current[i] ^ current[i - 4];
        }
        let rotated = [
            sbox(previous[13]) ^ rcon,
            sbox(previous[14]),
            sbox(previous[15]),
            sbox(previous[12]),
        ];
        for i in 0..4 {
            previous[i] = current[i] ^ rotated[i];
        }
        current = previous;
    }
    current
}

pub(super) fn same(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0_u8, |out, (x, y)| out | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn standard_sha1_vectors() {
        assert_eq!(
            crate::identity::hex(&sha1(b""), false),
            "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        );
        assert_eq!(
            crate::identity::hex(&sha1(b"abc"), false),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        assert_eq!(
            crate::identity::hex(
                &sha1(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
                false
            ),
            "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
        );
    }
}
