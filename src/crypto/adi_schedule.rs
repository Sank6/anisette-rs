pub fn expand(block: &[u8; 64]) -> [u32; 64] {
    let mut words = [0_u32; 64];
    for (word, bytes) in words[..16].iter_mut().zip(block.chunks_exact(4)) {
        *word = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    }
    for i in 16..64 {
        words[i] = next_word(words[i - 16], words[i - 15], words[i - 7], words[i - 2]);
    }
    words
}

pub fn next_word(old: u32, first: u32, seventh: u32, second: u32) -> u32 {
    let sigma0 = first
        .rotate_right(7)
        .wrapping_sub(first.rotate_right(18))
        .wrapping_sub(first >> 3);
    let sigma1 = (second.rotate_right(17) ^ second.rotate_right(19)).wrapping_add(second >> 10);
    old ^ sigma0.wrapping_sub(sigma1).wrapping_sub(seventh)
}
