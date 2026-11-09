pub fn prepare_block(unix_seconds: u64, lanes: &[u8; 16]) -> [u8; 64] {
    let mut block = [0_u8; 64];
    let counter = ((unix_seconds / 30) as u16).to_be_bytes();
    for chunk in block[..8].chunks_exact_mut(2) {
        chunk.copy_from_slice(&counter);
    }
    let mut feedback = 0x2f30_2222_u32;
    for i in 0..96 {
        let destination = (i + 7) % 55;
        let delta = lanes[i % 16].wrapping_add((feedback as u8) ^ 0xb1);
        block[destination] ^= delta;
        feedback ^= u32::from(block[destination]).wrapping_mul(0x5d80_9044);
    }
    block[55] = 0x80;
    block[56..].copy_from_slice(&440_u64.to_be_bytes());
    block
}
