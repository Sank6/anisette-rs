use super::adi_schedule;

pub const INITIAL_STATE: [u32; 8] = [
    0xcf800017, 0xe63a7835, 0x7e133bf2, 0x6a9ae5dd, 0xd0465c04, 0xa1f23e27, 0x94b66da2, 0xe718d556,
];

pub const ROUND_CONSTANTS: [u32; 64] = [
    0x8576c81e, 0x47b236e5, 0x2456deac, 0xee8b1510, 0xc349aa3f, 0x84a4595f, 0x6fae546b, 0x4ce75a8b,
    0x4e93fe87, 0x19f07088, 0xe0dd64e6, 0x1e93f14f, 0x15723d4b, 0x1bfbaa22, 0x2eb08cd3, 0x55dc791e,
    0x6f7ec298, 0x5862d900, 0x9ddf952d, 0x0c2c2d4d, 0x907d149d, 0x73de690a, 0xe6c851e9, 0x0f500c6c,
    0x43e98608, 0x40b07401, 0x4550f859, 0xb423f2b8, 0x171f0ba2, 0xae2a37cf, 0x391d76e2, 0xf37b0dc9,
    0x6b3de19b, 0x21cd1ebd, 0x1042f6da, 0x5ce730ab, 0x7bbcd6d5, 0x7b4e3e93, 0x15c19e22, 0xbc94337a,
    0xe9ce9398, 0xa38b2cb8, 0xe662a1f5, 0xf0c05280, 0x5d7ef5bf, 0xda05bee6, 0xa4247273, 0x39523e47,
    0x3c5b38fb, 0x2e36883d, 0x4f1ec69b, 0xa9e26828, 0xd07ce3ae, 0xfde5e2cb, 0x4560cb39, 0xf8a4909c,
    0x59a7af41, 0x6e1f2516, 0x17f54fa3, 0x42c95dc4, 0x6ee24f14, 0x5e91028b, 0x950dfd58, 0xbf95ffaa,
];

pub fn round(state: [u32; 8], word: u32, constant: u32) -> [u32; 8] {
    let [a, b, c, d, e, f, g, h] = state;
    let sigma0 = a
        .rotate_right(2)
        .wrapping_add(a.rotate_right(13))
        .wrapping_sub(a.rotate_right(22));
    let sigma1 = e.rotate_right(6).wrapping_sub(e.rotate_right(11)) ^ e.rotate_right(25);
    let choose = ((e ^ g) ^ e.wrapping_add(f)).wrapping_add(g);
    let majority = (a ^ b).wrapping_sub(b.wrapping_add(c).wrapping_add(a ^ c));
    let first = h
        .wrapping_add(sigma1)
        .wrapping_sub(choose)
        .wrapping_add(constant)
        ^ word;
    let second = majority ^ sigma0;
    [
        first.wrapping_add(second),
        a,
        b,
        c,
        d.wrapping_add(first),
        e,
        f,
        g,
    ]
}

pub fn run_rounds(mut state: [u32; 8], block: &[u8; 64]) -> [u32; 8] {
    for (word, constant) in adi_schedule::expand(block).into_iter().zip(ROUND_CONSTANTS) {
        state = round(state, word, constant);
    }
    state
}

pub fn compress_block(block: &[u8; 64]) -> [u32; 8] {
    let [a, b, c, d, e, f, g, h] = run_rounds(INITIAL_STATE, block);
    [
        a.wrapping_sub(INITIAL_STATE[0]),
        b.wrapping_add(INITIAL_STATE[1]),
        c ^ INITIAL_STATE[2],
        d ^ INITIAL_STATE[3],
        e.wrapping_sub(INITIAL_STATE[4]),
        f.wrapping_sub(INITIAL_STATE[5]),
        g.wrapping_sub(INITIAL_STATE[6]),
        h.wrapping_add(INITIAL_STATE[7]),
    ]
}
