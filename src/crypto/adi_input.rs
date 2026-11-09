//! Scalar state sequence used by the separate proof-input mask expansion.
//!
//! Complete word-domain checks cover all 32 updates, intermediate phases,
//! finalizers, and seed parity. Mask expansion is outside this module.

use zeroize::Zeroizing;

const INPUT_XOR: [u8; 32] = [
    0xe7, 0xee, 0xd9, 0x75, 0xed, 0xd1, 0xeb, 0x5e, 0x21, 0x82, 0x7f, 0xfe, 0x67, 0x18, 0x7e, 0x3e,
    0x5d, 0x2a, 0x44, 0x85, 0xb3, 0x04, 0xdd, 0x4a, 0x0e, 0x02, 0xb1, 0x31, 0xd1, 0x43, 0x24, 0x4f,
];

fn fold_word(value: u32) -> u32 {
    let first = value.wrapping_sub(value >> 16);
    first.wrapping_sub(first >> 8)
}

fn clear_state(encoded: u32) -> u32 {
    (encoded ^ 0x8000_0000).wrapping_sub(434_776_548)
}

fn fold_input(input: &[u8; 32], mut visit: impl FnMut(usize, u32, u32)) -> u32 {
    // In this coordinate, both halves of an update use the same round.
    let mut state = 0xf78e_2ce0_u32.wrapping_add(434_776_548) ^ 0x8000_0000;
    for (index, (&byte, &encoding)) in input.iter().zip(&INPUT_XOR).enumerate() {
        let counter = index as u32;
        let product = u32::from(byte ^ encoding).wrapping_mul(661_609_471);
        let first = fold_word((state ^ product).wrapping_add(counter)).wrapping_add(3_765_704_412);
        state = fold_word((first ^ product).wrapping_add(counter)).wrapping_add(3_765_704_412);
        visit(index, first, state);
    }
    clear_state(state)
}

pub fn proof_input_states(input: &[u8; 32]) -> Zeroizing<[u32; 32]> {
    let mut result = Zeroizing::new([0_u32; 32]);
    fold_input(input, |index, _, state| result[index] = clear_state(state));
    result
}

fn subtract_shift(value: u32, shift: u32) -> u32 {
    value.wrapping_sub(value >> shift)
}

fn add_shift(value: u32, shift: u32) -> u32 {
    value.wrapping_add(value >> shift)
}

fn finalize_first(value: u32) -> u32 {
    let value = subtract_shift(subtract_shift(value.wrapping_add(0xa0fd_01e5), 8), 2);
    let value = subtract_shift(subtract_shift(value.wrapping_add(0x1080_e96d), 10), 4);
    let value = subtract_shift(subtract_shift(value.wrapping_add(0x3445_3457), 12), 8);
    let value = add_shift(subtract_shift(value.wrapping_add(0x3f32_01d7), 15), 3);
    add_shift(subtract_shift(value ^ 0x43dd_9158, 15), 4) ^ 0x6edf_1891
}

fn finalize_second(value: u32) -> u32 {
    let value = add_shift(
        add_shift((value ^ 0x6edf_1891).wrapping_add(0x64e0_16ad), 14),
        4,
    );
    let value = add_shift(subtract_shift(value.wrapping_add(0x540d_3a33), 13), 2);
    let value = subtract_shift(add_shift(value.wrapping_add(0xd2be_e516), 12), 5);
    let value = add_shift(add_shift(value.wrapping_add(0x55eb_c8fe), 8), 1);
    subtract_shift(subtract_shift(value.wrapping_add(0xc875_9026), 12), 7) ^ 0x5e16_5793
}

fn finalize_third(value: u32) -> u32 {
    let value = subtract_shift(subtract_shift(value ^ 0x6d90_a79a, 8), 6) ^ 0x8000_0000;
    let value = subtract_shift(subtract_shift(value ^ 0x3845_ddb1, 10), 5) ^ 0x8000_0000;
    let value = add_shift(add_shift(value ^ 0x2b4a_668e, 9), 5);
    let value = subtract_shift(add_shift(value.wrapping_add(0x6f3b_bf4a), 9), 6) ^ 0x213b_e34c;
    add_shift(subtract_shift(value ^ 0xd446_5371, 13), 2).wrapping_add(0x0347_5680) ^ 0x5f
}

pub fn proof_input_seeds(input: &[u8; 32]) -> Zeroizing<[u8; 3]> {
    let mut parity = 0_u8;
    let last = fold_input(input, |_, first, state| parity ^= (first ^ state) as u8);
    // Phase and state encodings contribute the same constant on each iteration,
    // so their 32 copies cancel from the XOR parity.
    let first = finalize_first(last);
    let second = finalize_second(first);
    let third = finalize_third(second);
    parity ^= (first ^ second ^ third) as u8;
    Zeroizing::new([parity ^ 0xbd, parity ^ 0x75, parity ^ 0x68])
}

#[cfg(test)]
mod tests {
    use super::{proof_input_seeds, proof_input_states};
    use sha2::{Digest, Sha256};

    #[test]
    fn mask_seeds_match_independent_original_graph_vectors() {
        for (input, expected) in [
            ([0; 32], [0xd1, 0x19, 0x04]),
            ([255; 32], [0x67, 0xaf, 0xb2]),
            (std::array::from_fn(|i| 208 + i as u8), [0xb2, 0x7a, 0x67]),
        ] {
            assert_eq!(*proof_input_seeds(&input), expected);
        }
    }

    #[test]
    fn all_states_match_independent_graph_vectors() {
        // Each digest covers all 32 little-endian words from an independent
        // evaluation of the reference graph.
        for (input, expected) in [
            (
                [0; 32],
                "7b2fd9efe5b5b4e17d2b67a40486daeb314fa04f8acec4d25184beffdeda45bf",
            ),
            (
                [255; 32],
                "bdd013017f72ca762ea22e7d5311746759f15b62e9b9a7df22df41e5b3a2953c",
            ),
            (
                std::array::from_fn(|i| 208 + i as u8),
                "45e6c772d1c7ae294c08788db9ccec1c5058549dc5684ff947255c9a09d32e16",
            ),
        ] {
            let states = proof_input_states(&input);
            let mut digest = Sha256::new();
            for state in states.iter() {
                digest.update(state.to_le_bytes());
            }
            assert_eq!(format!("{:x}", digest.finalize()), expected);
        }
    }
}
