//! Provisioning hardware adjustments adapted from apple-auth under the MIT license.

use super::{byte_math::*, data};
use crate::{Error, Result};

pub(super) fn adjust_seed(
    state: &mut [u8; 384],
    output: &mut [u8],
    parameters: &[u8; 128],
) -> Result<()> {
    if output.is_empty() {
        return Err(Error::Protocol);
    }
    let initial = Buf::from_bytes(*state);
    let mut state_out = initial;
    let parameters = Buf::from_bytes(*parameters);
    let mut working = Buf::from_bytes(data::HARDWARE_SEED_WORKING_BASE);
    let mut local = Buf::<64>::zero();
    let mut fixed = Buf::<64>::zero();
    for i in 0..64 {
        let index = n(i);
        local[index] = parameters[n(64) + index] ^ n(120);
        fixed[index] = byte(parameters[index] + n(233));
    }
    let table_26_lookup = fixed[initial[n(90)] & n(0x3F)];
    working[n(26)] = byte(
        (byte((word(initial[n(75)]) * table_26_lookup) >> n(1))
            - ((word(initial[n(75)]) * table_26_lookup) & n(0xF2))
            + n(0x79))
            ^ n(0x79),
    );
    state_out[n(197)] = byte(initial[n(69)] + initial[n(197)]);
    working[n(40)] = byte(initial[n(231)] ^ n(0xF3));
    state_out[n(239)] = byte(initial[n(239)] + n(0xE1));
    let state_bits = byte((initial[n(153)] & n(0x1A)) | (initial[n(194)] & n(0xE4)));
    local[n(23)] = byte(((word(state_bits) >> n(1)) - (state_bits & n(0xF0)) + n(0x78)) ^ n(0x78));
    local[n(6)] = n(0x28);
    let table_5_lookup = working[initial[n(153)] & n(0x3F)];
    working[n(5)] = byte(
        (n(0x77) + ((table_5_lookup & n(0x18)) ^ n(0xDE))
            - (((n(2) * n(0x77)) + (n(0xFE) * ((table_5_lookup & n(0x18)) ^ n(0x22)))) & n(0xF2))
            + n(0x79))
            ^ n(0x79),
    );
    local[n(5)] = byte(n(2) * (fixed[initial[n(17)] & n(0x3F)] / n(5)));
    let shifted_constant = byte(xor_shifts(
        n(0x77),
        initial[n(230)] & n(7),
        (n(0) - initial[n(230)]) & n(7),
    ));
    let output_mask = byte(shifted_constant & n(0x92));
    working[n(11)] = byte(shifted_constant & n(0x10));
    let table_22_lookup = local[initial[n(51)] & n(0x3F)];
    let table_22_shift = working[initial[n(112)] & n(0x3F)];
    state_out[n(64)] = byte(working[initial[n(103)] & n(0x3F)] + initial[n(64)]);
    state_out[n(11)] = byte(word(initial[n(121)]) >> n(1));
    working[n(32)] = byte((n(0x1A) + n(0x4B)) ^ n(0x80));
    working[n(52)] = byte(n(0xDC) ^ (byte((n(0x39) & n(0xAD)) ^ n(0x83)) / n(5)));
    let table_45_lookup = working[initial[n(59)] & n(0x3F)];
    let shifted_lookup = byte(xor_shifts(
        (table_22_lookup & n(0x90)) ^ n(0x2A),
        (table_22_shift & n(2)) ^ n(7),
        (table_22_shift & n(2)) ^ n(1),
    ));
    local[n(22)] = byte(shifted_lookup + n(0x62));
    working[n(45)] = byte(
        (n(0xFD) + (((word(byte(table_45_lookup ^ n(0x79))) >> n(1)) & n(0x1C)) ^ n(0x82))
            - (((n(2) * n(0xFD)) + ((table_45_lookup & n(0x38)) ^ n(0x3C))) & n(0xF2))
            + n(0x79))
            ^ n(0x79),
    );
    working[n(53)] = n(0x5E);
    local[n(12)] = n(0x84);
    let output_8_lookup = local[initial[n(75)] & n(0x3F)];
    let table_2_left = fixed[initial[n(198)] & n(0x3F)];
    let table_2_right = fixed[initial[n(163)] & n(0x3F)];
    working[n(2)] = byte(
        n(0x7C)
            + (((initial[n(65)] & n(0x33)) | ((table_2_right & table_2_left) & n(0xCC)))
                | ((table_2_right | table_2_left) & n(0xC8))),
    );
    state_out[n(81)] = byte((n(2) * state_out[n(239)]) + n(0xA4));
    let difference_left = local[initial[n(130)] & n(0x3F)];
    let difference_right = working[initial[n(83)] & n(0x3F)];
    working[n(41)] =
        byte(n(0xA1) ^ (word(byte(state_out[n(64)] ^ n(0xFF))) * (initial[n(151)] ^ n(0x2D))));
    let state_192_shift = working[initial[n(158)] & n(0x3F)];
    state_out[n(192)] = byte(
        (initial[n(192)] ^ byte(n(0x50) << (state_192_shift & n(7))))
            ^ byte(n(0x50) >> ((n(0) - state_192_shift) & n(7))),
    );
    let combined_left = working[initial[n(191)] & n(0x3F)];
    let combined_right = fixed[initial[n(175)] & n(0x3F)];
    state_out[n(76)] = byte((n(0xC6) & n(0xDD)) ^ n(0x86));
    working[n(49)] = byte(n(0x80) + n(0x43));
    state_out[n(131)] =
        byte(initial[n(131)] - ((fixed[initial[n(160)] & n(0x3F)] / n(3)) & n(0x76)));
    let state_10_lookup = local[initial[n(210)] & n(0x3F)];
    state_out[n(10)] = byte(
        initial[n(10)]
            - (!((state_10_lookup & n(0xF)) | (n(0xC5) & ((state_10_lookup & n(0xF0)) ^ n(0xF))))),
    );
    working[n(22)] = byte(
        n(0xE6) - (((working[initial[n(72)] & n(0x3F)] ^ n(0xDD)) & initial[n(139)]) & n(0xA7)),
    );
    let lookup_difference = byte((difference_right - difference_left) | n(8));
    let lookup_bias = byte(n(0) - lookup_difference - n(13));
    local[n(14)] = byte(
        local[initial[n(48)] & n(0x3F)]
            - ((fixed[lookup_bias & n(0x3F)] & (working[n(11)] ^ n(0xFF)))
                | (working[n(11)] & n(0x94)))
            + n(0xDA),
    );
    let combined_lookups =
        byte((combined_left & combined_right) | ((combined_left | combined_right) & n(0x7D)));
    let folded_bits = rotl8(combined_lookups, n(1));
    working[n(51)] = byte(folded_bits ^ n(0xC1));
    let output_9_shift = local[initial[n(146)] & n(0x3F)];
    let square_lookup = working[initial[n(247)] & n(0x3F)];
    working[n(32)] = byte(
        working[n(32)]
            ^ ((((n(0xE1) & n(0xE2)) ^ n(0xE2)) | (initial[n(203)] & n(0xE1))) + n(0xD8)),
    );
    let output_21_lookup = local[initial[n(211)] & n(0x3F)];
    let state_77_left = fixed[initial[n(180)] & n(0x3F)];
    let state_77_right = fixed[initial[n(194)] & n(0x3F)];
    let state_77_bits = byte(((initial[n(23)] ^ n(0x40)) | state_77_left) & n(0xB9));
    state_out[n(77)] = byte(
        (((initial[n(23)] & state_77_left) | state_77_bits) & (word(state_77_right) * n(3)))
            | (((((n(3) * state_77_right) + n(0x80)) | (initial[n(23)] & state_77_left))
                | state_77_bits)
                & n(0x75)),
    );
    working[n(57)] = byte(lookup_difference + n(0x6D) + n(0x4D));
    local[n(53)] = initial[n(238)];
    local[n(41)] = byte(cube_byte(
        (fixed[lookup_bias & n(0x3F)] + n(0x80)) & n(0x63),
    ));
    working[n(29)] = byte(n(0x9C) - initial[n(207)]);
    local[n(49)] = byte(
        (!(((initial[n(115)] & n(0x75)) | (fixed[initial[n(113)] & n(0x3F)] & n(0x8A))) ^ n(0x1B)))
            ^ n(0x78),
    );
    let table_36_lookup = working[initial[n(185)] & n(0x3F)];
    let table_36_mask = local[initial[n(242)] & n(0x3F)];
    working[n(36)] = byte(
        (fixed[table_36_lookup & n(0x3F)] ^ n(0xC4))
            ^ ((table_36_mask & n(0x43)) | (n(0x39) & (table_36_mask | n(0x43)))),
    );
    local[n(46)] = byte(
        (((n(0x1C) & n(0xC1)) ^ n(0xC1))
            | (xor_shifts(
                n(0xF6),
                (n(0) - initial[n(128)]) & n(7),
                initial[n(128)] & n(7),
            ) & n(0x1C)))
            ^ n(0x8A),
    );
    local[n(48)] = n(0xD4);
    let table_10_lookup = working[initial[n(166)] & n(0x3F)];
    working[n(10)] = byte(
        n(0x59)
            ^ ((n(0xA7) & (table_10_lookup ^ n(0x88)))
                | (((!(n(0xA7) ^ n(0x79))) | (!(table_10_lookup ^ n(0x79)))) & n(0x51))),
    );
    let square_input = byte((square_lookup & (local[n(6)] ^ n(0xFF))) | (local[n(6)] & n(0x69)));
    let squared_lookup = byte(word(square_input) * square_input);
    let table_34_lookup = working[(squared_lookup & n(0x3F)) ^ n(0xB)];
    let table_34_mask = working[initial[n(147)] & n(0x3F)];
    working[n(34)] = byte(
        n(0xD5)
            + table_34_lookup
            + ((initial[n(53)] & table_34_mask) | ((initial[n(53)] | table_34_mask) & n(0x33))),
    );
    let state_163_left = local[initial[n(116)] & n(0x3F)];
    let state_163_right = local[initial[n(56)] & n(0x3F)];
    let state_163_lookup = working[initial[n(143)] & n(0x3F)];
    let square_adjustment = byte(squared_lookup ^ n(0xCB));
    state_out[n(163)] = byte(
        initial[n(163)]
            - (((word(state_163_lookup) * n(3)) & (n(0xD9) ^ n(0xFF)))
                | (n(0xD9)
                    & ((state_163_right & (square_adjustment ^ n(0xFF)))
                        | (square_adjustment & state_163_left)))),
    );
    local[n(8)] = byte((n(0x8C) & n(0xCB)) ^ n(0xA7));
    let table_7_lookup = fixed[state_out[n(76)] & n(0x3F)];
    working[n(7)] = byte(
        n(0xA8) - ((table_7_lookup & n(0x18)) | (working[n(51)] & (table_7_lookup | n(0x18)))),
    );
    working[n(2)] = byte(
        ((byte(((word(byte(lookup_bias | n(0xC3))) * n(0xCD)) & n(0xFC00)) >> n(10)) ^ n(0x39))
            + n(0x40))
            ^ n(0x79),
    );
    working[n(23)] = byte(n(0x15) + n(5));
    let output_0_lookup = fixed[initial[n(130)] & n(0x3F)];
    let table_11_left = local[initial[n(32)] & n(0x3F)];
    let table_11_right = fixed[state_out[n(10)] & n(0x3F)];
    working[n(11)] = byte(
        initial[n(237)]
            & ((table_11_left & table_11_right)
                | (((table_11_left ^ n(0x20)) | table_11_right) & n(0xDE))),
    );
    state_out[n(32)] = byte(
        initial[n(32)]
            - (((initial[n(111)] / n(5)) & (folded_bits ^ n(0x3E))) | (working[n(51)] & n(0x19))),
    );
    let output_delta = byte((initial[n(180)] & n(0xC3)) | n(0x10));
    let adjustments = Buf::new([
        byte(
            n(0) - (word(byte((output_0_lookup & n(0x88)) | n(0x17)))
                * ((output_0_lookup & n(0x88)) | n(0x17)))
                + n(0xE7),
        ),
        n(0x78),
        n(0xDD),
        n(0x6F),
        n(0x79),
        n(0xB2),
        byte(n(0) - lookup_difference + n(0xB3)),
        n(0x88),
        byte(
            output_mask
                - ((((output_8_lookup + n(0xCF)) & output_delta)
                    | (((output_8_lookup ^ n(0x40)) + n(0xF)) & n(0x2D)))
                    | (output_delta & n(0x2D)))
                + n(0x1D),
        ),
        xor_shifts(
            fixed[initial[n(127)] & n(0x3F)],
            (output_9_shift + n(0xB6)) & n(7),
            ((output_9_shift ^ n(0xFF)) + n(0x53)) & n(7),
        ),
        n(0xA7),
        square_adjustment,
        n(0x3F),
        n(0x41),
        n(0xB9),
        n(6),
        n(0xE0),
        n(0xBB),
        working[n(51)],
        n(0xB1),
        n(0x63),
        byte(((output_21_lookup ^ n(0x18)) | n(0x9E)) + fixed[initial[n(187)] & n(0x3F)] + n(0x2A)),
        n(0xC3),
        n(0x3B),
        n(0x7D),
        byte(shifted_lookup + n(0x62)),
        n(0xC3),
        n(0xD3),
        n(0xA5),
        n(0x93),
        n(0x94),
        n(0xDE),
    ]);
    for (index, delta) in adjustments.bytes().into_iter().enumerate() {
        let at = index % output.len();
        output[at] = output[at].wrapping_add(delta);
    }
    for index in 0..64 {
        output[index % output.len()] ^= working.0[index].0 as u8 ^ local.0[index].0 as u8;
    }
    *state = state_out.bytes();
    Ok(())
}

pub(super) fn adjust_mixer(
    state: &mut [u8; 384],
    output: &mut [u8],
    parameters: &[u8; 128],
) -> Result<()> {
    if output.is_empty() {
        return Err(Error::Protocol);
    }
    let initial = Buf::from_bytes(*state);
    let mut state_out = initial;
    let parameters = Buf::from_bytes(*parameters);
    let mut working = Buf::from_bytes(data::HARDWARE_MIXER_WORKING_BASE);
    let mut local = Buf::<64>::zero();
    let mut fixed = Buf::<64>::zero();
    for i in 0..64 {
        let index = n(i);
        local[index] = parameters[n(64) + index] ^ n(125);
        fixed[index] = byte(parameters[index] + n(186));
    }
    working[n(26)] = byte(initial[n(54)] ^ n(0x73));
    working[n(40)] = n(0xFA);
    local[n(25)] = n(0x4B);
    local[n(47)] =
        byte((((local[initial[n(144)] & n(0x3F)] & n(0xEE)) ^ n(0xFE)) + n(0x15)) ^ n(0xCA));
    local[n(58)] = byte(n(0) - initial[n(97)] + n(0xE8));
    state_out[n(227)] = initial[n(63)];
    local[n(26)] = byte(
        (((n(0) - (((n(0xED) ^ n(0xFF)) & n(0xC9)) | (n(0xED) & (initial[n(148)] + n(0x6B))))
            + n(0x31))
            ^ n(0x7D))
            + n(0x80))
            ^ n(0x7D),
    );
    state_out[n(34)] = byte(working[initial[n(28)] & n(0x3F)] + initial[n(34)] + n(0x4B));
    local[n(8)] = byte(
        (!(fixed[initial[n(41)] & n(0x3F)] | n(0xED)))
            | (((n(0x8E) * n(0xFD)) + n(0xBA)) & n(0xEC)),
    );
    let rotation_source = fixed[initial[n(191)] & n(0x3F)];
    let table_2_left = working[initial[n(103)] & n(0x3F)];
    let table_2_right = working[initial[n(24)] & n(0x3F)];
    working[n(2)] = byte(
        (((word(initial[n(80)]) * table_2_left) & (word(table_2_right) * n(0x9A)))
            | ((word(table_2_right) * n(0x9A)) & n(0x76)))
            | ((word(initial[n(80)]) * table_2_left) & n(0x76)),
    );
    state_out[n(199)] = byte(
        initial[n(199)]
            - ((initial[n(178)] & n(0xA5)) | ((word(initial[n(114)]) * n(3)) & n(0x5A))),
    );
    working[n(38)] = byte(n(0x41) + fixed[initial[n(29)] & n(0x3F)]);
    state_out[n(95)] = byte(initial[n(95)] - local[initial[n(5)] & n(0x3F)]);
    working[n(15)] =
        byte(n(0xEB) + (n(2) * working[initial[n(52)] & n(0x3F)]) - cube_byte(initial[n(54)]));
    working[n(10)] = byte((initial[n(148)] + n(0x4D)) ^ n(0x80));
    working[n(50)] = n(0x42);
    let table_11_lookup = working[initial[n(184)] & n(0x3F)];
    let table_11_shift = working[initial[n(65)] & n(0x3F)];
    local[n(14)] = byte(
        (word(byte((local[n(58)] & n(0x6D)) ^ n(0x92))) * ((local[n(58)] & n(0x6D)) ^ n(0x92)))
            + n(0x26),
    );
    local[n(28)] =
        byte(((initial[n(158)] & local[initial[n(37)] & n(0x3F)]) - initial[n(51)]) ^ n(0xAD));
    local[n(11)] = xor_shifts(
        table_11_lookup & n(0x81),
        (table_11_shift & n(4)) ^ n(5),
        (table_11_shift & n(4)) ^ n(3),
    );
    let output_2_shift = working[initial[n(109)] & n(0x3F)];
    let majority_left = fixed[initial[n(245)] & n(0x3F)];
    let majority_right = fixed[initial[n(45)] & n(0x3F)];
    local[n(62)] = byte(
        (((initial[n(69)] + n(0x80)) & n(0x10)) | ((word(initial[n(112)]) * n(2)) & n(0x6C)))
            ^ n(0x6B),
    );
    let state_24_mask = local[initial[n(24)] & n(0x3F)];
    let lookup_bias =
        byte(n(0) - (word(rotation_source) >> n(1)) + (rotation_source & n(0x36)) + n(0x64));
    let rotated_bits = byte(
        ((initial[n(162)] & rotl8(rotation_source, n(7)))
            | ((initial[n(162)] | lookup_bias) & n(0x18)))
            ^ n(0x63),
    );
    let state_24_lookup = fixed[rotated_bits & n(0x3F)];
    working[n(42)] = n(0x96);
    state_out[n(24)] =
        byte((state_24_lookup | n(0xCD)) ^ ((state_24_mask ^ n(0x7D)) & n(0x47)) ^ n(0xE5));
    let state_95_bits = byte(((initial[n(95)] & n(0x16)) ^ n(0x31)) + n(0x63));
    working[n(3)] = byte((state_95_bits & n(0x8A)) ^ n(0x64));
    let combined_left = local[initial[n(74)] & n(0x3F)];
    let cubed_bits = cube_byte(byte(state_95_bits | (initial[n(200)] + n(0x80))));
    let combined_right = local[(n(0) - cubed_bits + n(0x16)) & n(0x3F)];
    local[n(40)] = byte(cube_byte(byte((initial[n(245)] & n(0x18)) ^ n(0x63))) + n(0xAE));
    state_out[n(174)] = byte(
        n(0) - fixed[working[initial[n(92)] & n(0x3F)] & n(0x3F)] - fixed[initial[n(6)] & n(0x3F)]
            + initial[n(174)],
    );
    let state_103_lookup = working[initial[n(59)] & n(0x3F)];
    let majority_bits =
        byte((majority_right & majority_left) | ((majority_right | majority_left) & state_95_bits));
    let table_bits = byte(
        ((majority_bits & n(0x99)) | (local[n(26)] & ((majority_bits ^ n(0x19)) | n(0x99))))
            ^ n(0xBE),
    );
    let selected_bits = byte(
        (state_103_lookup & n(0x2C)) | (table_bits & ((state_103_lookup & n(0xD3)) ^ n(0x2C))),
    );
    let shift_source = byte(initial[n(21)] | fixed[state_out[n(34)] & n(0x3F)]);
    state_out[n(103)] = byte(
        initial[n(103)]
            ^ xor_shifts(
                selected_bits,
                shift_source & n(7),
                (n(0) - shift_source) & n(7),
            ),
    );
    working[n(60)] = byte(n(0x97) + n(4));
    let state_23_bits =
        byte((initial[n(45)] & n(0xF4)) | ((fixed[initial[n(173)] & n(0x3F)] / n(3)) & n(9)));
    state_out[n(23)] = byte(state_23_bits ^ n(2));
    let shifted_lookup = byte(xor_shifts(
        fixed[((n(0xFD) ^ n(0x7F)) + n(0xC6)) & n(0x3F)],
        (n(0) - initial[n(120)]) & n(7),
        initial[n(120)] & n(7),
    ));
    let scaled_bits = byte(((n(3) * rotated_bits) & n(0x3D)) + rotated_bits);
    state_out[n(235)] = byte(
        initial[n(235)]
            ^ ((shifted_lookup & scaled_bits) | ((shifted_lookup | scaled_bits) & n(0xDE))),
    );
    working[n(15)] = byte(working[n(15)] + n(0x32));
    working[n(53)] = byte(
        n(0x13)
            ^ ((((n(0xE1) & n(0xBC)) ^ n(0xBC)) & (working[n(38)] ^ n(0xFF)))
                | ((n(0) - cubed_bits + n(0x96)) & working[n(38)])),
    );
    state_out[n(126)] =
        byte(initial[n(126)] ^ (word(byte(local[initial[n(74)] & n(0x3F)] + n(0x3B))) * n(3)));
    state_out[n(224)] = n(0xEE);
    state_out[n(253)] = initial[n(146)];
    let table_36_left = local[state_out[n(235)] & n(0x3F)];
    let table_36_right = working[initial[n(111)] & n(0x3F)];
    state_out[n(10)] = byte(initial[n(10)] + n(0x7D));
    working[n(36)] = byte(
        (((word(initial[n(99)]) * n(2))
            ^ (((table_36_right ^ n(0x5A)) & n(0xF0)) | ((table_36_left ^ n(0x7D)) & n(0xF))))
            ^ n(0xE1))
            ^ n(0x5D),
    );
    let output_30_left = working[initial[n(9)] & n(0x3F)];
    let output_30_right = local[initial[n(168)] & n(0x3F)];
    let combined_lookups = byte(
        ((combined_right ^ n(1)) & (combined_left ^ n(1)))
            | (n(0x2C) & ((combined_right ^ n(1)) | (combined_left ^ n(1)))),
    );
    let lookup_index = byte((word(combined_lookups) >> n(1)) - (combined_lookups & n(0xC)) + n(6));
    working[n(13)] = n(0xA);
    let table_2_mask = local[initial[n(53)] & n(0x3F)];
    let table_2_bits = byte(fixed[initial[n(105)] & n(0x3F)] | n(0x48));
    working[n(2)] = byte(
        (table_2_bits & (table_2_mask ^ n(0xFF)))
            | ((table_2_bits | (table_2_mask ^ n(0xFF))) & n(0xE8)),
    );
    let product = byte(word(local[initial[n(22)] & n(0x3F)]) * fixed[initial[n(165)] & n(0x3F)]);
    working[n(55)] = byte(word(product) * product);
    let output_7_lookup = fixed[working[initial[n(62)] & n(0x3F)] & n(0x3F)];
    state_out[n(252)] = byte(initial[n(252)] ^ n(0x5C));
    working[n(51)] = byte(
        n(0xFA) + (initial[n(210)] | (local[n(58)] + local[(output_7_lookup / n(5)) ^ n(0x34)])),
    );
    state_out[n(33)] =
        byte(initial[n(33)] - byte((word(working[initial[n(249)] & n(0x3F)]) * n(0xA1)) >> n(1)));
    local[n(27)] = byte((word(initial[n(217)]) * initial[n(217)]) + n(0xDC));
    state_out[n(172)] = byte(initial[n(172)] ^ (initial[n(40)] & n(0x51)) ^ n(0xD5));
    working[n(56)] = byte(
        (initial[n(106)] & (lookup_index ^ n(0x18)))
            | ((lookup_index ^ n(0xA7)) & ((initial[n(22)] & n(0x24)) ^ n(0x8B))),
    );
    let table_32_lookup = fixed[initial[n(181)] & n(0x3F)];
    working[n(32)] = byte(
        n(0xE8)
            + (((((local[initial[n(130)] & n(0x3F)] ^ n(0x7D)) & n(0x32))
                | (fixed[initial[n(213)] & n(0x3F)] & n(0xCD)))
                ^ n(0x30))
                & ((table_32_lookup & local[n(8)]) | (n(0xBA) & (table_32_lookup | local[n(8)])))),
    );
    let output_18_left = working[initial[n(165)] & n(0x3F)];
    local[n(1)] = byte(local[initial[n(35)] & n(0x3F)] ^ n(0x3C));
    let output_18_right = local[initial[n(85)] & n(0x3F)];
    let adjustments = Buf::new([
        byte(lookup_index ^ n(0xE7)),
        n(0x46),
        xor_shifts(
            byte(word(fixed[initial[n(254)] & n(0x3F)]) * n(3)),
            output_2_shift & n(7),
            (n(0) - output_2_shift) & n(7),
        ),
        n(0xFA),
        n(0xF),
        n(0x2C),
        n(0xC),
        byte((output_7_lookup / n(5)) ^ n(0x74)),
        n(0x26),
        byte(fixed[initial[n(136)] & n(0x3F)] + n(0x25)),
        n(0xBC),
        n(0x6B),
        n(0x48),
        state_95_bits,
        n(0x48),
        n(0xA1),
        n(0xD0),
        scaled_bits,
        byte(
            (((output_18_right ^ n(0x7D)) & n(0x5E))
                | ((word(byte(output_18_left ^ n(0x5A))) * n(2)) & n(0xA0)))
                ^ n(0xFC),
        ),
        n(0x3A),
        table_bits,
        n(0x7B),
        n(0x6B),
        byte(n(0) - cubed_bits + n(0x96)),
        n(0xEE),
        n(0x42),
        n(0x77),
        initial[n(105)],
        n(0xFA),
        n(2),
        byte(
            ((output_30_left & output_30_right)
                | (((output_30_left ^ n(8)) | (output_30_right ^ n(9))) & n(0x76)))
                & n(0xD6),
        ),
        n(0x67),
    ]);
    for (index, delta) in adjustments.bytes().into_iter().enumerate() {
        let at = index % output.len();
        output[at] = output[at].wrapping_add(delta);
    }
    for index in 0..64 {
        output[index % output.len()] ^= working.0[index].0 as u8 ^ local.0[index].0 as u8;
    }
    *state = state_out.bytes();
    Ok(())
}
