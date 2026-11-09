//! Native file-key mutation adapted from apple-auth under the MIT license.

use super::byte_math::*;
use super::data;

fn reduction_input(bias: Buf<13>) -> Buf<16> {
    let mut input = Buf::<16>::zero();

    input[n(0)] = byte(bias[n(7)] + bias[n(6)] + n(0x97));
    input[n(1)] = byte(n(0x27));
    input[n(2)] = byte((rotl8(byte(bias[n(12)]), n(6)) ^ n(0x61)) + n(0x87));
    input[n(3)] = byte(bias[n(5)] + bias[n(8)] + n(0xA9));
    input[n(4)] = byte(n(0xD5));
    input[n(5)] = byte(n(0xF));
    input[n(6)] = byte((bias[n(1)] ^ n(0x70)) + n(0xB9));
    input[n(7)] = byte((bias[n(2)] ^ n(0xDA)) + n(0x47));
    input[n(8)] = byte(bias[n(11)] + n(3));
    input[n(9)] = byte(n(0x25));
    input[n(10)] = byte(n(0) - bias[n(3)] + n(0xE));
    input[n(11)] = byte(n(0x23));
    input[n(12)] = byte(n(0) - bias[n(0)] + n(0xEB));
    input[n(13)] = byte(bias[n(4)] + (bias[n(10)] ^ n(0x34)) + n(0xB));
    input[n(14)] = byte(n(0x93));
    input[n(15)] = byte((bias[n(9)] ^ n(0x24)) + n(0xCD));
    input
}

pub(super) fn mutate(initial: &[u8; 319], tables: &[u8; 128]) -> ([u8; 319], [u8; 128], [u8; 16]) {
    let initial = Buf::from_bytes(*initial);
    let tables = Buf::from_bytes(*tables);
    let file_key_fixed_table = Buf::from_bytes(data::FILE_KEY_FIXED_TABLE);
    let mut state = initial;
    let mut tables_out = tables;
    let state_94_lookup = tables_out[initial[n(40)] & n(0x3F)];
    let state_94_mask = tables_out[n(64) + (initial[n(52)] & n(0x3F))];
    let selected_bits =
        byte(((state_94_lookup ^ n(0x73)) & n(0x75)) | ((tables[n(33)] ^ n(0x73)) & n(0x8A)));
    state[n(94)] = byte(
        initial[n(94)]
            - (((selected_bits ^ n(0x73))
                & (((tables[n(36)] ^ n(0x73)) & n(0x20)) | (state_94_mask & tables[n(36)])))
                | (((selected_bits ^ n(0xF3))
                    | ((tables[n(36)] ^ n(0x73)) & n(0x20))
                    | (state_94_mask & tables[n(36)]))
                    & n(0x2B))),
    );
    state[n(64)] =
        byte(initial[n(64)] ^ (file_key_fixed_table[initial[n(85)] & n(0x3F)] & n(0xA)) ^ n(0x22));
    let bias_2_lookup = tables_out[initial[n(157)] & n(0x3F)];
    let bias_6_lookup = tables_out[initial[n(104)] & n(0x3F)];
    tables_out[n(8)] = byte(n(0xFC));
    state[n(175)] = byte(initial[n(175)] - initial[n(52)]);
    let bias_1_lookup = tables_out[n(64) + (initial[n(44)] & n(0x3F))];
    state[n(100)] = byte(initial[n(100)] - n(3));
    tables_out[n(67)] = byte(tables_out[initial[n(17)] & n(0x3F)] + tables[n(67)]);
    state[n(101)] = byte(
        initial[n(101)]
            - (byte(
                (((tables[n(96)] ^ n(0x73)) & n(0x8C))
                    | ((file_key_fixed_table[initial[n(57)] & n(0x3F)] ^ n(0x73)) & n(0x73)))
                    ^ n(0x30),
            ) / n(3)),
    );
    let state_249_lookup = file_key_fixed_table[initial[n(217)] & n(0x3F)];
    state[n(249)] = byte(
        initial[n(249)]
            - ((word(initial[n(7)]) >> n(1))
                | ((state_249_lookup & n(0x36)) ^ n(6))
                | (tables[n(79)] & ((state_249_lookup ^ n(0x73)) | n(0x36)))),
    );
    state[n(30)] = byte(initial[n(30)] ^ n(0x58));
    state[n(215)] = cube_byte(byte(
        (tables_out[initial[n(241)] & n(0x3F)] & n(0xC8)) | (tables[n(64)] & n(0x37)),
    ));
    let cubed_bits = cube_byte(byte(
        (initial[n(21)] & initial[n(109)]) | ((initial[n(21)] | initial[n(109)]) & n(0x73)),
    ));
    tables_out[n(127)] = byte(tables_out[(n(0) - cubed_bits) & n(0x3F)]);
    let table_62_lookup = tables_out[initial[n(13)] & n(0x3F)];
    tables_out[n(62)] = byte(xor_shifts(
        table_62_lookup & n(0x2C),
        byte(cube_byte(initial[n(146)])) & n(7),
        (n(0) - byte(cube_byte(initial[n(146)]))) & n(7),
    ));
    let table_11_shift = tables_out[n(64) + (initial[n(220)] & n(0x3F))];
    let majority_bits = byte(
        (tables[n(74)] & initial[n(131)]) | (tables[n(81)] & (tables[n(74)] | initial[n(131)])),
    );
    tables_out[n(11)] = byte(
        tables[n(11)]
            + xor_shifts(
                majority_bits,
                (n(0) - table_11_shift) & n(7),
                table_11_shift & n(7),
            ),
    );
    let state_67_shift = tables_out[n(64) + (initial[n(27)] & n(0x3F))];
    state[n(67)] = byte(
        initial[n(67)]
            - xor_shifts(
                word(initial[n(10)]) >> n(1),
                (n(0) - (word(state_67_shift) * state_67_shift)) & n(7),
                byte(word(state_67_shift) * state_67_shift) & n(7),
            ),
    );
    state[n(195)] = byte(
        initial[n(195)] + ((file_key_fixed_table[initial[n(136)] & n(0x3F)] & n(0xAC)) ^ n(0x16)),
    );
    let bias_4_lookup = tables_out[initial[n(182)] & n(0x3F)];
    let table_104_left = tables_out[initial[n(196)] & n(0x3F)];
    let table_104_right = tables_out[n(64) + (initial[n(21)] & n(0x3F))];
    tables_out[n(104)] = byte(
        tables[n(104)] + tables_out[n(64) + (initial[n(127)] & n(0x3F))]
            - ((table_104_right & table_104_left)
                | (((table_104_right ^ n(0x32)) | (table_104_left ^ n(0x32))) & n(0x49))),
    );
    tables_out[n(50)] = byte(
        ((((initial[n(140)] + n(0x40))
            & ((tables_out[n(64) + (initial[n(65)] & n(0x3F))] & n(2)) ^ n(0x24)))
            ^ n(0x22))
            + n(0x51))
            ^ n(0x73),
    );
    state[n(151)] = byte(n(0));
    tables_out[n(2)] = byte(byte((initial[n(134)] & n(0x89)) | n(0x74)) / n(5));
    tables_out[n(11)] = byte(
        tables_out[n(11)]
            + ((((tables_out[initial[n(39)] & n(0x3F)] ^ n(0x40)) + n(0x32)) & n(0x32))
                | (byte((word(tables[n(20)]) * n(0xAB)) >> n(9)) & n(0x4D))),
    );
    state[n(237)] =
        byte(initial[n(237)] + (file_key_fixed_table[initial[n(201)] & n(0x3F)] ^ n(0xB8)));
    let table_16_lookup = tables_out[(bias_4_lookup + n(0x4D)) & n(0x3F)];
    let bias_0_lookup = tables_out[n(64) + (initial[n(120)] & n(0x3F))];
    tables_out[n(16)] = byte(
        tables[n(16)]
            + (((initial[n(208)] + n(0x2B)) & (tables_out[n(8)] ^ n(0xFF)))
                | (tables_out[n(8)] & (word(table_16_lookup) >> n(1)))),
    );
    let table_75_lookup = tables_out[n(64) + (initial[n(162)] & n(0x3F))];
    tables_out[n(75)] = byte(
        tables[n(75)]
            ^ (word(byte(
                (table_75_lookup & n(0x7E))
                    | ((tables[n(4)] ^ n(1)) & ((table_75_lookup ^ n(0x73)) | n(0x7E))),
            )) >> n(1)),
    );
    tables_out[n(37)] =
        byte((tables_out[initial[n(65)] & n(0x3F)] + n(0x31)) ^ tables[n(37)] ^ n(0x12));
    tables_out[n(117)] = byte(n(0) - initial[n(103)] + tables[n(117)]);
    state[n(227)] =
        byte(initial[n(227)] + (n(0xFE) * tables_out[n(64) + (initial[n(173)] & n(0x3F))]));
    let scaled_lookup = byte(
        (((file_key_fixed_table[initial[n(56)] & n(0x3F)] ^ n(0xA1)) * n(0xAB)) & n(0xFE00))
            >> n(9),
    );
    tables_out[n(64)] = byte(tables_out[n(64) + (scaled_lookup & n(0x3F))] ^ tables[n(64)]);
    tables_out[n(31)] = byte(tables[n(31)] + (n(0) - (word(initial[n(26)]) * initial[n(26)])));
    let table_39_lookup = tables_out[initial[n(136)] & n(0x3F)];
    let table_39_bits = byte(
        (table_39_lookup & tables[n(66)]) | (tables[n(59)] & (table_39_lookup | tables[n(66)])),
    );
    tables_out[n(39)] = byte(
        ((word(tables[n(55)]) >> n(1)) & table_39_bits)
            | (((word(byte(tables[n(55)] ^ n(0x73))) >> n(1)) & n(0x3D)) ^ n(0x39))
            | (table_39_bits & n(0xBD)),
    );
    let shifted_bits =
        byte((initial[n(92)] & (tables[n(103)] ^ n(0xFF))) | (tables[n(103)] & n(0x8A)));
    tables_out[n(76)] = byte(
        tables[n(76)]
            - xor_shifts(
                shifted_bits,
                (initial[n(155)] / n(5)) & n(7),
                (n(0) - (initial[n(155)] / n(5))) & n(7),
            ),
    );
    tables_out[n(26)] = byte(tables[n(26)] ^ n(0xFD));
    tables_out[n(24)] = byte(tables[n(24)] + (n(0xD3) * tables[n(47)] * tables[n(47)]));
    let bias_11_lookup = tables_out[initial[n(116)] & n(0x3F)];
    state[n(96)] = byte((n(0xFE) * tables_out[n(64) + (initial[n(85)] & n(0x3F))]) - n(1));
    let state_39_bits = byte((word(initial[n(39)]) >> n(1)) & n(0x33));
    tables_out[n(54)] = byte(
        tables[n(54)]
            ^ (tables_out[(state_39_bits + n(0x26)) & n(0x3F)]
                & (file_key_fixed_table[initial[n(33)] & n(0x3F)] ^ n(0x47))),
    );
    let table_52_left = tables_out[n(64) + (initial[n(239)] & n(0x3F))];
    let bias_9_lookup = tables_out[n(64) + (initial[n(105)] & n(0x3F))];
    let table_122_bits = byte(
        (tables[n(20)] & (tables[n(35)] ^ n(0x7F))) | ((initial[n(221)] + n(0x80)) & tables[n(35)]),
    );
    tables_out[n(122)] = byte(
        (((initial[n(142)] & n(0x80)) | (table_122_bits & n(0x7F)))
            - ((word(table_122_bits) * n(2)) & n(0xE6))
            + n(0x73))
            ^ n(0x73),
    );
    state[n(44)] =
        byte(initial[n(44)] ^ ((tables_out[initial[n(171)] & n(0x3F)] / n(5)) + initial[n(24)]));
    tables_out[n(104)] = byte(
        (((word(initial[n(137)]) >> n(1)) & n(0x5F)) | ((tables[n(10)] ^ n(0x73)) & n(0x20)))
            ^ tables_out[n(104)]
            ^ n(0x20),
    );
    tables_out[n(25)] =
        byte(tables[n(25)] ^ (word(byte((state[n(67)] & n(0x4F)) ^ n(0x20))) * n(3)));
    tables_out[n(51)] = byte(n(0xB5));
    tables_out[n(100)] = byte(tables[n(100)] ^ n(0xBD));
    state[n(188)] = byte(
        ((((tables_out[initial[n(37)] & n(0x3F)] ^ n(0x73)) & n(0x5E))
            | ((tables[n(81)] ^ n(0x73)) & n(0xA1)))
            ^ n(0x7D))
            + initial[n(188)],
    );
    let table_38_lookup = file_key_fixed_table[initial[n(193)] & n(0x3F)];
    tables_out[n(38)] = byte(
        tables[n(38)]
            - (((table_38_lookup ^ n(0x47)) & initial[n(61)])
                | (tables[n(84)] & ((table_38_lookup ^ n(0x47)) | initial[n(61)]))),
    );
    let table_52_right = tables_out[initial[n(159)] & n(0x3F)];
    tables_out[n(52)] = byte(
        (((((table_52_left | initial[n(148)]) & n(6)) ^ n(6)) & (table_52_right ^ n(0x71)))
            | ((table_52_left | initial[n(148)]) & n(2))
            | ((table_52_right ^ n(0x73)) & n(0x11)))
            ^ tables[n(52)]
            ^ n(0x31),
    );
    let state_39_bias = byte(state_39_bits + n(0x66));
    let table_28_bits = byte(
        (tables[n(97)] & initial[n(116)]) | (tables[n(30)] & (tables[n(97)] | initial[n(116)])),
    );
    let shifted_bias = byte(word(state_39_bias) >> n(1));
    tables_out[n(28)] =
        byte((shifted_bias & table_28_bits) | (tables_out[n(2)] & (table_28_bits | shifted_bias)));
    let table_35_lookup = tables_out[n(64) + (initial[n(41)] & n(0x3F))];
    let bias_12_lookup = tables_out[n(64) + (state[n(188)] & n(0x3F))];
    let table_35_bits = byte(
        (table_35_lookup & initial[n(247)]) | (tables[n(96)] & (table_35_lookup | initial[n(247)])),
    );
    let shifted_table = byte(xor_shifts(
        tables[n(111)],
        initial[n(4)] & n(7),
        (n(0) - initial[n(4)]) & n(7),
    ));
    tables_out[n(35)] = byte(
        tables[n(35)]
            + ((table_35_bits & shifted_table)
                | (tables_out[n(62)] & shifted_table)
                | (table_35_bits & tables_out[n(62)])),
    );
    let square_input =
        byte((tables[n(53)] & (tables[n(123)] ^ n(0xFF))) | (tables[n(123)] & n(0x23)));
    tables_out[n(20)] = byte(word(square_input) * square_input);
    tables_out[n(42)] = byte(tables[n(42)] + tables[n(3)] - ((tables[n(125)] & n(0x25)) ^ n(0xA)));

    let bias_bits =
        byte((bias_0_lookup & tables[n(81)]) | (tables[n(73)] & (bias_0_lookup | tables[n(81)])));
    let shifted_constant = xor_shifts(n(0x37), tables[n(3)] & n(7), (n(0) - tables[n(3)]) & n(7));
    let input = reduction_input(Buf::new([
        byte(
            (bias_bits & tables[n(117)])
                | (((bias_bits ^ n(0x30)) | (tables[n(117)] ^ n(0x30))) & n(0x4F)),
        ),
        byte(bias_1_lookup / n(5)),
        byte(((initial[n(125)] & n(0xC9)) | n(2)) ^ ((bias_2_lookup ^ n(0xFF)) - n(2))),
        byte(cubed_bits + n(0x80)),
        byte(bias_4_lookup + n(0x1A)),
        byte(scaled_lookup + n(0x6F)),
        byte(
            (((tables[n(68)] & n(0x9F)) ^ n(0x3E)) & (word(bias_6_lookup) * bias_6_lookup))
                ^ n(0x4B),
        ),
        byte((shifted_constant & n(0x2D)) | ((shifted_constant | n(0x2D)) & tables[n(82)])),
        state_39_bias,
        byte(
            ((bias_9_lookup ^ n(0x73)) & n(0x20))
                | (((table_52_left | initial[n(148)]) ^ n(0x14)) & n(0xC6)),
        ),
        byte(file_key_fixed_table[initial[n(239)] & n(0x3F)] ^ n(0x73)),
        byte(word(byte((initial[n(69)] & n(0x55)) ^ n(0x22))) * (bias_11_lookup ^ n(0xFF))),
        byte(bias_12_lookup ^ n(0x73)),
    ]));
    (state.bytes(), tables_out.bytes(), input.bytes())
}
