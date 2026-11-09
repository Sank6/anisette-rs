use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::Deserialize;
use zeroize::Zeroizing;

use crate::{Error, Result};

const MAX_PROFILE_BYTES: usize = 256 * 1024 * 1024;
const MAX_NODES: usize = 8_000_000;
const MAX_TABLE_BYTES: usize = 16 * 1024 * 1024;
const MAX_ARRAY_STORAGE: usize = 64 * 1024 * 1024;

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Op {
    Constant,
    Input,
    Lookup,
    Add,
    Sub,
    Mul,
    Xor,
    And,
    Or,
    Neg,
    Not,
    Resize,
    SignExtend,
    Extract,
    Concat,
    ShiftLeft,
    ShiftRight,
    ArithmeticRight,
    RotateLeft,
    RotateRight,
    Equal,
    UnsignedLess,
    UnsignedLessEqual,
    SignedLess,
    SignedLessEqual,
    Select,
    ArrayNew,
    ArrayStore,
    ArrayLoad,
    UnsignedDivide,
    UnsignedRemainder,
    MultiplyHighSigned,
    MultiplyHighUnsigned,
    BitScanReverse,
}

impl Op {
    fn from_code(code: u8) -> Option<Self> {
        const OPERATIONS: &[Op] = &[
            Op::Constant,
            Op::Input,
            Op::Lookup,
            Op::Add,
            Op::Sub,
            Op::Mul,
            Op::Xor,
            Op::And,
            Op::Or,
            Op::Neg,
            Op::Not,
            Op::Resize,
            Op::SignExtend,
            Op::Extract,
            Op::Concat,
            Op::ShiftLeft,
            Op::ShiftRight,
            Op::ArithmeticRight,
            Op::RotateLeft,
            Op::RotateRight,
            Op::Equal,
            Op::UnsignedLess,
            Op::UnsignedLessEqual,
            Op::SignedLess,
            Op::SignedLessEqual,
            Op::Select,
            Op::ArrayNew,
            Op::ArrayStore,
            Op::ArrayLoad,
            Op::UnsignedDivide,
            Op::UnsignedRemainder,
            Op::MultiplyHighSigned,
            Op::MultiplyHighUnsigned,
            Op::BitScanReverse,
        ];
        OPERATIONS.get(usize::from(code)).copied()
    }

    fn is_array(self) -> bool {
        matches!(self, Self::ArrayNew | Self::ArrayStore)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Node {
    bits: u8,
    op: Op,
    args: Vec<usize>,
    value: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EncodedTable {
    width: u8,
    data_b64: Option<String>,
    byte_nodes: Option<Vec<usize>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Profile {
    input_bytes: usize,
    nodes: Vec<(u8, u8, Vec<usize>, u64)>,
    outputs: Vec<usize>,
    tables: Vec<EncodedTable>,
    guards: Vec<usize>,
}

struct Table {
    width: usize,
    bytes: Option<Zeroizing<Vec<u8>>>,
    byte_nodes: Option<Vec<usize>>,
}

pub struct Circuit {
    input_bytes: usize,
    nodes: Vec<Node>,
    outputs: Vec<usize>,
    tables: Vec<Table>,
    guards: Vec<usize>,
    array_uses: Vec<u32>,
}

fn invalid() -> Error {
    Error::Circuit
}
fn mask(bits: u8) -> u64 {
    u64::MAX >> (64 - bits)
}

impl Circuit {
    pub fn guard_input_dependencies(&self, guard: usize) -> Result<Vec<usize>> {
        let root = *self.guards.get(guard).ok_or_else(invalid)?;
        let mut seen = vec![false; self.nodes.len()];
        let mut inputs = vec![false; self.input_bytes];
        let mut pending = vec![root];
        while let Some(index) = pending.pop() {
            if seen[index] {
                continue;
            }
            seen[index] = true;
            let node = &self.nodes[index];
            if matches!(node.op, Op::Input) {
                inputs[node.value as usize] = true;
            }
            pending.extend(node.args.iter().copied());
            if matches!(node.op, Op::Lookup)
                && let Some(nodes) = &self.tables[node.value as usize].byte_nodes
            {
                pending.extend(nodes.iter().copied());
            }
        }
        Ok(inputs
            .into_iter()
            .enumerate()
            .filter_map(|(i, used)| used.then_some(i))
            .collect())
    }
    pub fn guards_depend_on_inputs(&self, selected: &[bool]) -> Result<Vec<bool>> {
        if selected.len() != self.input_bytes {
            return Err(invalid());
        }
        let mut dependencies = vec![false; self.nodes.len()];
        for (index, node) in self.nodes.iter().enumerate() {
            dependencies[index] = if matches!(node.op, Op::Input) {
                selected[node.value as usize]
            } else {
                node.args.iter().any(|&arg| dependencies[arg])
                    || matches!(node.op, Op::Lookup)
                        && self.tables[node.value as usize]
                            .byte_nodes
                            .as_ref()
                            .is_some_and(|nodes| nodes.iter().any(|&id| dependencies[id]))
            };
        }
        Ok(self.guards.iter().map(|&id| dependencies[id]).collect())
    }
    pub fn dimensions(&self) -> (usize, usize) {
        (self.input_bytes, self.outputs.len())
    }
    pub fn guard_repair_candidates(&self, guard: usize, input: &[u8]) -> Result<Vec<usize>> {
        let mut candidates = None;
        let result = self.evaluate_with_failure(input, &mut |failed, values| {
            if failed == guard {
                candidates = Some(self.guard_inputs_on_path(guard, values));
            }
        });
        match result {
            Err(Error::CircuitPath(failed)) if failed == guard => candidates.ok_or_else(invalid)?,
            _ => Err(invalid()),
        }
    }

    fn guard_inputs_on_path(&self, guard: usize, values: &[u64]) -> Result<Vec<usize>> {
        let mut pending = vec![*self.guards.get(guard).ok_or_else(invalid)?];
        let mut seen = vec![false; self.nodes.len()];
        let mut inputs = vec![false; self.input_bytes];
        while let Some(index) = pending.pop() {
            if seen[index] {
                continue;
            }
            seen[index] = true;
            let node = &self.nodes[index];
            match node.op {
                Op::Input => inputs[node.value as usize] = true,
                Op::ArrayLoad => {
                    pending.push(node.args[1]);
                    let offset = values[node.args[1]];
                    let mut version = node.args[0];
                    loop {
                        let array = &self.nodes[version];
                        match array.op {
                            Op::ArrayNew => break,
                            Op::ArrayStore => {
                                if values[array.args[1]] == offset {
                                    pending.extend([array.args[1], array.args[2]]);
                                    break;
                                }
                                version = array.args[0];
                            }
                            _ => return Err(invalid()),
                        }
                    }
                }
                Op::Lookup => {
                    pending.extend(node.args.iter().copied());
                    let table = &self.tables[node.value as usize];
                    if let Some(bytes) = &table.byte_nodes {
                        let offset =
                            usize::try_from(values[node.args[0]]).map_err(|_| invalid())?;
                        pending.extend(
                            bytes
                                .get(offset..offset + table.width)
                                .ok_or_else(invalid)?
                                .iter()
                                .copied(),
                        );
                    }
                }
                Op::Select => {
                    pending.push(node.args[0]);
                    pending.push(node.args[if values[node.args[0]] != 0 { 1 } else { 2 }]);
                }
                _ => pending.extend(node.args.iter().copied()),
            }
        }
        Ok(inputs
            .into_iter()
            .enumerate()
            .filter_map(|(i, used)| used.then_some(i))
            .collect())
    }
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_PROFILE_BYTES {
            return Err(invalid());
        }
        let profile: Profile = serde_json::from_slice(bytes).map_err(|_| invalid())?;
        if !(1..=4096).contains(&profile.input_bytes)
            || profile.nodes.is_empty()
            || profile.nodes.len() > MAX_NODES
            || profile.outputs.is_empty()
            || profile.outputs.len() > 4096
            || profile.tables.len() > 4096
        {
            return Err(invalid());
        }
        let nodes = profile
            .nodes
            .into_iter()
            .map(|(bits, code, args, value)| {
                Ok(Node {
                    bits,
                    op: Op::from_code(code).ok_or_else(invalid)?,
                    args,
                    value,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let mut total = 0_usize;
        let mut tables = Vec::new();
        for table in profile.tables {
            if ![1, 2, 4, 8].contains(&table.width) {
                return Err(invalid());
            }
            if table.data_b64.is_some() == table.byte_nodes.is_some() {
                return Err(invalid());
            }
            let bytes = table
                .data_b64
                .map(|data| STANDARD.decode(data).map(Zeroizing::new))
                .transpose()
                .map_err(|_| invalid())?;
            let length = bytes.as_ref().map_or_else(
                || table.byte_nodes.as_ref().map_or(0, Vec::len),
                |data| data.len(),
            );
            total = total.checked_add(length).ok_or_else(invalid)?;
            if length == 0 || total > MAX_TABLE_BYTES {
                return Err(invalid());
            }
            tables.push(Table {
                width: usize::from(table.width),
                bytes,
                byte_nodes: table.byte_nodes,
            });
        }
        let mut circuit = Self {
            input_bytes: profile.input_bytes,
            nodes,
            outputs: profile.outputs,
            tables,
            guards: profile.guards,
            array_uses: Vec::new(),
        };
        circuit.validate()?;
        circuit.array_uses = vec![0; circuit.nodes.len()];
        for node in &circuit.nodes {
            if matches!(node.op, Op::ArrayStore | Op::ArrayLoad) {
                circuit.array_uses[node.args[0]] += 1;
            }
        }
        Ok(circuit)
    }

    fn validate(&self) -> Result<()> {
        for table in &self.tables {
            if table.byte_nodes.as_ref().is_some_and(|nodes| {
                nodes
                    .iter()
                    .any(|&i| self.nodes.get(i).is_none_or(|node| node.bits != 8))
            }) {
                return Err(invalid());
            }
        }
        for (index, node) in self.nodes.iter().enumerate() {
            if !(1..=64).contains(&node.bits) || node.args.iter().any(|&arg| arg >= index) {
                return Err(invalid());
            }
            let count = node.args.len();
            let arg_bits = |i: usize| self.nodes[node.args[i]].bits;
            if !matches!(node.op, Op::ArrayStore | Op::ArrayLoad)
                && node.args.iter().any(|&i| self.nodes[i].op.is_array())
            {
                return Err(invalid());
            }
            let valid = match node.op {
                Op::Constant => count == 0 && node.value & !mask(node.bits) == 0,
                Op::Input => count == 0 && node.bits == 8 && node.value < self.input_bytes as u64,
                Op::Lookup => {
                    count == 1
                        && arg_bits(0) == 64
                        && node.value < (self.tables.len() as u64)
                        && self.tables.get(node.value as usize).is_some_and(|table| {
                            table.width * 8 == usize::from(node.bits)
                                && table
                                    .byte_nodes
                                    .as_ref()
                                    .is_none_or(|nodes| nodes.iter().all(|&i| i < index))
                        })
                }
                Op::Add | Op::Mul | Op::Xor | Op::And | Op::Or => {
                    count >= 1 && node.args.iter().all(|&i| self.nodes[i].bits == node.bits)
                }
                Op::Sub | Op::ShiftLeft | Op::ShiftRight | Op::ArithmeticRight => {
                    count == 2 && arg_bits(0) == node.bits && arg_bits(1) == node.bits
                }
                Op::UnsignedDivide | Op::UnsignedRemainder => {
                    count == 2 && arg_bits(0) == node.bits && arg_bits(1) == node.bits
                }
                Op::MultiplyHighSigned | Op::MultiplyHighUnsigned => {
                    count == 2 && node.bits == 64 && arg_bits(0) == 64 && arg_bits(1) == 64
                }
                Op::BitScanReverse => count == 1 && arg_bits(0) == node.bits,
                Op::Neg | Op::Not => count == 1 && arg_bits(0) == node.bits,
                Op::Resize => count == 1,
                Op::SignExtend => count == 1 && arg_bits(0) <= node.bits,
                Op::Extract => {
                    count == 1
                        && node.value < u64::from(arg_bits(0))
                        && node.value + u64::from(node.bits) <= u64::from(arg_bits(0))
                }
                Op::Concat => {
                    count >= 1
                        && node
                            .args
                            .iter()
                            .map(|&i| usize::from(self.nodes[i].bits))
                            .sum::<usize>()
                            == usize::from(node.bits)
                }
                Op::RotateLeft | Op::RotateRight => {
                    (count == 1 || count == 2)
                        && arg_bits(0) == node.bits
                        && (count == 1 || arg_bits(1) == node.bits)
                }
                Op::Equal
                | Op::UnsignedLess
                | Op::UnsignedLessEqual
                | Op::SignedLess
                | Op::SignedLessEqual => count == 2 && node.bits == 1 && arg_bits(0) == arg_bits(1),
                Op::Select => {
                    count == 3
                        && arg_bits(0) == 1
                        && arg_bits(1) == node.bits
                        && arg_bits(2) == node.bits
                }
                Op::ArrayNew => count == 0 && node.bits == 64 && (1..=65536).contains(&node.value),
                Op::ArrayStore => {
                    count == 3
                        && node.bits == 64
                        && self.nodes[node.args[0]].op.is_array()
                        && arg_bits(1) == 64
                        && !self.nodes[node.args[1]].op.is_array()
                        && arg_bits(2) == 8
                }
                Op::ArrayLoad => {
                    count == 2
                        && node.bits == 8
                        && self.nodes[node.args[0]].op.is_array()
                        && arg_bits(1) == 64
                        && !self.nodes[node.args[1]].op.is_array()
                }
            };
            if !valid {
                return Err(invalid());
            }
        }
        if self
            .outputs
            .iter()
            .any(|&i| self.nodes.get(i).is_none_or(|node| node.bits != 8))
        {
            return Err(invalid());
        }
        if self.guards.len() > MAX_NODES
            || self
                .guards
                .iter()
                .any(|&i| self.nodes.get(i).is_none_or(|node| node.bits != 1))
        {
            return Err(invalid());
        }
        Ok(())
    }

    pub fn evaluate(&self, input: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        self.evaluate_with_failure(input, &mut |_, _| {})
    }

    fn evaluate_with_failure(
        &self,
        input: &[u8],
        failure: &mut impl FnMut(usize, &[u64]),
    ) -> Result<Zeroizing<Vec<u8>>> {
        if input.len() != self.input_bytes {
            return Err(invalid());
        }
        let mut values = Zeroizing::new(Vec::<u64>::with_capacity(self.nodes.len()));
        let mut arrays = Vec::<Option<Zeroizing<Vec<u8>>>>::new();
        let mut array_uses = self.array_uses.clone();
        let mut array_storage = 0_usize;
        let mut next_guard = 0_usize;
        for (index, node) in self.nodes.iter().enumerate() {
            let arg = |i: usize| values[node.args[i]];
            let result = match node.op {
                Op::Constant => node.value,
                Op::Input => u64::from(input[node.value as usize]),
                Op::ArrayNew => {
                    let length = usize::try_from(node.value).map_err(|_| invalid())?;
                    array_storage = array_storage.checked_add(length).ok_or_else(invalid)?;
                    if array_storage > MAX_ARRAY_STORAGE {
                        return Err(invalid());
                    }
                    let id = arrays.len();
                    arrays.push(Some(Zeroizing::new(vec![0; length])));
                    id as u64
                }
                Op::ArrayStore => {
                    let previous = usize::try_from(arg(0)).map_err(|_| invalid())?;
                    let offset = usize::try_from(arg(1)).map_err(|_| invalid())?;
                    let length = arrays
                        .get(previous)
                        .and_then(Option::as_ref)
                        .ok_or_else(invalid)?
                        .len();
                    if offset >= length {
                        return Err(invalid());
                    }
                    // Moving the final reference preserves immutable graph
                    // semantics without retaining superseded buffers.
                    let mut updated = if array_uses[node.args[0]] == 1 {
                        arrays[previous].take().ok_or_else(invalid)?
                    } else {
                        array_storage = array_storage.checked_add(length).ok_or_else(invalid)?;
                        if array_storage > MAX_ARRAY_STORAGE {
                            return Err(invalid());
                        }
                        Zeroizing::new(arrays[previous].as_ref().ok_or_else(invalid)?.to_vec())
                    };
                    updated[offset] = arg(2) as u8;
                    let id = arrays.len();
                    arrays.push(Some(updated));
                    id as u64
                }
                Op::ArrayLoad => {
                    let previous = usize::try_from(arg(0)).map_err(|_| invalid())?;
                    let offset = usize::try_from(arg(1)).map_err(|_| invalid())?;
                    u64::from(
                        *arrays
                            .get(previous)
                            .and_then(Option::as_ref)
                            .and_then(|data| data.get(offset))
                            .ok_or_else(invalid)?,
                    )
                }
                Op::Lookup => {
                    let table = &self.tables[node.value as usize];
                    let offset = usize::try_from(arg(0)).map_err(|_| invalid())?;
                    let end = offset.checked_add(table.width).ok_or_else(invalid)?;
                    let mut word = [0_u8; 8];
                    if let Some(bytes) = &table.bytes {
                        word[..table.width]
                            .copy_from_slice(bytes.get(offset..end).ok_or_else(invalid)?);
                    } else if let Some(nodes) = &table.byte_nodes {
                        for (out, &id) in word
                            .iter_mut()
                            .zip(nodes.get(offset..end).ok_or_else(invalid)?)
                        {
                            *out = values[id] as u8;
                        }
                    } else {
                        return Err(invalid());
                    }
                    u64::from_le_bytes(word)
                }
                Op::Add => node
                    .args
                    .iter()
                    .fold(0_u64, |a, &i| a.wrapping_add(values[i])),
                Op::Mul => node
                    .args
                    .iter()
                    .fold(1_u64, |a, &i| a.wrapping_mul(values[i])),
                Op::Xor => node.args.iter().fold(0_u64, |a, &i| a ^ values[i]),
                Op::And => node.args.iter().fold(u64::MAX, |a, &i| a & values[i]),
                Op::Or => node.args.iter().fold(0_u64, |a, &i| a | values[i]),
                Op::Sub => arg(0).wrapping_sub(arg(1)),
                Op::UnsignedDivide => arg(0).checked_div(arg(1)).ok_or_else(invalid)?,
                Op::UnsignedRemainder => arg(0).checked_rem(arg(1)).ok_or_else(invalid)?,
                Op::MultiplyHighSigned => {
                    (((arg(0) as i64 as i128) * (arg(1) as i64 as i128)) >> 64) as u64
                }
                Op::MultiplyHighUnsigned => (((arg(0) as u128) * (arg(1) as u128)) >> 64) as u64,
                Op::BitScanReverse => {
                    if arg(0) == 0 {
                        0
                    } else {
                        u64::from(63 - arg(0).leading_zeros())
                    }
                }
                Op::Equal => u64::from(arg(0) == arg(1)),
                Op::UnsignedLess => u64::from(arg(0) < arg(1)),
                Op::UnsignedLessEqual => u64::from(arg(0) <= arg(1)),
                Op::SignedLess | Op::SignedLessEqual => {
                    let shift = 64 - self.nodes[node.args[0]].bits;
                    let a = ((arg(0) << shift) as i64) >> shift;
                    let b = ((arg(1) << shift) as i64) >> shift;
                    u64::from(if matches!(node.op, Op::SignedLess) {
                        a < b
                    } else {
                        a <= b
                    })
                }
                Op::Select => {
                    if arg(0) != 0 {
                        arg(1)
                    } else {
                        arg(2)
                    }
                }
                Op::Neg => arg(0).wrapping_neg(),
                Op::Not => !arg(0),
                Op::Resize => arg(0),
                Op::SignExtend => {
                    let shift = 64 - self.nodes[node.args[0]].bits;
                    (((arg(0) << shift) as i64) >> shift) as u64
                }
                Op::Extract => arg(0) >> node.value,
                Op::Concat => node.args.iter().fold(0_u64, |value, &i| {
                    if self.nodes[i].bits == 64 {
                        values[i]
                    } else {
                        (value << self.nodes[i].bits) | values[i]
                    }
                }),
                Op::ShiftLeft => {
                    if arg(1) >= u64::from(node.bits) {
                        0
                    } else {
                        arg(0) << arg(1)
                    }
                }
                Op::ShiftRight => {
                    if arg(1) >= u64::from(node.bits) {
                        0
                    } else {
                        arg(0) >> arg(1)
                    }
                }
                Op::ArithmeticRight => {
                    let extend = 64 - node.bits;
                    let signed = ((arg(0) << extend) as i64) >> extend;
                    (signed >> arg(1).min(63)) as u64
                }
                Op::RotateLeft | Op::RotateRight => {
                    let count = (if node.args.len() == 2 {
                        arg(1)
                    } else {
                        node.value
                    }) % u64::from(node.bits);
                    if count == 0 {
                        arg(0)
                    } else if matches!(node.op, Op::RotateLeft) {
                        (arg(0) << count) | (arg(0) >> (u64::from(node.bits) - count))
                    } else {
                        (arg(0) >> count) | (arg(0) << (u64::from(node.bits) - count))
                    }
                }
            };
            values.push(result & mask(node.bits));
            while self.guards.get(next_guard).is_some_and(|&id| id <= index) {
                if values[self.guards[next_guard]] != 1 {
                    failure(next_guard, &values);
                    return Err(Error::CircuitPath(next_guard));
                }
                next_guard += 1;
            }
            if matches!(node.op, Op::ArrayStore | Op::ArrayLoad) {
                let previous = node.args[0];
                array_uses[previous] -= 1;
                if array_uses[previous] == 0 {
                    let id = usize::try_from(values[previous]).map_err(|_| invalid())?;
                    if let Some(data) = arrays.get_mut(id).ok_or_else(invalid)?.take() {
                        array_storage -= data.len();
                    }
                }
            }
            if node.op.is_array() && array_uses[index] == 0 {
                let id = usize::try_from(values[index]).map_err(|_| invalid())?;
                if let Some(data) = arrays.get_mut(id).ok_or_else(invalid)?.take() {
                    array_storage -= data.len();
                }
            }
        }
        Ok(Zeroizing::new(
            self.outputs.iter().map(|&i| values[i] as u8).collect(),
        ))
    }
}
