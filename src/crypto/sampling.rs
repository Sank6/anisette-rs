//! Entropy selection for guarded arithmetic profiles.
//!
//! Only selected random bytes may change, and every candidate is checked by a
//! full circuit evaluation.

use super::circuit::Circuit;
use crate::{Error, Result};
use std::{collections::BTreeMap, io::Read};
use zeroize::Zeroizing;

pub const MAX_EVALUATIONS: usize = 4096;

fn shuffle(values: &mut [usize], random: &mut impl Read) -> Result<()> {
    for end in (1..values.len()).rev() {
        let width = (end + 1) as u64;
        let limit = (1_u64 << 32) / width * width;
        let choice = loop {
            let mut bytes = [0; 4];
            random.read_exact(&mut bytes)?;
            let value = u64::from(u32::from_le_bytes(bytes));
            if value < limit {
                break (value % width) as usize;
            }
        };
        values.swap(end, choice);
    }
    Ok(())
}

fn fill(input: &mut [u8], selected: &[bool], random: &mut impl Read) -> Result<()> {
    for (i, used) in selected.iter().enumerate() {
        if *used {
            random.read_exact(&mut input[i..i + 1])?;
        }
    }
    Ok(())
}

pub fn sample(
    program: &Circuit,
    input: &mut [u8],
    selected: &[bool],
    random: &mut impl Read,
) -> Result<Zeroizing<Vec<u8>>> {
    if selected.len() != input.len() || input.len() != program.dimensions().0 {
        return Err(Error::Circuit);
    }
    let movable_guards = program.guards_depend_on_inputs(selected)?;
    let mut dependencies = BTreeMap::<usize, (Vec<usize>, Vec<usize>)>::new();
    fill(input, selected, random)?;
    let mut evaluations = 1;
    let mut result = program.evaluate(input);
    'search: loop {
        let guard = match result {
            Ok(output) => return Ok(output),
            Err(Error::CircuitPath(guard)) => {
                if !movable_guards.get(guard).copied().unwrap_or(false) {
                    return Err(Error::CircuitPath(guard));
                }
                Some(guard)
            }
            Err(Error::Circuit) => None,
            Err(error) => return Err(error),
        };
        if evaluations >= MAX_EVALUATIONS {
            return Err(guard.map_or(Error::Circuit, Error::CircuitPath));
        }
        if let Some(guard) = guard {
            if let std::collections::btree_map::Entry::Vacant(entry) = dependencies.entry(guard) {
                let all = program
                    .guard_input_dependencies(guard)?
                    .into_iter()
                    .filter(|&i| selected[i])
                    .collect::<Vec<_>>();
                let preferred = if all.len() > 2 {
                    program
                        .guard_repair_candidates(guard, input)?
                        .into_iter()
                        .filter(|&i| selected[i])
                        .collect()
                } else {
                    all.clone()
                };
                let rest = all.into_iter().filter(|i| !preferred.contains(i)).collect();
                entry.insert((preferred, rest));
            }
            let (mut indices, mut rest) = dependencies[&guard].clone();
            shuffle(&mut indices, random)?;
            shuffle(&mut rest, random)?;
            indices.extend(rest);
            for index in indices {
                let original = input[index];
                let mut alternatives = (0..=255).collect::<Vec<usize>>();
                shuffle(&mut alternatives, random)?;
                for value in alternatives {
                    if value as u8 == original {
                        continue;
                    }
                    if evaluations >= MAX_EVALUATIONS {
                        input[index] = original;
                        return Err(Error::CircuitPath(guard));
                    }
                    input[index] = value as u8;
                    evaluations += 1;
                    match program.evaluate(input) {
                        Ok(output) => return Ok(output),
                        Err(Error::CircuitPath(next)) if next > guard => {
                            result = Err(Error::CircuitPath(next));
                            continue 'search;
                        }
                        Err(Error::CircuitPath(_) | Error::Circuit) => {}
                        Err(error) => {
                            input[index] = original;
                            return Err(error);
                        }
                    }
                }
                input[index] = original;
            }
        }
        // Coupled constraints can require several bytes to change together.
        // Start another fresh vector rather than weakening a checked predicate.
        if evaluations >= MAX_EVALUATIONS {
            return Err(guard.map_or(Error::Circuit, Error::CircuitPath));
        }
        fill(input, selected, random)?;
        dependencies.clear();
        evaluations += 1;
        result = program.evaluate(input);
    }
}
