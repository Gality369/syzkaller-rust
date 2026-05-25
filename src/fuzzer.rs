use crate::program::*;
use rand::Rng;
use std::collections::{HashMap, HashSet};

const MAX_CALLS: usize = 10;
const MIN_CALLS: usize = 1;

/// Generate a random program from scratch.
pub fn generate(descs: &[SyscallDesc], rng: &mut impl Rng) -> Program {
    let choice_table = SyscallChoiceTable::build(descs, &[]);
    generate_with_choice_table(descs, &choice_table, rng)
}

/// Generate a random program from scratch, optionally biased by corpus history.
pub fn generate_with_corpus(
    descs: &[SyscallDesc],
    corpus: &[Program],
    rng: &mut impl Rng,
) -> Program {
    let choice_table = SyscallChoiceTable::build(descs, corpus);
    generate_with_choice_table(descs, &choice_table, rng)
}

pub fn generate_with_choice_table(
    descs: &[SyscallDesc],
    choice_table: &SyscallChoiceTable,
    rng: &mut impl Rng,
) -> Program {
    generate_with_choice_table_and_edge_bias(descs, choice_table, &HashMap::new(), rng)
}

pub fn generate_with_choice_table_and_edge_bias(
    descs: &[SyscallDesc],
    choice_table: &SyscallChoiceTable,
    timeout_edge_failures: &HashMap<String, u32>,
    rng: &mut impl Rng,
) -> Program {
    let num_calls = rng.gen_range(MIN_CALLS..=MAX_CALLS);
    let mut calls = Vec::new();
    let mut available_resources: HashMap<String, Vec<ResultRef>> = HashMap::new();

    for _ in 0..num_calls {
        let previous_syscall_idx = calls.last().map(|call: &Call| call.syscall_idx);
        let syscall_idx = choose_syscall_for_generation(
            descs,
            choice_table,
            previous_syscall_idx,
            &available_resources,
            timeout_edge_failures,
            rng,
        );

        let desc = &descs[syscall_idx];
        let args = generate_args(desc, &available_resources, rng);

        let call_idx = calls.len();
        for (result_idx, output) in resource_outputs(desc).into_iter().enumerate() {
            register_available_resource(
                &mut available_resources,
                &output.resource,
                ResultRef {
                    call_idx,
                    result_idx,
                },
            );
        }

        calls.push(Call { syscall_idx, args });
    }

    let prog = Program { calls };
    debug_assert!(validate_program(&prog, descs).is_ok());
    prog
}

fn choose_syscall_for_generation(
    descs: &[SyscallDesc],
    choice_table: &SyscallChoiceTable,
    previous_syscall_idx: Option<usize>,
    available_resources: &HashMap<String, Vec<ResultRef>>,
    timeout_edge_failures: &HashMap<String, u32>,
    rng: &mut impl Rng,
) -> usize {
    let enabled_syscalls = choice_table.enabled_syscalls();
    let preferred_enabled = prefer_low_penalty_candidates(
        descs,
        previous_syscall_idx,
        enabled_syscalls,
        timeout_edge_failures,
    );
    let ready_consumers =
        resource_consumers_for_available_inputs(descs, enabled_syscalls, available_resources);
    if !ready_consumers.is_empty() && rng.gen_bool(0.6) {
        let preferred_ready = prefer_low_penalty_candidates(
            descs,
            previous_syscall_idx,
            &ready_consumers,
            timeout_edge_failures,
        );
        return choice_table.choose_subset(&preferred_ready, previous_syscall_idx, rng);
    }

    let candidate = choice_table.choose_subset(&preferred_enabled, previous_syscall_idx, rng);
    let fallback_producers = resource_producers_for_missing_inputs(
        descs,
        enabled_syscalls,
        &descs[candidate],
        available_resources,
    );
    if !fallback_producers.is_empty() && rng.gen_bool(0.7) {
        let preferred_fallback = prefer_low_penalty_candidates(
            descs,
            previous_syscall_idx,
            &fallback_producers,
            timeout_edge_failures,
        );
        choice_table.choose_subset(&preferred_fallback, previous_syscall_idx, rng)
    } else {
        candidate
    }
}

/// Generate arguments for a syscall.
fn generate_args(
    desc: &SyscallDesc,
    available_resources: &HashMap<String, Vec<ResultRef>>,
    rng: &mut impl Rng,
) -> Vec<ArgValue> {
    let mut args = Vec::with_capacity(desc.args.len());
    for arg_type in &desc.args {
        let arg_value = generate_arg(desc, &args, arg_type, available_resources, rng);
        args.push(arg_value);
    }
    args
}

/// Generate a single argument value.
fn generate_arg(
    desc: &SyscallDesc,
    generated_args: &[ArgValue],
    arg_type: &ArgType,
    available_resources: &HashMap<String, Vec<ResultRef>>,
    rng: &mut impl Rng,
) -> ArgValue {
    match arg_type {
        ArgType::Const {
            size,
            values,
            range,
            ..
        } => {
            if !values.is_empty() {
                // Pick from valid values, occasionally mutate
                if rng.gen_bool(0.9) {
                    ArgValue::Const(values[rng.gen_range(0..values.len())])
                } else {
                    ArgValue::Const(random_value_for_size(*size, rng))
                }
            } else if let Some((min, max)) = range {
                if min <= max {
                    ArgValue::Const(rng.gen_range(*min..=*max))
                } else {
                    ArgValue::Const(*min)
                }
            } else {
                ArgValue::Const(random_value_for_size(*size, rng))
            }
        }
        ArgType::Len { target, kind, .. } => {
            let value = derived_length_for_arg(desc, generated_args, *target, *kind).unwrap_or(0);
            ArgValue::Const(value as u64)
        }
        ArgType::Resource(resource) => {
            if let Some(available) = available_resources
                .get(&resource.kind)
                .filter(|values| !values.is_empty())
            {
                if rng.gen_bool(0.8) {
                    return ArgValue::ResultRef(
                        available[rng.gen_range(0..available.len())].clone(),
                    );
                }
            }
            if !resource.values.is_empty() {
                ArgValue::Const(resource.values[rng.gen_range(0..resource.values.len())])
            } else {
                ArgValue::Const(0)
            }
        }
        ArgType::Ptr {
            inner,
            dir,
            optional,
        } => {
            if *optional && rng.gen_bool(0.35) {
                return ArgValue::Null;
            }
            match dir {
                PtrDir::Out => ArgValue::OutPtr,
                PtrDir::In | PtrDir::InOut => {
                    generate_pointer_arg_value(desc, generated_args, inner, dir, rng)
                }
            }
        }
        ArgType::Array { .. } => ArgValue::Null,
        ArgType::Struct { size, .. } => {
            let bytes = generate_inline_bytes(arg_type, rng).unwrap_or_else(|| vec![0; *size]);
            ArgValue::Buffer(bytes)
        }
        ArgType::Buffer {
            min_size,
            max_size,
            dir,
        } => {
            let size = rng.gen_range(*min_size..=*max_size);
            let mut data = vec![0u8; size];
            if *dir != BufferDir::Out {
                rng.fill(&mut data[..]);
            }
            ArgValue::Buffer(data)
        }
        ArgType::Filename => ArgValue::Filename(random_filename(rng)),
    }
}

fn generate_pointer_arg_value(
    desc: &SyscallDesc,
    generated_args: &[ArgValue],
    inner: &ArgType,
    dir: &PtrDir,
    rng: &mut impl Rng,
) -> ArgValue {
    match inner {
        ArgType::Buffer {
            min_size,
            max_size,
            dir,
        } => {
            let size = rng.gen_range(*min_size..=*max_size);
            let mut data = vec![0u8; size];
            if *dir != BufferDir::Out {
                rng.fill(&mut data[..]);
            }
            ArgValue::Buffer(data)
        }
        ArgType::Len { target, size, kind } => {
            let value =
                derived_length_for_arg(desc, generated_args, *target, *kind).unwrap_or(0) as u64;
            ArgValue::Buffer(encode_scalar_bytes(*size, value))
        }
        ArgType::Struct { size, .. } => generate_inline_bytes(inner, rng)
            .map(ArgValue::Buffer)
            .unwrap_or_else(|| ArgValue::Buffer(vec![0; *size])),
        _ => {
            if let Some(size) = arg_type_fixed_size(inner) {
                let mut data = vec![0u8; size];
                if *dir != PtrDir::Out {
                    rng.fill(&mut data[..]);
                }
                ArgValue::Buffer(data)
            } else {
                ArgValue::OutPtr
            }
        }
    }
}

fn derived_length_for_arg(
    desc: &SyscallDesc,
    generated_args: &[ArgValue],
    target: usize,
    kind: LengthKind,
) -> Option<usize> {
    let target_type = desc.args.get(target)?;
    let target_value = generated_args.get(target)?;
    derived_arg_length(target_type, target_value, kind)
}

fn generate_inline_bytes(arg_type: &ArgType, rng: &mut impl Rng) -> Option<Vec<u8>> {
    match arg_type {
        ArgType::Const {
            size,
            values,
            range,
            endian,
        } => {
            let value = if !values.is_empty() {
                values[rng.gen_range(0..values.len())]
            } else if let Some((min, max)) = range {
                if min <= max {
                    rng.gen_range(*min..=*max)
                } else {
                    *min
                }
            } else {
                random_value_for_size(*size, rng)
            };
            Some(encode_scalar_bytes_endian(*size, value, *endian))
        }
        ArgType::Resource(resource) => {
            Some(encode_scalar_bytes(resource.size, resource.default_value()))
        }
        ArgType::Array { inner, len } => {
            let mut out = Vec::new();
            for _ in 0..*len {
                out.extend(generate_inline_bytes(inner, rng)?);
            }
            Some(out)
        }
        ArgType::Struct { fields, size } => {
            let mut out = Vec::new();
            for field in fields {
                out.extend(generate_inline_bytes(field, rng)?);
            }
            out.resize(*size, 0);
            Some(out)
        }
        ArgType::Buffer {
            min_size,
            max_size,
            dir,
        } if min_size == max_size => {
            let mut data = vec![0u8; *max_size];
            if *dir != BufferDir::Out {
                rng.fill(&mut data[..]);
            }
            Some(data)
        }
        ArgType::Len { size, .. } => Some(vec![0; *size]),
        _ => None,
    }
}

// ============================================================
// Mutation operations
// ============================================================

/// Mutate a program by applying a random mutation.
pub fn mutate(prog: &Program, descs: &[SyscallDesc], rng: &mut impl Rng) -> Program {
    let choice_table = SyscallChoiceTable::build(descs, &[]);
    mutate_with_choice_table(prog, descs, &choice_table, rng)
}

/// Mutate a program by applying a random mutation, optionally biased by corpus history.
pub fn mutate_with_corpus(
    prog: &Program,
    descs: &[SyscallDesc],
    corpus: &[Program],
    rng: &mut impl Rng,
) -> Program {
    let choice_table = SyscallChoiceTable::build(descs, corpus);
    mutate_with_choice_table(prog, descs, &choice_table, rng)
}

pub fn mutate_with_choice_table(
    prog: &Program,
    descs: &[SyscallDesc],
    choice_table: &SyscallChoiceTable,
    rng: &mut impl Rng,
) -> Program {
    mutate_with_choice_table_and_edge_bias(prog, descs, choice_table, &HashMap::new(), rng)
}

pub fn mutate_with_choice_table_and_edge_bias(
    prog: &Program,
    descs: &[SyscallDesc],
    choice_table: &SyscallChoiceTable,
    timeout_edge_failures: &HashMap<String, u32>,
    rng: &mut impl Rng,
) -> Program {
    let mut new_prog = prog.clone();
    let mutation_type = rng.gen_range(0..6);
    match mutation_type {
        0 => mutate_insert_call(
            &mut new_prog,
            descs,
            choice_table,
            timeout_edge_failures,
            rng,
        ),
        1 => mutate_remove_call(&mut new_prog, rng),
        2 => mutate_args(&mut new_prog, descs, rng),
        3 => mutate_integer(&mut new_prog, descs, rng),
        4 => mutate_buffer(&mut new_prog, descs, rng),
        5 => splice(
            &mut new_prog,
            descs,
            choice_table,
            timeout_edge_failures,
            rng,
        ),
        _ => {}
    }
    // Ensure program is not empty
    if new_prog.calls.is_empty() {
        new_prog = generate_with_choice_table_and_edge_bias(
            descs,
            choice_table,
            timeout_edge_failures,
            rng,
        );
    }
    // Ensure program is not too long
    if new_prog.calls.len() > MAX_CALLS {
        new_prog.calls.truncate(MAX_CALLS);
    }
    repair_result_refs(&mut new_prog, descs);
    debug_assert!(validate_program(&new_prog, descs).is_ok());
    new_prog
}

/// Insert a random call at a random position.
fn mutate_insert_call(
    prog: &mut Program,
    descs: &[SyscallDesc],
    choice_table: &SyscallChoiceTable,
    timeout_edge_failures: &HashMap<String, u32>,
    rng: &mut impl Rng,
) {
    if prog.calls.len() >= MAX_CALLS {
        return;
    }
    if choice_table.enabled_syscalls().is_empty() {
        return;
    }
    let pos = rng.gen_range(0..=prog.calls.len());
    shift_result_refs_for_insert(prog, pos);
    let available_resources = available_resources_before(&prog.calls, descs, pos);
    let previous_syscall_idx = pos
        .checked_sub(1)
        .and_then(|idx| prog.calls.get(idx))
        .map(|call| call.syscall_idx);
    let syscall_idx = choose_syscall_for_generation(
        descs,
        choice_table,
        previous_syscall_idx,
        &available_resources,
        timeout_edge_failures,
        rng,
    );
    let desc = &descs[syscall_idx];
    let args = generate_args(desc, &available_resources, rng);
    prog.calls.insert(pos, Call { syscall_idx, args });
}

/// Remove a random call.
fn mutate_remove_call(prog: &mut Program, rng: &mut impl Rng) {
    if prog.calls.len() <= 1 {
        return;
    }
    let pos = rng.gen_range(0..prog.calls.len());
    prog.calls.remove(pos);
    shift_result_refs_for_removal(prog, pos);
}

/// Replace arguments of a random call with fresh ones.
fn mutate_args(prog: &mut Program, descs: &[SyscallDesc], rng: &mut impl Rng) {
    if prog.calls.is_empty() {
        return;
    }
    let idx = rng.gen_range(0..prog.calls.len());
    let available_resources = available_resources_before(&prog.calls, descs, idx);

    let desc = &descs[prog.calls[idx].syscall_idx];
    prog.calls[idx].args = generate_args(desc, &available_resources, rng);
}

/// Mutate an integer argument.
fn mutate_integer(prog: &mut Program, descs: &[SyscallDesc], rng: &mut impl Rng) {
    if prog.calls.is_empty() {
        return;
    }
    let call_idx = rng.gen_range(0..prog.calls.len());
    let call = &mut prog.calls[call_idx];
    let desc = &descs[call.syscall_idx];
    if call.args.is_empty() {
        return;
    }
    let arg_idx = rng.gen_range(0..call.args.len());
    if matches!(desc.args.get(arg_idx), Some(ArgType::Len { .. })) {
        return;
    }
    if let ArgValue::Const(ref mut val) = call.args[arg_idx] {
        let op = rng.gen_range(0..5);
        match op {
            0 => *val = val.wrapping_add(rng.gen_range(1..=16)),
            1 => *val = val.wrapping_sub(rng.gen_range(1..=16)),
            2 => *val ^= 1u64 << rng.gen_range(0..64),
            3 => *val = rng.gen(),
            4 => {
                *val = [
                    0,
                    1,
                    0xFFFF_FFFF,
                    0xFFFF_FFFF_FFFF_FFFF,
                    0x80000000,
                    0x7FFFFFFF,
                ][rng.gen_range(0..6)]
            }
            _ => {}
        }
    }
}

/// Mutate buffer content.
fn mutate_buffer(prog: &mut Program, descs: &[SyscallDesc], rng: &mut impl Rng) {
    if prog.calls.is_empty() {
        return;
    }
    let call_idx = rng.gen_range(0..prog.calls.len());
    let call = &mut prog.calls[call_idx];
    let desc = &descs[call.syscall_idx];
    if call.args.is_empty() {
        return;
    }
    let arg_idx = rng.gen_range(0..call.args.len());
    if matches!(
        desc.args.get(arg_idx),
        Some(ArgType::Ptr {
            inner,
            ..
        }) if matches!(inner.as_ref(), ArgType::Len { .. })
    ) {
        return;
    }
    if let ArgValue::Buffer(ref mut data) = call.args[arg_idx] {
        if data.is_empty() {
            return;
        }
        let op = rng.gen_range(0..3);
        match op {
            0 => {
                // Flip a random byte
                let pos = rng.gen_range(0..data.len());
                data[pos] ^= 1u8 << rng.gen_range(0..8);
            }
            1 => {
                // Overwrite with random bytes
                let pos = rng.gen_range(0..data.len());
                let len = rng.gen_range(1..=std::cmp::min(8, data.len() - pos));
                for i in pos..pos + len {
                    data[i] = rng.gen();
                }
            }
            2 => {
                // Set a byte to a special value
                let pos = rng.gen_range(0..data.len());
                data[pos] = [0, 0xFF, 0x7F, 0x80, 0x41][rng.gen_range(0..5)];
            }
            _ => {}
        }
    }
}

/// Splice: take calls from a fresh program and merge.
fn splice(
    prog: &mut Program,
    descs: &[SyscallDesc],
    choice_table: &SyscallChoiceTable,
    timeout_edge_failures: &HashMap<String, u32>,
    rng: &mut impl Rng,
) {
    let other =
        generate_with_choice_table_and_edge_bias(descs, choice_table, timeout_edge_failures, rng);
    if other.calls.is_empty() || prog.calls.is_empty() {
        return;
    }
    let split_self = rng.gen_range(0..prog.calls.len());
    let split_other = rng.gen_range(0..other.calls.len());
    let mut new_calls = prog.calls[..split_self].to_vec();
    new_calls.extend_from_slice(&other.calls[split_other..]);
    prog.calls = new_calls;
    repair_result_refs(prog, descs);
}

/// Describe a program in human-readable form.
pub fn describe_program(prog: &Program, descs: &[SyscallDesc]) -> String {
    let mut s = String::new();
    for (i, call) in prog.calls.iter().enumerate() {
        let desc = &descs[call.syscall_idx];
        s.push_str(&format!("{}. {}(", i, desc.name));
        for (j, arg) in call.args.iter().enumerate() {
            if j > 0 {
                s.push_str(", ");
            }
            match arg {
                ArgValue::Const(v) => s.push_str(&format!("0x{:x}", v)),
                ArgValue::ResultRef(result_ref) => s.push_str(&format!(
                    "result_from_call_{}_{}",
                    result_ref.call_idx, result_ref.result_idx
                )),
                ArgValue::Buffer(d) => s.push_str(&format!("buf[{}]", d.len())),
                ArgValue::Filename(f) => s.push_str(&format!("\"{}\"", f)),
                ArgValue::OutPtr => s.push_str("&out"),
                ArgValue::Null => s.push_str("NULL"),
            }
        }
        s.push_str(")\n");
    }
    s
}

fn random_value_for_size(size: usize, rng: &mut impl Rng) -> u64 {
    let bit_width = size.saturating_mul(8);
    if bit_width >= 64 {
        rng.gen()
    } else {
        rng.gen::<u64>() & ((1u64 << bit_width) - 1)
    }
}

fn resource_producers_for_missing_inputs(
    descs: &[SyscallDesc],
    enabled_syscalls: &[usize],
    desc: &SyscallDesc,
    available_resources: &HashMap<String, Vec<ResultRef>>,
) -> Vec<usize> {
    let mut producers = Vec::new();
    let mut seen = HashSet::new();

    for resource in input_resources(desc) {
        let is_available = available_resources
            .get(&resource.kind)
            .is_some_and(|values| !values.is_empty());
        if is_available {
            continue;
        }
        for syscall_idx in resource_constructor_syscalls(descs, &resource) {
            if enabled_syscalls.contains(&syscall_idx) && seen.insert(syscall_idx) {
                producers.push(syscall_idx);
            }
        }
    }

    producers
}

fn resource_consumers_for_available_inputs(
    descs: &[SyscallDesc],
    enabled_syscalls: &[usize],
    available_resources: &HashMap<String, Vec<ResultRef>>,
) -> Vec<usize> {
    let mut consumers = Vec::new();

    for &syscall_idx in enabled_syscalls {
        let inputs = input_resources(&descs[syscall_idx]);
        if inputs.is_empty() {
            continue;
        }

        let all_available = inputs.iter().all(|resource| {
            available_resources
                .get(&resource.kind)
                .is_some_and(|values| !values.is_empty())
        });
        if !all_available {
            continue;
        }

        let uses_current_resources = inputs.iter().any(|resource| {
            available_resources
                .get(&resource.kind)
                .is_some_and(|values| !values.is_empty())
        });
        if uses_current_resources {
            consumers.push(syscall_idx);
        }
    }

    consumers
}

fn timeout_edge_penalty(
    descs: &[SyscallDesc],
    previous_syscall_idx: Option<usize>,
    candidate_idx: usize,
    timeout_edge_failures: &HashMap<String, u32>,
) -> u32 {
    let Some(previous_syscall_idx) = previous_syscall_idx else {
        return 0;
    };
    timeout_prone_edge_key(descs, previous_syscall_idx, candidate_idx)
        .and_then(|edge| timeout_edge_failures.get(&edge).copied())
        .unwrap_or(0)
}

fn prefer_low_penalty_candidates(
    descs: &[SyscallDesc],
    previous_syscall_idx: Option<usize>,
    candidates: &[usize],
    timeout_edge_failures: &HashMap<String, u32>,
) -> Vec<usize> {
    if candidates.len() <= 1 || timeout_edge_failures.is_empty() {
        return candidates.to_vec();
    }

    let mut best_penalty = u32::MAX;
    let mut filtered = Vec::new();
    for &candidate in candidates {
        let penalty = timeout_edge_penalty(
            descs,
            previous_syscall_idx,
            candidate,
            timeout_edge_failures,
        );
        if penalty < best_penalty {
            best_penalty = penalty;
            filtered.clear();
            filtered.push(candidate);
        } else if penalty == best_penalty {
            filtered.push(candidate);
        }
    }

    if filtered.is_empty() {
        candidates.to_vec()
    } else {
        filtered
    }
}

fn available_resources_before(
    calls: &[Call],
    descs: &[SyscallDesc],
    upto: usize,
) -> HashMap<String, Vec<ResultRef>> {
    let mut resources = HashMap::new();
    for (index, call) in calls[..upto].iter().enumerate() {
        for (result_idx, output) in resource_outputs(&descs[call.syscall_idx])
            .into_iter()
            .enumerate()
        {
            register_available_resource(
                &mut resources,
                &output.resource,
                ResultRef {
                    call_idx: index,
                    result_idx,
                },
            );
        }
    }
    resources
}

fn shift_result_refs_for_insert(prog: &mut Program, pos: usize) {
    for call in &mut prog.calls {
        for arg in &mut call.args {
            if let ArgValue::ResultRef(result_ref) = arg {
                if result_ref.call_idx >= pos {
                    result_ref.call_idx += 1;
                }
            }
        }
    }
}

fn shift_result_refs_for_removal(prog: &mut Program, pos: usize) {
    for call in &mut prog.calls {
        for arg in &mut call.args {
            if let ArgValue::ResultRef(result_ref) = arg {
                if result_ref.call_idx == pos {
                    result_ref.call_idx = usize::MAX;
                    result_ref.result_idx = usize::MAX;
                } else if result_ref.call_idx > pos {
                    result_ref.call_idx -= 1;
                }
            }
        }
    }
}

fn repair_result_refs(prog: &mut Program, descs: &[SyscallDesc]) {
    let mut available_resources: HashMap<String, Vec<ResultRef>> = HashMap::new();
    for call_idx in 0..prog.calls.len() {
        let desc = &descs[prog.calls[call_idx].syscall_idx];
        for (arg_type, arg_value) in desc.args.iter().zip(prog.calls[call_idx].args.iter_mut()) {
            if let ArgType::Resource(resource) = arg_type {
                if let ArgValue::ResultRef(ref_idx) = arg_value {
                    let available = available_resources.get(&resource.kind);
                    let has_match = available.is_some_and(|indices| indices.contains(ref_idx));
                    if !has_match {
                        if let Some(last_idx) =
                            available.and_then(|indices| indices.last()).cloned()
                        {
                            *ref_idx = last_idx;
                        } else {
                            *arg_value = ArgValue::Const(resource.default_value());
                        }
                    }
                }
            }
        }
        for (result_idx, output) in resource_outputs(desc).into_iter().enumerate() {
            register_available_resource(
                &mut available_resources,
                &output.resource,
                ResultRef {
                    call_idx,
                    result_idx,
                },
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;

    #[test]
    fn generates_program_from_parsed_descriptions() {
        let descs = get_syscall_descs();
        let mut rng = rand::rngs::StdRng::seed_from_u64(0x5eed);
        let prog = generate(&descs, &mut rng);
        assert!(!prog.calls.is_empty());
        assert!(prog.calls.len() <= MAX_CALLS);
        for call in &prog.calls {
            assert!(call.syscall_idx < descs.len());
        }
        prog.validate(&descs)
            .expect("generated programs must validate");
    }

    #[test]
    fn repair_result_refs_after_removal_retargets_to_previous_resource() {
        let descs = get_syscall_descs();
        let mut prog = Program {
            calls: vec![
                Call {
                    syscall_idx: 9, // eventfd2 -> fd
                    args: vec![ArgValue::Const(0), ArgValue::Const(0)],
                },
                Call {
                    syscall_idx: 9, // eventfd2 -> fd
                    args: vec![ArgValue::Const(1), ArgValue::Const(0)],
                },
                Call {
                    syscall_idx: 1, // close(fd)
                    args: vec![ArgValue::ResultRef(ResultRef {
                        call_idx: 1,
                        result_idx: 0,
                    })],
                },
            ],
        };

        prog.calls.remove(1);
        shift_result_refs_for_removal(&mut prog, 1);
        repair_result_refs(&mut prog, &descs);

        match prog.calls[1].args[0] {
            ArgValue::ResultRef(ref result_ref) => {
                assert_eq!(result_ref.call_idx, 0);
                assert_eq!(result_ref.result_idx, 0);
            }
            ref other => panic!("unexpected arg after repair: {:?}", other),
        }
    }

    #[test]
    fn mutated_programs_remain_valid() {
        let descs = get_syscall_descs();
        let mut rng = rand::rngs::StdRng::seed_from_u64(0xfacefeed);
        let mut prog = generate(&descs, &mut rng);

        for _ in 0..64 {
            prog = mutate(&prog, &descs, &mut rng);
            prog.validate(&descs)
                .expect("mutated programs must remain structurally valid");
        }
    }

    #[test]
    fn generates_unbounded_8_byte_constants() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(0xabad1dea);
        let desc = SyscallDesc {
            name: "const_only".into(),
            id: 1,
            args: vec![ArgType::Const {
                size: 8,
                values: vec![],
                range: None,
                endian: ScalarEndian::Native,
            }],
            ret: ReturnType::Int,
            attrs: SyscallAttrs::default(),
        };
        let arg = generate_arg(
            &desc,
            &[],
            &ArgType::Const {
                size: 8,
                values: vec![],
                range: None,
                endian: ScalarEndian::Native,
            },
            &HashMap::new(),
            &mut rng,
        );

        assert!(matches!(arg, ArgValue::Const(_)));
    }

    #[test]
    fn generates_length_arguments_from_materialized_pointer_sizes() {
        let descs = crate::description::parse_syscall_descs(
            r#"
                resource fd[4] = -1, 0
                resource sock[fd]
                type sockaddr_storage buffer[16:16]
                bind(fd sock, addr ptr[in, sockaddr_storage], addrlen len[addr, int32])
            "#,
        )
        .expect("test target should parse");
        let desc = &descs[0];
        let mut rng = rand::rngs::StdRng::seed_from_u64(0x600d_f00d);
        let mut available_resources = HashMap::new();
        register_available_resource(
            &mut available_resources,
            match &desc.args[0] {
                ArgType::Resource(resource) => resource,
                other => panic!("unexpected bind fd arg: {:?}", other),
            },
            ResultRef {
                call_idx: 0,
                result_idx: 0,
            },
        );

        let args = generate_args(desc, &available_resources, &mut rng);
        assert!(matches!(args[1], ArgValue::Buffer(ref data) if data.len() == 16));
        assert!(matches!(args[2], ArgValue::Const(16)));
    }

    #[test]
    fn generates_structured_sockaddr_bytes_and_matching_length() {
        let descs = crate::description::parse_syscall_descs(
            r#"
                resource fd[4] = -1, 0
                resource sock[fd]
                resource sock_in[sock]
                const AF_INET = 2
                type sock_port int16be[20000:20004]
                type ipv4_addr const[0x7f000001, int32be]
                sockaddr_in {
                    family const[AF_INET, int16]
                    port sock_port
                    addr ipv4_addr
                } [size[16]]
                bind$inet(fd sock_in, addr ptr[in, sockaddr_in], addrlen len[addr])
            "#,
        )
        .expect("test target should parse");
        let desc = &descs[0];
        let mut rng = rand::rngs::StdRng::seed_from_u64(0x1a7e_5eed);
        let mut available_resources = HashMap::new();
        register_available_resource(
            &mut available_resources,
            match &desc.args[0] {
                ArgType::Resource(resource) => resource,
                other => panic!("unexpected bind fd arg: {:?}", other),
            },
            ResultRef {
                call_idx: 0,
                result_idx: 0,
            },
        );

        let args = generate_args(desc, &available_resources, &mut rng);
        match &args[1] {
            ArgValue::Buffer(data) => {
                assert_eq!(data.len(), 16);
                assert_eq!(&data[..2], &[2, 0]);
                assert_eq!(&data[4..8], &[127, 0, 0, 1]);
            }
            other => panic!("unexpected bind addr arg: {:?}", other),
        }
        assert!(matches!(args[2], ArgValue::Const(16)));
    }

    #[test]
    fn generates_buffer_lengths_for_len_and_bytesize() {
        let descs = crate::description::parse_syscall_descs(
            r#"
                resource fd[4] = -1, 0
                syscall send@1(fd fd, buf buffer[in], count len[buf, int32], size bytesize[buf, int32])
            "#,
        )
        .expect("test target should parse");
        let desc = &descs[0];
        let mut rng = rand::rngs::StdRng::seed_from_u64(0x600d_beef);
        let mut available_resources = HashMap::new();
        register_available_resource(
            &mut available_resources,
            match &desc.args[0] {
                ArgType::Resource(resource) => resource,
                other => panic!("unexpected send fd arg: {:?}", other),
            },
            ResultRef {
                call_idx: 0,
                result_idx: 0,
            },
        );

        let args = generate_args(desc, &available_resources, &mut rng);
        let buf_len = match &args[1] {
            ArgValue::Buffer(data) => data.len() as u64,
            other => panic!("unexpected send buf arg: {:?}", other),
        };
        assert!(matches!(args[2], ArgValue::Const(v) if v == buf_len));
        assert!(matches!(args[3], ArgValue::Const(v) if v == buf_len));
    }

    #[test]
    fn missing_sock_input_prefers_sock_constructor() {
        let descs = crate::description::parse_syscall_descs(
            r#"
                resource fd[4] = -1, 0
                resource sock[fd] = -1, 0
                syscall socket@1 -> sock(const[4; 2], const[4; 1], const[4; 0])
                syscall listen@2 -> int(sock, const[4; 1])
                syscall close@3 -> int(fd)
            "#,
        )
        .expect("test target should parse");

        let availability = transitively_enabled_syscalls(&descs);
        let producers = resource_producers_for_missing_inputs(
            &descs,
            &availability.enabled,
            &descs[1],
            &HashMap::new(),
        );
        assert_eq!(producers, vec![0]);
    }

    #[test]
    fn generation_skips_transitively_disabled_syscalls() {
        let descs = crate::description::parse_syscall_descs(
            r#"
                resource fd[4] = -1
                syscall getpid@1 -> int()
                syscall close@2 -> int(fd)
            "#,
        )
        .expect("test target should parse");
        let mut rng = rand::rngs::StdRng::seed_from_u64(0x1234_5678);

        for _ in 0..16 {
            let prog = generate(&descs, &mut rng);
            assert!(!prog.calls.is_empty());
            assert!(prog.calls.iter().all(|call| call.syscall_idx == 0));
        }
    }

    #[test]
    fn generation_skips_no_generate_syscalls() {
        let descs = crate::description::parse_syscall_descs(
            r#"
                resource fd[4] = -1
                syscall getpid@1 -> int()
                syscall eventfd2@2 -> fd(const[4; 0], const[4; 0]) (no_generate)
                syscall close@3 -> int(fd)
            "#,
        )
        .expect("test target should parse");
        let mut rng = rand::rngs::StdRng::seed_from_u64(0x5678_1234);

        for _ in 0..16 {
            let prog = generate(&descs, &mut rng);
            assert!(!prog.calls.is_empty());
            assert!(prog.calls.iter().all(|call| call.syscall_idx == 0));
        }
    }

    #[test]
    fn available_sock_resources_surface_sock_consumers() {
        let descs = crate::description::parse_syscall_descs(
            r#"
                resource fd[4] = -1, 0
                resource sock[fd] = -1, 0
                syscall socket@1 -> sock(const[4; 2], const[4; 1], const[4; 0])
                syscall listen@2 -> int(sock, const[4; 1, 8])
                syscall close@3 -> int(fd)
                syscall getpid@4 -> int()
            "#,
        )
        .expect("test target should parse");
        let availability = transitively_enabled_syscalls(&descs);
        let mut available_resources = HashMap::new();
        register_available_resource(
            &mut available_resources,
            match &descs[0].ret {
                ReturnType::Resource(resource) => resource,
                other => panic!("unexpected socket return: {:?}", other),
            },
            ResultRef {
                call_idx: 0,
                result_idx: 0,
            },
        );

        let consumers = resource_consumers_for_available_inputs(
            &descs,
            &availability.enabled,
            &available_resources,
        );
        assert!(consumers.contains(&1)); // listen(sock)
        assert!(consumers.contains(&2)); // close(fd) via sock -> fd compatibility
        assert!(!consumers.contains(&0)); // socket does not consume resources
        assert!(!consumers.contains(&3)); // getpid does not consume resources
    }

    #[test]
    fn timeout_edge_penalty_filters_followup_candidates() {
        let descs = crate::description::parse_syscall_descs(
            r#"
                resource fd[4] = -1, 0
                resource sock[fd] = -1, 0
                type sockaddr_storage buffer[16:16]
                syscall socket$inet@1 -> sock(const[4; 2], const[4; 1], const[4; 0])
                sendto$inet(fd sock, buf buffer[in], len bytesize[buf, int32], flags const[4; 0], addr ptr[in, sockaddr_storage, opt], addrlen len[addr, int32])
                bind$inet(fd sock, addr ptr[in, sockaddr_storage], addrlen len[addr, int32])
                connect$inet(fd sock, addr ptr[in, sockaddr_storage], addrlen len[addr, int32])
            "#,
        )
        .expect("test target should parse");
        let penalties = HashMap::from([("sendto$inet->bind$inet".to_string(), 1)]);

        assert_eq!(
            prefer_low_penalty_candidates(&descs, Some(1), &[2, 3], &penalties),
            vec![3]
        );
    }

    #[test]
    fn generation_bias_avoids_penalized_timeout_edge_when_alternative_exists() {
        let descs = crate::description::parse_syscall_descs(
            r#"
                resource fd[4] = -1, 0
                resource sock[fd] = -1, 0
                type sockaddr_storage buffer[16:16]
                syscall socket$inet@1 -> sock(const[4; 2], const[4; 1], const[4; 0])
                sendto$inet(fd sock, buf buffer[in], len bytesize[buf, int32], flags const[4; 0], addr ptr[in, sockaddr_storage, opt], addrlen len[addr, int32])
                bind$inet(fd sock, addr ptr[in, sockaddr_storage], addrlen len[addr, int32])
                connect$inet(fd sock, addr ptr[in, sockaddr_storage], addrlen len[addr, int32])
            "#,
        )
        .expect("test target should parse");
        let choice_table = SyscallChoiceTable::build(&descs, &[]);
        let mut available_resources = HashMap::new();
        register_available_resource(
            &mut available_resources,
            match &descs[0].ret {
                ReturnType::Resource(resource) => resource,
                other => panic!("unexpected socket return: {:?}", other),
            },
            ResultRef {
                call_idx: 0,
                result_idx: 0,
            },
        );
        let penalties = HashMap::from([("sendto$inet->bind$inet".to_string(), 1)]);
        let mut rng = rand::rngs::StdRng::seed_from_u64(0xfeed_cafe);

        for _ in 0..16 {
            let choice = choose_syscall_for_generation(
                &descs,
                &choice_table,
                Some(1),
                &available_resources,
                &penalties,
                &mut rng,
            );
            assert_ne!(choice, 2);
        }
    }

    #[test]
    fn weighted_choice_prefers_resource_followup_calls() {
        let descs = crate::description::parse_syscall_descs(
            r#"
                resource fd[4] = -1, 0
                resource sock[fd] = -1, 0
                syscall socket@1 -> sock(const[4; 2], const[4; 1], const[4; 0])
                syscall listen@2 -> int(sock, const[4; 1, 8])
                syscall close@3 -> int(fd)
                syscall getpid@4 -> int()
            "#,
        )
        .expect("test target should parse");
        let choice_table = SyscallChoiceTable::build(&descs, &[]);
        let mut rng = rand::rngs::StdRng::seed_from_u64(0x5151_8282);

        for _ in 0..32 {
            let choice = choice_table.choose_subset(&[1, 2, 3], Some(0), &mut rng);
            assert_ne!(choice, 3);
        }
    }

    #[test]
    fn weighted_choice_uses_dynamic_corpus_bias() {
        let descs = crate::description::parse_syscall_descs(
            r#"
                syscall alpha@1 -> int()
                syscall beta@2 -> int()
                syscall gamma@3 -> int()
            "#,
        )
        .expect("test target should parse");
        let corpus = vec![Program {
            calls: vec![
                Call {
                    syscall_idx: 0,
                    args: vec![],
                },
                Call {
                    syscall_idx: 1,
                    args: vec![],
                },
            ],
        }];
        let choice_table = SyscallChoiceTable::build(&descs, &corpus);
        let mut rng = rand::rngs::StdRng::seed_from_u64(0x4141_9292);

        for _ in 0..32 {
            let choice = choice_table.choose_subset(&[1, 2], Some(0), &mut rng);
            assert_eq!(choice, 1);
        }
    }
}
