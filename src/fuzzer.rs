use crate::program::*;
use rand::Rng;

const MAX_CALLS: usize = 10;
const MIN_CALLS: usize = 1;

/// Generate a random program from scratch.
pub fn generate(descs: &[SyscallDesc], rng: &mut impl Rng) -> Program {
    let num_calls = rng.gen_range(MIN_CALLS..=MAX_CALLS);
    let fd_producers = fd_producing_syscalls(descs);
    let mut calls = Vec::new();
    let mut available_fds: Vec<usize> = Vec::new(); // call indices that produced fds

    for _ in 0..num_calls {
        // Decide whether to generate an fd-producing call or fd-consuming call
        let needs_fd_bias = available_fds.is_empty() && !fd_producers.is_empty();
        let syscall_idx = if needs_fd_bias && rng.gen_bool(0.7) {
            // Bias toward fd-producing syscalls when we have no fds
            fd_producers[rng.gen_range(0..fd_producers.len())]
        } else {
            rng.gen_range(0..descs.len())
        };

        let desc = &descs[syscall_idx];
        let args = generate_args(desc, &available_fds, rng);

        if desc.ret == ReturnType::Fd {
            available_fds.push(calls.len());
        }

        calls.push(Call { syscall_idx, args });
    }

    Program { calls }
}

/// Generate arguments for a syscall.
fn generate_args(desc: &SyscallDesc, available_fds: &[usize], rng: &mut impl Rng) -> Vec<ArgValue> {
    desc.args.iter().map(|arg_type| generate_arg(arg_type, available_fds, rng)).collect()
}

/// Generate a single argument value.
fn generate_arg(arg_type: &ArgType, available_fds: &[usize], rng: &mut impl Rng) -> ArgValue {
    match arg_type {
        ArgType::Const { size, values } => {
            if !values.is_empty() {
                // Pick from valid values, occasionally mutate
                if rng.gen_bool(0.9) {
                    ArgValue::Const(values[rng.gen_range(0..values.len())])
                } else {
                    ArgValue::Const(rng.gen::<u64>() & ((1u64 << (*size as u64 * 8)) - 1))
                }
            } else {
                ArgValue::Const(rng.gen::<u64>() & ((1u64 << (*size as u64 * 8)) - 1))
            }
        }
        ArgType::Fd => {
            if !available_fds.is_empty() && rng.gen_bool(0.8) {
                ArgValue::FdRef(available_fds[rng.gen_range(0..available_fds.len())])
            } else {
                // Use a small literal fd (stdin/stdout/stderr or small number)
                ArgValue::Const(rng.gen_range(0..5) as u64)
            }
        }
        ArgType::Ptr { inner, dir: _ } => {
            match inner.as_ref() {
                ArgType::Buffer { min_size, max_size } => {
                    let size = rng.gen_range(*min_size..=*max_size);
                    let mut data = vec![0u8; size];
                    rng.fill(&mut data[..]);
                    ArgValue::Buffer(data)
                }
                _ => ArgValue::Buffer(vec![0u8; 8]),
            }
        }
        ArgType::Buffer { min_size, max_size } => {
            let size = rng.gen_range(*min_size..=*max_size);
            let mut data = vec![0u8; size];
            rng.fill(&mut data[..]);
            ArgValue::Buffer(data)
        }
        ArgType::Filename => {
            ArgValue::Filename(random_filename(rng))
        }
    }
}

// ============================================================
// Mutation operations
// ============================================================

/// Mutate a program by applying a random mutation.
pub fn mutate(prog: &Program, descs: &[SyscallDesc], rng: &mut impl Rng) -> Program {
    let mut new_prog = prog.clone();
    let mutation_type = rng.gen_range(0..6);
    match mutation_type {
        0 => mutate_insert_call(&mut new_prog, descs, rng),
        1 => mutate_remove_call(&mut new_prog, rng),
        2 => mutate_args(&mut new_prog, descs, rng),
        3 => mutate_integer(&mut new_prog, rng),
        4 => mutate_buffer(&mut new_prog, rng),
        5 => splice(&mut new_prog, descs, rng),
        _ => {}
    }
    // Ensure program is not empty
    if new_prog.calls.is_empty() {
        new_prog = generate(descs, rng);
    }
    // Ensure program is not too long
    if new_prog.calls.len() > MAX_CALLS {
        new_prog.calls.truncate(MAX_CALLS);
    }
    new_prog
}

/// Insert a random call at a random position.
fn mutate_insert_call(prog: &mut Program, descs: &[SyscallDesc], rng: &mut impl Rng) {
    if prog.calls.len() >= MAX_CALLS {
        return;
    }
    let available_fds: Vec<usize> = prog.calls.iter().enumerate()
        .filter(|(_, c)| descs[c.syscall_idx].ret == ReturnType::Fd)
        .map(|(i, _)| i)
        .collect();

    let syscall_idx = rng.gen_range(0..descs.len());
    let desc = &descs[syscall_idx];
    let args = generate_args(desc, &available_fds, rng);
    let pos = rng.gen_range(0..=prog.calls.len());
    prog.calls.insert(pos, Call { syscall_idx, args });
}

/// Remove a random call.
fn mutate_remove_call(prog: &mut Program, rng: &mut impl Rng) {
    if prog.calls.len() <= 1 {
        return;
    }
    let pos = rng.gen_range(0..prog.calls.len());
    prog.calls.remove(pos);
}

/// Replace arguments of a random call with fresh ones.
fn mutate_args(prog: &mut Program, descs: &[SyscallDesc], rng: &mut impl Rng) {
    if prog.calls.is_empty() {
        return;
    }
    let idx = rng.gen_range(0..prog.calls.len());
    let available_fds: Vec<usize> = prog.calls[..idx].iter().enumerate()
        .filter(|(_, c)| descs[c.syscall_idx].ret == ReturnType::Fd)
        .map(|(i, _)| i)
        .collect();

    let desc = &descs[prog.calls[idx].syscall_idx];
    prog.calls[idx].args = generate_args(desc, &available_fds, rng);
}

/// Mutate an integer argument.
fn mutate_integer(prog: &mut Program, rng: &mut impl Rng) {
    if prog.calls.is_empty() {
        return;
    }
    let call_idx = rng.gen_range(0..prog.calls.len());
    let call = &mut prog.calls[call_idx];
    if call.args.is_empty() {
        return;
    }
    let arg_idx = rng.gen_range(0..call.args.len());
    if let ArgValue::Const(ref mut val) = call.args[arg_idx] {
        let op = rng.gen_range(0..5);
        match op {
            0 => *val = val.wrapping_add(rng.gen_range(1..=16)),
            1 => *val = val.wrapping_sub(rng.gen_range(1..=16)),
            2 => *val ^= 1u64 << rng.gen_range(0..64),
            3 => *val = rng.gen(),
            4 => *val = [0, 1, 0xFFFF_FFFF, 0xFFFF_FFFF_FFFF_FFFF, 0x80000000, 0x7FFFFFFF][rng.gen_range(0..6)],
            _ => {}
        }
    }
}

/// Mutate buffer content.
fn mutate_buffer(prog: &mut Program, rng: &mut impl Rng) {
    if prog.calls.is_empty() {
        return;
    }
    let call_idx = rng.gen_range(0..prog.calls.len());
    let call = &mut prog.calls[call_idx];
    if call.args.is_empty() {
        return;
    }
    let arg_idx = rng.gen_range(0..call.args.len());
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
fn splice(prog: &mut Program, descs: &[SyscallDesc], rng: &mut impl Rng) {
    let other = generate(descs, rng);
    if other.calls.is_empty() || prog.calls.is_empty() {
        return;
    }
    let split_self = rng.gen_range(0..prog.calls.len());
    let split_other = rng.gen_range(0..other.calls.len());
    let mut new_calls = prog.calls[..split_self].to_vec();
    new_calls.extend_from_slice(&other.calls[split_other..]);
    prog.calls = new_calls;
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
                ArgValue::FdRef(idx) => s.push_str(&format!("fd_from_call_{}", idx)),
                ArgValue::FdNew => s.push_str("fd_new"),
                ArgValue::Buffer(d) => s.push_str(&format!("buf[{}]", d.len())),
                ArgValue::Filename(f) => s.push_str(&format!("\"{}\"", f)),
                ArgValue::Null => s.push_str("NULL"),
            }
        }
        s.push_str(")\n");
    }
    s
}
