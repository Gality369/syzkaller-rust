use crate::program::*;
use std::collections::HashMap;

// Exec format constants (matching Go's encodingexec.go)
const EXEC_INSTR_EOF: u64 = !0u64; // 0xFFFFFFFFFFFFFFFF
const EXEC_INSTR_COPYIN: u64 = !1u64; // 0xFFFFFFFFFFFFFFFE
const EXEC_INSTR_COPYOUT: u64 = !2u64; // 0xFFFFFFFFFFFFFFFFD
const EXEC_INSTR_SET_PROPS: u64 = !3u64; // 0xFFFFFFFFFFFFFFFC

const EXEC_ARG_CONST: u64 = 0;
const EXEC_ARG_ADDR32: u64 = 1;
const EXEC_ARG_ADDR64: u64 = 2;
const EXEC_ARG_RESULT: u64 = 3;
const EXEC_ARG_DATA: u64 = 4;

const EXEC_NO_COPYOUT: u64 = !0u64;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct PointerPathKey {
    arg_idx: usize,
    offsets: Vec<usize>,
}

fn scalar_endian_exec_format(endian: ScalarEndian) -> u64 {
    match endian {
        ScalarEndian::Native => 0,
        ScalarEndian::Big => 1,
    }
}

fn top_level_data_storage_value(
    arg_val: &ArgValue,
) -> Option<(&[u8], Option<&[InlinePointerValue]>)> {
    match arg_val {
        ArgValue::Buffer(data) => Some((data.as_slice(), None)),
        ArgValue::Composite { data, pointers, .. } => Some((data.as_slice(), Some(pointers))),
        ArgValue::Array { data, pointers, .. } => Some((data.as_slice(), Some(pointers))),
        _ => None,
    }
}

/// Serialize a program into the executor's binary format.
/// This matches the varint-encoded format from Go's encodingexec.go.
pub fn serialize_program(
    prog: &Program,
    descs: &[SyscallDesc],
) -> Result<Vec<u8>, ValidationError> {
    validate_program(prog, descs)?;
    let mut w = ExecWriter::new();
    let used_results = used_results(prog);
    let mut resolved_results: HashMap<ResultRef, u64> = HashMap::new();
    let mut next_copyout_idx = 0u64;

    // Number of calls
    w.write_val(prog.calls.len() as u64);

    // Per-call data page allocation: each call's pointer args get their own page
    let mut next_data_page: u64 = 0;

    for (call_idx, call) in prog.calls.iter().enumerate() {
        let desc = &descs[call.syscall_idx];
        let outputs = resource_outputs(desc);
        let mut data_addrs: Vec<(usize, u64)> = Vec::new(); // (arg_idx, addr)
        let mut nested_data_addrs: HashMap<PointerPathKey, u64> = HashMap::new();

        // First pass: allocate data pages and emit copyin instructions for pointer args
        // and for top-level buffer-like syscall arguments that upstream exec encoding
        // expects to reside in the data segment.
        for (arg_idx, (arg_type, arg_val)) in desc.args.iter().zip(call.args.iter()).enumerate() {
            match (arg_type, arg_val) {
                (ArgType::Ptr { .. }, ArgValue::Null) => {}
                (ArgType::Ptr { .. }, _)
                | (ArgType::Filename, _)
                | (ArgType::Array { .. }, ArgValue::Buffer(_))
                | (ArgType::Array { .. }, ArgValue::Composite { .. })
                | (ArgType::Array { .. }, ArgValue::Array { .. })
                | (ArgType::String { .. }, ArgValue::Buffer(_))
                | (ArgType::Buffer { .. }, ArgValue::Buffer(_))
                | (ArgType::Buffer { .. }, ArgValue::Composite { .. })
                | (ArgType::Buffer { .. }, ArgValue::Array { .. }) => {
                    let addr = DATA_OFFSET + next_data_page * PAGE_SIZE;
                    data_addrs.push((arg_idx, addr));
                    next_data_page += 1;

                    // Emit copyin for input data
                    match (arg_type, arg_val) {
                        (
                            ArgType::Ptr {
                                inner: _,
                                dir: PtrDir::In | PtrDir::InOut,
                                ..
                            },
                            ArgValue::Buffer(data),
                        ) => emit_copyin_bytes(&mut w, addr, data),
                        (
                            ArgType::Ptr {
                                inner: _,
                                dir: PtrDir::In | PtrDir::InOut,
                                ..
                            },
                            ArgValue::Composite { data, pointers, .. },
                        ) => {
                            let mut pointer_chain = Vec::new();
                            emit_composite_copyin(
                                &mut w,
                                addr,
                                data,
                                pointers,
                                &mut next_data_page,
                                arg_idx,
                                &mut nested_data_addrs,
                                &mut pointer_chain,
                            )?
                        }
                        (
                            ArgType::Ptr {
                                inner: _,
                                dir: PtrDir::In | PtrDir::InOut,
                                ..
                            },
                            ArgValue::Array { data, pointers, .. },
                        ) => {
                            let mut pointer_chain = Vec::new();
                            emit_composite_copyin(
                                &mut w,
                                addr,
                                data,
                                pointers,
                                &mut next_data_page,
                                arg_idx,
                                &mut nested_data_addrs,
                                &mut pointer_chain,
                            )?
                        }
                        (
                            ArgType::Ptr {
                                inner: _,
                                dir: PtrDir::Out,
                                ..
                            },
                            ArgValue::Buffer(data),
                        ) => emit_copyin_bytes(&mut w, addr, data),
                        (
                            ArgType::Ptr {
                                inner: _,
                                dir: PtrDir::Out,
                                ..
                            },
                            ArgValue::Composite { data, pointers, .. },
                        ) => {
                            let mut pointer_chain = Vec::new();
                            emit_composite_copyin(
                                &mut w,
                                addr,
                                data,
                                pointers,
                                &mut next_data_page,
                                arg_idx,
                                &mut nested_data_addrs,
                                &mut pointer_chain,
                            )?
                        }
                        (
                            ArgType::Ptr {
                                inner: _,
                                dir: PtrDir::Out,
                                ..
                            },
                            ArgValue::Array { data, pointers, .. },
                        ) => {
                            let mut pointer_chain = Vec::new();
                            emit_composite_copyin(
                                &mut w,
                                addr,
                                data,
                                pointers,
                                &mut next_data_page,
                                arg_idx,
                                &mut nested_data_addrs,
                                &mut pointer_chain,
                            )?
                        }
                        (ArgType::Filename, ArgValue::Filename(name)) => {
                            let data = {
                                let mut d = name.as_bytes().to_vec();
                                d.push(0); // null terminator
                                d
                            };
                            emit_copyin_bytes(&mut w, addr, &data);
                        }
                        (
                            ArgType::Ptr {
                                dir: PtrDir::Out, ..
                            },
                            ArgValue::OutPtr,
                        ) => {
                            // Output buffer: no copyin needed, just reserve space
                        }
                        (ArgType::Array { .. }, arg_val)
                        | (ArgType::String { .. }, arg_val)
                        | (ArgType::Buffer { .. }, arg_val) => {
                            if let Some((data, pointers)) = top_level_data_storage_value(arg_val) {
                                if let Some(pointers) = pointers {
                                    let mut pointer_chain = Vec::new();
                                    emit_composite_copyin(
                                        &mut w,
                                        addr,
                                        data,
                                        pointers,
                                        &mut next_data_page,
                                        arg_idx,
                                        &mut nested_data_addrs,
                                        &mut pointer_chain,
                                    )?;
                                } else {
                                    emit_copyin_bytes(&mut w, addr, data);
                                }
                            }
                        }
                        _ => {}
                    }
                }
                _ => {}
            }
        }

        // Emit the syscall itself
        w.write_val(desc.id);
        let return_result_ref = outputs
            .first()
            .filter(|output| matches!(output.source, ResourceSource::ReturnValue))
            .map(|_| ResultRef {
                call_idx,
                result_idx: 0,
            });
        if let Some(result_ref) =
            return_result_ref.filter(|result_ref| used_results.contains(result_ref))
        {
            resolved_results.insert(result_ref, next_copyout_idx);
            w.write_val(next_copyout_idx);
            next_copyout_idx += 1;
        } else {
            w.write_val(EXEC_NO_COPYOUT);
        }
        w.write_val(desc.args.len() as u64);

        // Emit arguments
        for (arg_idx, (arg_type, arg_val)) in desc.args.iter().zip(call.args.iter()).enumerate() {
            match (arg_type, arg_val) {
                (ArgType::Const { size, .. }, ArgValue::Const(val)) => {
                    w.write_val(EXEC_ARG_CONST);
                    w.write_val(meta_const(*size, 0, 0, 0, 0));
                    w.write_val(*val);
                }
                (
                    ArgType::Proc {
                        size,
                        values_start,
                        values_per_proc,
                        endian,
                    },
                    ArgValue::Const(val),
                ) => {
                    let (value, pid_stride) = if *val == PROC_DEFAULT_VALUE {
                        (0, 0)
                    } else {
                        (values_start.wrapping_add(*val), *values_per_proc)
                    };
                    w.write_val(EXEC_ARG_CONST);
                    w.write_val(meta_const(
                        *size,
                        scalar_endian_exec_format(*endian),
                        0,
                        0,
                        pid_stride,
                    ));
                    w.write_val(value);
                }
                (ArgType::Len { size, .. }, ArgValue::Const(val)) => {
                    w.write_val(EXEC_ARG_CONST);
                    w.write_val(meta_const(*size, 0, 0, 0, 0));
                    w.write_val(*val);
                }
                (ArgType::Vma { .. }, ArgValue::Vma { addr, size: _ }) => {
                    w.write_val(EXEC_ARG_ADDR64);
                    w.write_val(*addr - DATA_OFFSET);
                }
                (ArgType::Vma { .. }, ArgValue::Null) => {
                    w.write_val(EXEC_ARG_CONST);
                    w.write_val(meta_const(8, 0, 0, 0, 0));
                    w.write_val(0);
                }
                (
                    ArgType::Resource(resource) | ArgType::OptionalResource(resource),
                    ArgValue::Const(val),
                ) => {
                    w.write_val(EXEC_ARG_CONST);
                    w.write_val(meta_const(resource.size, 0, 0, 0, 0));
                    w.write_val(*val);
                }
                (
                    ArgType::Resource(resource) | ArgType::OptionalResource(resource),
                    ArgValue::ResultRef(result_ref),
                ) => {
                    if let Some(copyout_idx) = resolved_results.get(result_ref).copied() {
                        w.write_val(EXEC_ARG_RESULT);
                        w.write_val(meta_result(resource.size, 0));
                        w.write_val(copyout_idx);
                        w.write_val(0); // op_div
                        w.write_val(0); // op_add
                        w.write_val(resource.default_value());
                    } else {
                        w.write_val(EXEC_ARG_CONST);
                        w.write_val(meta_const(resource.size, 0, 0, 0, 0));
                        w.write_val(resource.default_value());
                    }
                }
                (
                    ArgType::Resource(resource) | ArgType::OptionalResource(resource),
                    ArgValue::Null,
                ) => {
                    w.write_val(EXEC_ARG_CONST);
                    w.write_val(meta_const(resource.size, 0, 0, 0, 0));
                    w.write_val(resource.default_value());
                }
                (ArgType::Array { .. }, ArgValue::Buffer(_))
                | (ArgType::Array { .. }, ArgValue::Composite { .. })
                | (ArgType::Array { .. }, ArgValue::Array { .. })
                | (ArgType::String { .. }, ArgValue::Buffer(_))
                | (ArgType::Buffer { .. }, ArgValue::Buffer(_))
                | (ArgType::Buffer { .. }, ArgValue::Composite { .. })
                | (ArgType::Buffer { .. }, ArgValue::Array { .. }) => {
                    if let Some((_, addr)) = data_addrs.iter().find(|(idx, _)| *idx == arg_idx) {
                        w.write_val(EXEC_ARG_ADDR64);
                        w.write_val(*addr - DATA_OFFSET);
                    } else {
                        w.write_val(EXEC_ARG_CONST);
                        w.write_val(meta_const(8, 0, 0, 0, 0));
                        w.write_val(0);
                    }
                }
                (ArgType::Array { .. }, _) => {
                    w.write_val(EXEC_ARG_CONST);
                    w.write_val(meta_const(8, 0, 0, 0, 0));
                    w.write_val(0);
                }
                (ArgType::Ptr { .. }, ArgValue::Null) => {
                    w.write_val(EXEC_ARG_CONST);
                    w.write_val(meta_const(8, 0, 0, 0, 0));
                    w.write_val(0);
                }
                (ArgType::Ptr { .. }, _) | (ArgType::Filename, _) => {
                    // Pointer argument: emit the address
                    if let Some((_, addr)) = data_addrs.iter().find(|(idx, _)| *idx == arg_idx) {
                        w.write_val(EXEC_ARG_ADDR64);
                        w.write_val(*addr - DATA_OFFSET);
                    } else {
                        // Null pointer
                        w.write_val(EXEC_ARG_CONST);
                        w.write_val(meta_const(8, 0, 0, 0, 0));
                        w.write_val(0);
                    }
                }
                _ => {
                    // Default: emit zero constant
                    w.write_val(EXEC_ARG_CONST);
                    w.write_val(meta_const(8, 0, 0, 0, 0));
                    w.write_val(0);
                }
            }
        }

        for (result_idx, output) in outputs.into_iter().enumerate() {
            let result_ref = ResultRef {
                call_idx,
                result_idx,
            };
            if !used_results.contains(&result_ref) {
                continue;
            }
            if let ResourceSource::PointerElement {
                arg_idx,
                offset,
                pointer_chain,
                ..
            } = output.source
            {
                let base_addr = if pointer_chain.is_empty() {
                    data_addrs
                        .iter()
                        .find(|(idx, _)| *idx == arg_idx)
                        .map(|(_, addr)| *addr)
                } else {
                    nested_data_addrs
                        .get(&PointerPathKey {
                            arg_idx,
                            offsets: pointer_chain,
                        })
                        .copied()
                };
                let Some(base_addr) = base_addr else {
                    continue;
                };
                resolved_results.insert(result_ref, next_copyout_idx);
                w.write_val(EXEC_INSTR_COPYOUT);
                w.write_val(next_copyout_idx);
                w.write_val(base_addr - DATA_OFFSET + offset as u64);
                w.write_val(output.resource.size as u64);
                next_copyout_idx += 1;
            }
        }
    }

    // EOF
    w.write_val(EXEC_INSTR_EOF);
    Ok(w.buf)
}

fn emit_copyin_bytes(w: &mut ExecWriter, addr: u64, data: &[u8]) {
    w.write_val(EXEC_INSTR_COPYIN);
    w.write_val(addr - DATA_OFFSET);
    w.write_val(EXEC_ARG_DATA);
    w.write_val(data.len() as u64);
    w.write_data(data);
}

fn emit_arg_value_copyin(
    w: &mut ExecWriter,
    addr: u64,
    value: &ArgValue,
    next_data_page: &mut u64,
    root_arg_idx: usize,
    nested_data_addrs: &mut HashMap<PointerPathKey, u64>,
    pointer_chain: &mut Vec<usize>,
) -> Result<(), ValidationError> {
    match value {
        ArgValue::Buffer(data) => {
            emit_copyin_bytes(w, addr, data);
            Ok(())
        }
        ArgValue::Composite { data, pointers, .. } => emit_composite_copyin(
            w,
            addr,
            data,
            pointers,
            next_data_page,
            root_arg_idx,
            nested_data_addrs,
            pointer_chain,
        ),
        ArgValue::Array { data, pointers, .. } => emit_composite_copyin(
            w,
            addr,
            data,
            pointers,
            next_data_page,
            root_arg_idx,
            nested_data_addrs,
            pointer_chain,
        ),
        ArgValue::Filename(name) => {
            let mut data = name.as_bytes().to_vec();
            data.push(0);
            emit_copyin_bytes(w, addr, &data);
            Ok(())
        }
        ArgValue::Null | ArgValue::OutPtr => Ok(()),
        ArgValue::Const(value) => {
            emit_copyin_bytes(w, addr, &encode_scalar_bytes(8, *value));
            Ok(())
        }
        ArgValue::Vma {
            addr: value_addr, ..
        } => {
            emit_copyin_bytes(w, addr, &encode_scalar_bytes(8, *value_addr));
            Ok(())
        }
        ArgValue::ResultRef(_) => Err(ValidationError::new(
            "inline pointer copyin does not support result references yet",
        )),
    }
}

fn emit_composite_copyin(
    w: &mut ExecWriter,
    addr: u64,
    data: &[u8],
    pointers: &[InlinePointerValue],
    next_data_page: &mut u64,
    root_arg_idx: usize,
    nested_data_addrs: &mut HashMap<PointerPathKey, u64>,
    pointer_chain: &mut Vec<usize>,
) -> Result<(), ValidationError> {
    let mut patched = data.to_vec();
    for pointer in pointers {
        let end = pointer
            .offset
            .checked_add(8)
            .ok_or_else(|| ValidationError::new("inline pointer offset overflow"))?;
        let slot = patched.get_mut(pointer.offset..end).ok_or_else(|| {
            ValidationError::new("inline pointer slot falls outside composite data")
        })?;
        let mut nested_chain = pointer_chain.clone();
        nested_chain.push(pointer.offset);
        match pointer.value.as_ref() {
            ArgValue::Null => {
                slot.copy_from_slice(&0u64.to_le_bytes());
            }
            ArgValue::OutPtr => {
                let nested_addr = DATA_OFFSET + *next_data_page * PAGE_SIZE;
                *next_data_page += 1;
                nested_data_addrs.insert(
                    PointerPathKey {
                        arg_idx: root_arg_idx,
                        offsets: nested_chain,
                    },
                    nested_addr,
                );
                slot.copy_from_slice(&nested_addr.to_le_bytes());
            }
            nested => {
                let nested_addr = DATA_OFFSET + *next_data_page * PAGE_SIZE;
                *next_data_page += 1;
                nested_data_addrs.insert(
                    PointerPathKey {
                        arg_idx: root_arg_idx,
                        offsets: nested_chain.clone(),
                    },
                    nested_addr,
                );
                slot.copy_from_slice(&nested_addr.to_le_bytes());
                emit_arg_value_copyin(
                    w,
                    nested_addr,
                    nested,
                    next_data_page,
                    root_arg_idx,
                    nested_data_addrs,
                    &mut nested_chain,
                )?;
            }
        }
    }
    emit_copyin_bytes(w, addr, &patched);
    Ok(())
}

/// Encode const metadata: size | (format << 8) | (bf_offset << 16) | (bf_len << 24) | (pid_stride << 32)
fn meta_const(size: usize, format: u64, bf_offset: u64, bf_len: u64, pid_stride: u64) -> u64 {
    (size as u64) | (format << 8) | (bf_offset << 16) | (bf_len << 24) | (pid_stride << 32)
}

fn meta_result(size: usize, format: u64) -> u64 {
    (size as u64) | (format << 8)
}

struct ExecWriter {
    buf: Vec<u8>,
}

impl ExecWriter {
    fn new() -> Self {
        ExecWriter {
            buf: Vec::with_capacity(4096),
        }
    }

    /// Write a uint64 value as a signed varint (matching Go's binary.AppendVarint).
    fn write_val(&mut self, v: u64) {
        // Go's binary.AppendVarint converts to zigzag encoding:
        // int64 x → uint64 ux = (x << 1) ^ (x >> 63)
        let x = v as i64;
        let ux: u64 = ((x << 1) ^ (x >> 63)) as u64;
        self.write_uvarint(ux);
    }

    /// Write an unsigned varint.
    fn write_uvarint(&mut self, mut v: u64) {
        while v >= 0x80 {
            self.buf.push((v as u8) | 0x80);
            v >>= 7;
        }
        self.buf.push(v as u8);
    }

    /// Write raw data bytes without any padding (executor reads exactly `size` bytes).
    fn write_data(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn syscall_idx(descs: &[SyscallDesc], name: &str) -> usize {
        descs
            .iter()
            .position(|desc| desc.name == name)
            .unwrap_or_else(|| panic!("missing syscall {name}"))
    }

    #[test]
    fn test_varint_encoding() {
        let mut w = ExecWriter::new();
        // Test EOF marker: uint64 max = -1 as i64
        // zigzag(-1) = 1
        w.write_val(EXEC_INSTR_EOF);
        assert_eq!(w.buf, vec![0x01]);
    }

    #[test]
    fn test_simple_program() {
        let descs = get_syscall_descs();
        let prog = Program {
            calls: vec![Call {
                syscall_idx: syscall_idx(&descs, "getpid"),
                args: vec![],
            }],
        };
        let data = serialize_program(&prog, &descs).expect("valid program should serialize");
        assert!(!data.is_empty());
        // First varint should encode 1 (number of calls)
        // zigzag(1) = 2
        assert_eq!(data[0], 0x02);
    }

    #[test]
    fn test_resource_result_argument_encoding() {
        let descs = get_syscall_descs();
        let eventfd2 = syscall_idx(&descs, "eventfd2");
        let close = syscall_idx(&descs, "close");
        let prog = Program {
            calls: vec![
                Call {
                    syscall_idx: eventfd2,
                    args: vec![ArgValue::Const(0), ArgValue::Const(0)],
                },
                Call {
                    syscall_idx: close,
                    args: vec![ArgValue::ResultRef(ResultRef {
                        call_idx: 0,
                        result_idx: 0,
                    })],
                },
            ],
        };

        let data =
            serialize_program(&prog, &descs).expect("valid resource program should serialize");
        let events = parse_exec_events(&data);

        let return_copyouts: Vec<u64> = events
            .iter()
            .filter_map(|event| match event {
                ParsedEvent::CallReturnCopyout { idx } => Some(*idx),
                _ => None,
            })
            .collect();
        assert_eq!(return_copyouts, vec![0]);

        let result_args: Vec<(u64, u64, u64)> = events
            .iter()
            .filter_map(|event| match event {
                ParsedEvent::ResultArg {
                    meta,
                    copyout_idx,
                    default,
                } => Some((*meta, *copyout_idx, *default)),
                _ => None,
            })
            .collect();
        assert_eq!(result_args, vec![(4, 0, (-1i64) as u64)]);
    }

    #[test]
    fn test_invalid_program_is_rejected_before_serialization() {
        let descs = get_syscall_descs();
        let close = syscall_idx(&descs, "close");
        let eventfd2 = syscall_idx(&descs, "eventfd2");
        let prog = Program {
            calls: vec![
                Call {
                    syscall_idx: close,
                    args: vec![ArgValue::ResultRef(ResultRef {
                        call_idx: 1,
                        result_idx: 0,
                    })],
                },
                Call {
                    syscall_idx: eventfd2,
                    args: vec![ArgValue::Const(0), ArgValue::Const(0)],
                },
            ],
        };

        let err = serialize_program(&prog, &descs)
            .expect_err("invalid programs should be rejected before serialization");
        assert!(err
            .to_string()
            .contains("resource result reference must point to an earlier call"));
    }

    #[test]
    fn test_pipe2_pointer_results_emit_copyout_instructions() {
        let descs = get_syscall_descs();
        let pipe2 = syscall_idx(&descs, "pipe2");
        let close = syscall_idx(&descs, "close");
        let prog = Program {
            calls: vec![
                Call {
                    syscall_idx: pipe2,
                    args: vec![ArgValue::OutPtr, ArgValue::Const(0)],
                },
                Call {
                    syscall_idx: close,
                    args: vec![ArgValue::ResultRef(ResultRef {
                        call_idx: 0,
                        result_idx: 0,
                    })],
                },
                Call {
                    syscall_idx: close,
                    args: vec![ArgValue::ResultRef(ResultRef {
                        call_idx: 0,
                        result_idx: 1,
                    })],
                },
            ],
        };

        let data = serialize_program(&prog, &descs).expect("pipe2 program should serialize");
        let events = parse_exec_events(&data);

        let copyouts: Vec<(u64, u64)> = events
            .iter()
            .filter_map(|event| match event {
                ParsedEvent::Copyout { idx, size, .. } => Some((*idx, *size)),
                _ => None,
            })
            .collect();
        assert_eq!(copyouts, vec![(0, 4), (1, 4)]);

        let result_copyout_indices: Vec<u64> = events
            .iter()
            .filter_map(|event| match event {
                ParsedEvent::ResultArg { copyout_idx, .. } => Some(*copyout_idx),
                _ => None,
            })
            .collect();
        assert_eq!(result_copyout_indices, vec![0, 1]);
    }

    #[test]
    fn test_optional_null_pointer_encodes_as_zero_and_zero_length() {
        let descs = crate::description::parse_syscall_descs(
            r#"
                resource fd[4] = -1, 0
                resource sock[fd]
                type sockaddr_storage buffer[16:16]
                bind(fd sock, addr ptr[in, sockaddr_storage, opt], addrlen len[addr, int32])
            "#,
        )
        .expect("test target should parse");
        let prog = Program {
            calls: vec![Call {
                syscall_idx: 0,
                args: vec![ArgValue::Const(0), ArgValue::Null, ArgValue::Const(0)],
            }],
        };

        let data =
            serialize_program(&prog, &descs).expect("optional null pointer should serialize");
        let events = parse_exec_events(&data);
        let const_values: Vec<u64> = events
            .iter()
            .filter_map(|event| match event {
                ParsedEvent::ConstArg { value, .. } => Some(*value),
                _ => None,
            })
            .collect();
        let addr_values: Vec<u64> = events
            .iter()
            .filter_map(|event| match event {
                ParsedEvent::AddrArg { addr } => Some(*addr),
                _ => None,
            })
            .collect();

        assert_eq!(const_values, vec![0, 0, 0]);
        assert!(addr_values.is_empty());
    }

    #[test]
    fn top_level_output_buffers_emit_reserved_copyin_and_derived_length() {
        let descs = crate::description::parse_syscall_descs(
            r#"
                resource fd[4] = -1, 0
                syscall recv@1(fd fd, buf ptr[out, array[int8, 16]], len bytesize[buf, int32])
            "#,
        )
        .expect("recv target should parse");
        let prog = Program {
            calls: vec![Call {
                syscall_idx: 0,
                args: vec![
                    ArgValue::Const(0),
                    ArgValue::Buffer(vec![0; 16]),
                    ArgValue::Const(16),
                ],
            }],
        };

        let data = serialize_program(&prog, &descs)
            .expect("program with reserved top-level output buffer should serialize");
        let events = parse_exec_events(&data);

        let copyin = events
            .iter()
            .find_map(|event| match event {
                ParsedEvent::CopyinData { data, .. } if data.len() == 16 => Some(data.clone()),
                _ => None,
            })
            .expect("reserved output buffer copyin should exist");
        assert_eq!(copyin, vec![0; 16]);

        let len_arg = events
            .iter()
            .find_map(|event| match event {
                ParsedEvent::ConstArg { value, .. } if *value == 16 => Some(*value),
                _ => None,
            })
            .expect("derived recv length should be serialized");
        assert_eq!(len_arg, 16);
    }

    #[test]
    fn top_level_input_buffers_emit_copyin_and_address_arguments() {
        let descs = crate::description::parse_syscall_descs(
            r#"
                resource fd[4] = -1, 0, 1
                syscall send@1(fd fd, buf buffer[in], count len[buf, int32])
            "#,
        )
        .expect("send target should parse");
        let payload = vec![1u8, 2, 3, 4, 5];
        let prog = Program {
            calls: vec![Call {
                syscall_idx: 0,
                args: vec![
                    ArgValue::Const(1),
                    ArgValue::Buffer(payload.clone()),
                    ArgValue::Const(payload.len() as u64),
                ],
            }],
        };

        let data =
            serialize_program(&prog, &descs).expect("top-level input buffer should serialize");
        let events = parse_exec_events(&data);

        let copyin = events
            .iter()
            .find_map(|event| match event {
                ParsedEvent::CopyinData { data, .. } => Some(data.clone()),
                _ => None,
            })
            .expect("copyin for top-level payload should exist");
        assert_eq!(copyin, payload);

        let addr_args = events
            .iter()
            .filter_map(|event| match event {
                ParsedEvent::AddrArg { addr } => Some(*addr),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(addr_args.len(), 1);
    }

    #[test]
    fn top_level_direct_output_buffers_emit_reserved_copyin_and_address_arguments() {
        let descs = crate::description::parse_syscall_descs(
            r#"
                resource fd[4] = -1, 0
                syscall read@1(fd fd, buf buffer[out], count bytesize[buf, int32])
            "#,
        )
        .expect("read target should parse");
        let reserved = vec![0u8; 12];
        let prog = Program {
            calls: vec![Call {
                syscall_idx: 0,
                args: vec![
                    ArgValue::Const(0),
                    ArgValue::Buffer(reserved.clone()),
                    ArgValue::Const(reserved.len() as u64),
                ],
            }],
        };

        let data =
            serialize_program(&prog, &descs).expect("top-level output buffer should serialize");
        let events = parse_exec_events(&data);

        let copyin = events
            .iter()
            .find_map(|event| match event {
                ParsedEvent::CopyinData { data, .. } => Some(data.clone()),
                _ => None,
            })
            .expect("reserved copyin for top-level output buffer should exist");
        assert_eq!(copyin, reserved);

        let addr_args = events
            .iter()
            .filter_map(|event| match event {
                ParsedEvent::AddrArg { addr } => Some(*addr),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(addr_args.len(), 1);

        let count_arg = events
            .iter()
            .find_map(|event| match event {
                ParsedEvent::ConstArg { value, .. } if *value == 12 => Some(*value),
                _ => None,
            })
            .expect("derived read size should be serialized");
        assert_eq!(count_arg, 12);
    }

    #[test]
    fn test_inline_pointer_struct_emits_nested_copyins() {
        let descs = crate::description::parse_syscall_descs(
            r#"
                type iovec {
                    base ptr[in, array[int8, 4:8]]
                    len len[base, intptr]
                } [size[16]]
                syscall writev@8027 -> int(fd const[1, int32], iov ptr[in, iovec], iovcnt const[1, int32])
            "#,
        )
        .expect("iovec target should parse");
        let payload = b"abcdef".to_vec();
        let prog = Program {
            calls: vec![Call {
                syscall_idx: 0,
                args: vec![
                    ArgValue::Const(1),
                    ArgValue::Composite {
                        data: encode_scalar_bytes(8, 0)
                            .into_iter()
                            .chain(encode_scalar_bytes(8, payload.len() as u64))
                            .collect(),
                        pointers: vec![InlinePointerValue {
                            offset: 0,
                            value: Box::new(ArgValue::Buffer(payload.clone())),
                        }],
                        struct_layouts: Vec::new(),
                    },
                    ArgValue::Const(1),
                ],
            }],
        };

        let data = serialize_program(&prog, &descs).expect("composite iovec should serialize");
        let events = parse_exec_events(&data);
        let copyins: Vec<(u64, Vec<u8>)> = events
            .iter()
            .filter_map(|event| match event {
                ParsedEvent::CopyinData { addr, data } => Some((*addr, data.clone())),
                _ => None,
            })
            .collect();
        assert_eq!(copyins.len(), 2);

        let nested_copyin = copyins
            .iter()
            .find(|(_, data)| data.as_slice() == payload.as_slice())
            .expect("nested payload copyin should exist");
        let root_copyin = copyins
            .iter()
            .find(|(_, data)| data.len() == 16)
            .expect("root iovec copyin should exist");

        assert_ne!(nested_copyin.0, root_copyin.0);
        let nested_absolute_addr = DATA_OFFSET + nested_copyin.0;
        assert_eq!(&root_copyin.1[0..8], &nested_absolute_addr.to_le_bytes());
        assert_eq!(&root_copyin.1[8..16], &(payload.len() as u64).to_le_bytes());
    }

    #[test]
    fn inline_iovec_out_arrays_emit_nested_reserved_output_copyins() {
        let descs = crate::description::parse_syscall_descs(
            r#"
                resource fd[4] = -1, 0
                type iovec_out {
                    base ptr[out, array[int8, 4:16]]
                    len len[base, intptr]
                } [size[16]]
                syscall readv@1(fd fd, vec ptr[in, array[iovec_out, 1:2]], vlen const[2, intptr])
            "#,
        )
        .expect("readv target should parse");

        let prog = Program {
            calls: vec![Call {
                syscall_idx: 0,
                args: vec![
                    ArgValue::Const(0),
                    ArgValue::Array {
                        data: encode_scalar_bytes(8, 0)
                            .into_iter()
                            .chain(encode_scalar_bytes(8, 5))
                            .chain(encode_scalar_bytes(8, 0))
                            .chain(encode_scalar_bytes(8, 7))
                            .collect(),
                        pointers: vec![
                            InlinePointerValue {
                                offset: 0,
                                value: Box::new(ArgValue::Buffer(vec![0; 5])),
                            },
                            InlinePointerValue {
                                offset: 16,
                                value: Box::new(ArgValue::Buffer(vec![0; 7])),
                            },
                        ],
                        element_sizes: vec![16, 16],
                        struct_layouts: Vec::new(),
                    },
                    ArgValue::Const(2),
                ],
            }],
        };

        let data = serialize_program(&prog, &descs).expect("readv iovec array should serialize");
        let events = parse_exec_events(&data);
        let copyins: Vec<(u64, Vec<u8>)> = events
            .iter()
            .filter_map(|event| match event {
                ParsedEvent::CopyinData { addr, data } => Some((*addr, data.clone())),
                _ => None,
            })
            .collect();
        assert_eq!(copyins.len(), 3);

        let root_copyin = copyins
            .iter()
            .find(|(_, data)| data.len() == 32)
            .expect("root iovec array copyin should exist");
        let nested_copyins = copyins
            .iter()
            .filter(|(_, data)| data.len() == 5 || data.len() == 7)
            .collect::<Vec<_>>();
        assert_eq!(nested_copyins.len(), 2);
        assert!(nested_copyins
            .iter()
            .all(|(_, data)| data.iter().all(|byte| *byte == 0)));

        let nested0_absolute_addr = DATA_OFFSET + nested_copyins[0].0;
        let nested1_absolute_addr = DATA_OFFSET + nested_copyins[1].0;
        let root = &root_copyin.1;
        let first_ptr = u64::from_le_bytes(root[0..8].try_into().unwrap());
        let first_len = u64::from_le_bytes(root[8..16].try_into().unwrap());
        let second_ptr = u64::from_le_bytes(root[16..24].try_into().unwrap());
        let second_len = u64::from_le_bytes(root[24..32].try_into().unwrap());

        assert_eq!(first_len, 5);
        assert_eq!(second_len, 7);
        let pointer_addrs = [first_ptr, second_ptr];
        assert!(pointer_addrs.contains(&nested0_absolute_addr));
        assert!(pointer_addrs.contains(&nested1_absolute_addr));

        let addr_args = events
            .iter()
            .filter_map(|event| match event {
                ParsedEvent::AddrArg { addr } => Some(*addr),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(addr_args.len(), 1);
    }

    #[test]
    fn inout_structs_with_nested_inout_buffers_emit_root_and_nested_copyins() {
        let descs = crate::description::parse_syscall_descs(
            r#"
                resource fd[4] = -1, 0
                type ifconf_buf {
                    ifc_len len[ifcu_buf, int32]
                    ifcu_buf ptr[inout, array[int8, 40:160]]
                } [size[16]]
                syscall ioctl_ifconf@1(fd fd, cmd const[35090, intptr], arg ptr[inout, ifconf_buf])
            "#,
        )
        .expect("ifconf target should parse");

        let prog = Program {
            calls: vec![Call {
                syscall_idx: 0,
                args: vec![
                    ArgValue::Const(0),
                    ArgValue::Const(35090),
                    ArgValue::Composite {
                        data: encode_scalar_bytes(4, 64)
                            .into_iter()
                            .chain([0u8; 4])
                            .chain(encode_scalar_bytes(8, 0))
                            .collect(),
                        pointers: vec![InlinePointerValue {
                            offset: 8,
                            value: Box::new(ArgValue::Buffer(vec![0; 64])),
                        }],
                        struct_layouts: Vec::new(),
                    },
                ],
            }],
        };

        let data = serialize_program(&prog, &descs).expect("ifconf program should serialize");
        let events = parse_exec_events(&data);
        let copyins: Vec<(u64, Vec<u8>)> = events
            .iter()
            .filter_map(|event| match event {
                ParsedEvent::CopyinData { addr, data } => Some((*addr, data.clone())),
                _ => None,
            })
            .collect();
        assert_eq!(copyins.len(), 2);

        let root_copyin = copyins
            .iter()
            .find(|(_, data)| data.len() == 16)
            .expect("root ifconf copyin should exist");
        let nested_copyin = copyins
            .iter()
            .find(|(_, data)| data.len() == 64)
            .expect("nested ifconf buffer copyin should exist");

        assert!(nested_copyin.1.iter().all(|byte| *byte == 0));
        let nested_absolute_addr = DATA_OFFSET + nested_copyin.0;
        assert_eq!(
            &root_copyin.1[8..16],
            &nested_absolute_addr.to_le_bytes(),
            "ifconf pointer slot should point at nested buffer",
        );
        assert_eq!(
            u32::from_le_bytes(root_copyin.1[0..4].try_into().unwrap()),
            64,
            "ifconf length field should preserve nested buffer size",
        );
    }

    #[test]
    fn top_level_inout_buffers_emit_copyin_and_address_arguments() {
        let descs = crate::description::parse_syscall_descs(
            r#"
                resource fd[4] = -1, 0
                syscall ioctl_probe@1(fd fd, cmd const[21531, intptr], arg buffer[inout])
            "#,
        )
        .expect("inout buffer target should parse");
        let payload = vec![0x11u8, 0x22, 0x33, 0x44];
        let prog = Program {
            calls: vec![Call {
                syscall_idx: 0,
                args: vec![
                    ArgValue::Const(0),
                    ArgValue::Const(21531),
                    ArgValue::Buffer(payload.clone()),
                ],
            }],
        };

        let data =
            serialize_program(&prog, &descs).expect("top-level inout buffer should serialize");
        let events = parse_exec_events(&data);

        let copyin = events
            .iter()
            .find_map(|event| match event {
                ParsedEvent::CopyinData { data, .. } => Some(data.clone()),
                _ => None,
            })
            .expect("copyin for top-level inout payload should exist");
        assert_eq!(copyin, payload);

        let addr_args = events
            .iter()
            .filter_map(|event| match event {
                ParsedEvent::AddrArg { addr } => Some(*addr),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(addr_args.len(), 1);
    }

    #[test]
    fn inout_structs_with_nested_inout_struct_pointers_emit_root_and_nested_copyins() {
        let descs = crate::description::parse_syscall_descs(
            r#"
                resource fd[4] = -1, 0
                type ethtool_drvinfo {
                    cmd const[3, int32]
                    driver array[int8, 32]
                }
                type ifreq_ethtool {
                    ifr_name string["lo", 16]
                    ifr_data ptr[inout, ethtool_drvinfo]
                    pad array[int8, 16]
                } [size[40]]
                syscall ioctl_ethtool@1(fd fd, cmd const[35142, intptr], arg ptr[inout, ifreq_ethtool])
            "#,
        )
        .expect("ethtool target should parse");

        let mut ifr_name = vec![0u8; 16];
        ifr_name[0] = b'l';
        ifr_name[1] = b'o';
        let inner = ArgValue::Composite {
            data: encode_scalar_bytes(4, 3)
                .into_iter()
                .chain([0u8; 32])
                .collect(),
            pointers: Vec::new(),
            struct_layouts: Vec::new(),
        };
        let prog = Program {
            calls: vec![Call {
                syscall_idx: 0,
                args: vec![
                    ArgValue::Const(0),
                    ArgValue::Const(35142),
                    ArgValue::Composite {
                        data: ifr_name.into_iter().chain([0u8; 24]).collect(),
                        pointers: vec![InlinePointerValue {
                            offset: 16,
                            value: Box::new(inner),
                        }],
                        struct_layouts: Vec::new(),
                    },
                ],
            }],
        };

        let data = serialize_program(&prog, &descs).expect("ethtool program should serialize");
        let events = parse_exec_events(&data);
        let copyins: Vec<(u64, Vec<u8>)> = events
            .iter()
            .filter_map(|event| match event {
                ParsedEvent::CopyinData { addr, data } => Some((*addr, data.clone())),
                _ => None,
            })
            .collect();
        assert_eq!(copyins.len(), 2);

        let root_copyin = copyins
            .iter()
            .find(|(_, data)| data.len() == 40)
            .expect("root ifreq copyin should exist");
        let nested_copyin = copyins
            .iter()
            .find(|(_, data)| data.len() == 36)
            .expect("nested ethtool payload copyin should exist");

        assert_eq!(&nested_copyin.1[0..4], &3u32.to_le_bytes());
        let nested_absolute_addr = DATA_OFFSET + nested_copyin.0;
        assert_eq!(
            &root_copyin.1[16..24],
            &nested_absolute_addr.to_le_bytes(),
            "ifreq data pointer should point at nested ethtool payload",
        );
        assert_eq!(&root_copyin.1[0..3], b"lo\0");
    }

    #[test]
    fn inout_structs_with_nested_varlen_struct_pointers_emit_root_and_nested_copyins() {
        let descs = crate::description::parse_syscall_descs(
            r#"
                resource fd[4] = -1, 0
                type ethtool_perm_addr {
                    cmd const[32, int32]
                    size len[data, int32]
                    data array[int8, 6:32]
                }
                type ifreq_ethtool_perm_addr {
                    ifr_name string["lo", 16]
                    ifr_data ptr[inout, ethtool_perm_addr]
                    pad array[int8, 16]
                } [size[40]]
                syscall ioctl_ethtool_perm@1(fd fd, cmd const[35142, intptr], arg ptr[inout, ifreq_ethtool_perm_addr])
            "#,
        )
        .expect("ethtool perm-addr target should parse");

        let mut ifr_name = vec![0u8; 16];
        ifr_name[0] = b'l';
        ifr_name[1] = b'o';
        let payload_len = 12u32;
        let inner = ArgValue::Composite {
            data: encode_scalar_bytes(4, 32)
                .into_iter()
                .chain(encode_scalar_bytes(4, payload_len as u64))
                .chain((0..payload_len).map(|idx| idx as u8))
                .collect(),
            pointers: Vec::new(),
            struct_layouts: Vec::new(),
        };
        let prog = Program {
            calls: vec![Call {
                syscall_idx: 0,
                args: vec![
                    ArgValue::Const(0),
                    ArgValue::Const(35142),
                    ArgValue::Composite {
                        data: ifr_name.into_iter().chain([0u8; 24]).collect(),
                        pointers: vec![InlinePointerValue {
                            offset: 16,
                            value: Box::new(inner),
                        }],
                        struct_layouts: Vec::new(),
                    },
                ],
            }],
        };

        let data = serialize_program(&prog, &descs).expect("perm-addr program should serialize");
        let events = parse_exec_events(&data);
        let copyins: Vec<(u64, Vec<u8>)> = events
            .iter()
            .filter_map(|event| match event {
                ParsedEvent::CopyinData { addr, data } => Some((*addr, data.clone())),
                _ => None,
            })
            .collect();
        assert_eq!(copyins.len(), 2);

        let root_copyin = copyins
            .iter()
            .find(|(_, data)| data.len() == 40)
            .expect("root ifreq copyin should exist");
        let nested_copyin = copyins
            .iter()
            .find(|(_, data)| data.len() == 8 + payload_len as usize)
            .expect("nested perm-addr payload copyin should exist");

        assert_eq!(&nested_copyin.1[0..4], &32u32.to_le_bytes());
        assert_eq!(&nested_copyin.1[4..8], &payload_len.to_le_bytes());
        let nested_absolute_addr = DATA_OFFSET + nested_copyin.0;
        assert_eq!(
            &root_copyin.1[16..24],
            &nested_absolute_addr.to_le_bytes(),
            "ifreq data pointer should point at nested perm-addr payload",
        );
    }

    #[test]
    fn inout_structs_with_nested_counted_i64_arrays_emit_root_and_nested_copyins() {
        let descs = crate::description::parse_syscall_descs(
            r#"
                resource fd[4] = -1, 0
                type ethtool_stats {
                    cmd const[29, int32]
                    n_stats len[data, int32]
                    data array[int64, 1:4]
                }
                type ifreq_ethtool_stats {
                    ifr_name string["lo", 16]
                    ifr_data ptr[inout, ethtool_stats]
                    pad array[int8, 16]
                } [size[40]]
                syscall ioctl_ethtool_stats@1(fd fd, cmd const[35142, intptr], arg ptr[inout, ifreq_ethtool_stats])
            "#,
        )
        .expect("ethtool stats target should parse");

        let mut ifr_name = vec![0u8; 16];
        ifr_name[0] = b'l';
        ifr_name[1] = b'o';
        let count = 3u32;
        let inner = ArgValue::Composite {
            data: encode_scalar_bytes(4, 29)
                .into_iter()
                .chain(encode_scalar_bytes(4, count as u64))
                .chain(encode_scalar_bytes(8, 0x11))
                .chain(encode_scalar_bytes(8, 0x22))
                .chain(encode_scalar_bytes(8, 0x33))
                .collect(),
            pointers: Vec::new(),
            struct_layouts: Vec::new(),
        };
        let prog = Program {
            calls: vec![Call {
                syscall_idx: 0,
                args: vec![
                    ArgValue::Const(0),
                    ArgValue::Const(35142),
                    ArgValue::Composite {
                        data: ifr_name.into_iter().chain([0u8; 24]).collect(),
                        pointers: vec![InlinePointerValue {
                            offset: 16,
                            value: Box::new(inner),
                        }],
                        struct_layouts: Vec::new(),
                    },
                ],
            }],
        };

        let data = serialize_program(&prog, &descs).expect("stats program should serialize");
        let events = parse_exec_events(&data);
        let copyins: Vec<(u64, Vec<u8>)> = events
            .iter()
            .filter_map(|event| match event {
                ParsedEvent::CopyinData { addr, data } => Some((*addr, data.clone())),
                _ => None,
            })
            .collect();
        assert_eq!(copyins.len(), 2);

        let root_copyin = copyins
            .iter()
            .find(|(_, data)| data.len() == 40)
            .expect("root ifreq copyin should exist");
        let nested_copyin = copyins
            .iter()
            .find(|(_, data)| data.len() == 8 + (count as usize * 8))
            .expect("nested stats payload copyin should exist");

        assert_eq!(&nested_copyin.1[0..4], &29u32.to_le_bytes());
        assert_eq!(&nested_copyin.1[4..8], &count.to_le_bytes());
        let nested_absolute_addr = DATA_OFFSET + nested_copyin.0;
        assert_eq!(
            &root_copyin.1[16..24],
            &nested_absolute_addr.to_le_bytes(),
            "ifreq data pointer should point at nested stats payload",
        );
    }

    #[test]
    fn inout_structs_with_nested_counted_byte_arrays_emit_root_and_nested_copyins() {
        let descs = crate::description::parse_syscall_descs(
            r#"
                resource fd[4] = -1, 0
                type ethtool_gstrings {
                    cmd const[27, int32]
                    string_set const[1, int32]
                    len len[data, int32]
                    data array[int8, 32:128]
                }
                type ifreq_ethtool_gstrings {
                    ifr_name string["lo", 16]
                    ifr_data ptr[inout, ethtool_gstrings]
                    pad array[int8, 16]
                } [size[40]]
                syscall ioctl_ethtool_gstrings@1(fd fd, cmd const[35142, intptr], arg ptr[inout, ifreq_ethtool_gstrings])
            "#,
        )
        .expect("ethtool gstrings target should parse");

        let mut ifr_name = vec![0u8; 16];
        ifr_name[0] = b'l';
        ifr_name[1] = b'o';
        let payload_len = 64u32;
        let inner = ArgValue::Composite {
            data: encode_scalar_bytes(4, 27)
                .into_iter()
                .chain(encode_scalar_bytes(4, 1))
                .chain(encode_scalar_bytes(4, payload_len as u64))
                .chain((0..payload_len).map(|idx| b'A' + (idx % 26) as u8))
                .collect(),
            pointers: Vec::new(),
            struct_layouts: Vec::new(),
        };
        let prog = Program {
            calls: vec![Call {
                syscall_idx: 0,
                args: vec![
                    ArgValue::Const(0),
                    ArgValue::Const(35142),
                    ArgValue::Composite {
                        data: ifr_name.into_iter().chain([0u8; 24]).collect(),
                        pointers: vec![InlinePointerValue {
                            offset: 16,
                            value: Box::new(inner),
                        }],
                        struct_layouts: Vec::new(),
                    },
                ],
            }],
        };

        let data = serialize_program(&prog, &descs).expect("gstrings program should serialize");
        let events = parse_exec_events(&data);
        let copyins: Vec<(u64, Vec<u8>)> = events
            .iter()
            .filter_map(|event| match event {
                ParsedEvent::CopyinData { addr, data } => Some((*addr, data.clone())),
                _ => None,
            })
            .collect();
        assert_eq!(copyins.len(), 2);

        let root_copyin = copyins
            .iter()
            .find(|(_, data)| data.len() == 40)
            .expect("root ifreq copyin should exist");
        let nested_copyin = copyins
            .iter()
            .find(|(_, data)| data.len() == 12 + payload_len as usize)
            .expect("nested gstrings payload copyin should exist");

        assert_eq!(&nested_copyin.1[0..4], &27u32.to_le_bytes());
        assert_eq!(&nested_copyin.1[4..8], &1u32.to_le_bytes());
        assert_eq!(&nested_copyin.1[8..12], &payload_len.to_le_bytes());
        let nested_absolute_addr = DATA_OFFSET + nested_copyin.0;
        assert_eq!(
            &root_copyin.1[16..24],
            &nested_absolute_addr.to_le_bytes(),
            "ifreq data pointer should point at nested gstrings payload",
        );
    }

    #[test]
    fn inout_structs_with_nested_masked_i32_arrays_emit_root_and_nested_copyins() {
        let descs = crate::description::parse_syscall_descs(
            r#"
                resource fd[4] = -1, 0
                type ethtool_sset_info {
                    cmd const[55, int32]
                    reserved const[0, int32]
                    sset_mask const[2, int64]
                    data array[int32, 1:4]
                }
                type ifreq_ethtool_sset_info {
                    ifr_name string["lo", 16]
                    ifr_data ptr[inout, ethtool_sset_info]
                    pad array[int8, 16]
                } [size[40]]
                syscall ioctl_ethtool_sset_info@1(fd fd, cmd const[35142, intptr], arg ptr[inout, ifreq_ethtool_sset_info])
            "#,
        )
        .expect("ethtool sset-info target should parse");

        let mut ifr_name = vec![0u8; 16];
        ifr_name[0] = b'l';
        ifr_name[1] = b'o';
        let inner = ArgValue::Composite {
            data: encode_scalar_bytes(4, 55)
                .into_iter()
                .chain(encode_scalar_bytes(4, 0))
                .chain(encode_scalar_bytes(8, 2))
                .chain(encode_scalar_bytes(4, 0x11))
                .chain(encode_scalar_bytes(4, 0x22))
                .chain(encode_scalar_bytes(4, 0x33))
                .chain(encode_scalar_bytes(4, 0))
                .collect(),
            pointers: Vec::new(),
            struct_layouts: Vec::new(),
        };
        let prog = Program {
            calls: vec![Call {
                syscall_idx: 0,
                args: vec![
                    ArgValue::Const(0),
                    ArgValue::Const(35142),
                    ArgValue::Composite {
                        data: ifr_name.into_iter().chain([0u8; 24]).collect(),
                        pointers: vec![InlinePointerValue {
                            offset: 16,
                            value: Box::new(inner),
                        }],
                        struct_layouts: Vec::new(),
                    },
                ],
            }],
        };

        let data = serialize_program(&prog, &descs).expect("sset-info program should serialize");
        let events = parse_exec_events(&data);
        let copyins: Vec<(u64, Vec<u8>)> = events
            .iter()
            .filter_map(|event| match event {
                ParsedEvent::CopyinData { addr, data } => Some((*addr, data.clone())),
                _ => None,
            })
            .collect();
        assert_eq!(copyins.len(), 2);

        let root_copyin = copyins
            .iter()
            .find(|(_, data)| data.len() == 40)
            .expect("root ifreq copyin should exist");
        let nested_copyin = copyins
            .iter()
            .find(|(_, data)| data.len() == 32)
            .expect("nested sset-info payload copyin should exist");

        assert_eq!(&nested_copyin.1[0..4], &55u32.to_le_bytes());
        assert_eq!(&nested_copyin.1[4..8], &0u32.to_le_bytes());
        assert_eq!(&nested_copyin.1[8..16], &2u64.to_le_bytes());
        let nested_absolute_addr = DATA_OFFSET + nested_copyin.0;
        assert_eq!(
            &root_copyin.1[16..24],
            &nested_absolute_addr.to_le_bytes(),
            "ifreq data pointer should point at nested sset-info payload",
        );
    }

    #[test]
    fn inout_structs_with_nested_counted_struct_arrays_emit_root_and_nested_copyins() {
        let descs = crate::description::parse_syscall_descs(
            r#"
                resource fd[4] = -1, 0
                type ethtool_get_features_block {
                    available const[0, int32]
                    requested const[0, int32]
                    active const[0, int32]
                    never_changed const[0, int32]
                }
                type ethtool_gfeatures {
                    cmd const[58, int32]
                    size len[features, int32]
                    features array[ethtool_get_features_block, 1:4]
                }
                type ifreq_ethtool_gfeatures {
                    ifr_name string["lo", 16]
                    ifr_data ptr[inout, ethtool_gfeatures]
                    pad array[int8, 16]
                } [size[40]]
                syscall ioctl_ethtool_gfeatures@1(fd fd, cmd const[35142, intptr], arg ptr[inout, ifreq_ethtool_gfeatures])
            "#,
        )
        .expect("ethtool gfeatures target should parse");

        let mut ifr_name = vec![0u8; 16];
        ifr_name[0] = b'l';
        ifr_name[1] = b'o';
        let count = 2u32;
        let inner = ArgValue::Composite {
            data: encode_scalar_bytes(4, 58)
                .into_iter()
                .chain(encode_scalar_bytes(4, count as u64))
                .chain([0u8; 32])
                .collect(),
            pointers: Vec::new(),
            struct_layouts: Vec::new(),
        };
        let prog = Program {
            calls: vec![Call {
                syscall_idx: 0,
                args: vec![
                    ArgValue::Const(0),
                    ArgValue::Const(35142),
                    ArgValue::Composite {
                        data: ifr_name.into_iter().chain([0u8; 24]).collect(),
                        pointers: vec![InlinePointerValue {
                            offset: 16,
                            value: Box::new(inner),
                        }],
                        struct_layouts: Vec::new(),
                    },
                ],
            }],
        };

        let data = serialize_program(&prog, &descs).expect("gfeatures program should serialize");
        let events = parse_exec_events(&data);
        let copyins: Vec<(u64, Vec<u8>)> = events
            .iter()
            .filter_map(|event| match event {
                ParsedEvent::CopyinData { addr, data } => Some((*addr, data.clone())),
                _ => None,
            })
            .collect();
        assert_eq!(copyins.len(), 2);

        let root_copyin = copyins
            .iter()
            .find(|(_, data)| data.len() == 40 && &data[0..3] == b"lo\0")
            .expect("root ifreq copyin should exist");
        let nested_copyin = copyins
            .iter()
            .find(|(_, data)| data.len() == 40 && &data[0..4] == &58u32.to_le_bytes())
            .expect("nested gfeatures payload copyin should exist");

        assert_eq!(&nested_copyin.1[0..4], &58u32.to_le_bytes());
        assert_eq!(&nested_copyin.1[4..8], &count.to_le_bytes());
        let nested_absolute_addr = DATA_OFFSET + nested_copyin.0;
        assert_eq!(
            &root_copyin.1[16..24],
            &nested_absolute_addr.to_le_bytes(),
            "ifreq data pointer should point at nested gfeatures payload",
        );
    }

    #[test]
    fn inout_structs_with_mixed_header_and_trailing_i32_arrays_emit_copyins() {
        let descs = crate::description::parse_syscall_descs(
            r#"
                resource fd[4] = -1, 0
                type ethtool_link_settings_min {
                    cmd const[76, int32]
                    speed int32
                    duplex int8
                    port int8
                    phy_address int8
                    autoneg int8
                    mdio_support int8
                    eth_tp_mdix int8
                    eth_tp_mdix_ctrl int8
                    link_mode_masks_nwords len[link_mode_masks, int8]
                    reserved array[const[0, int32], 8]
                    link_mode_masks array[int32, 1:4]
                }
                type ifreq_ethtool_link_settings {
                    ifr_name string["lo", 16]
                    ifr_data ptr[inout, ethtool_link_settings_min]
                    pad array[int8, 16]
                } [size[40]]
                syscall ioctl_ethtool_link_settings@1(fd fd, cmd const[35142, intptr], arg ptr[inout, ifreq_ethtool_link_settings])
            "#,
        )
        .expect("ethtool link-settings target should parse");

        let mut ifr_name = vec![0u8; 16];
        ifr_name[0] = b'l';
        ifr_name[1] = b'o';
        let count = 2u8;
        let inner = ArgValue::Composite {
            data: encode_scalar_bytes(4, 76)
                .into_iter()
                .chain(encode_scalar_bytes(4, 0))
                .chain([0u8; 7])
                .chain([count])
                .chain([0u8; 32])
                .chain(encode_scalar_bytes(4, 0x11))
                .chain(encode_scalar_bytes(4, 0x22))
                .collect(),
            pointers: Vec::new(),
            struct_layouts: Vec::new(),
        };
        let prog = Program {
            calls: vec![Call {
                syscall_idx: 0,
                args: vec![
                    ArgValue::Const(0),
                    ArgValue::Const(35142),
                    ArgValue::Composite {
                        data: ifr_name.into_iter().chain([0u8; 24]).collect(),
                        pointers: vec![InlinePointerValue {
                            offset: 16,
                            value: Box::new(inner),
                        }],
                        struct_layouts: Vec::new(),
                    },
                ],
            }],
        };

        let data =
            serialize_program(&prog, &descs).expect("link-settings program should serialize");
        let events = parse_exec_events(&data);
        let copyins: Vec<(u64, Vec<u8>)> = events
            .iter()
            .filter_map(|event| match event {
                ParsedEvent::CopyinData { addr, data } => Some((*addr, data.clone())),
                _ => None,
            })
            .collect();
        assert_eq!(copyins.len(), 2);

        let root_copyin = copyins
            .iter()
            .find(|(_, data)| data.len() == 40 && &data[0..3] == b"lo\0")
            .expect("root ifreq copyin should exist");
        let nested_copyin = copyins
            .iter()
            .find(|(_, data)| data.len() == 56 && &data[0..4] == &76u32.to_le_bytes())
            .expect("nested link-settings payload copyin should exist");

        assert_eq!(&nested_copyin.1[0..4], &76u32.to_le_bytes());
        assert_eq!(nested_copyin.1[15], count);
        let nested_absolute_addr = DATA_OFFSET + nested_copyin.0;
        assert_eq!(
            &root_copyin.1[16..24],
            &nested_absolute_addr.to_le_bytes(),
            "ifreq data pointer should point at nested link-settings payload",
        );
    }

    #[test]
    fn inout_structs_with_fixed_mixed_headers_and_reserved_arrays_emit_copyins() {
        let descs = crate::description::parse_syscall_descs(
            r#"
                resource fd[4] = -1, 0
                type ethtool_ts_info {
                    cmd const[65, int32]
                    so_timestamping const[0, int32]
                    phc_index const[0, int32]
                    tx_types const[0, int32]
                    tx_reserved array[const[0, int32], 3]
                    rx_filters const[0, int32]
                    rx_reserved array[const[0, int32], 3]
                }
                type ifreq_ethtool_ts_info {
                    ifr_name string["lo", 16]
                    ifr_data ptr[inout, ethtool_ts_info]
                    pad array[int8, 16]
                } [size[40]]
                syscall ioctl_ethtool_ts_info@1(fd fd, cmd const[35142, intptr], arg ptr[inout, ifreq_ethtool_ts_info])
            "#,
        )
        .expect("ethtool ts-info target should parse");

        let mut ifr_name = vec![0u8; 16];
        ifr_name[0] = b'l';
        ifr_name[1] = b'o';
        let inner = ArgValue::Composite {
            data: encode_scalar_bytes(4, 65)
                .into_iter()
                .chain(encode_scalar_bytes(4, 0))
                .chain(encode_scalar_bytes(4, 0))
                .chain(encode_scalar_bytes(4, 0))
                .chain([0u8; 12])
                .chain(encode_scalar_bytes(4, 0))
                .chain([0u8; 12])
                .collect(),
            pointers: Vec::new(),
            struct_layouts: Vec::new(),
        };
        let prog = Program {
            calls: vec![Call {
                syscall_idx: 0,
                args: vec![
                    ArgValue::Const(0),
                    ArgValue::Const(35142),
                    ArgValue::Composite {
                        data: ifr_name.into_iter().chain([0u8; 24]).collect(),
                        pointers: vec![InlinePointerValue {
                            offset: 16,
                            value: Box::new(inner),
                        }],
                        struct_layouts: Vec::new(),
                    },
                ],
            }],
        };

        let data = serialize_program(&prog, &descs).expect("ts-info program should serialize");
        let events = parse_exec_events(&data);
        let copyins: Vec<(u64, Vec<u8>)> = events
            .iter()
            .filter_map(|event| match event {
                ParsedEvent::CopyinData { addr, data } => Some((*addr, data.clone())),
                _ => None,
            })
            .collect();
        assert_eq!(copyins.len(), 2);

        let root_copyin = copyins
            .iter()
            .find(|(_, data)| data.len() == 40 && &data[0..3] == b"lo\0")
            .expect("root ifreq copyin should exist");
        let nested_copyin = copyins
            .iter()
            .find(|(_, data)| data.len() == 44 && &data[0..4] == &65u32.to_le_bytes())
            .expect("nested ts-info payload copyin should exist");

        assert_eq!(&nested_copyin.1[0..4], &65u32.to_le_bytes());
        assert_eq!(&nested_copyin.1[4..8], &0u32.to_le_bytes());
        assert_eq!(&nested_copyin.1[8..12], &0u32.to_le_bytes());
        assert_eq!(&nested_copyin.1[12..16], &0u32.to_le_bytes());
        assert_eq!(&nested_copyin.1[16..28], &[0u8; 12]);
        assert_eq!(&nested_copyin.1[28..32], &0u32.to_le_bytes());
        assert_eq!(&nested_copyin.1[32..44], &[0u8; 12]);
        let nested_absolute_addr = DATA_OFFSET + nested_copyin.0;
        assert_eq!(
            &root_copyin.1[16..24],
            &nested_absolute_addr.to_le_bytes(),
            "ifreq data pointer should point at nested ts-info payload",
        );
    }

    #[test]
    fn inout_structs_with_fixed_i32_query_payloads_emit_copyins() {
        let descs = crate::description::parse_syscall_descs(
            r#"
                resource fd[4] = -1, 0
                type ethtool_channels {
                    cmd const[60, int32]
                    max_rx int32
                    max_tx int32
                    max_other int32
                    max_combined int32
                    rx_count int32
                    tx_count int32
                    other_count int32
                    combined_count int32
                }
                type ifreq_ethtool_channels {
                    ifr_name string["lo", 16]
                    ifr_data ptr[inout, ethtool_channels]
                    pad array[int8, 16]
                } [size[40]]
                syscall ioctl_ethtool_channels@1(fd fd, cmd const[35142, intptr], arg ptr[inout, ifreq_ethtool_channels])
            "#,
        )
        .expect("ethtool channels target should parse");

        let mut ifr_name = vec![0u8; 16];
        ifr_name[0] = b'l';
        ifr_name[1] = b'o';
        let inner = ArgValue::Composite {
            data: encode_scalar_bytes(4, 60)
                .into_iter()
                .chain(encode_scalar_bytes(4, 0))
                .chain(encode_scalar_bytes(4, 0))
                .chain(encode_scalar_bytes(4, 0))
                .chain(encode_scalar_bytes(4, 0))
                .chain(encode_scalar_bytes(4, 0))
                .chain(encode_scalar_bytes(4, 0))
                .chain(encode_scalar_bytes(4, 0))
                .chain(encode_scalar_bytes(4, 0))
                .collect(),
            pointers: Vec::new(),
            struct_layouts: Vec::new(),
        };
        let prog = Program {
            calls: vec![Call {
                syscall_idx: 0,
                args: vec![
                    ArgValue::Const(0),
                    ArgValue::Const(35142),
                    ArgValue::Composite {
                        data: ifr_name.into_iter().chain([0u8; 24]).collect(),
                        pointers: vec![InlinePointerValue {
                            offset: 16,
                            value: Box::new(inner),
                        }],
                        struct_layouts: Vec::new(),
                    },
                ],
            }],
        };

        let data =
            serialize_program(&prog, &descs).expect("ethtool channels program should serialize");
        let events = parse_exec_events(&data);
        let copyins: Vec<(u64, Vec<u8>)> = events
            .iter()
            .filter_map(|event| match event {
                ParsedEvent::CopyinData { addr, data } => Some((*addr, data.clone())),
                _ => None,
            })
            .collect();
        assert_eq!(copyins.len(), 2);

        let root_copyin = copyins
            .iter()
            .find(|(_, data)| data.len() == 40 && &data[0..3] == b"lo\0")
            .expect("root ifreq copyin should exist");
        let nested_copyin = copyins
            .iter()
            .find(|(_, data)| data.len() == 36 && &data[0..4] == &60u32.to_le_bytes())
            .expect("nested channels payload copyin should exist");

        assert_eq!(&nested_copyin.1[0..4], &60u32.to_le_bytes());
        assert_eq!(&nested_copyin.1[4..36], &[0u8; 32]);
        let nested_absolute_addr = DATA_OFFSET + nested_copyin.0;
        assert_eq!(
            &root_copyin.1[16..24],
            &nested_absolute_addr.to_le_bytes(),
            "ifreq data pointer should point at nested channels payload",
        );
    }

    #[test]
    fn inout_structs_with_fixed_ethtool_value_payloads_emit_copyins() {
        let descs = crate::description::parse_syscall_descs(
            r#"
                resource fd[4] = -1, 0
                type ethtool_msglvl_value {
                    cmd const[7, int32]
                    data int32
                }
                type ifreq_ethtool_msglvl_value {
                    ifr_name string["lo", 16]
                    ifr_data ptr[inout, ethtool_msglvl_value]
                    pad array[int8, 16]
                } [size[40]]
                syscall ioctl_ethtool_msglvl_value@1(fd fd, cmd const[35142, intptr], arg ptr[inout, ifreq_ethtool_msglvl_value])
            "#,
        )
        .expect("ethtool msglvl target should parse");

        let mut ifr_name = vec![0u8; 16];
        ifr_name[0] = b'l';
        ifr_name[1] = b'o';
        let inner = ArgValue::Composite {
            data: encode_scalar_bytes(4, 7)
                .into_iter()
                .chain(encode_scalar_bytes(4, 0))
                .collect(),
            pointers: Vec::new(),
            struct_layouts: Vec::new(),
        };
        let prog = Program {
            calls: vec![Call {
                syscall_idx: 0,
                args: vec![
                    ArgValue::Const(0),
                    ArgValue::Const(35142),
                    ArgValue::Composite {
                        data: ifr_name.into_iter().chain([0u8; 24]).collect(),
                        pointers: vec![InlinePointerValue {
                            offset: 16,
                            value: Box::new(inner),
                        }],
                        struct_layouts: Vec::new(),
                    },
                ],
            }],
        };

        let data =
            serialize_program(&prog, &descs).expect("ethtool msglvl program should serialize");
        let events = parse_exec_events(&data);
        let copyins: Vec<(u64, Vec<u8>)> = events
            .iter()
            .filter_map(|event| match event {
                ParsedEvent::CopyinData { addr, data } => Some((*addr, data.clone())),
                _ => None,
            })
            .collect();
        assert_eq!(copyins.len(), 2);

        let root_copyin = copyins
            .iter()
            .find(|(_, data)| data.len() == 40 && &data[0..3] == b"lo\0")
            .expect("root ifreq copyin should exist");
        let nested_copyin = copyins
            .iter()
            .find(|(_, data)| data.len() == 8 && &data[0..4] == &7u32.to_le_bytes())
            .expect("nested msglvl payload copyin should exist");

        assert_eq!(&nested_copyin.1[0..4], &7u32.to_le_bytes());
        assert_eq!(&nested_copyin.1[4..8], &0u32.to_le_bytes());
        let nested_absolute_addr = DATA_OFFSET + nested_copyin.0;
        assert_eq!(
            &root_copyin.1[16..24],
            &nested_absolute_addr.to_le_bytes(),
            "ifreq data pointer should point at nested msglvl payload",
        );
    }

    #[test]
    fn inout_structs_with_len_derived_i32_array_payloads_emit_copyins() {
        let descs = crate::description::parse_syscall_descs(
            r#"
                resource fd[4] = -1, 0
                type ethtool_rxfh_indir_min {
                    cmd const[56, int32]
                    size len[ring_index, int32]
                    ring_index array[int32, 1:4]
                }
                type ifreq_ethtool_rxfh_indir_min {
                    ifr_name string["lo", 16]
                    ifr_data ptr[inout, ethtool_rxfh_indir_min]
                    pad array[int8, 16]
                } [size[40]]
                syscall ioctl_ethtool_rxfh_indir_min@1(fd fd, cmd const[35142, intptr], arg ptr[inout, ifreq_ethtool_rxfh_indir_min])
            "#,
        )
        .expect("ethtool rxfh indir target should parse");

        let mut ifr_name = vec![0u8; 16];
        ifr_name[0] = b'l';
        ifr_name[1] = b'o';
        let entries = [1u32, 2u32, 3u32, 4u32];
        let entry_count = entries.len() as u32;
        let inner = ArgValue::Composite {
            data: encode_scalar_bytes(4, 56)
                .into_iter()
                .chain(encode_scalar_bytes(4, entry_count as u64))
                .chain(
                    entries
                        .into_iter()
                        .flat_map(|value| encode_scalar_bytes(4, value as u64)),
                )
                .collect(),
            pointers: Vec::new(),
            struct_layouts: Vec::new(),
        };
        let prog = Program {
            calls: vec![Call {
                syscall_idx: 0,
                args: vec![
                    ArgValue::Const(0),
                    ArgValue::Const(35142),
                    ArgValue::Composite {
                        data: ifr_name.into_iter().chain([0u8; 24]).collect(),
                        pointers: vec![InlinePointerValue {
                            offset: 16,
                            value: Box::new(inner),
                        }],
                        struct_layouts: Vec::new(),
                    },
                ],
            }],
        };

        let data =
            serialize_program(&prog, &descs).expect("ethtool rxfh indir program should serialize");
        let events = parse_exec_events(&data);
        let copyins: Vec<(u64, Vec<u8>)> = events
            .iter()
            .filter_map(|event| match event {
                ParsedEvent::CopyinData { addr, data } => Some((*addr, data.clone())),
                _ => None,
            })
            .collect();
        assert_eq!(copyins.len(), 2);

        let root_copyin = copyins
            .iter()
            .find(|(_, data)| data.len() == 40 && &data[0..3] == b"lo\0")
            .expect("root ifreq copyin should exist");
        let nested_copyin = copyins
            .iter()
            .find(|(_, data)| {
                data.len() == 8 + entry_count as usize * 4 && &data[0..4] == &56u32.to_le_bytes()
            })
            .expect("nested rxfh indir payload copyin should exist");

        assert_eq!(&nested_copyin.1[0..4], &56u32.to_le_bytes());
        assert_eq!(&nested_copyin.1[4..8], &entry_count.to_le_bytes());
        assert_eq!(&nested_copyin.1[8..12], &1u32.to_le_bytes());
        assert_eq!(&nested_copyin.1[12..16], &2u32.to_le_bytes());
        assert_eq!(&nested_copyin.1[16..20], &3u32.to_le_bytes());
        assert_eq!(&nested_copyin.1[20..24], &4u32.to_le_bytes());
        let nested_absolute_addr = DATA_OFFSET + nested_copyin.0;
        assert_eq!(
            &root_copyin.1[16..24],
            &nested_absolute_addr.to_le_bytes(),
            "ifreq data pointer should point at nested rxfh indir payload",
        );
    }

    #[test]
    fn inout_structs_with_mixed_headers_and_len_derived_i32_arrays_emit_copyins() {
        let descs = crate::description::parse_syscall_descs(
            r#"
                resource fd[4] = -1, 0
                type ethtool_rxfh_min {
                    cmd const[70, int32]
                    rss_context const[0, int32]
                    indir_size len[rss_config, int32]
                    key_size const[0, int32]
                    hfunc const[0, int8]
                    rsvd8_0 const[0, int8]
                    rsvd8_1 const[0, int8]
                    rsvd8_2 const[0, int8]
                    rsvd32 const[0, int32]
                    rss_config array[int32, 1:4]
                }
                type ifreq_ethtool_rxfh_min {
                    ifr_name string["lo", 16]
                    ifr_data ptr[inout, ethtool_rxfh_min]
                    pad array[int8, 16]
                } [size[40]]
                syscall ioctl_ethtool_rxfh_min@1(fd fd, cmd const[35142, intptr], arg ptr[inout, ifreq_ethtool_rxfh_min])
            "#,
        )
        .expect("ethtool rxfh target should parse");

        let mut ifr_name = vec![0u8; 16];
        ifr_name[0] = b'l';
        ifr_name[1] = b'o';
        let entries = [1u32, 2u32, 3u32, 4u32];
        let entry_count = entries.len() as u32;
        let inner = ArgValue::Composite {
            data: encode_scalar_bytes(4, 70)
                .into_iter()
                .chain(encode_scalar_bytes(4, 0))
                .chain(encode_scalar_bytes(4, entry_count as u64))
                .chain(encode_scalar_bytes(4, 0))
                .chain([0u8; 4])
                .chain(encode_scalar_bytes(4, 0))
                .chain(
                    entries
                        .into_iter()
                        .flat_map(|value| encode_scalar_bytes(4, value as u64)),
                )
                .collect(),
            pointers: Vec::new(),
            struct_layouts: Vec::new(),
        };
        let prog = Program {
            calls: vec![Call {
                syscall_idx: 0,
                args: vec![
                    ArgValue::Const(0),
                    ArgValue::Const(35142),
                    ArgValue::Composite {
                        data: ifr_name.into_iter().chain([0u8; 24]).collect(),
                        pointers: vec![InlinePointerValue {
                            offset: 16,
                            value: Box::new(inner),
                        }],
                        struct_layouts: Vec::new(),
                    },
                ],
            }],
        };

        let data = serialize_program(&prog, &descs).expect("ethtool rxfh program should serialize");
        let events = parse_exec_events(&data);
        let copyins: Vec<(u64, Vec<u8>)> = events
            .iter()
            .filter_map(|event| match event {
                ParsedEvent::CopyinData { addr, data } => Some((*addr, data.clone())),
                _ => None,
            })
            .collect();
        assert_eq!(copyins.len(), 2);

        let root_copyin = copyins
            .iter()
            .find(|(_, data)| data.len() == 40 && &data[0..3] == b"lo ")
            .expect("root ifreq copyin should exist");
        let nested_copyin = copyins
            .iter()
            .find(|(_, data)| data.len() == 40 && &data[0..4] == &70u32.to_le_bytes())
            .expect("nested rxfh payload copyin should exist");

        assert_eq!(&nested_copyin.1[0..4], &70u32.to_le_bytes());
        assert_eq!(&nested_copyin.1[4..8], &0u32.to_le_bytes());
        assert_eq!(&nested_copyin.1[8..12], &entry_count.to_le_bytes());
        assert_eq!(&nested_copyin.1[12..16], &0u32.to_le_bytes());
        assert_eq!(&nested_copyin.1[16..20], &[0u8; 4]);
        assert_eq!(&nested_copyin.1[20..24], &0u32.to_le_bytes());
        assert_eq!(&nested_copyin.1[24..28], &1u32.to_le_bytes());
        assert_eq!(&nested_copyin.1[28..32], &2u32.to_le_bytes());
        assert_eq!(&nested_copyin.1[32..36], &3u32.to_le_bytes());
        assert_eq!(&nested_copyin.1[36..40], &4u32.to_le_bytes());
        let nested_absolute_addr = DATA_OFFSET + nested_copyin.0;
        assert_eq!(
            &root_copyin.1[16..24],
            &nested_absolute_addr.to_le_bytes(),
            "ifreq data pointer should point at nested rxfh payload",
        );
    }

    #[test]
    fn inout_structs_with_mixed_headers_i32_arrays_and_trailing_bytes_emit_copyins() {
        let descs = crate::description::parse_syscall_descs(
            r#"
                resource fd[4] = -1, 0
                type ethtool_rxfh_keyed {
                    cmd const[70, int32]
                    rss_context const[0, int32]
                    indir_size len[rss_config, int32]
                    key_size len[key, int32]
                    hfunc const[0, int8]
                    rsvd8_0 const[0, int8]
                    rsvd8_1 const[0, int8]
                    rsvd8_2 const[0, int8]
                    rsvd32 const[0, int32]
                    rss_config array[int32, 1:4]
                    key array[int8, 4:16]
                }
                type ifreq_ethtool_rxfh_keyed {
                    ifr_name string["lo", 16]
                    ifr_data ptr[inout, ethtool_rxfh_keyed]
                    pad array[int8, 16]
                } [size[40]]
                syscall ioctl_ethtool_rxfh_keyed@1(fd fd, cmd const[35142, intptr], arg ptr[inout, ifreq_ethtool_rxfh_keyed])
            "#,
        )
        .expect("ethtool keyed rxfh target should parse");

        let mut ifr_name = vec![0u8; 16];
        ifr_name[0] = b'l';
        ifr_name[1] = b'o';
        let entries = [1u32, 2u32, 3u32, 4u32];
        let key = [0xa1u8, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x17, 0x28];
        let entry_count = entries.len() as u32;
        let key_len = key.len() as u32;
        let inner = ArgValue::Composite {
            data: encode_scalar_bytes(4, 70)
                .into_iter()
                .chain(encode_scalar_bytes(4, 0))
                .chain(encode_scalar_bytes(4, entry_count as u64))
                .chain(encode_scalar_bytes(4, key_len as u64))
                .chain([0u8; 4])
                .chain(encode_scalar_bytes(4, 0))
                .chain(
                    entries
                        .into_iter()
                        .flat_map(|value| encode_scalar_bytes(4, value as u64)),
                )
                .chain(key)
                .collect(),
            pointers: Vec::new(),
            struct_layouts: vec![InlineStructLayout {
                base_offset: 0,
                field_ranges: vec![
                    (0, 4),
                    (4, 8),
                    (8, 12),
                    (12, 16),
                    (16, 17),
                    (17, 18),
                    (18, 19),
                    (19, 20),
                    (20, 24),
                    (24, 40),
                    (40, 48),
                ],
            }],
        };
        let prog = Program {
            calls: vec![Call {
                syscall_idx: 0,
                args: vec![
                    ArgValue::Const(0),
                    ArgValue::Const(35142),
                    ArgValue::Composite {
                        data: ifr_name.into_iter().chain([0u8; 24]).collect(),
                        pointers: vec![InlinePointerValue {
                            offset: 16,
                            value: Box::new(inner),
                        }],
                        struct_layouts: Vec::new(),
                    },
                ],
            }],
        };

        let data =
            serialize_program(&prog, &descs).expect("ethtool keyed rxfh program should serialize");
        let events = parse_exec_events(&data);
        let copyins: Vec<(u64, Vec<u8>)> = events
            .iter()
            .filter_map(|event| match event {
                ParsedEvent::CopyinData { addr, data } => Some((*addr, data.clone())),
                _ => None,
            })
            .collect();
        assert_eq!(copyins.len(), 2);

        let root_copyin = copyins
            .iter()
            .find(|(_, data)| data.len() == 40 && &data[0..3] == b"lo ")
            .expect("root ifreq copyin should exist");
        let nested_copyin = copyins
            .iter()
            .find(|(_, data)| data.len() == 48 && &data[0..4] == &70u32.to_le_bytes())
            .expect("nested keyed rxfh payload copyin should exist");

        assert_eq!(&nested_copyin.1[0..4], &70u32.to_le_bytes());
        assert_eq!(&nested_copyin.1[4..8], &0u32.to_le_bytes());
        assert_eq!(&nested_copyin.1[8..12], &entry_count.to_le_bytes());
        assert_eq!(&nested_copyin.1[12..16], &key_len.to_le_bytes());
        assert_eq!(&nested_copyin.1[16..20], &[0u8; 4]);
        assert_eq!(&nested_copyin.1[20..24], &0u32.to_le_bytes());
        assert_eq!(&nested_copyin.1[24..28], &1u32.to_le_bytes());
        assert_eq!(&nested_copyin.1[28..32], &2u32.to_le_bytes());
        assert_eq!(&nested_copyin.1[32..36], &3u32.to_le_bytes());
        assert_eq!(&nested_copyin.1[36..40], &4u32.to_le_bytes());
        assert_eq!(&nested_copyin.1[40..48], &key);
        let nested_absolute_addr = DATA_OFFSET + nested_copyin.0;
        assert_eq!(
            &root_copyin.1[16..24],
            &nested_absolute_addr.to_le_bytes(),
            "ifreq data pointer should point at nested keyed rxfh payload",
        );
    }

    #[test]
    fn inout_structs_with_fixed_rxnfc_query_headers_emit_copyins() {
        let descs = crate::description::parse_syscall_descs(
            r#"
                resource fd[4] = -1, 0
                type ethtool_rxnfc_rule_cnt_min {
                    cmd const[46, int32]
                    flow_type const[0, int32]
                    data const[0, int64]
                    fs array[const[0, int8], 168]
                    rule_cnt const[0, int32]
                }
                type ifreq_ethtool_rxnfc_rule_cnt_min {
                    ifr_name string["lo", 16]
                    ifr_data ptr[inout, ethtool_rxnfc_rule_cnt_min]
                    pad array[int8, 16]
                } [size[40]]
                syscall ioctl_ethtool_rxnfc_rule_cnt_min@1(fd fd, cmd const[35142, intptr], arg ptr[inout, ifreq_ethtool_rxnfc_rule_cnt_min])
            "#,
        )
        .expect("ethtool rxnfc rule-count target should parse");

        let mut ifr_name = vec![0u8; 16];
        ifr_name[0] = b'l';
        ifr_name[1] = b'o';
        let mut inner_data = encode_scalar_bytes(4, 46)
            .into_iter()
            .chain(encode_scalar_bytes(4, 0))
            .chain(encode_scalar_bytes(8, 0))
            .chain([0u8; 168])
            .chain(encode_scalar_bytes(4, 0))
            .collect::<Vec<_>>();
        inner_data.extend([0u8; 4]);
        let inner = ArgValue::Composite {
            data: inner_data,
            pointers: Vec::new(),
            struct_layouts: Vec::new(),
        };
        let prog = Program {
            calls: vec![Call {
                syscall_idx: 0,
                args: vec![
                    ArgValue::Const(0),
                    ArgValue::Const(35142),
                    ArgValue::Composite {
                        data: ifr_name.into_iter().chain([0u8; 24]).collect(),
                        pointers: vec![InlinePointerValue {
                            offset: 16,
                            value: Box::new(inner),
                        }],
                        struct_layouts: Vec::new(),
                    },
                ],
            }],
        };

        let data = serialize_program(&prog, &descs)
            .expect("ethtool rxnfc rule-count program should serialize");
        let events = parse_exec_events(&data);
        let copyins: Vec<(u64, Vec<u8>)> = events
            .iter()
            .filter_map(|event| match event {
                ParsedEvent::CopyinData { addr, data } => Some((*addr, data.clone())),
                _ => None,
            })
            .collect();
        assert_eq!(copyins.len(), 2);

        let root_copyin = copyins
            .iter()
            .find(|(_, data)| data.len() == 40 && &data[0..3] == b"lo ")
            .expect("root ifreq copyin should exist");
        let nested_copyin = copyins
            .iter()
            .find(|(_, data)| data.len() == 192 && &data[0..4] == &46u32.to_le_bytes())
            .expect("nested rxnfc query payload copyin should exist");

        assert_eq!(&nested_copyin.1[0..4], &46u32.to_le_bytes());
        assert_eq!(&nested_copyin.1[4..8], &0u32.to_le_bytes());
        assert_eq!(&nested_copyin.1[8..16], &0u64.to_le_bytes());
        assert_eq!(&nested_copyin.1[16..184], &[0u8; 168]);
        assert_eq!(&nested_copyin.1[184..188], &0u32.to_le_bytes());
        assert_eq!(&nested_copyin.1[188..192], &[0u8; 4]);
        let nested_absolute_addr = DATA_OFFSET + nested_copyin.0;
        assert_eq!(
            &root_copyin.1[16..24],
            &nested_absolute_addr.to_le_bytes(),
            "ifreq data pointer should point at nested rxnfc query payload",
        );
    }

    #[test]
    fn inout_structs_with_rxnfc_rule_query_locations_emit_copyins() {
        let descs = crate::description::parse_syscall_descs(
            r#"
                resource fd[4] = -1, 0
                type ethtool_rx_flow_spec_query_min {
                    flow_type const[0, int32]
                    payload array[const[0, int8], 148]
                    ring_cookie const[0, int64]
                    location int32
                    pad array[const[0, int8], 4]
                }
                type ethtool_rxnfc_rule_query_min {
                    cmd const[47, int32]
                    flow_type const[0, int32]
                    data const[0, int64]
                    fs ethtool_rx_flow_spec_query_min
                    rule_cnt const[0, int32]
                }
                type ifreq_ethtool_rxnfc_rule_query_min {
                    ifr_name string["lo", 16]
                    ifr_data ptr[inout, ethtool_rxnfc_rule_query_min]
                    pad array[int8, 16]
                } [size[40]]
                syscall ioctl_ethtool_rxnfc_rule_query_min@1(fd fd, cmd const[35142, intptr], arg ptr[inout, ifreq_ethtool_rxnfc_rule_query_min])
            "#,
        )
        .expect("ethtool rxnfc rule-query target should parse");

        let mut ifr_name = vec![0u8; 16];
        ifr_name[0] = b'l';
        ifr_name[1] = b'o';
        let location = 7u32;
        let inner = ArgValue::Composite {
            data: encode_scalar_bytes(4, 47)
                .into_iter()
                .chain(encode_scalar_bytes(4, 0))
                .chain(encode_scalar_bytes(8, 0))
                .chain(encode_scalar_bytes(4, 0))
                .chain([0u8; 148])
                .chain(encode_scalar_bytes(8, 0))
                .chain(encode_scalar_bytes(4, location as u64))
                .chain([0u8; 4])
                .chain(encode_scalar_bytes(4, 0))
                .chain([0u8; 4])
                .collect(),
            pointers: Vec::new(),
            struct_layouts: Vec::new(),
        };
        let prog = Program {
            calls: vec![Call {
                syscall_idx: 0,
                args: vec![
                    ArgValue::Const(0),
                    ArgValue::Const(35142),
                    ArgValue::Composite {
                        data: ifr_name.into_iter().chain([0u8; 24]).collect(),
                        pointers: vec![InlinePointerValue {
                            offset: 16,
                            value: Box::new(inner),
                        }],
                        struct_layouts: Vec::new(),
                    },
                ],
            }],
        };

        let data = serialize_program(&prog, &descs)
            .expect("ethtool rxnfc rule-query program should serialize");
        let events = parse_exec_events(&data);
        let copyins: Vec<(u64, Vec<u8>)> = events
            .iter()
            .filter_map(|event| match event {
                ParsedEvent::CopyinData { addr, data } => Some((*addr, data.clone())),
                _ => None,
            })
            .collect();
        assert_eq!(copyins.len(), 2);

        let root_copyin = copyins
            .iter()
            .find(|(_, data)| data.len() == 40 && &data[0..3] == b"lo ")
            .expect("root ifreq copyin should exist");
        let nested_copyin = copyins
            .iter()
            .find(|(_, data)| data.len() == 192 && &data[0..4] == &47u32.to_le_bytes())
            .expect("nested rxnfc rule-query payload copyin should exist");

        assert_eq!(&nested_copyin.1[0..4], &47u32.to_le_bytes());
        assert_eq!(&nested_copyin.1[4..8], &0u32.to_le_bytes());
        assert_eq!(&nested_copyin.1[8..16], &0u64.to_le_bytes());
        assert_eq!(&nested_copyin.1[16..20], &0u32.to_le_bytes());
        assert_eq!(&nested_copyin.1[20..168], &[0u8; 148]);
        assert_eq!(&nested_copyin.1[168..176], &0u64.to_le_bytes());
        assert_eq!(&nested_copyin.1[176..180], &location.to_le_bytes());
        assert_eq!(&nested_copyin.1[180..184], &[0u8; 4]);
        assert_eq!(&nested_copyin.1[184..188], &0u32.to_le_bytes());
        assert_eq!(&nested_copyin.1[188..192], &[0u8; 4]);
        let nested_absolute_addr = DATA_OFFSET + nested_copyin.0;
        assert_eq!(
            &root_copyin.1[16..24],
            &nested_absolute_addr.to_le_bytes(),
            "ifreq data pointer should point at nested rxnfc rule-query payload",
        );
    }

    #[test]
    fn inout_structs_with_typed_tcp_v4_rxnfc_rule_queries_emit_copyins() {
        let descs = crate::description::parse_syscall_descs(
            r#"
                resource fd[4] = -1, 0
                const TCP_V4_FLOW = 1
                type ethtool_tcpip4_spec_min {
                    ip4src int32
                    ip4dst int32
                    psrc int16
                    pdst int16
                    tos int8
                    pad array[const[0, int8], 3]
                }
                type ethtool_flow_union_tcp_v4_min {
                    tcp ethtool_tcpip4_spec_min
                    pad array[const[0, int8], 36]
                }
                type ethtool_rx_flow_spec_tcp_v4_query_min {
                    flow_type const[TCP_V4_FLOW, int32]
                    h_u ethtool_flow_union_tcp_v4_min
                    h_ext array[const[0, int8], 20]
                    m_u array[const[0, int8], 52]
                    m_ext array[const[0, int8], 20]
                    align_pad array[const[0, int8], 4]
                    ring_cookie const[0, int64]
                    location int32
                    pad array[const[0, int8], 4]
                }
                type ethtool_rxnfc_tcp_v4_query_min {
                    cmd const[47, int32]
                    flow_type const[TCP_V4_FLOW, int32]
                    data const[0, int64]
                    fs ethtool_rx_flow_spec_tcp_v4_query_min
                    rule_cnt const[0, int32]
                }
                type ifreq_ethtool_rxnfc_tcp_v4_query_min {
                    ifr_name string["lo", 16]
                    ifr_data ptr[inout, ethtool_rxnfc_tcp_v4_query_min]
                    pad array[int8, 16]
                } [size[40]]
                syscall ioctl_ethtool_rxnfc_tcp_v4_query_min@1(fd fd, cmd const[35142, intptr], arg ptr[inout, ifreq_ethtool_rxnfc_tcp_v4_query_min])
            "#,
        )
        .expect("typed ethtool rxnfc tcp_v4 target should parse");

        let mut ifr_name = vec![0u8; 16];
        ifr_name[0] = b'l';
        ifr_name[1] = b'o';
        let flow = 1u32;
        let ip4src = 0x01020304u32;
        let ip4dst = 0x05060708u32;
        let psrc = 0x1112u16;
        let pdst = 0x1314u16;
        let tos = 0x15u8;
        let location = 9u32;
        let inner = ArgValue::Composite {
            data: encode_scalar_bytes(4, 47)
                .into_iter()
                .chain(encode_scalar_bytes(4, flow as u64))
                .chain(encode_scalar_bytes(8, 0))
                .chain(encode_scalar_bytes(4, flow as u64))
                .chain(encode_scalar_bytes(4, ip4src as u64))
                .chain(encode_scalar_bytes(4, ip4dst as u64))
                .chain(encode_scalar_bytes(2, psrc as u64))
                .chain(encode_scalar_bytes(2, pdst as u64))
                .chain(encode_scalar_bytes(1, tos as u64))
                .chain([0u8; 3])
                .chain([0u8; 36])
                .chain([0u8; 20])
                .chain([0u8; 52])
                .chain([0u8; 20])
                .chain([0u8; 4])
                .chain(encode_scalar_bytes(8, 0))
                .chain(encode_scalar_bytes(4, location as u64))
                .chain([0u8; 4])
                .chain(encode_scalar_bytes(4, 0))
                .chain([0u8; 4])
                .collect(),
            pointers: Vec::new(),
            struct_layouts: Vec::new(),
        };
        let prog = Program {
            calls: vec![Call {
                syscall_idx: 0,
                args: vec![
                    ArgValue::Const(0),
                    ArgValue::Const(35142),
                    ArgValue::Composite {
                        data: ifr_name.into_iter().chain([0u8; 24]).collect(),
                        pointers: vec![InlinePointerValue {
                            offset: 16,
                            value: Box::new(inner),
                        }],
                        struct_layouts: Vec::new(),
                    },
                ],
            }],
        };

        let data = serialize_program(&prog, &descs)
            .expect("typed ethtool rxnfc tcp_v4 program should serialize");
        let events = parse_exec_events(&data);
        let copyins: Vec<(u64, Vec<u8>)> = events
            .iter()
            .filter_map(|event| match event {
                ParsedEvent::CopyinData { addr, data } => Some((*addr, data.clone())),
                _ => None,
            })
            .collect();
        assert_eq!(copyins.len(), 2);

        let root_copyin = copyins
            .iter()
            .find(|(_, data)| data.len() == 40 && &data[0..3] == b"lo ")
            .expect("root ifreq copyin should exist");
        let nested_copyin = copyins
            .iter()
            .find(|(_, data)| data.len() == 192 && &data[0..4] == &47u32.to_le_bytes())
            .expect("nested typed rxnfc payload copyin should exist");

        assert_eq!(&nested_copyin.1[0..4], &47u32.to_le_bytes());
        assert_eq!(&nested_copyin.1[4..8], &flow.to_le_bytes());
        assert_eq!(&nested_copyin.1[8..16], &0u64.to_le_bytes());
        assert_eq!(&nested_copyin.1[16..20], &flow.to_le_bytes());
        assert_eq!(&nested_copyin.1[20..24], &ip4src.to_le_bytes());
        assert_eq!(&nested_copyin.1[24..28], &ip4dst.to_le_bytes());
        assert_eq!(&nested_copyin.1[28..30], &psrc.to_le_bytes());
        assert_eq!(&nested_copyin.1[30..32], &pdst.to_le_bytes());
        assert_eq!(nested_copyin.1[32], tos);
        assert_eq!(&nested_copyin.1[33..36], &[0u8; 3]);
        assert_eq!(&nested_copyin.1[36..72], &[0u8; 36]);
        assert_eq!(&nested_copyin.1[72..92], &[0u8; 20]);
        assert_eq!(&nested_copyin.1[92..144], &[0u8; 52]);
        assert_eq!(&nested_copyin.1[144..164], &[0u8; 20]);
        assert_eq!(&nested_copyin.1[164..168], &[0u8; 4]);
        assert_eq!(&nested_copyin.1[168..176], &0u64.to_le_bytes());
        assert_eq!(&nested_copyin.1[176..180], &location.to_le_bytes());
        assert_eq!(&nested_copyin.1[180..184], &[0u8; 4]);
        assert_eq!(&nested_copyin.1[184..188], &0u32.to_le_bytes());
        assert_eq!(&nested_copyin.1[188..192], &[0u8; 4]);
        let nested_absolute_addr = DATA_OFFSET + nested_copyin.0;
        assert_eq!(
            &root_copyin.1[16..24],
            &nested_absolute_addr.to_le_bytes(),
            "ifreq data pointer should point at nested typed rxnfc payload",
        );
    }

    #[test]
    fn inout_structs_with_typed_tcp_v4_ext_rxnfc_rule_queries_emit_copyins() {
        let descs = crate::description::parse_syscall_descs(
            r#"
                resource fd[4] = -1, 0
                const TCP_V4_FLOW_EXT = -2147483647
                type ethtool_tcpip4_spec_min {
                    ip4src int32
                    ip4dst int32
                    psrc int16
                    pdst int16
                    tos int8
                    pad array[const[0, int8], 3]
                }
                type ethtool_flow_union_tcp_v4_min {
                    tcp ethtool_tcpip4_spec_min
                    pad array[const[0, int8], 36]
                }
                type ethtool_flow_ext_min {
                    padding array[const[0, int8], 2]
                    h_dest array[int8, 6]
                    vlan_etype int16
                    vlan_tci int16
                    data array[int32, 2]
                }
                type ethtool_rx_flow_spec_tcp_v4_ext_query_min {
                    flow_type const[TCP_V4_FLOW_EXT, int32]
                    h_u ethtool_flow_union_tcp_v4_min
                    h_ext ethtool_flow_ext_min
                    m_u array[const[0, int8], 52]
                    m_ext ethtool_flow_ext_min
                    align_pad array[const[0, int8], 4]
                    ring_cookie const[0, int64]
                    location int32
                    pad array[const[0, int8], 4]
                }
                type ethtool_rxnfc_tcp_v4_ext_query_min {
                    cmd const[47, int32]
                    flow_type const[TCP_V4_FLOW_EXT, int32]
                    data const[0, int64]
                    fs ethtool_rx_flow_spec_tcp_v4_ext_query_min
                    rule_cnt const[0, int32]
                }
                type ifreq_ethtool_rxnfc_tcp_v4_ext_query_min {
                    ifr_name string["lo", 16]
                    ifr_data ptr[inout, ethtool_rxnfc_tcp_v4_ext_query_min]
                    pad array[int8, 16]
                } [size[40]]
                syscall ioctl_ethtool_rxnfc_tcp_v4_ext_query_min@1(fd fd, cmd const[35142, intptr], arg ptr[inout, ifreq_ethtool_rxnfc_tcp_v4_ext_query_min])
            "#,
        )
        .expect("typed ethtool rxnfc tcp_v4 ext target should parse");

        let mut ifr_name = vec![0u8; 16];
        ifr_name[0] = b'l';
        ifr_name[1] = b'o';
        let flow = 0x8000_0001u32;
        let ip4src = 0x0a000001u32;
        let ip4dst = 0x0a000002u32;
        let psrc = 0x1234u16;
        let pdst = 0x5678u16;
        let tos = 0x9au8;
        let h_dest = [1u8, 2, 3, 4, 5, 6];
        let vlan_etype = 0x8100u16;
        let vlan_tci = 0x1234u16;
        let ext_data0 = 0x11111111u32;
        let ext_data1 = 0x22222222u32;
        let mask_dest = [10u8, 20, 30, 40, 50, 60];
        let mask_vlan_etype = 0xffffu16;
        let mask_vlan_tci = 0x0ff0u16;
        let mask_data0 = 0x33333333u32;
        let mask_data1 = 0x44444444u32;
        let location = 13u32;
        let inner = ArgValue::Composite {
            data: encode_scalar_bytes(4, 47)
                .into_iter()
                .chain(encode_scalar_bytes(4, flow as u64))
                .chain(encode_scalar_bytes(8, 0))
                .chain(encode_scalar_bytes(4, flow as u64))
                .chain(encode_scalar_bytes(4, ip4src as u64))
                .chain(encode_scalar_bytes(4, ip4dst as u64))
                .chain(encode_scalar_bytes(2, psrc as u64))
                .chain(encode_scalar_bytes(2, pdst as u64))
                .chain(encode_scalar_bytes(1, tos as u64))
                .chain([0u8; 3])
                .chain([0u8; 36])
                .chain([0u8; 2])
                .chain(h_dest)
                .chain(encode_scalar_bytes(2, vlan_etype as u64))
                .chain(encode_scalar_bytes(2, vlan_tci as u64))
                .chain(encode_scalar_bytes(4, ext_data0 as u64))
                .chain(encode_scalar_bytes(4, ext_data1 as u64))
                .chain([0u8; 52])
                .chain([0u8; 2])
                .chain(mask_dest)
                .chain(encode_scalar_bytes(2, mask_vlan_etype as u64))
                .chain(encode_scalar_bytes(2, mask_vlan_tci as u64))
                .chain(encode_scalar_bytes(4, mask_data0 as u64))
                .chain(encode_scalar_bytes(4, mask_data1 as u64))
                .chain([0u8; 4])
                .chain(encode_scalar_bytes(8, 0))
                .chain(encode_scalar_bytes(4, location as u64))
                .chain([0u8; 4])
                .chain(encode_scalar_bytes(4, 0))
                .chain([0u8; 4])
                .collect(),
            pointers: Vec::new(),
            struct_layouts: Vec::new(),
        };
        let prog = Program {
            calls: vec![Call {
                syscall_idx: 0,
                args: vec![
                    ArgValue::Const(0),
                    ArgValue::Const(35142),
                    ArgValue::Composite {
                        data: ifr_name.into_iter().chain([0u8; 24]).collect(),
                        pointers: vec![InlinePointerValue {
                            offset: 16,
                            value: Box::new(inner),
                        }],
                        struct_layouts: Vec::new(),
                    },
                ],
            }],
        };

        let data = serialize_program(&prog, &descs)
            .expect("typed ethtool rxnfc tcp_v4 ext program should serialize");
        let events = parse_exec_events(&data);
        let copyins: Vec<(u64, Vec<u8>)> = events
            .iter()
            .filter_map(|event| match event {
                ParsedEvent::CopyinData { addr, data } => Some((*addr, data.clone())),
                _ => None,
            })
            .collect();
        assert_eq!(copyins.len(), 2);

        let root_copyin = copyins
            .iter()
            .find(|(_, data)| data.len() == 40 && &data[0..3] == b"lo ")
            .expect("root ifreq copyin should exist");
        let nested_copyin = copyins
            .iter()
            .find(|(_, data)| data.len() == 192 && &data[0..4] == &47u32.to_le_bytes())
            .expect("nested typed rxnfc ext payload copyin should exist");

        assert_eq!(&nested_copyin.1[0..4], &47u32.to_le_bytes());
        assert_eq!(&nested_copyin.1[4..8], &flow.to_le_bytes());
        assert_eq!(&nested_copyin.1[8..16], &0u64.to_le_bytes());
        assert_eq!(&nested_copyin.1[16..20], &flow.to_le_bytes());
        assert_eq!(&nested_copyin.1[20..24], &ip4src.to_le_bytes());
        assert_eq!(&nested_copyin.1[24..28], &ip4dst.to_le_bytes());
        assert_eq!(&nested_copyin.1[28..30], &psrc.to_le_bytes());
        assert_eq!(&nested_copyin.1[30..32], &pdst.to_le_bytes());
        assert_eq!(nested_copyin.1[32], tos);
        assert_eq!(&nested_copyin.1[33..36], &[0u8; 3]);
        assert_eq!(&nested_copyin.1[36..72], &[0u8; 36]);
        assert_eq!(&nested_copyin.1[72..74], &[0u8; 2]);
        assert_eq!(&nested_copyin.1[74..80], &h_dest);
        assert_eq!(&nested_copyin.1[80..82], &vlan_etype.to_le_bytes());
        assert_eq!(&nested_copyin.1[82..84], &vlan_tci.to_le_bytes());
        assert_eq!(&nested_copyin.1[84..88], &ext_data0.to_le_bytes());
        assert_eq!(&nested_copyin.1[88..92], &ext_data1.to_le_bytes());
        assert_eq!(&nested_copyin.1[92..144], &[0u8; 52]);
        assert_eq!(&nested_copyin.1[144..146], &[0u8; 2]);
        assert_eq!(&nested_copyin.1[146..152], &mask_dest);
        assert_eq!(&nested_copyin.1[152..154], &mask_vlan_etype.to_le_bytes());
        assert_eq!(&nested_copyin.1[154..156], &mask_vlan_tci.to_le_bytes());
        assert_eq!(&nested_copyin.1[156..160], &mask_data0.to_le_bytes());
        assert_eq!(&nested_copyin.1[160..164], &mask_data1.to_le_bytes());
        assert_eq!(&nested_copyin.1[164..168], &[0u8; 4]);
        assert_eq!(&nested_copyin.1[168..176], &0u64.to_le_bytes());
        assert_eq!(&nested_copyin.1[176..180], &location.to_le_bytes());
        assert_eq!(&nested_copyin.1[180..184], &[0u8; 4]);
        assert_eq!(&nested_copyin.1[184..188], &0u32.to_le_bytes());
        assert_eq!(&nested_copyin.1[188..192], &[0u8; 4]);
        let nested_absolute_addr = DATA_OFFSET + nested_copyin.0;
        assert_eq!(
            &root_copyin.1[16..24],
            &nested_absolute_addr.to_le_bytes(),
            "ifreq data pointer should point at nested typed rxnfc ext payload",
        );
    }
    #[test]
    fn inout_structs_with_typed_tcp_v4_mac_ext_rxnfc_rule_queries_emit_copyins() {
        let descs = crate::description::parse_syscall_descs(
            r#"
                resource fd[4] = -1, 0
                const TCP_V4_FLOW_MAC_EXT = 1073741825
                type ethtool_tcpip4_spec_min {
                    ip4src int32
                    ip4dst int32
                    psrc int16
                    pdst int16
                    tos int8
                    pad array[const[0, int8], 3]
                }
                type ethtool_flow_union_tcp_v4_min {
                    tcp ethtool_tcpip4_spec_min
                    pad array[const[0, int8], 36]
                }
                type ethtool_flow_ext_min {
                    padding array[const[0, int8], 2]
                    h_dest array[int8, 6]
                    vlan_etype int16
                    vlan_tci int16
                    data array[int32, 2]
                }
                type ethtool_rx_flow_spec_tcp_v4_mac_ext_query_min {
                    flow_type const[TCP_V4_FLOW_MAC_EXT, int32]
                    h_u ethtool_flow_union_tcp_v4_min
                    h_ext ethtool_flow_ext_min
                    m_u array[const[0, int8], 52]
                    m_ext ethtool_flow_ext_min
                    align_pad array[const[0, int8], 4]
                    ring_cookie const[0, int64]
                    location int32
                    pad array[const[0, int8], 4]
                }
                type ethtool_rxnfc_tcp_v4_mac_ext_query_min {
                    cmd const[47, int32]
                    flow_type const[TCP_V4_FLOW_MAC_EXT, int32]
                    data const[0, int64]
                    fs ethtool_rx_flow_spec_tcp_v4_mac_ext_query_min
                    rule_cnt const[0, int32]
                }
                type ifreq_ethtool_rxnfc_tcp_v4_mac_ext_query_min {
                    ifr_name string["lo", 16]
                    ifr_data ptr[inout, ethtool_rxnfc_tcp_v4_mac_ext_query_min]
                    pad array[int8, 16]
                } [size[40]]
                syscall ioctl_ethtool_rxnfc_tcp_v4_mac_ext_query_min@1(fd fd, cmd const[35142, intptr], arg ptr[inout, ifreq_ethtool_rxnfc_tcp_v4_mac_ext_query_min])
            "#,
        )
        .expect("typed ethtool rxnfc tcp_v4 mac ext target should parse");

        let mut ifr_name = vec![0u8; 16];
        ifr_name[0] = b'l';
        ifr_name[1] = b'o';
        let flow = 0x4000_0001u32;
        let ip4src = 0x0a000001u32;
        let ip4dst = 0x0a000002u32;
        let psrc = 0x1234u16;
        let pdst = 0x5678u16;
        let tos = 0x9au8;
        let h_dest = [1u8, 2, 3, 4, 5, 6];
        let vlan_etype = 0u16;
        let vlan_tci = 0u16;
        let ext_data0 = 0u32;
        let ext_data1 = 0u32;
        let mask_dest = [10u8, 20, 30, 40, 50, 60];
        let mask_vlan_etype = 0u16;
        let mask_vlan_tci = 0u16;
        let mask_data0 = 0u32;
        let mask_data1 = 0u32;
        let location = 13u32;
        let inner = ArgValue::Composite {
            data: encode_scalar_bytes(4, 47)
                .into_iter()
                .chain(encode_scalar_bytes(4, flow as u64))
                .chain(encode_scalar_bytes(8, 0))
                .chain(encode_scalar_bytes(4, flow as u64))
                .chain(encode_scalar_bytes(4, ip4src as u64))
                .chain(encode_scalar_bytes(4, ip4dst as u64))
                .chain(encode_scalar_bytes(2, psrc as u64))
                .chain(encode_scalar_bytes(2, pdst as u64))
                .chain(encode_scalar_bytes(1, tos as u64))
                .chain([0u8; 3])
                .chain([0u8; 36])
                .chain([0u8; 2])
                .chain(h_dest)
                .chain(encode_scalar_bytes(2, vlan_etype as u64))
                .chain(encode_scalar_bytes(2, vlan_tci as u64))
                .chain(encode_scalar_bytes(4, ext_data0 as u64))
                .chain(encode_scalar_bytes(4, ext_data1 as u64))
                .chain([0u8; 52])
                .chain([0u8; 2])
                .chain(mask_dest)
                .chain(encode_scalar_bytes(2, mask_vlan_etype as u64))
                .chain(encode_scalar_bytes(2, mask_vlan_tci as u64))
                .chain(encode_scalar_bytes(4, mask_data0 as u64))
                .chain(encode_scalar_bytes(4, mask_data1 as u64))
                .chain([0u8; 4])
                .chain(encode_scalar_bytes(8, 0))
                .chain(encode_scalar_bytes(4, location as u64))
                .chain([0u8; 4])
                .chain(encode_scalar_bytes(4, 0))
                .chain([0u8; 4])
                .collect(),
            pointers: Vec::new(),
            struct_layouts: Vec::new(),
        };
        let prog = Program {
            calls: vec![Call {
                syscall_idx: 0,
                args: vec![
                    ArgValue::Const(0),
                    ArgValue::Const(35142),
                    ArgValue::Composite {
                        data: ifr_name.into_iter().chain([0u8; 24]).collect(),
                        pointers: vec![InlinePointerValue {
                            offset: 16,
                            value: Box::new(inner),
                        }],
                        struct_layouts: Vec::new(),
                    },
                ],
            }],
        };

        let data = serialize_program(&prog, &descs)
            .expect("typed ethtool rxnfc tcp_v4 mac ext program should serialize");
        let events = parse_exec_events(&data);
        let copyins: Vec<(u64, Vec<u8>)> = events
            .iter()
            .filter_map(|event| match event {
                ParsedEvent::CopyinData { addr, data } => Some((*addr, data.clone())),
                _ => None,
            })
            .collect();
        assert_eq!(copyins.len(), 2);

        let root_copyin = copyins
            .iter()
            .find(|(_, data)| data.len() == 40 && &data[0..3] == b"lo ")
            .expect("root ifreq copyin should exist");
        let nested_copyin = copyins
            .iter()
            .find(|(_, data)| data.len() == 192 && &data[0..4] == &47u32.to_le_bytes())
            .expect("nested typed rxnfc mac ext payload copyin should exist");

        assert_eq!(&nested_copyin.1[0..4], &47u32.to_le_bytes());
        assert_eq!(&nested_copyin.1[4..8], &flow.to_le_bytes());
        assert_eq!(&nested_copyin.1[8..16], &0u64.to_le_bytes());
        assert_eq!(&nested_copyin.1[16..20], &flow.to_le_bytes());
        assert_eq!(&nested_copyin.1[20..24], &ip4src.to_le_bytes());
        assert_eq!(&nested_copyin.1[24..28], &ip4dst.to_le_bytes());
        assert_eq!(&nested_copyin.1[28..30], &psrc.to_le_bytes());
        assert_eq!(&nested_copyin.1[30..32], &pdst.to_le_bytes());
        assert_eq!(nested_copyin.1[32], tos);
        assert_eq!(&nested_copyin.1[33..36], &[0u8; 3]);
        assert_eq!(&nested_copyin.1[36..72], &[0u8; 36]);
        assert_eq!(&nested_copyin.1[72..74], &[0u8; 2]);
        assert_eq!(&nested_copyin.1[74..80], &h_dest);
        assert_eq!(&nested_copyin.1[80..82], &vlan_etype.to_le_bytes());
        assert_eq!(&nested_copyin.1[82..84], &vlan_tci.to_le_bytes());
        assert_eq!(&nested_copyin.1[84..88], &ext_data0.to_le_bytes());
        assert_eq!(&nested_copyin.1[88..92], &ext_data1.to_le_bytes());
        assert_eq!(&nested_copyin.1[92..144], &[0u8; 52]);
        assert_eq!(&nested_copyin.1[144..146], &[0u8; 2]);
        assert_eq!(&nested_copyin.1[146..152], &mask_dest);
        assert_eq!(&nested_copyin.1[152..154], &mask_vlan_etype.to_le_bytes());
        assert_eq!(&nested_copyin.1[154..156], &mask_vlan_tci.to_le_bytes());
        assert_eq!(&nested_copyin.1[156..160], &mask_data0.to_le_bytes());
        assert_eq!(&nested_copyin.1[160..164], &mask_data1.to_le_bytes());
        assert_eq!(&nested_copyin.1[164..168], &[0u8; 4]);
        assert_eq!(&nested_copyin.1[168..176], &0u64.to_le_bytes());
        assert_eq!(&nested_copyin.1[176..180], &location.to_le_bytes());
        assert_eq!(&nested_copyin.1[180..184], &[0u8; 4]);
        assert_eq!(&nested_copyin.1[184..188], &0u32.to_le_bytes());
        assert_eq!(&nested_copyin.1[188..192], &[0u8; 4]);
        let nested_absolute_addr = DATA_OFFSET + nested_copyin.0;
        assert_eq!(
            &root_copyin.1[16..24],
            &nested_absolute_addr.to_le_bytes(),
            "ifreq data pointer should point at nested typed rxnfc mac ext payload",
        );
    }
    #[test]
    fn inout_structs_with_rxnfc_rss_query_contexts_emit_copyins() {
        let descs = crate::description::parse_syscall_descs(
            r#"
                resource fd[4] = -1, 0
                const FLOW_RSS = 536870912
                type ethtool_rx_flow_spec_rss_query_min {
                    flow_type const[FLOW_RSS, int32]
                    payload array[const[0, int8], 148]
                    ring_cookie const[0, int64]
                    location int32
                    pad array[const[0, int8], 4]
                }
                type ethtool_rxnfc_rss_query_min {
                    cmd const[47, int32]
                    flow_type const[FLOW_RSS, int32]
                    data const[0, int64]
                    fs ethtool_rx_flow_spec_rss_query_min
                    rss_context int32
                }
                type ifreq_ethtool_rxnfc_rss_query_min {
                    ifr_name string["lo", 16]
                    ifr_data ptr[inout, ethtool_rxnfc_rss_query_min]
                    pad array[int8, 16]
                } [size[40]]
                syscall ioctl_ethtool_rxnfc_rss_query_min@1(fd fd, cmd const[35142, intptr], arg ptr[inout, ifreq_ethtool_rxnfc_rss_query_min])
            "#,
        )
        .expect("ethtool rxnfc rss-query target should parse");

        let mut ifr_name = vec![0u8; 16];
        ifr_name[0] = b'l';
        ifr_name[1] = b'o';
        let location = 11u32;
        let rss_context = 5u32;
        let flow_rss = 536_870_912u32;
        let inner = ArgValue::Composite {
            data: encode_scalar_bytes(4, 47)
                .into_iter()
                .chain(encode_scalar_bytes(4, flow_rss as u64))
                .chain(encode_scalar_bytes(8, 0))
                .chain(encode_scalar_bytes(4, flow_rss as u64))
                .chain([0u8; 148])
                .chain(encode_scalar_bytes(8, 0))
                .chain(encode_scalar_bytes(4, location as u64))
                .chain([0u8; 4])
                .chain(encode_scalar_bytes(4, rss_context as u64))
                .chain([0u8; 4])
                .collect(),
            pointers: Vec::new(),
            struct_layouts: Vec::new(),
        };
        let prog = Program {
            calls: vec![Call {
                syscall_idx: 0,
                args: vec![
                    ArgValue::Const(0),
                    ArgValue::Const(35142),
                    ArgValue::Composite {
                        data: ifr_name.into_iter().chain([0u8; 24]).collect(),
                        pointers: vec![InlinePointerValue {
                            offset: 16,
                            value: Box::new(inner),
                        }],
                        struct_layouts: Vec::new(),
                    },
                ],
            }],
        };

        let data = serialize_program(&prog, &descs)
            .expect("ethtool rxnfc rss-query program should serialize");
        let events = parse_exec_events(&data);
        let copyins: Vec<(u64, Vec<u8>)> = events
            .iter()
            .filter_map(|event| match event {
                ParsedEvent::CopyinData { addr, data } => Some((*addr, data.clone())),
                _ => None,
            })
            .collect();
        assert_eq!(copyins.len(), 2);

        let root_copyin = copyins
            .iter()
            .find(|(_, data)| data.len() == 40 && &data[0..3] == b"lo\0")
            .expect("root ifreq copyin should exist");
        let nested_copyin = copyins
            .iter()
            .find(|(_, data)| data.len() == 192 && &data[0..4] == &47u32.to_le_bytes())
            .expect("nested rxnfc rss-query payload copyin should exist");

        assert_eq!(&nested_copyin.1[0..4], &47u32.to_le_bytes());
        assert_eq!(&nested_copyin.1[4..8], &flow_rss.to_le_bytes());
        assert_eq!(&nested_copyin.1[8..16], &0u64.to_le_bytes());
        assert_eq!(&nested_copyin.1[16..20], &flow_rss.to_le_bytes());
        assert_eq!(&nested_copyin.1[20..168], &[0u8; 148]);
        assert_eq!(&nested_copyin.1[168..176], &0u64.to_le_bytes());
        assert_eq!(&nested_copyin.1[176..180], &location.to_le_bytes());
        assert_eq!(&nested_copyin.1[180..184], &[0u8; 4]);
        assert_eq!(&nested_copyin.1[184..188], &rss_context.to_le_bytes());
        assert_eq!(&nested_copyin.1[188..192], &[0u8; 4]);
        let nested_absolute_addr = DATA_OFFSET + nested_copyin.0;
        assert_eq!(
            &root_copyin.1[16..24],
            &nested_absolute_addr.to_le_bytes(),
            "ifreq data pointer should point at nested rxnfc rss-query payload",
        );
    }

    #[test]
    fn inout_structs_with_fixed_headers_and_len_derived_rule_location_arrays_emit_copyins() {
        let descs = crate::description::parse_syscall_descs(
            r#"
                resource fd[4] = -1, 0
                type ethtool_rxnfc_rule_locs_min {
                    cmd const[48, int32]
                    flow_type const[0, int32]
                    data const[0, int64]
                    fs array[const[0, int8], 168]
                    rule_cnt len[rule_locs, int32]
                    rule_locs array[int32, 1:4]
                }
                type ifreq_ethtool_rxnfc_rule_locs_min {
                    ifr_name string["lo", 16]
                    ifr_data ptr[inout, ethtool_rxnfc_rule_locs_min]
                    pad array[int8, 16]
                } [size[40]]
                syscall ioctl_ethtool_rxnfc_rule_locs_min@1(fd fd, cmd const[35142, intptr], arg ptr[inout, ifreq_ethtool_rxnfc_rule_locs_min])
            "#,
        )
        .expect("ethtool rxnfc rule-locs target should parse");

        let mut ifr_name = vec![0u8; 16];
        ifr_name[0] = b'l';
        ifr_name[1] = b'o';
        let entries = [7u32, 11u32, 13u32, 17u32];
        let entry_count = entries.len() as u32;
        let mut inner_data = encode_scalar_bytes(4, 48)
            .into_iter()
            .chain(encode_scalar_bytes(4, 0))
            .chain(encode_scalar_bytes(8, 0))
            .chain([0u8; 168])
            .chain(encode_scalar_bytes(4, entry_count as u64))
            .chain(
                entries
                    .into_iter()
                    .flat_map(|value| encode_scalar_bytes(4, value as u64)),
            )
            .collect::<Vec<_>>();
        inner_data.extend([0u8; 4]);
        let inner = ArgValue::Composite {
            data: inner_data,
            pointers: Vec::new(),
            struct_layouts: vec![InlineStructLayout {
                base_offset: 0,
                field_ranges: vec![(0, 4), (4, 8), (8, 16), (16, 184), (184, 188), (188, 204)],
            }],
        };
        let prog = Program {
            calls: vec![Call {
                syscall_idx: 0,
                args: vec![
                    ArgValue::Const(0),
                    ArgValue::Const(35142),
                    ArgValue::Composite {
                        data: ifr_name.into_iter().chain([0u8; 24]).collect(),
                        pointers: vec![InlinePointerValue {
                            offset: 16,
                            value: Box::new(inner),
                        }],
                        struct_layouts: Vec::new(),
                    },
                ],
            }],
        };

        let data = serialize_program(&prog, &descs)
            .expect("ethtool rxnfc rule-locs program should serialize");
        let events = parse_exec_events(&data);
        let copyins: Vec<(u64, Vec<u8>)> = events
            .iter()
            .filter_map(|event| match event {
                ParsedEvent::CopyinData { addr, data } => Some((*addr, data.clone())),
                _ => None,
            })
            .collect();
        assert_eq!(copyins.len(), 2);

        let root_copyin = copyins
            .iter()
            .find(|(_, data)| data.len() == 40 && &data[0..3] == b"lo ")
            .expect("root ifreq copyin should exist");
        let nested_copyin = copyins
            .iter()
            .find(|(_, data)| data.len() == 208 && &data[0..4] == &48u32.to_le_bytes())
            .expect("nested rxnfc payload copyin should exist");

        assert_eq!(&nested_copyin.1[0..4], &48u32.to_le_bytes());
        assert_eq!(&nested_copyin.1[4..8], &0u32.to_le_bytes());
        assert_eq!(&nested_copyin.1[8..16], &0u64.to_le_bytes());
        assert_eq!(&nested_copyin.1[16..184], &[0u8; 168]);
        assert_eq!(&nested_copyin.1[184..188], &entry_count.to_le_bytes());
        assert_eq!(&nested_copyin.1[188..192], &7u32.to_le_bytes());
        assert_eq!(&nested_copyin.1[192..196], &11u32.to_le_bytes());
        assert_eq!(&nested_copyin.1[196..200], &13u32.to_le_bytes());
        assert_eq!(&nested_copyin.1[200..204], &17u32.to_le_bytes());
        assert_eq!(&nested_copyin.1[204..208], &[0u8; 4]);
        let nested_absolute_addr = DATA_OFFSET + nested_copyin.0;
        assert_eq!(
            &root_copyin.1[16..24],
            &nested_absolute_addr.to_le_bytes(),
            "ifreq data pointer should point at nested rxnfc payload",
        );
    }

    #[test]
    fn inout_structs_with_fixed_status_payloads_and_reserved_arrays_emit_copyins() {
        let descs = crate::description::parse_syscall_descs(
            r#"
                resource fd[4] = -1, 0
                type ethtool_eee {
                    cmd const[68, int32]
                    supported int32
                    advertised int32
                    lp_advertised int32
                    eee_active int32
                    eee_enabled int32
                    tx_lpi_enabled int32
                    tx_lpi_timer int32
                    reserved array[int32, 2]
                }
                type ifreq_ethtool_eee {
                    ifr_name string["lo", 16]
                    ifr_data ptr[inout, ethtool_eee]
                    pad array[int8, 16]
                } [size[40]]
                syscall ioctl_ethtool_eee@1(fd fd, cmd const[35142, intptr], arg ptr[inout, ifreq_ethtool_eee])
            "#,
        )
        .expect("ethtool eee target should parse");

        let mut ifr_name = vec![0u8; 16];
        ifr_name[0] = b'l';
        ifr_name[1] = b'o';
        let inner = ArgValue::Composite {
            data: encode_scalar_bytes(4, 68)
                .into_iter()
                .chain([0u8; 36])
                .collect(),
            pointers: Vec::new(),
            struct_layouts: Vec::new(),
        };
        let prog = Program {
            calls: vec![Call {
                syscall_idx: 0,
                args: vec![
                    ArgValue::Const(0),
                    ArgValue::Const(35142),
                    ArgValue::Composite {
                        data: ifr_name.into_iter().chain([0u8; 24]).collect(),
                        pointers: vec![InlinePointerValue {
                            offset: 16,
                            value: Box::new(inner),
                        }],
                        struct_layouts: Vec::new(),
                    },
                ],
            }],
        };

        let data = serialize_program(&prog, &descs).expect("ethtool eee program should serialize");
        let events = parse_exec_events(&data);
        let copyins: Vec<(u64, Vec<u8>)> = events
            .iter()
            .filter_map(|event| match event {
                ParsedEvent::CopyinData { addr, data } => Some((*addr, data.clone())),
                _ => None,
            })
            .collect();
        assert_eq!(copyins.len(), 2);

        let root_copyin = copyins
            .iter()
            .find(|(_, data)| data.len() == 40 && &data[0..3] == b"lo\0")
            .expect("root ifreq copyin should exist");
        let nested_copyin = copyins
            .iter()
            .find(|(_, data)| data.len() == 40 && &data[0..4] == &68u32.to_le_bytes())
            .expect("nested eee payload copyin should exist");

        assert_eq!(&nested_copyin.1[0..4], &68u32.to_le_bytes());
        assert_eq!(&nested_copyin.1[4..40], &[0u8; 36]);
        let nested_absolute_addr = DATA_OFFSET + nested_copyin.0;
        assert_eq!(
            &root_copyin.1[16..24],
            &nested_absolute_addr.to_le_bytes(),
            "ifreq data pointer should point at nested eee payload",
        );
    }

    #[test]
    fn inout_structs_with_fixed_pauseparam_payloads_emit_copyins() {
        let descs = crate::description::parse_syscall_descs(
            r#"
                resource fd[4] = -1, 0
                type ethtool_pauseparam {
                    cmd const[18, int32]
                    autoneg int32
                    rx_pause int32
                    tx_pause int32
                }
                type ifreq_ethtool_pauseparam {
                    ifr_name string["lo", 16]
                    ifr_data ptr[inout, ethtool_pauseparam]
                    pad array[int8, 16]
                } [size[40]]
                syscall ioctl_ethtool_pauseparam@1(fd fd, cmd const[35142, intptr], arg ptr[inout, ifreq_ethtool_pauseparam])
            "#,
        )
        .expect("ethtool pauseparam target should parse");

        let mut ifr_name = vec![0u8; 16];
        ifr_name[0] = b'l';
        ifr_name[1] = b'o';
        let inner = ArgValue::Composite {
            data: encode_scalar_bytes(4, 18)
                .into_iter()
                .chain([0u8; 12])
                .collect(),
            pointers: Vec::new(),
            struct_layouts: Vec::new(),
        };
        let prog = Program {
            calls: vec![Call {
                syscall_idx: 0,
                args: vec![
                    ArgValue::Const(0),
                    ArgValue::Const(35142),
                    ArgValue::Composite {
                        data: ifr_name.into_iter().chain([0u8; 24]).collect(),
                        pointers: vec![InlinePointerValue {
                            offset: 16,
                            value: Box::new(inner),
                        }],
                        struct_layouts: Vec::new(),
                    },
                ],
            }],
        };

        let data =
            serialize_program(&prog, &descs).expect("ethtool pauseparam program should serialize");
        let events = parse_exec_events(&data);
        let copyins: Vec<(u64, Vec<u8>)> = events
            .iter()
            .filter_map(|event| match event {
                ParsedEvent::CopyinData { addr, data } => Some((*addr, data.clone())),
                _ => None,
            })
            .collect();
        assert_eq!(copyins.len(), 2);

        let root_copyin = copyins
            .iter()
            .find(|(_, data)| data.len() == 40 && &data[0..3] == b"lo\0")
            .expect("root ifreq copyin should exist");
        let nested_copyin = copyins
            .iter()
            .find(|(_, data)| data.len() == 16 && &data[0..4] == &18u32.to_le_bytes())
            .expect("nested pauseparam payload copyin should exist");

        assert_eq!(&nested_copyin.1[0..4], &18u32.to_le_bytes());
        assert_eq!(&nested_copyin.1[4..16], &[0u8; 12]);
        let nested_absolute_addr = DATA_OFFSET + nested_copyin.0;
        assert_eq!(
            &root_copyin.1[16..24],
            &nested_absolute_addr.to_le_bytes(),
            "ifreq data pointer should point at nested pauseparam payload",
        );
    }

    #[test]
    fn inout_structs_with_fixed_reserved_tail_payloads_emit_copyins() {
        let descs = crate::description::parse_syscall_descs(
            r#"
                resource fd[4] = -1, 0
                type ethtool_modinfo {
                    cmd const[66, int32]
                    type int32
                    eeprom_len int32
                    reserved array[const[0, int32], 8]
                }
                type ifreq_ethtool_modinfo {
                    ifr_name string["lo", 16]
                    ifr_data ptr[inout, ethtool_modinfo]
                    pad array[int8, 16]
                } [size[40]]
                syscall ioctl_ethtool_modinfo@1(fd fd, cmd const[35142, intptr], arg ptr[inout, ifreq_ethtool_modinfo])
            "#,
        )
        .expect("ethtool modinfo target should parse");

        let mut ifr_name = vec![0u8; 16];
        ifr_name[0] = b'l';
        ifr_name[1] = b'o';
        let inner = ArgValue::Composite {
            data: encode_scalar_bytes(4, 66)
                .into_iter()
                .chain(encode_scalar_bytes(4, 0))
                .chain(encode_scalar_bytes(4, 0))
                .chain([0u8; 32])
                .collect(),
            pointers: Vec::new(),
            struct_layouts: Vec::new(),
        };
        let prog = Program {
            calls: vec![Call {
                syscall_idx: 0,
                args: vec![
                    ArgValue::Const(0),
                    ArgValue::Const(35142),
                    ArgValue::Composite {
                        data: ifr_name.into_iter().chain([0u8; 24]).collect(),
                        pointers: vec![InlinePointerValue {
                            offset: 16,
                            value: Box::new(inner),
                        }],
                        struct_layouts: Vec::new(),
                    },
                ],
            }],
        };

        let data =
            serialize_program(&prog, &descs).expect("ethtool modinfo program should serialize");
        let events = parse_exec_events(&data);
        let copyins: Vec<(u64, Vec<u8>)> = events
            .iter()
            .filter_map(|event| match event {
                ParsedEvent::CopyinData { addr, data } => Some((*addr, data.clone())),
                _ => None,
            })
            .collect();
        assert_eq!(copyins.len(), 2);

        let root_copyin = copyins
            .iter()
            .find(|(_, data)| data.len() == 40 && &data[0..3] == b"lo\0")
            .expect("root ifreq copyin should exist");
        let nested_copyin = copyins
            .iter()
            .find(|(_, data)| data.len() == 44 && &data[0..4] == &66u32.to_le_bytes())
            .expect("nested modinfo payload copyin should exist");

        assert_eq!(&nested_copyin.1[0..4], &66u32.to_le_bytes());
        assert_eq!(&nested_copyin.1[4..8], &0u32.to_le_bytes());
        assert_eq!(&nested_copyin.1[8..12], &0u32.to_le_bytes());
        assert_eq!(&nested_copyin.1[12..44], &[0u8; 32]);
        let nested_absolute_addr = DATA_OFFSET + nested_copyin.0;
        assert_eq!(
            &root_copyin.1[16..24],
            &nested_absolute_addr.to_le_bytes(),
            "ifreq data pointer should point at nested modinfo payload",
        );
    }

    #[test]
    fn inout_structs_with_len_derived_trailing_bytes_emit_copyins() {
        let descs = crate::description::parse_syscall_descs(
            r#"
                resource fd[4] = -1, 0
                type ethtool_module_eeprom {
                    cmd const[67, int32]
                    magic int32
                    offset int32
                    len len[data, int32]
                    data array[int8, 32:128]
                }
                type ifreq_ethtool_module_eeprom {
                    ifr_name string["lo", 16]
                    ifr_data ptr[inout, ethtool_module_eeprom]
                    pad array[int8, 16]
                } [size[40]]
                syscall ioctl_ethtool_module_eeprom@1(fd fd, cmd const[35142, intptr], arg ptr[inout, ifreq_ethtool_module_eeprom])
            "#,
        )
        .expect("ethtool module-eeprom target should parse");

        let mut ifr_name = vec![0u8; 16];
        ifr_name[0] = b'l';
        ifr_name[1] = b'o';
        let payload = [0x11u8; 32];
        let payload_len = payload.len() as u32;
        let inner = ArgValue::Composite {
            data: encode_scalar_bytes(4, 67)
                .into_iter()
                .chain(encode_scalar_bytes(4, 0))
                .chain(encode_scalar_bytes(4, 0))
                .chain(encode_scalar_bytes(4, payload_len as u64))
                .chain(payload)
                .collect(),
            pointers: Vec::new(),
            struct_layouts: Vec::new(),
        };
        let prog = Program {
            calls: vec![Call {
                syscall_idx: 0,
                args: vec![
                    ArgValue::Const(0),
                    ArgValue::Const(35142),
                    ArgValue::Composite {
                        data: ifr_name.into_iter().chain([0u8; 24]).collect(),
                        pointers: vec![InlinePointerValue {
                            offset: 16,
                            value: Box::new(inner),
                        }],
                        struct_layouts: Vec::new(),
                    },
                ],
            }],
        };

        let data = serialize_program(&prog, &descs)
            .expect("ethtool module-eeprom program should serialize");
        let events = parse_exec_events(&data);
        let copyins: Vec<(u64, Vec<u8>)> = events
            .iter()
            .filter_map(|event| match event {
                ParsedEvent::CopyinData { addr, data } => Some((*addr, data.clone())),
                _ => None,
            })
            .collect();
        assert_eq!(copyins.len(), 2);

        let root_copyin = copyins
            .iter()
            .find(|(_, data)| data.len() == 40 && &data[0..3] == b"lo\0")
            .expect("root ifreq copyin should exist");
        let nested_copyin = copyins
            .iter()
            .find(|(_, data)| {
                data.len() == 16 + payload_len as usize && &data[0..4] == &67u32.to_le_bytes()
            })
            .expect("nested module-eeprom payload copyin should exist");

        assert_eq!(&nested_copyin.1[0..4], &67u32.to_le_bytes());
        assert_eq!(&nested_copyin.1[4..8], &0u32.to_le_bytes());
        assert_eq!(&nested_copyin.1[8..12], &0u32.to_le_bytes());
        assert_eq!(&nested_copyin.1[12..16], &payload_len.to_le_bytes());
        assert_eq!(&nested_copyin.1[16..48], &payload);
        let nested_absolute_addr = DATA_OFFSET + nested_copyin.0;
        assert_eq!(
            &root_copyin.1[16..24],
            &nested_absolute_addr.to_le_bytes(),
            "ifreq data pointer should point at nested module-eeprom payload",
        );
    }

    #[test]
    fn inout_structs_with_fixed_ringparam_payloads_emit_copyins() {
        let descs = crate::description::parse_syscall_descs(
            r#"
                resource fd[4] = -1, 0
                type ethtool_ringparam {
                    cmd const[16, int32]
                    rx_max_pending int32
                    rx_mini_max_pending int32
                    rx_jumbo_max_pending int32
                    tx_max_pending int32
                    rx_pending int32
                    rx_mini_pending int32
                    rx_jumbo_pending int32
                    tx_pending int32
                }
                type ifreq_ethtool_ringparam {
                    ifr_name string["lo", 16]
                    ifr_data ptr[inout, ethtool_ringparam]
                    pad array[int8, 16]
                } [size[40]]
                syscall ioctl_ethtool_ringparam@1(fd fd, cmd const[35142, intptr], arg ptr[inout, ifreq_ethtool_ringparam])
            "#,
        )
        .expect("ethtool ringparam target should parse");

        let mut ifr_name = vec![0u8; 16];
        ifr_name[0] = b'l';
        ifr_name[1] = b'o';
        let inner = ArgValue::Composite {
            data: encode_scalar_bytes(4, 16)
                .into_iter()
                .chain([0u8; 32])
                .collect(),
            pointers: Vec::new(),
            struct_layouts: Vec::new(),
        };
        let prog = Program {
            calls: vec![Call {
                syscall_idx: 0,
                args: vec![
                    ArgValue::Const(0),
                    ArgValue::Const(35142),
                    ArgValue::Composite {
                        data: ifr_name.into_iter().chain([0u8; 24]).collect(),
                        pointers: vec![InlinePointerValue {
                            offset: 16,
                            value: Box::new(inner),
                        }],
                        struct_layouts: Vec::new(),
                    },
                ],
            }],
        };

        let data =
            serialize_program(&prog, &descs).expect("ethtool ringparam program should serialize");
        let events = parse_exec_events(&data);
        let copyins: Vec<(u64, Vec<u8>)> = events
            .iter()
            .filter_map(|event| match event {
                ParsedEvent::CopyinData { addr, data } => Some((*addr, data.clone())),
                _ => None,
            })
            .collect();
        assert_eq!(copyins.len(), 2);

        let root_copyin = copyins
            .iter()
            .find(|(_, data)| data.len() == 40 && &data[0..3] == b"lo\0")
            .expect("root ifreq copyin should exist");
        let nested_copyin = copyins
            .iter()
            .find(|(_, data)| data.len() == 36 && &data[0..4] == &16u32.to_le_bytes())
            .expect("nested ringparam payload copyin should exist");

        assert_eq!(&nested_copyin.1[0..4], &16u32.to_le_bytes());
        assert_eq!(&nested_copyin.1[4..36], &[0u8; 32]);
        let nested_absolute_addr = DATA_OFFSET + nested_copyin.0;
        assert_eq!(
            &root_copyin.1[16..24],
            &nested_absolute_addr.to_le_bytes(),
            "ifreq data pointer should point at nested ringparam payload",
        );
    }

    #[test]
    fn inout_structs_with_wide_fixed_coalesce_payloads_emit_copyins() {
        let descs = crate::description::parse_syscall_descs(
            r#"
                resource fd[4] = -1, 0
                type ethtool_coalesce {
                    cmd const[14, int32]
                    rx_coalesce_usecs int32
                    rx_max_coalesced_frames int32
                    rx_coalesce_usecs_irq int32
                    rx_max_coalesced_frames_irq int32
                    tx_coalesce_usecs int32
                    tx_max_coalesced_frames int32
                    tx_coalesce_usecs_irq int32
                    tx_max_coalesced_frames_irq int32
                    stats_block_coalesce_usecs int32
                    use_adaptive_rx_coalesce int32
                    use_adaptive_tx_coalesce int32
                    pkt_rate_low int32
                    rx_coalesce_usecs_low int32
                    rx_max_coalesced_frames_low int32
                    tx_coalesce_usecs_low int32
                    tx_max_coalesced_frames_low int32
                    pkt_rate_high int32
                    rx_coalesce_usecs_high int32
                    rx_max_coalesced_frames_high int32
                    tx_coalesce_usecs_high int32
                    tx_max_coalesced_frames_high int32
                    rate_sample_interval int32
                }
                type ifreq_ethtool_coalesce {
                    ifr_name string["lo", 16]
                    ifr_data ptr[inout, ethtool_coalesce]
                    pad array[int8, 16]
                } [size[40]]
                syscall ioctl_ethtool_coalesce@1(fd fd, cmd const[35142, intptr], arg ptr[inout, ifreq_ethtool_coalesce])
            "#,
        )
        .expect("ethtool coalesce target should parse");

        let mut ifr_name = vec![0u8; 16];
        ifr_name[0] = b'l';
        ifr_name[1] = b'o';
        let inner = ArgValue::Composite {
            data: encode_scalar_bytes(4, 14)
                .into_iter()
                .chain([0u8; 88])
                .collect(),
            pointers: Vec::new(),
            struct_layouts: Vec::new(),
        };
        let prog = Program {
            calls: vec![Call {
                syscall_idx: 0,
                args: vec![
                    ArgValue::Const(0),
                    ArgValue::Const(35142),
                    ArgValue::Composite {
                        data: ifr_name.into_iter().chain([0u8; 24]).collect(),
                        pointers: vec![InlinePointerValue {
                            offset: 16,
                            value: Box::new(inner),
                        }],
                        struct_layouts: Vec::new(),
                    },
                ],
            }],
        };

        let data =
            serialize_program(&prog, &descs).expect("ethtool coalesce program should serialize");
        let events = parse_exec_events(&data);
        let copyins: Vec<(u64, Vec<u8>)> = events
            .iter()
            .filter_map(|event| match event {
                ParsedEvent::CopyinData { addr, data } => Some((*addr, data.clone())),
                _ => None,
            })
            .collect();
        assert_eq!(copyins.len(), 2);

        let root_copyin = copyins
            .iter()
            .find(|(_, data)| data.len() == 40 && &data[0..3] == b"lo\0")
            .expect("root ifreq copyin should exist");
        let nested_copyin = copyins
            .iter()
            .find(|(_, data)| data.len() == 92 && &data[0..4] == &14u32.to_le_bytes())
            .expect("nested coalesce payload copyin should exist");

        assert_eq!(&nested_copyin.1[0..4], &14u32.to_le_bytes());
        assert_eq!(&nested_copyin.1[4..92], &[0u8; 88]);
        let nested_absolute_addr = DATA_OFFSET + nested_copyin.0;
        assert_eq!(
            &root_copyin.1[16..24],
            &nested_absolute_addr.to_le_bytes(),
            "ifreq data pointer should point at nested coalesce payload",
        );
    }

    #[test]
    fn inout_structs_with_fixed_byte_array_payloads_emit_copyins() {
        let descs = crate::description::parse_syscall_descs(
            r#"
                resource fd[4] = -1, 0
                type ethtool_wolinfo {
                    cmd const[5, int32]
                    supported int32
                    wolopts int32
                    sopass array[int8, 6]
                }
                type ifreq_ethtool_wolinfo {
                    ifr_name string["lo", 16]
                    ifr_data ptr[inout, ethtool_wolinfo]
                    pad array[int8, 16]
                } [size[40]]
                syscall ioctl_ethtool_wolinfo@1(fd fd, cmd const[35142, intptr], arg ptr[inout, ifreq_ethtool_wolinfo])
            "#,
        )
        .expect("ethtool wolinfo target should parse");

        let mut ifr_name = vec![0u8; 16];
        ifr_name[0] = b'l';
        ifr_name[1] = b'o';
        let sopass = [1u8, 2, 3, 4, 5, 6];
        let inner = ArgValue::Composite {
            data: encode_scalar_bytes(4, 5)
                .into_iter()
                .chain(encode_scalar_bytes(4, 0))
                .chain(encode_scalar_bytes(4, 0))
                .chain(sopass)
                .chain([0u8; 2])
                .collect(),
            pointers: Vec::new(),
            struct_layouts: Vec::new(),
        };
        let prog = Program {
            calls: vec![Call {
                syscall_idx: 0,
                args: vec![
                    ArgValue::Const(0),
                    ArgValue::Const(35142),
                    ArgValue::Composite {
                        data: ifr_name.into_iter().chain([0u8; 24]).collect(),
                        pointers: vec![InlinePointerValue {
                            offset: 16,
                            value: Box::new(inner),
                        }],
                        struct_layouts: Vec::new(),
                    },
                ],
            }],
        };

        let data =
            serialize_program(&prog, &descs).expect("ethtool wolinfo program should serialize");
        let events = parse_exec_events(&data);
        let copyins: Vec<(u64, Vec<u8>)> = events
            .iter()
            .filter_map(|event| match event {
                ParsedEvent::CopyinData { addr, data } => Some((*addr, data.clone())),
                _ => None,
            })
            .collect();
        assert_eq!(copyins.len(), 2);

        let root_copyin = copyins
            .iter()
            .find(|(_, data)| data.len() == 40 && &data[0..3] == b"lo\0")
            .expect("root ifreq copyin should exist");
        let nested_copyin = copyins
            .iter()
            .find(|(_, data)| data.len() == 20 && &data[0..4] == &5u32.to_le_bytes())
            .expect("nested wolinfo payload copyin should exist");

        assert_eq!(&nested_copyin.1[0..4], &5u32.to_le_bytes());
        assert_eq!(&nested_copyin.1[4..8], &0u32.to_le_bytes());
        assert_eq!(&nested_copyin.1[8..12], &0u32.to_le_bytes());
        assert_eq!(&nested_copyin.1[12..18], &sopass);
        assert_eq!(&nested_copyin.1[18..20], &[0u8; 2]);
        let nested_absolute_addr = DATA_OFFSET + nested_copyin.0;
        assert_eq!(
            &root_copyin.1[16..24],
            &nested_absolute_addr.to_le_bytes(),
            "ifreq data pointer should point at nested wolinfo payload",
        );
    }

    #[test]
    fn inout_structs_with_len_derived_register_payloads_emit_copyins() {
        let descs = crate::description::parse_syscall_descs(
            r#"
                resource fd[4] = -1, 0
                type ethtool_regs {
                    cmd const[4, int32]
                    version int32
                    len len[data, int32]
                    data array[int8, 32:128]
                }
                type ifreq_ethtool_regs {
                    ifr_name string["lo", 16]
                    ifr_data ptr[inout, ethtool_regs]
                    pad array[int8, 16]
                } [size[40]]
                syscall ioctl_ethtool_regs@1(fd fd, cmd const[35142, intptr], arg ptr[inout, ifreq_ethtool_regs])
            "#,
        )
        .expect("ethtool regs target should parse");

        let mut ifr_name = vec![0u8; 16];
        ifr_name[0] = b'l';
        ifr_name[1] = b'o';
        let payload = [0xABu8; 32];
        let payload_len = payload.len() as u32;
        let inner = ArgValue::Composite {
            data: encode_scalar_bytes(4, 4)
                .into_iter()
                .chain(encode_scalar_bytes(4, 0))
                .chain(encode_scalar_bytes(4, payload_len as u64))
                .chain(payload)
                .collect(),
            pointers: Vec::new(),
            struct_layouts: Vec::new(),
        };
        let prog = Program {
            calls: vec![Call {
                syscall_idx: 0,
                args: vec![
                    ArgValue::Const(0),
                    ArgValue::Const(35142),
                    ArgValue::Composite {
                        data: ifr_name.into_iter().chain([0u8; 24]).collect(),
                        pointers: vec![InlinePointerValue {
                            offset: 16,
                            value: Box::new(inner),
                        }],
                        struct_layouts: Vec::new(),
                    },
                ],
            }],
        };

        let data = serialize_program(&prog, &descs).expect("ethtool regs program should serialize");
        let events = parse_exec_events(&data);
        let copyins: Vec<(u64, Vec<u8>)> = events
            .iter()
            .filter_map(|event| match event {
                ParsedEvent::CopyinData { addr, data } => Some((*addr, data.clone())),
                _ => None,
            })
            .collect();
        assert_eq!(copyins.len(), 2);

        let root_copyin = copyins
            .iter()
            .find(|(_, data)| data.len() == 40 && &data[0..3] == b"lo\0")
            .expect("root ifreq copyin should exist");
        let nested_copyin = copyins
            .iter()
            .find(|(_, data)| {
                data.len() == 12 + payload_len as usize && &data[0..4] == &4u32.to_le_bytes()
            })
            .expect("nested regs payload copyin should exist");

        assert_eq!(&nested_copyin.1[0..4], &4u32.to_le_bytes());
        assert_eq!(&nested_copyin.1[4..8], &0u32.to_le_bytes());
        assert_eq!(&nested_copyin.1[8..12], &payload_len.to_le_bytes());
        assert_eq!(&nested_copyin.1[12..44], &payload);
        let nested_absolute_addr = DATA_OFFSET + nested_copyin.0;
        assert_eq!(
            &root_copyin.1[16..24],
            &nested_absolute_addr.to_le_bytes(),
            "ifreq data pointer should point at nested regs payload",
        );
    }

    #[test]
    fn inout_structs_with_len_derived_eeprom_payloads_emit_copyins() {
        let descs = crate::description::parse_syscall_descs(
            r#"
                resource fd[4] = -1, 0
                type ethtool_eeprom {
                    cmd const[11, int32]
                    magic int32
                    offset int32
                    len len[data, int32]
                    data array[int8, 32:128]
                }
                type ifreq_ethtool_eeprom {
                    ifr_name string["lo", 16]
                    ifr_data ptr[inout, ethtool_eeprom]
                    pad array[int8, 16]
                } [size[40]]
                syscall ioctl_ethtool_eeprom@1(fd fd, cmd const[35142, intptr], arg ptr[inout, ifreq_ethtool_eeprom])
            "#,
        )
        .expect("ethtool eeprom target should parse");

        let mut ifr_name = vec![0u8; 16];
        ifr_name[0] = b'l';
        ifr_name[1] = b'o';
        let payload = [0xCDu8; 32];
        let payload_len = payload.len() as u32;
        let inner = ArgValue::Composite {
            data: encode_scalar_bytes(4, 11)
                .into_iter()
                .chain(encode_scalar_bytes(4, 0))
                .chain(encode_scalar_bytes(4, 0))
                .chain(encode_scalar_bytes(4, payload_len as u64))
                .chain(payload)
                .collect(),
            pointers: Vec::new(),
            struct_layouts: Vec::new(),
        };
        let prog = Program {
            calls: vec![Call {
                syscall_idx: 0,
                args: vec![
                    ArgValue::Const(0),
                    ArgValue::Const(35142),
                    ArgValue::Composite {
                        data: ifr_name.into_iter().chain([0u8; 24]).collect(),
                        pointers: vec![InlinePointerValue {
                            offset: 16,
                            value: Box::new(inner),
                        }],
                        struct_layouts: Vec::new(),
                    },
                ],
            }],
        };

        let data =
            serialize_program(&prog, &descs).expect("ethtool eeprom program should serialize");
        let events = parse_exec_events(&data);
        let copyins: Vec<(u64, Vec<u8>)> = events
            .iter()
            .filter_map(|event| match event {
                ParsedEvent::CopyinData { addr, data } => Some((*addr, data.clone())),
                _ => None,
            })
            .collect();
        assert_eq!(copyins.len(), 2);

        let root_copyin = copyins
            .iter()
            .find(|(_, data)| data.len() == 40 && &data[0..3] == b"lo\0")
            .expect("root ifreq copyin should exist");
        let nested_copyin = copyins
            .iter()
            .find(|(_, data)| {
                data.len() == 16 + payload_len as usize && &data[0..4] == &11u32.to_le_bytes()
            })
            .expect("nested eeprom payload copyin should exist");

        assert_eq!(&nested_copyin.1[0..4], &11u32.to_le_bytes());
        assert_eq!(&nested_copyin.1[4..8], &0u32.to_le_bytes());
        assert_eq!(&nested_copyin.1[8..12], &0u32.to_le_bytes());
        assert_eq!(&nested_copyin.1[12..16], &payload_len.to_le_bytes());
        assert_eq!(&nested_copyin.1[16..48], &payload);
        let nested_absolute_addr = DATA_OFFSET + nested_copyin.0;
        assert_eq!(
            &root_copyin.1[16..24],
            &nested_absolute_addr.to_le_bytes(),
            "ifreq data pointer should point at nested eeprom payload",
        );
    }

    #[test]
    fn inout_structs_with_tunable_headers_and_fixed_u32_data_emit_copyins() {
        let descs = crate::description::parse_syscall_descs(
            r#"
                resource fd[4] = -1, 0
                type ethtool_tunable_u32 {
                    cmd const[72, int32]
                    id const[2, int32]
                    type_id const[3, int32]
                    len len[data, int32]
                    data array[int8, 4]
                }
                type ifreq_ethtool_tunable_u32 {
                    ifr_name string["lo", 16]
                    ifr_data ptr[inout, ethtool_tunable_u32]
                    pad array[int8, 16]
                } [size[40]]
                syscall ioctl_ethtool_tunable_u32@1(fd fd, cmd const[35142, intptr], arg ptr[inout, ifreq_ethtool_tunable_u32])
            "#,
        )
        .expect("ethtool tunable target should parse");

        let mut ifr_name = vec![0u8; 16];
        ifr_name[0] = b'l';
        ifr_name[1] = b'o';
        let payload = [0x34u8, 0x12, 0x00, 0x00];
        let payload_len = payload.len() as u32;
        let inner = ArgValue::Composite {
            data: encode_scalar_bytes(4, 72)
                .into_iter()
                .chain(encode_scalar_bytes(4, 2))
                .chain(encode_scalar_bytes(4, 3))
                .chain(encode_scalar_bytes(4, payload_len as u64))
                .chain(payload)
                .collect(),
            pointers: Vec::new(),
            struct_layouts: Vec::new(),
        };
        let prog = Program {
            calls: vec![Call {
                syscall_idx: 0,
                args: vec![
                    ArgValue::Const(0),
                    ArgValue::Const(35142),
                    ArgValue::Composite {
                        data: ifr_name.into_iter().chain([0u8; 24]).collect(),
                        pointers: vec![InlinePointerValue {
                            offset: 16,
                            value: Box::new(inner),
                        }],
                        struct_layouts: Vec::new(),
                    },
                ],
            }],
        };

        let data =
            serialize_program(&prog, &descs).expect("ethtool tunable program should serialize");
        let events = parse_exec_events(&data);
        let copyins: Vec<(u64, Vec<u8>)> = events
            .iter()
            .filter_map(|event| match event {
                ParsedEvent::CopyinData { addr, data } => Some((*addr, data.clone())),
                _ => None,
            })
            .collect();
        assert_eq!(copyins.len(), 2);

        let root_copyin = copyins
            .iter()
            .find(|(_, data)| data.len() == 40 && &data[0..3] == b"lo\0")
            .expect("root ifreq copyin should exist");
        let nested_copyin = copyins
            .iter()
            .find(|(_, data)| {
                data.len() == 16 + payload_len as usize && &data[0..4] == &72u32.to_le_bytes()
            })
            .expect("nested tunable payload copyin should exist");

        assert_eq!(&nested_copyin.1[0..4], &72u32.to_le_bytes());
        assert_eq!(&nested_copyin.1[4..8], &2u32.to_le_bytes());
        assert_eq!(&nested_copyin.1[8..12], &3u32.to_le_bytes());
        assert_eq!(&nested_copyin.1[12..16], &payload_len.to_le_bytes());
        assert_eq!(&nested_copyin.1[16..20], &payload);
        let nested_absolute_addr = DATA_OFFSET + nested_copyin.0;
        assert_eq!(
            &root_copyin.1[16..24],
            &nested_absolute_addr.to_le_bytes(),
            "ifreq data pointer should point at nested tunable payload",
        );
    }

    #[test]
    fn nested_output_pointer_resources_copyout_from_nested_allocation() {
        let descs = crate::description::parse_syscall_descs(
            r#"
                resource handle[intptr]
                type inner {
                    h handle
                }
                type wrapper {
                    out ptr[out, inner]
                }
                syscall make@1 -> int(arg ptr[inout, wrapper])
                syscall use@2 -> int(h handle)
            "#,
        )
        .expect("nested output target should parse");

        let prog = Program {
            calls: vec![
                Call {
                    syscall_idx: 0,
                    args: vec![ArgValue::Composite {
                        data: vec![0; 8],
                        pointers: vec![InlinePointerValue {
                            offset: 0,
                            value: Box::new(ArgValue::OutPtr),
                        }],
                        struct_layouts: Vec::new(),
                    }],
                },
                Call {
                    syscall_idx: 1,
                    args: vec![ArgValue::ResultRef(ResultRef {
                        call_idx: 0,
                        result_idx: 0,
                    })],
                },
            ],
        };

        let data = serialize_program(&prog, &descs)
            .expect("program with nested output pointer resource should serialize");
        let events = parse_exec_events(&data);
        let root_copyin = events
            .iter()
            .find_map(|event| match event {
                ParsedEvent::CopyinData { data, .. } if data.len() == 8 => Some(data.clone()),
                _ => None,
            })
            .expect("root wrapper copyin should exist");
        let nested_absolute_addr = u64::from_le_bytes(root_copyin[..8].try_into().unwrap());

        let copyouts: Vec<(u64, u64, u64)> = events
            .iter()
            .filter_map(|event| match event {
                ParsedEvent::Copyout { idx, addr, size } => Some((*idx, *addr, *size)),
                _ => None,
            })
            .collect();
        assert_eq!(copyouts, vec![(0, nested_absolute_addr - DATA_OFFSET, 8)]);

        let result_args: Vec<(u64, u64)> = events
            .iter()
            .filter_map(|event| match event {
                ParsedEvent::ResultArg {
                    copyout_idx,
                    default,
                    ..
                } => Some((*copyout_idx, *default)),
                _ => None,
            })
            .collect();
        assert_eq!(result_args, vec![(0, 0)]);
    }

    #[test]
    fn test_proc_argument_encodes_pid_stride() {
        let descs = crate::description::parse_syscall_descs(
            r#"
                syscall use_proc@1 -> int(id proc[100, 4])
            "#,
        )
        .expect("proc-bearing target should parse");

        let prog = Program {
            calls: vec![Call {
                syscall_idx: 0,
                args: vec![ArgValue::Const(0)],
            }],
        };
        let data = serialize_program(&prog, &descs).expect("proc program should serialize");
        let events = parse_exec_events(&data);
        let const_args = events
            .iter()
            .filter_map(|event| match event {
                ParsedEvent::ConstArg { meta, value } => Some((*meta, *value)),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(const_args, vec![(8 | (4 << 32), 100)]);

        let default_prog = Program {
            calls: vec![Call {
                syscall_idx: 0,
                args: vec![ArgValue::Const(PROC_DEFAULT_VALUE)],
            }],
        };
        let default_data = serialize_program(&default_prog, &descs)
            .expect("default proc program should serialize");
        let default_events = parse_exec_events(&default_data);
        let default_const_args = default_events
            .iter()
            .filter_map(|event| match event {
                ParsedEvent::ConstArg { meta, value } => Some((*meta, *value)),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(default_const_args, vec![(8, 0)]);
    }

    #[derive(Debug, PartialEq, Eq)]
    enum ParsedEvent {
        CallReturnCopyout {
            idx: u64,
        },
        CopyinData {
            addr: u64,
            data: Vec<u8>,
        },
        ConstArg {
            meta: u64,
            value: u64,
        },
        AddrArg {
            addr: u64,
        },
        ResultArg {
            meta: u64,
            copyout_idx: u64,
            default: u64,
        },
        Copyout {
            idx: u64,
            addr: u64,
            size: u64,
        },
    }

    fn parse_exec_events(data: &[u8]) -> Vec<ParsedEvent> {
        let mut events = Vec::new();
        let mut index = 0usize;
        let _num_calls = read_exec_value(data, &mut index);

        loop {
            let opcode = read_exec_value(data, &mut index);
            match opcode {
                EXEC_INSTR_EOF => break,
                EXEC_INSTR_COPYIN => {
                    let addr = read_exec_value(data, &mut index);
                    parse_arg_payload(data, &mut index, &mut events, Some(addr));
                }
                EXEC_INSTR_COPYOUT => {
                    let idx = read_exec_value(data, &mut index);
                    let addr = read_exec_value(data, &mut index);
                    let size = read_exec_value(data, &mut index);
                    events.push(ParsedEvent::Copyout { idx, addr, size });
                }
                EXEC_INSTR_SET_PROPS => {
                    panic!("call properties are not expected in current tests");
                }
                _call_id => {
                    let copyout_idx = read_exec_value(data, &mut index);
                    if copyout_idx != EXEC_NO_COPYOUT {
                        events.push(ParsedEvent::CallReturnCopyout { idx: copyout_idx });
                    }
                    let num_args = read_exec_value(data, &mut index) as usize;
                    for _ in 0..num_args {
                        parse_arg_payload(data, &mut index, &mut events, None);
                    }
                }
            }
        }

        events
    }

    fn parse_arg_payload(
        data: &[u8],
        index: &mut usize,
        events: &mut Vec<ParsedEvent>,
        copyin_addr: Option<u64>,
    ) {
        let arg_kind = read_exec_value(data, index);
        match arg_kind {
            EXEC_ARG_CONST => {
                let meta = read_exec_value(data, index);
                let value = read_exec_value(data, index);
                events.push(ParsedEvent::ConstArg { meta, value });
            }
            EXEC_ARG_ADDR32 | EXEC_ARG_ADDR64 => {
                let addr = read_exec_value(data, index);
                events.push(ParsedEvent::AddrArg { addr });
            }
            EXEC_ARG_RESULT => {
                let meta = read_exec_value(data, index);
                let copyout_idx = read_exec_value(data, index);
                let _op_div = read_exec_value(data, index);
                let _op_add = read_exec_value(data, index);
                let default = read_exec_value(data, index);
                events.push(ParsedEvent::ResultArg {
                    meta,
                    copyout_idx,
                    default,
                });
            }
            EXEC_ARG_DATA => {
                let size = read_exec_value(data, index) as usize;
                let payload = data[*index..*index + size].to_vec();
                *index += size;
                if let Some(addr) = copyin_addr {
                    events.push(ParsedEvent::CopyinData {
                        addr,
                        data: payload,
                    });
                }
            }
            other => panic!("unexpected exec arg kind in test parser: {}", other),
        }
    }

    fn read_exec_value(data: &[u8], index: &mut usize) -> u64 {
        let (ux, consumed) = read_uvarint(&data[*index..]);
        *index += consumed;
        (ux >> 1) ^ (0u64.wrapping_sub(ux & 1))
    }

    fn decode_varints(data: &[u8]) -> Vec<u64> {
        let mut values = Vec::new();
        let mut index = 0;
        while index < data.len() {
            let (ux, consumed) = read_uvarint(&data[index..]);
            let value = (ux >> 1) ^ (0u64.wrapping_sub(ux & 1));
            values.push(value);
            index += consumed;
        }
        values
    }

    fn read_uvarint(data: &[u8]) -> (u64, usize) {
        let mut value = 0u64;
        let mut shift = 0u32;
        for (i, byte) in data.iter().enumerate() {
            value |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return (value, i + 1);
            }
            shift += 7;
        }
        panic!("unterminated uvarint");
    }
}
