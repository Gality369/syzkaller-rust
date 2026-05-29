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

        // First pass: allocate data pages and emit copyin instructions for pointer args
        for (arg_idx, (arg_type, arg_val)) in desc.args.iter().zip(call.args.iter()).enumerate() {
            match (arg_type, arg_val) {
                (ArgType::Ptr { .. }, ArgValue::Null) => {}
                (ArgType::Ptr { .. }, _) | (ArgType::Filename, _) => {
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
                            ArgValue::Composite { data, pointers },
                        ) => emit_composite_copyin(
                            &mut w,
                            addr,
                            data,
                            pointers,
                            &mut next_data_page,
                        )?,
                        (
                            ArgType::Ptr {
                                inner: _,
                                dir: PtrDir::In | PtrDir::InOut,
                                ..
                            },
                            ArgValue::Array { data, pointers, .. },
                        ) => emit_composite_copyin(
                            &mut w,
                            addr,
                            data,
                            pointers,
                            &mut next_data_page,
                        )?,
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
                (ArgType::Resource(resource), ArgValue::Const(val)) => {
                    w.write_val(EXEC_ARG_CONST);
                    w.write_val(meta_const(resource.size, 0, 0, 0, 0));
                    w.write_val(*val);
                }
                (ArgType::Resource(resource), ArgValue::ResultRef(result_ref)) => {
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
                (ArgType::Resource(resource), ArgValue::Null) => {
                    w.write_val(EXEC_ARG_CONST);
                    w.write_val(meta_const(resource.size, 0, 0, 0, 0));
                    w.write_val(resource.default_value());
                }
                (ArgType::Array { .. }, ArgValue::Buffer(data))
                | (ArgType::Array { .. }, ArgValue::Composite { data, .. })
                | (ArgType::Array { .. }, ArgValue::Array { data, .. }) => {
                    w.write_val(EXEC_ARG_DATA);
                    w.write_val(data.len() as u64);
                    w.write_data(data);
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
                (ArgType::String { .. }, ArgValue::Buffer(data)) => {
                    w.write_val(EXEC_ARG_DATA);
                    w.write_val(data.len() as u64);
                    w.write_data(data);
                }
                (ArgType::Buffer { .. }, ArgValue::Buffer(data)) => {
                    w.write_val(EXEC_ARG_DATA);
                    w.write_val(data.len() as u64);
                    w.write_data(data);
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
                arg_idx, offset, ..
            } = output.source
            {
                let Some((_, base_addr)) = data_addrs.iter().find(|(idx, _)| *idx == arg_idx)
                else {
                    continue;
                };
                resolved_results.insert(result_ref, next_copyout_idx);
                w.write_val(EXEC_INSTR_COPYOUT);
                w.write_val(next_copyout_idx);
                w.write_val(*base_addr - DATA_OFFSET + offset as u64);
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
) -> Result<(), ValidationError> {
    match value {
        ArgValue::Buffer(data) => {
            emit_copyin_bytes(w, addr, data);
            Ok(())
        }
        ArgValue::Composite { data, pointers } => {
            emit_composite_copyin(w, addr, data, pointers, next_data_page)
        }
        ArgValue::Array { data, pointers, .. } => {
            emit_composite_copyin(w, addr, data, pointers, next_data_page)
        }
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
        match pointer.value.as_ref() {
            ArgValue::Null => {
                slot.copy_from_slice(&0u64.to_le_bytes());
            }
            ArgValue::OutPtr => {
                let nested_addr = DATA_OFFSET + *next_data_page * PAGE_SIZE;
                *next_data_page += 1;
                slot.copy_from_slice(&nested_addr.to_le_bytes());
            }
            nested => {
                let nested_addr = DATA_OFFSET + *next_data_page * PAGE_SIZE;
                *next_data_page += 1;
                slot.copy_from_slice(&nested_addr.to_le_bytes());
                emit_arg_value_copyin(w, nested_addr, nested, next_data_page)?;
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
                ParsedEvent::Copyout { idx, size } => Some((*idx, *size)),
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
                    let _addr = read_exec_value(data, &mut index);
                    let size = read_exec_value(data, &mut index);
                    events.push(ParsedEvent::Copyout { idx, size });
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
