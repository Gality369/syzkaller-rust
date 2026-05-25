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

                    // Emit copyin for input data
                    match (arg_type, arg_val) {
                        (
                            ArgType::Ptr {
                                inner: _,
                                dir: PtrDir::In | PtrDir::InOut,
                                ..
                            },
                            ArgValue::Buffer(data),
                        ) => {
                            w.write_val(EXEC_INSTR_COPYIN);
                            w.write_val(addr - DATA_OFFSET);
                            w.write_val(EXEC_ARG_DATA);
                            w.write_val(data.len() as u64);
                            w.write_data(data);
                        }
                        (ArgType::Filename, ArgValue::Filename(name)) => {
                            let data = {
                                let mut d = name.as_bytes().to_vec();
                                d.push(0); // null terminator
                                d
                            };
                            w.write_val(EXEC_INSTR_COPYIN);
                            w.write_val(addr - DATA_OFFSET);
                            w.write_val(EXEC_ARG_DATA);
                            w.write_val(data.len() as u64);
                            w.write_data(&data);
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
                    next_data_page += 1;
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
                syscall_idx: 17, // getpid
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
        let prog = Program {
            calls: vec![
                Call {
                    syscall_idx: 9, // eventfd2
                    args: vec![ArgValue::Const(0), ArgValue::Const(0)],
                },
                Call {
                    syscall_idx: 1, // close
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
        let prog = Program {
            calls: vec![
                Call {
                    syscall_idx: 1, // close(fd)
                    args: vec![ArgValue::ResultRef(ResultRef {
                        call_idx: 1,
                        result_idx: 0,
                    })],
                },
                Call {
                    syscall_idx: 9, // eventfd2 -> fd
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
        let prog = Program {
            calls: vec![
                Call {
                    syscall_idx: 4, // pipe2
                    args: vec![ArgValue::OutPtr, ArgValue::Const(0)],
                },
                Call {
                    syscall_idx: 1, // close(fd)
                    args: vec![ArgValue::ResultRef(ResultRef {
                        call_idx: 0,
                        result_idx: 0,
                    })],
                },
                Call {
                    syscall_idx: 1, // close(fd)
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

    #[derive(Debug, PartialEq, Eq)]
    enum ParsedEvent {
        CallReturnCopyout {
            idx: u64,
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
                    let _addr = read_exec_value(data, &mut index);
                    parse_arg_payload(data, &mut index, &mut events);
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
                        parse_arg_payload(data, &mut index, &mut events);
                    }
                }
            }
        }

        events
    }

    fn parse_arg_payload(data: &[u8], index: &mut usize, events: &mut Vec<ParsedEvent>) {
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
                *index += size;
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
