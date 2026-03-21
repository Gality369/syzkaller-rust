use crate::program::*;

// Exec format constants (matching Go's encodingexec.go)
const EXEC_INSTR_EOF: u64 = !0u64;        // 0xFFFFFFFFFFFFFFFF
const EXEC_INSTR_COPYIN: u64 = !1u64;     // 0xFFFFFFFFFFFFFFFE
const EXEC_INSTR_COPYOUT: u64 = !2u64;    // 0xFFFFFFFFFFFFFFFFD
const EXEC_INSTR_SET_PROPS: u64 = !3u64;  // 0xFFFFFFFFFFFFFFFC

const EXEC_ARG_CONST: u64 = 0;
const EXEC_ARG_ADDR32: u64 = 1;
const EXEC_ARG_ADDR64: u64 = 2;
const EXEC_ARG_RESULT: u64 = 3;
const EXEC_ARG_DATA: u64 = 4;

const EXEC_NO_COPYOUT: u64 = !0u64;

/// Serialize a program into the executor's binary format.
/// This matches the varint-encoded format from Go's encodingexec.go.
pub fn serialize_program(prog: &Program, descs: &[SyscallDesc]) -> Vec<u8> {
    let mut w = ExecWriter::new();

    // Number of calls
    w.write_val(prog.calls.len() as u64);

    // Per-call data page allocation: each call's pointer args get their own page
    let mut next_data_page: u64 = 0;

    for (_call_idx, call) in prog.calls.iter().enumerate() {
        let desc = &descs[call.syscall_idx];
        let mut data_addrs: Vec<(usize, u64)> = Vec::new(); // (arg_idx, addr)

        // First pass: allocate data pages and emit copyin instructions for pointer args
        for (arg_idx, (arg_type, arg_val)) in desc.args.iter().zip(call.args.iter()).enumerate() {
            match (arg_type, arg_val) {
                (ArgType::Ptr { .. }, _) | (ArgType::Filename, _) => {
                    let addr = DATA_OFFSET + next_data_page * PAGE_SIZE;
                    data_addrs.push((arg_idx, addr));

                    // Emit copyin for input data
                    match (arg_type, arg_val) {
                        (ArgType::Ptr { inner: _, dir: PtrDir::In | PtrDir::InOut }, ArgValue::Buffer(data)) => {
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
                        (ArgType::Ptr { dir: PtrDir::Out, .. }, _) => {
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
        w.write_val(EXEC_NO_COPYOUT); // no copyout for now
        w.write_val(desc.args.len() as u64);

        // Emit arguments
        for (arg_idx, (arg_type, arg_val)) in desc.args.iter().zip(call.args.iter()).enumerate() {
            match (arg_type, arg_val) {
                (ArgType::Const { size, .. }, ArgValue::Const(val)) => {
                    w.write_val(EXEC_ARG_CONST);
                    w.write_val(meta_const(*size, 0, 0, 0, 0));
                    w.write_val(*val);
                }
                (ArgType::Fd, ArgValue::Const(val)) => {
                    // Fd passed as a constant (e.g., literal fd number)
                    w.write_val(EXEC_ARG_CONST);
                    w.write_val(meta_const(8, 0, 0, 0, 0));
                    w.write_val(*val);
                }
                (ArgType::Fd, ArgValue::FdRef(_call_idx)) => {
                    // For now, pass fd references as constants
                    // In a full implementation, this would use execArgResult + copyout
                    w.write_val(EXEC_ARG_CONST);
                    w.write_val(meta_const(8, 0, 0, 0, 0));
                    // Use a reasonable default fd value
                    w.write_val(0xFFFFFFFFFFFFFFFF); // -1, will fail gracefully
                }
                (ArgType::Fd, ArgValue::Null) => {
                    w.write_val(EXEC_ARG_CONST);
                    w.write_val(meta_const(8, 0, 0, 0, 0));
                    w.write_val(0xFFFFFFFFFFFFFFFF);
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
    }

    // EOF
    w.write_val(EXEC_INSTR_EOF);
    w.buf
}

/// Encode const metadata: size | (format << 8) | (bf_offset << 16) | (bf_len << 24) | (pid_stride << 32)
fn meta_const(size: usize, format: u64, bf_offset: u64, bf_len: u64, pid_stride: u64) -> u64 {
    (size as u64) | (format << 8) | (bf_offset << 16) | (bf_len << 24) | (pid_stride << 32)
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
            calls: vec![
                Call {
                    syscall_idx: 15, // getpid
                    args: vec![],
                },
            ],
        };
        let data = serialize_program(&prog, &descs);
        assert!(!data.is_empty());
        // First varint should encode 1 (number of calls)
        // zigzag(1) = 2
        assert_eq!(data[0], 0x02);
    }
}
