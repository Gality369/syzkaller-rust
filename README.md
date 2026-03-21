# syzkaller-rust

A minimal Linux kernel fuzzer written in Rust, compatible with [syzkaller](https://github.com/google/syzkaller)'s `syz-executor` binary protocol. It reuses the original syzkaller executor to run test programs, while reimplementing the fuzzer scheduling logic in Rust.

## Background

This project is a Rust reimplementation of syzkaller's core orchestration logic. It does **not** reimplement the executor (the in-kernel syscall runner). Instead, it communicates directly with the original `syz-executor` binary via the FlatRPC protocol. This allows focusing on fuzzer scheduling, program generation, and corpus management, while maintaining full wire-level compatibility with the syzkaller executor.

## Architecture

```
syzkaller-rust (this project)
    │
    ├── Launch QEMU virtual machine
    ├── Copy syz-executor to VM via SCP and start it over SSH
    ├── Perform FlatRPC handshake with the executor runner over TCP
    ├── Generate / mutate test programs (syscall sequences)
    ├── Serialize programs into the executor binary format and send them
    ├── Receive coverage signals (kcov) and update the corpus
    └── Detect kernel crashes (KASAN / KFENCE / panic / etc.)
```

### Module Overview

| Module | Responsibility |
|--------|---------------|
| `main.rs` | Entry point: parse config, launch manager |
| `manager.rs` | Main loop: VM lifecycle, FlatRPC handshake, fuzz loop |
| `program.rs` | Syscall descriptors (syzkaller internal IDs), program data structures, random filename generation |
| `exec.rs` | Serialize programs into the executor binary format (varint encoding, compatible with `encodingexec.go`) |
| `fuzzer.rs` | Program generation (random) and mutation (insert/remove/modify calls, argument mutation, splicing) |
| `corpus.rs` | Corpus: track discovered coverage signals, store programs that produce new signal |
| `crash.rs` | Kernel crash detection: recognize BUG/KASAN/KFENCE/panic patterns, save crash reports |
| `protocol.rs` | FlatRPC message encode/decode (size-prefixed FlatBuffers) |
| `flatrpc_generated.rs` | Auto-generated FlatBuffers code (from syzkaller's `flatrpc.fbs`) |
| `qemu.rs` | QEMU VM launch, SSH port forwarding, serial console output capture |
| `ssh.rs` | SSH command execution, SCP file transfer |
| `config.rs` | JSON configuration file parsing |

## Prerequisites

- Rust 1.70+ (`cargo`)
- QEMU (`qemu-system-x86_64`)
- syzkaller's `syz-executor` binary (statically compiled for linux/amd64)
- Kernel image (bzImage) and QEMU disk image (e.g. `bullseye.img`)
- SSH key for the VM

## Build

```bash
cd syzkaller-rust
cargo build --release
```

## Configuration

Edit `config.json`:

```json
{
    "workdir": "/path/to/workdir",
    "kernel_obj": "/path/to/linux-6.8",
    "image": "/path/to/bullseye.img",
    "sshkey": "/path/to/bullseye.id_rsa",
    "ssh_user": "root",
    "executor": "/path/to/syz-executor",
    "procs": 1,
    "sandbox": "none",
    "cover": true,
    "syscall_timeout_ms": 500,
    "program_timeout_ms": 5000,
    "slowdown": 1,
    "vm": {
        "count": 1,
        "kernel": "/path/to/bzImage",
        "cpu": 2,
        "mem": 2048,
        "qemu": "qemu-system-x86_64",
        "cmdline": "console=ttyS0 root=/dev/sda earlyprintk=serial net.ifnames=0"
    }
}
```

## Running

```bash
RUST_LOG=info ./target/release/syzkaller-rust config.json
```

Log levels: `error` / `warn` / `info` / `debug`.

The following directories are created under `workdir/` at runtime:
- `crashes/` — kernel crash reports (console output)

## FlatRPC Protocol

The fuzzer implements syzkaller's FlatRPC handshake protocol:

```
fuzzer  → executor:  ConnectRequest  (version, architecture info)
executor → fuzzer:  ConnectReply    (supported features, timeout config)
executor → fuzzer:  InfoRequest     (process configuration request)
fuzzer  → executor:  InfoReply       (coverage filter, signal filter)
--- handshake complete, enter execution loop ---
fuzzer  → executor:  ExecRequest     (program data + exec options, via shared memory)
executor → fuzzer:  ExecResult      (per-call return values, coverage signals)
```

Wire format: 4-byte little-endian size prefix + FlatBuffers-encoded message body.

## Program Wire Format

Test programs are passed to the executor as a stream of varints (zigzag-encoded):

```
uint64  num_calls
// for each call:
[COPYIN instructions]*   // write data pages (filenames, buffer contents, etc.)
uint64  syscall_id       // syzkaller internal ID (NOT the Linux syscall NR)
uint64  copyout_idx      // copyout result index (!0 = no copyout)
uint64  num_args
[arg]*                   // type + value for each argument
uint64  EXEC_INSTR_EOF   // !0u64 end marker
```

> **Important**: `syscall_id` is the index into the executor's `syscalls[]` table for the target platform, **not** the Linux syscall number (NR). For example, `read` has syzkaller ID `5264` on linux/amd64, while its Linux NR is `0`.

## Supported Syscalls

A minimal subset of ~18 syscalls for linux/amd64, covering filesystem operations, network sockets, and memory management:

`openat`, `close`, `read`, `write`, `pipe2`, `dup3`, `socket`, `eventfd2`,  
`mmap`, `munmap`, `mprotect`, `mkdirat`, `unlinkat`, `fstat`, `getcwd`,  
`getpid`, `getuid`, `ioctl`

## Known Limitations

- Only linux/amd64 target is supported
- Only `sandbox=none` mode is supported
- `execArgResult` (fd result passing between calls) is not implemented; fd arguments use literal values
- Advanced instructions (`setprops`, `copyout`) are not implemented
- No network sync with a syzkaller manager; runs standalone
- Syscall count per program and argument value ranges are limited to a small fixed set

## Implementation Notes

### Varint Encoding

The executor uses signed varint with zigzag encoding, identical to Go's `binary.AppendVarint`:

```
x: i64  →  ux: u64 = (x << 1) ^ (x >> 63)
```

### Data Arguments

`EXEC_ARG_DATA` bytes are written raw with **no alignment padding**. The executor advances its read pointer with `input_pos += size` exactly, so any padding bytes would corrupt the instruction stream.

### Timeout Behavior

In fork-server mode, the executor runner's watchdog fires at `3 × program_timeout_ms`. With `program_timeout_ms=5000` (the default), the watchdog timeout is 15 seconds. The fuzzer restarts the VM if no `ExecResult` is received within that window.
