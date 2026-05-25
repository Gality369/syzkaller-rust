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
| `avoidance.rs` | Persist and reload learned timeout-avoidance state (edge/syscall failure counts) |
| `main.rs` | Entry point: parse config, launch manager |
| `manager.rs` | Main loop: VM lifecycle, FlatRPC handshake, fuzz loop |
| `program.rs` | Syscall descriptors (syzkaller internal IDs), program data structures, random filename generation |
| `exec.rs` | Serialize programs into the executor binary format (varint encoding, compatible with `encodingexec.go`) |
| `fuzzer.rs` | Program generation (random) and mutation (insert/remove/modify calls, argument mutation, splicing) |
| `corpus.rs` | Corpus: track discovered coverage signals, store programs that produce new signal, persist and reload snapshots |
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
    "max_execs": 1,
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

`max_execs` is optional. When set, the manager exits cleanly after that many
completed executions, which is useful for bounded smoke tests and scripted
end-to-end checks.

## Running

```bash
RUST_LOG=info ./target/release/syzkaller-rust config.json
```

Log levels: `error` / `warn` / `info` / `debug`.

The following directories are created under `workdir/` at runtime:
- `crashes/` — kernel crash reports (console output)
- `timeouts/` — timed-out or executor-reported hanged programs, including their syscall shape and timeout-prone edge profile, for later triage

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

> **Important**: `syscall_id` is the index into the executor's `syscalls[]` table for the target platform, **not** the Linux syscall number (NR). For example, `read` has syzkaller ID `5186` on linux/amd64 in the current bundled target, while its Linux NR is `0`.

## Supported Syscalls

A minimal subset of ~20 syscalls for linux/amd64, covering filesystem operations, network sockets, and memory management:

`openat`, `close`, `read`, `write`, `pipe2`, `dup3`, `socket`, `socketpair`, `listen`, `eventfd2`,  
`mmap`, `munmap`, `mprotect`, `mkdirat`, `unlinkat`, `fstat`, `getcwd`,  
`getpid`, `getuid`, `ioctl`

## Description DSL

The current Rust-side description parser supports a deliberately small subset of
syzlang-oriented concepts:

- scalar constants via `const NAME = VALUE`
- named constant and flag groups via `constset NAME[SIZE] = ...` and `flagset NAME[SIZE] = ...`
- syz-sysgen style `.txt.const` constant files for linux/amd64 constant imports
- automatic loading of sibling `name.txt.const` files when parsing `name.txt`
- resource declarations with optional parent resources
- `include "file.txt"` and directory fragment loading
- header-style `include <linux/...>` directives are accepted and ignored
- directory loading of `.txt` and `.txt.const` fragments in sorted order
- unconstrained scalar integer arguments via `int8`, `int16`, `int32`, `int64`, and `intptr`
- endian-qualified scalar ranges via `int16be[min:max]`, `int32be[min:max]`, and `int64be[min:max]`
- typed constants and flags via forms like `const[AF_INET, int16]` and `flags[socket_type, int16]`
- fixed-size struct blocks like `sockaddr_in { ... } [size[16]]`
- bare syzlang-style syscall declarations like `socket(...) sock` and variant names like `socket$inet(...) sock_in` for the currently bundled linux/amd64 syscall subset
- basic syscall attributes via trailing groups like `(automatic_helper)`, `(no_generate)`, and `(disabled)`
- derived length arguments via `len[target]` and `len[target, int32]`
- byte-size relations via `bytesize[target]` and `bytesize[target, int32]`
- directional blob buffers via `buffer[in]`, `buffer[out]`, and `buffer[inout]`
- optional pointers via `ptr[dir, inner, opt]`
- syscall arguments built from `const[...]`, `flags[...]`, `filename`, `buffer[min:max]`,
  `array[inner; len]`, and `ptr[in|out|inout; inner]`

For a reusable smoke-test target that is closer to upstream `sys/linux/socket.txt`
style than the builtin minimal file, see `descriptions/linux/socket-subset.txt`
plus its sibling `socket-subset.txt.const`. That target now uses a structured
`sockaddr_in` and inet-specific syscall variants such as `socket$inet`,
`bind$inet`, `connect$inet`, and `accept$inet`.

For a more aggressive parser/executor target that also includes direct
`buffer[in|out]` socket I/O shapes like `sendto$inet` and `recvfrom$inet`, see
`descriptions/linux/socket-io-subset.txt`. That target currently keeps
`recvfrom$inet` marked `no_generate` so bounded smoke runs can still exercise
the parser and serializer without defaulting into a blocking receive loop.

## Known Limitations

- Only linux/amd64 target is supported
- Only `sandbox=none` mode is supported
- The builtin target is still a small curated linux/amd64 subset, not full syzkaller coverage
- Copyout-backed result passing is implemented for resource returns and fixed-size output resources, but generic scalar/output modeling is still incomplete
- The description DSL still lacks unions, templates, checksums, vmas, and most of the larger syzlang type system
- Bare syscall-name lookup only covers the currently bundled linux/amd64 syscall subset
- No network sync with a syzkaller manager; runs standalone
- Multi-VM / multi-proc fuzzing is still pending

## Implementation Notes

### Syscall ID Sync

The repository includes `tools/syzkaller-id-dump/`, a tiny helper that reads the
local syzkaller-generated linux/amd64 target and prints exact internal syscall
IDs. It is useful when expanding the builtin Rust target while keeping
wire-level compatibility with the bundled `syz-executor`.

### Varint Encoding

The executor uses signed varint with zigzag encoding, identical to Go's `binary.AppendVarint`:

```
x: i64  →  ux: u64 = (x << 1) ^ (x >> 63)
```

### Data Arguments

`EXEC_ARG_DATA` bytes are written raw with **no alignment padding**. The executor advances its read pointer with `input_pos += size` exactly, so any padding bytes would corrupt the instruction stream.

### Timeout Behavior

In fork-server mode, the executor runner's watchdog fires at `3 × program_timeout_ms`. With `program_timeout_ms=5000` (the default), the watchdog timeout is 15 seconds. The fuzzer restarts the VM if no `ExecResult` is received within that window.
