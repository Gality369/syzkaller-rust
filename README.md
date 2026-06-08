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

Start from the checked-in template and keep your machine-specific paths in an
untracked local file:

```bash
cp config.example.json config.local.json
```

Then edit `config.local.json`:

`config.example.json` already includes the recommended Linux core bundle target:
`data/target-bundles/linux-amd64-core.json`.

`max_execs` is optional. When set, the manager exits cleanly after that many
execution requests (including timed out ones), which is useful for bounded smoke tests and scripted
end-to-end checks.

`target_bundle` is also optional. When present, the runtime loads exported JSON
target metadata instead of `syscall_descriptions`:

```json
{
    "target_bundle": "data/target-bundles/linux-amd64-core.json"
}
```

## Running

```bash
RUST_LOG=info ./target/release/syzkaller-rust config.local.json
```

Log levels: `error` / `warn` / `info` / `debug`.

## Smoke Run

For a bounded end-to-end smoke run, use the dedicated CLI wrapper instead of
editing `config.json` by hand:

```bash
RUST_LOG=info ./target/release/syzkaller-rust smoke config.local.json
```

By default this:

- forces `max_execs=32`
- uses `data/target-bundles/linux-amd64-core.json` when the config does not
  already specify `target_bundle` or `syscall_descriptions`
- validates the configured kernel/image/executor/QEMU paths before starting
- runs inside a clean per-target workdir at
  `<workdir>/smoke/<target-slug>`, resetting that directory before each run
- prints a JSON summary after the bounded run completes

That keeps bounded smoke corpus and crash artifacts separate from any longer
running fuzz session that uses the base `workdir`.

For a multi-target regression pass with isolated per-target workdirs, use the
suite wrapper:

```bash
RUST_LOG=info ./target/release/syzkaller-rust smoke-suite config.local.json
```

By default this runs:

- `descriptions/linux/file-subset.txt`
- `descriptions/linux/path-info-subset.txt`
- `descriptions/linux/dirent-subset.txt`
- `descriptions/linux/pipe-io-subset.txt`
- `descriptions/linux/msg-io-subset.txt`
- `descriptions/linux/recvmsg-io-subset.txt`
- `descriptions/linux/recvmmsg-io-subset.txt`
- `descriptions/linux/dgram-io-subset.txt`
- `descriptions/linux/socket-io-subset.txt`
- `descriptions/linux/sockopt-buf-subset.txt`
- `descriptions/linux/sock-ifreq-subset.txt`
- `descriptions/linux/sock-ifconf-subset.txt`
- `descriptions/linux/sock-ethtool-subset.txt`
- `descriptions/linux/pipe-fionread-subset.txt`
- `descriptions/linux/accept-connect-subset.txt`
- `descriptions/linux/socket-subset.txt`
- `descriptions/linux/image-subset.txt`
- `descriptions/linux/mm-subset.txt`
- `descriptions/linux/process-subset.txt`

Each target gets its own clean workdir under `workdir/smoke-suite/<slug>`, so
corpus and artifact summaries do not bleed across targets.

You can override either one:

```bash
RUST_LOG=info ./target/release/syzkaller-rust smoke config.local.json 8
RUST_LOG=info ./target/release/syzkaller-rust smoke config.local.json 8 descriptions/linux/socket-io-subset.txt
RUST_LOG=info ./target/release/syzkaller-rust smoke config.local.json 1 descriptions/linux/image-subset.txt
RUST_LOG=info ./target/release/syzkaller-rust smoke config.local.json 4 bundle:data/target-bundles/linux-amd64-core.json
RUST_LOG=info ./target/release/syzkaller-rust smoke-suite config.local.json 4 descriptions/linux/mm-subset.txt descriptions/linux/process-subset.txt
RUST_LOG=info ./target/release/syzkaller-rust smoke-suite config.local.json 1 descriptions/linux/socket-io-subset.txt
```

The following directories are created under `workdir/` at runtime:
- `crashes/` — kernel crash reports (console output)
- `timeouts/` — timed-out or executor-reported hanged programs, including their syscall shape and timeout-prone edge profile, for later triage

Timeout artifacts also preserve the latest guest serial tail, and when available
the `syz-executor` SSH stdout/stderr stream, so executor-side hangs can be
triaged without rerunning the whole smoke target immediately.

Timeout and hang artifacts now also include a lightweight per-request trace
showing whether the manager observed `Executing`, opaque `State`, or
`ExecResult` messages before the request stalled.

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

## Target Bundles

The repository now ships two checked-in Linux bundle fixtures:

- `data/target-bundles/linux-amd64-smoke.json`
  - the narrow 27-syscall smoke seed used to prove out the original bundle path
- `data/target-bundles/linux-amd64-core.json`
  - the curated 41-syscall Linux core target that the bounded `smoke` command
    now uses by default

The `linux-amd64-core` target currently includes:

`accept`, `bind`, `close`, `connect`, `dup3`, `eventfd2`, `fstat`, `getcwd`, `getegid`, `geteuid`, `getgid`, `getpgid`, `getpid`, `getsockopt`, `gettid`, `getuid`, `ioctl`, `listen`, `lseek`, `madvise`, `mkdirat`, `mmap`, `mprotect`, `mremap`, `msync`, `munmap`, `newfstatat`, `openat`, `pipe2`, `pread64`, `pwrite64`, `read`, `recvmsg`, `sendmmsg`, `sendmsg`, `setpgid`, `setsockopt`, `socket`, `socketpair`, `write`, `writev`

To regenerate the curated core bundle from upstream syzkaller target metadata:

```bash
cd tools/syzkaller-target-bundle
go run . \
  --syscalls-file ../../data/target-bundles/linux-amd64-core.syscalls \
  --output ../../data/target-bundles/linux-amd64-core.json
```

You can inspect bundle coverage without booting a VM:

```bash
cargo run --quiet -- target-summary bundle:data/target-bundles/linux-amd64-core.json 12
```

Recommended bounded Linux run:

```bash
RUST_LOG=info ./target/release/syzkaller-rust smoke config.local.json 128 bundle:data/target-bundles/linux-amd64-core.json
```

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
- ranged fixed-element arrays via `array[int8, 4:8]`, `array[qid, 1:3]`, and
  default short arrays like `array[int8]`
- variable-sized array elements behind pointer or top-level array values, with
  preserved per-element boundaries so `array[cmsghdr_like, 1:2]`-style message
  batches can derive both total byte size and element count without collapsing
  back to opaque flat buffers
- trailing variable-sized struct fields when the final field is a fixed-element
  array, so packed message shapes like `{ count bytesize[data]; data array[...] }`
  can materialize and validate without falling back to raw buffers
- inline pointer fields inside fixed-size structs, unions, and arrays of structs,
  including `iovec`-style layouts where nested `len[...]` fields track pointed-to
  payload sizes and executor serialization emits nested copyins
- nested pointer-bearing containers like `msghdr` layouts, where optional inline
  pointers derive zero lengths when absent and nested `array[iovec]` fields keep
  per-element payload lengths and aggregate counts aligned
- output-oriented nested containers like `recv_msghdr`, where inline `ptr[out]`
  fields materialize zeroed reserved buffers with real capacities instead of
  collapsing to opaque placeholder pointers
- default C-style struct padding plus explicit `[packed]` / `align[N]` layout
  semantics, so `msghdr`-style fixed headers and aligned trailing payload
  containers derive real field offsets and total sizes instead of packed-byte
  approximations
- aligned control-message batches inside `send_msghdr`-style containers, where
  `msg_control ptr[in, array[cmsghdr_like, ...]]` keeps element boundaries,
  aligned `cmsg_len` values, and aggregate `msg_controllen` sizes consistent
  through generation, validation, replay, and executor copyin
- batched message vectors like `array[send_mmsghdr, 1:2]`, where each fixed-size
  element embeds a full `msghdr` container plus its own per-message metadata,
  so `sendmmsg`-style inputs keep nested lengths and optional pointers coherent
  across multiple messages in one syscall
- union blocks like `sockaddr_arg [ v4 sockaddr_in v6 buffer[28:28] ]`, including
  fixed-size `[size[N]]` unions and `[varlen]` unions
- virtual memory area arguments via `vma`, `vma[opt]`, `vma[N]`, and `vma[min:max]`
- string arguments via `string`, `string["literal"]`, `string[set_name]`,
  `string[filename]`, `string[..., N]`, and `stringnoz[...]`
- top-level string-set definitions like `names = "foo", "bar"`
- parameterized top-level `type` templates for aliases, structs, and unions, such as
  `type wrap[PAYLOAD] { payload PAYLOAD }` and `type alias_wrap[PAYLOAD] wrap[PAYLOAD]`
- parent-derived inline sizes inside fixed-size structs and struct templates via
  `len[parent, intN]` and `bytesize[parent, intN]`
- zero-sized `void` fields plus `offsetof[field, intN]` for fixed-size struct
  layouts, which is enough for small `nlattr`-style headers
- rooted named-path size targets via forms like `len[arg:field]`,
  `bytesize[type_name:field]`, `bytesize[parent:parent:field]`,
  `bytesize[syscall:arg]`, and nested `offsetof[type_name:field:subfield, intN]`
- bare syzlang-style syscall declarations like `socket(...) sock` and variant names like `socket$inet(...) sock_in` for the currently bundled linux/amd64 syscall subset
- basic syscall attributes via trailing groups like `(automatic_helper)`, `(no_generate)`, and `(disabled)`
- derived length arguments via `len[target]` and `len[target, int32]`
- byte-size relations via `bytesize[target]` and `bytesize[target, int32]`
- directional blob buffers via `buffer[in]`, `buffer[out]`, and `buffer[inout]`
- optional pointers via `ptr[dir, inner, opt]`
- syscall arguments built from `const[...]`, `flags[...]`, `filename`, `buffer[min:max]`,
  `array[inner; len]` (including pointer-backed arrays of variable-sized
  elements), and `ptr[in|out|inout; inner]`

For a reusable smoke-test target that is closer to upstream `sys/linux/socket.txt`
style than the builtin minimal file, see `descriptions/linux/socket-subset.txt`
plus its sibling `socket-subset.txt.const`. That target now uses a structured
`sockaddr_in` and inet-specific syscall variants such as `socket$inet`,
`bind$inet`, `connect$inet`, and `accept$inet`.

For a more aggressive parser/executor target that also includes direct
`buffer[in|out]` socket I/O shapes like `sendto$inet` and `recvfrom$inet`, see
`descriptions/linux/socket-io-subset.txt`. That target is now a narrowed
AF_INET datagram subset with `recvfrom$inet` kept `no_generate`, so bounded
smoke runs can probe real inet serialization without immediately defaulting
into a receive loop. It is back in the default `smoke-suite` matrix after
fixing top-level bare `buffer[in]` exec encoding for `sendto$inet`; bounded
smoke now runs cleanly on the current QEMU/manager setup.

If you want the older, broader socket lifecycle pressure target, see
`descriptions/linux/socket-io-stress-subset.txt`, which preserves the previous
include-based `socket/bind/connect/listen/accept/sendto/recvfrom` mix for
parser and resource-chain probing. It is still kept out of the default
`smoke-suite` matrix to avoid overlap with the narrower socket targets, but the
current bounded smoke path now runs it cleanly as a targeted stress check too.

For a minimal generic sockopt data-path target that exercises direct
`setsockopt(buffer[in])` / `getsockopt(buffer[out])` arguments on plain
syscalls rather than typed pointer wrappers, see
`descriptions/linux/sockopt-buf-subset.txt`.

For a minimal socket ioctl data-path target that exercises `ptr[inout, ifreq]`
style payloads on real network ioctls, see
`descriptions/linux/sock-ifreq-subset.txt`.

For a nested socket ioctl data-path target that exercises `ptr[inout, struct]`
where the struct itself contains a nested `ptr[inout, buffer]`, see
`descriptions/linux/sock-ifconf-subset.txt`.

For a nested socket ioctl target that exercises `ptr[inout, ifreq]` where the
payload field itself is a typed `ptr[inout, struct]`, see
`descriptions/linux/sock-ethtool-subset.txt`.

For a minimal top-level `buffer[inout]` target on a stable kernel interface,
see `descriptions/linux/pipe-fionread-subset.txt`, which uses `pipe2` plus
`ioctl(FIONREAD)` on the read end.

For execution-side smoke coverage beyond files, sockets, and image helpers, the
repository also includes:

- `descriptions/linux/pipe-io-subset.txt` for `pipe2` / `writev` / `close`
- `descriptions/linux/file-subset.txt` for `openat(O_RDWR|O_CREAT|O_TRUNC)` / `write(buffer[in])` / `pwrite64(buffer[in])` / `lseek(SEEK_SET)` / `read(buffer[out])` / `pread64(buffer[out])` / `readv(iovec_out)` / `preadv(iovec_out)` / `close`
- `descriptions/linux/msg-io-subset.txt` for `socketpair` / `sendmsg` / `sendmmsg` / `close`
- `descriptions/linux/recvmsg-io-subset.txt` for `socketpair` / `sendmsg` / `recvmsg(MSG_DONTWAIT)`
- `descriptions/linux/recvmmsg-io-subset.txt` for `socketpair` / `sendmmsg` / `recvmmsg(MSG_DONTWAIT)`
- `descriptions/linux/dgram-io-subset.txt` for `socketpair` / `sendto` / `recvfrom(MSG_DONTWAIT)`
- `descriptions/linux/sockopt-buf-subset.txt` for generic `socketpair` / `setsockopt(buffer[in])` / `getsockopt(buffer[out])` / `close`
- `descriptions/linux/sock-ifreq-subset.txt` for `socket$inet` / `ioctl(SIOCGIFINDEX)` / `ioctl(SIOCGIFMTU)` / `close` over a fixed `lo` ifreq payload
- `descriptions/linux/sock-ifconf-subset.txt` for `socket$inet` / `ioctl(SIOCGIFCONF)` / `close` over an `ifconf`-style nested inout buffer payload
- `descriptions/linux/sock-ethtool-subset.txt` for `socket$inet` / `ioctl(SIOCETHTOOL)` / `close` over `ifreq` payloads whose `ifr_data` field is a typed nested `ptr[inout, ethtool_drvinfo]`, `ptr[inout, ethtool_wolinfo]`, `ptr[inout, ethtool_regs]`, `ptr[inout, ethtool_eeprom]`, `ptr[inout, ethtool_tunable_u32]`, `ptr[inout, ethtool_value]`, `ptr[inout, ethtool_msglvl_value]`, `ptr[inout, ethtool_rx_csum_value]`, `ptr[inout, ethtool_tx_csum_value]`, `ptr[inout, ethtool_gro_value]`, `ptr[inout, ethtool_sg_value]`, `ptr[inout, ethtool_tso_value]`, `ptr[inout, ethtool_ufo_value]`, `ptr[inout, ethtool_gso_value]`, `ptr[inout, ethtool_flags_value]`, `ptr[inout, ethtool_pflags_value]`, `ptr[inout, ethtool_rxfh_indir_min]`, `ptr[inout, ethtool_rxfh_min]`, `ptr[inout, ethtool_rxfh_keyed]`, `ptr[inout, ethtool_rxnfc_hash_min]`, `ptr[inout, ethtool_rxnfc_rule_query_min]`, `ptr[inout, ethtool_rxnfc_tcp_v4_query_min]`, `ptr[inout, ethtool_rxnfc_tcp_v4_ext_query_min]`, `ptr[inout, ethtool_rxnfc_tcp_v4_mac_ext_query_min]`, `ptr[inout, ethtool_rxnfc_rss_query_min]`, `ptr[inout, ethtool_rxnfc_rings_min]`, `ptr[inout, ethtool_rxnfc_rule_cnt_min]`, `ptr[inout, ethtool_rxnfc_rule_locs_min]`, `ptr[inout, ethtool_pauseparam]`, `ptr[inout, ethtool_gstrings]`, `ptr[inout, ethtool_gfeatures]`, `ptr[inout, ethtool_channels]`, `ptr[inout, ethtool_coalesce]`, `ptr[inout, ethtool_ringparam]`, `ptr[inout, ethtool_modinfo]`, `ptr[inout, ethtool_module_eeprom]`, `ptr[inout, ethtool_eee]`, `ptr[inout, ethtool_ts_info]`, `ptr[inout, ethtool_link_settings_min]`, `ptr[inout, ethtool_sset_info]`, `ptr[inout, ethtool_stats]`, or `ptr[inout, ethtool_perm_addr]`
- `descriptions/linux/pipe-fionread-subset.txt` for `pipe2` / `write` / `ioctl(FIONREAD, buffer[inout])` / `close`
- `descriptions/linux/accept-connect-subset.txt` for nonblocking `socket/setsockopt(SO_REUSEADDR)/bind/listen/connect/accept/accept4/getsockname/getpeername/getsockopt(SO_ERROR)/shutdown/close` over loopback TCP
- `descriptions/linux/mm-subset.txt` for `mmap` / `mprotect` / `madvise` / `msync` / `mremap` / `munmap`
- `descriptions/linux/process-subset.txt` for `getpid` / `gettid` / `getpgid` / `setpgid`

## Known Limitations

- Only linux/amd64 target is supported
- Only `sandbox=none` mode is supported
- The builtin target is still a small curated linux/amd64 subset, not full syzkaller coverage
- Copyout-backed result passing is implemented for resource returns and fixed-size output resources, but generic scalar/output modeling is still incomplete
- The description DSL still lacks `self` relations, conditional fields, checksums, bitfields, and most of the larger syzlang type system
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
