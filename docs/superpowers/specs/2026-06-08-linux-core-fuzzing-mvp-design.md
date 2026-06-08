# Linux Core Fuzzing MVP Design

## Context

This repository already has a working Linux fuzzing host loop in Rust:

- QEMU VM boot and lifecycle management
- SSH/SCP orchestration for upstream `syz-executor`
- FlatRPC handshake and execution loop
- program generation, mutation, validation, and serialization
- corpus persistence and signal-based retention
- crash, timeout, and repro queue plumbing
- bounded `smoke` and `smoke-suite` commands

It also now has a working target-bundle bridge. The checked-in bundle
`data/target-bundles/linux-amd64-smoke.json` can be loaded by Rust, inspected
with `target-summary`, and executed through a bounded smoke run.

The shortest path to "start testing Linux" is therefore no longer blocked on
the executor protocol or VM management. The main question is where to spend the
next units of effort.

## Problem Statement

The project goal is not "match all of syzkaller before anything is usable." The
near-term goal is to make Linux fuzzing work with the least effort and keep
each iteration runnable.

Two tempting directions are poor fits for that goal right now:

- fully matching upstream syzlang parsing before broadening runtime coverage
- forcing near-complete linux/amd64 target export before we have a stable,
  useful Linux fuzzing target

Both directions spend early effort on breadth and fidelity before the project
has a durable default Linux target that can simply be run.

## Goals

- Make Linux fuzzing usable with minimal additional implementation effort.
- Promote the current smoke-oriented bundle approach into a durable Linux fuzz
  target strategy.
- Keep every iteration runnable and validated with real bounded execution.
- Grow syscall coverage by prioritizing high-yield, low-complexity Linux paths.
- Preserve the existing artifact loop: corpus, crashes, timeouts, and repro
  queue.

## Non-Goals

- Rewriting `syz-executor`.
- Achieving full upstream `linux/amd64` target import in this phase.
- Achieving full syzlang parser parity in this phase.
- Prioritizing advanced minimization, triage, or distributed scheduling.
- Prioritizing complex Linux subsystems with high type/export cost, such as
  BPF, netlink-heavy families, mount/namespace, DRM, media, or block stacks.

## Recommendation

Build and maintain a curated `linux-amd64-core` target bundle as the default
Linux fuzzing MVP.

This target should be larger and more durable than the current 27-syscall smoke
bundle, but it should remain intentionally selective. The principle is:

> Prefer syscall sets that noticeably improve real Linux fuzzing value while
> staying inside the current Rust runtime and exporter comfort zone.

The project should treat "stable, continuously runnable Linux fuzzing" as more
important than "maximum syscall count" in this phase.

## Approaches Considered

### Approach 1: Curated bundle expansion

Keep using the target-bundle path that already works. Expand coverage by
carefully selecting additional Linux syscalls in layers, validating each growth
step with bounded fuzz runs.

Pros:

- lowest implementation risk
- preserves the currently working runtime path
- fastest route to practical Linux fuzzing
- keeps work focused on high-value syscall families

Cons:

- coverage grows manually rather than automatically
- target breadth will lag far behind upstream for a while

### Approach 2: Parser-first growth

Invest primarily in the Rust syzlang parser and description pipeline, then
expand Linux support through larger handwritten or imported description sets.

Pros:

- moves the rewrite toward a more self-contained Rust stack
- improves long-term description fidelity

Cons:

- slower route to usable fuzzing
- expansion remains gated on parser compatibility
- easy to spend a lot of effort without increasing runnable target breadth

### Approach 3: Full-target exporter unblocking

Prioritize fixing the recursive-type/exporter stack overflow and push toward a
much larger or near-complete linux/amd64 bundle quickly.

Pros:

- largest theoretical coverage growth
- aligns with the long-term target-import vision

Cons:

- turns the immediate roadmap back into infrastructure-first work
- risks weeks of exporter/type-system effort before a clearly better default
  Linux target exists

### Selected Approach

Choose Approach 1 for the first Linux fuzzing MVP phase.

The current repository already proves that bundle-backed bounded Linux fuzzing
works. The smallest useful next step is to turn that into a curated core target
that can be run repeatedly, documented clearly, and expanded in measured layers.

## Target Definition

Introduce a first-class curated target bundle named `linux-amd64-core`.

This target is not intended to be a complete Linux target. It is intended to be
the default recommended Linux fuzzing target for the repository until broader
import becomes cheap enough to justify.

The current smoke bundle becomes the seed for this target rather than a separate
long-term direction.

## Layering Strategy

The curated target should grow in four layers ordered by fuzzing value versus
implementation cost.

### Layer A: Survival and memory-management primitives

This layer keeps generation stable and gives the fuzzer enough cheap, reusable
building blocks:

- `mmap`
- `munmap`
- `mprotect`
- `mremap`
- `madvise`
- `msync`
- `getpid`
- `gettid`
- `getuid`
- `getpgid`
- `setpgid`
- `close`
- `dup3`
- `pipe2`
- `eventfd2`

Rationale:

- low dependency depth
- high likelihood of successful execution
- useful for building stable programs early in fuzz runs

### Layer B: File descriptor and file I/O core path

This layer establishes realistic resource chains around `fd` values:

- `openat`
- `read`
- `write`
- `writev`
- `pread64`
- `pwrite64`
- `lseek`
- `fstat`
- `newfstatat`
- `getcwd`
- `mkdirat`

Optional additions only if they require no new runtime IR category and no new
exporter mechanism beyond what already works for the smoke bundle:

- `readlinkat`
- `getdents64`
- `renameat2`

Rationale:

- file syscalls are cheap to express and easy to keep runnable
- they create rich `fd` usage patterns for later families
- they improve corpus diversity without immediately requiring complex structs

### Layer C: Socket baseline

This layer adds a real networking/resource path without trying to cover all of
Linux networking:

- `socket`
- `socketpair`
- `bind`
- `listen`
- `accept`
- `connect`
- `sendmsg`
- `sendmmsg`
- `recvmsg`
- `setsockopt`
- `getsockopt`

Initial focus should stay on simple `AF_UNIX` and basic `AF_INET` forms already
close to current support.

Rationale:

- increases signal diversity substantially
- stays within the current executor/runtime architecture
- avoids immediate expansion into protocol-specific complexity

### Layer D: ioctl-lite

This layer admits only generic or already-supported ioctl paths that are cheap
to model and useful in practice:

- simple integer or buffer-oriented `ioctl` requests such as `FIONREAD`
- already smoke-tested socket ioctl variants

Rationale:

- `ioctl` is valuable but easy to over-expand into costly subsystem-specific
  work
- the MVP should admit only low-friction `ioctl` coverage

## Explicit Deferrals

To protect the MVP, the following work stays out of scope for this phase:

- full `linux/amd64` exporter support
- recursive target export redesign
- parser parity with upstream syzlang
- complex subsystem enablement for syscall-count optics
- broad scheduler or multi-VM architecture changes

These are good future projects, but they do not help the shortest path to
"start fuzzing Linux now" enough to justify front-loading them.

## Milestones

### M0: Linux smoke works

Objective:

- formalize the currently working bundle-backed Linux smoke path as a supported
  entry point

Expected state:

- documented default Linux entry path
- stable `target-summary`
- stable bounded `smoke`
- artifact paths still intact

### M1: Linux core bundle works

Objective:

- expand the current smoke seed into a curated `linux-amd64-core` bundle with
  at least 40 selected syscalls, and normally no more than about 70 during this
  phase unless expansion stays inside the four defined layers without
  increasing complexity materially

Expected state:

- Layer A and Layer B fully or mostly included
- initial Layer C coverage included
- most enabled syscalls are generatable
- README documents the core target as a normal Linux fuzzing target

### M2: Linux core fuzzing is sustainable

Objective:

- verify that the curated core target behaves like a practical bounded fuzzer,
  not just a smoke demo

Expected state:

- a longer bounded run such as `max_execs=128` or `256`
- corpus grows over time
- manager and VM lifecycle remain stable
- timeout/crash/repro paths still function

## Acceptance Criteria

The MVP phase is complete when all of the following are true:

1. `linux-amd64-core` exists as a repository-supported target bundle.
2. The target contains at least 40 enabled syscalls and materially exceeds the
   current 27-syscall smoke bundle in useful Linux coverage.
3. `cargo test` remains green.
4. `go test ./...` in `tools/syzkaller-target-bundle` remains green.
5. `target-summary bundle:...` shows the curated target is mostly generatable.
6. A bounded Linux fuzz run longer than a trivial smoke pass completes without
   obvious runtime regression.
7. Corpus, timeout, crash, and repro artifacts still round-trip correctly.
8. README documents how to inspect and run the target.

## Testing Strategy

Every expansion step must preserve runnable software.

Required validation loop for each iteration:

1. update or regenerate the curated bundle
2. run focused exporter tests
3. run Rust unit/integration tests
4. run `target-summary` on the curated bundle
5. run a real bounded Linux fuzz pass using the curated bundle

The project should reject coverage-only progress that is not backed by an
actual bounded run.

## Immediate Next Subproject

The next implementation subproject should not attempt all MVP milestones at
once. It should focus on the smallest useful upgrade:

- promote the checked-in smoke bundle into the first `linux-amd64-core` target
  revision
- expand it with a small Layer A and Layer B increment
- wire documentation and command examples around the core target
- validate with both tests and a real bounded run

This preserves the smallest-effort philosophy while creating a better default
Linux fuzzing target immediately.

## Future Follow-On Work

After the MVP phase is stable, the project can re-evaluate whether the next
highest-value effort is:

- continuing curated bundle expansion
- unblocking recursive exporter support for broader import
- improving parser compatibility to reduce manual curation

That decision should be made based on which effort most directly improves real
Linux fuzzing throughput at that time, not on architectural purity alone.
