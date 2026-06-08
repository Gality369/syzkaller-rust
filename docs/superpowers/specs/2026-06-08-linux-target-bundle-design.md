# Linux Target Bundle Design

## Context

This project is a Rust reimplementation of the core host-side logic of
`syzkaller` for Linux kernel fuzzing. The current repository already has a
working host loop with:

- syscall description parsing for a focused syzlang subset
- program generation, mutation, validation, and executor serialization
- QEMU/SSH-based `syz-executor` orchestration
- corpus persistence, crash detection, timeout capture, and repro queue support
- bounded `smoke` and `smoke-suite` commands

The main functional gap is target breadth. The current builtin target is the
minimal `descriptions/linux/amd64-minimal.txt` bundle, which only exposes a
small Linux/amd64 syscall set. That is enough for infrastructure testing, but
it is not enough to grow into a practical Linux-only fuzzer.

Upstream `syzkaller` treats syscall descriptions as an input language that is
compiled into a machine-usable target, and `syz-manager` then operates on that
compiled target during generation, execution, and crash handling. We will keep
that boundary in the Rust rewrite.

## Problem Statement

We need a way to expand the Linux/amd64 syscall surface quickly while keeping
every intermediate version runnable.

Trying to fully replicate upstream `syzlang` parsing and compilation before
expanding coverage is too risky for early milestones:

- it delays practical fuzzing progress
- it increases the chance of large, hard-to-verify parser work
- it makes it difficult to keep each iteration runnable

At the same time, continuing to hand-maintain small description subsets scales
too slowly to reach a functionally complete Linux fuzzer.

## Goals

- Keep the existing Rust runtime IR as the single source of truth for execution.
- Expand Linux/amd64 syscall coverage without waiting for full `syzlang`
  compatibility.
- Preserve a stable runnable path in every iteration.
- Make target loading uniform across builtin descriptions, syzlang files, and a
  new exported bundle format.
- Surface unsupported syscalls and types explicitly instead of silently
  degrading them.
- Provide visibility into coverage growth through `target-summary`.

## Non-Goals

- Rewriting `syz-executor` in this phase.
- Achieving complete compatibility with upstream `sys/linux/*.txt` parsing in
  the first milestone.
- Importing every upstream Linux syscall immediately.
- Reworking crash triage, minimization, or advanced scheduling before target
  breadth improves.
- Supporting non-Linux operating systems.

## Recommendation

Use a staged "target bundle" bridge:

1. Keep the current Rust runtime IR (`SyscallDesc`, `ArgType`, `ResourceDesc`,
   `Program`) unchanged as the execution-time contract.
2. Add a new offline exporter, implemented in Go, that reads upstream
   `prog.GetTarget("linux", "amd64")` and serializes only the Rust-supported
   syscall/type subset into a JSON bundle.
3. Add a Rust loader for that JSON bundle and route all target loading through a
   single source abstraction.
4. Preserve the builtin minimal target as a fallback while validating bundle
   support through tests and bounded smoke runs.

This gives us a fast path to larger Linux coverage while keeping parser work
incremental and driven by real gaps.

## Architecture

### Runtime Boundary

The runtime continues to be fully owned by Rust:

- target load
- target validation
- program generation and mutation
- executor serialization
- VM lifecycle
- coverage/corpus handling
- crash and timeout capture
- repro queue logic

The only upstream dependency introduced by this design is an offline target
export step that materializes a Rust-consumable bundle from upstream
`syzkaller` metadata.

### Target Source Model

Introduce a unified target source layer with three source kinds:

- `BuiltinMinimal`
  Loads the current embedded minimal Linux/amd64 descriptions.
- `DescriptionPath`
  Loads an explicit syzlang file or directory through the current Rust parser.
- `BundlePath`
  Loads an exported JSON bundle.

All three sources must converge into the same in-memory IR:

- `Vec<SyscallDesc>`
- `Vec<ResourceDesc>` as embedded by descriptors
- existing validation and generation semantics

### Fail-Closed Import Semantics

The bundle export/import pipeline must reject ambiguity.

Rules:

- unsupported upstream syscall/type forms are skipped by the exporter
- every skip is counted and categorized
- imported bundle metadata includes skip statistics
- Rust never silently weakens a type during load
- Rust target validation still runs after bundle load

This keeps target expansion measurable and safe.

## Bundle Format

The first bundle format will be JSON for ease of debugging and testability.

Suggested top-level shape:

```json
{
  "format_version": 1,
  "source": {
    "kind": "upstream-syzkaller",
    "os": "linux",
    "arch": "amd64",
    "syzkaller_git_revision": "..."
  },
  "export_summary": {
    "total_syscalls": 0,
    "exported_syscalls": 0,
    "skipped_syscalls": 0,
    "skip_reasons": []
  },
  "syscalls": [],
  "resources": []
}
```

The exact syscall entries should map directly onto current Rust IR concepts
rather than mirroring upstream Go types 1:1. The format exists to feed the Rust
runtime, not to be a generic interchange format.

## Exporter Design

Add a new Go tool under `tools/` that:

- loads upstream target metadata through `prog.GetTarget("linux", "amd64")`
- walks the syscall/type graph
- converts only supported forms into Rust bundle entries
- records precise skip reasons for unsupported constructs
- emits deterministic JSON

Initial supported forms should match what the Rust IR and serializer already
support well today:

- scalar constants and ranged integers
- flags backed by scalar integer storage
- resources and optional resources
- pointers with in/out/inout directions
- plain buffers and strings
- filenames
- arrays
- fixed and selected variable-sized structs/unions already represented by the
  current IR
- length-derived fields already handled by Rust validation/generation
- VMA/proc/compressed-image forms already present in the Rust model

The exporter must not invent approximations for unsupported upstream constructs.

## Rust Loader Design

### New Loader Entry Point

Refactor target loading so all call sites use a single source-driven entry point
instead of directly assuming "optional description path".

This loader should:

1. resolve the requested target source
2. load syscall descriptors from the appropriate backend
3. validate the resulting descriptor set
4. return both descriptors and source metadata for reporting

### Source Metadata

Target load results should carry source metadata including:

- human-readable source label
- source kind
- optional source revision
- optional export summary

This metadata will feed:

- `target-summary`
- smoke reports
- future corpus compatibility checks

### Corpus and Artifact Compatibility

This milestone does not need a full target hash enforcement scheme, but the
loader must expose enough stable metadata to support a later target-identity
check without redesigning the loader interface.

At minimum, we should preserve source identity in summaries and reports so it is
easy to reason about whether a workdir was produced from:

- builtin minimal target
- hand-authored subset descriptions
- exported upstream bundle

## CLI and Config Changes

### Configuration

The current config supports `syscall_descriptions`.

For backward compatibility, keep that field working. Add support for a new
bundle-oriented field:

- `target_bundle`

The resolved precedence should be explicit:

1. explicit CLI target override
2. explicit config bundle path
3. explicit config syzlang description path
4. builtin minimal target fallback

### Commands

Update:

- `target-summary`
- `smoke`
- `smoke-suite`
- repro-related target loading paths

All of them should flow through the same target source abstraction.

## Testing Strategy

Every iteration must remain runnable.

### Required Verification for This Milestone

- `cargo test` passes
- new bundle loader tests pass
- `target-summary` supports bundle inputs
- generated bundle target has more usable syscalls than the builtin minimal
  target
- bounded smoke runs succeed on at least one exported bundle-backed target

### Test Types

- unit tests for bundle JSON decoding and validation
- regression tests for `target-summary` source labels and counts
- generation/serialization tests using imported syscall descriptors
- exporter fixture tests for deterministic skip accounting
- end-to-end bounded smoke using a conservative bundle-backed target

## Milestones

### M0: Keep Current Baseline Stable

- preserve builtin minimal target
- preserve existing smoke and smoke-suite flows
- preserve corpus/crash/repro behavior

### M1: Unified Target Source Layer

- add source abstraction
- load builtin, description path, and bundle path through one entry point
- update summaries and command paths

### M2: Bundle Export/Import

- implement Go exporter
- implement Rust bundle loader
- add bundle-aware tests

### M3: Expand Conservative Linux Coverage

- export a stable supported subset much larger than 24 syscalls
- verify generation and serialization against that target
- add bundle-backed smoke coverage

### M4: Use Real Gaps to Drive Parser and IR Growth

- identify skipped syscall/type classes from exporter stats
- add the highest-value missing forms to Rust IR/parser/serializer
- re-export and increase supported coverage

## Risks

### Risk: Bundle and Parser Diverge

The bundle path and the syzlang parser may temporarily support different target
surfaces.

Mitigation:

- keep one runtime IR
- keep one target validation path
- keep `target-summary` comparable across sources

### Risk: Exported Syscalls Validate but Serialize Poorly

Some imported descriptors may pass shape validation but still expose serializer
or generator gaps.

Mitigation:

- gate new coverage through generation + serialization tests
- use bounded smoke instead of relying only on unit tests

### Risk: Hidden Approximation Bugs

The exporter could accidentally coerce unsupported upstream constructs into
incorrect Rust equivalents.

Mitigation:

- fail-closed conversion
- explicit skip reasons
- deterministic exporter fixtures

## Alternatives Considered

### Full Parser-First Compatibility

Rejected for the first milestone because it delays practical fuzzing progress
and creates a long period where the project is technically improving but not
materially expanding Linux fuzz coverage.

### Continue Hand-Maintaining Small Subsets

Rejected as the main strategy because it scales too slowly to reach a functionally
complete Linux-only fuzzer.

## First Implementation Slice

The first concrete implementation after this spec should include:

1. `TargetSource` abstraction in Rust
2. bundle JSON schema and loader
3. upstream exporter tool in `tools/`
4. bundle-aware `target-summary`
5. tests proving bundle load, validation, and generation
6. one bounded smoke path using a conservative bundle-backed target

## Success Criteria

This design is successful when:

- the repository still has a stable runnable builtin target
- a second target source kind (`bundle`) is supported end-to-end
- `target-summary` makes coverage growth visible
- the project can expand Linux syscall coverage without blocking on complete
  parser parity
- future iterations can focus on the highest-value skipped syscall/type classes
  rather than guessing what to implement next
