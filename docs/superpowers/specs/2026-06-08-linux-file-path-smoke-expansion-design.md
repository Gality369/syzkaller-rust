# Linux File/Path Smoke Expansion Design

## Context

The repository now has a stable Linux fuzzing entry path:

- bounded `smoke` defaults to the curated `linux-amd64-core` bundle
- `smoke-suite` already runs a matrix of isolated regression targets
- real bounded Linux runs succeed through upstream `syz-executor`
- file I/O, socket, process, and memory-management subsets already provide
  broad coverage of the current execution pipeline

The next highest-value step is not a wider default bundle. It is expanding the
execution regression surface with a few additional low-cost Linux file/path
targets that are easy to run and easy to debug when they fail.

## Problem Statement

The current smoke matrix already covers ordinary file I/O through
`openat/read/write/pread64/pwrite64/readv/preadv/close`, but it still has a
gap around Linux path-oriented filesystem calls:

1. there is no dedicated smoke target for stable path metadata operations such
   as `getcwd`, `newfstatat`, and `readlinkat`
2. there is no dedicated smoke target for directory enumeration via
   `openat -> getdents64 -> close`
3. without these targets, the project has less direct regression coverage for:
   - fixed path inputs
   - output buffers paired with returned lengths
   - pointer-to-struct metadata outputs
   - directory-fd resource chains
   - larger top-level output buffer encoding

These are valuable Linux syscall shapes, and they can be added with much less
effort than widening the default core bundle.

## Goals

- Add a cheap, stable path-metadata smoke target.
- Add a cheap, stable directory-enumeration smoke target.
- Keep both targets independent from the default `linux-amd64-core` bundle.
- Extend `smoke-suite` coverage without making bounded Linux runs harder to
  reason about.
- Keep the subproject small enough for a single short implementation cycle.

## Non-Goals

- Expanding the default `linux-amd64-core` bundle in this subproject.
- Adding stateful path mutation flows such as `renameat2`.
- Reworking filename generation or path reuse strategy globally.
- Running longer `256/512`-exec stability campaigns in this subproject.
- Expanding socket, process, or mm regression targets here.

## Approaches Considered

### Approach 1: Expand the existing file subset only

Keep everything inside `descriptions/linux/file-subset.txt` and broaden that
single target with more path-oriented syscalls.

Pros:

- smallest file count increase
- no new smoke targets to document

Cons:

- mixes ordinary file I/O regressions with path-metadata regressions
- failures become harder to localize
- makes one target do too many unrelated things

### Approach 2: Add two focused file/path smoke targets

Create one target for path metadata and one target for directory enumeration,
then add them to `smoke-suite`.

Pros:

- keeps failures easy to localize
- broadens Linux execution coverage with minimal conceptual overhead
- avoids contaminating the default core bundle
- fits the current regression-target style well

Cons:

- adds two more checked-in subset files
- slightly enlarges the default smoke-suite matrix

### Approach 3: Widen the core bundle first

Push these syscalls directly into `linux-amd64-core.json` and rely on bounded
core smoke runs to validate them.

Pros:

- default bounded Linux target becomes broader immediately

Cons:

- failures affect the main Linux entry path instead of an isolated regression
  target
- makes it harder to distinguish coverage expansion from regression isolation

## Selected Approach

Choose Approach 2.

This is the best match for the project’s current priority: increase Linux
execution coverage with the smallest possible blast radius. New syscall shapes
should first prove themselves in isolated smoke targets before they influence
the default bundle.

## Design

### 1. `path-info-subset.txt`

Add a new Linux description subset focused on stable path metadata calls.

The first version should include:

- `getcwd`
- `newfstatat`
- `readlinkat`

The target should favor deterministic paths that already exist on a normal
Linux guest, such as:

- `.`
- `/proc/self/exe`
- `/proc/self/cwd`

The design goal is to cover these execution shapes cheaply:

- fixed path input strings
- top-level output buffers
- pointer-to-output-struct arguments
- path-related return values that coexist with output data

This target should avoid cross-call path mutation and avoid depending on guest
filesystem side effects.

### 2. `dirent-subset.txt`

Add a second Linux description subset focused on directory enumeration.

The first version should include:

- `openat`
- `getdents64`
- `close`

The directory path should be deterministic and always present on a normal Linux
guest, with `/proc` as the preferred starting point.

The design goal is to cover:

- directory-fd resource creation and consumption
- a larger top-level output buffer
- directory-entry style variable output payloads
- a simple open-consume-close lifecycle

This target should stay intentionally narrow. It is not meant to become a full
directory traversal workload in this iteration.

### 3. Smoke-Suite Integration

Once each target passes on its own, add both to the default `smoke-suite`
matrix.

This preserves the existing operating model:

- each target gets its own isolated workdir
- failures remain attributable to a single subset
- the default Linux bounded `smoke` entry remains the curated core bundle

The suite should not be changed before the individual targets have their own
`target-summary` and bounded `smoke` coverage working.

### 4. Testing Strategy

This subproject should be validated in three layers:

1. description-level coverage
   - each new subset must load through `target-summary`
   - each syscall in the subset should be transitively enabled and generatable

2. Rust regression coverage
   - update `src/main.rs` smoke-suite regression expectations
   - add or extend any parser/generation tests only if the new subsets expose a
     real missing shape

3. real bounded Linux runs
   - run each new target through bounded `smoke`
   - after both pass individually, run `smoke-suite` including them

This keeps the implementation aligned with the project rule that each
iteration must remain runnable, not merely parsable.

## Acceptance Criteria

This subproject is complete when all of the following are true:

1. a checked-in `path-info-subset.txt` exists and passes `target-summary`
2. a checked-in `dirent-subset.txt` exists and passes `target-summary`
3. both new targets are fully generatable in their subset summaries
4. both targets pass at least one bounded Linux `smoke` run
5. both targets are added to the default `smoke-suite` target list
6. `cargo test` continues to pass
7. README remains accurate about the smoke-suite regression matrix

## Immediate Implementation Scope

The implementation plan for this subproject should stay narrow:

1. add `path-info-subset.txt`
2. add `dirent-subset.txt`
3. extend `smoke-suite` defaults and related tests
4. update README target lists if needed
5. run `target-summary`, `cargo test`, and bounded Linux smoke verification

## Deferred Follow-On Work

After this lands cleanly, the next pragmatic choices remain:

- expand more file/path regression targets such as `renameat2` or
  `mkdirat`-driven flows
- widen the curated `linux-amd64-core` bundle with newly proven syscall shapes
- run longer bounded campaigns to look for stability regressions

Those should remain separate decisions so this iteration stays focused on cheap
execution-surface expansion.
