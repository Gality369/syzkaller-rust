# Linux Smoke Entry Stabilization Design

## Context

The repository now has a practical Linux fuzzing MVP:

- a checked-in `linux-amd64-core` target bundle with 41 fully generatable
  syscalls
- bundle-backed bounded `smoke` runs through upstream `syz-executor`
- passing Rust and Go tests
- a successful real bounded Linux run on the current machine

This means the project can already start testing Linux. The next highest-value
work is not broader syscall import. It is making the default bounded Linux
entry path feel reliable, truthful, and easy to reuse.

## Problem Statement

The current bounded `smoke` path still has three usability/stability issues:

1. startup logging can claim the run is using `builtin:linux/amd64-minimal`
   even when the manager actually loads `bundle:data/target-bundles/linux-amd64-core.json`
2. bounded `smoke` reuses the main configured `workdir`, so repeated smoke runs
   accumulate or inherit corpus state instead of starting from a clean bounded
   verification workspace
3. the repository currently only exposes a machine-specific checked-in
   `config.json`, which couples the default Linux entry path to one local
   filesystem layout

None of these issues prevent fuzzing outright, but together they make the
default Linux entry feel less trustworthy than it already is.

## Goals

- Make bounded `smoke` report the actual resolved target source everywhere.
- Give bounded `smoke` an isolated, resettable workdir by default.
- Reduce machine-specific configuration coupling without redesigning the config
  system.
- Preserve the current core bundle, target loader, manager, and executor path.
- Keep this subproject small and focused.

## Non-Goals

- Expanding syscall coverage in this subproject.
- Redesigning target bundles or the exporter.
- Adding distributed fuzzing or multi-VM scheduling changes.
- Reworking corpus, crash, timeout, or repro formats.
- Introducing a large configuration framework.

## Approaches Considered

### Approach 1: Minimal truthfulness fixes only

Fix the startup label bug and add clearer docs, but keep the current workdir and
config setup.

Pros:

- smallest code delta
- least behavior change

Cons:

- smoke runs still inherit prior corpus state
- repository remains strongly coupled to one machine-specific config file

### Approach 2: Entry stabilization with isolated smoke workspace

Fix target labeling, give bounded `smoke` a dedicated clean workdir under the
base workdir, and introduce a tracked config template plus ignored local config
pattern.

Pros:

- directly addresses the three current usability issues
- keeps bounded smoke reproducible and easier to reason about
- reduces accidental pollution of the main fuzzing workdir
- stays small enough for one short iteration

Cons:

- changes default bounded smoke workdir behavior
- requires light documentation and config hygiene changes

### Approach 3: Full profile system

Add explicit config profiles or layered config merging for smoke versus long-run
fuzzing.

Pros:

- most flexible long-term operator model

Cons:

- too much engineering for the current need
- distracts from the "minimum effort to work" goal

## Selected Approach

Choose Approach 2.

This is the smallest subproject that materially improves confidence in the
default Linux entry path. It makes `smoke` truthful and clean without turning
the repo into a configuration project.

## Design

### 1. Accurate Resolved Target Reporting

Bounded `smoke` should report the same resolved target source label that the
manager and final summary use.

Concretely:

- the startup `println!` and `log::info!` lines should stop reading directly
  from `cfg.syscall_descriptions`
- instead, `smoke` should resolve the target source once, derive a source label
  from that resolution, and reuse it consistently in:
  - startup output
  - bounded smoke summaries

This removes the current misleading `builtin` startup text when the run is
actually using the core bundle.

### 2. Isolated Bounded Smoke Workdir

Bounded `smoke` should behave like a clean verification run by default, not as
an incremental continuation of the main fuzzing workspace.

Concretely:

- introduce a default bounded smoke workdir under
  `<base_workdir>/smoke/<target-slug>`
- reset that workdir before each bounded smoke run
- keep `smoke-suite` behavior conceptually aligned, since it already uses
  isolated target-specific workdirs under `smoke-suite/`

This means:

- the configured base workdir remains the root namespace
- the main fuzzing corpus is no longer silently reused by bounded `smoke`
- repeated smoke runs become easier to compare and reason about

The slug should be derived from the resolved target label, so bundle-backed and
description-backed smoke runs get stable, readable directories.

### 3. Portable Config Template Pattern

The repository should stop presenting one machine-bound config file as the only
normal way to run Linux fuzzing.

Concretely:

- add a tracked `config.example.json` with example paths
- extend `.gitignore` to ignore local runtime files such as:
  - `config.local.json`
  - `workdir/`
- keep the existing config schema and CLI unchanged
- update docs to describe:
  - `config.example.json` as the tracked template
  - `config.local.json` as the normal machine-specific working file

This keeps the solution lightweight:

- no config inheritance system
- no profile parser
- no environment-variable layer required

### 4. Documentation Positioning

The docs should make a sharper distinction between:

- bounded verification with `smoke`
- longer-running fuzzing with a persistent workdir

Bounded `smoke` should be documented as:

- isolated
- resettable
- suitable for quick Linux verification and regression checks

The normal persistent config workdir should remain available for longer fuzzing
sessions outside the bounded smoke wrapper.

## Acceptance Criteria

This subproject is complete when all of the following are true:

1. startup smoke output names the same resolved target source that the manager
   actually loads
2. bounded `smoke` uses an isolated target-specific workdir under
   `<base_workdir>/smoke/`
3. repeated bounded smoke runs no longer inherit previous bounded smoke corpus
   state unless the user explicitly chooses a different path
4. the repository includes a tracked `config.example.json`
5. `.gitignore` ignores local machine-specific config and runtime workdir state
6. README explains the new template/local-config pattern and the difference
   between bounded smoke and persistent fuzzing
7. Rust tests continue to pass
8. at least one real bounded Linux smoke run still passes on the current
   machine using the core bundle

## Immediate Implementation Scope

The implementation plan for this subproject should stay intentionally small:

1. add a smoke run metadata helper that resolves source labels and target slugs
2. switch bounded smoke to an isolated default workdir
3. add config template and gitignore hygiene
4. update tests and README
5. re-run a real bounded Linux smoke verification

## Deferred Follow-On Work

If this subproject lands cleanly, the next decision can stay pragmatic:

- either expand the core bundle further
- or keep improving operator ergonomics for longer Linux fuzzing runs

That choice should be based on what most directly helps real Linux testing next,
not on architectural purity.
