# Linux File/Path Smoke Expansion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add two cheap Linux file/path execution regression targets, prove them through bounded smoke runs, and fold them into the default `smoke-suite` matrix without changing the default core bundle.

**Architecture:** Keep the current bounded `smoke` entry path untouched. Add two new checked-in syzlang subset files under `descriptions/linux/`, cover them with focused `target-summary` tests in `src/main.rs`, then wire them into `DEFAULT_SMOKE_SUITE_DESCRIPTIONS` and the README once they pass individually.

**Tech Stack:** Rust 2021 CLI tests in `src/main.rs`, syzlang subset files in `descriptions/linux/`, existing `target-summary` and `smoke` CLIs, README matrix docs, real bounded Linux smoke verification with QEMU and upstream `syz-executor`.

---

## File Structure

- Create: `descriptions/linux/path-info-subset.txt`
  - Stable path metadata smoke target covering `getcwd`, `newfstatat`, and `readlinkat`.
- Create: `descriptions/linux/dirent-subset.txt`
  - Stable directory enumeration smoke target covering `openat`, `getdents64`, and `close`.
- Modify: `src/main.rs`
  - Add focused `target-summary` tests for the new subsets and extend the default `smoke-suite` target list and expectations.
- Modify: `README.md`
  - Add the two new targets to the documented default `smoke-suite` matrix.

### Task 1: Add the Path Metadata Smoke Target

**Files:**
- Create: `descriptions/linux/path-info-subset.txt`
- Modify: `src/main.rs`
- Test: `src/main.rs`

- [ ] **Step 1: Write the failing `target-summary` test for the new path metadata target**

Add this test near the other `build_target_summary` smoke target coverage in `src/main.rs`:

```rust
#[test]
fn target_summary_loads_path_info_subset() {
    let summary = build_target_summary(Some("descriptions/linux/path-info-subset.txt"), 2)
        .expect("path-info subset should load");

    assert_eq!(summary.source, "descriptions/linux/path-info-subset.txt");
    assert_eq!(summary.total_syscalls, 3);
    assert_eq!(summary.transitively_enabled_syscalls, 3);
    assert_eq!(summary.transitively_generatable_syscalls, 3);
}
```

- [ ] **Step 2: Run the focused test and confirm it fails because the file does not exist yet**

Run:

```bash
cargo test tests::target_summary_loads_path_info_subset -- --exact
```

Expected: FAIL with an error loading `descriptions/linux/path-info-subset.txt`.

- [ ] **Step 3: Create the new `path-info-subset.txt` description**

Create `descriptions/linux/path-info-subset.txt` with exactly this content:

```txt
const AT_FDCWD = -100

type stat_buf_out {
    bytes array[int8, 144]
} [size[144]]

getcwd(buf buffer[out], size bytesize[buf, intptr])
newfstatat(dirfd const[AT_FDCWD, int32], path ptr[in, glob["/proc/self/exe"]], stat ptr[out, stat_buf_out], flags const[0, int32])
readlinkat(dirfd const[AT_FDCWD, int32], path ptr[in, glob["/proc/self/cwd"]], buf buffer[out], bufsiz bytesize[buf, int32])
```

- [ ] **Step 4: Re-run the focused test and inspect the target summary directly**

Run:

```bash
cargo test tests::target_summary_loads_path_info_subset -- --exact
cargo run --quiet -- target-summary descriptions/linux/path-info-subset.txt 4
```

Expected:

- the Rust test passes
- `target-summary` reports `3 total`, `3 enabled`, and `3 generatable`

- [ ] **Step 5: Commit the path metadata target**

```bash
git add descriptions/linux/path-info-subset.txt src/main.rs
git commit -m "feat: add path metadata smoke subset"
```

### Task 2: Add the Directory Enumeration Smoke Target

**Files:**
- Create: `descriptions/linux/dirent-subset.txt`
- Modify: `src/main.rs`
- Test: `src/main.rs`

- [ ] **Step 1: Write the failing `target-summary` test for the directory enumeration target**

Add this test near the other execution regression subset coverage in `src/main.rs`:

```rust
#[test]
fn target_summary_loads_dirent_subset() {
    let summary = build_target_summary(Some("descriptions/linux/dirent-subset.txt"), 2)
        .expect("dirent subset should load");

    assert_eq!(summary.source, "descriptions/linux/dirent-subset.txt");
    assert_eq!(summary.total_syscalls, 3);
    assert_eq!(summary.transitively_enabled_syscalls, 3);
    assert_eq!(summary.transitively_generatable_syscalls, 3);
}
```

- [ ] **Step 2: Run the focused test and confirm it fails because the file does not exist yet**

Run:

```bash
cargo test tests::target_summary_loads_dirent_subset -- --exact
```

Expected: FAIL with an error loading `descriptions/linux/dirent-subset.txt`.

- [ ] **Step 3: Create the new `dirent-subset.txt` description**

Create `descriptions/linux/dirent-subset.txt` with exactly this content:

```txt
const AT_FDCWD = -100

resource fd[int32]: -1

openat(dirfd const[AT_FDCWD, int32], path ptr[in, glob["/proc"]], flags const[0, int32], mode const[0, int32]) fd
getdents64(fd fd, dirp buffer[out], count bytesize[dirp, int32])
close(fd fd)
```

- [ ] **Step 4: Re-run the focused test and inspect the target summary directly**

Run:

```bash
cargo test tests::target_summary_loads_dirent_subset -- --exact
cargo run --quiet -- target-summary descriptions/linux/dirent-subset.txt 4
```

Expected:

- the Rust test passes
- `target-summary` reports `3 total`, `3 enabled`, and `3 generatable`

- [ ] **Step 5: Commit the directory enumeration target**

```bash
git add descriptions/linux/dirent-subset.txt src/main.rs
git commit -m "feat: add dirent smoke subset"
```

### Task 3: Add Both Targets to the Default Smoke-Suite Matrix

**Files:**
- Modify: `src/main.rs`
- Modify: `README.md`
- Test: `src/main.rs`

- [ ] **Step 1: Update the default smoke-suite expectation test first**

In `src/main.rs`, update `smoke_suite_defaults_to_regression_targets` so the expected default list becomes:

```rust
assert_eq!(
    descriptions,
    vec![
        "descriptions/linux/file-subset.txt".to_string(),
        "descriptions/linux/path-info-subset.txt".to_string(),
        "descriptions/linux/dirent-subset.txt".to_string(),
        "descriptions/linux/pipe-io-subset.txt".to_string(),
        "descriptions/linux/msg-io-subset.txt".to_string(),
        "descriptions/linux/recvmsg-io-subset.txt".to_string(),
        "descriptions/linux/recvmmsg-io-subset.txt".to_string(),
        "descriptions/linux/dgram-io-subset.txt".to_string(),
        "descriptions/linux/socket-io-subset.txt".to_string(),
        "descriptions/linux/sockopt-buf-subset.txt".to_string(),
        "descriptions/linux/sock-ifreq-subset.txt".to_string(),
        "descriptions/linux/sock-ifconf-subset.txt".to_string(),
        "descriptions/linux/sock-ethtool-subset.txt".to_string(),
        "descriptions/linux/pipe-fionread-subset.txt".to_string(),
        "descriptions/linux/accept-connect-subset.txt".to_string(),
        "descriptions/linux/socket-subset.txt".to_string(),
        "descriptions/linux/image-subset.txt".to_string(),
        "descriptions/linux/mm-subset.txt".to_string(),
        "descriptions/linux/process-subset.txt".to_string(),
    ]
);
```

- [ ] **Step 2: Run the focused smoke-suite defaults test and confirm it fails before the constant is updated**

Run:

```bash
cargo test tests::smoke_suite_defaults_to_regression_targets -- --exact
```

Expected: FAIL because `DEFAULT_SMOKE_SUITE_DESCRIPTIONS` still lacks the two new targets.

- [ ] **Step 3: Update the smoke-suite defaults constant and README target list**

In `src/main.rs`, update `DEFAULT_SMOKE_SUITE_DESCRIPTIONS` so it includes the two new targets immediately after `file-subset.txt`:

```rust
const DEFAULT_SMOKE_SUITE_DESCRIPTIONS: &[&str] = &[
    "descriptions/linux/file-subset.txt",
    "descriptions/linux/path-info-subset.txt",
    "descriptions/linux/dirent-subset.txt",
    "descriptions/linux/pipe-io-subset.txt",
    "descriptions/linux/msg-io-subset.txt",
    "descriptions/linux/recvmsg-io-subset.txt",
    "descriptions/linux/recvmmsg-io-subset.txt",
    "descriptions/linux/dgram-io-subset.txt",
    "descriptions/linux/socket-io-subset.txt",
    "descriptions/linux/sockopt-buf-subset.txt",
    "descriptions/linux/sock-ifreq-subset.txt",
    "descriptions/linux/sock-ifconf-subset.txt",
    "descriptions/linux/sock-ethtool-subset.txt",
    "descriptions/linux/pipe-fionread-subset.txt",
    "descriptions/linux/accept-connect-subset.txt",
    "descriptions/linux/socket-subset.txt",
    "descriptions/linux/image-subset.txt",
    "descriptions/linux/mm-subset.txt",
    "descriptions/linux/process-subset.txt",
];
```

In `README.md`, update the documented default `smoke-suite` list so it also includes:

```md
- `descriptions/linux/path-info-subset.txt`
- `descriptions/linux/dirent-subset.txt`
```

Place them directly after `descriptions/linux/file-subset.txt` to match the code.

- [ ] **Step 4: Re-run the focused smoke-suite test**

Run:

```bash
cargo test tests::smoke_suite_defaults_to_regression_targets -- --exact
```

Expected: PASS

- [ ] **Step 5: Commit the smoke-suite integration**

```bash
git add src/main.rs README.md
git commit -m "feat: add file path targets to smoke suite"
```

### Task 4: Verify the New Targets End-to-End

**Files:**
- Verify: `descriptions/linux/path-info-subset.txt`
- Verify: `descriptions/linux/dirent-subset.txt`
- Verify: `README.md`

- [ ] **Step 1: Run the full Rust test suite**

Run:

```bash
cargo test
```

Expected: PASS

- [ ] **Step 2: Re-run `target-summary` for both new subsets**

Run:

```bash
cargo run --quiet -- target-summary descriptions/linux/path-info-subset.txt 4
cargo run --quiet -- target-summary descriptions/linux/dirent-subset.txt 4
```

Expected:

- `path-info-subset.txt` reports `3 total / 3 enabled / 3 generatable`
- `dirent-subset.txt` reports `3 total / 3 enabled / 3 generatable`

- [ ] **Step 3: Run bounded Linux smoke for each new subset individually**

Run:

```bash
RUST_LOG=info cargo run --quiet -- smoke config.json 4 descriptions/linux/path-info-subset.txt
RUST_LOG=info cargo run --quiet -- smoke config.json 4 descriptions/linux/dirent-subset.txt
```

Expected:

- each run boots the VM, completes cleanly, and prints a JSON summary
- both runs finish with `artifacts_total = 0`

- [ ] **Step 4: Run a targeted smoke-suite pass with just the two new targets**

Run:

```bash
RUST_LOG=info cargo run --quiet -- smoke-suite config.json 4 descriptions/linux/path-info-subset.txt descriptions/linux/dirent-subset.txt
```

Expected:

- both targets run in isolated `workdir/smoke-suite/<slug>` directories
- the suite exits cleanly with two run summaries

- [ ] **Step 5: Commit the verified final state**

```bash
git add descriptions/linux/path-info-subset.txt descriptions/linux/dirent-subset.txt src/main.rs README.md
git commit -m "feat: expand file path smoke coverage"
```
