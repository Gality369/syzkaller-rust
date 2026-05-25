use crate::program::{stable_program_key, Program, SyscallDesc};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::io;
use std::path::Path;

const CORPUS_SNAPSHOT_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CorpusLoadReport {
    pub loaded_programs: usize,
    pub skipped_programs: usize,
    pub signal_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CorpusSnapshot {
    version: u32,
    programs: Vec<Program>,
    max_signal: Vec<u64>,
}

/// Minimal corpus: a set of programs that have produced new coverage.
pub struct Corpus {
    pub programs: Vec<Program>,
    /// Maximum signal set: all unique coverage signals seen.
    pub max_signal: HashSet<u64>,
    /// New signal accumulated since last sync to runners.
    pub new_signal: Vec<u64>,
    /// Dedup key for already-stored programs.
    program_keys: HashSet<String>,
}

impl Corpus {
    pub fn new() -> Self {
        Corpus {
            programs: Vec::new(),
            max_signal: HashSet::new(),
            new_signal: Vec::new(),
            program_keys: HashSet::new(),
        }
    }

    pub fn load(path: &Path, descs: &[SyscallDesc]) -> Result<(Self, CorpusLoadReport), io::Error> {
        if !path.exists() {
            return Ok((Self::new(), CorpusLoadReport::default()));
        }

        let data = fs::read_to_string(path)?;
        let snapshot: CorpusSnapshot = serde_json::from_str(&data).map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "failed to parse corpus snapshot {}: {}",
                    path.display(),
                    err
                ),
            )
        })?;
        if snapshot.version != CORPUS_SNAPSHOT_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "unsupported corpus snapshot version {} in {}",
                    snapshot.version,
                    path.display()
                ),
            ));
        }

        let mut corpus = Self::new();
        let mut report = CorpusLoadReport::default();
        for signal in snapshot.max_signal {
            if signal != 0 {
                corpus.max_signal.insert(signal);
            }
        }
        report.signal_count = corpus.max_signal.len();

        for prog in snapshot.programs {
            if prog.validate(descs).is_ok() {
                if corpus.insert_program(prog) {
                    report.loaded_programs += 1;
                } else {
                    report.skipped_programs += 1;
                }
            } else {
                report.skipped_programs += 1;
            }
        }

        Ok((corpus, report))
    }

    pub fn save(&self, path: &Path) -> Result<(), io::Error> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let snapshot = CorpusSnapshot {
            version: CORPUS_SNAPSHOT_VERSION,
            programs: self.programs.clone(),
            max_signal: self.signal_vec(),
        };
        let data = serde_json::to_vec_pretty(&snapshot).map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "failed to serialize corpus snapshot {}: {}",
                    path.display(),
                    err
                ),
            )
        })?;

        let tmp_path = path.with_extension("json.tmp");
        fs::write(&tmp_path, &data)?;
        fs::rename(&tmp_path, path)?;
        Ok(())
    }

    /// Add execution signals and return whether any new signal was found.
    /// If new signal was found, also add the program to the corpus.
    pub fn add_result(&mut self, prog: &Program, signals: &[u64]) -> bool {
        let mut has_new = false;
        for &sig in signals {
            if sig != 0 && self.max_signal.insert(sig) {
                has_new = true;
                self.new_signal.push(sig);
            }
        }
        if has_new {
            self.insert_program(prog.clone());
        }
        has_new
    }

    /// Take new signal for syncing to runners, clearing the buffer.
    pub fn take_new_signal(&mut self) -> Vec<u64> {
        std::mem::take(&mut self.new_signal)
    }

    /// Get a random program from the corpus for mutation.
    pub fn random_program(&self, rng: &mut impl rand::Rng) -> Option<&Program> {
        if self.programs.is_empty() {
            None
        } else {
            Some(&self.programs[rng.gen_range(0..self.programs.len())])
        }
    }

    pub fn programs(&self) -> &[Program] {
        &self.programs
    }

    pub fn signal_vec(&self) -> Vec<u64> {
        let mut signals = self.max_signal.iter().copied().collect::<Vec<_>>();
        signals.sort_unstable();
        signals
    }

    pub fn len(&self) -> usize {
        self.programs.len()
    }

    pub fn signal_count(&self) -> usize {
        self.max_signal.len()
    }

    fn insert_program(&mut self, prog: Program) -> bool {
        let key = stable_program_key(&prog);
        if !self.program_keys.insert(key) {
            return false;
        }
        self.programs.push(prog);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::description::parse_syscall_descs;
    use crate::program::{ArgValue, Call};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_temp_path(name: &str) -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "syzkaller-rust-{}-{}-{}.json",
            name,
            std::process::id(),
            nanos
        ))
    }

    #[test]
    fn corpus_snapshot_roundtrip_preserves_programs_and_signals() {
        let descs = parse_syscall_descs(
            r#"
                syscall getpid@1 -> int()
            "#,
        )
        .expect("test target should parse");
        let prog = Program {
            calls: vec![Call {
                syscall_idx: 0,
                args: vec![],
            }],
        };
        let path = unique_temp_path("corpus-roundtrip");
        let mut corpus = Corpus::new();
        corpus.add_result(&prog, &[7, 0, 9, 7]);
        corpus
            .save(&path)
            .expect("corpus snapshot should save successfully");

        let (loaded, report) = Corpus::load(&path, &descs).expect("corpus snapshot should load");
        let _ = fs::remove_file(&path);

        assert_eq!(report.loaded_programs, 1);
        assert_eq!(report.skipped_programs, 0);
        assert_eq!(report.signal_count, 2);
        assert_eq!(loaded.programs(), &[prog]);
        assert_eq!(loaded.signal_vec(), vec![7, 9]);
        assert!(loaded.new_signal.is_empty());
    }

    #[test]
    fn corpus_load_skips_programs_invalid_for_current_target() {
        let descs = parse_syscall_descs(
            r#"
                syscall getpid@1 -> int()
            "#,
        )
        .expect("test target should parse");
        let valid = Program {
            calls: vec![Call {
                syscall_idx: 0,
                args: vec![],
            }],
        };
        let invalid = Program {
            calls: vec![Call {
                syscall_idx: 1,
                args: vec![ArgValue::Const(1)],
            }],
        };
        let path = unique_temp_path("corpus-invalid");
        let snapshot = CorpusSnapshot {
            version: CORPUS_SNAPSHOT_VERSION,
            programs: vec![valid.clone(), invalid],
            max_signal: vec![11, 0, 13],
        };
        fs::write(
            &path,
            serde_json::to_vec_pretty(&snapshot).expect("snapshot should serialize"),
        )
        .expect("snapshot file should write");

        let (loaded, report) = Corpus::load(&path, &descs).expect("corpus snapshot should load");
        let _ = fs::remove_file(&path);

        assert_eq!(report.loaded_programs, 1);
        assert_eq!(report.skipped_programs, 1);
        assert_eq!(report.signal_count, 2);
        assert_eq!(loaded.programs(), &[valid]);
        assert_eq!(loaded.signal_vec(), vec![11, 13]);
    }

    #[test]
    fn corpus_deduplicates_identical_programs_while_tracking_new_signal() {
        let prog = Program {
            calls: vec![Call {
                syscall_idx: 0,
                args: vec![],
            }],
        };
        let mut corpus = Corpus::new();

        assert!(corpus.add_result(&prog, &[5]));
        assert_eq!(corpus.len(), 1);
        assert_eq!(corpus.signal_vec(), vec![5]);

        assert!(corpus.add_result(&prog, &[5, 7]));
        assert_eq!(corpus.len(), 1);
        assert_eq!(corpus.signal_vec(), vec![5, 7]);
    }

    #[test]
    fn corpus_load_skips_duplicate_programs_from_snapshot() {
        let descs = parse_syscall_descs(
            r#"
                syscall getpid@1 -> int()
            "#,
        )
        .expect("test target should parse");
        let prog = Program {
            calls: vec![Call {
                syscall_idx: 0,
                args: vec![],
            }],
        };
        let path = unique_temp_path("corpus-duplicates");
        let snapshot = CorpusSnapshot {
            version: CORPUS_SNAPSHOT_VERSION,
            programs: vec![prog.clone(), prog.clone()],
            max_signal: vec![3, 5],
        };
        fs::write(
            &path,
            serde_json::to_vec_pretty(&snapshot).expect("snapshot should serialize"),
        )
        .expect("snapshot file should write");

        let (loaded, report) = Corpus::load(&path, &descs).expect("corpus snapshot should load");
        let _ = fs::remove_file(&path);

        assert_eq!(report.loaded_programs, 1);
        assert_eq!(report.skipped_programs, 1);
        assert_eq!(loaded.programs(), &[prog]);
        assert_eq!(loaded.signal_vec(), vec![3, 5]);
    }
}
