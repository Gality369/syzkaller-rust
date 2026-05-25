use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io;
use std::path::Path;

const AVOIDANCE_SNAPSHOT_VERSION: u32 = 2;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AvoidanceLoadReport {
    pub edge_failures: usize,
    pub blocked_edges: usize,
    pub syscall_failures: usize,
    pub blocked_syscalls: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AvoidanceState {
    pub learning_epoch: u64,
    pub timeout_edge_failures: HashMap<String, u32>,
    pub timeout_syscall_failures: HashMap<String, u32>,
    pub timeout_edge_last_failure_epoch: HashMap<String, u64>,
    pub timeout_syscall_last_failure_epoch: HashMap<String, u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct AvoidanceSnapshot {
    version: u32,
    #[serde(default)]
    learning_epoch: u64,
    timeout_edge_failures: HashMap<String, u32>,
    timeout_syscall_failures: HashMap<String, u32>,
    #[serde(default)]
    timeout_edge_last_failure_epoch: HashMap<String, u64>,
    #[serde(default)]
    timeout_syscall_last_failure_epoch: HashMap<String, u64>,
}

impl AvoidanceState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn load(
        path: &Path,
        edge_block_threshold: u32,
        syscall_block_threshold: u32,
    ) -> Result<(Self, AvoidanceLoadReport), io::Error> {
        if !path.exists() {
            return Ok((Self::new(), AvoidanceLoadReport::default()));
        }

        let data = fs::read_to_string(path)?;
        let snapshot: AvoidanceSnapshot = serde_json::from_str(&data).map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "failed to parse avoidance snapshot {}: {}",
                    path.display(),
                    err
                ),
            )
        })?;
        if !matches!(snapshot.version, 1 | AVOIDANCE_SNAPSHOT_VERSION) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "unsupported avoidance snapshot version {} in {}",
                    snapshot.version,
                    path.display()
                ),
            ));
        }

        let mut state = Self::new();
        state.learning_epoch = snapshot.learning_epoch;
        state.timeout_edge_failures = snapshot
            .timeout_edge_failures
            .into_iter()
            .filter(|(edge, count)| !edge.trim().is_empty() && *count > 0)
            .collect();
        state.timeout_syscall_failures = snapshot
            .timeout_syscall_failures
            .into_iter()
            .filter(|(syscall, count)| !syscall.trim().is_empty() && *count > 0)
            .collect();
        state.timeout_edge_last_failure_epoch = state
            .timeout_edge_failures
            .keys()
            .map(|edge| {
                let epoch = snapshot
                    .timeout_edge_last_failure_epoch
                    .get(edge)
                    .copied()
                    .unwrap_or(state.learning_epoch);
                (edge.clone(), epoch)
            })
            .collect();
        state.timeout_syscall_last_failure_epoch = state
            .timeout_syscall_failures
            .keys()
            .map(|syscall| {
                let epoch = snapshot
                    .timeout_syscall_last_failure_epoch
                    .get(syscall)
                    .copied()
                    .unwrap_or(state.learning_epoch);
                (syscall.clone(), epoch)
            })
            .collect();

        let report = AvoidanceLoadReport {
            edge_failures: state.timeout_edge_failures.len(),
            blocked_edges: state.blocked_edges(edge_block_threshold).len(),
            syscall_failures: state.timeout_syscall_failures.len(),
            blocked_syscalls: state.blocked_syscalls(syscall_block_threshold).len(),
        };

        Ok((state, report))
    }

    pub fn save(&self, path: &Path) -> Result<(), io::Error> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let snapshot = AvoidanceSnapshot {
            version: AVOIDANCE_SNAPSHOT_VERSION,
            learning_epoch: self.learning_epoch,
            timeout_edge_failures: self.timeout_edge_failures.clone(),
            timeout_syscall_failures: self.timeout_syscall_failures.clone(),
            timeout_edge_last_failure_epoch: self.timeout_edge_last_failure_epoch.clone(),
            timeout_syscall_last_failure_epoch: self.timeout_syscall_last_failure_epoch.clone(),
        };
        let data = serde_json::to_vec_pretty(&snapshot).map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "failed to serialize avoidance snapshot {}: {}",
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

    pub fn blocked_edges(&self, threshold: u32) -> HashSet<String> {
        self.timeout_edge_failures
            .iter()
            .filter(|(_, count)| **count >= threshold)
            .map(|(edge, _)| edge.clone())
            .collect()
    }

    pub fn blocked_syscalls(&self, threshold: u32) -> HashSet<String> {
        self.timeout_syscall_failures
            .iter()
            .filter(|(_, count)| **count >= threshold)
            .map(|(syscall, _)| syscall.clone())
            .collect()
    }

    pub fn note_edge_failure(&mut self, edge: &str, epoch: u64) -> u32 {
        self.learning_epoch = self.learning_epoch.max(epoch);
        self.timeout_edge_last_failure_epoch
            .insert(edge.to_string(), epoch);
        let failures = self
            .timeout_edge_failures
            .entry(edge.to_string())
            .or_insert(0);
        *failures += 1;
        *failures
    }

    pub fn note_syscall_failure(&mut self, syscall: &str, epoch: u64) -> u32 {
        self.learning_epoch = self.learning_epoch.max(epoch);
        self.timeout_syscall_last_failure_epoch
            .insert(syscall.to_string(), epoch);
        let failures = self
            .timeout_syscall_failures
            .entry(syscall.to_string())
            .or_insert(0);
        *failures += 1;
        *failures
    }

    pub fn decay(&mut self, amount: u32) -> bool {
        if amount == 0 {
            return false;
        }
        let edge_changed = decay_failure_counts(
            &mut self.timeout_edge_failures,
            &mut self.timeout_edge_last_failure_epoch,
            amount,
        );
        let syscall_changed = decay_failure_counts(
            &mut self.timeout_syscall_failures,
            &mut self.timeout_syscall_last_failure_epoch,
            amount,
        );
        edge_changed || syscall_changed
    }

    pub fn decay_stale(&mut self, amount: u32, min_idle_epochs: u64) -> bool {
        if amount == 0 {
            return false;
        }
        let cutoff_epoch = self.learning_epoch.saturating_sub(min_idle_epochs);
        let edge_changed = decay_stale_failure_counts(
            &mut self.timeout_edge_failures,
            &mut self.timeout_edge_last_failure_epoch,
            amount,
            cutoff_epoch,
        );
        let syscall_changed = decay_stale_failure_counts(
            &mut self.timeout_syscall_failures,
            &mut self.timeout_syscall_last_failure_epoch,
            amount,
            cutoff_epoch,
        );
        edge_changed || syscall_changed
    }

    pub fn decay_stale_weighted(&mut self, min_idle_epochs: u64, max_decay_amount: u32) -> bool {
        if max_decay_amount == 0 || min_idle_epochs == 0 {
            return false;
        }
        let edge_changed = decay_stale_failure_counts_weighted(
            &mut self.timeout_edge_failures,
            &mut self.timeout_edge_last_failure_epoch,
            self.learning_epoch,
            min_idle_epochs,
            max_decay_amount,
        );
        let syscall_changed = decay_stale_failure_counts_weighted(
            &mut self.timeout_syscall_failures,
            &mut self.timeout_syscall_last_failure_epoch,
            self.learning_epoch,
            min_idle_epochs,
            max_decay_amount,
        );
        edge_changed || syscall_changed
    }

    pub fn compact(
        &mut self,
        edge_block_threshold: u32,
        syscall_block_threshold: u32,
        min_idle_epochs: u64,
    ) -> bool {
        let edge_changed = compact_failure_counts(
            &mut self.timeout_edge_failures,
            &mut self.timeout_edge_last_failure_epoch,
            self.learning_epoch,
            edge_block_threshold,
            min_idle_epochs,
        );
        let syscall_changed = compact_failure_counts(
            &mut self.timeout_syscall_failures,
            &mut self.timeout_syscall_last_failure_epoch,
            self.learning_epoch,
            syscall_block_threshold,
            min_idle_epochs,
        );
        edge_changed || syscall_changed
    }

    pub fn prune_weak_entries(
        &mut self,
        edge_block_threshold: u32,
        syscall_block_threshold: u32,
        max_weak_edges: usize,
        max_weak_syscalls: usize,
    ) -> bool {
        let edge_changed = prune_weak_failure_counts(
            &mut self.timeout_edge_failures,
            &mut self.timeout_edge_last_failure_epoch,
            self.learning_epoch,
            edge_block_threshold,
            max_weak_edges,
        );
        let syscall_changed = prune_weak_failure_counts(
            &mut self.timeout_syscall_failures,
            &mut self.timeout_syscall_last_failure_epoch,
            self.learning_epoch,
            syscall_block_threshold,
            max_weak_syscalls,
        );
        edge_changed || syscall_changed
    }
}

fn decay_failure_counts(
    entries: &mut HashMap<String, u32>,
    last_failure_epochs: &mut HashMap<String, u64>,
    amount: u32,
) -> bool {
    let mut changed = false;
    entries.retain(|key, count| {
        if *count <= amount {
            changed = true;
            last_failure_epochs.remove(key);
            return false;
        }
        *count -= amount;
        changed = true;
        true
    });
    changed
}

fn decay_stale_failure_counts(
    entries: &mut HashMap<String, u32>,
    last_failure_epochs: &mut HashMap<String, u64>,
    amount: u32,
    cutoff_epoch: u64,
) -> bool {
    let mut changed = false;
    let stale_keys = entries
        .keys()
        .filter(|key| last_failure_epochs.get(*key).copied().unwrap_or(0) <= cutoff_epoch)
        .cloned()
        .collect::<Vec<_>>();
    for key in stale_keys {
        let Some(count) = entries.get_mut(&key) else {
            continue;
        };
        changed = true;
        if *count <= amount {
            entries.remove(&key);
            last_failure_epochs.remove(&key);
        } else {
            *count -= amount;
        }
    }
    changed
}

fn decay_stale_failure_counts_weighted(
    entries: &mut HashMap<String, u32>,
    last_failure_epochs: &mut HashMap<String, u64>,
    learning_epoch: u64,
    min_idle_epochs: u64,
    max_decay_amount: u32,
) -> bool {
    let mut changed = false;
    let keys = entries.keys().cloned().collect::<Vec<_>>();
    for key in keys {
        let last_epoch = last_failure_epochs
            .get(&key)
            .copied()
            .unwrap_or(learning_epoch);
        let idle_epochs = learning_epoch.saturating_sub(last_epoch);
        let decay_amount = graded_decay_amount(idle_epochs, min_idle_epochs, max_decay_amount);
        if decay_amount == 0 {
            continue;
        }
        let Some(count) = entries.get_mut(&key) else {
            continue;
        };
        changed = true;
        if *count <= decay_amount {
            entries.remove(&key);
            last_failure_epochs.remove(&key);
        } else {
            *count -= decay_amount;
        }
    }
    changed
}

fn graded_decay_amount(idle_epochs: u64, min_idle_epochs: u64, max_decay_amount: u32) -> u32 {
    if min_idle_epochs == 0 || max_decay_amount == 0 || idle_epochs < min_idle_epochs {
        return 0;
    }
    let tiers = 1u64 + ((idle_epochs - min_idle_epochs) / min_idle_epochs);
    tiers.min(max_decay_amount as u64) as u32
}

fn compact_failure_counts(
    entries: &mut HashMap<String, u32>,
    last_failure_epochs: &mut HashMap<String, u64>,
    learning_epoch: u64,
    block_threshold: u32,
    min_idle_epochs: u64,
) -> bool {
    let mut changed = false;
    entries.retain(|key, count| {
        let last_epoch = last_failure_epochs
            .get(key)
            .copied()
            .unwrap_or(learning_epoch);
        let idle_epochs = learning_epoch.saturating_sub(last_epoch);
        let should_drop = *count < block_threshold && idle_epochs >= min_idle_epochs;
        if should_drop {
            changed = true;
            last_failure_epochs.remove(key);
            false
        } else {
            true
        }
    });
    changed
}

fn prune_weak_failure_counts(
    entries: &mut HashMap<String, u32>,
    last_failure_epochs: &mut HashMap<String, u64>,
    learning_epoch: u64,
    block_threshold: u32,
    max_weak_entries: usize,
) -> bool {
    let mut weak_entries = entries
        .iter()
        .filter(|(_, count)| **count < block_threshold)
        .map(|(key, count)| {
            (
                key.clone(),
                *count,
                last_failure_epochs
                    .get(key)
                    .copied()
                    .unwrap_or(learning_epoch),
            )
        })
        .collect::<Vec<_>>();
    if weak_entries.len() <= max_weak_entries {
        return false;
    }

    weak_entries.sort_by(|a, b| {
        b.1.cmp(&a.1)
            .then_with(|| b.2.cmp(&a.2))
            .then_with(|| a.0.cmp(&b.0))
    });
    let keep = weak_entries
        .into_iter()
        .take(max_weak_entries)
        .map(|(key, _, _)| key)
        .collect::<HashSet<_>>();

    let mut changed = false;
    entries.retain(|key, count| {
        let should_keep = *count >= block_threshold || keep.contains(key);
        if !should_keep {
            changed = true;
            last_failure_epochs.remove(key);
        }
        should_keep
    });
    changed
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_temp_path(name: &str) -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "syzkaller-rust-avoidance-{}-{}-{}.json",
            name,
            std::process::id(),
            nanos
        ))
    }

    #[test]
    fn avoidance_snapshot_roundtrip_preserves_failure_counts() {
        let path = unique_temp_path("roundtrip");
        let state = AvoidanceState {
            learning_epoch: 7,
            timeout_edge_failures: HashMap::from([
                ("sendto$inet->connect$inet".to_string(), 2),
                ("accept$inet->bind$inet".to_string(), 1),
            ]),
            timeout_syscall_failures: HashMap::from([("sendto$inet".to_string(), 3)]),
            timeout_edge_last_failure_epoch: HashMap::from([
                ("sendto$inet->connect$inet".to_string(), 7),
                ("accept$inet->bind$inet".to_string(), 5),
            ]),
            timeout_syscall_last_failure_epoch: HashMap::from([("sendto$inet".to_string(), 6)]),
        };

        state
            .save(&path)
            .expect("avoidance snapshot should save successfully");

        let (loaded, report) =
            AvoidanceState::load(&path, 2, 3).expect("avoidance snapshot should load");
        let _ = fs::remove_file(&path);

        assert_eq!(loaded, state);
        assert_eq!(report.edge_failures, 2);
        assert_eq!(report.blocked_edges, 1);
        assert_eq!(report.syscall_failures, 1);
        assert_eq!(report.blocked_syscalls, 1);
    }

    #[test]
    fn avoidance_load_skips_empty_or_zero_entries() {
        let path = unique_temp_path("sanitize");
        let snapshot = AvoidanceSnapshot {
            version: 1,
            learning_epoch: 0,
            timeout_edge_failures: HashMap::from([
                ("".to_string(), 2),
                ("accept$inet->bind$inet".to_string(), 0),
                ("sendto$inet->connect$inet".to_string(), 1),
            ]),
            timeout_syscall_failures: HashMap::from([
                ("".to_string(), 4),
                ("sendto$inet".to_string(), 0),
                ("connect$inet".to_string(), 2),
            ]),
            timeout_edge_last_failure_epoch: HashMap::new(),
            timeout_syscall_last_failure_epoch: HashMap::new(),
        };
        fs::write(
            &path,
            serde_json::to_vec_pretty(&snapshot).expect("snapshot should serialize"),
        )
        .expect("snapshot file should write");

        let (loaded, report) =
            AvoidanceState::load(&path, 2, 3).expect("avoidance snapshot should load");
        let _ = fs::remove_file(&path);

        assert_eq!(
            loaded.timeout_edge_failures,
            HashMap::from([("sendto$inet->connect$inet".to_string(), 1)])
        );
        assert_eq!(
            loaded.timeout_syscall_failures,
            HashMap::from([("connect$inet".to_string(), 2)])
        );
        assert_eq!(loaded.timeout_edge_last_failure_epoch.len(), 1);
        assert_eq!(loaded.timeout_syscall_last_failure_epoch.len(), 1);
        assert_eq!(report.edge_failures, 1);
        assert_eq!(report.blocked_edges, 0);
        assert_eq!(report.syscall_failures, 1);
        assert_eq!(report.blocked_syscalls, 0);
    }

    #[test]
    fn avoidance_decay_reduces_counts_and_drops_zero_entries() {
        let mut state = AvoidanceState {
            learning_epoch: 9,
            timeout_edge_failures: HashMap::from([
                ("accept$inet->bind$inet".to_string(), 2),
                ("sendto$inet->connect$inet".to_string(), 1),
            ]),
            timeout_syscall_failures: HashMap::from([
                ("sendto$inet".to_string(), 3),
                ("accept$inet".to_string(), 1),
            ]),
            timeout_edge_last_failure_epoch: HashMap::from([
                ("accept$inet->bind$inet".to_string(), 4),
                ("sendto$inet->connect$inet".to_string(), 9),
            ]),
            timeout_syscall_last_failure_epoch: HashMap::from([
                ("sendto$inet".to_string(), 7),
                ("accept$inet".to_string(), 9),
            ]),
        };

        assert!(state.decay(1));
        assert_eq!(
            state.timeout_edge_failures,
            HashMap::from([("accept$inet->bind$inet".to_string(), 1)])
        );
        assert_eq!(
            state.timeout_syscall_failures,
            HashMap::from([("sendto$inet".to_string(), 2)])
        );

        assert!(state.decay(2));
        assert!(state.timeout_edge_failures.is_empty());
        assert!(state.timeout_syscall_failures.is_empty());
        assert!(state.timeout_edge_last_failure_epoch.is_empty());
        assert!(state.timeout_syscall_last_failure_epoch.is_empty());
    }

    #[test]
    fn avoidance_decay_stale_respects_last_failure_epoch() {
        let mut state = AvoidanceState {
            learning_epoch: 20,
            timeout_edge_failures: HashMap::from([
                ("old-edge".to_string(), 2),
                ("fresh-edge".to_string(), 2),
            ]),
            timeout_syscall_failures: HashMap::from([
                ("old-syscall".to_string(), 3),
                ("fresh-syscall".to_string(), 3),
            ]),
            timeout_edge_last_failure_epoch: HashMap::from([
                ("old-edge".to_string(), 1),
                ("fresh-edge".to_string(), 19),
            ]),
            timeout_syscall_last_failure_epoch: HashMap::from([
                ("old-syscall".to_string(), 2),
                ("fresh-syscall".to_string(), 18),
            ]),
        };

        assert!(state.decay_stale(1, 4));
        assert_eq!(
            state.timeout_edge_failures,
            HashMap::from([("old-edge".to_string(), 1), ("fresh-edge".to_string(), 2),])
        );
        assert_eq!(
            state.timeout_syscall_failures,
            HashMap::from([
                ("old-syscall".to_string(), 2),
                ("fresh-syscall".to_string(), 3),
            ])
        );
    }

    #[test]
    fn avoidance_decay_stale_weighted_cools_long_idle_entries_faster() {
        let mut state = AvoidanceState {
            learning_epoch: 40,
            timeout_edge_failures: HashMap::from([
                ("very-old-edge".to_string(), 5),
                ("medium-edge".to_string(), 4),
                ("fresh-edge".to_string(), 3),
            ]),
            timeout_syscall_failures: HashMap::from([
                ("very-old-syscall".to_string(), 5),
                ("medium-syscall".to_string(), 4),
                ("fresh-syscall".to_string(), 3),
            ]),
            timeout_edge_last_failure_epoch: HashMap::from([
                ("very-old-edge".to_string(), 0),
                ("medium-edge".to_string(), 15),
                ("fresh-edge".to_string(), 35),
            ]),
            timeout_syscall_last_failure_epoch: HashMap::from([
                ("very-old-syscall".to_string(), 0),
                ("medium-syscall".to_string(), 15),
                ("fresh-syscall".to_string(), 35),
            ]),
        };

        assert!(state.decay_stale_weighted(10, 3));
        assert_eq!(
            state.timeout_edge_failures,
            HashMap::from([
                ("very-old-edge".to_string(), 2),
                ("medium-edge".to_string(), 2),
                ("fresh-edge".to_string(), 3),
            ])
        );
        assert_eq!(
            state.timeout_syscall_failures,
            HashMap::from([
                ("very-old-syscall".to_string(), 2),
                ("medium-syscall".to_string(), 2),
                ("fresh-syscall".to_string(), 3),
            ])
        );
    }

    #[test]
    fn avoidance_note_failure_updates_epoch_tracking() {
        let mut state = AvoidanceState::new();

        assert_eq!(state.note_edge_failure("edge", 11), 1);
        assert_eq!(state.note_edge_failure("edge", 13), 2);
        assert_eq!(state.note_syscall_failure("syscall", 12), 1);

        assert_eq!(state.learning_epoch, 13);
        assert_eq!(state.timeout_edge_failures.get("edge"), Some(&2));
        assert_eq!(state.timeout_syscall_failures.get("syscall"), Some(&1));
        assert_eq!(state.timeout_edge_last_failure_epoch.get("edge"), Some(&13));
        assert_eq!(
            state.timeout_syscall_last_failure_epoch.get("syscall"),
            Some(&12)
        );
    }

    #[test]
    fn avoidance_compact_drops_stale_unblocked_entries_but_keeps_recent_or_blocked_ones() {
        let mut state = AvoidanceState {
            learning_epoch: 100,
            timeout_edge_failures: HashMap::from([
                ("stale-noise-edge".to_string(), 1),
                ("recent-noise-edge".to_string(), 1),
                ("blocked-edge".to_string(), 2),
            ]),
            timeout_syscall_failures: HashMap::from([
                ("stale-noise-syscall".to_string(), 1),
                ("recent-noise-syscall".to_string(), 1),
                ("blocked-syscall".to_string(), 3),
            ]),
            timeout_edge_last_failure_epoch: HashMap::from([
                ("stale-noise-edge".to_string(), 0),
                ("recent-noise-edge".to_string(), 95),
                ("blocked-edge".to_string(), 0),
            ]),
            timeout_syscall_last_failure_epoch: HashMap::from([
                ("stale-noise-syscall".to_string(), 0),
                ("recent-noise-syscall".to_string(), 95),
                ("blocked-syscall".to_string(), 0),
            ]),
        };

        assert!(state.compact(2, 3, 16));
        assert_eq!(
            state.timeout_edge_failures,
            HashMap::from([
                ("recent-noise-edge".to_string(), 1),
                ("blocked-edge".to_string(), 2),
            ])
        );
        assert_eq!(
            state.timeout_syscall_failures,
            HashMap::from([
                ("recent-noise-syscall".to_string(), 1),
                ("blocked-syscall".to_string(), 3),
            ])
        );
        assert_eq!(
            state.timeout_edge_last_failure_epoch,
            HashMap::from([
                ("recent-noise-edge".to_string(), 95),
                ("blocked-edge".to_string(), 0),
            ])
        );
        assert_eq!(
            state.timeout_syscall_last_failure_epoch,
            HashMap::from([
                ("recent-noise-syscall".to_string(), 95),
                ("blocked-syscall".to_string(), 0),
            ])
        );
    }

    #[test]
    fn avoidance_prunes_weak_entries_to_recent_and_strong_budget() {
        let mut state = AvoidanceState {
            learning_epoch: 100,
            timeout_edge_failures: HashMap::from([
                ("blocked-edge".to_string(), 2),
                ("edge-a".to_string(), 1),
                ("edge-b".to_string(), 1),
                ("edge-c".to_string(), 1),
            ]),
            timeout_syscall_failures: HashMap::from([
                ("blocked-syscall".to_string(), 3),
                ("syscall-a".to_string(), 2),
                ("syscall-b".to_string(), 2),
                ("syscall-c".to_string(), 1),
                ("syscall-d".to_string(), 1),
            ]),
            timeout_edge_last_failure_epoch: HashMap::from([
                ("blocked-edge".to_string(), 0),
                ("edge-a".to_string(), 95),
                ("edge-b".to_string(), 90),
                ("edge-c".to_string(), 85),
            ]),
            timeout_syscall_last_failure_epoch: HashMap::from([
                ("blocked-syscall".to_string(), 0),
                ("syscall-a".to_string(), 95),
                ("syscall-b".to_string(), 90),
                ("syscall-c".to_string(), 99),
                ("syscall-d".to_string(), 80),
            ]),
        };

        assert!(state.prune_weak_entries(2, 3, 2, 2));
        assert_eq!(
            state.timeout_edge_failures,
            HashMap::from([
                ("blocked-edge".to_string(), 2),
                ("edge-a".to_string(), 1),
                ("edge-b".to_string(), 1),
            ])
        );
        assert_eq!(
            state.timeout_syscall_failures,
            HashMap::from([
                ("blocked-syscall".to_string(), 3),
                ("syscall-a".to_string(), 2),
                ("syscall-b".to_string(), 2),
            ])
        );
        assert!(!state.timeout_edge_last_failure_epoch.contains_key("edge-c"));
        assert!(!state
            .timeout_syscall_last_failure_epoch
            .contains_key("syscall-c"));
        assert!(!state
            .timeout_syscall_last_failure_epoch
            .contains_key("syscall-d"));
    }
}
