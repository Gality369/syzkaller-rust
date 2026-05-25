/// Minimal crash detector for Linux kernel console output.
/// Checks for common crash signatures in serial/console output.
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CrashPattern {
    needle: &'static str,
    priority: u8,
    excludes: &'static [&'static str],
}

const CRASH_PATTERNS: &[CrashPattern] = &[
    CrashPattern {
        needle: "kasan:",
        priority: 100,
        excludes: &["initialized"],
    },
    CrashPattern {
        needle: "ubsan:",
        priority: 100,
        excludes: &[],
    },
    CrashPattern {
        needle: "kernel panic",
        priority: 100,
        excludes: &[],
    },
    CrashPattern {
        needle: "bug: unable to handle",
        priority: 95,
        excludes: &[],
    },
    CrashPattern {
        needle: "bug: kernel null pointer dereference",
        priority: 95,
        excludes: &[],
    },
    CrashPattern {
        needle: "general protection fault",
        priority: 95,
        excludes: &[],
    },
    CrashPattern {
        needle: "invalid opcode:",
        priority: 95,
        excludes: &[],
    },
    CrashPattern {
        needle: "divide error:",
        priority: 95,
        excludes: &[],
    },
    CrashPattern {
        needle: "bug: kfence:",
        priority: 92,
        excludes: &[],
    },
    CrashPattern {
        needle: "bug: kcsan:",
        priority: 92,
        excludes: &[],
    },
    CrashPattern {
        needle: "kfence:",
        priority: 90,
        excludes: &["initialized"],
    },
    CrashPattern {
        needle: "kcsan:",
        priority: 90,
        excludes: &["initialized"],
    },
    CrashPattern {
        needle: "bug: sleeping function called",
        priority: 90,
        excludes: &[],
    },
    CrashPattern {
        needle: "kernel bug at",
        priority: 90,
        excludes: &[],
    },
    CrashPattern {
        needle: "stack-protector:",
        priority: 90,
        excludes: &[],
    },
    CrashPattern {
        needle: "warning: cpu:",
        priority: 85,
        excludes: &[],
    },
    CrashPattern {
        needle: "bug: soft lockup",
        priority: 80,
        excludes: &[],
    },
    CrashPattern {
        needle: "info: rcu_sched detected stalls",
        priority: 80,
        excludes: &[],
    },
    CrashPattern {
        needle: "info: task hung for more than",
        priority: 80,
        excludes: &[],
    },
    CrashPattern {
        needle: "bug:",
        priority: 70,
        excludes: &[],
    },
    CrashPattern {
        needle: "oops:",
        priority: 60,
        excludes: &[],
    },
    CrashPattern {
        needle: "rip:",
        priority: 20,
        excludes: &[],
    },
    CrashPattern {
        needle: "call trace:",
        priority: 10,
        excludes: &[],
    },
];

const ARTIFACT_METADATA_VERSION: u32 = 2;
const ARTIFACT_CATALOG_VERSION: u32 = 2;
const ARTIFACT_REPRO_QUEUE_VERSION: u32 = 4;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ArtifactMetadata {
    version: u32,
    artifact_type: String,
    summary: String,
    #[serde(default)]
    normalized_summary: String,
    signature: String,
    first_seen_unix_secs: u64,
    last_seen_unix_secs: u64,
    occurrences: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    shape: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    profile: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
struct ArtifactCatalogEntry {
    artifact_type: String,
    summary: String,
    normalized_summary: String,
    signature: String,
    occurrences: u64,
    first_seen_unix_secs: u64,
    last_seen_unix_secs: u64,
    directory: String,
    summary_path: String,
    program_path: String,
    preferred_summary_path: String,
    preferred_program_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    log_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    preferred_log_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    shape: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    shape_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    preferred_shape_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    profile: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    profile_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    preferred_profile_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    repro_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    preferred_repro_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    first_summary_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    first_program_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    first_log_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    first_shape_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    first_profile_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    first_repro_path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
struct ArtifactCatalog {
    version: u32,
    updated_unix_secs: u64,
    entries: Vec<ArtifactCatalogEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct ArtifactReproQueueEntry {
    pub artifact_type: String,
    pub summary: String,
    pub normalized_summary: String,
    pub signature: String,
    pub occurrences: u64,
    pub priority: u64,
    pub attempts: u64,
    pub first_seen_unix_secs: u64,
    pub last_seen_unix_secs: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_attempt_unix_secs: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_attempt_outcome: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_attempt_not_before_unix_secs: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lease_owner: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lease_expires_unix_secs: Option<u64>,
    pub directory: String,
    pub preferred_summary_path: String,
    pub preferred_program_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preferred_log_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preferred_shape_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preferred_profile_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preferred_repro_path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
struct ArtifactReproQueue {
    version: u32,
    updated_unix_secs: u64,
    entries: Vec<ArtifactReproQueueEntry>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ArtifactCatalogSyncReport {
    pub total_entries: usize,
    pub crash_entries: usize,
    pub timeout_entries: usize,
    pub skipped_entries: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactReproInfo {
    pub artifact_type: String,
    pub summary: String,
    pub signature: String,
    pub manager_instance: usize,
    pub total_execs: u64,
    pub syscall_descriptions: Option<String>,
    pub executor: String,
    pub sandbox: String,
    pub procs: i32,
    pub cover: bool,
    pub syscall_timeout_ms: i32,
    pub program_timeout_ms: i32,
    pub slowdown: i32,
    pub vm_count: usize,
    pub vm_cpu: usize,
    pub vm_mem: usize,
    pub vm_qemu: String,
    pub vm_kernel: String,
    pub vm_image: String,
    pub vm_cmdline: String,
    pub program: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shape: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
}

/// Check if the given output contains a kernel crash.
/// Returns Some(crash_title) if a crash is detected, None otherwise.
pub fn detect_crash(output: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(output);
    let mut best: Option<(u8, usize, String)> = None;
    for (line_idx, line) in text.lines().enumerate() {
        let stripped = strip_log_prefix(line).trim();
        if stripped.is_empty() {
            continue;
        }
        let lower = stripped.to_ascii_lowercase();
        let line_priority = CRASH_PATTERNS
            .iter()
            .filter(|pattern| {
                lower.contains(pattern.needle)
                    && !pattern.excludes.iter().any(|needle| lower.contains(needle))
            })
            .map(|pattern| pattern.priority)
            .max();
        let Some(priority) = line_priority else {
            continue;
        };

        match &best {
            Some((best_priority, best_line_idx, _))
                if *best_priority > priority
                    || (*best_priority == priority && *best_line_idx <= line_idx) => {}
            _ => best = Some((priority, line_idx, stripped.to_string())),
        }
    }
    best.map(|(_, _, title)| title)
}

/// Save crash information to disk.
pub fn save_crash(
    workdir: &str,
    title: &str,
    serial_output: &[u8],
    program_desc: &str,
    shape_desc: Option<&str>,
    profile_desc: Option<&str>,
    repro_info: Option<&ArtifactReproInfo>,
) -> std::io::Result<()> {
    let crash_dir = std::path::Path::new(workdir).join("crashes");
    std::fs::create_dir_all(&crash_dir)?;

    let normalized_summary = normalize_summary(title);
    let signature = artifact_signature(&[
        "crash",
        &normalized_summary,
        shape_desc.unwrap_or(""),
        profile_desc.unwrap_or(""),
        crash_signature_program_context(&normalized_summary, program_desc),
    ]);
    let crash_subdir = prepare_artifact_dir(&crash_dir, &normalized_summary, &signature)?;

    // Save log
    std::fs::write(crash_subdir.join("log"), serial_output)?;

    // Save description
    std::fs::write(crash_subdir.join("description"), title.as_bytes())?;

    // Save the program
    std::fs::write(crash_subdir.join("program"), program_desc.as_bytes())?;
    if let Some(shape) = shape_desc {
        std::fs::write(crash_subdir.join("shape"), shape.as_bytes())?;
    }
    if let Some(profile) = profile_desc {
        std::fs::write(crash_subdir.join("profile"), profile.as_bytes())?;
    }
    let metadata = update_artifact_metadata(
        &crash_subdir,
        "crash",
        title,
        &normalized_summary,
        &signature,
        shape_desc,
        profile_desc,
    )?;
    let repro_written = if let Some(repro) = repro_info {
        let mut repro = repro.clone();
        repro.artifact_type = "crash".to_string();
        repro.summary = title.to_string();
        repro.signature = signature.clone();
        repro.program = program_desc.to_string();
        repro.shape = shape_desc.map(str::to_string);
        repro.profile = profile_desc.map(str::to_string);
        update_repro_info(&crash_subdir, repro)?;
        true
    } else {
        false
    };
    snapshot_first_seen_files(
        &crash_subdir,
        metadata.occurrences,
        &[
            "log",
            "description",
            "program",
            "shape",
            "profile",
            "repro.json",
        ],
    )?;
    update_artifact_catalog(
        std::path::Path::new(workdir),
        build_artifact_catalog_entry(
            std::path::Path::new(workdir),
            &crash_subdir,
            &metadata,
            "description",
            "program",
            Some("log"),
            shape_desc.map(|_| "shape"),
            profile_desc.map(|_| "profile"),
            repro_written.then_some("repro.json"),
        ),
    )?;

    log::warn!("Crash saved to {:?}: {}", crash_subdir, title);
    Ok(())
}

/// Save a timed-out or hanged program for later triage.
pub fn save_timeout(
    workdir: &str,
    reason: &str,
    program_desc: &str,
    shape_desc: &str,
    profile_desc: &str,
    repro_info: Option<&ArtifactReproInfo>,
) -> std::io::Result<()> {
    let timeout_dir = std::path::Path::new(workdir).join("timeouts");
    std::fs::create_dir_all(&timeout_dir)?;

    let normalized_summary = normalize_summary(reason);
    let signature = artifact_signature(&[
        "timeout",
        &normalized_summary,
        shape_desc,
        profile_desc,
        timeout_signature_program_context(program_desc, shape_desc, profile_desc),
    ]);
    let timeout_subdir = prepare_artifact_dir(&timeout_dir, &normalized_summary, &signature)?;
    std::fs::write(timeout_subdir.join("reason"), reason.as_bytes())?;
    std::fs::write(timeout_subdir.join("program"), program_desc.as_bytes())?;
    std::fs::write(timeout_subdir.join("shape"), shape_desc.as_bytes())?;
    std::fs::write(timeout_subdir.join("profile"), profile_desc.as_bytes())?;
    let metadata = update_artifact_metadata(
        &timeout_subdir,
        "timeout",
        reason,
        &normalized_summary,
        &signature,
        Some(shape_desc),
        Some(profile_desc),
    )?;
    let repro_written = if let Some(repro) = repro_info {
        let mut repro = repro.clone();
        repro.artifact_type = "timeout".to_string();
        repro.summary = reason.to_string();
        repro.signature = signature.clone();
        repro.program = program_desc.to_string();
        repro.shape = Some(shape_desc.to_string());
        repro.profile = Some(profile_desc.to_string());
        update_repro_info(&timeout_subdir, repro)?;
        true
    } else {
        false
    };
    snapshot_first_seen_files(
        &timeout_subdir,
        metadata.occurrences,
        &["reason", "program", "shape", "profile", "repro.json"],
    )?;
    update_artifact_catalog(
        std::path::Path::new(workdir),
        build_artifact_catalog_entry(
            std::path::Path::new(workdir),
            &timeout_subdir,
            &metadata,
            "reason",
            "program",
            None,
            Some("shape"),
            Some("profile"),
            repro_written.then_some("repro.json"),
        ),
    )?;

    log::warn!(
        "Timed-out program saved to {:?}: {}",
        timeout_subdir,
        reason
    );
    Ok(())
}

fn sanitize_artifact_component(text: &str) -> String {
    let sanitized = text
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '_' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .take(80)
        .collect::<String>();
    if sanitized.is_empty() {
        "artifact".to_string()
    } else {
        sanitized
    }
}

fn artifact_signature(parts: &[&str]) -> String {
    const FNV_OFFSET_BASIS: u64 = 0xcbf29ce484222325;
    const FNV_PRIME: u64 = 0x100000001b3;
    let mut hash = FNV_OFFSET_BASIS;
    for part in parts {
        for byte in part.as_bytes() {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(FNV_PRIME);
        }
        hash ^= 0xff;
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    format!("{hash:016x}")
}

fn strip_log_prefix(line: &str) -> &str {
    let mut rest = line.trim_start();
    loop {
        let trimmed = rest.trim_start();
        if let Some(next) = strip_angle_prefix(trimmed) {
            rest = next;
            continue;
        }
        if let Some(next) = strip_bracket_prefix(trimmed) {
            rest = next;
            continue;
        }
        return trimmed;
    }
}

fn strip_angle_prefix(line: &str) -> Option<&str> {
    if !line.starts_with('<') {
        return None;
    }
    let end = line.find('>')?;
    let prefix = &line[1..end];
    if prefix.chars().all(|ch| ch.is_ascii_digit()) {
        Some(line[end + 1..].trim_start())
    } else {
        None
    }
}

fn strip_bracket_prefix(line: &str) -> Option<&str> {
    if !line.starts_with('[') {
        return None;
    }
    let end = line.find(']')?;
    let prefix = &line[1..end];
    if prefix
        .chars()
        .all(|ch| ch.is_ascii_digit() || ch == ' ' || ch == '.' || ch == ':')
    {
        Some(line[end + 1..].trim_start())
    } else {
        None
    }
}

fn normalize_summary(summary: &str) -> String {
    summary
        .split_whitespace()
        .map(normalize_summary_token)
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase()
}

fn normalize_summary_token(token: &str) -> String {
    let chars = token.chars().collect::<Vec<_>>();
    let mut normalized = String::new();
    let mut i = 0usize;
    while i < chars.len() {
        if chars[i] == '0'
            && i + 2 < chars.len()
            && (chars[i + 1] == 'x' || chars[i + 1] == 'X')
            && chars[i + 2].is_ascii_hexdigit()
        {
            let mut j = i + 2;
            while j < chars.len() && chars[j].is_ascii_hexdigit() {
                j += 1;
            }
            if j > i + 2 {
                normalized.push_str("0x<hex>");
                i = j;
                continue;
            }
        }
        if chars[i].is_ascii_digit() {
            let mut j = i;
            while j < chars.len() && chars[j].is_ascii_digit() {
                j += 1;
            }
            if j - i >= 3 {
                normalized.push_str("<num>");
                i = j;
                continue;
            }
        }
        if chars[i].is_ascii_hexdigit() {
            let mut j = i;
            while j < chars.len() && chars[j].is_ascii_hexdigit() {
                j += 1;
            }
            if j - i >= 8 {
                normalized.push_str("<hex>");
                i = j;
                continue;
            }
        }
        normalized.push(chars[i]);
        i += 1;
    }
    normalized
}

fn crash_signature_program_context<'a>(normalized_summary: &str, program_desc: &'a str) -> &'a str {
    if normalized_summary == "rip:"
        || normalized_summary == "call trace:"
        || normalized_summary == "oops:"
    {
        signature_program_desc(program_desc)
    } else {
        ""
    }
}

fn timeout_signature_program_context<'a>(
    program_desc: &'a str,
    shape_desc: &str,
    profile_desc: &str,
) -> &'a str {
    if shape_desc.trim().is_empty() || profile_desc.trim().is_empty() || profile_desc == "(none)" {
        signature_program_desc(program_desc)
    } else {
        ""
    }
}

fn signature_program_desc(program_desc: &str) -> &str {
    if program_desc.starts_with('(') {
        ""
    } else {
        program_desc
    }
}

fn current_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn prepare_artifact_dir(
    artifact_root: &std::path::Path,
    summary: &str,
    signature: &str,
) -> std::io::Result<std::path::PathBuf> {
    let safe_summary = sanitize_artifact_component(summary);
    let artifact_dir = artifact_root.join(format!("{}_{}", safe_summary, signature));
    std::fs::create_dir_all(&artifact_dir)?;
    Ok(artifact_dir)
}

fn update_artifact_metadata(
    artifact_dir: &std::path::Path,
    artifact_type: &str,
    summary: &str,
    normalized_summary: &str,
    signature: &str,
    shape_desc: Option<&str>,
    profile_desc: Option<&str>,
) -> std::io::Result<ArtifactMetadata> {
    let metadata_path = artifact_dir.join("metadata.json");
    let now = current_unix_secs();
    let mut metadata = if metadata_path.exists() {
        let data = std::fs::read(&metadata_path)?;
        serde_json::from_slice::<ArtifactMetadata>(&data).unwrap_or(ArtifactMetadata {
            version: ARTIFACT_METADATA_VERSION,
            artifact_type: artifact_type.to_string(),
            summary: summary.to_string(),
            normalized_summary: normalized_summary.to_string(),
            signature: signature.to_string(),
            first_seen_unix_secs: now,
            last_seen_unix_secs: now,
            occurrences: 0,
            shape: shape_desc.map(str::to_string),
            profile: profile_desc.map(str::to_string),
        })
    } else {
        ArtifactMetadata {
            version: ARTIFACT_METADATA_VERSION,
            artifact_type: artifact_type.to_string(),
            summary: summary.to_string(),
            normalized_summary: normalized_summary.to_string(),
            signature: signature.to_string(),
            first_seen_unix_secs: now,
            last_seen_unix_secs: now,
            occurrences: 0,
            shape: shape_desc.map(str::to_string),
            profile: profile_desc.map(str::to_string),
        }
    };
    metadata.version = ARTIFACT_METADATA_VERSION;
    metadata.artifact_type = artifact_type.to_string();
    metadata.summary = summary.to_string();
    metadata.normalized_summary = normalized_summary.to_string();
    metadata.signature = signature.to_string();
    metadata.last_seen_unix_secs = now;
    if metadata.first_seen_unix_secs == 0 {
        metadata.first_seen_unix_secs = now;
    }
    metadata.occurrences += 1;
    metadata.shape = shape_desc.map(str::to_string);
    metadata.profile = profile_desc.map(str::to_string);
    let data = serde_json::to_vec_pretty(&metadata)?;
    std::fs::write(metadata_path, data)?;
    Ok(metadata)
}

fn update_repro_info(
    artifact_dir: &std::path::Path,
    repro_info: ArtifactReproInfo,
) -> std::io::Result<()> {
    let data = serde_json::to_vec_pretty(&repro_info)?;
    std::fs::write(artifact_dir.join("repro.json"), data)?;
    Ok(())
}

fn build_artifact_catalog_entry(
    workdir: &std::path::Path,
    artifact_dir: &std::path::Path,
    metadata: &ArtifactMetadata,
    summary_filename: &str,
    program_filename: &str,
    log_filename: Option<&str>,
    shape_filename: Option<&str>,
    profile_filename: Option<&str>,
    repro_filename: Option<&str>,
) -> ArtifactCatalogEntry {
    let summary_path = relative_artifact_path(workdir, &artifact_dir.join(summary_filename));
    let program_path = relative_artifact_path(workdir, &artifact_dir.join(program_filename));
    let log_path =
        log_filename.map(|name| relative_artifact_path(workdir, &artifact_dir.join(name)));
    let shape_path =
        shape_filename.map(|name| relative_artifact_path(workdir, &artifact_dir.join(name)));
    let profile_path =
        profile_filename.map(|name| relative_artifact_path(workdir, &artifact_dir.join(name)));
    let repro_path =
        repro_filename.map(|name| relative_artifact_path(workdir, &artifact_dir.join(name)));
    let first_summary_path = artifact_optional_relative_path(
        workdir,
        artifact_dir,
        &format!("first_{summary_filename}"),
    );
    let first_program_path = artifact_optional_relative_path(
        workdir,
        artifact_dir,
        &format!("first_{program_filename}"),
    );
    let first_log_path = log_filename.and_then(|name| {
        artifact_optional_relative_path(workdir, artifact_dir, &format!("first_{name}"))
    });
    let first_shape_path = shape_filename.and_then(|name| {
        artifact_optional_relative_path(workdir, artifact_dir, &format!("first_{name}"))
    });
    let first_profile_path = profile_filename.and_then(|name| {
        artifact_optional_relative_path(workdir, artifact_dir, &format!("first_{name}"))
    });
    let first_repro_path = repro_filename.and_then(|name| {
        artifact_optional_relative_path(workdir, artifact_dir, &format!("first_{name}"))
    });
    ArtifactCatalogEntry {
        artifact_type: metadata.artifact_type.clone(),
        summary: metadata.summary.clone(),
        normalized_summary: metadata.normalized_summary.clone(),
        signature: metadata.signature.clone(),
        occurrences: metadata.occurrences,
        first_seen_unix_secs: metadata.first_seen_unix_secs,
        last_seen_unix_secs: metadata.last_seen_unix_secs,
        directory: relative_artifact_path(workdir, artifact_dir),
        summary_path: summary_path.clone(),
        program_path: program_path.clone(),
        preferred_summary_path: first_summary_path
            .clone()
            .unwrap_or_else(|| summary_path.clone()),
        preferred_program_path: first_program_path
            .clone()
            .unwrap_or_else(|| program_path.clone()),
        log_path: log_path.clone(),
        preferred_log_path: first_log_path.clone().or_else(|| log_path.clone()),
        shape: metadata.shape.clone(),
        shape_path: shape_path.clone(),
        preferred_shape_path: first_shape_path.clone().or_else(|| shape_path.clone()),
        profile: metadata.profile.clone(),
        profile_path: profile_path.clone(),
        preferred_profile_path: first_profile_path.clone().or_else(|| profile_path.clone()),
        repro_path: repro_path.clone(),
        preferred_repro_path: first_repro_path.clone().or_else(|| repro_path.clone()),
        first_summary_path,
        first_program_path,
        first_log_path,
        first_shape_path,
        first_profile_path,
        first_repro_path,
    }
}

fn relative_artifact_path(workdir: &std::path::Path, path: &std::path::Path) -> String {
    path.strip_prefix(workdir)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

fn artifact_optional_relative_path(
    workdir: &std::path::Path,
    artifact_dir: &std::path::Path,
    filename: &str,
) -> Option<String> {
    let path = artifact_dir.join(filename);
    path.exists()
        .then(|| relative_artifact_path(workdir, &path))
}

fn update_artifact_catalog(
    workdir: &std::path::Path,
    entry: ArtifactCatalogEntry,
) -> std::io::Result<()> {
    let mut catalog = load_artifact_catalog(workdir)?;
    catalog.version = ARTIFACT_CATALOG_VERSION;
    if let Some(existing) = catalog.entries.iter_mut().find(|existing| {
        existing.artifact_type == entry.artifact_type && existing.signature == entry.signature
    }) {
        *existing = entry;
    } else {
        catalog.entries.push(entry);
    }
    write_artifact_catalog(workdir, catalog)
}

fn snapshot_first_seen_files(
    artifact_dir: &std::path::Path,
    occurrences: u64,
    filenames: &[&str],
) -> std::io::Result<()> {
    if occurrences != 1 {
        return Ok(());
    }
    for filename in filenames {
        let src = artifact_dir.join(filename);
        if !src.exists() {
            continue;
        }
        let dst = artifact_dir.join(format!("first_{filename}"));
        std::fs::copy(src, dst)?;
    }
    Ok(())
}

pub fn sync_artifact_catalog(workdir: &str) -> std::io::Result<ArtifactCatalogSyncReport> {
    let workdir = std::path::Path::new(workdir);
    let (crash_entries, skipped_crashes) = scan_artifact_catalog_entries(
        workdir,
        "crash",
        "crashes",
        "description",
        "program",
        Some("log"),
    )?;
    let (timeout_entries, skipped_timeouts) =
        scan_artifact_catalog_entries(workdir, "timeout", "timeouts", "reason", "program", None)?;
    let mut entries = crash_entries;
    entries.extend(timeout_entries);
    let report = ArtifactCatalogSyncReport {
        total_entries: entries.len(),
        crash_entries: entries
            .iter()
            .filter(|entry| entry.artifact_type == "crash")
            .count(),
        timeout_entries: entries
            .iter()
            .filter(|entry| entry.artifact_type == "timeout")
            .count(),
        skipped_entries: skipped_crashes + skipped_timeouts,
    };
    let catalog = ArtifactCatalog {
        version: ARTIFACT_CATALOG_VERSION,
        updated_unix_secs: current_unix_secs(),
        entries,
    };
    write_artifact_catalog(workdir, catalog)?;
    Ok(report)
}

fn scan_artifact_catalog_entries(
    workdir: &std::path::Path,
    artifact_type: &str,
    root_name: &str,
    summary_filename: &str,
    program_filename: &str,
    log_filename: Option<&str>,
) -> std::io::Result<(Vec<ArtifactCatalogEntry>, usize)> {
    let root = workdir.join(root_name);
    if !root.exists() {
        return Ok((Vec::new(), 0));
    }
    let mut entries = Vec::new();
    let mut skipped = 0usize;
    for dir_entry in std::fs::read_dir(&root)? {
        let dir_entry = dir_entry?;
        if !dir_entry.file_type()?.is_dir() {
            continue;
        }
        let artifact_dir = dir_entry.path();
        let metadata_path = artifact_dir.join("metadata.json");
        let metadata = match std::fs::read(&metadata_path)
            .ok()
            .and_then(|data| serde_json::from_slice::<ArtifactMetadata>(&data).ok())
        {
            Some(metadata) if metadata.artifact_type == artifact_type => metadata,
            _ => {
                skipped += 1;
                continue;
            }
        };
        let shape_filename = artifact_dir.join("shape").exists().then_some("shape");
        let profile_filename = artifact_dir.join("profile").exists().then_some("profile");
        let repro_filename = artifact_dir
            .join("repro.json")
            .exists()
            .then_some("repro.json");
        entries.push(build_artifact_catalog_entry(
            workdir,
            &artifact_dir,
            &metadata,
            summary_filename,
            program_filename,
            log_filename.filter(|name| artifact_dir.join(name).exists()),
            shape_filename,
            profile_filename,
            repro_filename,
        ));
    }
    Ok((entries, skipped))
}

fn load_artifact_catalog(workdir: &std::path::Path) -> std::io::Result<ArtifactCatalog> {
    let catalog_path = workdir.join("artifacts.json");
    let now = current_unix_secs();
    if !catalog_path.exists() {
        return Ok(ArtifactCatalog {
            version: ARTIFACT_CATALOG_VERSION,
            updated_unix_secs: now,
            entries: Vec::new(),
        });
    }
    let data = std::fs::read(&catalog_path)?;
    Ok(
        serde_json::from_slice::<ArtifactCatalog>(&data).unwrap_or(ArtifactCatalog {
            version: ARTIFACT_CATALOG_VERSION,
            updated_unix_secs: now,
            entries: Vec::new(),
        }),
    )
}

fn write_artifact_catalog(
    workdir: &std::path::Path,
    mut catalog: ArtifactCatalog,
) -> std::io::Result<()> {
    catalog.version = ARTIFACT_CATALOG_VERSION;
    catalog.updated_unix_secs = current_unix_secs();
    catalog.entries.sort_by(|left, right| {
        right
            .last_seen_unix_secs
            .cmp(&left.last_seen_unix_secs)
            .then_with(|| right.occurrences.cmp(&left.occurrences))
            .then_with(|| left.artifact_type.cmp(&right.artifact_type))
            .then_with(|| left.signature.cmp(&right.signature))
    });
    let data = serde_json::to_vec_pretty(&catalog)?;
    std::fs::write(workdir.join("artifacts.json"), data)?;
    write_artifact_repro_queue(workdir, build_artifact_repro_queue(workdir, &catalog))?;
    Ok(())
}

fn build_artifact_repro_queue(
    workdir: &std::path::Path,
    catalog: &ArtifactCatalog,
) -> ArtifactReproQueue {
    let previous_queue = load_artifact_repro_queue(workdir).unwrap_or_default();
    let now = current_unix_secs();
    let mut entries = catalog
        .entries
        .iter()
        .map(|entry| build_artifact_repro_queue_entry(entry, &previous_queue, now))
        .collect::<Vec<_>>();
    sort_artifact_repro_queue_entries(&mut entries, now);
    ArtifactReproQueue {
        version: ARTIFACT_REPRO_QUEUE_VERSION,
        updated_unix_secs: current_unix_secs(),
        entries,
    }
}

fn build_artifact_repro_queue_entry(
    entry: &ArtifactCatalogEntry,
    previous_queue: &ArtifactReproQueue,
    now: u64,
) -> ArtifactReproQueueEntry {
    let previous = previous_queue.entries.iter().find(|previous| {
        previous.artifact_type == entry.artifact_type && previous.signature == entry.signature
    });
    let (lease_owner, lease_expires_unix_secs) = previous
        .map(|entry| retained_repro_queue_lease(entry, now))
        .unwrap_or((None, None));
    let next_attempt_not_before_unix_secs =
        previous.and_then(|entry| retained_repro_queue_backoff(entry, now));
    ArtifactReproQueueEntry {
        artifact_type: entry.artifact_type.clone(),
        summary: entry.summary.clone(),
        normalized_summary: entry.normalized_summary.clone(),
        signature: entry.signature.clone(),
        occurrences: entry.occurrences,
        priority: artifact_repro_priority(entry),
        attempts: previous.map(|entry| entry.attempts).unwrap_or(0),
        first_seen_unix_secs: entry.first_seen_unix_secs,
        last_seen_unix_secs: entry.last_seen_unix_secs,
        last_attempt_unix_secs: previous.and_then(|entry| entry.last_attempt_unix_secs),
        last_attempt_outcome: previous.and_then(|entry| {
            entry
                .last_attempt_outcome
                .as_deref()
                .map(canonicalize_repro_queue_outcome)
        }),
        next_attempt_not_before_unix_secs,
        lease_owner,
        lease_expires_unix_secs,
        directory: entry.directory.clone(),
        preferred_summary_path: entry.preferred_summary_path.clone(),
        preferred_program_path: entry.preferred_program_path.clone(),
        preferred_log_path: entry.preferred_log_path.clone(),
        preferred_shape_path: entry.preferred_shape_path.clone(),
        preferred_profile_path: entry.preferred_profile_path.clone(),
        preferred_repro_path: entry.preferred_repro_path.clone(),
    }
}

fn repro_queue_entry_succeeded(entry: &ArtifactReproQueueEntry) -> bool {
    repro_queue_outcome_rank(entry.last_attempt_outcome.as_deref()) >= 3
}

fn repro_queue_outcome_rank(outcome: Option<&str>) -> u8 {
    match outcome.map(canonicalize_repro_queue_outcome).as_deref() {
        None => 0,
        Some("failed") => 1,
        Some("timed_out") => 2,
        Some("succeeded") => 3,
        Some(_) => 1,
    }
}

fn repro_queue_entry_is_in_backoff(entry: &ArtifactReproQueueEntry, now: u64) -> bool {
    matches!(entry.next_attempt_not_before_unix_secs, Some(not_before) if not_before > now)
}

fn repro_queue_entry_has_active_lease(entry: &ArtifactReproQueueEntry, now: u64) -> bool {
    matches!(
        (entry.lease_owner.as_deref(), entry.lease_expires_unix_secs),
        (Some(owner), Some(expires_at)) if !owner.is_empty() && expires_at > now
    )
}

fn retained_repro_queue_backoff(entry: &ArtifactReproQueueEntry, now: u64) -> Option<u64> {
    entry
        .next_attempt_not_before_unix_secs
        .filter(|not_before| *not_before > now)
}

fn retained_repro_queue_lease(
    entry: &ArtifactReproQueueEntry,
    now: u64,
) -> (Option<String>, Option<u64>) {
    if repro_queue_entry_has_active_lease(entry, now) {
        (entry.lease_owner.clone(), entry.lease_expires_unix_secs)
    } else {
        (None, None)
    }
}

fn sort_artifact_repro_queue_entries(entries: &mut [ArtifactReproQueueEntry], now: u64) {
    entries.sort_by(|left, right| {
        repro_queue_entry_has_active_lease(left, now)
            .cmp(&repro_queue_entry_has_active_lease(right, now))
            .then_with(|| {
                repro_queue_entry_is_in_backoff(left, now)
                    .cmp(&repro_queue_entry_is_in_backoff(right, now))
            })
            .then_with(|| {
                retained_repro_queue_backoff(left, now)
                    .unwrap_or(0)
                    .cmp(&retained_repro_queue_backoff(right, now).unwrap_or(0))
            })
            .then_with(|| {
                repro_queue_entry_succeeded(left).cmp(&repro_queue_entry_succeeded(right))
            })
            .then_with(|| (right.attempts == 0).cmp(&(left.attempts == 0)))
            .then_with(|| {
                repro_queue_outcome_rank(left.last_attempt_outcome.as_deref()).cmp(
                    &repro_queue_outcome_rank(right.last_attempt_outcome.as_deref()),
                )
            })
            .then_with(|| right.priority.cmp(&left.priority))
            .then_with(|| left.attempts.cmp(&right.attempts))
            .then_with(|| {
                left.last_attempt_unix_secs
                    .unwrap_or(0)
                    .cmp(&right.last_attempt_unix_secs.unwrap_or(0))
            })
            .then_with(|| right.last_seen_unix_secs.cmp(&left.last_seen_unix_secs))
            .then_with(|| right.occurrences.cmp(&left.occurrences))
            .then_with(|| left.artifact_type.cmp(&right.artifact_type))
            .then_with(|| left.signature.cmp(&right.signature))
    });
}

fn repro_queue_backoff_secs(outcome: &str, attempts: u64) -> Option<u64> {
    let normalized = canonicalize_repro_queue_outcome(outcome);
    if normalized == "succeeded" {
        return None;
    }
    let capped_attempts = attempts.clamp(1, 10);
    let base_secs: u64 = match normalized.as_str() {
        "failed" => 60,
        "timed_out" => 300,
        _ => 120,
    };
    Some(base_secs.saturating_mul(capped_attempts))
}

fn canonicalize_repro_queue_outcome(outcome: &str) -> String {
    let normalized = outcome.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "" => "failed".to_string(),
        "success" | "succeeded" | "reproduced" | "minimized" => "succeeded".to_string(),
        "timeout" | "timed_out" | "timed-out" | "hanged" | "hung" => "timed_out".to_string(),
        "failure" | "failed" | "error" | "errored" => "failed".to_string(),
        _ => normalized,
    }
}

fn artifact_repro_priority(entry: &ArtifactCatalogEntry) -> u64 {
    let type_score = if entry.artifact_type == "crash" {
        2_000_000
    } else {
        1_000_000
    };
    let repro_bonus = if entry.preferred_repro_path.is_some() {
        100_000
    } else {
        0
    };
    let log_bonus = if entry.preferred_log_path.is_some() {
        10_000
    } else {
        0
    };
    let shape_bonus = if entry.preferred_shape_path.is_some() {
        1_000
    } else {
        0
    };
    let profile_bonus = if entry.preferred_profile_path.is_some() {
        500
    } else {
        0
    };
    type_score + repro_bonus + log_bonus + shape_bonus + profile_bonus + entry.occurrences.min(999)
}

fn write_artifact_repro_queue(
    workdir: &std::path::Path,
    mut queue: ArtifactReproQueue,
) -> std::io::Result<()> {
    queue.version = ARTIFACT_REPRO_QUEUE_VERSION;
    queue.updated_unix_secs = current_unix_secs();
    let data = serde_json::to_vec_pretty(&queue)?;
    std::fs::write(workdir.join("repro_queue.json"), data)?;
    Ok(())
}

fn load_artifact_repro_queue(workdir: &std::path::Path) -> std::io::Result<ArtifactReproQueue> {
    let queue_path = workdir.join("repro_queue.json");
    let now = current_unix_secs();
    if !queue_path.exists() {
        return Ok(ArtifactReproQueue {
            version: ARTIFACT_REPRO_QUEUE_VERSION,
            updated_unix_secs: now,
            entries: Vec::new(),
        });
    }
    let data = std::fs::read(&queue_path)?;
    Ok(
        serde_json::from_slice::<ArtifactReproQueue>(&data).unwrap_or(ArtifactReproQueue {
            version: ARTIFACT_REPRO_QUEUE_VERSION,
            updated_unix_secs: now,
            entries: Vec::new(),
        }),
    )
}

pub fn record_repro_queue_attempt(
    workdir: &str,
    artifact_type: &str,
    signature: &str,
    outcome: &str,
) -> std::io::Result<bool> {
    record_repro_queue_attempt_at(
        std::path::Path::new(workdir),
        artifact_type,
        signature,
        outcome,
        current_unix_secs(),
    )
}

fn record_repro_queue_attempt_at(
    workdir: &std::path::Path,
    artifact_type: &str,
    signature: &str,
    outcome: &str,
    now: u64,
) -> std::io::Result<bool> {
    let mut queue = load_artifact_repro_queue(workdir)?;
    let Some(entry) = queue
        .entries
        .iter_mut()
        .find(|entry| entry.artifact_type == artifact_type && entry.signature == signature)
    else {
        return Ok(false);
    };
    entry.attempts += 1;
    entry.last_attempt_unix_secs = Some(now);
    entry.last_attempt_outcome = Some(canonicalize_repro_queue_outcome(outcome));
    entry.next_attempt_not_before_unix_secs = repro_queue_backoff_secs(outcome, entry.attempts)
        .map(|backoff| now.saturating_add(backoff));
    entry.lease_owner = None;
    entry.lease_expires_unix_secs = None;
    sort_artifact_repro_queue_entries(&mut queue.entries, now);
    write_artifact_repro_queue(workdir, queue)?;
    Ok(true)
}

pub fn claim_repro_queue_entry(
    workdir: &str,
    worker_id: &str,
    lease_secs: u64,
) -> std::io::Result<Option<ArtifactReproQueueEntry>> {
    claim_repro_queue_entry_at(
        std::path::Path::new(workdir),
        worker_id,
        lease_secs,
        current_unix_secs(),
    )
}

fn claim_repro_queue_entry_at(
    workdir: &std::path::Path,
    worker_id: &str,
    lease_secs: u64,
    now: u64,
) -> std::io::Result<Option<ArtifactReproQueueEntry>> {
    let mut queue = load_artifact_repro_queue(workdir)?;
    let lease_expires_unix_secs = Some(now.saturating_add(lease_secs.max(1)));

    if let Some(entry) = queue.entries.iter_mut().find(|entry| {
        matches!(
            (entry.lease_owner.as_deref(), entry.lease_expires_unix_secs),
            (Some(owner), Some(expires_at)) if owner == worker_id && expires_at > now
        )
    }) {
        entry.next_attempt_not_before_unix_secs = retained_repro_queue_backoff(entry, now);
        entry.lease_owner = Some(worker_id.to_string());
        entry.lease_expires_unix_secs = lease_expires_unix_secs;
        let claimed = entry.clone();
        sort_artifact_repro_queue_entries(&mut queue.entries, now);
        write_artifact_repro_queue(workdir, queue)?;
        return Ok(Some(claimed));
    }

    if let Some(entry) = queue.entries.iter_mut().find(|entry| {
        !repro_queue_entry_has_active_lease(entry, now)
            && !repro_queue_entry_is_in_backoff(entry, now)
    }) {
        entry.next_attempt_not_before_unix_secs = None;
        entry.lease_owner = Some(worker_id.to_string());
        entry.lease_expires_unix_secs = lease_expires_unix_secs;
        let claimed = entry.clone();
        sort_artifact_repro_queue_entries(&mut queue.entries, now);
        write_artifact_repro_queue(workdir, queue)?;
        return Ok(Some(claimed));
    }

    Ok(None)
}

pub fn release_repro_queue_claim(
    workdir: &str,
    artifact_type: &str,
    signature: &str,
    worker_id: &str,
) -> std::io::Result<bool> {
    release_repro_queue_claim_at(
        std::path::Path::new(workdir),
        artifact_type,
        signature,
        worker_id,
        current_unix_secs(),
    )
}

fn release_repro_queue_claim_at(
    workdir: &std::path::Path,
    artifact_type: &str,
    signature: &str,
    worker_id: &str,
    now: u64,
) -> std::io::Result<bool> {
    let mut queue = load_artifact_repro_queue(workdir)?;
    let Some(entry) = queue
        .entries
        .iter_mut()
        .find(|entry| entry.artifact_type == artifact_type && entry.signature == signature)
    else {
        return Ok(false);
    };
    if entry.lease_owner.as_deref() != Some(worker_id) {
        return Ok(false);
    }
    entry.lease_owner = None;
    entry.lease_expires_unix_secs = None;
    sort_artifact_repro_queue_entries(&mut queue.entries, now);
    write_artifact_repro_queue(workdir, queue)?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::{
        artifact_signature, claim_repro_queue_entry_at, detect_crash, normalize_summary,
        record_repro_queue_attempt, record_repro_queue_attempt_at, relative_artifact_path,
        release_repro_queue_claim, save_crash, save_timeout, sync_artifact_catalog,
        ArtifactCatalog, ArtifactMetadata, ArtifactReproInfo, ArtifactReproQueue,
    };
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_temp_dir(name: &str) -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "syzkaller-rust-{}-{}-{}",
            name,
            std::process::id(),
            nanos
        ))
    }

    fn read_artifact_catalog(workdir: &std::path::Path) -> ArtifactCatalog {
        let catalog = std::fs::read_to_string(workdir.join("artifacts.json"))
            .expect("artifact catalog should exist");
        serde_json::from_str(&catalog).expect("artifact catalog should deserialize")
    }

    fn read_repro_queue(workdir: &std::path::Path) -> ArtifactReproQueue {
        let queue = std::fs::read_to_string(workdir.join("repro_queue.json"))
            .expect("repro queue should exist");
        serde_json::from_str(&queue).expect("repro queue should deserialize")
    }

    fn test_repro_info(
        artifact_type: &str,
        summary: &str,
        signature: &str,
        program: &str,
        shape: Option<&str>,
        profile: Option<&str>,
    ) -> ArtifactReproInfo {
        ArtifactReproInfo {
            artifact_type: artifact_type.to_string(),
            summary: summary.to_string(),
            signature: signature.to_string(),
            manager_instance: 0,
            total_execs: 7,
            syscall_descriptions: Some("/tmp/socket-subset.txt".to_string()),
            executor: "/tmp/syz-executor".to_string(),
            sandbox: "none".to_string(),
            procs: 1,
            cover: true,
            syscall_timeout_ms: 500,
            program_timeout_ms: 5000,
            slowdown: 1,
            vm_count: 1,
            vm_cpu: 2,
            vm_mem: 2048,
            vm_qemu: "qemu-system-x86_64".to_string(),
            vm_kernel: "/tmp/bzImage".to_string(),
            vm_image: "/tmp/bullseye.img".to_string(),
            vm_cmdline: "console=ttyS0".to_string(),
            program: program.to_string(),
            shape: shape.map(str::to_string),
            profile: profile.map(str::to_string),
        }
    }

    #[test]
    fn save_timeout_writes_reason_and_program_files() {
        let workdir = unique_temp_dir("timeout-save");
        std::fs::create_dir_all(&workdir).expect("temp workdir should be creatable");
        let program = "0. socket$inet(0x2, 0x1, 0x0)\n";
        let signature = artifact_signature(&[
            "timeout",
            &normalize_summary("executor_reported_hang"),
            "socket$inet",
            "socket$inet->connect$inet",
            "",
        ]);

        save_timeout(
            workdir.to_str().expect("temp path should be utf-8"),
            "executor_reported_hang",
            program,
            "socket$inet",
            "socket$inet->connect$inet",
            Some(&test_repro_info(
                "timeout",
                "executor_reported_hang",
                &signature,
                program,
                Some("socket$inet"),
                Some("socket$inet->connect$inet"),
            )),
        )
        .expect("timeout artifact should save");

        let timeouts_dir = workdir.join("timeouts");
        let entries = std::fs::read_dir(&timeouts_dir)
            .expect("timeouts dir should exist")
            .collect::<Result<Vec<_>, _>>()
            .expect("timeouts dir should be readable");
        assert_eq!(entries.len(), 1);
        let timeout_subdir = entries[0].path();
        let reason = std::fs::read_to_string(timeout_subdir.join("reason"))
            .expect("reason file should exist");
        let first_reason = std::fs::read_to_string(timeout_subdir.join("first_reason"))
            .expect("first reason file should exist");
        let program = std::fs::read_to_string(timeout_subdir.join("program"))
            .expect("program file should exist");
        let first_program = std::fs::read_to_string(timeout_subdir.join("first_program"))
            .expect("first program file should exist");
        let shape =
            std::fs::read_to_string(timeout_subdir.join("shape")).expect("shape file should exist");
        let profile = std::fs::read_to_string(timeout_subdir.join("profile"))
            .expect("profile file should exist");
        let metadata = std::fs::read_to_string(timeout_subdir.join("metadata.json"))
            .expect("metadata file should exist");
        let metadata: ArtifactMetadata =
            serde_json::from_str(&metadata).expect("metadata should deserialize");
        let repro = std::fs::read_to_string(timeout_subdir.join("repro.json"))
            .expect("repro file should exist");
        let repro: ArtifactReproInfo =
            serde_json::from_str(&repro).expect("repro should deserialize");
        assert_eq!(reason, "executor_reported_hang");
        assert_eq!(first_reason, "executor_reported_hang");
        assert!(program.contains("socket$inet"));
        assert_eq!(first_program, program);
        assert_eq!(shape, "socket$inet");
        assert_eq!(profile, "socket$inet->connect$inet");
        assert_eq!(metadata.artifact_type, "timeout");
        assert_eq!(metadata.summary, "executor_reported_hang");
        assert_eq!(metadata.normalized_summary, "executor_reported_hang");
        assert_eq!(metadata.occurrences, 1);
        assert_eq!(metadata.shape.as_deref(), Some("socket$inet"));
        assert_eq!(
            metadata.profile.as_deref(),
            Some("socket$inet->connect$inet")
        );
        assert_eq!(repro.signature, signature);
        assert_eq!(repro.program, program);
        assert_eq!(repro.vm_image, "/tmp/bullseye.img");
        let catalog = read_artifact_catalog(&workdir);
        assert_eq!(catalog.version, 2);
        assert_eq!(catalog.entries.len(), 1);
        assert_eq!(catalog.entries[0].artifact_type, "timeout");
        assert_eq!(
            catalog.entries[0].directory,
            relative_artifact_path(&workdir, &timeout_subdir)
        );
        assert_eq!(
            catalog.entries[0].summary_path,
            relative_artifact_path(&workdir, &timeout_subdir.join("reason"))
        );
        assert_eq!(
            catalog.entries[0].program_path,
            relative_artifact_path(&workdir, &timeout_subdir.join("program"))
        );
        assert_eq!(
            catalog.entries[0].preferred_summary_path,
            relative_artifact_path(&workdir, &timeout_subdir.join("first_reason"))
        );
        assert_eq!(
            catalog.entries[0].preferred_program_path,
            relative_artifact_path(&workdir, &timeout_subdir.join("first_program"))
        );
        assert_eq!(
            catalog.entries[0].shape_path.as_deref(),
            Some(relative_artifact_path(&workdir, &timeout_subdir.join("shape")).as_str())
        );
        assert_eq!(
            catalog.entries[0].profile_path.as_deref(),
            Some(relative_artifact_path(&workdir, &timeout_subdir.join("profile")).as_str())
        );
        assert_eq!(
            catalog.entries[0].repro_path.as_deref(),
            Some(relative_artifact_path(&workdir, &timeout_subdir.join("repro.json")).as_str())
        );
        assert_eq!(
            catalog.entries[0].first_summary_path.as_deref(),
            Some(relative_artifact_path(&workdir, &timeout_subdir.join("first_reason")).as_str())
        );
        assert_eq!(
            catalog.entries[0].first_program_path.as_deref(),
            Some(relative_artifact_path(&workdir, &timeout_subdir.join("first_program")).as_str())
        );
        assert_eq!(
            catalog.entries[0].preferred_repro_path.as_deref(),
            Some(
                relative_artifact_path(&workdir, &timeout_subdir.join("first_repro.json")).as_str()
            )
        );
        let queue = read_repro_queue(&workdir);
        assert_eq!(queue.version, 4);
        assert_eq!(queue.entries.len(), 1);
        assert_eq!(queue.entries[0].artifact_type, "timeout");
        assert_eq!(queue.entries[0].attempts, 0);
        assert_eq!(queue.entries[0].last_attempt_unix_secs, None);
        assert_eq!(queue.entries[0].last_attempt_outcome, None);
        assert_eq!(queue.entries[0].next_attempt_not_before_unix_secs, None);
        assert_eq!(queue.entries[0].lease_owner, None);
        assert_eq!(queue.entries[0].lease_expires_unix_secs, None);
        assert_eq!(
            queue.entries[0].preferred_program_path,
            catalog.entries[0].preferred_program_path
        );
        assert_eq!(
            queue.entries[0].preferred_repro_path.as_deref(),
            catalog.entries[0].preferred_repro_path.as_deref()
        );

        let _ = std::fs::remove_dir_all(&workdir);
    }

    #[test]
    fn record_repro_queue_attempt_updates_state() {
        let workdir = unique_temp_dir("repro-queue-attempt");
        std::fs::create_dir_all(&workdir).expect("temp workdir should be creatable");

        save_timeout(
            workdir.to_str().expect("temp path should be utf-8"),
            "executor_reported_hang",
            "0. socket$inet(0x2, 0x1, 0x0)\n",
            "socket$inet",
            "socket$inet->connect$inet",
            None,
        )
        .expect("timeout artifact should save");

        let before = read_repro_queue(&workdir);
        let signature = before.entries[0].signature.clone();
        assert!(claim_repro_queue_entry_at(&workdir, "worker-a", 30, 100)
            .expect("claim should succeed")
            .is_some());
        assert!(record_repro_queue_attempt(
            workdir.to_str().expect("temp path should be utf-8"),
            "timeout",
            &signature,
            "failed",
        )
        .expect("attempt recording should succeed"));

        let after = read_repro_queue(&workdir);
        assert_eq!(after.entries.len(), 1);
        assert_eq!(after.entries[0].attempts, 1);
        assert_eq!(
            after.entries[0].last_attempt_outcome.as_deref(),
            Some("failed")
        );
        assert!(after.entries[0].last_attempt_unix_secs.is_some());
        assert!(after.entries[0].next_attempt_not_before_unix_secs.is_some());
        assert_eq!(after.entries[0].lease_owner, None);
        assert_eq!(after.entries[0].lease_expires_unix_secs, None);

        let _ = std::fs::remove_dir_all(&workdir);
    }

    #[test]
    fn record_repro_queue_attempt_sets_and_clears_backoff_by_outcome() {
        let workdir = unique_temp_dir("repro-queue-backoff");
        std::fs::create_dir_all(&workdir).expect("temp workdir should be creatable");

        save_timeout(
            workdir.to_str().expect("temp path should be utf-8"),
            "executor_reported_hang",
            "0. socket$inet(0x2, 0x1, 0x0)\n",
            "socket$inet",
            "socket$inet->connect$inet",
            None,
        )
        .expect("timeout artifact should save");

        let signature = read_repro_queue(&workdir).entries[0].signature.clone();
        assert!(
            record_repro_queue_attempt_at(&workdir, "timeout", &signature, "FAILED", 100)
                .expect("failed attempt should record")
        );
        let failed = read_repro_queue(&workdir);
        assert_eq!(
            failed.entries[0].last_attempt_outcome.as_deref(),
            Some("failed")
        );
        assert_eq!(
            failed.entries[0].next_attempt_not_before_unix_secs,
            Some(160)
        );

        assert!(
            record_repro_queue_attempt_at(&workdir, "timeout", &signature, "reproduced", 170)
                .expect("successful attempt should record")
        );
        let succeeded = read_repro_queue(&workdir);
        assert_eq!(succeeded.entries[0].next_attempt_not_before_unix_secs, None);
        assert_eq!(
            succeeded.entries[0].last_attempt_outcome.as_deref(),
            Some("succeeded")
        );

        let _ = std::fs::remove_dir_all(&workdir);
    }

    #[test]
    fn record_repro_queue_attempt_canonicalizes_timeout_aliases() {
        let workdir = unique_temp_dir("repro-queue-outcome-canonical");
        std::fs::create_dir_all(&workdir).expect("temp workdir should be creatable");

        save_timeout(
            workdir.to_str().expect("temp path should be utf-8"),
            "executor_reported_hang",
            "0. socket$inet(0x2, 0x1, 0x0)\n",
            "socket$inet",
            "socket$inet->connect$inet",
            None,
        )
        .expect("timeout artifact should save");

        let signature = read_repro_queue(&workdir).entries[0].signature.clone();
        assert!(
            record_repro_queue_attempt_at(&workdir, "timeout", &signature, "HANGED", 100)
                .expect("timeout alias should record")
        );
        let queue = read_repro_queue(&workdir);
        assert_eq!(
            queue.entries[0].last_attempt_outcome.as_deref(),
            Some("timed_out")
        );
        assert_eq!(
            queue.entries[0].next_attempt_not_before_unix_secs,
            Some(400)
        );

        let _ = std::fs::remove_dir_all(&workdir);
    }

    #[test]
    fn claim_repro_queue_entry_assigns_and_renews_lease() {
        let workdir = unique_temp_dir("repro-queue-claim");
        std::fs::create_dir_all(&workdir).expect("temp workdir should be creatable");

        save_timeout(
            workdir.to_str().expect("temp path should be utf-8"),
            "executor_reported_hang",
            "0. socket$inet(0x2, 0x1, 0x0)\n",
            "socket$inet",
            "socket$inet->connect$inet",
            None,
        )
        .expect("timeout artifact should save");

        let claimed = claim_repro_queue_entry_at(&workdir, "worker-a", 30, 100)
            .expect("claim should succeed")
            .expect("queue entry should be claimable");
        assert_eq!(claimed.lease_owner.as_deref(), Some("worker-a"));
        assert_eq!(claimed.lease_expires_unix_secs, Some(130));

        let renewed = claim_repro_queue_entry_at(&workdir, "worker-a", 45, 110)
            .expect("lease renewal should succeed")
            .expect("existing lease should be returned");
        assert_eq!(renewed.signature, claimed.signature);
        assert_eq!(renewed.lease_owner.as_deref(), Some("worker-a"));
        assert_eq!(renewed.lease_expires_unix_secs, Some(155));

        let queue = read_repro_queue(&workdir);
        assert_eq!(queue.entries.len(), 1);
        assert_eq!(queue.entries[0].lease_owner.as_deref(), Some("worker-a"));
        assert_eq!(queue.entries[0].lease_expires_unix_secs, Some(155));

        let _ = std::fs::remove_dir_all(&workdir);
    }

    #[test]
    fn claim_repro_queue_entry_skips_backed_off_entry_for_next_available_one() {
        let workdir = unique_temp_dir("repro-queue-claim-backoff");
        std::fs::create_dir_all(&workdir).expect("temp workdir should be creatable");

        save_timeout(
            workdir.to_str().expect("temp path should be utf-8"),
            "manager_request_timeout",
            "0. socket$inet(0x2, 0x1, 0x0)\n",
            "socket$inet",
            "socket$inet->connect$inet",
            None,
        )
        .expect("timeout artifact should save");
        save_crash(
            workdir.to_str().expect("temp path should be utf-8"),
            "BUG: unable to handle kernel NULL pointer dereference at ffff888012345678",
            b"BUG: unable to handle kernel NULL pointer dereference\nCall Trace:\n",
            "0. socket$inet(0x2, 0x2, 0x0)\n1. connect$inet(...)",
            Some("socket$inet -> connect$inet"),
            Some("socket$inet->connect$inet"),
            None,
        )
        .expect("crash artifact should save");

        let crash_signature = read_repro_queue(&workdir)
            .entries
            .iter()
            .find(|entry| entry.artifact_type == "crash")
            .expect("crash queue entry should exist")
            .signature
            .clone();
        assert!(
            record_repro_queue_attempt_at(&workdir, "crash", &crash_signature, "failed", 100)
                .expect("backoff should record")
        );

        let claimed = claim_repro_queue_entry_at(&workdir, "worker-a", 30, 120)
            .expect("claim should succeed")
            .expect("next available item should be claimable");
        assert_eq!(claimed.artifact_type, "timeout");

        let _ = std::fs::remove_dir_all(&workdir);
    }

    #[test]
    fn claim_repro_queue_entry_uses_next_available_when_top_entry_is_leased() {
        let workdir = unique_temp_dir("repro-queue-claim-next");
        std::fs::create_dir_all(&workdir).expect("temp workdir should be creatable");

        save_timeout(
            workdir.to_str().expect("temp path should be utf-8"),
            "manager_request_timeout",
            "0. socket$inet(0x2, 0x1, 0x0)\n",
            "socket$inet",
            "socket$inet->connect$inet",
            None,
        )
        .expect("timeout artifact should save");
        save_crash(
            workdir.to_str().expect("temp path should be utf-8"),
            "BUG: unable to handle kernel NULL pointer dereference at ffff888012345678",
            b"BUG: unable to handle kernel NULL pointer dereference\nCall Trace:\n",
            "0. socket$inet(0x2, 0x2, 0x0)\n1. connect$inet(...)",
            Some("socket$inet -> connect$inet"),
            Some("socket$inet->connect$inet"),
            None,
        )
        .expect("crash artifact should save");

        let first = claim_repro_queue_entry_at(&workdir, "worker-a", 30, 100)
            .expect("first claim should succeed")
            .expect("top entry should be claimable");
        assert_eq!(first.artifact_type, "crash");

        let second = claim_repro_queue_entry_at(&workdir, "worker-b", 30, 101)
            .expect("second claim should succeed")
            .expect("next entry should be claimable");
        assert_eq!(second.artifact_type, "timeout");

        let _ = std::fs::remove_dir_all(&workdir);
    }

    #[test]
    fn sync_artifact_catalog_reorders_entries_by_outcome_class_after_backoff_expires() {
        let workdir = unique_temp_dir("repro-queue-outcome-order");
        std::fs::create_dir_all(&workdir).expect("temp workdir should be creatable");

        save_timeout(
            workdir.to_str().expect("temp path should be utf-8"),
            "timeout-a",
            "0. socket$inet(0x2, 0x1, 0x0)\n",
            "socket$inet",
            "socket$inet->connect$inet",
            None,
        )
        .expect("first timeout artifact should save");
        save_timeout(
            workdir.to_str().expect("temp path should be utf-8"),
            "timeout-b",
            "0. socket$inet(0x2, 0x1, 0x0)\n1. close(...)\n",
            "socket$inet",
            "socket$inet->connect$inet",
            None,
        )
        .expect("second timeout artifact should save");
        save_timeout(
            workdir.to_str().expect("temp path should be utf-8"),
            "timeout-c",
            "0. socket$inet(0x2, 0x1, 0x0)\n2. listen(...)\n",
            "socket$inet",
            "socket$inet->connect$inet",
            None,
        )
        .expect("third timeout artifact should save");

        let queue = read_repro_queue(&workdir);
        let sig_a = queue
            .entries
            .iter()
            .find(|entry| entry.summary == "timeout-a")
            .expect("timeout-a should exist")
            .signature
            .clone();
        let sig_b = queue
            .entries
            .iter()
            .find(|entry| entry.summary == "timeout-b")
            .expect("timeout-b should exist")
            .signature
            .clone();
        let sig_c = queue
            .entries
            .iter()
            .find(|entry| entry.summary == "timeout-c")
            .expect("timeout-c should exist")
            .signature
            .clone();
        assert!(
            record_repro_queue_attempt_at(&workdir, "timeout", &sig_a, "failed", 100)
                .expect("failed outcome should record")
        );
        assert!(
            record_repro_queue_attempt_at(&workdir, "timeout", &sig_b, "HANGED", 100)
                .expect("timed-out outcome should record")
        );
        assert!(
            record_repro_queue_attempt_at(&workdir, "timeout", &sig_c, "reproduced", 100)
                .expect("successful outcome should record")
        );

        sync_artifact_catalog(workdir.to_str().expect("temp path should be utf-8"))
            .expect("catalog rebuild should succeed");

        let rebuilt = read_repro_queue(&workdir);
        let timeout_entries = rebuilt
            .entries
            .iter()
            .filter(|entry| entry.artifact_type == "timeout")
            .map(|entry| entry.summary.as_str())
            .collect::<Vec<_>>();
        let failed_idx = timeout_entries
            .iter()
            .position(|summary| *summary == "timeout-a")
            .expect("failed timeout should remain in queue");
        let timed_out_idx = timeout_entries
            .iter()
            .position(|summary| *summary == "timeout-b")
            .expect("timed-out timeout should remain in queue");
        let succeeded_idx = timeout_entries
            .iter()
            .position(|summary| *summary == "timeout-c")
            .expect("successful timeout should remain in queue");
        assert!(failed_idx < timed_out_idx);
        assert!(timed_out_idx < succeeded_idx);

        let _ = std::fs::remove_dir_all(&workdir);
    }

    #[test]
    fn claim_repro_queue_entry_skips_active_lease_until_expiry() {
        let workdir = unique_temp_dir("repro-queue-claim-expiry");
        std::fs::create_dir_all(&workdir).expect("temp workdir should be creatable");

        save_timeout(
            workdir.to_str().expect("temp path should be utf-8"),
            "executor_reported_hang",
            "0. socket$inet(0x2, 0x1, 0x0)\n",
            "socket$inet",
            "socket$inet->connect$inet",
            None,
        )
        .expect("timeout artifact should save");

        assert!(claim_repro_queue_entry_at(&workdir, "worker-a", 30, 100)
            .expect("claim should succeed")
            .is_some());
        assert!(claim_repro_queue_entry_at(&workdir, "worker-b", 30, 120)
            .expect("active lease should be honored")
            .is_none());

        let reclaimed = claim_repro_queue_entry_at(&workdir, "worker-b", 30, 131)
            .expect("expired lease should be claimable")
            .expect("expired lease should be reassigned");
        assert_eq!(reclaimed.lease_owner.as_deref(), Some("worker-b"));
        assert_eq!(reclaimed.lease_expires_unix_secs, Some(161));

        let _ = std::fs::remove_dir_all(&workdir);
    }

    #[test]
    fn release_repro_queue_claim_clears_matching_lease() {
        let workdir = unique_temp_dir("repro-queue-release");
        std::fs::create_dir_all(&workdir).expect("temp workdir should be creatable");

        save_timeout(
            workdir.to_str().expect("temp path should be utf-8"),
            "executor_reported_hang",
            "0. socket$inet(0x2, 0x1, 0x0)\n",
            "socket$inet",
            "socket$inet->connect$inet",
            None,
        )
        .expect("timeout artifact should save");

        let claimed = claim_repro_queue_entry_at(&workdir, "worker-a", 30, 100)
            .expect("claim should succeed")
            .expect("queue entry should be claimable");
        assert!(!release_repro_queue_claim(
            workdir.to_str().expect("temp path should be utf-8"),
            &claimed.artifact_type,
            &claimed.signature,
            "worker-b",
        )
        .expect("mismatched release should succeed"));
        assert!(release_repro_queue_claim(
            workdir.to_str().expect("temp path should be utf-8"),
            &claimed.artifact_type,
            &claimed.signature,
            "worker-a",
        )
        .expect("matching release should succeed"));

        let queue = read_repro_queue(&workdir);
        assert_eq!(queue.entries[0].lease_owner, None);
        assert_eq!(queue.entries[0].lease_expires_unix_secs, None);

        let _ = std::fs::remove_dir_all(&workdir);
    }

    #[test]
    fn save_timeout_deduplicates_repeated_artifacts() {
        let workdir = unique_temp_dir("timeout-dedupe");
        std::fs::create_dir_all(&workdir).expect("temp workdir should be creatable");

        save_timeout(
            workdir.to_str().expect("temp path should be utf-8"),
            "manager_request_timeout",
            "0. socket$inet(0x2, 0x1, 0x0)\n",
            "socket$inet",
            "socket$inet->connect$inet",
            None,
        )
        .expect("timeout artifact should save");
        save_timeout(
            workdir.to_str().expect("temp path should be utf-8"),
            "manager_request_timeout",
            "0. socket$inet(0x2, 0x2, 0x0)\n1. connect$inet(...)\n",
            "socket$inet",
            "socket$inet->connect$inet",
            None,
        )
        .expect("timeout artifact should save");

        let timeouts_dir = workdir.join("timeouts");
        let entries = std::fs::read_dir(&timeouts_dir)
            .expect("timeouts dir should exist")
            .collect::<Result<Vec<_>, _>>()
            .expect("timeouts dir should be readable");
        assert_eq!(entries.len(), 1);
        let metadata = std::fs::read_to_string(entries[0].path().join("metadata.json"))
            .expect("metadata file should exist");
        let metadata: ArtifactMetadata =
            serde_json::from_str(&metadata).expect("metadata should deserialize");
        let latest_program = std::fs::read_to_string(entries[0].path().join("program"))
            .expect("latest program should exist");
        let first_program = std::fs::read_to_string(entries[0].path().join("first_program"))
            .expect("first program should exist");
        assert_eq!(metadata.occurrences, 2);
        assert_eq!(metadata.normalized_summary, "manager_request_timeout");
        assert_eq!(first_program, "0. socket$inet(0x2, 0x1, 0x0)\n");
        assert_eq!(
            latest_program,
            "0. socket$inet(0x2, 0x2, 0x0)\n1. connect$inet(...)\n"
        );
        let catalog = read_artifact_catalog(&workdir);
        assert_eq!(catalog.entries.len(), 1);
        assert_eq!(catalog.entries[0].occurrences, 2);
        assert_eq!(catalog.entries[0].artifact_type, "timeout");
        assert_eq!(
            catalog.entries[0].preferred_program_path,
            relative_artifact_path(&workdir, &entries[0].path().join("first_program"))
        );
        assert_eq!(
            catalog.entries[0].program_path,
            relative_artifact_path(&workdir, &entries[0].path().join("program"))
        );

        let _ = std::fs::remove_dir_all(&workdir);
    }

    #[test]
    fn save_crash_deduplicates_and_records_optional_context() {
        let workdir = unique_temp_dir("crash-save");
        std::fs::create_dir_all(&workdir).expect("temp workdir should be creatable");

        save_crash(
            workdir.to_str().expect("temp path should be utf-8"),
            "BUG: unable to handle kernel NULL pointer dereference at ffff888012345678",
            b"BUG: unable to handle kernel NULL pointer dereference\nCall Trace:\n",
            "0. socket$inet(0x2, 0x1, 0x0)\n1. connect$inet(...)",
            Some("socket$inet -> connect$inet"),
            Some("socket$inet->connect$inet"),
            None,
        )
        .expect("crash artifact should save");
        save_crash(
            workdir.to_str().expect("temp path should be utf-8"),
            "BUG: unable to handle kernel NULL pointer dereference at ffff8880deadbeef",
            b"BUG: unable to handle kernel NULL pointer dereference\nCall Trace:\n",
            "0. socket$inet(0x2, 0x2, 0x0)\n1. connect$inet(...)",
            Some("socket$inet -> connect$inet"),
            Some("socket$inet->connect$inet"),
            None,
        )
        .expect("crash artifact should save");

        let crashes_dir = workdir.join("crashes");
        let entries = std::fs::read_dir(&crashes_dir)
            .expect("crashes dir should exist")
            .collect::<Result<Vec<_>, _>>()
            .expect("crashes dir should be readable");
        assert_eq!(entries.len(), 1);
        let crash_subdir = entries[0].path();
        let shape =
            std::fs::read_to_string(crash_subdir.join("shape")).expect("shape file should exist");
        let profile = std::fs::read_to_string(crash_subdir.join("profile"))
            .expect("profile file should exist");
        let latest_description = std::fs::read_to_string(crash_subdir.join("description"))
            .expect("description file should exist");
        let first_description = std::fs::read_to_string(crash_subdir.join("first_description"))
            .expect("first description file should exist");
        let latest_program = std::fs::read_to_string(crash_subdir.join("program"))
            .expect("program file should exist");
        let first_program = std::fs::read_to_string(crash_subdir.join("first_program"))
            .expect("first program file should exist");
        let metadata = std::fs::read_to_string(crash_subdir.join("metadata.json"))
            .expect("metadata file should exist");
        let metadata: ArtifactMetadata =
            serde_json::from_str(&metadata).expect("metadata should deserialize");
        assert_eq!(shape, "socket$inet -> connect$inet");
        assert_eq!(profile, "socket$inet->connect$inet");
        assert_eq!(
            latest_description,
            "BUG: unable to handle kernel NULL pointer dereference at ffff8880deadbeef"
        );
        assert_eq!(
            first_description,
            "BUG: unable to handle kernel NULL pointer dereference at ffff888012345678"
        );
        assert_eq!(
            first_program,
            "0. socket$inet(0x2, 0x1, 0x0)\n1. connect$inet(...)"
        );
        assert_eq!(
            latest_program,
            "0. socket$inet(0x2, 0x2, 0x0)\n1. connect$inet(...)"
        );
        assert_eq!(metadata.artifact_type, "crash");
        assert_eq!(metadata.occurrences, 2);
        assert_eq!(
            metadata.normalized_summary,
            "bug: unable to handle kernel null pointer dereference at <hex>"
        );
        assert_eq!(
            metadata.signature,
            artifact_signature(&[
                "crash",
                "bug: unable to handle kernel null pointer dereference at <hex>",
                "socket$inet -> connect$inet",
                "socket$inet->connect$inet",
                "",
            ])
        );
        let catalog = read_artifact_catalog(&workdir);
        assert_eq!(catalog.entries.len(), 1);
        assert_eq!(catalog.entries[0].artifact_type, "crash");
        assert_eq!(catalog.entries[0].occurrences, 2);
        assert_eq!(
            catalog.entries[0].preferred_summary_path,
            relative_artifact_path(&workdir, &crash_subdir.join("first_description"))
        );
        assert_eq!(
            catalog.entries[0].preferred_program_path,
            relative_artifact_path(&workdir, &crash_subdir.join("first_program"))
        );
        assert_eq!(
            catalog.entries[0].log_path.as_deref(),
            Some(relative_artifact_path(&workdir, &crash_subdir.join("log")).as_str())
        );
        assert_eq!(
            catalog.entries[0].summary_path,
            relative_artifact_path(&workdir, &crash_subdir.join("description"))
        );
        assert_eq!(
            catalog.entries[0].first_log_path.as_deref(),
            Some(relative_artifact_path(&workdir, &crash_subdir.join("first_log")).as_str())
        );

        let _ = std::fs::remove_dir_all(&workdir);
    }

    #[test]
    fn artifact_catalog_keeps_crashes_and_timeouts_together() {
        let workdir = unique_temp_dir("artifact-catalog");
        std::fs::create_dir_all(&workdir).expect("temp workdir should be creatable");

        save_timeout(
            workdir.to_str().expect("temp path should be utf-8"),
            "manager_request_timeout",
            "0. socket$inet(0x2, 0x2, 0x0)\n1. connect$inet(...)\n",
            "socket$inet",
            "socket$inet->connect$inet",
            None,
        )
        .expect("timeout artifact should save");
        save_crash(
            workdir.to_str().expect("temp path should be utf-8"),
            "BUG: unable to handle kernel NULL pointer dereference at ffff888012345678",
            b"BUG: unable to handle kernel NULL pointer dereference\nCall Trace:\n",
            "0. socket$inet(0x2, 0x1, 0x0)\n1. connect$inet(...)",
            Some("socket$inet -> connect$inet"),
            Some("socket$inet->connect$inet"),
            None,
        )
        .expect("crash artifact should save");

        let catalog = read_artifact_catalog(&workdir);
        assert_eq!(catalog.entries.len(), 2);
        assert!(catalog
            .entries
            .iter()
            .any(|entry| entry.artifact_type == "timeout"
                && entry.directory.starts_with("timeouts/")));
        assert!(
            catalog
                .entries
                .iter()
                .any(|entry| entry.artifact_type == "crash"
                    && entry.directory.starts_with("crashes/"))
        );
        let queue = read_repro_queue(&workdir);
        assert_eq!(queue.entries.len(), 2);
        assert_eq!(queue.entries[0].artifact_type, "crash");
        assert_eq!(queue.entries[1].artifact_type, "timeout");
        assert!(queue.entries[0].priority > queue.entries[1].priority);

        let _ = std::fs::remove_dir_all(&workdir);
    }

    #[test]
    fn sync_artifact_catalog_rebuilds_entries_from_existing_artifacts() {
        let workdir = unique_temp_dir("artifact-catalog-sync");
        std::fs::create_dir_all(&workdir).expect("temp workdir should be creatable");

        save_timeout(
            workdir.to_str().expect("temp path should be utf-8"),
            "manager_request_timeout",
            "0. socket$inet(0x2, 0x2, 0x0)\n1. connect$inet(...)\n",
            "socket$inet",
            "socket$inet->connect$inet",
            None,
        )
        .expect("timeout artifact should save");
        save_timeout(
            workdir.to_str().expect("temp path should be utf-8"),
            "manager_request_timeout",
            "0. socket$inet(0x2, 0x2, 0x0)\n1. connect$inet(...)\n2. close(...)\n",
            "socket$inet",
            "socket$inet->connect$inet",
            None,
        )
        .expect("timeout artifact should save");
        save_crash(
            workdir.to_str().expect("temp path should be utf-8"),
            "BUG: unable to handle kernel NULL pointer dereference at ffff888012345678",
            b"BUG: unable to handle kernel NULL pointer dereference\nCall Trace:\n",
            "0. socket$inet(0x2, 0x1, 0x0)\n1. connect$inet(...)",
            Some("socket$inet -> connect$inet"),
            Some("socket$inet->connect$inet"),
            None,
        )
        .expect("crash artifact should save");

        std::fs::remove_file(workdir.join("artifacts.json"))
            .expect("artifact catalog should be removable for rebuild");

        let report = sync_artifact_catalog(workdir.to_str().expect("temp path should be utf-8"))
            .expect("artifact catalog rebuild should succeed");
        assert_eq!(report.total_entries, 2);
        assert_eq!(report.crash_entries, 1);
        assert_eq!(report.timeout_entries, 1);
        assert_eq!(report.skipped_entries, 0);

        let catalog = read_artifact_catalog(&workdir);
        assert_eq!(catalog.entries.len(), 2);
        let queue = read_repro_queue(&workdir);
        assert_eq!(queue.entries.len(), 2);
        let timeout_entry = catalog
            .entries
            .iter()
            .find(|entry| entry.artifact_type == "timeout")
            .expect("timeout entry should exist");
        assert_eq!(timeout_entry.occurrences, 2);
        assert_eq!(
            timeout_entry.preferred_program_path,
            timeout_entry
                .first_program_path
                .clone()
                .expect("rebuilt timeout entry should preserve first-program path")
        );
        let crash_entry = catalog
            .entries
            .iter()
            .find(|entry| entry.artifact_type == "crash")
            .expect("crash entry should exist");
        assert_eq!(
            crash_entry.preferred_summary_path,
            crash_entry
                .first_summary_path
                .clone()
                .expect("rebuilt crash entry should preserve first-summary path")
        );
        assert_eq!(
            queue
                .entries
                .iter()
                .find(|entry| entry.artifact_type == "timeout")
                .expect("rebuilt timeout queue entry should exist")
                .preferred_program_path,
            timeout_entry.preferred_program_path
        );

        let _ = std::fs::remove_dir_all(&workdir);
    }

    #[test]
    fn sync_artifact_catalog_preserves_repro_queue_attempt_state() {
        let workdir = unique_temp_dir("repro-queue-preserve");
        std::fs::create_dir_all(&workdir).expect("temp workdir should be creatable");

        save_timeout(
            workdir.to_str().expect("temp path should be utf-8"),
            "manager_request_timeout",
            "0. socket$inet(0x2, 0x1, 0x0)\n",
            "socket$inet",
            "socket$inet->connect$inet",
            None,
        )
        .expect("timeout artifact should save");

        let initial_queue = read_repro_queue(&workdir);
        let signature = initial_queue.entries[0].signature.clone();
        record_repro_queue_attempt(
            workdir.to_str().expect("temp path should be utf-8"),
            "timeout",
            &signature,
            "failed",
        )
        .expect("attempt recording should succeed");

        sync_artifact_catalog(workdir.to_str().expect("temp path should be utf-8"))
            .expect("catalog rebuild should succeed");

        let rebuilt_queue = read_repro_queue(&workdir);
        assert_eq!(rebuilt_queue.entries.len(), 1);
        assert_eq!(rebuilt_queue.entries[0].attempts, 1);
        assert_eq!(
            rebuilt_queue.entries[0].last_attempt_outcome.as_deref(),
            Some("failed")
        );
        assert!(rebuilt_queue.entries[0].last_attempt_unix_secs.is_some());
        assert!(rebuilt_queue.entries[0]
            .next_attempt_not_before_unix_secs
            .is_some());

        let _ = std::fs::remove_dir_all(&workdir);
    }

    #[test]
    fn sync_artifact_catalog_preserves_active_repro_queue_backoff_state() {
        let workdir = unique_temp_dir("repro-queue-backoff-preserve");
        std::fs::create_dir_all(&workdir).expect("temp workdir should be creatable");
        let now = super::current_unix_secs();

        save_timeout(
            workdir.to_str().expect("temp path should be utf-8"),
            "manager_request_timeout",
            "0. socket$inet(0x2, 0x1, 0x0)\n",
            "socket$inet",
            "socket$inet->connect$inet",
            None,
        )
        .expect("timeout artifact should save");

        let signature = read_repro_queue(&workdir).entries[0].signature.clone();
        assert!(
            record_repro_queue_attempt_at(&workdir, "timeout", &signature, "failed", now)
                .expect("backoff should record")
        );

        sync_artifact_catalog(workdir.to_str().expect("temp path should be utf-8"))
            .expect("catalog rebuild should succeed");

        let rebuilt_queue = read_repro_queue(&workdir);
        assert_eq!(rebuilt_queue.entries.len(), 1);
        assert_eq!(
            rebuilt_queue.entries[0].next_attempt_not_before_unix_secs,
            Some(now + 60)
        );
        assert_eq!(
            rebuilt_queue.entries[0].last_attempt_outcome.as_deref(),
            Some("failed")
        );

        let _ = std::fs::remove_dir_all(&workdir);
    }

    #[test]
    fn sync_artifact_catalog_preserves_active_repro_queue_lease_state() {
        let workdir = unique_temp_dir("repro-queue-lease-preserve");
        std::fs::create_dir_all(&workdir).expect("temp workdir should be creatable");
        let now = super::current_unix_secs();

        save_timeout(
            workdir.to_str().expect("temp path should be utf-8"),
            "manager_request_timeout",
            "0. socket$inet(0x2, 0x1, 0x0)\n",
            "socket$inet",
            "socket$inet->connect$inet",
            None,
        )
        .expect("timeout artifact should save");

        let claimed = claim_repro_queue_entry_at(&workdir, "worker-a", 300, now)
            .expect("claim should succeed")
            .expect("queue entry should be claimable");
        assert_eq!(claimed.lease_owner.as_deref(), Some("worker-a"));
        assert_eq!(claimed.lease_expires_unix_secs, Some(now + 300));

        sync_artifact_catalog(workdir.to_str().expect("temp path should be utf-8"))
            .expect("catalog rebuild should succeed");

        let rebuilt_queue = read_repro_queue(&workdir);
        assert_eq!(rebuilt_queue.entries.len(), 1);
        assert_eq!(
            rebuilt_queue.entries[0].lease_owner.as_deref(),
            Some("worker-a")
        );
        assert_eq!(
            rebuilt_queue.entries[0].lease_expires_unix_secs,
            Some(now + 300)
        );

        let _ = std::fs::remove_dir_all(&workdir);
    }

    #[test]
    fn sync_artifact_catalog_skips_invalid_artifact_dirs() {
        let workdir = unique_temp_dir("artifact-catalog-invalid");
        std::fs::create_dir_all(workdir.join("crashes/bad"))
            .expect("bad crash directory should be creatable");
        std::fs::write(
            workdir.join("artifacts.json"),
            b"{\"version\":1,\"entries\":[{\"artifact_type\":\"crash\",\"signature\":\"stale\"}]}",
        )
        .expect("stale artifact catalog should be writable");

        let report = sync_artifact_catalog(workdir.to_str().expect("temp path should be utf-8"))
            .expect("artifact catalog rebuild should succeed");
        assert_eq!(report.total_entries, 0);
        assert_eq!(report.skipped_entries, 1);
        let catalog = read_artifact_catalog(&workdir);
        assert_eq!(catalog.entries.len(), 0);

        let _ = std::fs::remove_dir_all(&workdir);
    }

    #[test]
    fn artifact_signature_uses_stable_fnv1a64() {
        assert_eq!(
            artifact_signature(&["timeout", "executor_reported_hang", "socket$inet"]),
            "1facc14f0d64b326"
        );
    }

    #[test]
    fn normalize_summary_replaces_dynamic_hex_and_decimal_runs() {
        assert_eq!(
            normalize_summary(
                "BUG: unable to handle page fault at ffff888012345678 pid 1234 RIP: foo+0x12/0x40"
            ),
            "bug: unable to handle page fault at <hex> pid <num> rip: foo+0x<hex>/0x<hex>"
        );
    }

    #[test]
    fn detect_crash_strips_kernel_log_prefixes() {
        let log = b"<3>[  123.456789] BUG: unable to handle kernel NULL pointer dereference at ffff888012345678\n";
        assert_eq!(
            detect_crash(log),
            Some(
                "BUG: unable to handle kernel NULL pointer dereference at ffff888012345678"
                    .to_string()
            )
        );
    }

    #[test]
    fn detect_crash_prefers_stronger_summary_over_call_trace() {
        let log = b"Call Trace:\nBUG: soft lockup - CPU#0 stuck for 22s!\n";
        assert_eq!(
            detect_crash(log),
            Some("BUG: soft lockup - CPU#0 stuck for 22s!".to_string())
        );
    }

    #[test]
    fn detect_crash_matches_kernel_panic_case_insensitively() {
        let log = b"[   42.000000] Kernel panic - not syncing: Attempted to kill init!\n";
        assert_eq!(
            detect_crash(log),
            Some("Kernel panic - not syncing: Attempted to kill init!".to_string())
        );
    }

    #[test]
    fn detect_crash_ignores_kasan_initialization_banner() {
        let log = b"[    0.000000] KASAN: KernelAddressSanitizer initialized\n";
        assert_eq!(detect_crash(log), None);
    }
}
