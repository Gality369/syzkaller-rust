#![allow(dead_code, unused_imports)]

mod avoidance;
mod config;
mod corpus;
mod crash;
mod description;
mod exec;
#[allow(
    unused_imports,
    dead_code,
    clippy::all,
    non_snake_case,
    non_camel_case_types
)]
mod flatrpc_generated;
mod fuzzer;
mod manager;
mod program;
mod protocol;
mod qemu;
mod repro;
mod special;
mod ssh;
mod target;

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::env;
use std::path::{Path, PathBuf};

const DEFAULT_TARGET_SUMMARY_LIMIT: usize = 10;
const DEFAULT_SMOKE_MAX_EXECS: u64 = 32;
const DEFAULT_SMOKE_BUNDLE: &str = "data/target-bundles/linux-amd64-core.json";
const DEFAULT_SMOKE_SUITE_DESCRIPTIONS: &[&str] = &[
    "descriptions/linux/file-subset.txt",
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

#[derive(Debug, Clone, serde::Serialize, PartialEq, Eq)]
struct TargetSummary {
    source: String,
    sample_limit: usize,
    total_syscalls: usize,
    transitively_enabled_syscalls: usize,
    transitively_generatable_syscalls: usize,
    enabled_but_not_generatable_syscalls: usize,
    fuzzer_relevant_enabled_syscalls: usize,
    fuzzer_relevant_generatable_syscalls: usize,
    fuzzer_relevant_enabled_but_not_generatable_syscalls: usize,
    explicitly_disabled_syscalls: usize,
    no_generate_syscalls: usize,
    automatic_helper_syscalls: usize,
    non_fuzzer_helper_syscalls: usize,
    resource_kinds: usize,
    enabled_sample: Vec<String>,
    generatable_sample: Vec<String>,
    unavailable_sample: Vec<TargetDisabledSyscall>,
    nongeneratable_sample: Vec<TargetDisabledSyscall>,
    unavailable_reason_counts: Vec<TargetDisabledReasonCount>,
    nongeneratable_reason_counts: Vec<TargetDisabledReasonCount>,
}

#[derive(Debug, Clone, serde::Serialize, PartialEq, Eq)]
struct TargetDisabledSyscall {
    name: String,
    reason: String,
}

#[derive(Debug, Clone, serde::Serialize, PartialEq, Eq)]
struct TargetDisabledReasonCount {
    reason: String,
    count: usize,
}

#[derive(Debug, Clone, serde::Serialize, PartialEq, Eq)]
struct SmokeSummary {
    workdir: String,
    max_execs: u64,
    descriptions: String,
    corpus_programs: usize,
    corpus_signals: usize,
    artifacts_total: usize,
    artifacts_crashes: usize,
    artifacts_timeouts: usize,
    artifacts_skipped: usize,
    repro_queue_total: usize,
    repro_queue_claimable: usize,
    repro_queue_leased: usize,
    repro_queue_backed_off: usize,
    repro_queue_failed: usize,
    repro_queue_timed_out: usize,
    repro_queue_succeeded: usize,
}

#[derive(Debug, Clone, serde::Serialize, PartialEq, Eq)]
struct SmokeSuiteSummary {
    base_workdir: String,
    max_execs: u64,
    runs: Vec<SmokeSummary>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SmokeRunMetadata {
    target_label: String,
    workdir: PathBuf,
}

fn print_main_usage(program: &str) {
    eprintln!(
        "Usage:\n  {program} <config.json>\n  {program} smoke <config.json> [max_execs] [target]\n  {program} smoke-suite <config.json> [max_execs] [target ...]\n  {program} target-summary [builtin|bundle:<path>|<description-path>] [limit]\n  {program} repro-queue <command> ...\n  {program} repro-worker <command> ...\n\nSmoke commands:\n  {program} smoke <config.json>\n  {program} smoke <config.json> [max_execs]\n  {program} smoke <config.json> [max_execs] [target]\n  {program} smoke-suite <config.json>\n  {program} smoke-suite <config.json> [max_execs]\n  {program} smoke-suite <config.json> [max_execs] [target ...]\n\nTarget inspection commands:\n  {program} target-summary\n  {program} target-summary builtin [limit]\n  {program} target-summary bundle:<path> [limit]\n  {program} target-summary <description-path> [limit]\n\nRepro queue commands:\n  {program} repro-queue sync <workdir>\n  {program} repro-queue status <workdir> [limit]\n  {program} repro-queue peek <workdir>\n  {program} repro-queue claim <workdir> <worker_id> [lease_secs]\n  {program} repro-queue release <workdir> <artifact_type> <signature> <worker_id>\n  {program} repro-queue requeue <workdir> <artifact_type> <signature> <worker_id> <outcome>\n  {program} repro-queue attempt <workdir> <artifact_type> <signature> <outcome>\n\nRepro worker commands:\n  {program} repro-worker run-once <config.json> <worker_id> [lease_secs] [max_replay_attempts]\n  {program} repro-worker run-batch <config.json> <worker_id> [max_items] [lease_secs] [max_replay_attempts]"
    );
}

fn parse_u64_arg(value: &str, name: &str) -> Result<u64, String> {
    value
        .parse::<u64>()
        .map_err(|err| format!("Invalid {name} '{value}': {err}"))
}

fn parse_usize_arg(value: &str, name: &str) -> Result<usize, String> {
    value
        .parse::<usize>()
        .map_err(|err| format!("Invalid {name} '{value}': {err}"))
}

fn print_json<T: serde::Serialize>(value: &T) -> Result<(), String> {
    let text = serde_json::to_string_pretty(value)
        .map_err(|err| format!("Failed to serialize JSON output: {err}"))?;
    println!("{text}");
    Ok(())
}

fn collect_resource_kinds(arg_type: &program::ArgType, resource_kinds: &mut BTreeSet<String>) {
    match arg_type {
        program::ArgType::Resource(resource) => {
            resource_kinds.insert(resource.kind.clone());
        }
        program::ArgType::Array { inner, .. } | program::ArgType::Ptr { inner, .. } => {
            collect_resource_kinds(inner, resource_kinds);
        }
        program::ArgType::Struct { fields, .. } | program::ArgType::Union { fields, .. } => {
            for field in fields {
                collect_resource_kinds(field, resource_kinds);
            }
        }
        _ => {}
    }
}

fn sample_syscall_names(
    descs: &[program::SyscallDesc],
    syscall_indices: &[usize],
    limit: usize,
) -> Vec<String> {
    syscall_indices
        .iter()
        .take(limit)
        .map(|&syscall_idx| descs[syscall_idx].name.clone())
        .collect()
}

fn build_target_summary(target_arg: Option<&str>, limit: usize) -> Result<TargetSummary, String> {
    let sample_limit = limit.max(1);
    let source = match target_arg {
        Some(value) => target::TargetSource::from_cli_arg(value)?,
        None => target::TargetSource::BuiltinMinimal,
    };
    let loaded = target::load_target(source)?;
    let source_label = loaded.source_label.clone();
    let descs = loaded.descs;
    let availability = program::transitively_enabled_syscalls(&descs);
    let generatable = program::transitively_generatable_syscalls(&descs);
    let non_fuzzer_helper_indices = descs
        .iter()
        .enumerate()
        .filter_map(|(idx, desc)| {
            special::is_non_fuzzer_helper(&desc.name, desc.attrs.kfuzz_test).then_some(idx)
        })
        .collect::<HashSet<_>>();

    let mut resource_kinds = BTreeSet::new();
    for desc in &descs {
        for arg in &desc.args {
            collect_resource_kinds(arg, &mut resource_kinds);
        }
        if let program::ReturnType::Resource(resource) = &desc.ret {
            resource_kinds.insert(resource.kind.clone());
        }
    }

    let mut unavailable = availability
        .disabled
        .clone()
        .into_iter()
        .collect::<Vec<_>>();
    unavailable.sort_by_key(|(syscall_idx, _)| *syscall_idx);

    let mut unavailable_reason_counts = BTreeMap::new();
    for (_, reason) in &unavailable {
        *unavailable_reason_counts
            .entry(reason.clone())
            .or_insert(0usize) += 1;
    }
    let mut unavailable_reason_counts = unavailable_reason_counts
        .into_iter()
        .map(|(reason, count)| TargetDisabledReasonCount { reason, count })
        .collect::<Vec<_>>();
    unavailable_reason_counts.sort_by(|left, right| {
        right
            .count
            .cmp(&left.count)
            .then_with(|| left.reason.cmp(&right.reason))
    });
    unavailable_reason_counts.truncate(sample_limit);

    let unavailable_sample = unavailable
        .into_iter()
        .take(sample_limit)
        .map(|(syscall_idx, reason)| TargetDisabledSyscall {
            name: descs[syscall_idx].name.clone(),
            reason,
        })
        .collect::<Vec<_>>();

    let mut nongeneratable = generatable.disabled.into_iter().collect::<Vec<_>>();
    nongeneratable.sort_by_key(|(syscall_idx, _)| *syscall_idx);

    let mut reason_counts = BTreeMap::new();
    for (_, reason) in &nongeneratable {
        *reason_counts.entry(reason.clone()).or_insert(0usize) += 1;
    }
    let mut nongeneratable_reason_counts = reason_counts
        .into_iter()
        .map(|(reason, count)| TargetDisabledReasonCount { reason, count })
        .collect::<Vec<_>>();
    nongeneratable_reason_counts.sort_by(|left, right| {
        right
            .count
            .cmp(&left.count)
            .then_with(|| left.reason.cmp(&right.reason))
    });
    nongeneratable_reason_counts.truncate(sample_limit);

    let nongeneratable_sample = nongeneratable
        .into_iter()
        .take(sample_limit)
        .map(|(syscall_idx, reason)| TargetDisabledSyscall {
            name: descs[syscall_idx].name.clone(),
            reason,
        })
        .collect::<Vec<_>>();

    let explicitly_disabled_syscalls = descs.iter().filter(|desc| desc.attrs.disabled).count();
    let no_generate_syscalls = descs.iter().filter(|desc| desc.attrs.no_generate).count();
    let automatic_helper_syscalls = descs
        .iter()
        .filter(|desc| desc.attrs.automatic_helper)
        .count();
    let non_fuzzer_helper_syscalls = non_fuzzer_helper_indices.len();
    let fuzzer_relevant_enabled_syscalls = availability
        .enabled
        .iter()
        .filter(|&&idx| !non_fuzzer_helper_indices.contains(&idx))
        .count();
    let fuzzer_relevant_generatable_syscalls = generatable
        .enabled
        .iter()
        .filter(|&&idx| !non_fuzzer_helper_indices.contains(&idx))
        .count();

    Ok(TargetSummary {
        source: source_label,
        sample_limit,
        total_syscalls: descs.len(),
        transitively_enabled_syscalls: availability.enabled.len(),
        transitively_generatable_syscalls: generatable.enabled.len(),
        enabled_but_not_generatable_syscalls: availability
            .enabled
            .len()
            .saturating_sub(generatable.enabled.len()),
        fuzzer_relevant_enabled_syscalls,
        fuzzer_relevant_generatable_syscalls,
        fuzzer_relevant_enabled_but_not_generatable_syscalls: fuzzer_relevant_enabled_syscalls
            .saturating_sub(fuzzer_relevant_generatable_syscalls),
        explicitly_disabled_syscalls,
        no_generate_syscalls,
        automatic_helper_syscalls,
        non_fuzzer_helper_syscalls,
        resource_kinds: resource_kinds.len(),
        enabled_sample: sample_syscall_names(&descs, &availability.enabled, sample_limit),
        generatable_sample: sample_syscall_names(&descs, &generatable.enabled, sample_limit),
        unavailable_sample,
        nongeneratable_sample,
        unavailable_reason_counts,
        nongeneratable_reason_counts,
    })
}

fn run_target_summary_cli(args: &[String]) -> Result<(), String> {
    if args.len() > 2 {
        return Err(
            "Usage: target-summary [builtin|bundle:<path>|<description-path>] [limit]".to_string(),
        );
    }

    let (description_path, limit) = match args {
        [] => (None, DEFAULT_TARGET_SUMMARY_LIMIT),
        [value] if value == "builtin" => (None, DEFAULT_TARGET_SUMMARY_LIMIT),
        [path] => (Some(path.as_str()), DEFAULT_TARGET_SUMMARY_LIMIT),
        [path, limit] if path == "builtin" => (None, parse_usize_arg(limit, "limit")?),
        [path, limit] => (Some(path.as_str()), parse_usize_arg(limit, "limit")?),
        _ => unreachable!(),
    };

    let summary = build_target_summary(description_path, limit)?;
    print_json(&summary)
}

fn build_smoke_config(
    mut cfg: config::Config,
    max_execs_override: Option<u64>,
    target_override: Option<&str>,
) -> Result<config::Config, String> {
    let max_execs = max_execs_override.unwrap_or(DEFAULT_SMOKE_MAX_EXECS);
    if max_execs == 0 {
        return Err("smoke max_execs must be greater than 0".to_string());
    }
    cfg.max_execs = Some(max_execs);
    if let Some(value) = target_override {
        match target::TargetSource::from_cli_arg(value)? {
            target::TargetSource::BuiltinMinimal => {
                cfg.target_bundle = None;
                cfg.syscall_descriptions = None;
            }
            target::TargetSource::DescriptionPath(path) => {
                cfg.target_bundle = None;
                cfg.syscall_descriptions = Some(path.display().to_string());
            }
            target::TargetSource::BundlePath(path) => {
                cfg.target_bundle = Some(path.display().to_string());
                cfg.syscall_descriptions = None;
            }
        }
    } else if cfg.target_bundle.is_none() && cfg.syscall_descriptions.is_none() {
        cfg.target_bundle = Some(DEFAULT_SMOKE_BUNDLE.to_string());
    }
    Ok(cfg)
}

fn command_exists(command: &str) -> bool {
    if command.is_empty() {
        return false;
    }

    let command_path = std::path::Path::new(command);
    if command_path.is_absolute() || command.contains(std::path::MAIN_SEPARATOR) {
        return command_path.exists();
    }

    std::env::var_os("PATH")
        .is_some_and(|paths| std::env::split_paths(&paths).any(|dir| dir.join(command).exists()))
}

fn validate_smoke_prerequisites(cfg: &config::Config) -> Result<(), String> {
    let mut missing = Vec::new();
    let required_paths = [
        ("kernel_obj", cfg.kernel_obj.as_str()),
        ("image", cfg.image.as_str()),
        ("sshkey", cfg.sshkey.as_str()),
        ("executor", cfg.executor.as_str()),
        ("vm.kernel", cfg.vm.kernel.as_str()),
    ];

    for (name, path) in required_paths {
        if !std::path::Path::new(path).exists() {
            missing.push(format!("{name}: {path}"));
        }
    }
    if let Some(description_path) = cfg.syscall_descriptions.as_deref() {
        if !std::path::Path::new(description_path).exists() {
            missing.push(format!("syscall_descriptions: {description_path}"));
        }
    }
    if let Some(bundle_path) = cfg.target_bundle.as_deref() {
        if !std::path::Path::new(bundle_path).exists() {
            missing.push(format!("target_bundle: {bundle_path}"));
        }
    }
    if !command_exists(&cfg.vm.qemu) {
        missing.push(format!("vm.qemu: {}", cfg.vm.qemu));
    }
    if cfg.vm.count == 0 {
        missing.push("vm.count: must be greater than 0".to_string());
    }

    if missing.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "Smoke preflight failed:\n  - {}",
            missing.join("\n  - ")
        ))
    }
}

fn build_smoke_summary(cfg: &config::Config) -> Result<SmokeSummary, String> {
    let loaded = target::load_target_from_config(cfg, None)
        .map_err(|err| format!("Failed to reload target for smoke summary: {err}"))?;
    let descriptions = loaded.source_label.clone();
    let descs = loaded.descs;
    let corpus_path = std::path::Path::new(&cfg.workdir).join("corpus.json");
    let (corpus, _) = corpus::Corpus::load(&corpus_path, &descs)
        .map_err(|err| format!("Failed to load smoke corpus snapshot: {err}"))?;
    let artifacts = crash::sync_artifact_catalog(&cfg.workdir)
        .map_err(|err| format!("Failed to refresh smoke artifact catalog: {err}"))?;
    let repro_queue = crash::load_repro_queue_snapshot(&cfg.workdir, 0)
        .map_err(|err| format!("Failed to load smoke repro queue snapshot: {err}"))?;
    Ok(SmokeSummary {
        workdir: cfg.workdir.clone(),
        max_execs: cfg.max_execs.unwrap_or(DEFAULT_SMOKE_MAX_EXECS),
        descriptions,
        corpus_programs: corpus.len(),
        corpus_signals: corpus.signal_count(),
        artifacts_total: artifacts.total_entries,
        artifacts_crashes: artifacts.crash_entries,
        artifacts_timeouts: artifacts.timeout_entries,
        artifacts_skipped: artifacts.skipped_entries,
        repro_queue_total: repro_queue.summary.total_entries,
        repro_queue_claimable: repro_queue.summary.claimable_entries,
        repro_queue_leased: repro_queue.summary.leased_entries,
        repro_queue_backed_off: repro_queue.summary.backed_off_entries,
        repro_queue_failed: repro_queue.summary.failed_entries,
        repro_queue_timed_out: repro_queue.summary.timed_out_entries,
        repro_queue_succeeded: repro_queue.summary.succeeded_entries,
    })
}

fn smoke_target_slug(target_label: &str) -> String {
    smoke_suite_slug(target_label)
}

fn smoke_suite_slug(description: &str) -> String {
    let mut slug = description
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>();
    while slug.contains("--") {
        slug = slug.replace("--", "-");
    }
    let slug = slug.trim_matches('-');
    if slug.is_empty() {
        "target".to_string()
    } else {
        slug.to_string()
    }
}

fn smoke_suite_workdir(base_workdir: &str, description: &str) -> PathBuf {
    Path::new(base_workdir)
        .join("smoke-suite")
        .join(smoke_suite_slug(description))
}

fn smoke_workdir(base_workdir: &str, target_label: &str) -> PathBuf {
    Path::new(base_workdir)
        .join("smoke")
        .join(smoke_target_slug(target_label))
}

fn reset_smoke_workdir(workdir: &Path) -> Result<(), String> {
    if workdir.exists() {
        std::fs::remove_dir_all(workdir)
            .map_err(|err| format!("Failed to reset smoke workdir {}: {err}", workdir.display()))?;
    }
    std::fs::create_dir_all(workdir).map_err(|err| {
        format!(
            "Failed to create smoke workdir {}: {err}",
            workdir.display()
        )
    })
}

fn resolve_smoke_suite_args(args: &[String]) -> Result<(Option<u64>, Vec<String>), String> {
    if args.is_empty() {
        return Ok((
            None,
            DEFAULT_SMOKE_SUITE_DESCRIPTIONS
                .iter()
                .map(|value| value.to_string())
                .collect(),
        ));
    }

    let (max_execs_override, description_start) = match args[0].parse::<u64>() {
        Ok(value) => (Some(value), 1),
        Err(_) => (None, 0),
    };

    let descriptions = if args.len() > description_start {
        args[description_start..].to_vec()
    } else {
        DEFAULT_SMOKE_SUITE_DESCRIPTIONS
            .iter()
            .map(|value| value.to_string())
            .collect()
    };
    Ok((max_execs_override, descriptions))
}

fn derive_smoke_run_metadata(
    cfg: &config::Config,
    target_override: Option<&str>,
) -> Result<SmokeRunMetadata, String> {
    let target_source = target::TargetSource::from_config(cfg, target_override)?;
    let target_label = target_source.display_label();
    Ok(SmokeRunMetadata {
        workdir: smoke_workdir(&cfg.workdir, &target_label),
        target_label,
    })
}

fn run_smoke_cli(args: &[String]) -> Result<(), String> {
    if args.is_empty() || args.len() > 3 {
        return Err("Usage: smoke <config.json> [max_execs] [target]".to_string());
    }

    let cfg =
        config::Config::load(&args[0]).map_err(|err| format!("Failed to load config: {err}"))?;
    let max_execs_override = if args.len() >= 2 {
        Some(parse_u64_arg(&args[1], "max_execs")?)
    } else {
        None
    };
    let description_override = args.get(2).map(String::as_str);
    let mut cfg = build_smoke_config(cfg, max_execs_override, description_override)?;
    let metadata = derive_smoke_run_metadata(&cfg, None)?;
    cfg.workdir = metadata.workdir.display().to_string();
    reset_smoke_workdir(&metadata.workdir)?;
    validate_smoke_prerequisites(&cfg)?;

    println!(
        "Starting smoke run: max_execs={} descriptions={} workdir={}",
        cfg.max_execs.unwrap_or(DEFAULT_SMOKE_MAX_EXECS),
        metadata.target_label,
        cfg.workdir
    );

    log::info!(
        "Starting smoke run with max_execs={} descriptions={}",
        cfg.max_execs.unwrap_or(DEFAULT_SMOKE_MAX_EXECS),
        metadata.target_label
    );

    manager::run(cfg.clone()).map_err(|err| format!("Smoke run failed: {err}"))?;
    let summary = build_smoke_summary(&cfg)?;
    print_json(&summary)
}

fn run_smoke_suite_cli(args: &[String]) -> Result<(), String> {
    if args.is_empty() {
        return Err("Usage: smoke-suite <config.json> [max_execs] [target ...]".to_string());
    }

    let base_cfg =
        config::Config::load(&args[0]).map_err(|err| format!("Failed to load config: {err}"))?;
    let (max_execs_override, descriptions) = resolve_smoke_suite_args(&args[1..])?;
    let max_execs = max_execs_override.unwrap_or(DEFAULT_SMOKE_MAX_EXECS);
    if max_execs == 0 {
        return Err("smoke-suite max_execs must be greater than 0".to_string());
    }

    let mut runs = Vec::with_capacity(descriptions.len());
    for description in descriptions {
        let workdir = smoke_suite_workdir(&base_cfg.workdir, &description);
        reset_smoke_workdir(&workdir)?;

        let mut cfg = build_smoke_config(base_cfg.clone(), Some(max_execs), Some(&description))?;
        cfg.workdir = workdir.display().to_string();
        validate_smoke_prerequisites(&cfg)?;

        println!(
            "Starting smoke-suite target: max_execs={} descriptions={} workdir={}",
            max_execs, description, cfg.workdir
        );
        manager::run(cfg.clone())
            .map_err(|err| format!("Smoke suite target {description} failed: {err}"))?;
        runs.push(build_smoke_summary(&cfg)?);
    }

    print_json(&SmokeSuiteSummary {
        base_workdir: base_cfg.workdir,
        max_execs,
        runs,
    })
}

fn run_repro_queue_cli(program: &str, args: &[String]) -> Result<(), String> {
    if args.is_empty() {
        print_main_usage(program);
        return Err("missing repro-queue command".to_string());
    }

    match args[0].as_str() {
        "sync" => {
            if args.len() != 2 {
                return Err("Usage: repro-queue sync <workdir>".to_string());
            }
            let report = crash::sync_artifact_catalog(&args[1])
                .map_err(|err| format!("Failed to sync artifact catalog: {err}"))?;
            print_json(&serde_json::json!({
                "total_entries": report.total_entries,
                "crash_entries": report.crash_entries,
                "timeout_entries": report.timeout_entries,
                "skipped_entries": report.skipped_entries,
            }))
        }
        "status" => {
            if args.len() < 2 || args.len() > 3 {
                return Err("Usage: repro-queue status <workdir> [limit]".to_string());
            }
            let limit = if args.len() == 3 {
                parse_usize_arg(&args[2], "limit")?
            } else {
                5
            };
            let snapshot = crash::load_repro_queue_snapshot(&args[1], limit)
                .map_err(|err| format!("Failed to load repro queue snapshot: {err}"))?;
            print_json(&snapshot)
        }
        "peek" => {
            if args.len() != 2 {
                return Err("Usage: repro-queue peek <workdir>".to_string());
            }
            let entry = crash::peek_repro_queue_entry(&args[1])
                .map_err(|err| format!("Failed to peek repro queue: {err}"))?;
            print_json(&entry)
        }
        "claim" => {
            if args.len() < 3 || args.len() > 4 {
                return Err(
                    "Usage: repro-queue claim <workdir> <worker_id> [lease_secs]".to_string(),
                );
            }
            let lease_secs = if args.len() == 4 {
                parse_u64_arg(&args[3], "lease_secs")?
            } else {
                300
            };
            let entry = crash::claim_repro_queue_entry(&args[1], &args[2], lease_secs)
                .map_err(|err| format!("Failed to claim repro queue entry: {err}"))?;
            print_json(&entry)
        }
        "release" => {
            if args.len() != 5 {
                return Err(
                    "Usage: repro-queue release <workdir> <artifact_type> <signature> <worker_id>"
                        .to_string(),
                );
            }
            let released = crash::release_repro_queue_claim(&args[1], &args[2], &args[3], &args[4])
                .map_err(|err| format!("Failed to release repro queue claim: {err}"))?;
            print_json(&serde_json::json!({ "released": released }))
        }
        "requeue" => {
            if args.len() != 6 {
                return Err(
                    "Usage: repro-queue requeue <workdir> <artifact_type> <signature> <worker_id> <outcome>"
                        .to_string(),
                );
            }
            let requeued =
                crash::requeue_repro_queue_claim(&args[1], &args[2], &args[3], &args[4], &args[5])
                    .map_err(|err| format!("Failed to requeue repro queue claim: {err}"))?;
            print_json(&serde_json::json!({ "requeued": requeued }))
        }
        "attempt" => {
            if args.len() != 5 {
                return Err(
                    "Usage: repro-queue attempt <workdir> <artifact_type> <signature> <outcome>"
                        .to_string(),
                );
            }
            let recorded =
                crash::record_repro_queue_attempt(&args[1], &args[2], &args[3], &args[4])
                    .map_err(|err| format!("Failed to record repro queue attempt: {err}"))?;
            print_json(&serde_json::json!({ "recorded": recorded }))
        }
        _ => Err(format!("Unknown repro-queue command: {}", args[0])),
    }
}

fn run_repro_worker_cli(args: &[String]) -> Result<(), String> {
    if args.is_empty() {
        return Err("missing repro-worker command".to_string());
    }
    match args[0].as_str() {
        "run-once" => {
            if args.len() < 3 || args.len() > 5 {
                return Err(
                    "Usage: repro-worker run-once <config.json> <worker_id> [lease_secs] [max_replay_attempts]"
                        .to_string(),
                );
            }
            let cfg = config::Config::load(&args[1])
                .map_err(|err| format!("Failed to load config: {err}"))?;
            let lease_secs = if args.len() >= 4 {
                parse_u64_arg(&args[3], "lease_secs")?
            } else {
                repro::default_repro_lease_secs()
            };
            let max_replay_attempts = if args.len() == 5 {
                parse_usize_arg(&args[4], "max_replay_attempts")?
            } else {
                repro::default_repro_max_attempts()
            };
            let report = repro::run_repro_worker_once_with_attempts(
                cfg,
                &args[2],
                lease_secs,
                max_replay_attempts,
            )
            .map_err(|err| format!("Repro worker failed: {err}"))?;
            print_json(&report)
        }
        "run-batch" => {
            if args.len() < 3 || args.len() > 6 {
                return Err(
                    "Usage: repro-worker run-batch <config.json> <worker_id> [max_items] [lease_secs] [max_replay_attempts]"
                        .to_string(),
                );
            }
            let cfg = config::Config::load(&args[1])
                .map_err(|err| format!("Failed to load config: {err}"))?;
            let max_items = if args.len() >= 4 {
                parse_usize_arg(&args[3], "max_items")?
            } else {
                10
            };
            let lease_secs = if args.len() >= 5 {
                parse_u64_arg(&args[4], "lease_secs")?
            } else {
                repro::default_repro_lease_secs()
            };
            let max_replay_attempts = if args.len() == 6 {
                parse_usize_arg(&args[5], "max_replay_attempts")?
            } else {
                repro::default_repro_max_attempts()
            };
            let report = repro::run_repro_worker_batch_with_attempts(
                cfg,
                &args[2],
                max_items,
                lease_secs,
                max_replay_attempts,
            )
            .map_err(|err| format!("Repro worker batch failed: {err}"))?;
            print_json(&report)
        }
        _ => Err(format!("Unknown repro-worker command: {}", args[0])),
    }
}

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp_millis()
        .init();

    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        print_main_usage(&args[0]);
        std::process::exit(1);
    }

    if args[1] == "repro-queue" {
        if let Err(err) = run_repro_queue_cli(&args[0], &args[2..]) {
            eprintln!("{err}");
            std::process::exit(1);
        }
        return;
    }
    if args[1] == "smoke" {
        if let Err(err) = run_smoke_cli(&args[2..]) {
            eprintln!("{err}");
            std::process::exit(1);
        }
        return;
    }
    if args[1] == "smoke-suite" {
        if let Err(err) = run_smoke_suite_cli(&args[2..]) {
            eprintln!("{err}");
            std::process::exit(1);
        }
        return;
    }
    if args[1] == "target-summary" {
        if let Err(err) = run_target_summary_cli(&args[2..]) {
            eprintln!("{err}");
            std::process::exit(1);
        }
        return;
    }
    if args[1] == "repro-worker" {
        if let Err(err) = run_repro_worker_cli(&args[2..]) {
            eprintln!("{err}");
            std::process::exit(1);
        }
        return;
    }

    let cfg = match config::Config::load(&args[1]) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to load config: {}", e);
            std::process::exit(1);
        }
    };

    log::info!("Starting syzkaller-rust with config: {:?}", cfg);

    if let Err(e) = manager::run(cfg) {
        log::error!("Manager failed: {}", e);
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::{
        build_smoke_config, build_smoke_summary, build_target_summary,
        derive_smoke_run_metadata, resolve_smoke_suite_args, smoke_suite_workdir,
        validate_smoke_prerequisites, SmokeSummary, TargetDisabledSyscall,
        DEFAULT_SMOKE_BUNDLE, DEFAULT_SMOKE_MAX_EXECS,
    };
    use crate::config::{Config, VmConfig};
    use crate::program;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn test_config() -> Config {
        Config {
            workdir: "/tmp/workdir".into(),
            kernel_obj: "/tmp/kernel_obj".into(),
            image: "/tmp/image".into(),
            sshkey: "/tmp/key".into(),
            ssh_user: "root".into(),
            executor: "/tmp/syz-executor".into(),
            target_bundle: None,
            syscall_descriptions: None,
            procs: 1,
            sandbox: "none".into(),
            cover: true,
            vm: VmConfig {
                count: 1,
                kernel: "/tmp/bzImage".into(),
                cpu: 2,
                mem: 2048,
                qemu_args: String::new(),
                qemu: "qemu-system-x86_64".into(),
                cmdline: "console=ttyS0".into(),
            },
            syscall_timeout_ms: 500,
            program_timeout_ms: 5000,
            slowdown: 1,
            max_execs: None,
        }
    }

    fn unique_temp_dir(name: &str) -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "syzkaller-rust-main-{name}-{}-{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("temp test dir should create");
        path
    }

    fn smoke_ready_config() -> Config {
        let root = unique_temp_dir("smoke-ready");
        let kernel_obj = root.join("kernel-obj");
        let workdir = root.join("workdir");
        fs::create_dir_all(&kernel_obj).expect("kernel obj dir should exist");
        fs::create_dir_all(&workdir).expect("workdir should exist");
        let image = root.join("image.img");
        let sshkey = root.join("id_rsa");
        let executor = root.join("syz-executor");
        let kernel = root.join("bzImage");
        let descriptions = root.join("smoke.txt");
        fs::write(&image, b"img").expect("image should write");
        fs::write(&sshkey, b"key").expect("sshkey should write");
        fs::write(&executor, b"exec").expect("executor should write");
        fs::write(&kernel, b"kernel").expect("kernel should write");
        fs::write(&descriptions, b"syscall getpid@1 -> int()\n")
            .expect("descriptions should write");

        Config {
            workdir: workdir.to_string_lossy().into_owned(),
            kernel_obj: kernel_obj.to_string_lossy().into_owned(),
            image: image.to_string_lossy().into_owned(),
            sshkey: sshkey.to_string_lossy().into_owned(),
            ssh_user: "root".into(),
            executor: executor.to_string_lossy().into_owned(),
            target_bundle: None,
            syscall_descriptions: Some(descriptions.to_string_lossy().into_owned()),
            procs: 1,
            sandbox: "none".into(),
            cover: true,
            vm: VmConfig {
                count: 1,
                kernel: kernel.to_string_lossy().into_owned(),
                cpu: 2,
                mem: 2048,
                qemu_args: String::new(),
                qemu: std::env::current_exe()
                    .expect("current exe should resolve")
                    .to_string_lossy()
                    .into_owned(),
                cmdline: "console=ttyS0".into(),
            },
            syscall_timeout_ms: 500,
            program_timeout_ms: 5000,
            slowdown: 1,
            max_execs: Some(4),
        }
    }

    fn write_test_bundle(root: &std::path::Path) -> PathBuf {
        let bundle_dir = root.join("bundles");
        fs::create_dir_all(&bundle_dir).expect("bundle dir should exist");
        let bundle_path = bundle_dir.join("linux-amd64-test.json");
        fs::write(
            &bundle_path,
            serde_json::json!({
                "format_version": 1,
                "source": {
                    "kind": "upstream-syzkaller",
                    "os": "linux",
                    "arch": "amd64",
                    "syzkaller_git_revision": "test"
                },
                "export_summary": {
                    "total_syscalls": 1,
                    "exported_syscalls": 1,
                    "skipped_syscalls": 0,
                    "skip_reasons": []
                },
                "syscalls": [
                    {
                        "name": "getpid",
                        "id": 1,
                        "arg_names": [],
                        "args": [],
                        "ret": "Int",
                        "attrs": {
                            "automatic_helper": false,
                            "no_generate": false,
                            "disabled": false,
                            "ignore_return": false,
                            "breaks_returns": false,
                            "no_minimize": false,
                            "no_squash": false,
                            "remote_cover": false,
                            "snapshot": false,
                            "kfuzz_test": false,
                            "timeout_ms": null,
                            "prog_timeout_ms": null,
                            "fsck_command": null
                        }
                    }
                ]
            })
            .to_string(),
        )
        .expect("bundle should write");
        bundle_path
    }

    #[test]
    fn target_summary_uses_builtin_target_by_default() {
        let summary = build_target_summary(None, 3).expect("builtin target summary should load");
        let descs = program::get_syscall_descs();
        let enabled = program::transitively_enabled_syscalls(&descs);
        let generatable = program::transitively_generatable_syscalls(&descs);

        assert_eq!(summary.source, "builtin:linux/amd64-minimal");
        assert_eq!(summary.total_syscalls, descs.len());
        assert_eq!(summary.transitively_enabled_syscalls, enabled.enabled.len());
        assert_eq!(
            summary.transitively_generatable_syscalls,
            generatable.enabled.len()
        );
        assert_eq!(
            summary.enabled_but_not_generatable_syscalls,
            enabled
                .enabled
                .len()
                .saturating_sub(generatable.enabled.len())
        );
        assert!(summary.fuzzer_relevant_enabled_syscalls <= summary.transitively_enabled_syscalls);
        assert!(
            summary.fuzzer_relevant_generatable_syscalls
                <= summary.transitively_generatable_syscalls
        );
        assert!(
            summary.fuzzer_relevant_enabled_but_not_generatable_syscalls
                <= summary.enabled_but_not_generatable_syscalls
        );
        assert!(summary.enabled_sample.len() <= 3);
        assert!(summary.generatable_sample.len() <= 3);
        assert!(summary.unavailable_sample.len() <= 3);
        assert!(summary.nongeneratable_sample.len() <= 3);
        assert!(summary.unavailable_reason_counts.len() <= 3);
        assert!(summary.resource_kinds > 0);
    }

    #[test]
    fn target_summary_honors_external_target_and_limit() {
        let summary = build_target_summary(Some("descriptions/linux/socket-subset.txt"), 2)
            .expect("external target summary should load");
        let descs = program::load_syscall_descs(Some("descriptions/linux/socket-subset.txt"))
            .expect("external descriptions should load");

        assert_eq!(summary.source, "descriptions/linux/socket-subset.txt");
        assert_eq!(summary.sample_limit, 2);
        assert_eq!(summary.total_syscalls, descs.len());
        assert!(summary.enabled_sample.len() <= 2);
        assert!(summary.generatable_sample.len() <= 2);
        assert!(summary.unavailable_sample.len() <= 2);
        assert!(summary.nongeneratable_sample.len() <= 2);
        assert!(summary.unavailable_reason_counts.len() <= 2);
        assert!(summary.nongeneratable_reason_counts.len() <= 2);
    }

    #[test]
    fn target_summary_accepts_bundle_source() {
        let root = unique_temp_dir("target-summary-bundle");
        let bundle = write_test_bundle(&root);
        let source = format!("bundle:{}", bundle.display());
        let summary = build_target_summary(Some(&source), 5).expect("bundle summary should load");

        assert!(summary.source.starts_with("bundle:"));
        assert_eq!(summary.total_syscalls, 1);
    }

    #[test]
    fn target_summary_accepts_checked_in_bundle_fixture() {
        let summary =
            build_target_summary(Some("bundle:data/target-bundles/linux-amd64-smoke.json"), 6)
                .expect("checked-in bundle fixture should load");

        assert_eq!(
            summary.source,
            "bundle:data/target-bundles/linux-amd64-smoke.json"
        );
        assert!(summary.total_syscalls >= 27);
        assert!(summary.transitively_generatable_syscalls >= 20);
        assert!(summary.enabled_sample.len() <= 6);
        assert!(summary.generatable_sample.len() <= 6);
    }

    #[test]
    fn target_summary_accepts_checked_in_core_bundle_fixture() {
        let summary =
            build_target_summary(Some("bundle:data/target-bundles/linux-amd64-core.json"), 12)
                .expect("core bundle summary should load");

        assert_eq!(
            summary.source,
            "bundle:data/target-bundles/linux-amd64-core.json"
        );
        assert_eq!(summary.total_syscalls, 41);
        assert_eq!(summary.transitively_enabled_syscalls, 41);
        assert_eq!(summary.transitively_generatable_syscalls, 41);
        assert_eq!(summary.enabled_but_not_generatable_syscalls, 0);
    }

    #[test]
    fn target_summary_loads_path_info_subset() {
        let summary = build_target_summary(Some("descriptions/linux/path-info-subset.txt"), 2)
            .expect("path-info subset should load");

        assert_eq!(summary.source, "descriptions/linux/path-info-subset.txt");
        assert_eq!(summary.total_syscalls, 3);
        assert_eq!(summary.transitively_enabled_syscalls, 3);
        assert_eq!(summary.transitively_generatable_syscalls, 3);
    }

    #[test]
    fn target_summary_loads_dirent_subset() {
        let summary = build_target_summary(Some("descriptions/linux/dirent-subset.txt"), 2)
            .expect("dirent subset should load");

        assert_eq!(summary.source, "descriptions/linux/dirent-subset.txt");
        assert_eq!(summary.total_syscalls, 3);
        assert_eq!(summary.transitively_enabled_syscalls, 3);
        assert_eq!(summary.transitively_generatable_syscalls, 3);
    }

    #[test]
    fn target_summary_loads_execution_regression_subsets() {
        let file_summary = build_target_summary(Some("descriptions/linux/file-subset.txt"), 2)
            .expect("file subset should load");
        let mm_summary = build_target_summary(Some("descriptions/linux/mm-subset.txt"), 2)
            .expect("mm subset should load");
        let process_summary =
            build_target_summary(Some("descriptions/linux/process-subset.txt"), 2)
                .expect("process subset should load");
        let socket_io_summary =
            build_target_summary(Some("descriptions/linux/socket-io-subset.txt"), 2)
                .expect("socket-io subset should load");
        let sockopt_buf_summary =
            build_target_summary(Some("descriptions/linux/sockopt-buf-subset.txt"), 2)
                .expect("sockopt-buf subset should load");
        let sock_ifreq_summary =
            build_target_summary(Some("descriptions/linux/sock-ifreq-subset.txt"), 2)
                .expect("sock-ifreq subset should load");
        let sock_ifconf_summary =
            build_target_summary(Some("descriptions/linux/sock-ifconf-subset.txt"), 2)
                .expect("sock-ifconf subset should load");
        let sock_ethtool_summary =
            build_target_summary(Some("descriptions/linux/sock-ethtool-subset.txt"), 2)
                .expect("sock-ethtool subset should load");
        let pipe_fionread_summary =
            build_target_summary(Some("descriptions/linux/pipe-fionread-subset.txt"), 2)
                .expect("pipe-fionread subset should load");
        let socket_io_stress_summary =
            build_target_summary(Some("descriptions/linux/socket-io-stress-subset.txt"), 2)
                .expect("socket-io stress subset should load");
        let pipe_io_summary =
            build_target_summary(Some("descriptions/linux/pipe-io-subset.txt"), 2)
                .expect("pipe-io subset should load");
        let msg_io_summary = build_target_summary(Some("descriptions/linux/msg-io-subset.txt"), 2)
            .expect("msg-io subset should load");
        let recvmsg_io_summary =
            build_target_summary(Some("descriptions/linux/recvmsg-io-subset.txt"), 2)
                .expect("recvmsg-io subset should load");
        let recvmmsg_io_summary =
            build_target_summary(Some("descriptions/linux/recvmmsg-io-subset.txt"), 2)
                .expect("recvmmsg-io subset should load");
        let dgram_io_summary =
            build_target_summary(Some("descriptions/linux/dgram-io-subset.txt"), 2)
                .expect("dgram-io subset should load");
        let accept_connect_summary =
            build_target_summary(Some("descriptions/linux/accept-connect-subset.txt"), 2)
                .expect("accept-connect subset should load");

        assert_eq!(file_summary.source, "descriptions/linux/file-subset.txt");
        assert_eq!(file_summary.total_syscalls, 9);
        assert_eq!(file_summary.transitively_enabled_syscalls, 9);
        assert_eq!(file_summary.transitively_generatable_syscalls, 9);

        assert_eq!(mm_summary.source, "descriptions/linux/mm-subset.txt");
        assert_eq!(mm_summary.total_syscalls, 6);
        assert_eq!(mm_summary.transitively_enabled_syscalls, 6);
        assert_eq!(mm_summary.transitively_generatable_syscalls, 6);

        assert_eq!(
            process_summary.source,
            "descriptions/linux/process-subset.txt"
        );
        assert_eq!(process_summary.total_syscalls, 4);
        assert_eq!(process_summary.transitively_enabled_syscalls, 4);
        assert_eq!(process_summary.transitively_generatable_syscalls, 4);

        assert_eq!(
            pipe_io_summary.source,
            "descriptions/linux/pipe-io-subset.txt"
        );
        assert_eq!(pipe_io_summary.total_syscalls, 3);
        assert_eq!(pipe_io_summary.transitively_enabled_syscalls, 3);
        assert_eq!(pipe_io_summary.transitively_generatable_syscalls, 3);

        assert_eq!(
            msg_io_summary.source,
            "descriptions/linux/msg-io-subset.txt"
        );
        assert_eq!(msg_io_summary.total_syscalls, 4);
        assert_eq!(msg_io_summary.transitively_enabled_syscalls, 4);
        assert_eq!(msg_io_summary.transitively_generatable_syscalls, 4);

        assert_eq!(
            recvmsg_io_summary.source,
            "descriptions/linux/recvmsg-io-subset.txt"
        );
        assert_eq!(recvmsg_io_summary.total_syscalls, 3);
        assert_eq!(recvmsg_io_summary.transitively_enabled_syscalls, 3);
        assert_eq!(recvmsg_io_summary.transitively_generatable_syscalls, 3);

        assert_eq!(
            recvmmsg_io_summary.source,
            "descriptions/linux/recvmmsg-io-subset.txt"
        );
        assert_eq!(recvmmsg_io_summary.total_syscalls, 3);
        assert_eq!(recvmmsg_io_summary.transitively_enabled_syscalls, 3);
        assert_eq!(recvmmsg_io_summary.transitively_generatable_syscalls, 3);

        assert_eq!(
            dgram_io_summary.source,
            "descriptions/linux/dgram-io-subset.txt"
        );
        assert_eq!(dgram_io_summary.total_syscalls, 3);
        assert_eq!(dgram_io_summary.transitively_enabled_syscalls, 3);
        assert_eq!(dgram_io_summary.transitively_generatable_syscalls, 3);

        assert_eq!(
            accept_connect_summary.source,
            "descriptions/linux/accept-connect-subset.txt"
        );
        assert_eq!(accept_connect_summary.total_syscalls, 12);
        assert_eq!(accept_connect_summary.transitively_enabled_syscalls, 12);
        assert_eq!(accept_connect_summary.transitively_generatable_syscalls, 12);

        assert_eq!(
            socket_io_summary.source,
            "descriptions/linux/socket-io-subset.txt"
        );
        assert_eq!(socket_io_summary.total_syscalls, 4);
        assert_eq!(socket_io_summary.transitively_enabled_syscalls, 4);
        assert_eq!(socket_io_summary.transitively_generatable_syscalls, 3);
        assert_eq!(socket_io_summary.enabled_but_not_generatable_syscalls, 1);

        assert_eq!(
            sockopt_buf_summary.source,
            "descriptions/linux/sockopt-buf-subset.txt"
        );
        assert_eq!(sockopt_buf_summary.total_syscalls, 4);
        assert_eq!(sockopt_buf_summary.transitively_enabled_syscalls, 4);
        assert_eq!(sockopt_buf_summary.transitively_generatable_syscalls, 4);

        assert_eq!(
            sock_ifreq_summary.source,
            "descriptions/linux/sock-ifreq-subset.txt"
        );
        assert_eq!(sock_ifreq_summary.total_syscalls, 4);
        assert_eq!(sock_ifreq_summary.transitively_enabled_syscalls, 4);
        assert_eq!(sock_ifreq_summary.transitively_generatable_syscalls, 4);

        assert_eq!(
            sock_ifconf_summary.source,
            "descriptions/linux/sock-ifconf-subset.txt"
        );
        assert_eq!(sock_ifconf_summary.total_syscalls, 3);
        assert_eq!(sock_ifconf_summary.transitively_enabled_syscalls, 3);
        assert_eq!(sock_ifconf_summary.transitively_generatable_syscalls, 3);

        assert_eq!(
            sock_ethtool_summary.source,
            "descriptions/linux/sock-ethtool-subset.txt"
        );
        assert_eq!(sock_ethtool_summary.total_syscalls, 44);
        assert_eq!(sock_ethtool_summary.transitively_enabled_syscalls, 44);
        assert_eq!(sock_ethtool_summary.transitively_generatable_syscalls, 44);

        assert_eq!(
            pipe_fionread_summary.source,
            "descriptions/linux/pipe-fionread-subset.txt"
        );
        assert_eq!(pipe_fionread_summary.total_syscalls, 4);
        assert_eq!(pipe_fionread_summary.transitively_enabled_syscalls, 4);
        assert_eq!(pipe_fionread_summary.transitively_generatable_syscalls, 4);

        assert_eq!(
            socket_io_stress_summary.source,
            "descriptions/linux/socket-io-stress-subset.txt"
        );
        assert_eq!(socket_io_stress_summary.total_syscalls, 8);
        assert_eq!(socket_io_stress_summary.transitively_enabled_syscalls, 8);
        assert_eq!(
            socket_io_stress_summary.transitively_generatable_syscalls,
            7
        );
        assert_eq!(
            socket_io_stress_summary.enabled_but_not_generatable_syscalls,
            1
        );
    }

    #[test]
    fn target_summary_separates_non_fuzzer_helpers_from_fuzzer_gap() {
        let root = unique_temp_dir("target-summary-non-fuzzer");
        let descriptions = root.join("summary.txt");
        fs::write(
            &descriptions,
            concat!(
                "syscall live@1 -> int()\n",
                "syscall syz_kvm_assert_fake$x86@2 -> int() (no_generate)\n",
                "syscall syz_kfuzztest_run@3 -> int() (kfuzz_test, no_generate)\n",
            ),
        )
        .expect("descriptions should write");

        let summary = build_target_summary(Some(descriptions.to_string_lossy().as_ref()), 4)
            .expect("summary should load");

        assert_eq!(summary.total_syscalls, 3);
        assert_eq!(summary.transitively_enabled_syscalls, 3);
        assert_eq!(summary.transitively_generatable_syscalls, 1);
        assert_eq!(summary.enabled_but_not_generatable_syscalls, 2);
        assert_eq!(summary.non_fuzzer_helper_syscalls, 2);
        assert_eq!(summary.fuzzer_relevant_enabled_syscalls, 1);
        assert_eq!(summary.fuzzer_relevant_generatable_syscalls, 1);
        assert_eq!(
            summary.fuzzer_relevant_enabled_but_not_generatable_syscalls,
            0
        );
        assert_eq!(summary.nongeneratable_sample.len(), 2);
        assert_eq!(
            summary.nongeneratable_sample[0],
            TargetDisabledSyscall {
                name: "syz_kvm_assert_fake$x86".to_string(),
                reason: "test-only helper".to_string(),
            }
        );
        assert_eq!(
            summary.nongeneratable_sample[1],
            TargetDisabledSyscall {
                name: "syz_kfuzztest_run".to_string(),
                reason: "specialized kfuzz_test helper".to_string(),
            }
        );
    }

    #[test]
    fn smoke_config_uses_bounded_defaults() {
        let cfg = build_smoke_config(test_config(), None, None)
            .expect("default smoke config should build");

        assert_eq!(cfg.max_execs, Some(DEFAULT_SMOKE_MAX_EXECS));
        assert_eq!(cfg.target_bundle.as_deref(), Some(DEFAULT_SMOKE_BUNDLE));
        assert!(cfg.syscall_descriptions.is_none());
    }

    #[test]
    fn smoke_config_preserves_existing_target_when_not_overridden() {
        let mut cfg = test_config();
        cfg.syscall_descriptions = Some("descriptions/linux/socket-io-subset.txt".into());

        let cfg = build_smoke_config(cfg, Some(7), None)
            .expect("smoke config should preserve explicit target");

        assert_eq!(cfg.max_execs, Some(7));
        assert_eq!(
            cfg.syscall_descriptions.as_deref(),
            Some("descriptions/linux/socket-io-subset.txt")
        );
    }

    #[test]
    fn smoke_config_preserves_explicit_bundle_target() {
        let mut cfg = test_config();
        cfg.target_bundle = Some("data/target-bundles/linux-amd64-smoke.json".into());

        let cfg = build_smoke_config(cfg, Some(7), None)
            .expect("smoke config should preserve explicit bundle target");

        assert_eq!(cfg.max_execs, Some(7));
        assert_eq!(
            cfg.target_bundle.as_deref(),
            Some("data/target-bundles/linux-amd64-smoke.json")
        );
        assert!(cfg.syscall_descriptions.is_none());
    }

    #[test]
    fn smoke_suite_defaults_to_regression_targets() {
        let (max_execs, descriptions) =
            resolve_smoke_suite_args(&[]).expect("default smoke suite args should resolve");

        assert_eq!(max_execs, None);
        assert_eq!(
            descriptions,
            vec![
                "descriptions/linux/file-subset.txt".to_string(),
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
    }

    #[test]
    fn smoke_suite_parses_exec_budget_and_isolates_workdirs() {
        let (max_execs, descriptions) = resolve_smoke_suite_args(&[
            "4".to_string(),
            "descriptions/linux/mm-subset.txt".to_string(),
            "descriptions/linux/process-subset.txt".to_string(),
        ])
        .expect("custom smoke suite args should resolve");

        assert_eq!(max_execs, Some(4));
        assert_eq!(
            descriptions,
            vec![
                "descriptions/linux/mm-subset.txt".to_string(),
                "descriptions/linux/process-subset.txt".to_string(),
            ]
        );

        let mm = smoke_suite_workdir("/tmp/workdir", "descriptions/linux/mm-subset.txt");
        let proc = smoke_suite_workdir("/tmp/workdir", "descriptions/linux/process-subset.txt");

        assert_ne!(mm, proc);
        assert!(mm.starts_with("/tmp/workdir/smoke-suite"));
        assert!(proc.starts_with("/tmp/workdir/smoke-suite"));
    }

    #[test]
    fn smoke_run_label_prefers_bundle_source() {
        let metadata = derive_smoke_run_metadata(
            &test_config(),
            Some("bundle:data/target-bundles/linux-amd64-core.json"),
        )
        .expect("bundle smoke metadata should resolve");

        assert_eq!(
            metadata.target_label,
            "bundle:data/target-bundles/linux-amd64-core.json"
        );
    }

    #[test]
    fn smoke_workdir_uses_target_specific_subdirectory() {
        let metadata = derive_smoke_run_metadata(
            &test_config(),
            Some("bundle:data/target-bundles/linux-amd64-core.json"),
        )
        .expect("bundle smoke metadata should resolve");

        assert_eq!(
            metadata.workdir,
            PathBuf::from("/tmp/workdir")
                .join("smoke")
                .join("bundle-data-target-bundles-linux-amd64-core-json")
        );
    }

    #[test]
    fn smoke_summary_reports_resolved_bundle_source() {
        let mut cfg = smoke_ready_config();
        cfg.target_bundle = Some("data/target-bundles/linux-amd64-core.json".into());
        cfg.syscall_descriptions = None;
        let summary = build_smoke_summary(&cfg).expect("bundle smoke summary should build");

        assert_eq!(
            summary.descriptions,
            "bundle:data/target-bundles/linux-amd64-core.json"
        );
    }

    #[test]
    fn smoke_config_allows_explicit_target_override() {
        let cfg = build_smoke_config(
            test_config(),
            Some(9),
            Some("descriptions/linux/socket-io-subset.txt"),
        )
        .expect("smoke config should accept explicit target override");

        assert_eq!(cfg.max_execs, Some(9));
        assert_eq!(
            cfg.syscall_descriptions.as_deref(),
            Some("descriptions/linux/socket-io-subset.txt")
        );
    }

    #[test]
    fn smoke_config_cli_bundle_override_wins() {
        let cfg = build_smoke_config(
            test_config(),
            Some(5),
            Some("bundle:data/target-bundles/linux-amd64-smoke.json"),
        )
        .expect("smoke config should accept explicit bundle override");

        assert_eq!(cfg.max_execs, Some(5));
        assert_eq!(
            cfg.target_bundle.as_deref(),
            Some("data/target-bundles/linux-amd64-smoke.json")
        );
        assert!(cfg.syscall_descriptions.is_none());
    }

    #[test]
    fn smoke_config_rejects_zero_exec_budget() {
        let err = build_smoke_config(test_config(), Some(0), None)
            .expect_err("smoke config should reject zero max_execs");
        assert!(err.contains("greater than 0"));
    }

    #[test]
    fn smoke_preflight_rejects_missing_runtime_inputs() {
        let cfg = build_smoke_config(test_config(), Some(2), Some("missing.txt"))
            .expect("smoke config should build before validation");
        let err = validate_smoke_prerequisites(&cfg)
            .expect_err("preflight should reject missing smoke inputs");

        assert!(err.contains("kernel_obj"));
        assert!(err.contains("image"));
        assert!(err.contains("sshkey"));
        assert!(err.contains("executor"));
        assert!(err.contains("vm.kernel"));
        assert!(err.contains("syscall_descriptions"));
    }

    #[test]
    fn smoke_preflight_accepts_existing_runtime_inputs() {
        let cfg = smoke_ready_config();
        validate_smoke_prerequisites(&cfg)
            .expect("preflight should accept fully materialized smoke config");
    }

    #[test]
    fn smoke_summary_reports_empty_workdir_state() {
        let cfg = smoke_ready_config();
        let summary = build_smoke_summary(&cfg).expect("empty smoke summary should build");

        assert_eq!(
            summary,
            SmokeSummary {
                workdir: cfg.workdir.clone(),
                max_execs: 4,
                descriptions: cfg
                    .syscall_descriptions
                    .clone()
                    .expect("test config should retain descriptions"),
                corpus_programs: 0,
                corpus_signals: 0,
                artifacts_total: 0,
                artifacts_crashes: 0,
                artifacts_timeouts: 0,
                artifacts_skipped: 0,
                repro_queue_total: 0,
                repro_queue_claimable: 0,
                repro_queue_leased: 0,
                repro_queue_backed_off: 0,
                repro_queue_failed: 0,
                repro_queue_timed_out: 0,
                repro_queue_succeeded: 0,
            }
        );
    }
}
