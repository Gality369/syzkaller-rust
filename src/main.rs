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
mod ssh;

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::env;

const DEFAULT_TARGET_SUMMARY_LIMIT: usize = 10;

#[derive(Debug, Clone, serde::Serialize, PartialEq, Eq)]
struct TargetSummary {
    source: String,
    sample_limit: usize,
    total_syscalls: usize,
    transitively_enabled_syscalls: usize,
    transitively_generatable_syscalls: usize,
    enabled_but_not_generatable_syscalls: usize,
    explicitly_disabled_syscalls: usize,
    no_generate_syscalls: usize,
    automatic_helper_syscalls: usize,
    resource_kinds: usize,
    enabled_sample: Vec<String>,
    generatable_sample: Vec<String>,
    nongeneratable_sample: Vec<TargetDisabledSyscall>,
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

fn print_main_usage(program: &str) {
    eprintln!(
        "Usage:\n  {program} <config.json>\n  {program} target-summary [builtin|<description-path>] [limit]\n  {program} repro-queue <command> ...\n  {program} repro-worker <command> ...\n\nTarget inspection commands:\n  {program} target-summary\n  {program} target-summary builtin [limit]\n  {program} target-summary <description-path> [limit]\n\nRepro queue commands:\n  {program} repro-queue sync <workdir>\n  {program} repro-queue status <workdir> [limit]\n  {program} repro-queue peek <workdir>\n  {program} repro-queue claim <workdir> <worker_id> [lease_secs]\n  {program} repro-queue release <workdir> <artifact_type> <signature> <worker_id>\n  {program} repro-queue requeue <workdir> <artifact_type> <signature> <worker_id> <outcome>\n  {program} repro-queue attempt <workdir> <artifact_type> <signature> <outcome>\n\nRepro worker commands:\n  {program} repro-worker run-once <config.json> <worker_id> [lease_secs] [max_replay_attempts]\n  {program} repro-worker run-batch <config.json> <worker_id> [max_items] [lease_secs] [max_replay_attempts]"
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

fn build_target_summary(description_path: Option<&str>, limit: usize) -> Result<TargetSummary, String> {
    let sample_limit = limit.max(1);
    let descs = program::load_syscall_descs(description_path)?;
    let enabled = program::transitively_enabled_syscalls(&descs);
    let generatable = program::transitively_generatable_syscalls(&descs);

    let mut resource_kinds = BTreeSet::new();
    for desc in &descs {
        for arg in &desc.args {
            collect_resource_kinds(arg, &mut resource_kinds);
        }
        if let program::ReturnType::Resource(resource) = &desc.ret {
            resource_kinds.insert(resource.kind.clone());
        }
    }

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

    Ok(TargetSummary {
        source: description_path
            .map(str::to_string)
            .unwrap_or_else(|| "builtin:linux/amd64-minimal".to_string()),
        sample_limit,
        total_syscalls: descs.len(),
        transitively_enabled_syscalls: enabled.enabled.len(),
        transitively_generatable_syscalls: generatable.enabled.len(),
        enabled_but_not_generatable_syscalls: enabled.enabled.len().saturating_sub(generatable.enabled.len()),
        explicitly_disabled_syscalls,
        no_generate_syscalls,
        automatic_helper_syscalls,
        resource_kinds: resource_kinds.len(),
        enabled_sample: sample_syscall_names(&descs, &enabled.enabled, sample_limit),
        generatable_sample: sample_syscall_names(&descs, &generatable.enabled, sample_limit),
        nongeneratable_sample,
        nongeneratable_reason_counts,
    })
}

fn run_target_summary_cli(args: &[String]) -> Result<(), String> {
    if args.len() > 2 {
        return Err(
            "Usage: target-summary [builtin|<description-path>] [limit]".to_string(),
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
    use super::build_target_summary;
    use crate::program;

    #[test]
    fn target_summary_uses_builtin_target_by_default() {
        let summary = build_target_summary(None, 3).expect("builtin target summary should load");
        let descs = program::get_syscall_descs();
        let enabled = program::transitively_enabled_syscalls(&descs);
        let generatable = program::transitively_generatable_syscalls(&descs);

        assert_eq!(summary.source, "builtin:linux/amd64-minimal");
        assert_eq!(summary.total_syscalls, descs.len());
        assert_eq!(summary.transitively_enabled_syscalls, enabled.enabled.len());
        assert_eq!(summary.transitively_generatable_syscalls, generatable.enabled.len());
        assert_eq!(
            summary.enabled_but_not_generatable_syscalls,
            enabled.enabled.len().saturating_sub(generatable.enabled.len())
        );
        assert!(summary.enabled_sample.len() <= 3);
        assert!(summary.generatable_sample.len() <= 3);
        assert!(summary.nongeneratable_sample.len() <= 3);
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
        assert!(summary.nongeneratable_sample.len() <= 2);
        assert!(summary.nongeneratable_reason_counts.len() <= 2);
    }
}
