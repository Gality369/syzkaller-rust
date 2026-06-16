use crate::config::Config;
use crate::crash::{self, ArtifactReproInfo, ArtifactReproQueueEntry};
use crate::exec;
use crate::flatrpc_generated::rpc::*;
use crate::program::{self, ArgType, ArgValue, Call, Program, ResultRef, SyscallDesc};
use crate::protocol;
use crate::qemu::QemuInstance;
use crate::target;
use serde::Serialize;
use std::io;
use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::process::Child;
use std::time::{Duration, Instant};

const EXECUTOR_ACCEPT_TIMEOUT: Duration = Duration::from_secs(60);
const EXECUTOR_REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
const SSH_READY_TIMEOUT: Duration = Duration::from_secs(120);
const DEFAULT_REPRO_LEASE_SECS: u64 = 300;
const DEFAULT_REPRO_MAX_ATTEMPTS: usize = 3;

#[derive(Debug, Clone, Serialize)]
pub struct ReproReplayAttemptReport {
    pub replay_attempt_index: usize,
    pub queue_outcome: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crash_title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub executor_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub worker_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub archive_path: Option<String>,
    pub reproduced: bool,
    pub request_timed_out: bool,
    pub hanged: bool,
    pub output_len: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReproWorkerRunReport {
    pub claimed: bool,
    pub queue_attempt_number: u64,
    pub replay_attempts_planned: usize,
    pub replay_attempts_run: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub queue_outcome: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crash_title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub executor_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub worker_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repro_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result_archive_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reproduced_on_attempt: Option<usize>,
    pub reproduced: bool,
    pub request_timed_out: bool,
    pub hanged: bool,
    pub output_len: usize,
    pub used_program_ir: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attempts: Vec<ReproReplayAttemptReport>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReproWorkerBatchReport {
    pub worker_id: String,
    pub max_items: usize,
    pub claimed_items: usize,
    pub reproduced_items: usize,
    pub timed_out_items: usize,
    pub failed_items: usize,
    pub queue_drained: bool,
    pub reports: Vec<ReproWorkerRunReport>,
}

#[derive(Debug, Clone, Serialize)]
struct ReproAttemptRecord {
    timestamp_unix_secs: u64,
    worker_id: String,
    artifact_type: String,
    signature: String,
    summary: String,
    attempt_number: u64,
    replay_attempt_index: usize,
    replay_attempts_planned: usize,
    queue_outcome: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    crash_title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    executor_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    worker_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    repro_path: Option<String>,
    reproduced: bool,
    request_timed_out: bool,
    hanged: bool,
    output_len: usize,
    used_program_ir: bool,
}

#[derive(Debug, Clone)]
struct ReplayArtifact {
    repro_path: Option<String>,
    target_bundle: Option<String>,
    syscall_descriptions: Option<String>,
    program_text: String,
    program_ir: Option<Program>,
    repro_info: Option<ArtifactReproInfo>,
}

#[derive(Debug)]
struct ReplayObservation {
    reproduced: bool,
    queue_outcome: String,
    request_timed_out: bool,
    hanged: bool,
    crash_title: Option<String>,
    executor_error: Option<String>,
    worker_error: Option<String>,
    output_len: usize,
}

struct ExecutorSession {
    vm: QemuInstance,
    stream: TcpStream,
    executor_ssh: Child,
}

impl Drop for ExecutorSession {
    fn drop(&mut self) {
        let _ = self.executor_ssh.kill();
        let _ = self.executor_ssh.wait();
    }
}

pub fn default_repro_lease_secs() -> u64 {
    DEFAULT_REPRO_LEASE_SECS
}

pub fn default_repro_max_attempts() -> usize {
    DEFAULT_REPRO_MAX_ATTEMPTS
}

pub fn run_repro_worker_batch(
    cfg: Config,
    worker_id: &str,
    max_items: usize,
    lease_secs: u64,
) -> Result<ReproWorkerBatchReport, Box<dyn std::error::Error>> {
    run_repro_worker_batch_with_attempts(
        cfg,
        worker_id,
        max_items,
        lease_secs,
        default_repro_max_attempts(),
    )
}

pub fn run_repro_worker_batch_with_attempts(
    cfg: Config,
    worker_id: &str,
    max_items: usize,
    lease_secs: u64,
    max_replay_attempts: usize,
) -> Result<ReproWorkerBatchReport, Box<dyn std::error::Error>> {
    let max_items = max_items.max(1);
    let mut report = ReproWorkerBatchReport {
        worker_id: worker_id.to_string(),
        max_items,
        claimed_items: 0,
        reproduced_items: 0,
        timed_out_items: 0,
        failed_items: 0,
        queue_drained: false,
        reports: Vec::new(),
    };

    for _ in 0..max_items {
        let run_report = run_repro_worker_once_with_attempts(
            cfg.clone(),
            worker_id,
            lease_secs,
            max_replay_attempts,
        )?;
        if !run_report.claimed {
            report.queue_drained = true;
            break;
        }
        report.claimed_items += 1;
        match run_report.queue_outcome.as_deref() {
            Some("reproduced") => report.reproduced_items += 1,
            Some("timed_out") => report.timed_out_items += 1,
            Some("failed") => report.failed_items += 1,
            _ => {}
        }
        report.reports.push(run_report);
    }

    Ok(report)
}

pub fn run_repro_worker_once(
    cfg: Config,
    worker_id: &str,
    lease_secs: u64,
) -> Result<ReproWorkerRunReport, Box<dyn std::error::Error>> {
    run_repro_worker_once_with_attempts(cfg, worker_id, lease_secs, default_repro_max_attempts())
}

pub fn run_repro_worker_once_with_attempts(
    cfg: Config,
    worker_id: &str,
    lease_secs: u64,
    max_replay_attempts: usize,
) -> Result<ReproWorkerRunReport, Box<dyn std::error::Error>> {
    let _ = crash::sync_artifact_catalog(&cfg.workdir);
    let claimed = crash::claim_repro_queue_entry(&cfg.workdir, worker_id, lease_secs.max(1))?;
    let Some(entry) = claimed else {
        log::info!(
            "Repro worker {} found no claimable artifacts under {}",
            worker_id,
            cfg.workdir
        );
        return Ok(ReproWorkerRunReport {
            claimed: false,
            queue_attempt_number: 0,
            replay_attempts_planned: max_replay_attempts.max(1),
            replay_attempts_run: 0,
            artifact_type: None,
            signature: None,
            summary: None,
            queue_outcome: None,
            crash_title: None,
            executor_error: None,
            worker_error: None,
            repro_path: None,
            result_archive_path: None,
            reproduced_on_attempt: None,
            reproduced: false,
            request_timed_out: false,
            hanged: false,
            output_len: 0,
            used_program_ir: false,
            attempts: Vec::new(),
        });
    };
    log::info!(
        "Repro worker {} claimed {}:{} ({})",
        worker_id,
        entry.artifact_type,
        entry.signature,
        entry.summary
    );

    let queue_attempt_number = entry.attempts.saturating_add(1);
    let replay_attempts_planned = max_replay_attempts.max(1);
    let mut report = ReproWorkerRunReport {
        claimed: true,
        queue_attempt_number,
        replay_attempts_planned,
        replay_attempts_run: 0,
        artifact_type: Some(entry.artifact_type.clone()),
        signature: Some(entry.signature.clone()),
        summary: Some(entry.summary.clone()),
        queue_outcome: None,
        crash_title: None,
        executor_error: None,
        worker_error: None,
        repro_path: None,
        result_archive_path: None,
        reproduced_on_attempt: None,
        reproduced: false,
        request_timed_out: false,
        hanged: false,
        output_len: 0,
        used_program_ir: false,
        attempts: Vec::new(),
    };

    let artifact = match load_replay_artifact(&cfg.workdir, entry.clone()) {
        Ok(artifact) => artifact,
        Err(err) => {
            report.worker_error = Some(err.to_string());
            finish_claim(&cfg.workdir, &entry, worker_id, "failed")?;
            report.queue_outcome = Some("failed".to_string());
            return Ok(report);
        }
    };
    report.repro_path = artifact.repro_path.clone();
    log::info!(
        "Loaded replay artifact {} from {}",
        entry.signature,
        report
            .repro_path
            .as_deref()
            .unwrap_or("<program file fallback>")
    );

    let descs = match match (
        artifact.target_bundle.as_deref(),
        artifact.syscall_descriptions.as_deref(),
    ) {
        (Some(bundle), _) => target::load_target(target::TargetSource::BundlePath(bundle.into()))
            .map(|loaded| loaded.descs),
        (None, Some(path)) => {
            target::load_target(target::TargetSource::DescriptionPath(path.into()))
                .map(|loaded| loaded.descs)
        }
        (None, None) => target::load_target_from_config(&cfg, None).map(|loaded| loaded.descs),
    } {
        Ok(descs) => descs,
        Err(err) => {
            report.worker_error = Some(err);
            finish_claim(&cfg.workdir, &entry, worker_id, "failed")?;
            report.queue_outcome = Some("failed".to_string());
            return Ok(report);
        }
    };

    let (prog, used_program_ir) = match restore_program(&artifact, &descs) {
        Ok(restored) => restored,
        Err(err) => {
            report.worker_error = Some(err);
            finish_claim(&cfg.workdir, &entry, worker_id, "failed")?;
            report.queue_outcome = Some("failed".to_string());
            return Ok(report);
        }
    };
    report.used_program_ir = used_program_ir;
    log::info!(
        "Restored replay program for {} via {}",
        entry.signature,
        if used_program_ir {
            "structured program_ir"
        } else {
            "text fallback"
        }
    );

    let prog_data = match exec::serialize_program(&prog, &descs) {
        Ok(data) => data,
        Err(err) => {
            report.worker_error = Some(err.to_string());
            finish_claim(&cfg.workdir, &entry, worker_id, "failed")?;
            report.queue_outcome = Some("failed".to_string());
            return Ok(report);
        }
    };

    for replay_attempt_index in 1..=replay_attempts_planned {
        let attempt = match replay_once(&cfg, &entry, &prog_data) {
            Ok(observation) => build_replay_attempt_report(replay_attempt_index, observation),
            Err(err) => ReproReplayAttemptReport {
                replay_attempt_index,
                queue_outcome: "failed".to_string(),
                crash_title: None,
                executor_error: None,
                worker_error: Some(err.to_string()),
                archive_path: None,
                reproduced: false,
                request_timed_out: false,
                hanged: false,
                output_len: 0,
            },
        };
        let mut attempt = attempt;
        if let Err(err) = append_repro_history(
            &cfg.workdir,
            &ReproAttemptRecord {
                timestamp_unix_secs: current_unix_secs(),
                worker_id: worker_id.to_string(),
                artifact_type: entry.artifact_type.clone(),
                signature: entry.signature.clone(),
                summary: entry.summary.clone(),
                attempt_number: queue_attempt_number,
                replay_attempt_index,
                replay_attempts_planned,
                queue_outcome: attempt.queue_outcome.clone(),
                crash_title: attempt.crash_title.clone(),
                executor_error: attempt.executor_error.clone(),
                worker_error: attempt.worker_error.clone(),
                repro_path: report.repro_path.clone(),
                reproduced: attempt.reproduced,
                request_timed_out: attempt.request_timed_out,
                hanged: attempt.hanged,
                output_len: attempt.output_len,
                used_program_ir: report.used_program_ir,
            },
        ) {
            log::warn!(
                "Failed to append repro history under {}: {}",
                cfg.workdir,
                err
            );
        }
        match archive_repro_attempt(
            &cfg.workdir,
            &entry,
            worker_id,
            queue_attempt_number,
            replay_attempts_planned,
            report.repro_path.as_deref(),
            report.used_program_ir,
            &attempt,
        ) {
            Ok(path) => attempt.archive_path = Some(path),
            Err(err) => log::warn!(
                "Failed to archive replay attempt for {}:{}: {}",
                entry.artifact_type,
                entry.signature,
                err
            ),
        }
        let stop_after_attempt = attempt.reproduced;
        report.attempts.push(attempt);
        if stop_after_attempt {
            report.reproduced_on_attempt = Some(replay_attempt_index);
            break;
        }
    }

    report.replay_attempts_run = report.attempts.len();
    let final_attempt = select_preferred_replay_attempt(&report.attempts)
        .cloned()
        .unwrap_or_else(|| ReproReplayAttemptReport {
            replay_attempt_index: 1,
            queue_outcome: "failed".to_string(),
            crash_title: None,
            executor_error: None,
            worker_error: Some("no replay attempts executed".to_string()),
            archive_path: None,
            reproduced: false,
            request_timed_out: false,
            hanged: false,
            output_len: 0,
        });

    finish_claim(
        &cfg.workdir,
        &entry,
        worker_id,
        &final_attempt.queue_outcome,
    )?;
    report.queue_outcome = Some(final_attempt.queue_outcome.clone());
    report.crash_title = final_attempt.crash_title.clone();
    report.executor_error = final_attempt.executor_error.clone();
    report.worker_error = final_attempt.worker_error.clone();
    report.reproduced = final_attempt.reproduced;
    report.request_timed_out = final_attempt.request_timed_out;
    report.hanged = final_attempt.hanged;
    report.output_len = final_attempt.output_len;
    if let Err(err) = archive_repro_result(&cfg.workdir, &entry, queue_attempt_number, &report) {
        log::warn!(
            "Failed to archive replay result for {}:{}: {}",
            entry.artifact_type,
            entry.signature,
            err
        );
    } else {
        report.result_archive_path =
            Some(repro_result_archive_rel_path(&entry, queue_attempt_number));
    }
    if let Err(err) = write_latest_artifact_repro_result(&cfg.workdir, &entry, &report) {
        log::warn!(
            "Failed to update latest artifact replay result for {}:{}: {}",
            entry.artifact_type,
            entry.signature,
            err
        );
    }
    if let Err(err) = write_latest_minimize_seed(
        &cfg.workdir,
        &entry,
        &artifact,
        &cfg,
        &prog,
        &descs,
        &report,
    ) {
        log::warn!(
            "Failed to update latest minimization seed for {}:{}: {}",
            entry.artifact_type,
            entry.signature,
            err
        );
    }
    log::info!(
        "Replay outcome for {}:{} => {} (reproduced={}, timed_out={}, hanged={}, output_len={})",
        entry.artifact_type,
        entry.signature,
        report.queue_outcome.as_deref().unwrap_or("unknown"),
        report.reproduced,
        report.request_timed_out,
        report.hanged,
        report.output_len
    );
    Ok(report)
}

fn finish_claim(
    workdir: &str,
    entry: &ArtifactReproQueueEntry,
    worker_id: &str,
    outcome: &str,
) -> io::Result<()> {
    if crash::requeue_repro_queue_claim(
        workdir,
        &entry.artifact_type,
        &entry.signature,
        worker_id,
        outcome,
    )? {
        Ok(())
    } else {
        crash::release_repro_queue_claim(workdir, &entry.artifact_type, &entry.signature, worker_id)
            .map(|_| ())
    }
}

fn build_replay_attempt_report(
    replay_attempt_index: usize,
    observation: ReplayObservation,
) -> ReproReplayAttemptReport {
    ReproReplayAttemptReport {
        replay_attempt_index,
        queue_outcome: observation.queue_outcome,
        crash_title: observation.crash_title,
        executor_error: observation.executor_error,
        worker_error: observation.worker_error,
        archive_path: None,
        reproduced: observation.reproduced,
        request_timed_out: observation.request_timed_out,
        hanged: observation.hanged,
        output_len: observation.output_len,
    }
}

fn replay_attempt_rank(attempt: &ReproReplayAttemptReport) -> u8 {
    if attempt.reproduced {
        3
    } else if attempt.request_timed_out || attempt.hanged || attempt.queue_outcome == "timed_out" {
        2
    } else {
        1
    }
}

fn select_preferred_replay_attempt(
    attempts: &[ReproReplayAttemptReport],
) -> Option<&ReproReplayAttemptReport> {
    attempts.iter().max_by(|left, right| {
        replay_attempt_rank(left)
            .cmp(&replay_attempt_rank(right))
            .then_with(|| left.replay_attempt_index.cmp(&right.replay_attempt_index))
    })
}

fn repro_run_claim_rel_dir(entry: &ArtifactReproQueueEntry, queue_attempt_number: u64) -> String {
    format!(
        "repro_runs/{}_{}/queue-attempt-{:06}",
        entry.artifact_type, entry.signature, queue_attempt_number
    )
}

fn repro_attempt_archive_rel_path(
    entry: &ArtifactReproQueueEntry,
    queue_attempt_number: u64,
    replay_attempt_index: usize,
) -> String {
    format!(
        "{}/replay-{:04}.json",
        repro_run_claim_rel_dir(entry, queue_attempt_number),
        replay_attempt_index
    )
}

fn repro_result_archive_rel_path(
    entry: &ArtifactReproQueueEntry,
    queue_attempt_number: u64,
) -> String {
    format!(
        "{}/result.json",
        repro_run_claim_rel_dir(entry, queue_attempt_number)
    )
}

fn archive_repro_attempt(
    workdir: &str,
    entry: &ArtifactReproQueueEntry,
    worker_id: &str,
    queue_attempt_number: u64,
    replay_attempts_planned: usize,
    repro_path: Option<&str>,
    used_program_ir: bool,
    attempt: &ReproReplayAttemptReport,
) -> io::Result<String> {
    #[derive(Serialize)]
    struct ArchivedReproAttempt<'a> {
        timestamp_unix_secs: u64,
        worker_id: &'a str,
        artifact_type: &'a str,
        signature: &'a str,
        summary: &'a str,
        queue_attempt_number: u64,
        replay_attempts_planned: usize,
        #[serde(skip_serializing_if = "Option::is_none")]
        repro_path: Option<&'a str>,
        used_program_ir: bool,
        #[serde(flatten)]
        attempt: &'a ReproReplayAttemptReport,
    }

    let relative =
        repro_attempt_archive_rel_path(entry, queue_attempt_number, attempt.replay_attempt_index);
    let path = std::path::Path::new(workdir).join(&relative);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let archived = ArchivedReproAttempt {
        timestamp_unix_secs: current_unix_secs(),
        worker_id,
        artifact_type: &entry.artifact_type,
        signature: &entry.signature,
        summary: &entry.summary,
        queue_attempt_number,
        replay_attempts_planned,
        repro_path,
        used_program_ir,
        attempt,
    };
    let data = serde_json::to_vec_pretty(&archived)?;
    std::fs::write(path, data)?;
    Ok(relative)
}

fn archive_repro_result(
    workdir: &str,
    entry: &ArtifactReproQueueEntry,
    queue_attempt_number: u64,
    report: &ReproWorkerRunReport,
) -> io::Result<()> {
    let relative = repro_result_archive_rel_path(entry, queue_attempt_number);
    let path = std::path::Path::new(workdir).join(relative);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let data = serde_json::to_vec_pretty(report)?;
    std::fs::write(path, data)
}

fn write_latest_artifact_repro_result(
    workdir: &str,
    entry: &ArtifactReproQueueEntry,
    report: &ReproWorkerRunReport,
) -> io::Result<()> {
    #[derive(Serialize)]
    struct LatestArtifactReproResult<'a> {
        version: u32,
        timestamp_unix_secs: u64,
        artifact_type: &'a str,
        signature: &'a str,
        summary: &'a str,
        queue_attempt_number: u64,
        replay_attempts_planned: usize,
        replay_attempts_run: usize,
        #[serde(skip_serializing_if = "Option::is_none")]
        queue_outcome: Option<&'a str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        crash_title: Option<&'a str>,
        reproduced: bool,
        request_timed_out: bool,
        hanged: bool,
        output_len: usize,
        used_program_ir: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        reproduced_on_attempt: Option<usize>,
        #[serde(skip_serializing_if = "Option::is_none")]
        result_archive_path: Option<&'a str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        best_attempt_archive_path: Option<&'a str>,
    }

    let best_attempt_archive_path = select_preferred_replay_attempt(&report.attempts)
        .and_then(|attempt| attempt.archive_path.as_deref());
    let path = std::path::Path::new(workdir)
        .join(&entry.directory)
        .join("latest_repro_result.json");
    let latest = LatestArtifactReproResult {
        version: 1,
        timestamp_unix_secs: current_unix_secs(),
        artifact_type: &entry.artifact_type,
        signature: &entry.signature,
        summary: &entry.summary,
        queue_attempt_number: report.queue_attempt_number,
        replay_attempts_planned: report.replay_attempts_planned,
        replay_attempts_run: report.replay_attempts_run,
        queue_outcome: report.queue_outcome.as_deref(),
        crash_title: report.crash_title.as_deref(),
        reproduced: report.reproduced,
        request_timed_out: report.request_timed_out,
        hanged: report.hanged,
        output_len: report.output_len,
        used_program_ir: report.used_program_ir,
        reproduced_on_attempt: report.reproduced_on_attempt,
        result_archive_path: report.result_archive_path.as_deref(),
        best_attempt_archive_path,
    };
    let data = serde_json::to_vec_pretty(&latest)?;
    std::fs::write(path, data)
}

fn format_program_description(prog: &Program, descs: &[SyscallDesc]) -> String {
    prog.calls
        .iter()
        .enumerate()
        .map(|(call_idx, call)| {
            let name = descs
                .get(call.syscall_idx)
                .map(|desc| desc.name.as_str())
                .unwrap_or("<unknown>");
            let args = call
                .args
                .iter()
                .zip(
                    descs
                        .get(call.syscall_idx)
                        .map(|desc| desc.args.iter())
                        .into_iter()
                        .flatten(),
                )
                .map(|(arg, arg_type)| format_program_arg(arg, arg_type))
                .collect::<Vec<_>>()
                .join(", ");
            format!("{call_idx}. {name}({args})")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn format_program_arg(arg: &ArgValue, arg_type: &ArgType) -> String {
    match arg {
        ArgValue::Const(value) => format!("0x{value:x}"),
        ArgValue::ResultRef(ResultRef {
            call_idx,
            result_idx,
        }) => format!("result_from_call_{call_idx}_{result_idx}"),
        ArgValue::Filename(name) => format!("{name:?}"),
        ArgValue::Buffer(data) => format!("buf[{}]", data.len()),
        ArgValue::Composite { data, pointers, .. } => {
            format!("obj[{};+{}ptr]", data.len(), pointers.len())
        }
        ArgValue::Array {
            data,
            pointers,
            element_sizes,
            ..
        } => format!(
            "arr[{};+{}ptr;{}elts]",
            data.len(),
            pointers.len(),
            element_sizes.len()
        ),
        ArgValue::Vma { addr, size } if matches!(arg_type, ArgType::Vma { .. }) => {
            format!("&(0x{addr:x}/0x{size:x})")
        }
        ArgValue::Vma { addr, .. } => format!("0x{addr:x}"),
        ArgValue::Null => "NULL".to_string(),
        ArgValue::OutPtr => "&out".to_string(),
    }
}

fn build_latest_minimize_seed_repro_info(
    cfg: &Config,
    entry: &ArtifactReproQueueEntry,
    artifact: &ReplayArtifact,
    prog: &Program,
    descs: &[SyscallDesc],
) -> ArtifactReproInfo {
    let mut repro = artifact
        .repro_info
        .clone()
        .unwrap_or_else(|| ArtifactReproInfo {
            artifact_type: entry.artifact_type.clone(),
            summary: entry.summary.clone(),
            signature: entry.signature.clone(),
            manager_instance: 0,
            total_execs: 0,
            target_bundle: cfg.target_bundle.clone(),
            syscall_descriptions: cfg.syscall_descriptions.clone(),
            executor: cfg.executor.clone(),
            sandbox: cfg.sandbox.clone(),
            procs: cfg.procs,
            cover: cfg.cover,
            syscall_timeout_ms: cfg.syscall_timeout_ms,
            program_timeout_ms: cfg.program_timeout_ms,
            slowdown: cfg.slowdown,
            vm_count: cfg.vm.count,
            vm_cpu: cfg.vm.cpu,
            vm_mem: cfg.vm.mem,
            vm_qemu: cfg.vm.qemu.clone(),
            vm_kernel: cfg.vm.kernel.clone(),
            vm_image: cfg.image.clone(),
            vm_cmdline: cfg.vm.cmdline.clone(),
            program: String::new(),
            program_ir: None,
            shape: None,
            profile: None,
        });
    repro.artifact_type = entry.artifact_type.clone();
    repro.summary = entry.summary.clone();
    repro.signature = entry.signature.clone();
    repro.target_bundle = repro.target_bundle.or_else(|| cfg.target_bundle.clone());
    repro.syscall_descriptions = repro
        .syscall_descriptions
        .or_else(|| cfg.syscall_descriptions.clone());
    repro.program = format_program_description(prog, descs);
    repro.program_ir = Some(prog.clone());
    repro
}

fn write_latest_minimize_seed(
    workdir: &str,
    entry: &ArtifactReproQueueEntry,
    artifact: &ReplayArtifact,
    cfg: &Config,
    prog: &Program,
    descs: &[SyscallDesc],
    report: &ReproWorkerRunReport,
) -> io::Result<()> {
    #[derive(Serialize)]
    struct LatestMinimizeSeed {
        version: u32,
        timestamp_unix_secs: u64,
        artifact_type: String,
        summary: String,
        normalized_summary: String,
        signature: String,
        queue_attempt_number: u64,
        replay_attempts_planned: usize,
        replay_attempts_run: usize,
        final_queue_outcome: Option<String>,
        eligible_for_minimization: bool,
        reproduced_on_attempt: Option<usize>,
        result_archive_path: Option<String>,
        best_attempt_archive_path: Option<String>,
        source_repro_path: Option<String>,
        repro: ArtifactReproInfo,
    }

    let best_attempt_archive_path = select_preferred_replay_attempt(&report.attempts)
        .and_then(|attempt| attempt.archive_path.clone());
    let seed = LatestMinimizeSeed {
        version: 1,
        timestamp_unix_secs: current_unix_secs(),
        artifact_type: entry.artifact_type.clone(),
        summary: entry.summary.clone(),
        normalized_summary: entry.normalized_summary.clone(),
        signature: entry.signature.clone(),
        queue_attempt_number: report.queue_attempt_number,
        replay_attempts_planned: report.replay_attempts_planned,
        replay_attempts_run: report.replay_attempts_run,
        final_queue_outcome: report.queue_outcome.clone(),
        eligible_for_minimization: matches!(
            report.queue_outcome.as_deref(),
            Some("reproduced") | Some("timed_out")
        ),
        reproduced_on_attempt: report.reproduced_on_attempt,
        result_archive_path: report.result_archive_path.clone(),
        best_attempt_archive_path,
        source_repro_path: report.repro_path.clone(),
        repro: build_latest_minimize_seed_repro_info(cfg, entry, artifact, prog, descs),
    };
    let path = std::path::Path::new(workdir)
        .join(&entry.directory)
        .join("latest_minimize_seed.json");
    let data = serde_json::to_vec_pretty(&seed)?;
    std::fs::write(path, data)
}

fn load_replay_artifact(
    workdir: &str,
    entry: ArtifactReproQueueEntry,
) -> io::Result<ReplayArtifact> {
    let workdir = std::path::Path::new(workdir);
    let repro_path = entry
        .preferred_repro_path
        .as_ref()
        .map(|path| workdir.join(path));
    if let Some(path) = repro_path.as_ref().filter(|path| path.exists()) {
        let data = std::fs::read(path)?;
        let repro = serde_json::from_slice::<ArtifactReproInfo>(&data).map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("failed to parse repro info {}: {}", path.display(), err),
            )
        })?;
        let target_bundle = repro.target_bundle.clone();
        let syscall_descriptions = repro.syscall_descriptions.clone();
        let program_text = repro.program.clone();
        let program_ir = repro.program_ir.clone();
        return Ok(ReplayArtifact {
            repro_path: Some(path.display().to_string()),
            target_bundle,
            syscall_descriptions,
            program_text,
            program_ir,
            repro_info: Some(repro),
        });
    }

    let program_path = workdir.join(&entry.preferred_program_path);
    let program_text = std::fs::read_to_string(&program_path)?;
    Ok(ReplayArtifact {
        repro_path: None,
        target_bundle: None,
        syscall_descriptions: None,
        program_text,
        program_ir: None,
        repro_info: None,
    })
}

fn restore_program(
    artifact: &ReplayArtifact,
    descs: &[SyscallDesc],
) -> Result<(Program, bool), String> {
    if let Some(prog) = artifact.program_ir.clone() {
        prog.validate(descs).map_err(|err| err.to_string())?;
        return Ok((prog, true));
    }
    let prog = parse_program_description(&artifact.program_text, descs)?;
    prog.validate(descs).map_err(|err| err.to_string())?;
    Ok((prog, false))
}

fn parse_program_description(text: &str, descs: &[SyscallDesc]) -> Result<Program, String> {
    let mut calls = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let (_, tail) = line
            .split_once(". ")
            .ok_or_else(|| format!("invalid program line: {}", line))?;
        let open = tail
            .find('(')
            .ok_or_else(|| format!("missing '(' in program line: {}", line))?;
        let close = tail
            .rfind(')')
            .ok_or_else(|| format!("missing ')' in program line: {}", line))?;
        let name = tail[..open].trim();
        let args_str = &tail[open + 1..close];
        let syscall_idx = descs
            .iter()
            .position(|desc| desc.name == name)
            .ok_or_else(|| format!("unknown syscall in replay program: {}", name))?;
        let desc = &descs[syscall_idx];
        let args = parse_program_args(args_str, &desc.args)?;
        calls.push(Call { syscall_idx, args });
    }
    Ok(Program { calls })
}

fn parse_program_args(args: &str, arg_types: &[ArgType]) -> Result<Vec<ArgValue>, String> {
    if args.trim() == "..." {
        return Ok(arg_types
            .iter()
            .map(default_arg_value_for_type)
            .collect::<Result<Vec<_>, _>>()?);
    }

    let arg_tokens = split_program_args(args);
    if arg_tokens.len() != arg_types.len() {
        return Err(format!(
            "argument count mismatch: expected {}, got {} in {}",
            arg_types.len(),
            arg_tokens.len(),
            args
        ));
    }
    arg_tokens
        .iter()
        .zip(arg_types.iter())
        .map(|(token, arg_type)| parse_program_arg_for_type(token, arg_type))
        .collect()
}

fn split_program_args(args: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    for ch in args.chars() {
        match ch {
            '"' => {
                in_quotes = !in_quotes;
                current.push(ch);
            }
            ',' if !in_quotes => {
                let token = current.trim();
                if !token.is_empty() {
                    tokens.push(token.to_string());
                }
                current.clear();
            }
            _ => current.push(ch),
        }
    }
    let token = current.trim();
    if !token.is_empty() {
        tokens.push(token.to_string());
    }
    tokens
}

fn parse_program_arg_for_type(token: &str, arg_type: &ArgType) -> Result<ArgValue, String> {
    if token == "..." {
        return default_arg_value_for_type(arg_type);
    }
    if token == "NULL" {
        return Ok(ArgValue::Null);
    }
    if token == "&out" {
        return Ok(ArgValue::OutPtr);
    }
    if let Some(rest) = token.strip_prefix("result_from_call_") {
        let mut parts = rest.split('_');
        let call_idx = parts
            .next()
            .ok_or_else(|| format!("invalid result ref: {}", token))?
            .parse::<usize>()
            .map_err(|err| format!("invalid result ref call index in {}: {}", token, err))?;
        let result_idx = parts
            .next()
            .ok_or_else(|| format!("invalid result ref: {}", token))?
            .parse::<usize>()
            .map_err(|err| format!("invalid result ref slot in {}: {}", token, err))?;
        return Ok(ArgValue::ResultRef(ResultRef {
            call_idx,
            result_idx,
        }));
    }
    if let Some(rest) = token
        .strip_prefix("buf[")
        .and_then(|rest| rest.strip_suffix(']'))
    {
        let len = rest
            .parse::<usize>()
            .map_err(|err| format!("invalid buffer length in {}: {}", token, err))?;
        return Ok(ArgValue::Buffer(vec![0; len]));
    }
    if token.starts_with('"') && token.ends_with('"') && token.len() >= 2 {
        return match arg_type {
            ArgType::String { noz, fixed_len, .. } => {
                Ok(ArgValue::Buffer(materialize_repro_string_bytes(
                    token[1..token.len() - 1].as_bytes().to_vec(),
                    *noz,
                    *fixed_len,
                )))
            }
            _ => Ok(ArgValue::Filename(token[1..token.len() - 1].to_string())),
        };
    }
    if let ArgType::Vma { .. } = arg_type {
        if let Some(inner) = token
            .strip_prefix("&(")
            .and_then(|rest| rest.strip_suffix(')'))
        {
            let (addr, size) = inner
                .split_once('/')
                .ok_or_else(|| format!("invalid vma address syntax: {}", token))?;
            let addr = parse_program_u64(addr.trim())?;
            let size = parse_program_u64(size.trim())?;
            return Ok(ArgValue::Vma { addr, size });
        }
    }
    if let Some(rest) = token.strip_prefix("0x") {
        let value = u64::from_str_radix(rest, 16)
            .map_err(|err| format!("invalid hex constant in {}: {}", token, err))?;
        return Ok(ArgValue::Const(value));
    }
    let value = token
        .parse::<u64>()
        .map_err(|err| format!("invalid constant {}: {}", token, err))?;
    Ok(ArgValue::Const(value))
}

fn default_arg_value_for_type(arg_type: &ArgType) -> Result<ArgValue, String> {
    match arg_type {
        ArgType::Const { range, values, .. } => Ok(ArgValue::Const(
            values
                .first()
                .copied()
                .or_else(|| range.map(|(min, _)| min))
                .unwrap_or(0),
        )),
        ArgType::Proc { .. } => Ok(ArgValue::Const(0)),
        ArgType::Resource(resource) | ArgType::OptionalResource(resource) => {
            Ok(ArgValue::Const(resource.default_value()))
        }
        ArgType::Len { .. } => Ok(ArgValue::Const(0)),
        ArgType::Filename => Ok(ArgValue::Filename("repro".to_string())),
        ArgType::String {
            values,
            noz,
            fixed_len,
            filename,
        } => Ok(ArgValue::Buffer(default_string_buffer(
            values, *noz, *fixed_len, *filename,
        ))),
        ArgType::Void => Ok(ArgValue::Buffer(Vec::new())),
        ArgType::Buffer { min_size, .. } => Ok(ArgValue::Buffer(vec![0; *min_size])),
        ArgType::Struct { size, .. } => Ok(ArgValue::Buffer(vec![0; *size])),
        ArgType::Union {
            fields,
            size,
            varlen,
            ..
        } => Ok(ArgValue::Buffer(default_union_buffer(
            fields, *size, *varlen,
        ))),
        ArgType::Vma {
            min_pages,
            max_pages,
            optional,
        } => {
            if *optional {
                Ok(ArgValue::Null)
            } else {
                let pages = (*min_pages).max(1).min(*max_pages) as u64;
                Ok(ArgValue::Vma {
                    addr: program::DATA_OFFSET
                        + program::VMA_RESERVED_START_PAGE * program::PAGE_SIZE,
                    size: pages * program::PAGE_SIZE,
                })
            }
        }
        ArgType::Array { .. } => Ok(ArgValue::Buffer(default_buffer_for_inner(arg_type)?)),
        ArgType::Ptr {
            inner,
            dir,
            optional,
        } => {
            if *optional {
                return Ok(ArgValue::Null);
            }
            match dir {
                program::PtrDir::Out => Ok(ArgValue::OutPtr),
                program::PtrDir::In | program::PtrDir::InOut => {
                    Ok(ArgValue::Buffer(default_buffer_for_inner(inner)?))
                }
            }
        }
    }
}

fn default_buffer_for_inner(arg_type: &ArgType) -> Result<Vec<u8>, String> {
    match arg_type {
        ArgType::Buffer { min_size, .. } => Ok(vec![0; *min_size]),
        ArgType::Proc {
            size,
            values_start,
            endian,
            ..
        } => Ok(program::encode_scalar_bytes_endian(
            *size,
            *values_start,
            *endian,
        )),
        ArgType::String {
            values,
            noz,
            fixed_len,
            filename,
        } => Ok(default_string_buffer(values, *noz, *fixed_len, *filename)),
        ArgType::Void => Ok(Vec::new()),
        ArgType::Struct { size, .. } => Ok(vec![0; *size]),
        ArgType::Union {
            fields,
            size,
            varlen,
            ..
        } => Ok(default_union_buffer(fields, *size, *varlen)),
        ArgType::Array {
            inner,
            min_len,
            max_len: _,
        } => {
            let element = default_buffer_for_inner(inner)?;
            let mut data = Vec::with_capacity(element.len().saturating_mul(*min_len));
            for _ in 0..*min_len {
                data.extend_from_slice(&element);
            }
            Ok(data)
        }
        ArgType::Len { size, .. } => Ok(vec![0; *size]),
        ArgType::Filename => {
            let mut bytes = b"repro".to_vec();
            bytes.push(0);
            Ok(bytes)
        }
        ArgType::Vma { .. } => Ok(vec![0; 8]),
        ArgType::Const { size, .. }
        | ArgType::Resource(program::ResourceDesc { size, .. })
        | ArgType::OptionalResource(program::ResourceDesc { size, .. }) => Ok(vec![0; *size]),
        ArgType::Ptr { inner, .. } => default_buffer_for_inner(inner),
    }
}

fn default_union_buffer(fields: &[ArgType], size: usize, varlen: bool) -> Vec<u8> {
    if !varlen {
        return vec![0; size];
    }
    fields
        .first()
        .and_then(program::arg_type_fixed_size)
        .map(|field_size| vec![0; field_size])
        .unwrap_or_else(|| vec![0; size])
}

fn default_string_buffer(
    values: &[Vec<u8>],
    noz: bool,
    fixed_len: Option<usize>,
    filename: bool,
) -> Vec<u8> {
    let source = if filename {
        b"./a".to_vec()
    } else if let Some(value) = values.first() {
        value.clone()
    } else {
        b"repro".to_vec()
    };
    materialize_repro_string_bytes(source, noz, fixed_len)
}

fn materialize_repro_string_bytes(
    mut source: Vec<u8>,
    noz: bool,
    fixed_len: Option<usize>,
) -> Vec<u8> {
    if let Some(limit) = fixed_len {
        let content_limit = if noz { limit } else { limit.saturating_sub(1) };
        if source.len() > content_limit {
            source.truncate(content_limit);
        }
    }
    if !noz {
        source.push(0);
    }
    if let Some(limit) = fixed_len {
        source.resize(limit, 0);
    }
    source
}

fn parse_program_u64(token: &str) -> Result<u64, String> {
    if let Some(rest) = token.strip_prefix("0x") {
        u64::from_str_radix(rest, 16)
            .map_err(|err| format!("invalid hex constant in {}: {}", token, err))
    } else {
        token
            .parse::<u64>()
            .map_err(|err| format!("invalid constant {}: {}", token, err))
    }
}

fn current_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn append_repro_history(workdir: &str, record: &ReproAttemptRecord) -> io::Result<()> {
    let path = std::path::Path::new(workdir).join("repro_history.jsonl");
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    serde_json::to_writer(&mut file, record)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
    file.write_all(b"\n")?;
    file.flush()
}

fn replay_once(
    cfg: &Config,
    entry: &ArtifactReproQueueEntry,
    prog_data: &[u8],
) -> Result<ReplayObservation, Box<dyn std::error::Error>> {
    let mut session = start_executor_session(cfg, 0)?;
    protocol::send_corpus_triaged(&mut session.stream)?;

    let mut env_flags = ExecEnv::SandboxNone;
    if cfg.cover {
        env_flags |= ExecEnv::Signal;
    }
    let exec_flags = ExecFlag::CollectSignal;
    let request_flags = RequestFlag::ReturnError | RequestFlag::ReturnOutput;
    protocol::send_exec_request(
        &mut session.stream,
        0,
        prog_data,
        env_flags,
        exec_flags,
        request_flags,
        0,
        &[],
    )?;

    let start = Instant::now();
    loop {
        if start.elapsed() > EXECUTOR_REQUEST_TIMEOUT {
            let serial = session.vm.get_serial_output();
            let crash_title = crash::detect_crash(&serial);
            return Ok(classify_observation(
                entry,
                true,
                false,
                crash_title,
                None,
                0,
            ));
        }

        let msg = match protocol::recv_executor_message(&mut session.stream) {
            Ok(msg) => msg,
            Err(err)
                if err.kind() == io::ErrorKind::WouldBlock
                    || err.kind() == io::ErrorKind::TimedOut =>
            {
                continue;
            }
            Err(err) => {
                let serial = session.vm.get_serial_output();
                let crash_title = crash::detect_crash(&serial);
                if crash_title.is_some() {
                    return Ok(classify_observation(
                        entry,
                        false,
                        false,
                        crash_title,
                        None,
                        0,
                    ));
                }
                return Err(err.into());
            }
        };

        match msg {
            protocol::ExecutorMsg::Executing(_) | protocol::ExecutorMsg::State(_) => continue,
            protocol::ExecutorMsg::ExecResult(result) => {
                let serial = session.vm.get_serial_output();
                let crash_title =
                    crash::detect_crash(&result.output).or_else(|| crash::detect_crash(&serial));
                let executor_error = (!result.error.is_empty()).then_some(result.error);
                return Ok(classify_observation(
                    entry,
                    false,
                    result.hanged,
                    crash_title,
                    executor_error,
                    result.output.len(),
                ));
            }
        }
    }
}

fn classify_observation(
    entry: &ArtifactReproQueueEntry,
    request_timed_out: bool,
    hanged: bool,
    crash_title: Option<String>,
    executor_error: Option<String>,
    output_len: usize,
) -> ReplayObservation {
    let reproduced = match entry.artifact_type.as_str() {
        "timeout" => request_timed_out || hanged,
        "crash" => crash_title
            .as_deref()
            .is_some_and(|title| crash_title_matches_artifact(entry, title)),
        _ => false,
    };
    let queue_outcome = if reproduced {
        "reproduced"
    } else if request_timed_out || hanged {
        "timed_out"
    } else {
        "failed"
    };
    ReplayObservation {
        reproduced,
        queue_outcome: queue_outcome.to_string(),
        request_timed_out,
        hanged,
        crash_title,
        executor_error,
        output_len,
        worker_error: None,
    }
}

fn crash_title_matches_artifact(entry: &ArtifactReproQueueEntry, title: &str) -> bool {
    let expected = if entry.normalized_summary.is_empty() {
        crash::normalize_summary(&entry.summary)
    } else {
        entry.normalized_summary.clone()
    };
    crash::normalize_summary(title) == expected
}

fn start_executor_session(
    cfg: &Config,
    vm_index: usize,
) -> Result<ExecutorSession, Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let flatrpc_port = listener.local_addr()?.port();

    log::info!("Starting replay VM instance {}", vm_index);
    let mut vm = QemuInstance::start(cfg, vm_index)?;
    vm.wait_ssh(cfg, SSH_READY_TIMEOUT)?;
    log::info!("Replay VM {} SSH ready", vm_index);
    vm.scp(cfg, &cfg.executor, "/tmp/syz-executor")?;
    log::info!("Replay VM {} executor copied", vm_index);

    let executor_cmd = format!(
        "chmod +x /tmp/syz-executor && /tmp/syz-executor runner {} localhost {}",
        vm_index, flatrpc_port
    );
    let executor_ssh = vm.run_with_forward(cfg, flatrpc_port, &executor_cmd)?;
    log::info!("Replay VM {} executor started", vm_index);

    listener.set_nonblocking(true)?;
    let accept_start = Instant::now();
    let mut stream = loop {
        match listener.accept() {
            Ok((stream, _addr)) => {
                stream.set_nonblocking(false)?;
                stream.set_read_timeout(Some(Duration::from_secs(5)))?;
                stream.set_write_timeout(Some(Duration::from_secs(30)))?;
                log::info!("Replay VM {} executor connected", vm_index);
                break stream;
            }
            Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => {
                if accept_start.elapsed() > EXECUTOR_ACCEPT_TIMEOUT {
                    return Err("executor connection timed out".into());
                }
                if !vm.is_running() {
                    let serial = vm.get_serial_output();
                    let serial_str = String::from_utf8_lossy(&serial);
                    return Err(format!(
                        "VM died before executor connected. Serial:\n{}",
                        &serial_str[serial_str.len().saturating_sub(2000)..]
                    )
                    .into());
                }
                std::thread::sleep(Duration::from_millis(200));
            }
            Err(err) => return Err(err.into()),
        }
    };

    do_handshake(&mut stream, cfg)?;
    log::info!("Replay VM {} handshake complete", vm_index);
    Ok(ExecutorSession {
        vm,
        stream,
        executor_ssh,
    })
}

fn do_handshake(stream: &mut TcpStream, cfg: &Config) -> Result<(), Box<dyn std::error::Error>> {
    let cookie: u64 = rand::random();
    protocol::send_connect_hello(stream, cookie)?;

    let connect_req = protocol::recv_connect_request(stream)?;
    let expected = protocol::auth_hash(cookie);
    if connect_req.cookie != expected {
        return Err(format!(
            "Auth failed: expected cookie 0x{:x}, got 0x{:x}",
            expected, connect_req.cookie
        )
        .into());
    }

    let features = Feature::Coverage | Feature::SandboxNone;
    protocol::send_connect_reply(
        stream,
        false,
        cfg.cover,
        true,
        true,
        cfg.procs,
        cfg.slowdown,
        cfg.syscall_timeout_ms,
        cfg.program_timeout_ms,
        features,
        &[],
        &[],
        &[],
    )?;

    let info_req = protocol::recv_info_request(stream)?;
    if !info_req.error.is_empty() {
        log::warn!(
            "Executor reported error during replay handshake: {}",
            info_req.error
        );
    }
    protocol::send_info_reply(stream, &[])?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        append_repro_history, archive_repro_attempt, archive_repro_result,
        build_latest_minimize_seed_repro_info, classify_observation, format_program_description,
        parse_program_description, repro_attempt_archive_rel_path, repro_result_archive_rel_path,
        restore_program, select_preferred_replay_attempt, write_latest_artifact_repro_result,
        write_latest_minimize_seed, ReplayArtifact, ReproAttemptRecord, ReproReplayAttemptReport,
        ReproWorkerBatchReport, ReproWorkerRunReport,
    };
    use crate::config::{Config, VmConfig};
    use crate::crash::ArtifactReproQueueEntry;
    use crate::program::{load_syscall_descs, ArgValue, Call, Program, ResultRef};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn socket_subset_descs() -> Vec<crate::program::SyscallDesc> {
        load_syscall_descs(Some("descriptions/linux/socket-subset.txt"))
            .expect("socket subset descriptions should parse")
    }

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

    #[test]
    fn parse_program_description_restores_described_calls() {
        let descs = socket_subset_descs();
        let text = concat!(
            "0. socket$inet(0x2, 0x1, 0x0)\n",
            "1. connect$inet(result_from_call_0_0, buf[16], 0x10)\n",
            "2. accept$inet(result_from_call_0_0, &out, buf[4])\n"
        );
        let prog = parse_program_description(text, &descs).expect("program text should parse");
        assert_eq!(prog.calls.len(), 3);
        assert_eq!(descs[prog.calls[0].syscall_idx].name, "socket$inet");
        assert_eq!(
            prog.calls[1].args[0],
            ArgValue::ResultRef(ResultRef {
                call_idx: 0,
                result_idx: 0
            })
        );
        assert_eq!(prog.calls[1].args[1], ArgValue::Buffer(vec![0; 16]));
        assert_eq!(prog.calls[2].args[1], ArgValue::OutPtr);
    }

    #[test]
    fn parse_program_description_expands_ellipsis_to_default_args() {
        let descs = socket_subset_descs();
        let text = concat!("0. listen(...)\n", "1. connect$inet(...)\n");
        let prog = parse_program_description(text, &descs).expect("ellipsis program should parse");
        assert_eq!(prog.calls.len(), 2);
        assert_eq!(descs[prog.calls[0].syscall_idx].name, "listen");
        assert_eq!(prog.calls[0].args.len(), 2);
        assert_eq!(prog.calls[0].args[0], ArgValue::Const(u64::MAX));
        assert_eq!(prog.calls[0].args[1], ArgValue::Const(0));
        assert_eq!(descs[prog.calls[1].syscall_idx].name, "connect$inet");
        assert_eq!(prog.calls[1].args.len(), 3);
    }

    #[test]
    fn restore_program_prefers_structured_ir_when_available() {
        let descs = socket_subset_descs();
        let prog = Program {
            calls: vec![Call {
                syscall_idx: descs
                    .iter()
                    .position(|desc| desc.name == "socket$inet")
                    .expect("socket$inet should exist"),
                args: vec![ArgValue::Const(2), ArgValue::Const(1), ArgValue::Const(0)],
            }],
        };
        let artifact = ReplayArtifact {
            repro_path: None,
            target_bundle: None,
            syscall_descriptions: None,
            program_text: "0. definitely_not_a_real_syscall()\n".to_string(),
            program_ir: Some(prog.clone()),
            repro_info: None,
        };
        let (restored, used_program_ir) =
            restore_program(&artifact, &descs).expect("structured IR should win");
        assert!(used_program_ir);
        assert_eq!(restored, prog);
    }

    #[test]
    fn classify_observation_marks_matching_timeout_artifacts_as_reproduced() {
        let timeout_entry = ArtifactReproQueueEntry {
            artifact_type: "timeout".to_string(),
            ..Default::default()
        };
        let crash_entry = ArtifactReproQueueEntry {
            artifact_type: "crash".to_string(),
            normalized_summary: crate::crash::normalize_summary(
                "BUG: unable to handle kernel NULL pointer dereference at ffff888012345678",
            ),
            ..Default::default()
        };

        let timeout = classify_observation(&timeout_entry, true, false, None, None, 0);
        assert!(timeout.reproduced);
        assert_eq!(timeout.queue_outcome, "reproduced");

        let crash = classify_observation(
            &crash_entry,
            false,
            false,
            Some(
                "BUG: unable to handle kernel NULL pointer dereference at ffff8880deadbeef"
                    .to_string(),
            ),
            None,
            32,
        );
        assert!(crash.reproduced);
        assert_eq!(crash.queue_outcome, "reproduced");

        let mismatch = classify_observation(
            &crash_entry,
            false,
            false,
            Some("BUG: KASAN: use-after-free in another subsystem".to_string()),
            Some("executor said nope".to_string()),
            0,
        );
        assert!(!mismatch.reproduced);
        assert_eq!(mismatch.queue_outcome, "failed");
    }

    #[test]
    fn repro_worker_batch_report_counts_per_outcome() {
        let mut batch = ReproWorkerBatchReport {
            worker_id: "worker-a".to_string(),
            max_items: 3,
            claimed_items: 0,
            reproduced_items: 0,
            timed_out_items: 0,
            failed_items: 0,
            queue_drained: false,
            reports: Vec::new(),
        };
        for outcome in [Some("reproduced"), Some("timed_out"), Some("failed")] {
            let report = ReproWorkerRunReport {
                claimed: true,
                queue_attempt_number: 1,
                replay_attempts_planned: 3,
                replay_attempts_run: 1,
                artifact_type: Some("timeout".to_string()),
                signature: Some("sig".to_string()),
                summary: Some("summary".to_string()),
                queue_outcome: outcome.map(str::to_string),
                crash_title: None,
                executor_error: None,
                worker_error: None,
                repro_path: None,
                result_archive_path: None,
                reproduced_on_attempt: None,
                reproduced: outcome == Some("reproduced"),
                request_timed_out: outcome == Some("timed_out"),
                hanged: false,
                output_len: 0,
                used_program_ir: false,
                attempts: Vec::new(),
            };
            batch.claimed_items += 1;
            match report.queue_outcome.as_deref() {
                Some("reproduced") => batch.reproduced_items += 1,
                Some("timed_out") => batch.timed_out_items += 1,
                Some("failed") => batch.failed_items += 1,
                _ => {}
            }
            batch.reports.push(report);
        }

        assert_eq!(batch.claimed_items, 3);
        assert_eq!(batch.reproduced_items, 1);
        assert_eq!(batch.timed_out_items, 1);
        assert_eq!(batch.failed_items, 1);
    }

    #[test]
    fn append_repro_history_writes_jsonl_entry() {
        let workdir = unique_temp_dir("repro-history");
        std::fs::create_dir_all(&workdir).expect("temp workdir should be creatable");
        let record = ReproAttemptRecord {
            timestamp_unix_secs: 123,
            worker_id: "worker-a".to_string(),
            artifact_type: "timeout".to_string(),
            signature: "abc".to_string(),
            summary: "executor_reported_hang".to_string(),
            attempt_number: 2,
            replay_attempt_index: 1,
            replay_attempts_planned: 3,
            queue_outcome: "failed".to_string(),
            crash_title: None,
            executor_error: None,
            worker_error: Some("parse failed".to_string()),
            repro_path: Some("/tmp/repro.json".to_string()),
            reproduced: false,
            request_timed_out: false,
            hanged: false,
            output_len: 0,
            used_program_ir: false,
        };
        append_repro_history(workdir.to_str().expect("path should be utf-8"), &record)
            .expect("history append should succeed");
        let data = std::fs::read_to_string(workdir.join("repro_history.jsonl"))
            .expect("history file should exist");
        let line = data
            .lines()
            .next()
            .expect("history should contain one line");
        let value: serde_json::Value =
            serde_json::from_str(line).expect("history line should be valid json");
        assert_eq!(value["worker_id"], "worker-a");
        assert_eq!(value["attempt_number"], 2);
        assert_eq!(value["replay_attempt_index"], 1);
        assert_eq!(value["replay_attempts_planned"], 3);
        assert_eq!(value["queue_outcome"], "failed");
        assert_eq!(value["worker_error"], "parse failed");
        let _ = std::fs::remove_dir_all(&workdir);
    }

    #[test]
    fn select_preferred_replay_attempt_prefers_stronger_outcomes() {
        let attempts = vec![
            ReproReplayAttemptReport {
                replay_attempt_index: 1,
                queue_outcome: "failed".to_string(),
                crash_title: None,
                executor_error: None,
                worker_error: Some("vm died".to_string()),
                archive_path: None,
                reproduced: false,
                request_timed_out: false,
                hanged: false,
                output_len: 0,
            },
            ReproReplayAttemptReport {
                replay_attempt_index: 2,
                queue_outcome: "timed_out".to_string(),
                crash_title: None,
                executor_error: None,
                worker_error: None,
                archive_path: None,
                reproduced: false,
                request_timed_out: true,
                hanged: false,
                output_len: 0,
            },
            ReproReplayAttemptReport {
                replay_attempt_index: 3,
                queue_outcome: "reproduced".to_string(),
                crash_title: Some("BUG: something".to_string()),
                executor_error: None,
                worker_error: None,
                archive_path: None,
                reproduced: true,
                request_timed_out: false,
                hanged: false,
                output_len: 64,
            },
        ];
        let preferred =
            select_preferred_replay_attempt(&attempts).expect("preferred attempt should exist");
        assert_eq!(preferred.replay_attempt_index, 3);
        assert_eq!(preferred.queue_outcome, "reproduced");
    }

    #[test]
    fn archive_repro_attempt_and_result_write_expected_files() {
        let workdir = unique_temp_dir("repro-archive");
        std::fs::create_dir_all(&workdir).expect("temp workdir should be creatable");
        let entry = ArtifactReproQueueEntry {
            artifact_type: "timeout".to_string(),
            signature: "deadbeef".to_string(),
            summary: "executor_reported_hang".to_string(),
            directory: "timeouts/executor_reported_hang_deadbeef".to_string(),
            ..Default::default()
        };
        std::fs::create_dir_all(workdir.join(&entry.directory))
            .expect("artifact directory should be creatable");
        let attempt = ReproReplayAttemptReport {
            replay_attempt_index: 2,
            queue_outcome: "failed".to_string(),
            crash_title: None,
            executor_error: None,
            worker_error: Some("ssh flake".to_string()),
            archive_path: None,
            reproduced: false,
            request_timed_out: false,
            hanged: false,
            output_len: 0,
        };
        let archive_path = archive_repro_attempt(
            workdir.to_str().expect("path should be utf-8"),
            &entry,
            "worker-a",
            4,
            3,
            Some("/tmp/repro.json"),
            true,
            &attempt,
        )
        .expect("attempt archive should succeed");
        assert_eq!(
            archive_path,
            repro_attempt_archive_rel_path(&entry, 4, attempt.replay_attempt_index)
        );
        let attempt_json = std::fs::read_to_string(workdir.join(&archive_path))
            .expect("attempt archive should exist");
        let attempt_value: serde_json::Value =
            serde_json::from_str(&attempt_json).expect("attempt archive should be valid json");
        assert_eq!(attempt_value["worker_id"], "worker-a");
        assert_eq!(attempt_value["queue_attempt_number"], 4);
        assert_eq!(attempt_value["replay_attempt_index"], 2);
        assert_eq!(attempt_value["used_program_ir"], true);
        assert_eq!(
            attempt_value
                .as_object()
                .expect("attempt archive should be object")
                .keys()
                .filter(|key| key.as_str() == "replay_attempt_index")
                .count(),
            1
        );

        let report = ReproWorkerRunReport {
            claimed: true,
            queue_attempt_number: 4,
            replay_attempts_planned: 3,
            replay_attempts_run: 2,
            artifact_type: Some("timeout".to_string()),
            signature: Some("deadbeef".to_string()),
            summary: Some("executor_reported_hang".to_string()),
            queue_outcome: Some("failed".to_string()),
            crash_title: None,
            executor_error: None,
            worker_error: Some("ssh flake".to_string()),
            repro_path: Some("/tmp/repro.json".to_string()),
            result_archive_path: Some(repro_result_archive_rel_path(&entry, 4)),
            reproduced_on_attempt: None,
            reproduced: false,
            request_timed_out: false,
            hanged: false,
            output_len: 0,
            used_program_ir: true,
            attempts: vec![ReproReplayAttemptReport {
                archive_path: Some(archive_path.clone()),
                ..attempt.clone()
            }],
        };
        archive_repro_result(
            workdir.to_str().expect("path should be utf-8"),
            &entry,
            4,
            &report,
        )
        .expect("result archive should succeed");
        let result_path = repro_result_archive_rel_path(&entry, 4);
        let result_json = std::fs::read_to_string(workdir.join(&result_path))
            .expect("result archive should exist");
        let result_value: serde_json::Value =
            serde_json::from_str(&result_json).expect("result archive should be valid json");
        assert_eq!(result_value["queue_attempt_number"], 4);
        assert_eq!(result_value["replay_attempts_run"], 2);
        assert_eq!(result_value["attempts"][0]["replay_attempt_index"], 2);

        write_latest_artifact_repro_result(
            workdir.to_str().expect("path should be utf-8"),
            &entry,
            &report,
        )
        .expect("latest artifact replay result should succeed");
        let latest_json = std::fs::read_to_string(
            workdir
                .join(&entry.directory)
                .join("latest_repro_result.json"),
        )
        .expect("latest artifact replay result should exist");
        let latest_value: serde_json::Value =
            serde_json::from_str(&latest_json).expect("latest result should be valid json");
        assert_eq!(latest_value["queue_attempt_number"], 4);
        assert_eq!(
            latest_value["best_attempt_archive_path"],
            format!("repro_runs/timeout_deadbeef/queue-attempt-000004/replay-0002.json")
        );
        assert_eq!(
            latest_value["result_archive_path"],
            format!("repro_runs/timeout_deadbeef/queue-attempt-000004/result.json")
        );
        let _ = std::fs::remove_dir_all(&workdir);
    }

    #[test]
    fn format_program_description_roundtrips_basic_replay_shape() {
        let descs = socket_subset_descs();
        let prog = Program {
            calls: vec![
                Call {
                    syscall_idx: descs
                        .iter()
                        .position(|desc| desc.name == "socket$inet")
                        .expect("socket$inet should exist"),
                    args: vec![ArgValue::Const(2), ArgValue::Const(1), ArgValue::Const(0)],
                },
                Call {
                    syscall_idx: descs
                        .iter()
                        .position(|desc| desc.name == "connect$inet")
                        .expect("connect$inet should exist"),
                    args: vec![
                        ArgValue::ResultRef(ResultRef {
                            call_idx: 0,
                            result_idx: 0,
                        }),
                        ArgValue::Buffer(vec![0; 16]),
                        ArgValue::Const(16),
                    ],
                },
            ],
        };
        let text = format_program_description(&prog, &descs);
        let reparsed = parse_program_description(&text, &descs)
            .expect("formatted replay program should parse");
        assert_eq!(reparsed, prog);
    }

    #[test]
    fn write_latest_minimize_seed_embeds_executable_program_ir() {
        let workdir = unique_temp_dir("repro-min-seed");
        std::fs::create_dir_all(&workdir).expect("temp workdir should be creatable");
        let descs = socket_subset_descs();
        let entry = ArtifactReproQueueEntry {
            artifact_type: "timeout".to_string(),
            summary: "executor_reported_hang".to_string(),
            normalized_summary: "executor_reported_hang".to_string(),
            signature: "cafebabe".to_string(),
            directory: "timeouts/executor_reported_hang_cafebabe".to_string(),
            ..Default::default()
        };
        std::fs::create_dir_all(workdir.join(&entry.directory))
            .expect("artifact directory should be creatable");
        let prog = Program {
            calls: vec![Call {
                syscall_idx: descs
                    .iter()
                    .position(|desc| desc.name == "socket$inet")
                    .expect("socket$inet should exist"),
                args: vec![ArgValue::Const(2), ArgValue::Const(1), ArgValue::Const(0)],
            }],
        };
        let artifact = ReplayArtifact {
            repro_path: Some("/tmp/repro.json".to_string()),
            target_bundle: None,
            syscall_descriptions: Some("descriptions/linux/socket-subset.txt".to_string()),
            program_text: "0. socket$inet(0x2, 0x1, 0x0)\n".to_string(),
            program_ir: Some(prog.clone()),
            repro_info: None,
        };
        let cfg = Config {
            workdir: workdir.to_string_lossy().to_string(),
            kernel_obj: "/tmp/kernel".to_string(),
            image: "/tmp/image".to_string(),
            sshkey: "/tmp/key".to_string(),
            ssh_user: "root".to_string(),
            executor: "/tmp/syz-executor".to_string(),
            target_bundle: None,
            syscall_descriptions: Some("descriptions/linux/socket-subset.txt".to_string()),
            procs: 1,
            sandbox: "none".to_string(),
            cover: true,
            syscall_timeout_ms: 500,
            program_timeout_ms: 5000,
            slowdown: 1,
            max_execs: None,
            vm: VmConfig {
                count: 1,
                kernel: "/tmp/bzImage".to_string(),
                cpu: 2,
                mem: 2048,
                qemu_args: String::new(),
                qemu: "qemu-system-x86_64".to_string(),
                cmdline: "console=ttyS0".to_string(),
            },
        };
        let report = ReproWorkerRunReport {
            claimed: true,
            queue_attempt_number: 2,
            replay_attempts_planned: 3,
            replay_attempts_run: 2,
            artifact_type: Some("timeout".to_string()),
            signature: Some("cafebabe".to_string()),
            summary: Some("executor_reported_hang".to_string()),
            queue_outcome: Some("failed".to_string()),
            crash_title: None,
            executor_error: None,
            worker_error: None,
            repro_path: Some("/tmp/repro.json".to_string()),
            result_archive_path: Some(repro_result_archive_rel_path(&entry, 2)),
            reproduced_on_attempt: None,
            reproduced: false,
            request_timed_out: false,
            hanged: false,
            output_len: 0,
            used_program_ir: true,
            attempts: vec![ReproReplayAttemptReport {
                replay_attempt_index: 2,
                queue_outcome: "failed".to_string(),
                crash_title: None,
                executor_error: None,
                worker_error: None,
                archive_path: Some(repro_attempt_archive_rel_path(&entry, 2, 2)),
                reproduced: false,
                request_timed_out: false,
                hanged: false,
                output_len: 0,
            }],
        };

        write_latest_minimize_seed(
            workdir.to_str().expect("path should be utf-8"),
            &entry,
            &artifact,
            &cfg,
            &prog,
            &descs,
            &report,
        )
        .expect("latest minimize seed should write");
        let value: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(
                workdir
                    .join(&entry.directory)
                    .join("latest_minimize_seed.json"),
            )
            .expect("latest minimize seed should exist"),
        )
        .expect("latest minimize seed should be valid json");
        assert_eq!(value["eligible_for_minimization"], false);
        assert_eq!(
            value["result_archive_path"],
            repro_result_archive_rel_path(&entry, 2)
        );
        assert_eq!(
            value["best_attempt_archive_path"],
            repro_attempt_archive_rel_path(&entry, 2, 2)
        );
        assert_eq!(
            value["repro"]["program_ir"]["calls"][0]["args"][0]["Const"],
            2
        );
        assert_eq!(
            value["repro"]["program"],
            format_program_description(&prog, &descs)
        );
        let _ = std::fs::remove_dir_all(&workdir);
    }
}
