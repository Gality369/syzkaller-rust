use crate::avoidance::AvoidanceState;
use crate::config::Config;
use crate::corpus::Corpus;
use crate::crash;
use crate::exec;
use crate::flatrpc_generated::rpc::*;
use crate::fuzzer;
use crate::program;
use crate::protocol;
use crate::qemu::QemuInstance;
use crate::target;

use rand::SeedableRng;
use std::collections::{HashMap, HashSet};
use std::io::{self, Read};
use std::net::TcpListener;
use std::path::Path;
use std::process::Child;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

const PROGRAM_SHAPE_BLOCK_THRESHOLD: u32 = 2;
const TIMEOUT_SYSCALL_EDGE_BLOCK_THRESHOLD: u32 = 2;
const TIMEOUT_SYSCALL_BLOCK_THRESHOLD: u32 = 3;
const EXECUTOR_RETRY_STALL_THRESHOLD: i32 = 8;
const EXECUTOR_RETRY_STALL_MIN_ELAPSED: Duration = Duration::from_secs(4);
const AVOIDANCE_DECAY_INTERVAL: u64 = 16;
const AVOIDANCE_MAX_DECAY_AMOUNT: u32 = 3;
const AVOIDANCE_COMPACT_IDLE_EPOCHS: u64 = AVOIDANCE_DECAY_INTERVAL * 2;
const AVOIDANCE_MAX_PERSISTED_WEAK_EDGES: usize = 8;
const AVOIDANCE_MAX_PERSISTED_WEAK_SYSCALLS: usize = 8;

struct ExecutorSshSession {
    child: Child,
    stdout_buf: Arc<Mutex<Vec<u8>>>,
    stderr_buf: Arc<Mutex<Vec<u8>>>,
    stdout_reader: Option<JoinHandle<()>>,
    stderr_reader: Option<JoinHandle<()>>,
}

impl ExecutorSshSession {
    fn new(mut child: Child) -> Self {
        let stdout_buf = Arc::new(Mutex::new(Vec::new()));
        let stderr_buf = Arc::new(Mutex::new(Vec::new()));
        let stdout_reader = child
            .stdout
            .take()
            .map(|stdout| spawn_output_reader(stdout, stdout_buf.clone()));
        let stderr_reader = child
            .stderr
            .take()
            .map(|stderr| spawn_output_reader(stderr, stderr_buf.clone()));
        Self {
            child,
            stdout_buf,
            stderr_buf,
            stdout_reader,
            stderr_reader,
        }
    }

    fn combined_output(&self) -> Vec<u8> {
        let stdout = self.stdout_buf.lock().unwrap().clone();
        let stderr = self.stderr_buf.lock().unwrap().clone();
        combine_named_logs(&[
            ("executor ssh stdout", stdout.as_slice()),
            ("executor ssh stderr", stderr.as_slice()),
        ])
        .unwrap_or_default()
    }
}

impl Drop for ExecutorSshSession {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(handle) = self.stdout_reader.take() {
            let _ = handle.join();
        }
        if let Some(handle) = self.stderr_reader.take() {
            let _ = handle.join();
        }
    }
}

fn spawn_output_reader<R: Read + Send + 'static>(
    mut reader: R,
    output: Arc<Mutex<Vec<u8>>>,
) -> JoinHandle<()> {
    std::thread::spawn(move || {
        let mut chunk = [0u8; 4096];
        loop {
            match reader.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(read) => {
                    let mut buf = output.lock().unwrap();
                    buf.extend_from_slice(&chunk[..read]);
                    if buf.len() > 256 * 1024 {
                        let drain = buf.len() - 128 * 1024;
                        buf.drain(..drain);
                    }
                }
            }
        }
    })
}

fn combine_named_logs(sections: &[(&str, &[u8])]) -> Option<Vec<u8>> {
    let mut combined = Vec::new();
    for (name, data) in sections {
        if data.is_empty() {
            continue;
        }
        if !combined.is_empty() && !combined.ends_with(b"\n") {
            combined.push(b'\n');
        }
        combined.extend_from_slice(format!("=== {} ===\n", name).as_bytes());
        combined.extend_from_slice(data);
        if !data.ends_with(b"\n") {
            combined.push(b'\n');
        }
    }
    if combined.is_empty() {
        None
    } else {
        Some(combined)
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct RequestTrace {
    events: Vec<RequestTraceEvent>,
    read_timeouts: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RequestTraceEvent {
    at_ms: u128,
    kind: RequestTraceEventKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum RequestTraceEventKind {
    SentExecRequest {
        id: i64,
        prog_bytes: usize,
    },
    Executing {
        id: i64,
        proc_id: i32,
        try_: i32,
        wait_duration: i64,
    },
    State {
        summary: String,
    },
    ExecResult {
        id: i64,
        proc: i32,
        hanged: bool,
        output_len: usize,
        error: String,
        call_count: usize,
        elapsed_ns: Option<u64>,
        freshness: Option<u64>,
    },
}

impl RequestTrace {
    fn record_sent_exec_request(&mut self, at_ms: u128, id: i64, prog_bytes: usize) {
        self.events.push(RequestTraceEvent {
            at_ms,
            kind: RequestTraceEventKind::SentExecRequest { id, prog_bytes },
        });
    }

    fn record_executing(&mut self, at_ms: u128, data: &protocol::ExecutingData) {
        self.events.push(RequestTraceEvent {
            at_ms,
            kind: RequestTraceEventKind::Executing {
                id: data.id,
                proc_id: data.proc_id,
                try_: data.try_,
                wait_duration: data.wait_duration,
            },
        });
    }

    fn record_state(&mut self, at_ms: u128, state: &[u8]) {
        self.events.push(RequestTraceEvent {
            at_ms,
            kind: RequestTraceEventKind::State {
                summary: summarize_state_payload(state),
            },
        });
    }

    fn record_exec_result(&mut self, at_ms: u128, result: &protocol::ExecResultData) {
        let (call_count, elapsed_ns, freshness) = result
            .info
            .as_ref()
            .map(|info| (info.calls.len(), Some(info.elapsed), Some(info.freshness)))
            .unwrap_or((0, None, None));
        self.events.push(RequestTraceEvent {
            at_ms,
            kind: RequestTraceEventKind::ExecResult {
                id: result.id,
                proc: result.proc,
                hanged: result.hanged,
                output_len: result.output.len(),
                error: result.error.clone(),
                call_count,
                elapsed_ns,
                freshness,
            },
        });
    }

    fn record_read_timeout(&mut self) {
        self.read_timeouts = self.read_timeouts.saturating_add(1);
    }

    fn render(&self, final_reason: &str, final_at_ms: u128) -> Vec<u8> {
        let mut lines = Vec::with_capacity(self.events.len() + 1);
        lines.push(format!(
            "final_reason={final_reason} at_ms={final_at_ms} read_timeouts={}",
            self.read_timeouts
        ));
        for event in &self.events {
            lines.push(event.render_line());
        }
        lines.join("\n").into_bytes()
    }
}

impl RequestTraceEvent {
    fn render_line(&self) -> String {
        let prefix = format!("[t+{}ms]", self.at_ms);
        match &self.kind {
            RequestTraceEventKind::SentExecRequest { id, prog_bytes } => {
                format!("{prefix} sent_exec_request id={id} prog_bytes={prog_bytes}")
            }
            RequestTraceEventKind::Executing {
                id,
                proc_id,
                try_,
                wait_duration,
            } => format!(
                "{prefix} executing id={id} proc={proc_id} try={try_} wait_duration_raw={wait_duration}"
            ),
            RequestTraceEventKind::State { summary } => {
                format!("{prefix} state {summary}")
            }
            RequestTraceEventKind::ExecResult {
                id,
                proc,
                hanged,
                output_len,
                error,
                call_count,
                elapsed_ns,
                freshness,
            } => {
                let mut line = format!(
                    "{prefix} exec_result id={id} proc={proc} hanged={hanged} output_len={output_len} error={error:?} calls={call_count}"
                );
                if let Some(elapsed_ns) = elapsed_ns {
                    line.push_str(&format!(" elapsed_ns={elapsed_ns}"));
                }
                if let Some(freshness) = freshness {
                    line.push_str(&format!(" freshness={freshness}"));
                }
                line
            }
        }
    }
}

fn summarize_state_payload(data: &[u8]) -> String {
    const MAX_PREFIX_BYTES: usize = 16;
    if data.is_empty() {
        return "len=0".to_string();
    }
    let prefix_len = data.len().min(MAX_PREFIX_BYTES);
    let prefix_hex = data[..prefix_len]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    if data.len() > MAX_PREFIX_BYTES {
        format!("len={} hex={}...", data.len(), prefix_hex)
    } else {
        format!("len={} hex={}", data.len(), prefix_hex)
    }
}

/// Main entry point: start VM, connect executor, run fuzz loop.
pub fn run(cfg: Config) -> Result<(), Box<dyn std::error::Error>> {
    let loaded_target = target::load_target_from_config(&cfg, None)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let descs = loaded_target.descs;
    let availability = program::transitively_enabled_syscalls(&descs);
    let generatable = program::transitively_generatable_syscalls(&descs);
    if availability.enabled.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "loaded target has no transitively enabled syscalls",
        )
        .into());
    }
    if generatable.enabled.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "loaded target has no transitively generatable syscalls",
        )
        .into());
    }
    let availability_disabled_keys = availability
        .disabled
        .keys()
        .copied()
        .collect::<std::collections::HashSet<_>>();
    let availability_disabled_count = availability.disabled.len();
    log::info!(
        "Loaded target {} with {} syscall descriptions ({} enabled, {} generatable, {} unavailable)",
        loaded_target.source_label,
        descs.len(),
        availability.enabled.len(),
        generatable.enabled.len(),
        availability_disabled_count
    );
    if !availability.disabled.is_empty() {
        let mut disabled = availability.disabled.into_iter().collect::<Vec<_>>();
        disabled.sort_by_key(|(syscall_idx, _)| *syscall_idx);
        for (syscall_idx, reason) in disabled {
            log::warn!("Disabling syscall {}: {}", descs[syscall_idx].name, reason);
        }
    }
    if generatable.disabled.len() > availability_disabled_count {
        let mut nongeneratable = generatable
            .disabled
            .into_iter()
            .filter(|(syscall_idx, _)| !availability_disabled_keys.contains(syscall_idx))
            .collect::<Vec<_>>();
        nongeneratable.sort_by_key(|(syscall_idx, _)| *syscall_idx);
        for (syscall_idx, reason) in nongeneratable {
            log::info!(
                "Skipping syscall {} during generation: {}",
                descs[syscall_idx].name,
                reason
            );
        }
    }
    std::fs::create_dir_all(&cfg.workdir)?;
    let crashes_dir = std::path::Path::new(&cfg.workdir).join("crashes");
    std::fs::create_dir_all(&crashes_dir)?;
    match crash::sync_artifact_catalog(&cfg.workdir) {
        Ok(report) if report.total_entries > 0 || report.skipped_entries > 0 => {
            log::info!(
                "Synced artifact catalog: entries={} (crashes={}, timeouts={}), skipped={}",
                report.total_entries,
                report.crash_entries,
                report.timeout_entries,
                report.skipped_entries
            );
        }
        Ok(_) => {}
        Err(err) => {
            log::warn!(
                "Failed to sync artifact catalog under {}: {}",
                cfg.workdir,
                err
            );
        }
    }
    let corpus_path = Path::new(&cfg.workdir).join("corpus.json");
    let avoidance_path = Path::new(&cfg.workdir).join("avoidance.json");
    let (mut corpus, corpus_report) = match Corpus::load(&corpus_path, &descs) {
        Ok(loaded) => loaded,
        Err(err) => {
            log::warn!(
                "Failed to load corpus snapshot {}: {}",
                corpus_path.display(),
                err
            );
            (Corpus::new(), Default::default())
        }
    };
    if corpus_report.loaded_programs > 0
        || corpus_report.skipped_programs > 0
        || corpus_report.signal_count > 0
    {
        log::info!(
            "Loaded corpus snapshot: programs={}, skipped={}, signals={}",
            corpus_report.loaded_programs,
            corpus_report.skipped_programs,
            corpus_report.signal_count
        );
    }
    let (mut avoidance_state, _) = match AvoidanceState::load(
        &avoidance_path,
        TIMEOUT_SYSCALL_EDGE_BLOCK_THRESHOLD,
        TIMEOUT_SYSCALL_BLOCK_THRESHOLD,
    ) {
        Ok(loaded) => loaded,
        Err(err) => {
            log::warn!(
                "Failed to load avoidance snapshot {}: {}",
                avoidance_path.display(),
                err
            );
            (AvoidanceState::new(), Default::default())
        }
    };
    if let Some(compaction_result) = compact_avoidance_state(&mut avoidance_state) {
        log::info!(
            "Compacted avoidance snapshot: edges={} -> {}, syscalls={} -> {}",
            compaction_result.before_edges,
            compaction_result.after_edges,
            compaction_result.before_syscalls,
            compaction_result.after_syscalls
        );
        if let Err(err) = avoidance_state.save(&avoidance_path) {
            log::warn!(
                "Failed to persist compacted avoidance snapshot {}: {}",
                avoidance_path.display(),
                err
            );
        }
    }
    if !avoidance_state.timeout_edge_failures.is_empty()
        || !avoidance_state.timeout_syscall_failures.is_empty()
    {
        log::info!(
            "Loaded avoidance snapshot: edges={} (blocked={}), syscalls={} (blocked={})",
            avoidance_state.timeout_edge_failures.len(),
            avoidance_state
                .blocked_edges(TIMEOUT_SYSCALL_EDGE_BLOCK_THRESHOLD)
                .len(),
            avoidance_state.timeout_syscall_failures.len(),
            avoidance_state
                .blocked_syscalls(TIMEOUT_SYSCALL_BLOCK_THRESHOLD)
                .len()
        );
    }
    let mut blocked_timeout_edges =
        avoidance_state.blocked_edges(TIMEOUT_SYSCALL_EDGE_BLOCK_THRESHOLD);
    let mut blocked_timeout_syscalls =
        avoidance_state.blocked_syscalls(TIMEOUT_SYSCALL_BLOCK_THRESHOLD);
    let mut avoidance_learning_epoch = avoidance_state.learning_epoch;
    let mut timeout_edge_failures = avoidance_state.timeout_edge_failures;
    let mut timeout_syscall_failures = avoidance_state.timeout_syscall_failures;
    let mut timeout_edge_last_failure_epoch = avoidance_state.timeout_edge_last_failure_epoch;
    let mut timeout_syscall_last_failure_epoch = avoidance_state.timeout_syscall_last_failure_epoch;
    let mut choice_table = rebuild_choice_table(
        &descs,
        &corpus,
        &timeout_edge_failures,
        &timeout_syscall_failures,
    );
    let mut rng = rand::rngs::StdRng::from_entropy();

    let mut vm_index: usize = 0;
    let mut total_execs: u64 = 0;
    let mut total_attempts: u64 = 0;
    let mut successful_execs_since_decay: u64 = 0;
    let mut last_stats = Instant::now();
    let mut blocked_programs = HashSet::new();
    let mut blocked_shapes = HashSet::new();
    let mut shape_failures = HashMap::new();

    // Outer loop: restart VM on crash or disconnect
    loop {
        if exec_limit_reached(&cfg, total_attempts) {
            log::info!("Reached max_execs={}, stopping manager", total_attempts);
            return Ok(());
        }
        log::info!("=== Starting VM instance {} ===", vm_index);
        match run_instance(
            &cfg,
            &descs,
            &mut corpus,
            &corpus_path,
            &avoidance_path,
            &mut choice_table,
            &mut blocked_programs,
            &mut blocked_shapes,
            &mut shape_failures,
            &mut blocked_timeout_edges,
            &mut timeout_edge_failures,
            &mut blocked_timeout_syscalls,
            &mut timeout_syscall_failures,
            &mut avoidance_learning_epoch,
            &mut timeout_edge_last_failure_epoch,
            &mut timeout_syscall_last_failure_epoch,
            &mut rng,
            &mut total_execs,
            &mut total_attempts,
            &mut successful_execs_since_decay,
            &mut last_stats,
            vm_index,
        ) {
            Ok(()) => {
                log::info!("Instance {} finished normally", vm_index);
            }
            Err(e) => {
                successful_execs_since_decay = 0;
                log::error!("Instance {} failed: {}", vm_index, e);
            }
        }
        if exec_limit_reached(&cfg, total_attempts) {
            log::info!("Reached max_execs={}, stopping manager", total_attempts);
            return Ok(());
        }
        vm_index += 1;
        // Brief pause before restarting
        std::thread::sleep(Duration::from_secs(2));
    }
}

/// Run a single VM instance through setup, handshake, and fuzz loop.
fn run_instance(
    cfg: &Config,
    descs: &[program::SyscallDesc],
    corpus: &mut Corpus,
    corpus_path: &Path,
    avoidance_path: &Path,
    choice_table: &mut program::SyscallChoiceTable,
    blocked_programs: &mut HashSet<String>,
    blocked_shapes: &mut HashSet<String>,
    shape_failures: &mut HashMap<String, u32>,
    blocked_timeout_edges: &mut HashSet<String>,
    timeout_edge_failures: &mut HashMap<String, u32>,
    blocked_timeout_syscalls: &mut HashSet<String>,
    timeout_syscall_failures: &mut HashMap<String, u32>,
    avoidance_learning_epoch: &mut u64,
    timeout_edge_last_failure_epoch: &mut HashMap<String, u64>,
    timeout_syscall_last_failure_epoch: &mut HashMap<String, u64>,
    rng: &mut rand::rngs::StdRng,
    total_execs: &mut u64,
    total_attempts: &mut u64,
    successful_execs_since_decay: &mut u64,
    last_stats: &mut Instant,
    vm_index: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    // 1. Bind TCP listener for flatrpc (port 0 = auto-assign)
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let flatrpc_port = listener.local_addr()?.port();
    log::info!("FlatRPC listener on port {}", flatrpc_port);

    // 2. Start QEMU VM
    let mut vm = QemuInstance::start(cfg, vm_index)?;
    log::info!("Waiting for SSH...");
    vm.wait_ssh(cfg, Duration::from_secs(120))?;
    log::info!("SSH ready");

    // 3. Copy executor to VM
    log::info!("Copying executor to VM...");
    vm.scp(cfg, &cfg.executor, "/tmp/syz-executor")?;
    log::info!("Executor copied");

    // 4. Start executor via SSH with reverse port forwarding
    let executor_cmd = format!(
        "chmod +x /tmp/syz-executor && /tmp/syz-executor runner {} localhost {}",
        vm_index, flatrpc_port
    );
    log::info!("Starting executor: {}", executor_cmd);
    let executor_ssh =
        ExecutorSshSession::new(vm.run_with_forward(cfg, flatrpc_port, &executor_cmd)?);

    // 5. Accept executor connection
    log::info!("Waiting for executor connection...");
    listener.set_nonblocking(false)?;
    let accept_timeout = Duration::from_secs(60);
    let accept_start = Instant::now();
    let mut stream = loop {
        // Use a polling approach since std TcpListener doesn't have set_timeout for accept
        listener.set_nonblocking(true)?;
        match listener.accept() {
            Ok((stream, addr)) => {
                log::info!("Executor connected from {:?}", addr);
                stream.set_nonblocking(false)?;
                stream.set_read_timeout(Some(Duration::from_secs(5)))?;
                stream.set_write_timeout(Some(Duration::from_secs(30)))?;
                break stream;
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                if accept_start.elapsed() > accept_timeout {
                    return Err("Executor connection timed out".into());
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
            Err(e) => return Err(e.into()),
        }
    };

    // 6. Perform flatrpc handshake
    log::info!("Performing handshake...");
    do_handshake(&mut stream, cfg)?;
    log::info!("Handshake complete");

    // 7. Send CorpusTriaged to signal that we're ready
    protocol::send_corpus_triaged(&mut stream)?;
    if corpus.signal_count() > 0 {
        let all_signal = corpus.signal_vec();
        protocol::send_signal_update(&mut stream, &all_signal)?;
        log::info!(
            "Sent {} restored coverage signals to executor",
            all_signal.len()
        );
    }

    // 8. Enter fuzz loop
    log::info!("Entering fuzz loop...");
    let mut req_id: i64 = 0;
    let mut executing_ids: std::collections::HashSet<i64> = std::collections::HashSet::new();

    loop {
        // Check VM health
        if !vm.is_running() {
            let serial = vm.get_serial_output();
            if let Some(title) = crash::detect_crash(&serial) {
                log::warn!("Crash detected: {}", title);
                let prog_desc = format!("(last {} programs)", executing_ids.len());
                let repro = build_artifact_repro_info(
                    cfg,
                    vm_index,
                    *total_execs,
                    "crash",
                    &title,
                    &prog_desc,
                    None,
                    None,
                    None,
                );
                crash::save_crash(
                    &cfg.workdir,
                    &title,
                    &serial,
                    &prog_desc,
                    None,
                    None,
                    Some(&repro),
                )?;
            }
            return Err("VM exited".into());
        }

        // Check serial for crashes periodically (not every exec, it's heavy)
        if *total_execs % 10 == 0 {
            let serial = vm.get_serial_output();
            if let Some(title) = crash::detect_crash(&serial) {
                log::warn!("Crash detected from serial: {}", title);
                let prog_desc = format!("(fuzzing in progress, exec #{})", total_execs);
                let repro = build_artifact_repro_info(
                    cfg,
                    vm_index,
                    *total_execs,
                    "crash",
                    &title,
                    &prog_desc,
                    None,
                    None,
                    None,
                );
                crash::save_crash(
                    &cfg.workdir,
                    &title,
                    &serial,
                    &prog_desc,
                    None,
                    None,
                    Some(&repro),
                )?;
                return Err(format!("Crash: {}", title).into());
            }
        }

        // Generate or mutate a program
        let prog = if corpus.len() > 0 && rand::Rng::gen_bool(rng, 0.8) {
            // 80% chance: mutate from corpus
            let base = corpus.random_program(rng).unwrap().clone();
            fuzzer::mutate_with_choice_table_and_edge_bias(
                &base,
                descs,
                choice_table,
                timeout_edge_failures,
                rng,
            )
        } else {
            // 20% chance: generate fresh
            fuzzer::generate_with_choice_table_and_edge_bias(
                descs,
                choice_table,
                timeout_edge_failures,
                rng,
            )
        };
        if program_is_blocked(blocked_programs, &prog) {
            log::debug!("Skipping blocked program");
            continue;
        }
        let prog_shape = program::program_shape_key(&prog, descs);
        if blocked_shapes.contains(&prog_shape) {
            log::debug!("Skipping blocked program shape: {}", prog_shape);
            continue;
        }
        let blocked_edges = blocked_timeout_edges_for_program(&prog, descs, blocked_timeout_edges);
        if !blocked_edges.is_empty() {
            log::debug!(
                "Skipping blocked timeout-prone syscall edge profile set: {}",
                blocked_edges.join(", ")
            );
            continue;
        }
        let blocked_syscalls =
            blocked_timeout_syscalls_for_program(&prog, descs, blocked_timeout_syscalls);
        if !blocked_syscalls.is_empty() {
            log::debug!(
                "Skipping blocked timeout-prone syscall set: {}",
                blocked_syscalls.join(", ")
            );
            continue;
        }
        let prog_desc = fuzzer::describe_program(&prog, descs);
        log::debug!("Program: {}", prog_desc);

        // Serialize and send
        let prog_data = match exec::serialize_program(&prog, descs) {
            Ok(data) => data,
            Err(err) => {
                log::warn!("Skipping invalid generated program: {}", err);
                continue;
            }
        };
        // Must set sandbox flag so executor knows how to run; add Signal for coverage
        let mut env_flags = ExecEnv::SandboxNone;
        if cfg.cover {
            env_flags |= ExecEnv::Signal;
        }
        let exec_flags = ExecFlag::CollectSignal;
        let request_flags = RequestFlag::ReturnError | RequestFlag::ReturnOutput;

        protocol::send_exec_request(
            &mut stream,
            req_id,
            &prog_data,
            env_flags,
            exec_flags,
            request_flags,
            0,   // sandbox_arg
            &[], // all_signal (empty for now)
        )?;
        *total_attempts += 1;

        executing_ids.insert(req_id);

        // Receive response(s) with timeout
        // The executor may retry hanging programs indefinitely, so we cap wait time.
        let mut got_result = false;
        let request_start = Instant::now();
        let request_timeout = Duration::from_secs(15);
        let mut request_trace = RequestTrace::default();
        request_trace.record_sent_exec_request(0, req_id, prog_data.len());
        while !got_result {
            if request_start.elapsed() > request_timeout {
                log::warn!(
                    "Request {} timed out after {:?}, restarting VM",
                    req_id,
                    request_timeout
                );
                *successful_execs_since_decay = 0;
                *avoidance_learning_epoch += 1;
                remember_blocked_program(blocked_programs, &prog);
                if note_shape_failure(blocked_shapes, shape_failures, &prog_shape) {
                    log::info!(
                        "Blocking program shape after repeated timeouts: {}",
                        prog_shape
                    );
                }
                for edge in note_timeout_edge_failures(
                    blocked_timeout_edges,
                    timeout_edge_failures,
                    timeout_edge_last_failure_epoch,
                    *avoidance_learning_epoch,
                    &prog,
                    descs,
                ) {
                    log::info!(
                        "Blocking timeout-prone syscall edge after repeated failures: {}",
                        edge
                    );
                }
                for syscall_name in note_timeout_syscall_failures(
                    blocked_timeout_syscalls,
                    timeout_syscall_failures,
                    timeout_syscall_last_failure_epoch,
                    *avoidance_learning_epoch,
                    &prog,
                    descs,
                ) {
                    log::info!(
                        "Blocking timeout-prone syscall after repeated failures: {}",
                        syscall_name
                    );
                }
                let timeout_profile = timeout_profile_desc(&prog, descs);
                let timeout_serial = vm.get_serial_output();
                let executor_ssh_output = executor_ssh.combined_output();
                let request_trace_log = request_trace.render(
                    "manager_request_timeout",
                    request_start.elapsed().as_millis(),
                );
                let timeout_log = combine_named_logs(&[
                    ("request trace", &request_trace_log),
                    ("executor ssh", &executor_ssh_output),
                    ("guest serial", &timeout_serial),
                ]);
                let repro = build_artifact_repro_info(
                    cfg,
                    vm_index,
                    *total_execs,
                    "timeout",
                    "manager_request_timeout",
                    &prog_desc,
                    Some(&prog),
                    Some(&prog_shape),
                    Some(&timeout_profile),
                );
                if let Err(e) = crash::save_timeout_with_log(
                    &cfg.workdir,
                    "manager_request_timeout",
                    &prog_desc,
                    &prog_shape,
                    &timeout_profile,
                    Some(&repro),
                    timeout_log.as_deref(),
                ) {
                    log::warn!("Failed to save timed-out program: {}", e);
                }
                if let Err(e) = save_avoidance_state(
                    avoidance_path,
                    *avoidance_learning_epoch,
                    timeout_edge_failures,
                    timeout_syscall_failures,
                    timeout_edge_last_failure_epoch,
                    timeout_syscall_last_failure_epoch,
                ) {
                    log::warn!(
                        "Failed to persist avoidance snapshot {}: {}",
                        avoidance_path.display(),
                        e
                    );
                }
                *choice_table = rebuild_choice_table(
                    descs,
                    corpus,
                    timeout_edge_failures,
                    timeout_syscall_failures,
                );
                return Err("program execution timed out".into());
            }
            let msg = protocol::recv_executor_message(&mut stream);
            let msg = match msg {
                Ok(m) => m,
                Err(e)
                    if e.kind() == io::ErrorKind::WouldBlock
                        || e.kind() == io::ErrorKind::TimedOut =>
                {
                    // Read timeout, check if we should give up
                    request_trace.record_read_timeout();
                    continue;
                }
                Err(e) => return Err(e.into()),
            };
            match msg {
                protocol::ExecutorMsg::Executing(data) => {
                    let elapsed = request_start.elapsed();
                    request_trace.record_executing(elapsed.as_millis(), &data);
                    log::debug!("Executing: id={}, proc={}", data.id, data.proc_id);
                    if executor_retry_stall_reached(data.try_, elapsed) {
                        log::warn!(
                            "Request {} entered executor retry stall at try={} after {:?}, restarting VM",
                            req_id,
                            data.try_,
                            elapsed
                        );
                        *successful_execs_since_decay = 0;
                        *avoidance_learning_epoch += 1;
                        remember_blocked_program(blocked_programs, &prog);
                        if note_shape_failure(blocked_shapes, shape_failures, &prog_shape) {
                            log::info!(
                                "Blocking program shape after repeated timeouts: {}",
                                prog_shape
                            );
                        }
                        for edge in note_timeout_edge_failures(
                            blocked_timeout_edges,
                            timeout_edge_failures,
                            timeout_edge_last_failure_epoch,
                            *avoidance_learning_epoch,
                            &prog,
                            descs,
                        ) {
                            log::info!(
                                "Blocking timeout-prone syscall edge after repeated failures: {}",
                                edge
                            );
                        }
                        for syscall_name in note_timeout_syscall_failures(
                            blocked_timeout_syscalls,
                            timeout_syscall_failures,
                            timeout_syscall_last_failure_epoch,
                            *avoidance_learning_epoch,
                            &prog,
                            descs,
                        ) {
                            log::info!(
                                "Blocking timeout-prone syscall after repeated failures: {}",
                                syscall_name
                            );
                        }
                        let timeout_profile = timeout_profile_desc(&prog, descs);
                        let timeout_serial = vm.get_serial_output();
                        let executor_ssh_output = executor_ssh.combined_output();
                        let request_trace_log =
                            request_trace.render("executor_retry_stall", elapsed.as_millis());
                        let timeout_log = combine_named_logs(&[
                            ("request trace", &request_trace_log),
                            ("executor ssh", &executor_ssh_output),
                            ("guest serial", &timeout_serial),
                        ]);
                        let repro = build_artifact_repro_info(
                            cfg,
                            vm_index,
                            *total_execs,
                            "timeout",
                            "executor_retry_stall",
                            &prog_desc,
                            Some(&prog),
                            Some(&prog_shape),
                            Some(&timeout_profile),
                        );
                        if let Err(e) = crash::save_timeout_with_log(
                            &cfg.workdir,
                            "executor_retry_stall",
                            &prog_desc,
                            &prog_shape,
                            &timeout_profile,
                            Some(&repro),
                            timeout_log.as_deref(),
                        ) {
                            log::warn!("Failed to save retry-stalled program: {}", e);
                        }
                        if let Err(e) = save_avoidance_state(
                            avoidance_path,
                            *avoidance_learning_epoch,
                            timeout_edge_failures,
                            timeout_syscall_failures,
                            timeout_edge_last_failure_epoch,
                            timeout_syscall_last_failure_epoch,
                        ) {
                            log::warn!(
                                "Failed to persist avoidance snapshot {}: {}",
                                avoidance_path.display(),
                                e
                            );
                        }
                        *choice_table = rebuild_choice_table(
                            descs,
                            corpus,
                            timeout_edge_failures,
                            timeout_syscall_failures,
                        );
                        return Err("executor retry stall".into());
                    }
                }
                protocol::ExecutorMsg::ExecResult(result) => {
                    request_trace.record_exec_result(request_start.elapsed().as_millis(), &result);
                    got_result = true;
                    executing_ids.remove(&result.id);
                    *total_execs += 1;
                    *avoidance_learning_epoch += 1;

                    log::debug!(
                        "ExecResult: id={}, hanged={}, error='{}', output_len={}, has_info={}",
                        result.id,
                        result.hanged,
                        result.error,
                        result.output.len(),
                        result.info.is_some()
                    );

                    if result.hanged {
                        *successful_execs_since_decay = 0;
                        remember_blocked_program(blocked_programs, &prog);
                        if note_shape_failure(blocked_shapes, shape_failures, &prog_shape) {
                            log::info!(
                                "Blocking program shape after repeated hangs: {}",
                                prog_shape
                            );
                        }
                        for edge in note_timeout_edge_failures(
                            blocked_timeout_edges,
                            timeout_edge_failures,
                            timeout_edge_last_failure_epoch,
                            *avoidance_learning_epoch,
                            &prog,
                            descs,
                        ) {
                            log::info!(
                                "Blocking timeout-prone syscall edge after repeated failures: {}",
                                edge
                            );
                        }
                        for syscall_name in note_timeout_syscall_failures(
                            blocked_timeout_syscalls,
                            timeout_syscall_failures,
                            timeout_syscall_last_failure_epoch,
                            *avoidance_learning_epoch,
                            &prog,
                            descs,
                        ) {
                            log::info!(
                                "Blocking timeout-prone syscall after repeated failures: {}",
                                syscall_name
                            );
                        }
                        let timeout_profile = timeout_profile_desc(&prog, descs);
                        let serial = vm.get_serial_output();
                        let executor_ssh_output = executor_ssh.combined_output();
                        let request_trace_log = request_trace.render(
                            "executor_reported_hang",
                            request_start.elapsed().as_millis(),
                        );
                        let timeout_log = combine_named_logs(&[
                            ("request trace", &request_trace_log),
                            ("executor output", &result.output),
                            ("executor ssh", &executor_ssh_output),
                            ("guest serial", &serial),
                        ]);
                        let repro = build_artifact_repro_info(
                            cfg,
                            vm_index,
                            *total_execs,
                            "timeout",
                            "executor_reported_hang",
                            &prog_desc,
                            Some(&prog),
                            Some(&prog_shape),
                            Some(&timeout_profile),
                        );
                        if let Err(e) = crash::save_timeout_with_log(
                            &cfg.workdir,
                            "executor_reported_hang",
                            &prog_desc,
                            &prog_shape,
                            &timeout_profile,
                            Some(&repro),
                            timeout_log.as_deref(),
                        ) {
                            log::warn!("Failed to save hanged program: {}", e);
                        }
                        if let Err(e) = save_avoidance_state(
                            avoidance_path,
                            *avoidance_learning_epoch,
                            timeout_edge_failures,
                            timeout_syscall_failures,
                            timeout_edge_last_failure_epoch,
                            timeout_syscall_last_failure_epoch,
                        ) {
                            log::warn!(
                                "Failed to persist avoidance snapshot {}: {}",
                                avoidance_path.display(),
                                e
                            );
                        }
                        *choice_table = rebuild_choice_table(
                            descs,
                            corpus,
                            timeout_edge_failures,
                            timeout_syscall_failures,
                        );
                    } else if let Some(decay_result) = maybe_decay_avoidance(
                        successful_execs_since_decay,
                        *avoidance_learning_epoch,
                        blocked_timeout_edges,
                        timeout_edge_failures,
                        timeout_edge_last_failure_epoch,
                        blocked_timeout_syscalls,
                        timeout_syscall_failures,
                        timeout_syscall_last_failure_epoch,
                    ) {
                        log::info!(
                            "Cooling timeout avoidance after {} stable executions",
                            AVOIDANCE_DECAY_INTERVAL
                        );
                        for edge in decay_result.unblocked_edges {
                            log::info!(
                                "Releasing timeout-prone syscall edge after cooldown: {}",
                                edge
                            );
                        }
                        for syscall_name in decay_result.unblocked_syscalls {
                            log::info!(
                                "Releasing timeout-prone syscall after cooldown: {}",
                                syscall_name
                            );
                        }
                        if let Err(e) = save_avoidance_state(
                            avoidance_path,
                            *avoidance_learning_epoch,
                            timeout_edge_failures,
                            timeout_syscall_failures,
                            timeout_edge_last_failure_epoch,
                            timeout_syscall_last_failure_epoch,
                        ) {
                            log::warn!(
                                "Failed to persist avoidance snapshot {}: {}",
                                avoidance_path.display(),
                                e
                            );
                        }
                        *choice_table = rebuild_choice_table(
                            descs,
                            corpus,
                            timeout_edge_failures,
                            timeout_syscall_failures,
                        );
                    }

                    // Check for executor-reported errors
                    if !result.error.is_empty() {
                        log::warn!("Exec error (id={}): {}", result.id, result.error);
                    }

                    // Process coverage signal
                    if let Some(ref info) = result.info {
                        let mut all_signal: Vec<u64> = Vec::new();
                        for ci in &info.calls {
                            all_signal.extend_from_slice(&ci.signal);
                        }
                        if !all_signal.is_empty() {
                            let has_new = corpus.add_result(&prog, &all_signal);
                            if has_new {
                                *choice_table = rebuild_choice_table(
                                    descs,
                                    corpus,
                                    timeout_edge_failures,
                                    timeout_syscall_failures,
                                );
                                let new_sig = corpus.take_new_signal();
                                log::info!(
                                    "New coverage! corpus={}, signal={}, new={}",
                                    corpus.len(),
                                    corpus.signal_count(),
                                    new_sig.len()
                                );
                                // Send signal update to executor
                                if let Err(e) = protocol::send_signal_update(&mut stream, &new_sig)
                                {
                                    log::warn!("Failed to send signal update: {}", e);
                                }
                                if let Err(e) = corpus.save(corpus_path) {
                                    log::warn!(
                                        "Failed to persist corpus snapshot {}: {}",
                                        corpus_path.display(),
                                        e
                                    );
                                }
                            }
                        }
                    }

                    // Check output for crashes
                    if !result.output.is_empty() {
                        if let Some(title) = crash::detect_crash(&result.output) {
                            log::warn!("Crash in exec output: {}", title);
                            let timeout_profile = timeout_profile_desc(&prog, descs);
                            let repro = build_artifact_repro_info(
                                cfg,
                                vm_index,
                                *total_execs,
                                "crash",
                                &title,
                                &prog_desc,
                                Some(&prog),
                                Some(&prog_shape),
                                Some(&timeout_profile),
                            );
                            crash::save_crash(
                                &cfg.workdir,
                                &title,
                                &result.output,
                                &prog_desc,
                                Some(&prog_shape),
                                Some(&timeout_profile),
                                Some(&repro),
                            )?;
                        }
                    }

                    if exec_limit_reached(cfg, *total_attempts) {
                        log::info!("Reached max_execs={}, ending fuzz loop", total_attempts);
                        return Ok(());
                    }
                }
                protocol::ExecutorMsg::State(data) => {
                    request_trace.record_state(request_start.elapsed().as_millis(), &data);
                    log::debug!("Received state message: {}", summarize_state_payload(&data));
                }
            }
        }

        req_id += 1;

        // Print stats periodically
        if last_stats.elapsed() > Duration::from_secs(10) {
            log::info!(
                "Stats: execs={}, corpus={}, signal={}, crashes_dir={:?}",
                total_execs,
                corpus.len(),
                corpus.signal_count(),
                crashes_dir_count(&cfg.workdir)
            );
            *last_stats = Instant::now();
        }
    }
}

/// Perform the flatrpc handshake with the executor.
fn do_handshake(
    stream: &mut std::net::TcpStream,
    cfg: &Config,
) -> Result<(), Box<dyn std::error::Error>> {
    // Step 1: Send ConnectHello with a random cookie
    let cookie: u64 = rand::random();
    protocol::send_connect_hello(stream, cookie)?;
    log::debug!("Sent ConnectHello (cookie=0x{:x})", cookie);

    // Step 2: Receive ConnectRequest from executor
    let connect_req = protocol::recv_connect_request(stream)?;
    log::info!(
        "ConnectRequest: id={}, arch={}, git={}, syz={}",
        connect_req.id,
        connect_req.arch,
        connect_req.git_revision,
        connect_req.syz_revision
    );

    // Verify auth cookie
    let expected = protocol::auth_hash(cookie);
    if connect_req.cookie != expected {
        return Err(format!(
            "Auth failed: expected cookie 0x{:x}, got 0x{:x}",
            expected, connect_req.cookie
        )
        .into());
    }
    log::debug!("Auth cookie verified");

    // Step 3: Send ConnectReply
    let features = Feature::Coverage | Feature::SandboxNone;
    protocol::send_connect_reply(
        stream,
        false,     // debug
        cfg.cover, // cover
        true,      // cover_edges
        true,      // kernel_64_bit
        cfg.procs, // procs
        cfg.slowdown,
        cfg.syscall_timeout_ms,
        cfg.program_timeout_ms,
        features,
        &[], // leak_frames
        &[], // race_frames
        &[], // files
    )?;
    log::debug!("Sent ConnectReply");

    // Step 4: Receive InfoRequest from executor
    let info_req = protocol::recv_info_request(stream)?;
    if !info_req.error.is_empty() {
        log::warn!("Executor reported error: {}", info_req.error);
    }
    for feat in &info_req.features {
        log::debug!(
            "Executor feature {:?}: need_setup={}, reason={}",
            feat.id,
            feat.need_setup,
            feat.reason
        );
    }
    for fi in &info_req.files {
        log::debug!(
            "Executor file {}: exists={}, error={}",
            fi.name,
            fi.exists,
            fi.error
        );
    }

    // Step 5: Send InfoReply with empty cover filter
    protocol::send_info_reply(stream, &[])?;
    log::debug!("Sent InfoReply");

    Ok(())
}

/// Count crash directories.
fn crashes_dir_count(workdir: &str) -> usize {
    let crashes = std::path::Path::new(workdir).join("crashes");
    match std::fs::read_dir(&crashes) {
        Ok(entries) => entries.count(),
        Err(_) => 0,
    }
}

fn program_is_blocked(blocked_programs: &HashSet<String>, prog: &program::Program) -> bool {
    blocked_programs.contains(&program::stable_program_key(prog))
}

fn remember_blocked_program(
    blocked_programs: &mut HashSet<String>,
    prog: &program::Program,
) -> bool {
    blocked_programs.insert(program::stable_program_key(prog))
}

fn note_shape_failure(
    blocked_shapes: &mut HashSet<String>,
    shape_failures: &mut HashMap<String, u32>,
    shape: &str,
) -> bool {
    let failures = shape_failures.entry(shape.to_string()).or_insert(0);
    *failures += 1;
    if *failures >= PROGRAM_SHAPE_BLOCK_THRESHOLD {
        blocked_shapes.insert(shape.to_string())
    } else {
        false
    }
}

fn timeout_prone_syscalls_in_program(
    prog: &program::Program,
    descs: &[program::SyscallDesc],
) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut syscalls = Vec::new();
    for call in &prog.calls {
        let desc = &descs[call.syscall_idx];
        if !program::syscall_is_timeout_prone(desc) {
            continue;
        }
        if seen.insert(desc.name.clone()) {
            syscalls.push(desc.name.clone());
        }
    }
    syscalls
}

fn timeout_prone_edges_in_program(
    prog: &program::Program,
    descs: &[program::SyscallDesc],
) -> Vec<String> {
    let syscalls = prog
        .calls
        .iter()
        .filter_map(|call| {
            program::syscall_is_timeout_prone(&descs[call.syscall_idx])
                .then_some(descs[call.syscall_idx].name.clone())
        })
        .collect::<Vec<_>>();
    let mut seen = HashSet::new();
    let mut edges = Vec::new();
    for window in syscalls.windows(2) {
        let edge = format!("{}->{}", window[0], window[1]);
        if seen.insert(edge.clone()) {
            edges.push(edge);
        }
    }
    edges
}

fn timeout_profile_desc(prog: &program::Program, descs: &[program::SyscallDesc]) -> String {
    let edges = timeout_prone_edges_in_program(prog, descs);
    if edges.is_empty() {
        "(none)".to_string()
    } else {
        edges.join("\n")
    }
}

fn build_artifact_repro_info(
    cfg: &Config,
    vm_index: usize,
    total_execs: u64,
    artifact_type: &str,
    summary: &str,
    program_desc: &str,
    program_ir: Option<&program::Program>,
    shape_desc: Option<&str>,
    profile_desc: Option<&str>,
) -> crash::ArtifactReproInfo {
    crash::ArtifactReproInfo {
        artifact_type: artifact_type.to_string(),
        summary: summary.to_string(),
        signature: String::new(),
        manager_instance: vm_index,
        total_execs,
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
        program: program_desc.to_string(),
        program_ir: program_ir.cloned(),
        shape: shape_desc.map(str::to_string),
        profile: profile_desc.map(str::to_string),
    }
}

fn blocked_timeout_edges_for_program(
    prog: &program::Program,
    descs: &[program::SyscallDesc],
    blocked_timeout_edges: &HashSet<String>,
) -> Vec<String> {
    timeout_prone_edges_in_program(prog, descs)
        .into_iter()
        .filter(|edge| blocked_timeout_edges.contains(edge))
        .collect()
}

fn note_timeout_edge_failures(
    blocked_timeout_edges: &mut HashSet<String>,
    timeout_edge_failures: &mut HashMap<String, u32>,
    timeout_edge_last_failure_epoch: &mut HashMap<String, u64>,
    failure_epoch: u64,
    prog: &program::Program,
    descs: &[program::SyscallDesc],
) -> Vec<String> {
    let mut newly_blocked = Vec::new();
    for edge in timeout_prone_edges_in_program(prog, descs) {
        let failures = {
            let mut state = AvoidanceState {
                learning_epoch: failure_epoch,
                timeout_edge_failures: std::mem::take(timeout_edge_failures),
                timeout_syscall_failures: HashMap::new(),
                timeout_edge_last_failure_epoch: std::mem::take(timeout_edge_last_failure_epoch),
                timeout_syscall_last_failure_epoch: HashMap::new(),
            };
            let failures = state.note_edge_failure(&edge, failure_epoch);
            *timeout_edge_failures = state.timeout_edge_failures;
            *timeout_edge_last_failure_epoch = state.timeout_edge_last_failure_epoch;
            failures
        };
        if failures >= TIMEOUT_SYSCALL_EDGE_BLOCK_THRESHOLD
            && blocked_timeout_edges.insert(edge.clone())
        {
            newly_blocked.push(edge);
        }
    }
    newly_blocked
}

fn blocked_timeout_syscalls_for_program(
    prog: &program::Program,
    descs: &[program::SyscallDesc],
    blocked_timeout_syscalls: &HashSet<String>,
) -> Vec<String> {
    timeout_prone_syscalls_in_program(prog, descs)
        .into_iter()
        .filter(|name| blocked_timeout_syscalls.contains(name))
        .collect()
}

fn note_timeout_syscall_failures(
    blocked_timeout_syscalls: &mut HashSet<String>,
    timeout_syscall_failures: &mut HashMap<String, u32>,
    timeout_syscall_last_failure_epoch: &mut HashMap<String, u64>,
    failure_epoch: u64,
    prog: &program::Program,
    descs: &[program::SyscallDesc],
) -> Vec<String> {
    let mut newly_blocked = Vec::new();
    for syscall_name in timeout_prone_syscalls_in_program(prog, descs) {
        let failures = {
            let mut state = AvoidanceState {
                learning_epoch: failure_epoch,
                timeout_edge_failures: HashMap::new(),
                timeout_syscall_failures: std::mem::take(timeout_syscall_failures),
                timeout_edge_last_failure_epoch: HashMap::new(),
                timeout_syscall_last_failure_epoch: std::mem::take(
                    timeout_syscall_last_failure_epoch,
                ),
            };
            let failures = state.note_syscall_failure(&syscall_name, failure_epoch);
            *timeout_syscall_failures = state.timeout_syscall_failures;
            *timeout_syscall_last_failure_epoch = state.timeout_syscall_last_failure_epoch;
            failures
        };
        if failures >= TIMEOUT_SYSCALL_BLOCK_THRESHOLD
            && blocked_timeout_syscalls.insert(syscall_name.clone())
        {
            newly_blocked.push(syscall_name);
        }
    }
    newly_blocked
}

fn save_avoidance_state(
    avoidance_path: &Path,
    learning_epoch: u64,
    timeout_edge_failures: &HashMap<String, u32>,
    timeout_syscall_failures: &HashMap<String, u32>,
    timeout_edge_last_failure_epoch: &HashMap<String, u64>,
    timeout_syscall_last_failure_epoch: &HashMap<String, u64>,
) -> io::Result<()> {
    let mut state = AvoidanceState {
        learning_epoch,
        timeout_edge_failures: timeout_edge_failures.clone(),
        timeout_syscall_failures: timeout_syscall_failures.clone(),
        timeout_edge_last_failure_epoch: timeout_edge_last_failure_epoch.clone(),
        timeout_syscall_last_failure_epoch: timeout_syscall_last_failure_epoch.clone(),
    };
    let _ = compact_avoidance_state(&mut state);
    state.save(avoidance_path)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AvoidanceCompactionResult {
    before_edges: usize,
    after_edges: usize,
    before_syscalls: usize,
    after_syscalls: usize,
}

fn compact_avoidance_state(state: &mut AvoidanceState) -> Option<AvoidanceCompactionResult> {
    let before_edges = state.timeout_edge_failures.len();
    let before_syscalls = state.timeout_syscall_failures.len();
    let compacted = state.compact(
        TIMEOUT_SYSCALL_EDGE_BLOCK_THRESHOLD,
        TIMEOUT_SYSCALL_BLOCK_THRESHOLD,
        AVOIDANCE_COMPACT_IDLE_EPOCHS,
    );
    let pruned = state.prune_weak_entries(
        TIMEOUT_SYSCALL_EDGE_BLOCK_THRESHOLD,
        TIMEOUT_SYSCALL_BLOCK_THRESHOLD,
        AVOIDANCE_MAX_PERSISTED_WEAK_EDGES,
        AVOIDANCE_MAX_PERSISTED_WEAK_SYSCALLS,
    );
    if !(compacted || pruned) {
        return None;
    }
    Some(AvoidanceCompactionResult {
        before_edges,
        after_edges: state.timeout_edge_failures.len(),
        before_syscalls,
        after_syscalls: state.timeout_syscall_failures.len(),
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct AvoidanceDecayResult {
    unblocked_edges: Vec<String>,
    unblocked_syscalls: Vec<String>,
}

fn maybe_decay_avoidance(
    successful_execs_since_decay: &mut u64,
    learning_epoch: u64,
    blocked_timeout_edges: &mut HashSet<String>,
    timeout_edge_failures: &mut HashMap<String, u32>,
    timeout_edge_last_failure_epoch: &mut HashMap<String, u64>,
    blocked_timeout_syscalls: &mut HashSet<String>,
    timeout_syscall_failures: &mut HashMap<String, u32>,
    timeout_syscall_last_failure_epoch: &mut HashMap<String, u64>,
) -> Option<AvoidanceDecayResult> {
    *successful_execs_since_decay += 1;
    if *successful_execs_since_decay < AVOIDANCE_DECAY_INTERVAL {
        return None;
    }
    *successful_execs_since_decay = 0;

    let mut state = AvoidanceState {
        learning_epoch,
        timeout_edge_failures: timeout_edge_failures.clone(),
        timeout_syscall_failures: timeout_syscall_failures.clone(),
        timeout_edge_last_failure_epoch: timeout_edge_last_failure_epoch.clone(),
        timeout_syscall_last_failure_epoch: timeout_syscall_last_failure_epoch.clone(),
    };
    if !state.decay_stale_weighted(AVOIDANCE_DECAY_INTERVAL, AVOIDANCE_MAX_DECAY_AMOUNT) {
        return None;
    }

    let previous_blocked_edges = blocked_timeout_edges.clone();
    let previous_blocked_syscalls = blocked_timeout_syscalls.clone();
    let next_blocked_edges = state.blocked_edges(TIMEOUT_SYSCALL_EDGE_BLOCK_THRESHOLD);
    let next_blocked_syscalls = state.blocked_syscalls(TIMEOUT_SYSCALL_BLOCK_THRESHOLD);

    let mut unblocked_edges = previous_blocked_edges
        .difference(&next_blocked_edges)
        .cloned()
        .collect::<Vec<_>>();
    unblocked_edges.sort();
    let mut unblocked_syscalls = previous_blocked_syscalls
        .difference(&next_blocked_syscalls)
        .cloned()
        .collect::<Vec<_>>();
    unblocked_syscalls.sort();

    *timeout_edge_failures = state.timeout_edge_failures;
    *timeout_syscall_failures = state.timeout_syscall_failures;
    *timeout_edge_last_failure_epoch = state.timeout_edge_last_failure_epoch;
    *timeout_syscall_last_failure_epoch = state.timeout_syscall_last_failure_epoch;
    *blocked_timeout_edges = next_blocked_edges;
    *blocked_timeout_syscalls = next_blocked_syscalls;

    Some(AvoidanceDecayResult {
        unblocked_edges,
        unblocked_syscalls,
    })
}

fn rebuild_choice_table(
    descs: &[program::SyscallDesc],
    corpus: &Corpus,
    timeout_edge_failures: &HashMap<String, u32>,
    timeout_syscall_failures: &HashMap<String, u32>,
) -> program::SyscallChoiceTable {
    program::SyscallChoiceTable::build_with_avoidance(
        descs,
        corpus.programs(),
        timeout_edge_failures,
        timeout_syscall_failures,
    )
}

fn exec_limit_reached(cfg: &Config, total_execs: u64) -> bool {
    cfg.max_execs.is_some_and(|limit| total_execs >= limit)
}

fn executor_retry_stall_reached(try_: i32, elapsed: Duration) -> bool {
    try_ >= EXECUTOR_RETRY_STALL_THRESHOLD && elapsed >= EXECUTOR_RETRY_STALL_MIN_ELAPSED
}

#[cfg(test)]
mod tests {
    use super::{
        blocked_timeout_edges_for_program, blocked_timeout_syscalls_for_program,
        compact_avoidance_state, exec_limit_reached, maybe_decay_avoidance, note_shape_failure,
        note_timeout_edge_failures, note_timeout_syscall_failures, program_is_blocked,
        remember_blocked_program, summarize_state_payload, timeout_prone_edges_in_program,
        timeout_prone_syscalls_in_program, RequestTrace, AVOIDANCE_COMPACT_IDLE_EPOCHS,
        AVOIDANCE_DECAY_INTERVAL, AVOIDANCE_MAX_PERSISTED_WEAK_EDGES,
        AVOIDANCE_MAX_PERSISTED_WEAK_SYSCALLS, EXECUTOR_RETRY_STALL_MIN_ELAPSED,
        EXECUTOR_RETRY_STALL_THRESHOLD, PROGRAM_SHAPE_BLOCK_THRESHOLD,
        TIMEOUT_SYSCALL_BLOCK_THRESHOLD, TIMEOUT_SYSCALL_EDGE_BLOCK_THRESHOLD,
    };
    use crate::avoidance::AvoidanceState;
    use crate::config::{Config, VmConfig};
    use crate::program::{
        ArgType, BufferDir, Call, LengthKind, LengthTarget, LengthTargetRoot, Program, PtrDir,
        ResourceDesc, ReturnType, ScalarEndian, SyscallAttrs, SyscallDesc,
    };
    use crate::protocol::{CallInfoData, ExecResultData, ExecutingData, ProgInfoData};
    use std::collections::{HashMap, HashSet};
    use std::time::Duration;

    fn test_config(max_execs: Option<u64>) -> Config {
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
            max_execs,
        }
    }

    #[test]
    fn exec_limit_helper_respects_optional_budget() {
        let unlimited = test_config(None);
        assert!(!exec_limit_reached(&unlimited, 0));
        assert!(!exec_limit_reached(&unlimited, 10));

        let limited = test_config(Some(3));
        assert!(!exec_limit_reached(&limited, 2));
        assert!(exec_limit_reached(&limited, 3));
        assert!(exec_limit_reached(&limited, 4));
    }

    #[test]
    fn blocked_program_helper_matches_exact_programs_only() {
        let prog_a = Program {
            calls: vec![Call {
                syscall_idx: 0,
                args: vec![],
            }],
        };
        let prog_b = Program {
            calls: vec![Call {
                syscall_idx: 1,
                args: vec![],
            }],
        };
        let mut blocked = HashSet::new();

        assert!(remember_blocked_program(&mut blocked, &prog_a));
        assert!(!remember_blocked_program(&mut blocked, &prog_a));
        assert!(program_is_blocked(&blocked, &prog_a));
        assert!(!program_is_blocked(&blocked, &prog_b));
    }

    #[test]
    fn shape_failures_block_after_threshold() {
        let mut blocked_shapes = HashSet::new();
        let mut shape_failures = HashMap::new();
        let shape = "accept$inet->listen";

        for attempt in 1..PROGRAM_SHAPE_BLOCK_THRESHOLD {
            assert!(!note_shape_failure(
                &mut blocked_shapes,
                &mut shape_failures,
                shape
            ));
            assert!(!blocked_shapes.contains(shape));
            assert_eq!(shape_failures.get(shape), Some(&attempt));
        }

        assert!(note_shape_failure(
            &mut blocked_shapes,
            &mut shape_failures,
            shape
        ));
        assert!(blocked_shapes.contains(shape));
        assert_eq!(
            shape_failures.get(shape),
            Some(&PROGRAM_SHAPE_BLOCK_THRESHOLD)
        );
    }

    fn test_fd_resource() -> ResourceDesc {
        ResourceDesc {
            kind: "fd".into(),
            size: 4,
            values: vec![!0u64],
            lineage: vec!["fd".into()],
        }
    }

    fn timeout_test_descs() -> Vec<SyscallDesc> {
        let fd = test_fd_resource();
        vec![
            SyscallDesc {
                name: "close".into(),
                id: 0,
                arg_names: vec!["fd".into()],
                args: vec![ArgType::Resource(fd.clone())],
                ret: ReturnType::Int,
                attrs: SyscallAttrs::default(),
            },
            SyscallDesc {
                name: "bind$inet".into(),
                id: 1,
                arg_names: vec!["fd".into(), "addr".into(), "addrlen".into()],
                args: vec![
                    ArgType::Resource(fd.clone()),
                    ArgType::Ptr {
                        inner: Box::new(ArgType::Buffer {
                            min_size: 16,
                            max_size: 16,
                            dir: BufferDir::In,
                        }),
                        dir: PtrDir::In,
                        optional: false,
                    },
                    ArgType::Len {
                        target: LengthTarget {
                            root: LengthTargetRoot::Arg("addr".into()),
                            fields: Vec::new(),
                        },
                        size: 4,
                        kind: LengthKind::Bytes,
                        endian: ScalarEndian::Native,
                        scale: 1,
                        bitfield_bits: None,
                    },
                ],
                ret: ReturnType::Int,
                attrs: SyscallAttrs::default(),
            },
            SyscallDesc {
                name: "accept$inet".into(),
                id: 2,
                arg_names: vec!["fd".into(), "peer".into(), "peerlen".into()],
                args: vec![
                    ArgType::Resource(fd),
                    ArgType::Ptr {
                        inner: Box::new(ArgType::Buffer {
                            min_size: 16,
                            max_size: 16,
                            dir: BufferDir::Out,
                        }),
                        dir: PtrDir::Out,
                        optional: true,
                    },
                    ArgType::Ptr {
                        inner: Box::new(ArgType::Len {
                            target: LengthTarget {
                                root: LengthTargetRoot::Arg("peer".into()),
                                fields: Vec::new(),
                            },
                            size: 4,
                            kind: LengthKind::Bytes,
                            endian: ScalarEndian::Native,
                            scale: 1,
                            bitfield_bits: None,
                        }),
                        dir: PtrDir::InOut,
                        optional: false,
                    },
                ],
                ret: ReturnType::Resource(test_fd_resource()),
                attrs: SyscallAttrs::default(),
            },
            SyscallDesc {
                name: "rename".into(),
                id: 3,
                arg_names: vec!["old".into(), "new".into()],
                args: vec![ArgType::Filename, ArgType::Filename],
                ret: ReturnType::Int,
                attrs: SyscallAttrs::default(),
            },
            SyscallDesc {
                name: "pure_const".into(),
                id: 4,
                arg_names: vec!["value".into()],
                args: vec![ArgType::Const {
                    size: 4,
                    values: vec![],
                    range: Some((0, 7)),
                    endian: ScalarEndian::Native,
                    allow_any: false,
                    bitfield_bits: None,
                }],
                ret: ReturnType::Int,
                attrs: SyscallAttrs::default(),
            },
        ]
    }

    #[test]
    fn timeout_prone_syscalls_ignore_resource_only_calls() {
        let descs = timeout_test_descs();
        let prog = Program {
            calls: vec![
                Call {
                    syscall_idx: 0,
                    args: vec![],
                },
                Call {
                    syscall_idx: 1,
                    args: vec![],
                },
                Call {
                    syscall_idx: 0,
                    args: vec![],
                },
                Call {
                    syscall_idx: 2,
                    args: vec![],
                },
                Call {
                    syscall_idx: 3,
                    args: vec![],
                },
                Call {
                    syscall_idx: 4,
                    args: vec![],
                },
            ],
        };

        assert_eq!(
            timeout_prone_syscalls_in_program(&prog, &descs),
            vec![
                "bind$inet".to_string(),
                "accept$inet".to_string(),
                "rename".to_string()
            ]
        );

        let blocked = HashSet::from(["accept$inet".to_string(), "rename".to_string()]);
        assert_eq!(
            blocked_timeout_syscalls_for_program(&prog, &descs, &blocked),
            vec!["accept$inet".to_string(), "rename".to_string()]
        );
    }

    #[test]
    fn timeout_prone_syscalls_block_after_threshold() {
        let descs = timeout_test_descs();
        let prog = Program {
            calls: vec![
                Call {
                    syscall_idx: 0,
                    args: vec![],
                },
                Call {
                    syscall_idx: 2,
                    args: vec![],
                },
            ],
        };
        let mut blocked_timeout_syscalls = HashSet::new();
        let mut timeout_syscall_failures = HashMap::new();
        let mut timeout_syscall_last_failure_epoch = HashMap::new();

        for attempt in 1..TIMEOUT_SYSCALL_BLOCK_THRESHOLD {
            let newly_blocked = note_timeout_syscall_failures(
                &mut blocked_timeout_syscalls,
                &mut timeout_syscall_failures,
                &mut timeout_syscall_last_failure_epoch,
                attempt as u64,
                &prog,
                &descs,
            );
            assert!(newly_blocked.is_empty());
            assert!(!blocked_timeout_syscalls.contains("accept$inet"));
            assert_eq!(timeout_syscall_failures.get("accept$inet"), Some(&attempt));
            assert_eq!(timeout_syscall_failures.get("close"), None);
        }

        assert_eq!(
            note_timeout_syscall_failures(
                &mut blocked_timeout_syscalls,
                &mut timeout_syscall_failures,
                &mut timeout_syscall_last_failure_epoch,
                TIMEOUT_SYSCALL_BLOCK_THRESHOLD as u64,
                &prog,
                &descs,
            ),
            vec!["accept$inet".to_string()]
        );
        assert!(blocked_timeout_syscalls.contains("accept$inet"));
        assert_eq!(
            timeout_syscall_failures.get("accept$inet"),
            Some(&TIMEOUT_SYSCALL_BLOCK_THRESHOLD)
        );
        assert_eq!(timeout_syscall_failures.get("close"), None);
    }

    #[test]
    fn timeout_prone_edges_preserve_timeout_prone_adjacency() {
        let descs = timeout_test_descs();
        let prog = Program {
            calls: vec![
                Call {
                    syscall_idx: 1,
                    args: vec![],
                },
                Call {
                    syscall_idx: 2,
                    args: vec![],
                },
                Call {
                    syscall_idx: 1,
                    args: vec![],
                },
                Call {
                    syscall_idx: 3,
                    args: vec![],
                },
            ],
        };

        assert_eq!(
            timeout_prone_edges_in_program(&prog, &descs),
            vec![
                "bind$inet->accept$inet".to_string(),
                "accept$inet->bind$inet".to_string(),
                "bind$inet->rename".to_string(),
            ]
        );

        let blocked = HashSet::from([
            "accept$inet->bind$inet".to_string(),
            "bind$inet->rename".to_string(),
        ]);
        assert_eq!(
            blocked_timeout_edges_for_program(&prog, &descs, &blocked),
            vec![
                "accept$inet->bind$inet".to_string(),
                "bind$inet->rename".to_string(),
            ]
        );
    }

    #[test]
    fn timeout_prone_edges_block_after_threshold() {
        let descs = timeout_test_descs();
        let prog = Program {
            calls: vec![
                Call {
                    syscall_idx: 1,
                    args: vec![],
                },
                Call {
                    syscall_idx: 0,
                    args: vec![],
                },
                Call {
                    syscall_idx: 2,
                    args: vec![],
                },
            ],
        };
        let mut blocked_timeout_edges = HashSet::new();
        let mut timeout_edge_failures = HashMap::new();
        let mut timeout_edge_last_failure_epoch = HashMap::new();

        for attempt in 1..TIMEOUT_SYSCALL_EDGE_BLOCK_THRESHOLD {
            let newly_blocked = note_timeout_edge_failures(
                &mut blocked_timeout_edges,
                &mut timeout_edge_failures,
                &mut timeout_edge_last_failure_epoch,
                attempt as u64,
                &prog,
                &descs,
            );
            assert!(newly_blocked.is_empty());
            assert!(!blocked_timeout_edges.contains("bind$inet->accept$inet"));
            assert_eq!(
                timeout_edge_failures.get("bind$inet->accept$inet"),
                Some(&attempt)
            );
        }

        assert_eq!(
            note_timeout_edge_failures(
                &mut blocked_timeout_edges,
                &mut timeout_edge_failures,
                &mut timeout_edge_last_failure_epoch,
                TIMEOUT_SYSCALL_EDGE_BLOCK_THRESHOLD as u64,
                &prog,
                &descs,
            ),
            vec!["bind$inet->accept$inet".to_string()]
        );
        assert!(blocked_timeout_edges.contains("bind$inet->accept$inet"));
        assert_eq!(
            timeout_edge_failures.get("bind$inet->accept$inet"),
            Some(&TIMEOUT_SYSCALL_EDGE_BLOCK_THRESHOLD)
        );
    }

    #[test]
    fn avoidance_decay_waits_for_full_stable_interval() {
        let mut successful_execs_since_decay = AVOIDANCE_DECAY_INTERVAL - 1;
        let learning_epoch = AVOIDANCE_DECAY_INTERVAL + 1;
        let mut blocked_timeout_edges = HashSet::from(["bind$inet->accept$inet".to_string()]);
        let mut timeout_edge_failures = HashMap::from([("bind$inet->accept$inet".to_string(), 2)]);
        let mut timeout_edge_last_failure_epoch =
            HashMap::from([("bind$inet->accept$inet".to_string(), 1)]);
        let mut blocked_timeout_syscalls = HashSet::from(["accept$inet".to_string()]);
        let mut timeout_syscall_failures = HashMap::from([("accept$inet".to_string(), 3)]);
        let mut timeout_syscall_last_failure_epoch =
            HashMap::from([("accept$inet".to_string(), 1)]);

        let decay = maybe_decay_avoidance(
            &mut successful_execs_since_decay,
            learning_epoch,
            &mut blocked_timeout_edges,
            &mut timeout_edge_failures,
            &mut timeout_edge_last_failure_epoch,
            &mut blocked_timeout_syscalls,
            &mut timeout_syscall_failures,
            &mut timeout_syscall_last_failure_epoch,
        )
        .expect("full stable interval should trigger decay");

        assert_eq!(successful_execs_since_decay, 0);
        assert_eq!(
            timeout_edge_failures,
            HashMap::from([("bind$inet->accept$inet".to_string(), 1)])
        );
        assert_eq!(
            timeout_syscall_failures,
            HashMap::from([("accept$inet".to_string(), 2)])
        );
        assert!(!blocked_timeout_edges.contains("bind$inet->accept$inet"));
        assert!(!blocked_timeout_syscalls.contains("accept$inet"));
        assert_eq!(
            decay.unblocked_edges,
            vec!["bind$inet->accept$inet".to_string()]
        );
        assert_eq!(decay.unblocked_syscalls, vec!["accept$inet".to_string()]);
    }

    #[test]
    fn avoidance_decay_does_not_fire_before_threshold() {
        let mut successful_execs_since_decay = AVOIDANCE_DECAY_INTERVAL - 2;
        let learning_epoch = AVOIDANCE_DECAY_INTERVAL;
        let mut blocked_timeout_edges = HashSet::from(["bind$inet->accept$inet".to_string()]);
        let mut timeout_edge_failures = HashMap::from([("bind$inet->accept$inet".to_string(), 2)]);
        let mut timeout_edge_last_failure_epoch =
            HashMap::from([("bind$inet->accept$inet".to_string(), 1)]);
        let mut blocked_timeout_syscalls = HashSet::from(["accept$inet".to_string()]);
        let mut timeout_syscall_failures = HashMap::from([("accept$inet".to_string(), 3)]);
        let mut timeout_syscall_last_failure_epoch =
            HashMap::from([("accept$inet".to_string(), 1)]);

        let decay = maybe_decay_avoidance(
            &mut successful_execs_since_decay,
            learning_epoch,
            &mut blocked_timeout_edges,
            &mut timeout_edge_failures,
            &mut timeout_edge_last_failure_epoch,
            &mut blocked_timeout_syscalls,
            &mut timeout_syscall_failures,
            &mut timeout_syscall_last_failure_epoch,
        );

        assert!(decay.is_none());
        assert_eq!(successful_execs_since_decay, AVOIDANCE_DECAY_INTERVAL - 1);
        assert_eq!(
            timeout_edge_failures.get("bind$inet->accept$inet"),
            Some(&2)
        );
        assert_eq!(timeout_syscall_failures.get("accept$inet"), Some(&3));
        assert!(blocked_timeout_edges.contains("bind$inet->accept$inet"));
        assert!(blocked_timeout_syscalls.contains("accept$inet"));
    }

    #[test]
    fn avoidance_decay_keeps_recent_failures_blocked() {
        let mut successful_execs_since_decay = AVOIDANCE_DECAY_INTERVAL - 1;
        let learning_epoch = AVOIDANCE_DECAY_INTERVAL;
        let mut blocked_timeout_edges = HashSet::from(["bind$inet->accept$inet".to_string()]);
        let mut timeout_edge_failures = HashMap::from([("bind$inet->accept$inet".to_string(), 2)]);
        let mut timeout_edge_last_failure_epoch =
            HashMap::from([("bind$inet->accept$inet".to_string(), learning_epoch)]);
        let mut blocked_timeout_syscalls = HashSet::from(["accept$inet".to_string()]);
        let mut timeout_syscall_failures = HashMap::from([("accept$inet".to_string(), 3)]);
        let mut timeout_syscall_last_failure_epoch =
            HashMap::from([("accept$inet".to_string(), learning_epoch)]);

        let decay = maybe_decay_avoidance(
            &mut successful_execs_since_decay,
            learning_epoch,
            &mut blocked_timeout_edges,
            &mut timeout_edge_failures,
            &mut timeout_edge_last_failure_epoch,
            &mut blocked_timeout_syscalls,
            &mut timeout_syscall_failures,
            &mut timeout_syscall_last_failure_epoch,
        );

        assert!(decay.is_none());
        assert_eq!(successful_execs_since_decay, 0);
        assert_eq!(
            timeout_edge_failures.get("bind$inet->accept$inet"),
            Some(&2)
        );
        assert_eq!(timeout_syscall_failures.get("accept$inet"), Some(&3));
        assert!(blocked_timeout_edges.contains("bind$inet->accept$inet"));
        assert!(blocked_timeout_syscalls.contains("accept$inet"));
    }

    #[test]
    fn avoidance_decay_old_failures_cool_faster_than_recent_ones() {
        let mut successful_execs_since_decay = AVOIDANCE_DECAY_INTERVAL - 1;
        let learning_epoch = 64;
        let mut blocked_timeout_edges =
            HashSet::from(["old-edge".to_string(), "recent-edge".to_string()]);
        let mut timeout_edge_failures =
            HashMap::from([("old-edge".to_string(), 4), ("recent-edge".to_string(), 4)]);
        let mut timeout_edge_last_failure_epoch =
            HashMap::from([("old-edge".to_string(), 0), ("recent-edge".to_string(), 40)]);
        let mut blocked_timeout_syscalls =
            HashSet::from(["old-syscall".to_string(), "recent-syscall".to_string()]);
        let mut timeout_syscall_failures = HashMap::from([
            ("old-syscall".to_string(), 4),
            ("recent-syscall".to_string(), 4),
        ]);
        let mut timeout_syscall_last_failure_epoch = HashMap::from([
            ("old-syscall".to_string(), 0),
            ("recent-syscall".to_string(), 40),
        ]);

        let decay = maybe_decay_avoidance(
            &mut successful_execs_since_decay,
            learning_epoch,
            &mut blocked_timeout_edges,
            &mut timeout_edge_failures,
            &mut timeout_edge_last_failure_epoch,
            &mut blocked_timeout_syscalls,
            &mut timeout_syscall_failures,
            &mut timeout_syscall_last_failure_epoch,
        )
        .expect("weighted cooldown should decay old and recent entries differently");

        assert_eq!(timeout_edge_failures.get("old-edge"), Some(&1));
        assert_eq!(timeout_edge_failures.get("recent-edge"), Some(&3));
        assert_eq!(timeout_syscall_failures.get("old-syscall"), Some(&1));
        assert_eq!(timeout_syscall_failures.get("recent-syscall"), Some(&3));
        assert!(!blocked_timeout_edges.contains("old-edge"));
        assert!(blocked_timeout_edges.contains("recent-edge"));
        assert!(!blocked_timeout_syscalls.contains("old-syscall"));
        assert!(blocked_timeout_syscalls.contains("recent-syscall"));
        assert_eq!(decay.unblocked_edges, vec!["old-edge".to_string()]);
        assert_eq!(decay.unblocked_syscalls, vec!["old-syscall".to_string()]);
    }

    #[test]
    fn avoidance_compaction_drops_stale_weak_entries_only() {
        let mut state = AvoidanceState {
            learning_epoch: 64,
            timeout_edge_failures: HashMap::from([
                ("stale-noise-edge".to_string(), 1),
                (
                    "blocked-edge".to_string(),
                    TIMEOUT_SYSCALL_EDGE_BLOCK_THRESHOLD,
                ),
                ("recent-noise-edge".to_string(), 1),
            ]),
            timeout_syscall_failures: HashMap::from([
                ("stale-noise-syscall".to_string(), 1),
                (
                    "blocked-syscall".to_string(),
                    TIMEOUT_SYSCALL_BLOCK_THRESHOLD,
                ),
                ("recent-noise-syscall".to_string(), 1),
            ]),
            timeout_edge_last_failure_epoch: HashMap::from([
                ("stale-noise-edge".to_string(), 0),
                ("blocked-edge".to_string(), 0),
                ("recent-noise-edge".to_string(), 63),
            ]),
            timeout_syscall_last_failure_epoch: HashMap::from([
                ("stale-noise-syscall".to_string(), 0),
                ("blocked-syscall".to_string(), 0),
                ("recent-noise-syscall".to_string(), 63),
            ]),
        };

        let compaction = compact_avoidance_state(&mut state)
            .expect("stale low-count entries should be compacted");

        assert_eq!(compaction.before_edges, 3);
        assert_eq!(compaction.after_edges, 2);
        assert_eq!(compaction.before_syscalls, 3);
        assert_eq!(compaction.after_syscalls, 2);
        assert!(!state.timeout_edge_failures.contains_key("stale-noise-edge"));
        assert!(!state
            .timeout_syscall_failures
            .contains_key("stale-noise-syscall"));
        assert_eq!(
            state.timeout_edge_failures.get("blocked-edge"),
            Some(&TIMEOUT_SYSCALL_EDGE_BLOCK_THRESHOLD)
        );
        assert_eq!(
            state.timeout_syscall_failures.get("blocked-syscall"),
            Some(&TIMEOUT_SYSCALL_BLOCK_THRESHOLD)
        );
        assert_eq!(
            state
                .timeout_edge_last_failure_epoch
                .get("recent-noise-edge"),
            Some(&63)
        );
        assert_eq!(
            state
                .timeout_syscall_last_failure_epoch
                .get("recent-noise-syscall"),
            Some(&63)
        );
        assert!(state.learning_epoch >= AVOIDANCE_COMPACT_IDLE_EPOCHS);
    }

    #[test]
    fn avoidance_compaction_caps_recent_weak_entries_to_budget() {
        let mut state = AvoidanceState {
            learning_epoch: 64,
            timeout_edge_failures: std::iter::once((
                "blocked-edge".to_string(),
                TIMEOUT_SYSCALL_EDGE_BLOCK_THRESHOLD,
            ))
            .chain((0..10).map(|idx| (format!("edge-{idx:02}"), 1)))
            .collect(),
            timeout_syscall_failures: std::iter::once((
                "blocked-syscall".to_string(),
                TIMEOUT_SYSCALL_BLOCK_THRESHOLD,
            ))
            .chain((0..10).map(|idx| {
                (
                    format!("syscall-{idx:02}"),
                    if idx < 2 {
                        TIMEOUT_SYSCALL_BLOCK_THRESHOLD - 1
                    } else {
                        1
                    },
                )
            }))
            .collect(),
            timeout_edge_last_failure_epoch: std::iter::once(("blocked-edge".to_string(), 0))
                .chain((0..10).map(|idx| (format!("edge-{idx:02}"), 64 - idx as u64)))
                .collect(),
            timeout_syscall_last_failure_epoch: std::iter::once(("blocked-syscall".to_string(), 0))
                .chain((0..10).map(|idx| (format!("syscall-{idx:02}"), 64 - idx as u64)))
                .collect(),
        };

        let compaction = compact_avoidance_state(&mut state)
            .expect("recent weak entries beyond the retention budget should be pruned");

        assert_eq!(
            compaction.after_edges,
            1 + AVOIDANCE_MAX_PERSISTED_WEAK_EDGES
        );
        assert_eq!(
            compaction.after_syscalls,
            1 + AVOIDANCE_MAX_PERSISTED_WEAK_SYSCALLS
        );
        assert!(state.timeout_edge_failures.contains_key("blocked-edge"));
        assert!(state
            .timeout_syscall_failures
            .contains_key("blocked-syscall"));
        assert!(state.timeout_edge_failures.contains_key("edge-00"));
        assert!(state.timeout_edge_failures.contains_key("edge-07"));
        assert!(!state.timeout_edge_failures.contains_key("edge-08"));
        assert!(!state.timeout_edge_failures.contains_key("edge-09"));
        assert!(state.timeout_syscall_failures.contains_key("syscall-00"));
        assert!(state.timeout_syscall_failures.contains_key("syscall-01"));
        assert!(state.timeout_syscall_failures.contains_key("syscall-07"));
        assert!(!state.timeout_syscall_failures.contains_key("syscall-08"));
        assert!(!state.timeout_syscall_failures.contains_key("syscall-09"));
    }

    #[test]
    fn summarize_state_payload_limits_hex_prefix() {
        assert_eq!(summarize_state_payload(&[]), "len=0");
        assert_eq!(
            summarize_state_payload(&[0x12, 0x34, 0xab, 0xcd]),
            "len=4 hex=1234abcd"
        );
        assert_eq!(
            summarize_state_payload(&[
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                0x0e, 0x0f, 0x10,
            ]),
            "len=17 hex=000102030405060708090a0b0c0d0e0f..."
        );
    }

    #[test]
    fn request_trace_render_includes_message_progress() {
        let mut trace = RequestTrace::default();
        trace.record_sent_exec_request(0, 7, 96);
        trace.record_executing(
            2,
            &ExecutingData {
                id: 7,
                proc_id: 1,
                try_: 0,
                wait_duration: 42,
            },
        );
        trace.record_state(4, &[0xde, 0xad, 0xbe, 0xef]);
        trace.record_read_timeout();
        trace.record_read_timeout();
        trace.record_exec_result(
            9,
            &ExecResultData {
                id: 7,
                proc: 1,
                output: vec![1, 2, 3],
                hanged: false,
                error: "oops".to_string(),
                info: Some(ProgInfoData {
                    calls: vec![CallInfoData {
                        flags: 1,
                        error: 0,
                        signal: vec![11, 22],
                        cover: vec![33],
                    }],
                    elapsed: 1234,
                    freshness: 9,
                }),
            },
        );

        let rendered = String::from_utf8(trace.render("manager_request_timeout", 15_000))
            .expect("trace should be utf-8");
        assert!(
            rendered.contains("final_reason=manager_request_timeout at_ms=15000 read_timeouts=2")
        );
        assert!(rendered.contains("[t+0ms] sent_exec_request id=7 prog_bytes=96"));
        assert!(rendered.contains("[t+2ms] executing id=7 proc=1 try=0 wait_duration_raw=42"));
        assert!(rendered.contains("[t+4ms] state len=4 hex=deadbeef"));
        assert!(rendered.contains(
            "[t+9ms] exec_result id=7 proc=1 hanged=false output_len=3 error=\"oops\" calls=1 elapsed_ns=1234 freshness=9"
        ));
    }

    #[test]
    fn executor_retry_stall_guard_waits_for_threshold_and_min_elapsed() {
        assert!(!super::executor_retry_stall_reached(
            EXECUTOR_RETRY_STALL_THRESHOLD - 1,
            EXECUTOR_RETRY_STALL_MIN_ELAPSED
        ));
        assert!(!super::executor_retry_stall_reached(
            EXECUTOR_RETRY_STALL_THRESHOLD,
            EXECUTOR_RETRY_STALL_MIN_ELAPSED - Duration::from_millis(1)
        ));
        assert!(super::executor_retry_stall_reached(
            EXECUTOR_RETRY_STALL_THRESHOLD,
            EXECUTOR_RETRY_STALL_MIN_ELAPSED
        ));
    }
}
