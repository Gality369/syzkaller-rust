use crate::config::Config;
use crate::corpus::Corpus;
use crate::crash;
use crate::exec;
use crate::flatrpc_generated::rpc::*;
use crate::fuzzer;
use crate::program;
use crate::protocol;
use crate::qemu::QemuInstance;

use rand::SeedableRng;
use std::io;
use std::net::TcpListener;
use std::time::{Duration, Instant};

/// Main entry point: start VM, connect executor, run fuzz loop.
pub fn run(cfg: Config) -> Result<(), Box<dyn std::error::Error>> {
    let descs = program::get_syscall_descs();
    let mut corpus = Corpus::new();
    let mut rng = rand::rngs::StdRng::from_entropy();

    std::fs::create_dir_all(&cfg.workdir)?;
    let crashes_dir = std::path::Path::new(&cfg.workdir).join("crashes");
    std::fs::create_dir_all(&crashes_dir)?;

    let mut vm_index: usize = 0;
    let mut total_execs: u64 = 0;
    let mut last_stats = Instant::now();

    // Outer loop: restart VM on crash or disconnect
    loop {
        log::info!("=== Starting VM instance {} ===", vm_index);
        match run_instance(&cfg, &descs, &mut corpus, &mut rng, &mut total_execs, &mut last_stats, vm_index) {
            Ok(()) => {
                log::info!("Instance {} finished normally", vm_index);
            }
            Err(e) => {
                log::error!("Instance {} failed: {}", vm_index, e);
            }
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
    rng: &mut rand::rngs::StdRng,
    total_execs: &mut u64,
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
    let mut _executor_ssh = vm.run_with_forward(cfg, flatrpc_port, &executor_cmd)?;

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
                    return Err(format!("VM died before executor connected. Serial:\n{}", 
                        &serial_str[serial_str.len().saturating_sub(2000)..]).into());
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
                crash::save_crash(&cfg.workdir, &title, &serial, &prog_desc)?;
            }
            return Err("VM exited".into());
        }

        // Check serial for crashes periodically (not every exec, it's heavy)
        if *total_execs % 10 == 0 {
            let serial = vm.get_serial_output();
            if let Some(title) = crash::detect_crash(&serial) {
                log::warn!("Crash detected from serial: {}", title);
                let prog_desc = format!("(fuzzing in progress, exec #{})", total_execs);
                crash::save_crash(&cfg.workdir, &title, &serial, &prog_desc)?;
                return Err(format!("Crash: {}", title).into());
            }
        }

        // Generate or mutate a program
        let prog = if corpus.len() > 0 && rand::Rng::gen_bool(rng, 0.8) {
            // 80% chance: mutate from corpus
            let base = corpus.random_program(rng).unwrap().clone();
            fuzzer::mutate(&base, descs, rng)
        } else {
            // 20% chance: generate fresh
            fuzzer::generate(descs, rng)
        };

        // Serialize and send
        let prog_data = exec::serialize_program(&prog, descs);
        // Must set sandbox flag so executor knows how to run; add Signal for coverage
        let mut env_flags = ExecEnv::SandboxNone;
        if cfg.cover {
            env_flags |= ExecEnv::Signal;
        }
        let exec_flags = ExecFlag::CollectSignal;

        protocol::send_exec_request(
            &mut stream,
            req_id,
            &prog_data,
            env_flags,
            exec_flags,
            0, // sandbox_arg
            &[], // all_signal (empty for now)
        )?;

        executing_ids.insert(req_id);

        // Receive response(s) with timeout
        // The executor may retry hanging programs indefinitely, so we cap wait time.
        let mut got_result = false;
        let request_start = Instant::now();
        let request_timeout = Duration::from_secs(15);
        while !got_result {
            if request_start.elapsed() > request_timeout {
                log::warn!("Request {} timed out after {:?}, restarting VM", req_id, request_timeout);
                return Err("program execution timed out".into());
            }
            let msg = protocol::recv_executor_message(&mut stream);
            let msg = match msg {
                Ok(m) => m,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut => {
                    // Read timeout, check if we should give up
                    continue;
                }
                Err(e) => return Err(e.into()),
            };
            match msg {
                protocol::ExecutorMsg::Executing(data) => {
                    log::debug!("Executing: id={}, proc={}", data.id, data.proc_id);
                }
                protocol::ExecutorMsg::ExecResult(result) => {
                    got_result = true;
                    executing_ids.remove(&result.id);
                    *total_execs += 1;

                    log::debug!("ExecResult: id={}, hanged={}, error='{}', output_len={}, has_info={}",
                        result.id, result.hanged, result.error, result.output.len(),
                        result.info.is_some());

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
                                let new_sig = corpus.take_new_signal();
                                log::info!("New coverage! corpus={}, signal={}, new={}",
                                    corpus.len(), corpus.signal_count(), new_sig.len());
                                // Send signal update to executor
                                if let Err(e) = protocol::send_signal_update(&mut stream, &new_sig) {
                                    log::warn!("Failed to send signal update: {}", e);
                                }
                            }
                        }
                    }

                    // Check output for crashes
                    if !result.output.is_empty() {
                        if let Some(title) = crash::detect_crash(&result.output) {
                            log::warn!("Crash in exec output: {}", title);
                            let prog_desc = fuzzer::describe_program(&prog, descs);
                            crash::save_crash(&cfg.workdir, &title, &result.output, &prog_desc)?;
                        }
                    }
                }
                protocol::ExecutorMsg::State(_) => {
                    log::debug!("Received state message (ignored)");
                }
            }
        }

        req_id += 1;

        // Print stats periodically
        if last_stats.elapsed() > Duration::from_secs(10) {
            log::info!("Stats: execs={}, corpus={}, signal={}, crashes_dir={:?}",
                total_execs, corpus.len(), corpus.signal_count(), crashes_dir_count(&cfg.workdir));
            *last_stats = Instant::now();
        }
    }
}

/// Perform the flatrpc handshake with the executor.
fn do_handshake(stream: &mut std::net::TcpStream, cfg: &Config) -> Result<(), Box<dyn std::error::Error>> {
    // Step 1: Send ConnectHello with a random cookie
    let cookie: u64 = rand::random();
    protocol::send_connect_hello(stream, cookie)?;
    log::debug!("Sent ConnectHello (cookie=0x{:x})", cookie);

    // Step 2: Receive ConnectRequest from executor
    let connect_req = protocol::recv_connect_request(stream)?;
    log::info!("ConnectRequest: id={}, arch={}, git={}, syz={}",
        connect_req.id, connect_req.arch, connect_req.git_revision, connect_req.syz_revision);

    // Verify auth cookie
    let expected = protocol::auth_hash(cookie);
    if connect_req.cookie != expected {
        return Err(format!(
            "Auth failed: expected cookie 0x{:x}, got 0x{:x}",
            expected, connect_req.cookie
        ).into());
    }
    log::debug!("Auth cookie verified");

    // Step 3: Send ConnectReply
    let features = Feature::Coverage | Feature::SandboxNone;
    protocol::send_connect_reply(
        stream,
        false,      // debug
        cfg.cover,  // cover
        true,       // cover_edges
        true,       // kernel_64_bit
        cfg.procs,  // procs
        cfg.slowdown,
        cfg.syscall_timeout_ms,
        cfg.program_timeout_ms,
        features,
        &[],        // leak_frames
        &[],        // race_frames
        &[],        // files
    )?;
    log::debug!("Sent ConnectReply");

    // Step 4: Receive InfoRequest from executor
    let info_req = protocol::recv_info_request(stream)?;
    if !info_req.error.is_empty() {
        log::warn!("Executor reported error: {}", info_req.error);
    }
    for feat in &info_req.features {
        log::debug!("Executor feature {:?}: need_setup={}, reason={}",
            feat.id, feat.need_setup, feat.reason);
    }
    for fi in &info_req.files {
        log::debug!("Executor file {}: exists={}, error={}",
            fi.name, fi.exists, fi.error);
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
