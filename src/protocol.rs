use crate::flatrpc_generated::rpc::*;
use flatbuffers::FlatBufferBuilder;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};

/// Auth hash matching the Go/C++ implementation:
/// (value * 73856093) ^ 83492791
pub fn auth_hash(value: u64) -> u64 {
    let prime1: u64 = 73856093;
    let prime2: u64 = 83492791;
    (value.wrapping_mul(prime1)) ^ prime2
}

/// Send a size-prefixed flatbuffers message over a TCP stream.
pub fn send_raw(stream: &mut TcpStream, data: &[u8]) -> io::Result<()> {
    stream.write_all(data)?;
    stream.flush()?;
    Ok(())
}

/// Build and send a ConnectHello message.
pub fn send_connect_hello(stream: &mut TcpStream, cookie: u64) -> io::Result<()> {
    let mut builder = FlatBufferBuilder::with_capacity(64);
    let args = ConnectHelloRawArgs { cookie };
    let off = ConnectHelloRaw::create(&mut builder, &args);
    builder.finish_size_prefixed(off, None);
    send_raw(stream, builder.finished_data())
}

/// Build and send a ConnectReply message.
pub fn send_connect_reply(
    stream: &mut TcpStream,
    debug: bool,
    cover: bool,
    cover_edges: bool,
    kernel_64_bit: bool,
    procs: i32,
    slowdown: i32,
    syscall_timeout_ms: i32,
    program_timeout_ms: i32,
    features: Feature,
    leak_frames: &[&str],
    race_frames: &[&str],
    files: &[&str],
) -> io::Result<()> {
    let mut builder = FlatBufferBuilder::with_capacity(1024);
    let leak_offsets: Vec<_> = leak_frames
        .iter()
        .map(|s| builder.create_string(s))
        .collect();
    let race_offsets: Vec<_> = race_frames
        .iter()
        .map(|s| builder.create_string(s))
        .collect();
    let file_offsets: Vec<_> = files.iter().map(|s| builder.create_string(s)).collect();
    let leak_vec = builder.create_vector(&leak_offsets);
    let race_vec = builder.create_vector(&race_offsets);
    let file_vec = builder.create_vector(&file_offsets);

    let args = ConnectReplyRawArgs {
        debug,
        cover,
        cover_edges,
        kernel_64_bit: kernel_64_bit,
        procs,
        slowdown,
        syscall_timeout_ms,
        program_timeout_ms,
        features,
        leak_frames: Some(leak_vec),
        race_frames: Some(race_vec),
        files: Some(file_vec),
    };
    let off = ConnectReplyRaw::create(&mut builder, &args);
    builder.finish_size_prefixed(off, None);
    send_raw(stream, builder.finished_data())
}

/// Build and send an InfoReply message (with empty cover filter for v1).
pub fn send_info_reply(stream: &mut TcpStream, cover_filter: &[u64]) -> io::Result<()> {
    let mut builder = FlatBufferBuilder::with_capacity(256);
    let filter_vec = if cover_filter.is_empty() {
        None
    } else {
        Some(builder.create_vector(cover_filter))
    };
    let args = InfoReplyRawArgs {
        cover_filter: filter_vec,
    };
    let off = InfoReplyRaw::create(&mut builder, &args);
    builder.finish_size_prefixed(off, None);
    send_raw(stream, builder.finished_data())
}

/// Build and send a HostMessage wrapping an ExecRequest.
pub fn send_exec_request(
    stream: &mut TcpStream,
    id: i64,
    prog_data: &[u8],
    env_flags: ExecEnv,
    exec_flags: ExecFlag,
    request_flags: RequestFlag,
    sandbox_arg: i64,
    all_signal: &[i32],
) -> io::Result<()> {
    let mut builder = FlatBufferBuilder::with_capacity(prog_data.len() + 512);

    let data_vec = builder.create_vector(prog_data);
    let signal_vec = if all_signal.is_empty() {
        None
    } else {
        Some(builder.create_vector(all_signal))
    };

    let exec_opts = &ExecOptsRaw::new(env_flags, exec_flags, sandbox_arg);

    let exec_args = ExecRequestRawArgs {
        id,
        type_: RequestType::Program,
        avoid: 0,
        data: Some(data_vec),
        exec_opts: Some(exec_opts),
        flags: request_flags,
        all_signal: signal_vec,
    };
    let exec_off = ExecRequestRaw::create(&mut builder, &exec_args);

    let host_args = HostMessageRawArgs {
        msg_type: HostMessagesRaw::ExecRequest,
        msg: Some(exec_off.as_union_value()),
    };
    let host_off = HostMessageRaw::create(&mut builder, &host_args);
    builder.finish_size_prefixed(host_off, None);
    send_raw(stream, builder.finished_data())
}

/// Build and send a HostMessage wrapping a SignalUpdate.
pub fn send_signal_update(stream: &mut TcpStream, new_max: &[u64]) -> io::Result<()> {
    let mut builder = FlatBufferBuilder::with_capacity(new_max.len() * 8 + 128);
    let vec = builder.create_vector(new_max);
    let sig_args = SignalUpdateRawArgs { new_max: Some(vec) };
    let sig_off = SignalUpdateRaw::create(&mut builder, &sig_args);

    let host_args = HostMessageRawArgs {
        msg_type: HostMessagesRaw::SignalUpdate,
        msg: Some(sig_off.as_union_value()),
    };
    let host_off = HostMessageRaw::create(&mut builder, &host_args);
    builder.finish_size_prefixed(host_off, None);
    send_raw(stream, builder.finished_data())
}

/// Build and send a HostMessage wrapping CorpusTriaged.
pub fn send_corpus_triaged(stream: &mut TcpStream) -> io::Result<()> {
    let mut builder = FlatBufferBuilder::with_capacity(64);
    let ct_args = CorpusTriagedRawArgs {};
    let ct_off = CorpusTriagedRaw::create(&mut builder, &ct_args);

    let host_args = HostMessageRawArgs {
        msg_type: HostMessagesRaw::CorpusTriaged,
        msg: Some(ct_off.as_union_value()),
    };
    let host_off = HostMessageRaw::create(&mut builder, &host_args);
    builder.finish_size_prefixed(host_off, None);
    send_raw(stream, builder.finished_data())
}

// ============================
// Receiving messages
// ============================

const MAX_MSG_SIZE: usize = 64 << 20; // 64 MB

/// Read a size-prefixed flatbuffers message from a stream.
/// Returns the raw bytes of the message (without the 4-byte size prefix).
pub fn recv_raw(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut size_buf = [0u8; 4];
    stream.read_exact(&mut size_buf)?;
    let size = u32::from_le_bytes(size_buf) as usize;
    if size > MAX_MSG_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("message too large: {}", size),
        ));
    }
    let mut buf = vec![0u8; size];
    stream.read_exact(&mut buf)?;
    Ok(buf)
}

/// Parsed ConnectRequest data.
#[derive(Debug)]
pub struct ConnectRequestData {
    pub cookie: u64,
    pub id: i64,
    pub arch: String,
    pub git_revision: String,
    pub syz_revision: String,
}

/// Receive and parse a ConnectRequest.
pub fn recv_connect_request(stream: &mut TcpStream) -> io::Result<ConnectRequestData> {
    let buf = recv_raw(stream)?;
    // Safety: data comes from our trusted executor binary.
    // Using unchecked to avoid overly strict alignment verification.
    let msg = unsafe { flatbuffers::root_unchecked::<ConnectRequestRaw>(&buf) };
    Ok(ConnectRequestData {
        cookie: msg.cookie(),
        id: msg.id(),
        arch: msg.arch().unwrap_or("").to_string(),
        git_revision: msg.git_revision().unwrap_or("").to_string(),
        syz_revision: msg.syz_revision().unwrap_or("").to_string(),
    })
}

/// Parsed InfoRequest data.
#[derive(Debug)]
pub struct InfoRequestData {
    pub error: String,
    pub features: Vec<FeatureInfoData>,
    pub files: Vec<FileInfoData>,
}

#[derive(Debug)]
pub struct FeatureInfoData {
    pub id: Feature,
    pub need_setup: bool,
    pub reason: String,
}

#[derive(Debug)]
pub struct FileInfoData {
    pub name: String,
    pub exists: bool,
    pub error: String,
    pub data: Vec<u8>,
}

/// Receive and parse an InfoRequest.
pub fn recv_info_request(stream: &mut TcpStream) -> io::Result<InfoRequestData> {
    let buf = recv_raw(stream)?;
    let msg = unsafe { flatbuffers::root_unchecked::<InfoRequestRaw>(&buf) };

    let mut features = Vec::new();
    if let Some(feats) = msg.features() {
        for i in 0..feats.len() {
            let f = feats.get(i);
            features.push(FeatureInfoData {
                id: f.id(),
                need_setup: f.need_setup(),
                reason: f.reason().unwrap_or("").to_string(),
            });
        }
    }

    let mut files = Vec::new();
    if let Some(fis) = msg.files() {
        for i in 0..fis.len() {
            let fi = fis.get(i);
            files.push(FileInfoData {
                name: fi.name().unwrap_or("").to_string(),
                exists: fi.exists(),
                error: fi.error().unwrap_or("").to_string(),
                data: fi.data().map(|d| d.to_vec()).unwrap_or_default(),
            });
        }
    }

    Ok(InfoRequestData {
        error: msg.error().unwrap_or("").to_string(),
        features,
        files,
    })
}

/// Parsed executor message types.
#[derive(Debug)]
pub enum ExecutorMsg {
    Executing(ExecutingData),
    ExecResult(ExecResultData),
    State(Vec<u8>),
}

#[derive(Debug)]
pub struct ExecutingData {
    pub id: i64,
    pub proc_id: i32,
    pub try_: i32,
    pub wait_duration: i64,
}

#[derive(Debug)]
pub struct ExecResultData {
    pub id: i64,
    pub proc: i32,
    pub output: Vec<u8>,
    pub hanged: bool,
    pub error: String,
    pub info: Option<ProgInfoData>,
}

#[derive(Debug, Clone)]
pub struct ProgInfoData {
    pub calls: Vec<CallInfoData>,
    pub elapsed: u64,
    pub freshness: u64,
}

#[derive(Debug, Clone)]
pub struct CallInfoData {
    pub flags: u8,
    pub error: i32,
    pub signal: Vec<u64>,
    pub cover: Vec<u64>,
}

/// Receive and parse an ExecutorMessage.
pub fn recv_executor_message(stream: &mut TcpStream) -> io::Result<ExecutorMsg> {
    let buf = recv_raw(stream)?;
    let msg = unsafe { flatbuffers::root_unchecked::<ExecutorMessageRaw>(&buf) };

    match msg.msg_type() {
        ExecutorMessagesRaw::Executing => {
            let exec = msg.msg_as_executing().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "missing Executing data")
            })?;
            Ok(ExecutorMsg::Executing(ExecutingData {
                id: exec.id(),
                proc_id: exec.proc_id(),
                try_: exec.r#try(),
                wait_duration: exec.wait_duration(),
            }))
        }
        ExecutorMessagesRaw::ExecResult => {
            let res = msg.msg_as_exec_result().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "missing ExecResult data")
            })?;

            let info = res.info().map(|pi| {
                let mut calls = Vec::new();
                if let Some(ci) = pi.calls() {
                    for i in 0..ci.len() {
                        let c = ci.get(i);
                        calls.push(CallInfoData {
                            flags: c.flags().bits(),
                            error: c.error(),
                            signal: c
                                .signal()
                                .map(|s| (0..s.len()).map(|j| s.get(j)).collect())
                                .unwrap_or_default(),
                            cover: c
                                .cover()
                                .map(|s| (0..s.len()).map(|j| s.get(j)).collect())
                                .unwrap_or_default(),
                        });
                    }
                }
                // Also collect extra_raw signal
                if let Some(er) = pi.extra_raw() {
                    for i in 0..er.len() {
                        let c = er.get(i);
                        let mut signal: Vec<u64> = Vec::new();
                        if let Some(s) = c.signal() {
                            for j in 0..s.len() {
                                signal.push(s.get(j));
                            }
                        }
                        if !signal.is_empty() {
                            // Merge extra signal into a synthetic call entry
                            calls.push(CallInfoData {
                                flags: c.flags().bits(),
                                error: 0,
                                signal,
                                cover: Vec::new(),
                            });
                        }
                    }
                }
                ProgInfoData {
                    calls,
                    elapsed: pi.elapsed(),
                    freshness: pi.freshness(),
                }
            });

            Ok(ExecutorMsg::ExecResult(ExecResultData {
                id: res.id(),
                proc: res.proc_(),
                output: res.output().map(|o| o.to_vec()).unwrap_or_default(),
                hanged: res.hanged(),
                error: res.error().unwrap_or("").to_string(),
                info,
            }))
        }
        ExecutorMessagesRaw::State => {
            let st = msg
                .msg_as_state()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing State data"))?;
            Ok(ExecutorMsg::State(
                st.data().map(|d| d.to_vec()).unwrap_or_default(),
            ))
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unknown executor message type: {:?}", msg.msg_type()),
        )),
    }
}
