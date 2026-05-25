use std::io;
use std::process::{Command, Output};
use std::time::{Duration, Instant};

/// Common SSH options for syzkaller VM connections.
fn ssh_base_args(key: &str, port: u16) -> Vec<String> {
    vec![
        "-p".into(),
        port.to_string(),
        "-F".into(),
        "/dev/null".into(),
        "-o".into(),
        "UserKnownHostsFile=/dev/null".into(),
        "-o".into(),
        "IdentitiesOnly=yes".into(),
        "-o".into(),
        "BatchMode=yes".into(),
        "-o".into(),
        "StrictHostKeyChecking=no".into(),
        "-o".into(),
        "ConnectTimeout=10".into(),
        "-i".into(),
        key.into(),
    ]
}

/// Wait for SSH to become available on the given port.
pub fn wait_for_ssh(key: &str, user: &str, port: u16, timeout: Duration) -> io::Result<()> {
    let start = Instant::now();
    loop {
        if start.elapsed() > timeout {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("SSH not available after {:?}", timeout),
            ));
        }
        let mut args = ssh_base_args(key, port);
        args.extend_from_slice(&[
            "-o".into(),
            "ConnectTimeout=5".into(),
            format!("{}@localhost", user),
            "echo".into(),
            "ok".into(),
        ]);
        let status = Command::new("ssh")
            .args(&args)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
        match status {
            Ok(s) if s.success() => {
                log::info!("SSH connection ready on port {}", port);
                return Ok(());
            }
            _ => {
                std::thread::sleep(Duration::from_secs(3));
            }
        }
    }
}

/// Copy a file to the VM via SCP.
pub fn scp_to_vm(
    key: &str,
    user: &str,
    port: u16,
    local_path: &str,
    remote_path: &str,
) -> io::Result<()> {
    let args = vec![
        "-P".into(),
        port.to_string(),
        "-F".into(),
        "/dev/null".into(),
        "-o".into(),
        "UserKnownHostsFile=/dev/null".into(),
        "-o".into(),
        "IdentitiesOnly=yes".into(),
        "-o".into(),
        "BatchMode=yes".into(),
        "-o".into(),
        "StrictHostKeyChecking=no".into(),
        "-o".into(),
        "ConnectTimeout=10".into(),
        "-i".into(),
        key.into(),
        local_path.into(),
        format!("{}@localhost:{}", user, remote_path),
    ];
    let output = Command::new("scp").args(&args).output()?;
    if !output.status.success() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("scp failed: {}", String::from_utf8_lossy(&output.stderr)),
        ));
    }
    Ok(())
}

/// Execute a command in the VM via SSH with reverse port forwarding.
/// Returns the child process (caller must manage its lifetime).
pub fn ssh_run_with_forward(
    key: &str,
    user: &str,
    ssh_port: u16,
    forward_port: u16,
    command: &str,
) -> io::Result<std::process::Child> {
    let mut args = ssh_base_args(key, ssh_port);
    // Reverse port forward: -R <remote_port>:127.0.0.1:<local_port>
    args.push("-R".into());
    args.push(format!("{}:127.0.0.1:{}", forward_port, forward_port));
    args.push(format!("{}@localhost", user));
    args.push(command.into());

    log::info!(
        "SSH command: ssh {} {} {}",
        args[..args.len() - 2].join(" "),
        format!("{}@localhost", user),
        command
    );

    let child = Command::new("ssh")
        .args(&args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?;
    Ok(child)
}

/// Execute a simple SSH command and return its output.
pub fn ssh_exec(key: &str, user: &str, port: u16, command: &str) -> io::Result<Output> {
    let mut args = ssh_base_args(key, port);
    args.push(format!("{}@localhost", user));
    args.push(command.into());
    Command::new("ssh").args(&args).output()
}
