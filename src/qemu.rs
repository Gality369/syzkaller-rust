use crate::config::Config;
use crate::ssh;
use std::io::{self, BufRead, BufReader};
use std::net::TcpListener;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// A running QEMU VM instance.
pub struct QemuInstance {
    pub index: usize,
    pub ssh_port: u16,
    pub serial_output: Arc<Mutex<Vec<u8>>>,
    qemu_process: Child,
    ssh_reader_handle: Option<std::thread::JoinHandle<()>>,
}

/// Find a free TCP port.
fn find_free_port() -> io::Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    drop(listener);
    Ok(port)
}

impl QemuInstance {
    /// Start a new QEMU VM instance.
    pub fn start(cfg: &Config, index: usize) -> io::Result<Self> {
        let ssh_port = find_free_port()?;
        let serial_output = Arc::new(Mutex::new(Vec::new()));

        // Build QEMU args
        let mut args: Vec<String> = vec![
            "-m".into(), cfg.vm.mem.to_string(),
            "-smp".into(), cfg.vm.cpu.to_string(),
            "-display".into(), "none".into(),
            "-serial".into(), "stdio".into(),
            "-no-reboot".into(),
            "-name".into(), format!("syzkaller-rust-VM-{}", index),
            // Enable KVM
            "-enable-kvm".into(),
            // Networking with SSH port forward
            "-device".into(), "e1000,netdev=net0".into(),
            "-netdev".into(), format!(
                "user,id=net0,restrict=on,hostfwd=tcp:127.0.0.1:{}-:22",
                ssh_port
            ),
        ];

        // Disk image
        args.extend_from_slice(&[
            "-snapshot".into(),
            "-hda".into(), cfg.image.clone(),
        ]);

        // Kernel boot
        args.extend_from_slice(&[
            "-kernel".into(), cfg.vm.kernel.clone(),
            "-append".into(), cfg.vm.cmdline.clone(),
        ]);

        // Extra QEMU args from config
        if !cfg.vm.qemu_args.is_empty() {
            let extra: Vec<String> = cfg.vm.qemu_args
                .split_whitespace()
                .map(|s| s.to_string())
                .collect();
            args.extend(extra);
        }

        log::info!("VM {}: Starting QEMU on SSH port {}", index, ssh_port);
        log::debug!("VM {}: qemu args: {:?}", index, args);

        let mut child = Command::new(&cfg.vm.qemu)
            .args(&args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;

        // Capture serial output (stdout) in background
        let serial_clone = serial_output.clone();
        let stdout = child.stdout.take().unwrap();
        let idx = index;
        let reader_handle = std::thread::spawn(move || {
            let reader = BufReader::new(stdout);
            for line in reader.lines() {
                match line {
                    Ok(line) => {
                        log::trace!("VM {} serial: {}", idx, line);
                        let mut buf = serial_clone.lock().unwrap();
                        buf.extend_from_slice(line.as_bytes());
                        buf.push(b'\n');
                        // Keep last 256KB of serial output
                        if buf.len() > 256 * 1024 {
                            let drain = buf.len() - 128 * 1024;
                            buf.drain(..drain);
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        Ok(QemuInstance {
            index,
            ssh_port,
            serial_output,
            qemu_process: child,
            ssh_reader_handle: Some(reader_handle),
        })
    }

    /// Wait for SSH to become available.
    pub fn wait_ssh(&self, cfg: &Config, timeout: Duration) -> io::Result<()> {
        ssh::wait_for_ssh(&cfg.sshkey, &cfg.ssh_user, self.ssh_port, timeout)
    }

    /// Copy a file into the VM.
    pub fn scp(&self, cfg: &Config, local_path: &str, remote_path: &str) -> io::Result<()> {
        ssh::scp_to_vm(&cfg.sshkey, &cfg.ssh_user, self.ssh_port, local_path, remote_path)
    }

    /// Run a command via SSH with reverse port forwarding.
    pub fn run_with_forward(
        &self,
        cfg: &Config,
        forward_port: u16,
        command: &str,
    ) -> io::Result<Child> {
        ssh::ssh_run_with_forward(
            &cfg.sshkey,
            &cfg.ssh_user,
            self.ssh_port,
            forward_port,
            command,
        )
    }

    /// Get recent serial output for crash detection.
    pub fn get_serial_output(&self) -> Vec<u8> {
        self.serial_output.lock().unwrap().clone()
    }

    /// Kill the QEMU process.
    pub fn kill(&mut self) {
        let _ = self.qemu_process.kill();
        let _ = self.qemu_process.wait();
        if let Some(h) = self.ssh_reader_handle.take() {
            let _ = h.join();
        }
    }

    /// Check if the QEMU process is still running.
    pub fn is_running(&mut self) -> bool {
        match self.qemu_process.try_wait() {
            Ok(Some(_)) => false,
            Ok(None) => true,
            Err(_) => false,
        }
    }
}

impl Drop for QemuInstance {
    fn drop(&mut self) {
        self.kill();
    }
}
