use serde::Deserialize;
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub workdir: String,
    pub kernel_obj: String,
    pub image: String,
    pub sshkey: String,
    #[serde(default = "default_ssh_user")]
    pub ssh_user: String,
    pub executor: String,
    /// Optional exported target bundle override.
    #[serde(default)]
    pub target_bundle: Option<String>,
    /// Optional syscall description override. May point to a single file or a directory of fragments.
    #[serde(default)]
    pub syscall_descriptions: Option<String>,
    #[serde(default = "default_procs")]
    pub procs: i32,
    #[serde(default = "default_sandbox")]
    pub sandbox: String,
    #[serde(default)]
    pub cover: bool,
    pub vm: VmConfig,
    /// Timeouts
    #[serde(default = "default_syscall_timeout_ms")]
    pub syscall_timeout_ms: i32,
    #[serde(default = "default_program_timeout_ms")]
    pub program_timeout_ms: i32,
    #[serde(default = "default_slowdown")]
    pub slowdown: i32,
    /// Optional execution budget for bounded fuzzing or end-to-end smoke tests.
    #[serde(default)]
    pub max_execs: Option<u64>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct VmConfig {
    #[serde(default = "default_count")]
    pub count: usize,
    pub kernel: String,
    #[serde(default = "default_cpu")]
    pub cpu: usize,
    #[serde(default = "default_mem")]
    pub mem: usize,
    #[serde(default)]
    pub qemu_args: String,
    #[serde(default = "default_qemu")]
    pub qemu: String,
    #[serde(default = "default_cmdline")]
    pub cmdline: String,
}

fn default_ssh_user() -> String {
    "root".into()
}
fn default_procs() -> i32 {
    1
}
fn default_sandbox() -> String {
    "none".into()
}
fn default_count() -> usize {
    1
}
fn default_cpu() -> usize {
    2
}
fn default_mem() -> usize {
    2048
}
fn default_qemu() -> String {
    "qemu-system-x86_64".into()
}
fn default_syscall_timeout_ms() -> i32 {
    500
}
fn default_program_timeout_ms() -> i32 {
    5000
}
fn default_slowdown() -> i32 {
    1
}
fn default_cmdline() -> String {
    "console=ttyS0 root=/dev/sda earlyprintk=serial net.ifnames=0".into()
}

impl Config {
    pub fn load(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let data = fs::read_to_string(path)?;
        let cfg: Config = serde_json::from_str(&data)?;
        // Ensure workdir exists
        fs::create_dir_all(&cfg.workdir)?;
        Ok(cfg)
    }

    pub fn workdir_instance(&self, index: usize) -> PathBuf {
        PathBuf::from(&self.workdir).join(format!("instance-{}", index))
    }
}
