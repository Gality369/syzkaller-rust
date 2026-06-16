use crate::config::Config;
use crate::program::{self, SyscallDesc};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetSource {
    BuiltinMinimal,
    DescriptionPath(PathBuf),
    BundlePath(PathBuf),
}

impl TargetSource {
    pub fn from_config(cfg: &Config, cli_override: Option<&str>) -> Result<Self, String> {
        if let Some(value) = cli_override {
            return Self::from_cli_arg(value);
        }
        if let Some(path) = cfg.target_bundle.as_deref() {
            return Ok(Self::BundlePath(path.into()));
        }
        if let Some(path) = cfg.syscall_descriptions.as_deref() {
            return Ok(Self::DescriptionPath(path.into()));
        }
        Ok(Self::BuiltinMinimal)
    }

    pub fn from_cli_arg(value: &str) -> Result<Self, String> {
        if value == "builtin" {
            return Ok(Self::BuiltinMinimal);
        }
        if let Some(path) = value.strip_prefix("bundle:") {
            return Ok(Self::BundlePath(path.into()));
        }
        Ok(Self::DescriptionPath(value.into()))
    }

    pub fn display_label(&self) -> String {
        match self {
            Self::BuiltinMinimal => "builtin:linux/amd64-minimal".to_string(),
            Self::DescriptionPath(path) => path.display().to_string(),
            Self::BundlePath(path) => format!("bundle:{}", path.display()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct TargetSkipReasonCount {
    pub reason: String,
    pub count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct TargetExportSummary {
    pub total_syscalls: usize,
    pub exported_syscalls: usize,
    pub skipped_syscalls: usize,
    pub skip_reasons: Vec<TargetSkipReasonCount>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadedTarget {
    pub source: TargetSource,
    pub source_label: String,
    pub descs: Vec<SyscallDesc>,
    pub export_summary: Option<TargetExportSummary>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct TargetBundleSource {
    kind: String,
    os: String,
    arch: String,
    syzkaller_git_revision: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct TargetBundleFile {
    format_version: u32,
    source: TargetBundleSource,
    export_summary: TargetExportSummary,
    syscalls: Vec<SyscallDesc>,
}

pub fn load_target(source: TargetSource) -> Result<LoadedTarget, String> {
    match source {
        TargetSource::BuiltinMinimal => {
            let descs =
                crate::description::parse_syscall_descs(program::BUILTIN_LINUX_AMD64_DESCRIPTIONS)?;
            program::validate_syscall_descs(&descs)
                .map_err(|err| format!("invalid syscall descriptions: {err}"))?;
            Ok(LoadedTarget {
                source: TargetSource::BuiltinMinimal,
                source_label: TargetSource::BuiltinMinimal.display_label(),
                descs,
                export_summary: None,
            })
        }
        TargetSource::DescriptionPath(path) => {
            let descs = crate::description::parse_syscall_descs_from_path(&path)?;
            program::validate_syscall_descs(&descs)
                .map_err(|err| format!("invalid syscall descriptions: {err}"))?;
            Ok(LoadedTarget {
                source: TargetSource::DescriptionPath(path.clone()),
                source_label: TargetSource::DescriptionPath(path).display_label(),
                descs,
                export_summary: None,
            })
        }
        TargetSource::BundlePath(path) => load_bundle_target(path),
    }
}

pub fn load_target_from_config(
    cfg: &Config,
    cli_override: Option<&str>,
) -> Result<LoadedTarget, String> {
    load_target(TargetSource::from_config(cfg, cli_override)?)
}

fn load_bundle_target(path: PathBuf) -> Result<LoadedTarget, String> {
    let data = fs::read_to_string(&path)
        .map_err(|err| format!("failed to read target bundle {}: {err}", path.display()))?;
    let bundle: TargetBundleFile = serde_json::from_str(&data)
        .map_err(|err| format!("failed to parse target bundle {}: {err}", path.display()))?;
    if bundle.format_version != 1 {
        return Err(format!(
            "unsupported target bundle format version {} in {}",
            bundle.format_version,
            path.display()
        ));
    }
    program::validate_syscall_descs(&bundle.syscalls)
        .map_err(|err| format!("invalid target bundle {}: {err}", path.display()))?;
    Ok(LoadedTarget {
        source: TargetSource::BundlePath(path.clone()),
        source_label: TargetSource::BundlePath(path).display_label(),
        descs: bundle.syscalls,
        export_summary: Some(bundle.export_summary),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, VmConfig};
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn base_config() -> Config {
        Config {
            workdir: "/tmp/workdir".into(),
            kernel_obj: "/tmp/kernel".into(),
            image: "/tmp/image".into(),
            sshkey: "/tmp/key".into(),
            ssh_user: "root".into(),
            executor: "/tmp/syz-executor".into(),
            syscall_descriptions: None,
            target_bundle: None,
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

    #[test]
    fn resolves_builtin_target_by_default() {
        let cfg = base_config();
        assert_eq!(
            TargetSource::from_config(&cfg, None).unwrap(),
            TargetSource::BuiltinMinimal
        );
    }

    #[test]
    fn prefers_bundle_override_over_description_path() {
        let mut cfg = base_config();
        cfg.syscall_descriptions = Some("descriptions/linux/socket-subset.txt".into());
        cfg.target_bundle = Some("data/target-bundles/linux-amd64-smoke.json".into());

        assert_eq!(
            TargetSource::from_config(&cfg, None).unwrap(),
            TargetSource::BundlePath("data/target-bundles/linux-amd64-smoke.json".into())
        );
    }

    #[test]
    fn parses_bundle_prefixed_cli_override() {
        assert_eq!(
            TargetSource::from_config(
                &base_config(),
                Some("bundle:data/target-bundles/linux-amd64-smoke.json"),
            )
            .unwrap(),
            TargetSource::BundlePath("data/target-bundles/linux-amd64-smoke.json".into())
        );
    }

    fn unique_temp_dir(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "syzkaller-rust-target-{name}-{}-{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("temp test dir should create");
        path
    }

    #[test]
    fn loads_bundle_with_export_summary_and_syscalls() {
        let dir = unique_temp_dir("bundle-load");
        let path = dir.join("bundle.json");
        fs::write(
            &path,
            serde_json::json!({
                "format_version": 1,
                "source": {
                    "kind": "upstream-syzkaller",
                    "os": "linux",
                    "arch": "amd64",
                    "syzkaller_git_revision": "test"
                },
                "export_summary": {
                    "total_syscalls": 2,
                    "exported_syscalls": 1,
                    "skipped_syscalls": 1,
                    "skip_reasons": [
                        {"reason": "unsupported text", "count": 1}
                    ]
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
        .expect("bundle fixture should write");

        let loaded =
            load_target(TargetSource::BundlePath(path)).expect("bundle target should load");
        assert!(loaded.source_label.starts_with("bundle:"));
        assert_eq!(loaded.descs.len(), 1);
        let summary = loaded.export_summary.expect("bundle summary should exist");
        assert_eq!(summary.exported_syscalls, 1);
        assert_eq!(summary.skipped_syscalls, 1);
    }

    #[test]
    fn rejects_unknown_bundle_format_version() {
        let dir = unique_temp_dir("bundle-version");
        let path = dir.join("bundle.json");
        fs::write(
            &path,
            serde_json::json!({
                "format_version": 99,
                "source": {
                    "kind": "upstream-syzkaller",
                    "os": "linux",
                    "arch": "amd64",
                    "syzkaller_git_revision": "test"
                },
                "export_summary": {
                    "total_syscalls": 0,
                    "exported_syscalls": 0,
                    "skipped_syscalls": 0,
                    "skip_reasons": []
                },
                "syscalls": []
            })
            .to_string(),
        )
        .expect("bundle fixture should write");

        let err = load_target(TargetSource::BundlePath(path))
            .expect_err("invalid bundle version should be rejected");
        assert!(err.contains("unsupported target bundle format version"));
    }
}
