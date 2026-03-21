/// Minimal crash detector for Linux kernel console output.
/// Checks for common crash signatures in serial/console output.

const CRASH_PATTERNS: &[&str] = &[
    "BUG:",
    "KASAN:",
    "UBSAN:",
    "kernel panic",
    "general protection fault",
    "WARNING: CPU:",
    "BUG: unable to handle",
    "BUG: kernel NULL pointer dereference",
    "Oops:",
    "RIP:",
    "Call Trace:",
    "divide error:",
    "invalid opcode:",
    "KFENCE:",
    "KCSAN:",
    "BUG: KFENCE:",
    "BUG: KCSAN:",
    "kernel BUG at",
    "stack-protector:",
    "BUG: sleeping function called",
    "INFO: rcu_sched detected stalls",
    "INFO: task hung for more than",
    "BUG: soft lockup",
];

/// Check if the given output contains a kernel crash.
/// Returns Some(crash_title) if a crash is detected, None otherwise.
pub fn detect_crash(output: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(output);
    for pattern in CRASH_PATTERNS {
        if let Some(pos) = text.find(pattern) {
            // Extract the crash title: from pattern to end of line
            let start = text[..pos].rfind('\n').map(|p| p + 1).unwrap_or(pos);
            let end = text[pos..].find('\n').map(|p| pos + p).unwrap_or(text.len());
            let title = text[start..end].trim().to_string();
            return Some(title);
        }
    }
    None
}

/// Save crash information to disk.
pub fn save_crash(
    workdir: &str,
    title: &str,
    serial_output: &[u8],
    program_desc: &str,
) -> std::io::Result<()> {
    let crash_dir = std::path::Path::new(workdir).join("crashes");
    std::fs::create_dir_all(&crash_dir)?;

    // Create a sanitized filename from the title
    let safe_title: String = title.chars()
        .map(|c| if c.is_alphanumeric() || c == '_' || c == '-' { c } else { '_' })
        .take(80)
        .collect();

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let crash_subdir = crash_dir.join(format!("{}_{}", safe_title, timestamp));
    std::fs::create_dir_all(&crash_subdir)?;

    // Save log
    std::fs::write(crash_subdir.join("log"), serial_output)?;

    // Save description
    std::fs::write(crash_subdir.join("description"), title.as_bytes())?;

    // Save the program
    std::fs::write(crash_subdir.join("program"), program_desc.as_bytes())?;

    log::warn!("Crash saved to {:?}: {}", crash_subdir, title);
    Ok(())
}
