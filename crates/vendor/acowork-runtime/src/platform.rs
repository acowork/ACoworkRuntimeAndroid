//! Platform detection module
//!
//! Centralizes runtime platform detection (OS, architecture, shell) using
//! `std::env::consts::OS` (runtime), NOT `#[cfg]` (compile-time).
//! Shell detection runs once at first access and is cached via `OnceLock`.
//!
//! On Windows, this module also detects Git Bash availability to support
//! multiple shell tools (bash + powershell) for LLM fallback chains.

use std::path::PathBuf;
use std::sync::OnceLock;

/// Detected shell information
#[derive(Debug, Clone)]
pub struct ShellInfo {
    /// Shell binary name (e.g. "pwsh", "bash", "cmd")
    pub binary: &'static str,
    /// Shell argument flag (e.g. "-Command", "-c", "/C")
    pub arg: &'static str,
    /// Human-readable display name (e.g. "PowerShell 7 (pwsh)")
    pub display_name: &'static str,
}

/// Available shell tool descriptors for this platform.
///
/// On Windows, this may include both bash (Git Bash) and powershell.
/// On Linux/macOS, typically just one unified "shell" tool.
#[derive(Debug, Clone)]
pub struct AvailableShell {
    /// Tool name exposed to the LLM (e.g. "bash", "powershell", "shell")
    pub tool_name: String,
    /// Human-readable display name for errors and logging
    pub display_name: String,
    /// Shell binary to pass to Command::new()
    pub binary: String,
    /// Resolved path for existence checks at runtime
    pub path: String,
    /// CLI flag for passing a command string (e.g. "-c", "-Command")
    pub arg: String,
    /// Whether this is the primary/preferred shell on this platform
    pub is_primary: bool,
}

static SHELL_INFO: OnceLock<ShellInfo> = OnceLock::new();
static AVAILABLE_SHELLS: OnceLock<Vec<AvailableShell>> = OnceLock::new();

// ---------------------------------------------------------------------------
// Git Bash detection (Windows only)
// ---------------------------------------------------------------------------

/// Known installation paths for Git Bash on Windows.
///
/// Checked in priority order — first match wins.
fn git_bash_candidates() -> Vec<PathBuf> {
    vec![
        // Default Git for Windows 64-bit
        PathBuf::from(r"C:\Program Files\Git\bin\bash.exe"),
        // Git for Windows 32-bit on 64-bit OS
        PathBuf::from(r"C:\Program Files (x86)\Git\bin\bash.exe"),
        // Chocolatey
        PathBuf::from(r"C:\ProgramData\chocolatey\bin\bash.exe"),
    ]
}

/// Try to locate a Git Bash installation on Windows.
///
/// Checks known install locations first, then falls back to PATH lookup
/// using `where bash` (Windows equivalent of `which`).
///
/// **WSL filtering**: `where bash` on Windows may find WSL's bash.exe
/// (e.g. `C:\Windows\System32\bash.exe`). This function explicitly skips
/// WSL bash entries because they resolve to `/bin/bash` inside the WSL VM
/// and cannot access Windows filesystem paths correctly.
///
/// Returns `(binary_name, full_path)` on success.
pub fn find_git_bash() -> Option<(String, String)> {
    if std::env::consts::OS != "windows" {
        return None;
    }

    // Check known install locations
    for candidate in git_bash_candidates() {
        if candidate.exists() {
            let path = candidate.to_string_lossy().to_string();
            tracing::info!(path = %path, "Found Git Bash at known location");
            return Some(("bash".to_string(), path));
        }
    }

    // Fallback: check PATH using Windows "where" command.
    // Filter out WSL bash entries — they are NOT Git Bash.
    if let Ok(output) = std::process::Command::new("where").arg("bash").output()
        && output.status.success()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            // Skip WSL bash (C:\Windows\System32\bash.exe or SysWOW64)
            if is_wsl_bash(trimmed) {
                tracing::debug!(
                    path = %trimmed,
                    "Skipping WSL bash entry from 'where bash'"
                );
                continue;
            }
            tracing::info!(path = %trimmed, "Found Git Bash via PATH (where bash)");
            return Some(("bash".to_string(), trimmed.to_string()));
        }
    }

    tracing::debug!("Git Bash not found");
    None
}

/// Check whether a bash.exe path is the WSL entry point (not Git Bash).
///
/// WSL installs a stub `bash.exe` in the Windows system directories.
/// Invoking this binary launches bash *inside* the WSL VM, where
/// Windows filesystem paths (e.g. `/f/work/...`) are not accessible.
fn is_wsl_bash(path: &str) -> bool {
    let lower = path.to_lowercase();
    // WSL bash is always under System32 or SysWOW64
    lower.contains("\\system32\\bash.exe") || lower.contains("\\syswow64\\bash.exe")
}

// ---------------------------------------------------------------------------
// Shell detection (cached)
// ---------------------------------------------------------------------------

/// Detect the best available shell for the current platform.
///
/// Priority order:
/// - Windows: pwsh > powershell > cmd
/// - macOS:    $SHELL (zsh > bash > sh fallback)
/// - Linux:    $SHELL (bash > zsh > sh fallback)
fn detect_shell() -> ShellInfo {
    match std::env::consts::OS {
        "windows" => {
            // Prefer PowerShell 7 (pwsh) over Windows PowerShell 5.1 over cmd
            if std::process::Command::new("pwsh")
                .arg("--version")
                .output()
                .is_ok()
            {
                ShellInfo {
                    binary: "pwsh",
                    arg: "-Command",
                    display_name: "PowerShell 7 (pwsh)",
                }
            } else if std::process::Command::new("powershell")
                .arg("-Command")
                .arg("echo ok")
                .output()
                .is_ok()
            {
                ShellInfo {
                    binary: "powershell",
                    arg: "-Command",
                    display_name: "Windows PowerShell 5.1",
                }
            } else {
                ShellInfo {
                    binary: "cmd",
                    arg: "/C",
                    display_name: "cmd.exe",
                }
            }
        }
        "macos" => {
            let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/zsh".to_string());
            if shell.contains("zsh") {
                ShellInfo {
                    binary: "zsh",
                    arg: "-c",
                    display_name: "zsh",
                }
            } else if shell.contains("bash") {
                ShellInfo {
                    binary: "bash",
                    arg: "-c",
                    display_name: "bash",
                }
            } else {
                ShellInfo {
                    binary: "sh",
                    arg: "-c",
                    display_name: "sh",
                }
            }
        }
        _ => {
            // Linux and other Unix-like systems
            let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/bash".to_string());
            if shell.contains("bash") {
                ShellInfo {
                    binary: "bash",
                    arg: "-c",
                    display_name: "bash",
                }
            } else if shell.contains("zsh") {
                ShellInfo {
                    binary: "zsh",
                    arg: "-c",
                    display_name: "zsh",
                }
            } else {
                ShellInfo {
                    binary: "sh",
                    arg: "-c",
                    display_name: "sh",
                }
            }
        }
    }
}

/// Detect all available shells for tool registration.
///
/// Returns a list of shell descriptors that should be registered as tools.
/// The first entry (if any `is_primary`) is the preferred shell.
///
/// Platform behavior:
/// - **Windows**: Git Bash (if found) + PowerShell. Bash is primary when available.
/// - **macOS/Linux**: Single "shell" tool using the detected system shell.
pub fn detected_shells() -> Vec<AvailableShell> {
    AVAILABLE_SHELLS
        .get_or_init(|| {
            let mut shells = Vec::new();

            match std::env::consts::OS {
                "android" => {
                    // Native Android target (APK / NDK). Prefer bash when present,
                    // else ash/mksh — same dual-registration idea as ADR-AND-001.
                    shells.extend(detect_android_shells());
                }
                "windows" => {
                    // Git Bash as primary tool (if available)
                    if let Some((binary, path)) = find_git_bash() {
                        shells.push(AvailableShell {
                            tool_name: "bash".to_string(),
                            display_name: "Git Bash".to_string(),
                            binary,
                            path,
                            arg: "-c".to_string(),
                            is_primary: true,
                        });
                    }

                    // PowerShell as secondary / fallback tool
                    let (pwsh_binary, pwsh_display) = if std::process::Command::new("pwsh")
                        .arg("--version")
                        .output()
                        .is_ok()
                    {
                        ("pwsh", "PowerShell 7 (pwsh)")
                    } else {
                        ("powershell", "Windows PowerShell 5.1")
                    };

                    // Resolve full path for PowerShell using "where" on Windows
                    let pwsh_path = std::process::Command::new("where")
                        .arg(pwsh_binary)
                        .output()
                        .ok()
                        .and_then(|out| {
                            if out.status.success() {
                                let stdout = String::from_utf8_lossy(&out.stdout);
                                stdout.lines().next().map(|s| s.trim().to_string())
                            } else {
                                None
                            }
                        })
                        .unwrap_or_else(|| pwsh_binary.to_string());

                    shells.push(AvailableShell {
                        tool_name: "powershell".to_string(),
                        display_name: pwsh_display.to_string(),
                        binary: pwsh_binary.to_string(),
                        path: pwsh_path,
                        arg: "-Command".to_string(),
                        is_primary: shells.is_empty(), // primary only if no Git Bash
                    });
                }
                _ => {
                    // Termux reports OS=linux but is still Android — dual-register
                    // when ANDROID_ROOT / /system/bin/sh are present.
                    if looks_like_android_host() {
                        shells.extend(detect_android_shells());
                    } else {
                        // Desktop Linux / macOS: single unified "shell" tool
                        let info = detect_shell();
                        shells.push(AvailableShell {
                            tool_name: "shell".to_string(),
                            display_name: info.display_name.to_string(),
                            binary: info.binary.to_string(),
                            path: info.binary.to_string(),
                            arg: info.arg.to_string(),
                            is_primary: true,
                        });
                    }
                }
            }

            tracing::info!(
                count = shells.len(),
                tools = ?shells.iter().map(|s| s.tool_name.as_str()).collect::<Vec<_>>(),
                "Detected available shells for tool registration"
            );

            shells
        })
        .clone()
}

/// Get the detected shell info (cached after first call).
///
/// Uses `OnceLock` so detection only runs once per process.
pub fn detected_shell() -> &'static ShellInfo {
    SHELL_INFO.get_or_init(detect_shell)
}

fn looks_like_android_host() -> bool {
    std::env::var_os("ANDROID_ROOT").is_some()
        || std::env::var_os("PREFIX").is_some_and(|p| {
            let s = p.to_string_lossy();
            s.contains("com.termux") || s.ends_with("/usr")
        })
        || std::path::Path::new("/system/bin/sh").exists()
}

fn detect_android_shells() -> Vec<AvailableShell> {
    let mut shells = Vec::new();
    // Prefer Termux bash when on PATH / PREFIX.
    let bash_candidates = [
        std::env::var("PREFIX")
            .ok()
            .map(|p| format!("{p}/bin/bash")),
        Some("/data/data/com.termux/files/usr/bin/bash".into()),
        Some("bash".into()),
    ];
    for cand in bash_candidates.into_iter().flatten() {
        if shell_runs(&cand, "-c") {
            shells.push(AvailableShell {
                tool_name: "bash".to_string(),
                display_name: "bash (Android/Termux)".to_string(),
                binary: cand.clone(),
                path: cand,
                arg: "-c".to_string(),
                is_primary: true,
            });
            break;
        }
    }
    // ash / system sh as secondary (or primary if no bash).
    let ash_candidates = ["/system/bin/sh", "sh"];
    for cand in ash_candidates {
        if shell_runs(cand, "-c") {
            shells.push(AvailableShell {
                tool_name: "ash".to_string(),
                display_name: "ash/mksh (Android)".to_string(),
                binary: cand.to_string(),
                path: cand.to_string(),
                arg: "-c".to_string(),
                is_primary: shells.is_empty(),
            });
            break;
        }
    }
    if shells.is_empty() {
        // Last resort so tools still register something.
        shells.push(AvailableShell {
            tool_name: "shell".to_string(),
            display_name: "sh".to_string(),
            binary: "sh".to_string(),
            path: "sh".to_string(),
            arg: "-c".to_string(),
            is_primary: true,
        });
    }
    shells
}

fn shell_runs(binary: &str, arg: &str) -> bool {
    std::process::Command::new(binary)
        .arg(arg)
        .arg("true")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detected_shell_returns_consistent_result() {
        let info1 = detected_shell();
        let info2 = detected_shell();
        // Same static reference — OnceLock guarantees single init
        assert!(std::ptr::eq(info1, info2));
    }

    #[test]
    fn test_shell_info_fields_are_non_empty() {
        let info = detected_shell();
        assert!(!info.binary.is_empty());
        assert!(!info.arg.is_empty());
        assert!(!info.display_name.is_empty());
    }

    #[test]
    fn test_detect_shell_platform_match() {
        let info = detect_shell();
        match std::env::consts::OS {
            "windows" => {
                assert!(matches!(info.binary, "pwsh" | "powershell" | "cmd"));
            }
            _ => {
                assert!(matches!(info.binary, "bash" | "zsh" | "sh"));
            }
        }
    }

    #[test]
    fn test_detected_shells_returns_at_least_one() {
        let shells = detected_shells();
        assert!(!shells.is_empty(), "Should have at least one shell tool");
    }

    #[test]
    fn test_detected_shells_idempotent() {
        let shells1 = detected_shells();
        let shells2 = detected_shells();
        assert_eq!(shells1.len(), shells2.len());
        for (a, b) in shells1.iter().zip(shells2.iter()) {
            assert_eq!(a.tool_name, b.tool_name);
            assert_eq!(a.binary, b.binary);
        }
    }
}
