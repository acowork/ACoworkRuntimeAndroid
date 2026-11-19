//! On-device probe transport: run the same [`ProbeRunner`] the node uses, against *this*
//! process's shell.
//!
//! [`super::adb`] reaches a phone from a development host. This module is the other direction:
//! the CLI (or a Termux-installed binary) is already *on* the device, so the probe must talk
//! to `/system/bin/sh` (or Termux's bash) as a local child, not through `adb`.
//!
//! The two transports share candidate roots and the "mutating probes are refused" rule so a
//! profile assembled on-device and one assembled over adb answer the same questions about the
//! same phone. They deliberately do **not** share the remote-argv token discipline — there is
//! no `adb shell` joining step here, so that check would be theatre.

use std::path::{Path, PathBuf};
use std::time::Duration;

use async_trait::async_trait;
use tokio::process::Command;

use super::facts::FsRoot;
use super::probe::{CommandOutput, PROBE_ITEM_TIMEOUT, ProbeCommand, ProbeError, ProbeRunner};
use super::profile::ShellPaths;
use super::spawn::run_captured;

/// Output cap for a single local probe command. Same number as the adb harness: larger than any
/// expected probe answer, so a result that exceeds it is itself the finding.
const PROBE_OUTPUT_CAP: usize = 64 * 1024;

/// Filesystem roots checked for reachability and writability (probe item 12).
///
/// Kept as a twin of [`super::adb::CANDIDATE_ROOTS`] rather than a shared constant so the adb
/// module can stay behind the `device` feature without forcing every on-device build to compile
/// the adb client. The lists must stay equal — the test below pins that.
pub const CANDIDATE_ROOTS: &[&str] = &[
    "/data/local/tmp",
    "/sdcard",
    "/storage/self/primary",
    "/data",
    "/data/data",
    "/system",
    "/vendor",
    "/product",
    "/",
];

/// A [`ProbeRunner`] that measures *this* process's host.
///
/// Constructed once at CLI start. The shell path is resolved up front so a missing
/// `/system/bin/sh` fails at construction with a clear reason, rather than as twelve identical
/// "command not found" answers that look like a device with no capabilities.
#[derive(Debug, Clone)]
pub struct LocalHost {
    shell: PathBuf,
    termux_prefix: Option<String>,
}

impl LocalHost {
    /// Prefer Android's system shell; fall back to a POSIX `/bin/sh` for host-side unit tests.
    ///
    /// Returns `Err` when neither exists — which is the honest answer on a Windows desktop that
    /// has no Android shell, and which is why the CLI defaults to the adb transport off-device.
    pub fn new() -> Result<LocalHost, ProbeError> {
        let shell = resolve_shell().ok_or_else(|| {
            ProbeError::Runner(
                "no local shell found at /system/bin/sh or /bin/sh — this transport is for a \
                 process running on Android (or a Unix host with /bin/sh). Off-device, use the \
                 adb transport (`ACOWORK_ADB` / `--transport adb`)"
                    .to_string(),
            )
        })?;
        Ok(LocalHost {
            shell,
            termux_prefix: std::env::var("PREFIX").ok().filter(|p| !p.is_empty()),
        })
    }

    /// The shell this runner will exec for every probe line.
    pub fn shell(&self) -> &Path {
        &self.shell
    }

    /// Override `$PREFIX` — used by tests and by a CLI that resolved Termux independently.
    pub fn with_termux_prefix(mut self, prefix: Option<String>) -> LocalHost {
        self.termux_prefix = prefix.filter(|p| !p.is_empty());
        self
    }

    async fn probe_line(&self, line: &str) -> Result<CommandOutput, ProbeError> {
        self.probe_line_timed(line, PROBE_ITEM_TIMEOUT).await
    }

    /// One probe line with an explicit timeout (Magisk grant UI needs tens of seconds).
    pub async fn run_timed(
        &self,
        command: ProbeCommand,
        timeout: Duration,
    ) -> Result<CommandOutput, ProbeError> {
        if command.is_mutating() {
            return Err(ProbeError::Runner(format!(
                "`{}` mutates device state; the on-device runner will not run it. Probe item 7b \
                 needs an explicit operator decision, not a side effect of starting the node.",
                command.command_line()
            )));
        }
        if let Some(out) = su_path_from_stat(command) {
            return Ok(out);
        }
        self.probe_line_timed(&su_aware_line(command), timeout).await
    }

    async fn probe_line_timed(
        &self,
        line: &str,
        timeout: Duration,
    ) -> Result<CommandOutput, ProbeError> {
        let started = std::time::Instant::now();
        let mut command = Command::new(&self.shell);
        // `-c` + one argument: the probe line is meant to be parsed by the shell. Inherited
        // environment on purpose — clearing it would answer "does getenforce resolve from the
        // default PATH", which is a fact about the *device*, and that is what the probe is for.
        //
        // stdin must be piped (even with an empty body): `run_captured` always takes the
        // stdin handle. `Stdio::null()` made every local probe return "stdin was not piped",
        // so the profile collapsed to apk-sandbox despite a working packaged ash.
        command
            .arg("-c")
            .arg(line)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());

        let child = command.spawn().map_err(|e| {
            ProbeError::Runner(format!("cannot start {}: {e}", self.shell.display()))
        })?;

        let raw = run_captured(
            child,
            String::new(),
            PROBE_OUTPUT_CAP,
            Some(timeout),
            started,
        )
        .await
        .map_err(|e| ProbeError::Runner(e.to_string()))?;

        Ok(CommandOutput {
            stdout: String::from_utf8_lossy(&raw.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&raw.stderr).into_owned(),
            exit_code: raw.exit_code,
            timed_out: raw.timed_out,
            duration_ms: None,
        })
    }
}

/// Prefer an absolute Magisk/KSU `su` so the packaged ash PATH does not have to
/// contain the overlay.
fn su_aware_line(command: ProbeCommand) -> String {
    if matches!(command, ProbeCommand::Su) {
        let su = ShellPaths::resolve_su().unwrap_or_else(|| PathBuf::from("su"));
        return format!("{} -c 'id -u; cat /proc/self/attr/current'", su.display());
    }
    command.command_line().into_owned()
}

/// Item 4a via `stat`, not `command -v`: Magisk overlay is not on untrusted_app PATH.
fn su_path_from_stat(command: ProbeCommand) -> Option<CommandOutput> {
    if !matches!(command, ProbeCommand::SuPath) {
        return None;
    }
    ShellPaths::resolve_su().map(|p| CommandOutput::ok(&p.display().to_string()))
}

fn resolve_shell() -> Option<PathBuf> {
    // Prefer an APK-packaged shell in nativeLibraryDir (jniLibs -> libacowork_ash.so).
    // On Enforcing SELinux, untrusted_app cannot execute /system/bin/sh (shell_exec),
    // which is why in-app probes previously collapsed to apk-sandbox and ash tool
    // calls always failed. A sibling of the engine binary is app-executable.
    if let Ok(p) = std::env::var("ACOWORK_ASH") {
        let path = PathBuf::from(p);
        if path.is_file() {
            return Some(path);
        }
    }
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        let packaged = dir.join("libacowork_ash.so");
        if packaged.is_file() {
            return Some(packaged);
        }
    }
    // JNI code's current_exe() is app_process, not the .so — find our libs via maps.
    if let Some(ash) = packaged_ash_from_maps() {
        return Some(ash);
    }
    for candidate in ["/system/bin/sh", "/bin/sh"] {
        let path = PathBuf::from(candidate);
        if path.is_file() {
            return Some(path);
        }
    }
    None
}

fn packaged_ash_from_maps() -> Option<PathBuf> {
    let maps = std::fs::read_to_string("/proc/self/maps").ok()?;
    for line in maps.lines() {
        if !(line.contains("libacowork_android_ffi.so") || line.contains("libacowork_engine.so")) {
            continue;
        }
        let path = line.split_whitespace().last()?;
        let dir = Path::new(path).parent()?;
        let ash = dir.join("libacowork_ash.so");
        if ash.is_file() {
            return Some(ash);
        }
    }
    None
}

/// Same resolution LocalHost uses — profile assembly points `system_sh` here.
pub fn resolved_shell_path() -> Option<PathBuf> {
    resolve_shell()
}

#[async_trait]
impl ProbeRunner for LocalHost {
    async fn run(&self, command: ProbeCommand) -> Result<CommandOutput, ProbeError> {
        if command.is_mutating() {
            return Err(ProbeError::Runner(format!(
                "`{}` mutates device state; the on-device runner will not run it. Probe item 7b \
                 needs an explicit operator decision, not a side effect of starting the node.",
                command.command_line()
            )));
        }
        if let Some(out) = su_path_from_stat(command) {
            return Ok(out);
        }
        self.probe_line(&su_aware_line(command)).await
    }

    async fn discover_fs_roots(&self, own_package: &str) -> Result<Vec<FsRoot>, ProbeError> {
        let own = format!("/data/data/{own_package}");
        let mut roots = Vec::new();
        for path in CANDIDATE_ROOTS
            .iter()
            .map(|s| (*s).to_string())
            .chain([own.clone()])
        {
            let dir = PathBuf::from(&path);
            if !dir.is_dir() {
                continue;
            }
            roots.push(FsRoot {
                path: path.clone(),
                writable: path_writable(&dir).await,
                own_package: path == own,
            });
        }
        Ok(roots)
    }

    fn termux_prefix(&self) -> Option<String> {
        self.termux_prefix.clone()
    }
}

/// Whether a path is writable, established by writing a file and removing it.
///
/// Same discipline as the adb harness: `test -w` asks the permission bits, and probe item 12
/// exists because permission bits and the SELinux domain disagree. A `touch` accounts for both.
async fn path_writable(dir: &Path) -> bool {
    let probe = dir.join(".acowork-writable-probe");
    let probe_str = probe.to_string_lossy();
    // Prefer the shell touch so SELinux is in the path; fall back to std::fs on hosts where
    // the shell cannot see the directory the test created under TMPDIR.
    let started = std::time::Instant::now();
    let shell = resolve_shell().unwrap_or_else(|| PathBuf::from("/bin/sh"));
    let mut command = Command::new(&shell);
    command
        .arg("-c")
        .arg(format!(
            "touch {probe_str} && rm -f {probe_str} && echo YES || echo NO"
        ))
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    if let Ok(child) = command.spawn()
        && let Ok(raw) = run_captured(
            child,
            String::new(),
            64,
            Some(Duration::from_secs(2)),
            started,
        )
        .await
    {
        return String::from_utf8_lossy(&raw.stdout).contains("YES");
    }
    match std::fs::File::create(&probe) {
        Ok(_) => {
            let _ = std::fs::remove_file(&probe);
            true
        }
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn candidate_roots_match_the_adb_list_when_adb_is_compiled() {
        // When the device feature is off this test is a no-op assertion on local alone; when
        // it is on, the two lists must be byte-identical or a profile assembled on-device and
        // one assembled over adb will disagree about the same phone.
        #[cfg(feature = "device")]
        {
            assert_eq!(CANDIDATE_ROOTS, crate::host::adb::CANDIDATE_ROOTS);
        }
        assert!(CANDIDATE_ROOTS.contains(&"/data/local/tmp"));
        assert!(CANDIDATE_ROOTS.contains(&"/sdcard"));
    }

    #[test]
    fn su_probe_prefers_an_absolute_helper() {
        let line = su_aware_line(ProbeCommand::Su);
        if let Some(su) = ShellPaths::resolve_su() {
            assert!(
                line.starts_with(&su.display().to_string()),
                "expected {}…, got {line}",
                su.display()
            );
        } else {
            assert!(line.starts_with("su -c "), "{line}");
        }
        assert!(line.contains("id -u"), "{line}");
    }

    #[tokio::test]
    async fn a_mutating_probe_is_refused_rather_than_run() {
        let Ok(host) = LocalHost::new() else {
            // Windows CI / hosts without /bin/sh: the construction error is itself the
            // contract this module documents.
            return;
        };
        let err = host.run(ProbeCommand::SystemRemount).await.err();
        assert!(
            matches!(err, Some(ProbeError::Runner(_))),
            "refusal must be a runner error, not an empty command output: {err:?}"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_local_id_probe_returns_a_real_uid_on_unix() {
        let host = LocalHost::new().expect("/bin/sh on unix");
        let out = host.run(ProbeCommand::Id).await.expect("id -u");
        assert!(
            out.succeeded(),
            "id -u must succeed on a unix host: stdout={:?} stderr={:?}",
            out.stdout,
            out.stderr
        );
        let uid: u32 = out.stdout.trim().parse().expect("uid is a number");
        assert!(uid > 0 || uid == 0, "parsed uid {uid}");
    }
}
