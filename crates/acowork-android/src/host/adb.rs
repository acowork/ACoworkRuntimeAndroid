//! Device harness transport: run the probe and the execution backends against a **real**
//! device from the machine attached to it.
//!
//! ```text
//!   this crate (host side)           adb            device
//!   ShellBackend / RootShellBackend  -->  adbd  -->  /system/bin/sh -s
//! ```
//!
//! # Why this is a `SpawnRunner` and not a shell script
//!
//! The alternative — a `.sh` file that runs the probe commands and greps the output — is
//! shorter, and it proves nothing. It would exercise its own parsing rather than
//! `script`'s, its own timeout rather than `run_captured`'s, and its own idea of what a
//! denial looks like rather than `su_prompt_denied`'s. Passing the device's real output
//! through the same types the shipped node uses is what makes a green harness run *evidence*
//! about production rather than evidence about the test.
//!
//! # Fidelity, and the one place it cannot be exact
//!
//! [`ProcessSpawnRunner`](super::spawn::ProcessSpawnRunner) clears the child's environment
//! before applying the backend's base environment. `adb` cannot set the *device-side*
//! process environment — it hands the remote shell whatever `adbd` exported, which on a
//! Huawei BLA-AL00 is a 40-variable soup including `HOME=/`, `LOGNAME=shell` and a 2 KB
//! `BOOTCLASSPATH`.
//!
//! Rather than let the harness quietly run under a different environment than production,
//! the remote argv is wrapped in the device's own `env -i`, so the clearing happens on the
//! device and the child sees exactly [`SpawnInvocation::env`]. One honest difference
//! remains: the *adb client* keeps the host environment, because clearing that would break
//! `adb` itself. The device-side shell never sees it, so it is not part of what is measured.
//!
//! # Two kinds of remote argument, and why the type says so
//!
//! `adb shell` joins its arguments with single spaces and lets the device shell re-parse the
//! result. So a request is one of two things:
//!
//! - [`RemoteArg::Token`] — something that must arrive as *one* argv element: a path, a
//!   flag, a `KEY=VALUE`. Whitespace in it would silently become two arguments, and shell
//!   syntax in it would become code. These are checked, and a violation is an error rather
//!   than a mis-run command.
//! - [`RemoteArg::Line`] — a whole command line, *intended* to be parsed by the device
//!   shell: `id -u`, `su -c 'id -u'`. These come from [`ProbeCommand::command_line`] or from
//!   this module's own `format!` with an already-checked path, never from a caller's data.
//!
//! Collapsing the two into `String` is how a harness ends up confidently describing a
//! command that never ran.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use tokio::process::Command;

use super::facts::FsRoot;
use super::probe::{CommandOutput, PROBE_ITEM_TIMEOUT, ProbeCommand, ProbeError, ProbeRunner};
use super::spawn::{RawOutput, SpawnError, SpawnInvocation, SpawnRunner, run_captured};

/// The device-side program that clears an environment.
///
/// A toybox applet on every Android 6+ device (verified on API 29). If it is missing the
/// harness reports the failure rather than falling back to "just use the inherited
/// environment", because that fallback is precisely the silent divergence this module exists
/// to prevent.
const ENV_PROGRAM: &str = "env";

/// Output cap for a single probe command.
///
/// Larger than any expected probe answer (the applet listing and the mount table are both
/// under 8 KB on a real device) so that a result which exceeds it is itself the finding.
const PROBE_OUTPUT_CAP: usize = 64 * 1024;

/// Filesystem roots the harness checks for reachability and writability (probe item 12).
///
/// `/data/data/<package>` is appended at runtime for the Agent's own package directory. A
/// root not on this list is simply not reported, which the profile reads as "not reachable"
/// — the conservative direction.
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

/// One element of a remote request. See the module docs for the distinction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteArg {
    /// Must arrive as exactly one argv element. Checked.
    Token(String),
    /// A command line the device shell is meant to parse. Trusted by construction.
    Line(String),
}

impl RemoteArg {
    /// A path, flag or `KEY=VALUE` pair.
    pub fn token(value: impl Into<String>) -> RemoteArg {
        RemoteArg::Token(value.into())
    }

    /// A whole command line, for the device shell to parse.
    pub fn line(value: impl Into<String>) -> RemoteArg {
        RemoteArg::Line(value.into())
    }

    /// Reject a token that `adb`'s space-joining would turn into something else.
    ///
    /// Whitespace splits one token into two arguments; `'"` `` ` `` `$` `;` `|` `&` `<` `>`
    /// `(` `)` make it syntax. `=` is allowed because `KEY=VALUE` is the entire vocabulary of
    /// `env -i`. A [`RemoteArg::Line`] is not checked — parsing is its purpose.
    fn check(&self) -> Result<(), SpawnError> {
        let RemoteArg::Token(token) = self else {
            return Ok(());
        };
        let offenders: Vec<char> = token
            .chars()
            .filter(|c| {
                c.is_whitespace()
                    || matches!(
                        c,
                        '"' | '\'' | '$' | '`' | ';' | '|' | '&' | '<' | '>' | '(' | ')'
                    )
            })
            .collect();
        if offenders.is_empty() {
            return Ok(());
        }
        Err(SpawnError::Backend(format!(
            "adb joins remote arguments with spaces and re-parses them, so this cannot be sent \
             as one argument: {token:?} contains {offenders:?}. A harness must not run a \
             different command than the caller asked for."
        )))
    }

    fn as_str(&self) -> &str {
        match self {
            RemoteArg::Token(s) | RemoteArg::Line(s) => s,
        }
    }
}

/// A handle on one device, reached over `adb`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdbTransport {
    binary: PathBuf,
    serial: Option<String>,
    termux_prefix: Option<String>,
}

impl AdbTransport {
    /// Attach to the device with this serial, using `adb` from `PATH`.
    pub fn new(serial: impl Into<String>) -> AdbTransport {
        AdbTransport {
            binary: PathBuf::from("adb"),
            serial: Some(serial.into()),
            termux_prefix: None,
        }
    }

    /// Attach to whatever single device `adb` sees, using `adb` from `PATH`.
    ///
    /// With two devices attached `adb` refuses the request, which surfaces as a spawn error
    /// naming the ambiguity — a better failure than guessing a serial.
    pub fn any() -> AdbTransport {
        AdbTransport {
            binary: PathBuf::from("adb"),
            serial: None,
            termux_prefix: None,
        }
    }

    /// Point at an explicit `adb` binary.
    ///
    /// Needed because `adb` is usually *not* on `PATH`: platform-tools gets unpacked under
    /// `/tmp` or `~/Library/Android/sdk/platform-tools` and used by absolute path.
    pub fn with_binary(binary: impl Into<PathBuf>, serial: Option<String>) -> AdbTransport {
        AdbTransport {
            binary: binary.into(),
            serial,
            termux_prefix: None,
        }
    }

    /// Build from the environment: `ACOWORK_ADB` (binary path), `ACOWORK_ADB_SERIAL`.
    ///
    /// `None` when neither is set, so "no device configured" stays an ordinary condition
    /// rather than an error on every unconfigured run.
    pub fn from_env() -> Option<AdbTransport> {
        let binary = std::env::var("ACOWORK_ADB").ok().map(PathBuf::from);
        let serial = std::env::var("ACOWORK_ADB_SERIAL")
            .ok()
            .filter(|s| !s.is_empty());
        match (binary, serial) {
            (Some(binary), serial) => Some(AdbTransport {
                binary,
                serial,
                termux_prefix: None,
            }),
            (None, Some(serial)) => Some(AdbTransport::new(serial)),
            (None, None) => None,
        }
    }

    /// The device serial, if this transport names one.
    pub fn serial(&self) -> Option<&str> {
        self.serial.as_deref()
    }

    /// Read `$PREFIX` on the device.
    ///
    /// Separate from [`ProbeRunner::termux_prefix`] because that trait method is
    /// synchronous — on the device it is a plain environment read — and a remote read must
    /// not block an async task. The harness asks once, up front, and hands the answer back
    /// through [`Self::with_termux_prefix`].
    pub async fn read_termux_prefix(&self) -> Option<String> {
        let out = self
            .remote(
                vec![RemoteArg::line(r#"echo "${PREFIX-}""#)],
                4096,
                Some(PROBE_ITEM_TIMEOUT),
            )
            .await
            .ok()?;
        let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
        (!text.is_empty()).then_some(text)
    }

    /// Carry a previously read `$PREFIX`, so the synchronous trait method can answer.
    pub fn with_termux_prefix(mut self, prefix: Option<String>) -> AdbTransport {
        self.termux_prefix = prefix;
        self
    }

    /// `adb [-s <serial>] shell <args…>`
    fn prefix(&self) -> Vec<String> {
        match &self.serial {
            Some(serial) => vec![
                self.binary.display().to_string(),
                "-s".into(),
                serial.clone(),
            ],
            None => vec![self.binary.display().to_string()],
        }
    }

    /// Run a remote request with an empty script on stdin.
    async fn remote(
        &self,
        args: Vec<RemoteArg>,
        cap: usize,
        timeout: Option<Duration>,
    ) -> Result<RawOutput, SpawnError> {
        self.remote_with_script(args, String::new(), cap, timeout)
            .await
    }

    /// Run a remote request, feeding `script` to the remote shell's stdin.
    async fn remote_with_script(
        &self,
        args: Vec<RemoteArg>,
        script: String,
        cap: usize,
        timeout: Option<Duration>,
    ) -> Result<RawOutput, SpawnError> {
        for arg in &args {
            arg.check()?;
        }

        let started = Instant::now();
        let mut argv = self.prefix();
        argv.push("shell".into());
        argv.extend(args.into_iter().map(|a| a.as_str().to_string()));

        let mut command = Command::new(&argv[0]);
        command
            .args(&argv[1..])
            // The adb client keeps the host environment on purpose: clearing it would break
            // adb, and the device-side shell never inherits it.
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());

        let file = argv[0].clone();
        let child = command.spawn().map_err(|e| SpawnError::Unavailable {
            file,
            reason: format!("cannot start the adb client: {e}"),
        })?;

        run_captured(child, script, cap, timeout, started).await
    }

    /// Run one probe command as the device's own shell would: inherited environment.
    ///
    /// Clearing it here would answer a different question — whether `getenforce` resolves
    /// from the default `PATH` is a fact about the device, and probe item 2 is supposed to
    /// learn facts about the device.
    async fn probe_line(&self, line: &str) -> Result<CommandOutput, ProbeError> {
        let raw = self
            .remote(
                vec![RemoteArg::line(line)],
                PROBE_OUTPUT_CAP,
                Some(PROBE_ITEM_TIMEOUT),
            )
            .await
            .map_err(|e| {
                // A missing `adb` is a runner problem, not a command that failed. Reporting
                // it as an empty answer would read as "the device says nothing".
                // `SpawnError`'s Display already names the program and the reason.
                ProbeError::Runner(e.to_string())
            })?;

        Ok(CommandOutput {
            // The NUL that `/proc/self/attr/current` ends with is kept, not scrubbed: the
            // parsers are what must tolerate it, and cleaning it here would hide a defect in
            // them behind the harness.
            stdout: String::from_utf8_lossy(&raw.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&raw.stderr).into_owned(),
            exit_code: raw.exit_code,
            timed_out: raw.timed_out,
            // Left to `run_probe`, which owns the number that matters for the budget: what
            // the probe loop waited, measured the same way for every runner.
            duration_ms: None,
        })
    }

    /// Whether a path exists and is a directory on the device.
    async fn path_exists(&self, path: &str) -> bool {
        self.test_flag(path, "test -d").await
    }

    /// Whether a path is writable, established by writing a file and removing it.
    ///
    /// `test -w` is not used: it asks the permission bits, and the point of probe item 12 is
    /// that permission bits and the SELinux domain disagree. A `touch` accounts for both.
    async fn path_writable(&self, path: &str) -> bool {
        if RemoteArg::token(path).check().is_err() {
            return false;
        }
        // Fixed name rather than randomized: the file is created and removed inside one
        // command, and a stable name makes a leaked probe file greppable on the device.
        let probe = format!("{path}/.acowork-writable-probe");
        let cmd = format!("touch {probe} && rm -f {probe} && echo YES || echo NO");
        self.remote(vec![RemoteArg::line(cmd)], 64, Some(PROBE_ITEM_TIMEOUT))
            .await
            .map(|out| String::from_utf8_lossy(&out.stdout).contains("YES"))
            .unwrap_or(false)
    }

    /// Run `<test> <path>` and report whether it succeeded.
    async fn test_flag(&self, path: &str, test: &str) -> bool {
        let cmd = format!("{test} {}", RemoteArg::token(path).as_str());
        self.remote(vec![RemoteArg::line(cmd)], 64, Some(PROBE_ITEM_TIMEOUT))
            .await
            .map(|out| out.exit_code == Some(0))
            .unwrap_or(false)
    }
}

#[async_trait]
impl SpawnRunner for AdbTransport {
    /// Start a device-side shell with exactly the supplied environment, script on stdin.
    ///
    /// The argv is `env -i KEY=VALUE… <file> <args…>` — the device-side equivalent of
    /// `env_clear()` + `envs()`. Cap, deadline and bounded drain are literally the same
    /// code path as the shipped runner, by way of `run_captured`.
    async fn spawn(&self, invocation: SpawnInvocation) -> Result<RawOutput, SpawnError> {
        let mut args = vec![RemoteArg::token(ENV_PROGRAM), RemoteArg::token("-i")];
        for (key, value) in &invocation.env {
            args.push(RemoteArg::token(format!("{key}={value}")));
        }
        args.push(RemoteArg::token(invocation.file.display().to_string()));
        args.extend(invocation.args.iter().map(|a| RemoteArg::token(a.clone())));

        self.remote_with_script(
            args,
            invocation.script,
            invocation.output_cap,
            invocation.timeout,
        )
        .await
    }
}

#[async_trait]
impl ProbeRunner for AdbTransport {
    /// Run one probe command verbatim on the device.
    ///
    /// A command that fails or is missing is a normal answer and is returned, not raised:
    /// `su: inaccessible or not found` is exactly the result that decides this device is not
    /// rooted. Only a runner that cannot operate at all returns `Err`.
    async fn run(&self, command: ProbeCommand) -> Result<CommandOutput, ProbeError> {
        if command.is_mutating() {
            return Err(ProbeError::Runner(format!(
                "`{}` mutates device state; the harness will not run it. Probe item 7b needs an \
                 explicit operator decision, not a side effect of starting the node.",
                command.command_line()
            )));
        }
        self.probe_line(command.command_line().as_ref()).await
    }

    /// Probe item 12, established by `touch` rather than by mount options.
    async fn discover_fs_roots(&self, own_package: &str) -> Result<Vec<FsRoot>, ProbeError> {
        let own = format!("/data/data/{own_package}");
        let mut roots = Vec::new();
        for path in CANDIDATE_ROOTS
            .iter()
            .map(|s| (*s).to_string())
            .chain([own.clone()])
        {
            // A path with a space in it cannot be sent through adb's argv at all; skipping
            // it is correct (it is then unreported, i.e. "not reachable"), and it cannot
            // happen for the candidates above.
            if RemoteArg::token(&path).check().is_err() || !self.path_exists(&path).await {
                continue;
            }
            roots.push(FsRoot {
                path: path.clone(),
                writable: self.path_writable(&path).await,
                own_package: path == own,
            });
        }
        Ok(roots)
    }

    /// The cached `$PREFIX`. See [`Self::read_termux_prefix`] for why it is cached.
    fn termux_prefix(&self) -> Option<String> {
        self.termux_prefix.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_with_spaces_are_refused_not_mis_run() {
        assert!(
            RemoteArg::token("PATH=/system/bin:/system/xbin")
                .check()
                .is_ok()
        );
        assert!(RemoteArg::token("/system/bin/sh").check().is_ok());
        assert!(RemoteArg::token("-s").check().is_ok());
        assert!(RemoteArg::token("su").check().is_ok());

        let err = RemoteArg::token("echo hi; rm -rf /").check().err().unwrap();
        let msg = err.to_string();
        assert!(msg.contains("spaces"), "{msg}");
        assert!(
            msg.contains("echo hi"),
            "the offending token is quoted back: {msg}"
        );
        assert!(RemoteArg::token("a\tb").check().is_err());
        assert!(RemoteArg::token("a'b").check().is_err());
        assert!(RemoteArg::token("$HOME").check().is_err());
    }

    #[test]
    fn a_command_line_is_meant_to_be_parsed_and_is_not_checked() {
        // `id -u` and `su -c '…'` are whole lines by design. Refusing them would make the
        // probe unable to run anything, which is the bug this variant exists to allow.
        assert!(
            RemoteArg::line("su -c 'id -u; cat /proc/self/attr/current'")
                .check()
                .is_ok()
        );
        assert!(RemoteArg::line("id -u").check().is_ok());
    }

    #[test]
    fn transport_names_the_device_it_targets() {
        let t = AdbTransport::new("emulator-5554");
        assert_eq!(t.serial(), Some("emulator-5554"));
        assert_eq!(t.prefix(), ["adb", "-s", "emulator-5554"]);
        assert_eq!(AdbTransport::any().prefix(), ["adb"]);
    }

    #[test]
    fn candidate_roots_cover_the_tiers_a_real_device_offers() {
        // `/data/local/tmp` is the one directory the adb-shell tier can write. If it ever
        // leaves this list, the profile silently loses its only writable root.
        assert!(CANDIDATE_ROOTS.contains(&"/data/local/tmp"));
        assert!(CANDIDATE_ROOTS.contains(&"/sdcard"));
        assert!(CANDIDATE_ROOTS.contains(&"/system"));
        for path in CANDIDATE_ROOTS {
            assert!(
                RemoteArg::token(*path).check().is_ok(),
                "candidate {path} cannot survive adb's argv"
            );
        }
    }

    #[tokio::test]
    async fn a_mutating_probe_is_refused_rather_than_run() {
        let t = AdbTransport::with_binary("/nonexistent/adb", None);
        let err = t.run(ProbeCommand::SystemRemount).await.err();
        assert!(
            matches!(err, Some(ProbeError::Runner(_))),
            "refusal must be a runner error, not an empty command output: {err:?}"
        );
    }

    #[tokio::test]
    async fn an_unreachable_adb_is_a_runner_error_not_a_device_that_said_nothing() {
        let t = AdbTransport::with_binary("/nonexistent/adb", None);
        let err = t.run(ProbeCommand::Id).await;
        assert!(matches!(err, Err(ProbeError::Runner(_))), "{err:?}");
    }
}
