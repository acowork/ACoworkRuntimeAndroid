//! The one place in this crate that starts a process.
//!
//! [`script`] decides *what text* a backend runs; this module decides *how a process is
//! actually started*, and [`super::backend`] turns that into an
//! [`ExecRecord`](super::backend::ExecRecord). The split is the same one
//! [`super::probe`] makes with [`ProbeRunner`](super::probe::ProbeRunner): pure decision
//! above, one narrow I/O boundary below, so that everything in this crate except this
//! file can be tested without a device, a shell, or a root.
//!
//! # Why this is not the same seam as `ProbeRunner`
//!
//! They look alike and must not be merged.
//!
//! | | `ProbeRunner` | [`SpawnRunner`] |
//! |---|---|---|
//! | Runs | a fixed list of read-only commands | an arbitrary caller-supplied script |
//! | Input | none | the script, on stdin |
//! | Output size | one line each | unbounded (`logcat -d` emits megabytes) |
//! | Overrun | skip the item, mark it stale | kill the process, keep the partial output |
//! | Result | cached for the session | never cached |
//!
//! A probe that hangs is a missing fact. A command that hangs is a session holding a
//! write lock while doing nothing. The two need different machinery, and folding them
//! together would give the probe path a kill-able process it does not want and the exec
//! path a cache it must never have.
//!
//! # The two properties this seam enforces rather than recommends
//!
//! **The script goes to stdin, never to argv** (ADR-AND-001 §4.7). Every process on an
//! Android device can read another's command line through `/proc/<pid>/cmdline`, so a
//! secret in an argument is a secret published to the whole device — including to the
//! untrusted app domain. `sh -s` reads the script from stdin instead, and stdin is not
//! world-readable. [`SpawnInvocation::script`] is therefore a field, not part of
//! [`SpawnInvocation::args`], and [`ProcessSpawnRunner`] has no way to put it in argv
//! even by accident.
//!
//! **The child's environment is the caller's, in full.** [`ProcessSpawnRunner`] calls
//! `env_clear()` before applying [`SpawnInvocation::env`]. The Runtime process holds the
//! Gateway enrolment credential and the LLM API key in its environment; a backend that
//! inherited it would hand both to a root shell, and to whatever script the model asked
//! for. Making inheritance impossible at the seam means a new backend cannot forget to
//! block it — but it also means a backend that supplies no `PATH` gets a shell with no
//! `PATH`, in which `id` and `cat` do not resolve and the identity probe silently
//! reports nothing. The base environment is therefore each backend's responsibility, and
//! [`super::backend`] implementations must set at least `PATH` and `HOME`.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::process::{Child, Command};

/// The default read chunk. Large enough that a `logcat -d` does not degenerate into one
/// syscall per line, small enough that a capped read stops close to the cap.
const READ_CHUNK: usize = 8 * 1024;

/// One process to start.
///
/// Deliberately flat and fully owned: no borrow of the request that produced it, because
/// a [`SpawnRunner`] implementation may hand this to another thread, a subprocess pool,
/// or an adb bridge that outlives the call which built it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpawnInvocation {
    /// Program to execute, as an **absolute path** where one is known.
    ///
    /// With the environment cleared (see the module docs) a bare name resolves only if
    /// `PATH` happens to be in `env`, so backends pass paths.
    pub file: PathBuf,
    /// Arguments. Never contains the script.
    pub args: Vec<String>,
    /// The script body, written to stdin and then closed.
    pub script: String,
    /// The child's complete environment. The Runtime's is not inherited.
    pub env: BTreeMap<String, String>,
    /// Stop accumulating output past this many bytes per stream, but keep draining so
    /// the child is not left blocked on a full pipe.
    pub output_cap: usize,
    /// Kill the process after this long. `None` means no deadline, which only a caller
    /// that will not leak a session should use.
    pub timeout: Option<Duration>,
}

impl SpawnInvocation {
    /// A minimal invocation: run `file` with no arguments, no environment, and the
    /// defaults a read-tier command wants.
    pub fn new(file: impl Into<PathBuf>, script: impl Into<String>) -> SpawnInvocation {
        SpawnInvocation {
            file: file.into(),
            args: Vec::new(),
            script: script.into(),
            env: BTreeMap::new(),
            output_cap: super::backend::DEFAULT_OUTPUT_CAP,
            timeout: Some(super::backend::DEFAULT_READ_TIMEOUT),
        }
    }

    /// Set the arguments, replacing any existing ones.
    pub fn with_args(mut self, args: &[&str]) -> SpawnInvocation {
        self.args = args.iter().map(|a| (*a).to_string()).collect();
        self
    }
}

/// What came back from a process, before any interpretation.
///
/// Byte-oriented on purpose. The caller decides whether stdout is UTF-8, whether the
/// identity marker is present, and whether a non-zero exit means failure — the runner
/// must not pre-judge any of it, because a truncated multi-byte output is still a valid
/// partial answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawOutput {
    /// Exit status, or `None` when the process was killed rather than having exited:
    /// a timeout, or a signal such as `SIGKILL` from the OOM killer.
    ///
    /// `None` is not `Some(0)`. Collapsing the two would let a command that never
    /// finished look like one that succeeded.
    pub exit_code: Option<i32>,
    /// Captured stdout, capped at the invocation's `output_cap`.
    pub stdout: Vec<u8>,
    /// Captured stderr.
    pub stderr: Vec<u8>,
    /// True when either stream exceeded the cap.
    ///
    /// One flag rather than two because [`ExecRecord`](super::backend::ExecRecord) has
    /// one, and a caller that needs to know *which* stream was cut has no reason to act
    /// differently once it does.
    pub truncated: bool,
    /// True when the process was killed for exceeding `timeout`.
    pub timed_out: bool,
    /// Wall-clock time from spawn to the process being gone.
    pub duration: Duration,
}

impl RawOutput {
    /// A completed run with both streams intact.
    fn finished(
        exit_code: Option<i32>,
        stdout: Vec<u8>,
        stderr: Vec<u8>,
        truncated: bool,
        duration: Duration,
    ) -> RawOutput {
        RawOutput {
            exit_code,
            stdout,
            stderr,
            truncated,
            timed_out: false,
            duration,
        }
    }

    /// True when the process ran to completion with status 0.
    pub fn succeeded(&self) -> bool {
        self.exit_code == Some(0) && !self.timed_out
    }
}

/// Why no process could be run.
///
/// Reserved for "the runner could not operate". A command that started and failed is a
/// normal [`RawOutput`], exactly as [`ProbeRunner`] treats a failing probe. Returning
/// `Err` for a non-zero exit would push every caller into distinguishing "could not run"
/// from "ran and said no", which is the distinction the whole backend exists to make.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SpawnError {
    /// The program is not there or would not start. `reason` is the OS message.
    ///
    /// This is the case a [`RootShellBackend`](super::backend) reports as
    /// `EscalationUnavailable`: no `su` on the device is a fact about the device, not an
    /// I/O failure, and the caller must be able to tell them apart.
    Unavailable {
        /// The program that could not be started.
        file: String,
        /// The OS-level reason.
        reason: String,
    },
    /// The runner itself broke: a pipe could not be made, a task panicked.
    Backend(String),
}

impl std::fmt::Display for SpawnError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SpawnError::Unavailable { file, reason } => {
                write!(f, "cannot start `{file}`: {reason}")
            }
            SpawnError::Backend(why) => write!(f, "process runner failed: {why}"),
        }
    }
}

impl std::error::Error for SpawnError {}

/// The I/O boundary for running a command.
#[async_trait]
pub trait SpawnRunner: Send + Sync {
    /// Start the process, capture both streams, and report what happened.
    ///
    /// Implementations must:
    /// - write [`SpawnInvocation::script`] to stdin and close it, never place it in argv;
    /// - clear the inherited environment before applying [`SpawnInvocation::env`];
    /// - return the bytes collected *so far* when the deadline fires, with
    ///   [`RawOutput::timed_out`] set — the identity prologue that
    ///   [`script`](super::script) puts first exists precisely so a killed command still
    ///   answers "who was running this";
    /// - keep draining the pipes past `output_cap` rather than stopping, because a child
    ///   blocked writing to an unread pipe will hit its timeout for the wrong reason.
    async fn spawn(&self, invocation: SpawnInvocation) -> Result<RawOutput, SpawnError>;
}

/// A [`SpawnRunner`] that starts real processes with `tokio::process`.
///
/// Unit tests never use this — they use [`ScriptedSpawnRunner`](scripted) so that the
/// backend logic is testable on a machine with no shell. It is exercised for real by
/// `tests/spawn_process.rs`, which runs `/bin/sh -s` on the build host: the argument
/// passing, the quoting in [`script`], and the identity round-trip are then genuinely
/// executed rather than asserted about.
#[derive(Debug, Default, Clone, Copy)]
pub struct ProcessSpawnRunner;

impl ProcessSpawnRunner {
    /// Construct the runner. It holds no state, so it is free to clone and share.
    pub fn new() -> ProcessSpawnRunner {
        ProcessSpawnRunner
    }
}

#[async_trait]
impl SpawnRunner for ProcessSpawnRunner {
    async fn spawn(&self, invocation: SpawnInvocation) -> Result<RawOutput, SpawnError> {
        let started = Instant::now();

        let mut command = Command::new(&invocation.file);
        command
            .args(&invocation.args)
            // The two properties from the module docs, spelled out in the order that
            // makes it hard to miss one.
            .env_clear()
            .envs(&invocation.env)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());

        let child: Child = command.spawn().map_err(|e| SpawnError::Unavailable {
            file: invocation.file.display().to_string(),
            reason: e.to_string(),
        })?;

        run_captured(
            child,
            invocation.script,
            invocation.output_cap,
            invocation.timeout,
            started,
        )
        .await
    }
}

/// Drive an already-spawned child to a [`RawOutput`].
///
/// Split out of [`ProcessSpawnRunner::spawn`] because the argv is not the only thing a
/// second transport changes: the device harness starts `adb` instead of the device's shell,
/// and would otherwise have its own copy of the capture rules. One copy means a harness run
/// exercises the same timeout, cap and drain behaviour the shipped node will, so a passing
/// device test is evidence about production and not about the test.
pub(crate) async fn run_captured(
    mut child: Child,
    script: String,
    cap: usize,
    timeout: Option<Duration>,
    started: Instant,
) -> Result<RawOutput, SpawnError> {
    // Stdin and both output pipes are handed to their own tasks, so each handle is
    // closed as soon as its task ends — including on the timeout path, where killing
    // the child makes the readers see EOF. Holding any of them open across `wait()`
    // deadlocks: `sh -s` does not exit while a writer is still connected, and
    // `wait()` does not return while an output pipe is open.
    let stdin = child
        .stdin
        .take()
        .ok_or_else(|| SpawnError::Backend("stdin was not piped".into()))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| SpawnError::Backend("stdout was not piped".into()))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| SpawnError::Backend("stderr was not piped".into()))?;

    let out = Capture::default();
    let err = Capture::default();
    let writer = tokio::spawn(async move {
        let mut stdin = stdin;
        // A failed write is normal and not reportable as an error: `su -c 'sh -c …'`
        // and any script that calls `exit` early close the pipe while the rest of the
        // body is still queued. Whether the script ran is answered by the exit code,
        // not by whether we managed to hand the whole thing over.
        let _ = stdin.write_all(script.as_bytes()).await;
        let _ = stdin.shutdown().await;
    });

    let out_task = tokio::spawn(read_capped(stdout, cap, out.clone()));
    let err_task = tokio::spawn(read_capped(stderr, cap, err.clone()));
    let out_abort = out_task.abort_handle();
    let err_abort = err_task.abort_handle();

    // Wait for exit, or for the deadline. `timeout` consumes the `wait()` future, so
    // the mutable borrow of `child` ends with it and `kill()` below is legal.
    let (status, timed_out) = match timeout {
        None => (child.wait().await, false),
        Some(limit) => match tokio::time::timeout(limit, child.wait()).await {
            Ok(inner) => (inner, false),
            Err(_elapsed) => (Err(std::io::Error::other("deadline exceeded")), true),
        },
    };

    if timed_out {
        // Best effort: if the process is already gone this errors, and we discard it.
        // The exit code stays `None` either way, which is the honest answer — we do
        // not know how it ended.
        //
        // This signals the direct child only. A script that backgrounded a long-lived
        // command leaves that grandchild running, and killing its process group needs
        // `killpg`, which is not in `std`. The drain below makes sure the orphan cannot
        // make *this* call hang; stopping the orphan itself is a device-side follow-up
        // recorded in the readiness assessment, because on a phone it is a battery cost
        // rather than a correctness one.
        let _ = child.kill().await;
    }

    // The process is gone, so whether the body was fully handed over no longer matters
    // and the writer may still be blocked on a stdin pipe nobody will read again.
    writer.abort();

    // A signal-killed process has no code, same as a killed-by-us one. Both are
    // `None`, and `ExecRecord` documents `None` as "killed rather than exited".
    let exit_code = if timed_out {
        None
    } else {
        status.ok().and_then(|s| s.code())
    };

    let (out_bytes, out_cut) = settle(out_task, &out_abort, &out).await;
    let (err_bytes, err_cut) = settle(err_task, &err_abort, &err).await;

    let duration = started.elapsed();
    let truncated = out_cut || err_cut;

    if timed_out {
        // Partial output is the payload here, not a consolation prize. The identity
        // prologue `script` puts first is what makes a killed command still answer
        // "who was running this", which is the difference between a timeout that can
        // be audited and one that cannot.
        return Ok(RawOutput {
            exit_code: None,
            stdout: out_bytes,
            stderr: err_bytes,
            truncated,
            timed_out: true,
            duration,
        });
    }

    Ok(RawOutput::finished(
        exit_code, out_bytes, err_bytes, truncated, duration,
    ))
}

/// How long to keep draining the output pipes after the process is gone.
///
/// The pipes are not guaranteed to close when the child does. A script that backgrounded
/// something — `logcat &`, `sleep 30 &` — leaves a grandchild holding the write end, and
/// reading to EOF would then wait for *it*. Anything still in the kernel buffer arrives in
/// microseconds, so a bounded wait captures the output without letting a lingering
/// grandchild decide how long a finished command takes.
const DRAIN_GRACE: Duration = Duration::from_millis(250);

/// One output stream, accumulated somewhere the caller can read even after the task that
/// fills it has been abandoned. See [`DRAIN_GRACE`].
#[derive(Clone, Default)]
struct Capture {
    inner: std::sync::Arc<std::sync::Mutex<Captured>>,
}

#[derive(Default)]
struct Captured {
    bytes: Vec<u8>,
    cut: bool,
}

impl Capture {
    /// Keep what still fits under `cap` and record that the rest was dropped.
    fn push(&self, chunk: &[u8], cap: usize) {
        let mut held = self.inner.lock().unwrap();
        let room = cap.saturating_sub(held.bytes.len());
        let take = chunk.len().min(room);
        held.bytes.extend_from_slice(&chunk[..take]);
        if take < chunk.len() {
            held.cut = true;
        }
    }

    /// Everything collected so far, and whether anything was dropped.
    fn take(&self) -> (Vec<u8>, bool) {
        let mut held = self.inner.lock().unwrap();
        (std::mem::take(&mut held.bytes), held.cut)
    }
}

/// Read a stream to EOF or until the task is aborted, feeding [`Capture`].
///
/// Keeps reading past the cap rather than stopping: a child blocked writing to a full pipe
/// would hit its deadline for the wrong reason, and would then be reported as a hang rather
/// than as a command that was merely verbose.
async fn read_capped<R>(mut reader: R, cap: usize, sink: Capture)
where
    R: AsyncRead + Unpin,
{
    let mut chunk = vec![0u8; READ_CHUNK];
    loop {
        match reader.read(&mut chunk).await {
            Ok(0) | Err(_) => break,
            Ok(n) => sink.push(&chunk[..n], cap),
        }
    }
}

/// Settle a reader task: give it [`DRAIN_GRACE`] to finish, then stop waiting for it.
///
/// The bytes are read from the shared [`Capture`] rather than from the task's return value,
/// which is what makes abandoning the task safe — an abandoned task loses nothing the caller
/// can still see.
async fn settle<T>(
    mut task: tokio::task::JoinHandle<T>,
    abort: &tokio::task::AbortHandle,
    capture: &Capture,
) -> (Vec<u8>, bool) {
    if tokio::time::timeout(DRAIN_GRACE, &mut task).await.is_err() {
        abort.abort();
    }
    capture.take()
}

/// A [`SpawnRunner`] that replays canned outputs, for tests of the layers above it.
///
/// Lives in `src` rather than a test file because both this crate's unit tests and its
/// integration tests need it, and duplicating it invites the two to drift apart.
///
/// It also records the invocations it was given, which is how a test asserts the
/// properties that matter — script on stdin, environment explicit — instead of merely
/// asserting the output mapping.
#[derive(Debug, Default)]
pub struct ScriptedSpawnRunner {
    replies: std::sync::Mutex<Vec<RawOutput>>,
    seen: std::sync::Mutex<Vec<SpawnInvocation>>,
}

impl ScriptedSpawnRunner {
    /// A runner that answers with `replies` in order, repeating the last one once they
    /// run out, so a test that does not care about call N does not have to script it.
    pub fn new(replies: Vec<RawOutput>) -> ScriptedSpawnRunner {
        ScriptedSpawnRunner {
            replies: std::sync::Mutex::new(replies),
            seen: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// A runner that computes its reply from the invocation it was given.
    ///
    /// This is what lets a fake behave like a shell instead of like a recording. A real
    /// shell echoes back the identity marker whose nonce it was handed inside the script, so
    /// a canned stdout cannot match it — the nonce is fresh per call. A dynamic reply closes
    /// that gap: see [`super::script::nonce_of`].
    pub fn dynamic<F>(reply: F) -> DynamicSpawnRunner<F>
    where
        F: Fn(&SpawnInvocation) -> RawOutput + Send + Sync + 'static,
    {
        DynamicSpawnRunner {
            reply,
            seen: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// A runner that answers every call with one output.
    pub fn always(out: RawOutput) -> ScriptedSpawnRunner {
        ScriptedSpawnRunner::new(vec![out])
    }

    /// Every invocation this runner was handed, in order.
    pub fn invocations(&self) -> Vec<SpawnInvocation> {
        self.seen.lock().unwrap().clone()
    }

    /// The single invocation it was handed, panicking if that is not exactly one.
    pub fn only_invocation(&self) -> SpawnInvocation {
        let all = self.invocations();
        assert_eq!(all.len(), 1, "expected exactly one invocation");
        all.into_iter().next().unwrap()
    }

    fn next_reply(&self) -> Option<RawOutput> {
        let mut replies = self.replies.lock().unwrap();
        if replies.is_empty() {
            return None;
        }
        if replies.len() == 1 {
            return replies.first().cloned();
        }
        Some(replies.remove(0))
    }
}

#[async_trait]
impl SpawnRunner for ScriptedSpawnRunner {
    async fn spawn(&self, invocation: SpawnInvocation) -> Result<RawOutput, SpawnError> {
        self.seen.lock().unwrap().push(invocation);
        self.next_reply().ok_or_else(|| {
            SpawnError::Backend("ScriptedSpawnRunner ran out of canned replies".into())
        })
    }
}

/// A [`SpawnRunner`] whose reply is computed from the invocation.
///
/// Returned by [`ScriptedSpawnRunner::dynamic`]. Separate from the canned runner because the
/// closure type differs per call site, and boxing it to share one type would buy nothing.
#[derive(Debug)]
pub struct DynamicSpawnRunner<F>
where
    F: Fn(&SpawnInvocation) -> RawOutput + Send + Sync,
{
    reply: F,
    seen: std::sync::Mutex<Vec<SpawnInvocation>>,
}

#[async_trait]
impl<F> SpawnRunner for DynamicSpawnRunner<F>
where
    F: Fn(&SpawnInvocation) -> RawOutput + Send + Sync + 'static,
{
    async fn spawn(&self, invocation: SpawnInvocation) -> Result<RawOutput, SpawnError> {
        let out = (self.reply)(&invocation);
        self.seen.lock().unwrap().push(invocation);
        Ok(out)
    }
}

impl<F> DynamicSpawnRunner<F>
where
    F: Fn(&SpawnInvocation) -> RawOutput + Send + Sync,
{
    /// Every invocation this runner was handed, in order.
    pub fn invocations(&self) -> Vec<SpawnInvocation> {
        self.seen.lock().unwrap().clone()
    }

    /// The single invocation it was handed, panicking if that is not exactly one.
    pub fn only_invocation(&self) -> SpawnInvocation {
        let all = self.invocations();
        assert_eq!(all.len(), 1, "expected exactly one invocation");
        all.into_iter().next().unwrap()
    }
}

/// Build a [`RawOutput`] for tests, from text rather than bytes.
pub fn scripted_output(exit_code: Option<i32>, stdout: &str, stderr: &str) -> RawOutput {
    RawOutput {
        exit_code,
        stdout: stdout.as_bytes().to_vec(),
        stderr: stderr.as_bytes().to_vec(),
        truncated: false,
        timed_out: false,
        duration: Duration::from_millis(1),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invocation_defaults_match_the_read_tier() {
        let inv = SpawnInvocation::new("/system/bin/sh", "echo hi");
        assert_eq!(inv.args, Vec::<String>::new());
        assert!(inv.env.is_empty());
        assert_eq!(inv.output_cap, super::super::backend::DEFAULT_OUTPUT_CAP);
        assert_eq!(
            inv.timeout,
            Some(super::super::backend::DEFAULT_READ_TIMEOUT)
        );
    }

    #[tokio::test]
    async fn scripted_runner_records_what_it_was_given() {
        let runner = ScriptedSpawnRunner::always(scripted_output(Some(0), "out", ""));
        let inv = SpawnInvocation::new("/system/bin/su", "id -u").with_args(&["-c", "sh -s"]);

        let out = runner.spawn(inv).await.unwrap();
        assert_eq!(out.stdout, b"out".to_vec());

        let seen = runner.only_invocation();
        assert_eq!(seen.file, PathBuf::from("/system/bin/su"));
        assert_eq!(seen.args, vec!["-c".to_string(), "sh -s".to_string()]);
        assert_eq!(seen.script, "id -u", "the script must stay out of argv");
    }

    #[tokio::test]
    async fn running_out_of_replies_is_an_error_not_a_hang() {
        let runner = ScriptedSpawnRunner::new(vec![]);
        let err = runner
            .spawn(SpawnInvocation::new("/bin/sh", "true"))
            .await
            .unwrap_err();
        assert!(matches!(err, SpawnError::Backend(_)), "{err:?}");
    }

    #[test]
    fn only_a_clean_zero_exit_counts_as_success() {
        let cases = [
            ("clean zero", Some(0), false, true),
            ("non-zero", Some(1), false, false),
            ("killed by our deadline", None, true, false),
            ("killed by a signal", None, false, false),
        ];
        for (name, code, timed_out, want) in cases {
            let out = RawOutput {
                exit_code: code,
                stdout: Vec::new(),
                stderr: Vec::new(),
                truncated: false,
                timed_out,
                duration: Duration::from_secs(1),
            };
            assert_eq!(out.succeeded(), want, "{name}");
        }
    }

    #[test]
    fn error_text_names_the_program_and_carries_the_reason() {
        let e = SpawnError::Unavailable {
            file: "/system/bin/su".into(),
            reason: "No such file or directory".into(),
        };
        let msg = e.to_string();
        assert!(msg.contains("/system/bin/su"), "{msg}");
        assert!(msg.contains("No such file"), "{msg}");
    }
}
