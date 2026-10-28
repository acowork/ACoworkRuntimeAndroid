//! ADR-AND-001 §4.6.1 — the audit trail: what ran, what was refused, by whom, and where it
//! went.
//!
//! # Why this module exists at all
//!
//! Before it, every field the ADR asks for was *computed* and then *dropped*.
//! [`ExecRecord`](super::backend::ExecRecord) carried uid, SELinux domain, exit code,
//! duration and parsed `avc` denials; [`BackendError`](super::backend::BackendError) carried
//! the refusal reason. Both were handed to the caller and, on the contract path, projected
//! down to a platform-neutral [`ExecOutcome`](acowork_platform_contract::ExecOutcome) whose
//! shape has nowhere to put any of it. So the answer to "which session ran `settings put` as
//! uid 2000 at 03:12, and did SELinux object?" was computed, correct, and gone.
//!
//! # What is audited, and what is not
//!
//! One attempt per `exec` that reached a backend — both halves below. The *gate's* own
//! refusals (no approval token, session lock held, attribution tier) are **not** recorded
//! here: they are decided in the platform-neutral contract crate, which has no idea what a
//! SELinux domain is, and the node that owns the gate has its own logging. This module covers
//! exactly the layer where device facts exist.
//!
//! # Two halves, because a phone can die mid-command
//!
//! ```text
//!   exec ──▶ record Attempted ──▶ backend ──▶ record Completed / Refused / …
//!                 │
//!                 └── fails ⇒ the command does not run
//! ```
//!
//! The `Attempted` half is written **before** the backend is entered, and a sink that cannot
//! accept it stops the command. That is the only moment where refusing is still possible, so
//! it is the only moment where fail-closed means anything: an audit trail that can be skipped
//! is a log, not a control. It also covers the failure mode a laptop does not have — the
//! device loses power, or the process is killed, while a command is in flight. A post-hoc-only
//! log would then contain no trace that anything happened. With two halves, the orphaned
//! `Attempted` record *is* the evidence: an attempt with no outcome is exactly what a human
//! needs to find.
//!
//! A terminal half that cannot be written is deliberately **not** turned into an error. The
//! command already ran; reporting an audit failure as a command failure tells the caller a
//! mutation did not happen when it did, and invites a retry of it. The loss is counted
//! ([`AuditSink::failures`]) for the node to surface instead.
//!
//! # This file is device-local, on purpose
//!
//! The raw SELinux context, the `avc` detail and the full command text are written here
//! because §4.6.1 asks for them and because the audit trail is the one place they belong.
//! ADR-AND-001 §7.1 forbids those strings going *to the Gateway*; nothing in this module talks
//! to a Gateway, and [`ExecRecord::to_contract`](super::backend::ExecRecord::to_contract)
//! stays the only projection onto the wire. The asymmetry is pinned from both sides by
//! `the_context_is_in_the_local_log_and_nowhere_else`.
//!
//! # Storage
//!
//! Append-only JSONL, one event per line: `tail -f` works, a device shell can read it without
//! a parser, and a crash mid-write corrupts at most the last line. It is bounded — a phone's
//! `/data` is not a log bucket, and an unbounded audit file is a self-inflicted denial of
//! service on the device it exists to protect. Past the cap the oldest lines are dropped: a
//! log that keeps the *oldest* entries stops being able to answer the only question anyone
//! asks it, "what just happened".

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::host::backend::{BackendError, ExecRecord, ExecRequest, ExecutionBackend};
use crate::host::commands::RefusalKind;
use crate::host::denial::SelinuxDenial;
use crate::host::facts::ShellDialect;
use crate::host::profile::HostProfile;

/// Longest command text kept in a record, in bytes.
///
/// The script is the evidence, so it is kept verbatim rather than summarised — but a model
/// that pastes a 4 MB here-document into `script` would otherwise get to decide how fast the
/// audit file fills up. What survives is the head, and
/// [`command_truncated`](AuditEvent::command_truncated) says so: a silent cut would be the
/// worst of both, because a reader could not tell a short command from a long one.
pub const MAX_COMMAND_BYTES: usize = 4096;

/// Default ceiling for the audit file, in bytes.
///
/// 1 MiB at ~250 bytes per record is roughly four thousand attempts: enough to reconstruct a
/// session, small enough to leave on a phone indefinitely without anyone thinking about it.
pub const DEFAULT_MAX_FILE_BYTES: u64 = 1 << 20;

/// How one attempt ended.
///
/// [`AuditOutcome::Attempted`](Self::Attempted) is not the same kind of thing as the rest — it is
/// the *opening* half, written before the device is touched — and it lives in this enum rather
/// than in a second type so the file stays one schema and one event per line. A reader pairs
/// halves on [`AuditEvent::id`](AuditEvent::id); an `Attempted` with no partner is an attempt
/// whose outcome was never written.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum AuditOutcome {
    /// Written before the backend is entered. Carries the request, not the result.
    ///
    /// Not named `Started`, because it does not mean a process started: a refused
    /// attempt gets this record too, and a reader who took it for a spawn would conclude the
    /// device was touched when it was not. It means the request reached the port.
    Attempted,
    /// The script ran.
    ///
    /// A non-zero `exit_code` is *not* an error and is not recorded as one — it is the
    /// command's own answer. `timed_out` and `selinux_blocked` are the two ways a run that
    /// looks successful is not.
    Completed {
        /// `None` when the process was killed rather than exiting.
        exit_code: Option<i32>,
        /// Killed for exceeding the budget.
        timed_out: bool,
        /// At least one non-permissive `avc: denied` appeared in stderr.
        selinux_blocked: bool,
        /// Output hit the cap, so the captured streams are partial.
        truncated: bool,
    },
    /// The port declined to run it, before the device was touched (§4.4 / §4.6.3).
    Refused {
        /// Which rule. A hard ban and a mislabel are opposite incidents in a log even though
        /// both read as one sentence in a message.
        kind: RefusalKind,
        /// The R9 message, verbatim.
        reason: String,
    },
    /// A privileged backend asked for uid 0 and did not get it (§7.4).
    ///
    /// Carries nothing, because the observed uid and domain are already on the event. What
    /// makes it an incident is the *combination* of an expected-privileged backend with a
    /// non-zero uid, which no single field expresses.
    PrivilegeNotGranted,
    /// The privileged helper is not there: no `su`, or the prompt was denied.
    EscalationUnavailable {
        /// Why, as the backend reported it.
        reason: String,
    },
    /// The backend itself broke: spawn failure, I/O error.
    BackendFailure {
        /// Why.
        reason: String,
    },
}

/// One line of the audit trail.
///
/// The field set is §4.6.1's list — capability, actual uid, SELinux domain, command, exit
/// code, duration, `avc` denials — plus the three things that make the list mean something
/// after the fact: who asked ([`session_id`](AuditEvent::session_id)), which mechanism
/// answered ([`backend`](AuditEvent::backend)), and when ([`timestamp_ms`](AuditEvent::timestamp_ms)).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Correlates the two halves of one attempt within this process.
    pub id: u64,
    /// Milliseconds since the Unix epoch, from the device clock.
    ///
    /// A phone's clock is not a witness: it is often wrong before the first network sync and
    /// the user can set it by hand. It orders events against each other, which is what a
    /// duration needs; anything that must hold across processes comes from
    /// [`id`](AuditEvent::id), which is monotonic per writer.
    pub timestamp_ms: u64,
    /// Which backend answered, e.g. `shell(system-shell)`. [`ExecutionBackend::name`]'s
    /// string, which already encodes the tier.
    pub backend: String,
    /// The session that asked. §7.2 attributes both the write lock and the audit trail to
    /// sessions, not to agents.
    pub session_id: String,
    /// Capability id the request was labelled with, e.g. `android:shell:read`.
    pub capability: String,
    /// The script body, capped at [`MAX_COMMAND_BYTES`].
    ///
    /// The *requested* script, before [`script::prepare`](super::script::prepare) adds the
    /// identity prologue: the prologue is ours and constant, so recording it would add noise
    /// and bury the interesting bytes under a prefix.
    pub command: String,
    /// True when [`command`](AuditEvent::command) was cut.
    pub command_truncated: bool,
    /// uid that actually ran, when the identity probe produced one. `None` for a refusal —
    /// nothing ran, and inventing an identity for a command that never started is how an
    /// audit trail becomes fiction.
    pub uid: Option<u32>,
    /// The raw SELinux context that actually ran. Local only; see the module docs.
    pub context: Option<String>,
    /// Wall-clock execution time. `0` for a refusal.
    pub duration_ms: u64,
    /// Structured `avc: denied` records from stderr, permissive ones included.
    pub selinux_denials: Vec<SelinuxDenial>,
    /// How it ended.
    pub outcome: AuditOutcome,
}

impl AuditEvent {
    /// The opening half: what was asked, written before anything is spawned.
    pub fn attempted(id: u64, backend: &str, request: &ExecRequest) -> AuditEvent {
        let (command, command_truncated) = cap_command(&request.script);
        AuditEvent {
            id,
            timestamp_ms: epoch_ms(),
            backend: backend.to_string(),
            session_id: request.session_id.clone(),
            capability: request.capability.as_str().to_string(),
            command,
            command_truncated,
            uid: None,
            context: None,
            duration_ms: 0,
            selinux_denials: Vec::new(),
            outcome: AuditOutcome::Attempted,
        }
    }

    /// The closing half, from whatever the backend returned.
    ///
    /// Takes the `Attempted` event rather than rebuilding from the request: the two halves must
    /// agree on id, backend, session, capability and command, and the cheapest way to
    /// guarantee that is to derive one from the other. Only the outcome and the observed
    /// identity change.
    pub fn finished(
        attempted: &AuditEvent,
        result: &Result<ExecRecord, BackendError>,
    ) -> AuditEvent {
        let mut event = attempted.clone();
        event.timestamp_ms = epoch_ms();
        event.outcome = match result {
            Ok(record) => {
                event.uid = record.uid;
                event.context = record.context.clone();
                event.duration_ms = record.duration_ms;
                event.selinux_denials = record.selinux_denials.clone();
                AuditOutcome::Completed {
                    exit_code: record.exit_code,
                    timed_out: record.timed_out,
                    selinux_blocked: record.was_blocked_by_selinux(),
                    truncated: record.truncated,
                }
            }
            Err(BackendError::PrivilegeNotGranted {
                observed_uid,
                observed_context,
            }) => {
                // The one error that arrives *with* an identity: the probe ran, and what it
                // saw is the reason the request was refused. Dropping it would leave the log
                // saying "not root" without saying what was.
                event.uid = *observed_uid;
                event.context = observed_context.clone();
                AuditOutcome::PrivilegeNotGranted
            }
            Err(BackendError::Refused { kind, reason }) => AuditOutcome::Refused {
                kind: *kind,
                reason: reason.clone(),
            },
            Err(BackendError::EscalationUnavailable(reason)) => {
                AuditOutcome::EscalationUnavailable {
                    reason: reason.clone(),
                }
            }
            Err(BackendError::Backend(reason)) => AuditOutcome::BackendFailure {
                reason: reason.clone(),
            },
        };
        event
    }
}

/// Cap the command text, reporting whether it was cut.
///
/// Cut on a byte boundary only after checking it is a *character* boundary: `script` is a
/// Rust `String`, so a naive `&s[..4096]` panics when a multi-byte character straddles the
/// limit — and a panic in the audit path would take down the very command it is recording.
fn cap_command(script: &str) -> (String, bool) {
    if script.len() <= MAX_COMMAND_BYTES {
        return (script.to_string(), false);
    }
    let mut end = MAX_COMMAND_BYTES;
    while !script.is_char_boundary(end) {
        end -= 1;
    }
    (script[..end].to_string(), true)
}

fn epoch_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Why a record could not be written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditError {
    /// The event would not serialise. Should be impossible — every field is a `String`, a
    /// `u64`, a `bool`, or a `Vec` of the same — and treated as a bug rather than retried.
    Serialize(String),
    /// The file could not be opened, written or rotated.
    Io {
        /// Which file. A sink that cannot write is diagnosable only if it says where.
        path: String,
        /// The OS message.
        reason: String,
    },
}

impl std::fmt::Display for AuditError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuditError::Serialize(why) => {
                write!(f, "audit record could not be serialised: {why}")
            }
            AuditError::Io { path, reason } => {
                write!(f, "audit record could not be written to `{path}`: {reason}")
            }
        }
    }
}

impl std::error::Error for AuditError {}

/// Where records go.
///
/// Sync by design: [`FileAuditSink`] does one small append, and marking it `async` would move
/// the blocking call into the executor without removing it. A sink that needs real work —
/// network, encryption, a database — belongs behind a queue owned by the node, which then
/// presents this trait. That is the node's decision, not a reason to complicate the seam.
pub trait AuditSink: Send + Sync {
    /// Write one record.
    ///
    /// An error is not a suggestion: on the `Attempted` half it stops the command.
    fn record(&self, event: &AuditEvent) -> Result<(), AuditError>;

    /// How many records this sink has refused to write, counting both halves.
    ///
    /// Required rather than defaulted, because a sink with no way to admit failure is a sink
    /// that fails silently — and the whole reason the terminal half does not error is that
    /// *something* still has to know the record was lost.
    fn failures(&self) -> u64;

    /// The most recent failure, for whoever has to explain a gap in the log.
    fn last_error(&self) -> Option<String> {
        None
    }
}

/// A sink that appends one JSON object per line, bounded in size.
///
/// Rotation drops the oldest lines, in the same directory, via temp-file + rename: `rename`
/// is atomic within a filesystem, so a reader sees either the old file or the new one and
/// never a half-truncated one. The device may be out of storage exactly when rotation
/// triggers, so the temp file is removed on failure rather than left behind making it worse.
pub struct FileAuditSink {
    path: PathBuf,
    max_bytes: u64,
    failures: AtomicU64,
    last_error: Mutex<Option<String>>,
}

impl FileAuditSink {
    /// A sink at `path` with the default cap.
    pub fn new(path: impl Into<PathBuf>) -> FileAuditSink {
        FileAuditSink::with_max_bytes(path, DEFAULT_MAX_FILE_BYTES)
    }

    /// A sink with an explicit cap, for tests and for partitions smaller than a phone's.
    pub fn with_max_bytes(path: impl Into<PathBuf>, max_bytes: u64) -> FileAuditSink {
        FileAuditSink {
            path: path.into(),
            max_bytes,
            failures: AtomicU64::new(0),
            last_error: Mutex::new(None),
        }
    }

    /// Where it writes.
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn fail(&self, err: AuditError) -> AuditError {
        self.failures.fetch_add(1, Ordering::Relaxed);
        if let Ok(mut guard) = self.last_error.lock() {
            *guard = Some(err.to_string());
        }
        err
    }

    /// Drop the oldest lines until the file fits in half the cap.
    ///
    /// Half, not the cap: rotating *at* the limit would rewrite on the very next record, and
    /// a log that rewrites itself once a line is I/O wear on the device it is meant to
    /// protect.
    fn rotate(&self) -> Result<(), AuditError> {
        let io_err = |e: std::io::Error| AuditError::Io {
            path: self.path.display().to_string(),
            reason: e.to_string(),
        };
        let bytes = std::fs::read(&self.path).map_err(io_err)?;
        let text = String::from_utf8_lossy(&bytes);
        let keep = (self.max_bytes / 2) as usize;

        // Walk from the newest line backwards, accumulating until the next one would not fit.
        // `split_inclusive` keeps the newline, so a piece's length is its cost on disk.
        let mut total = 0usize;
        let mut split = text.len();
        for line in text.split_inclusive('\n').rev() {
            let next = total + line.len();
            if next > keep {
                break;
            }
            total = next;
            split -= line.len();
        }
        let tail = &text[split..];

        let tmp = {
            let mut p = self.path.clone().into_os_string();
            p.push(".tmp");
            PathBuf::from(p)
        };
        std::fs::write(&tmp, tail.as_bytes()).map_err(io_err)?;
        std::fs::rename(&tmp, &self.path).map_err(|e| {
            let _ = std::fs::remove_file(&tmp);
            io_err(e)
        })
    }
}

impl AuditSink for FileAuditSink {
    fn record(&self, event: &AuditEvent) -> Result<(), AuditError> {
        let line = serde_json::to_string(event)
            .map_err(|e| self.fail(AuditError::Serialize(e.to_string())))?;

        if let Some(parent) = self.path.parent()
            && !parent.as_os_str().is_empty()
        {
            let _ = std::fs::create_dir_all(parent);
        }

        let opened = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| {
                self.fail(AuditError::Io {
                    path: self.path.display().to_string(),
                    reason: e.to_string(),
                })
            })?;
        let mut file = opened;
        let written = file
            .write_all(line.as_bytes())
            .and_then(|()| file.write_all(b"\n"))
            .and_then(|()| file.flush())
            .and_then(|()| file.sync_all());
        drop(file);
        if let Err(e) = written {
            return Err(self.fail(AuditError::Io {
                path: self.path.display().to_string(),
                reason: e.to_string(),
            }));
        }

        let len = std::fs::metadata(&self.path)
            .map(|m| m.len())
            .map_err(|e| {
                self.fail(AuditError::Io {
                    path: self.path.display().to_string(),
                    reason: e.to_string(),
                })
            })?;
        if len > self.max_bytes {
            self.rotate().map_err(|e| self.fail(e))?;
        }
        Ok(())
    }

    fn failures(&self) -> u64 {
        self.failures.load(Ordering::Relaxed)
    }

    fn last_error(&self) -> Option<String> {
        self.last_error.lock().ok().and_then(|g| g.clone())
    }
}

impl std::fmt::Debug for FileAuditSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileAuditSink")
            .field("path", &self.path)
            .field("max_bytes", &self.max_bytes)
            .field("failures", &self.failures.load(Ordering::Relaxed))
            .finish()
    }
}

/// Records held in memory: for tests, and for a node that wants to buffer and flush itself.
///
/// `fail_after` exists so the fail-closed path is testable without inventing a read-only
/// filesystem, which on a developer machine is not a reliable thing to arrange.
#[derive(Debug, Default)]
pub struct MemoryAuditSink {
    events: Mutex<Vec<AuditEvent>>,
    fail_after: Option<usize>,
    failures: AtomicU64,
    last_error: Mutex<Option<String>>,
}

impl MemoryAuditSink {
    /// An empty sink that accepts everything.
    pub fn new() -> MemoryAuditSink {
        MemoryAuditSink::default()
    }

    /// A sink that accepts `n` records and fails every one after that.
    pub fn failing_after(n: usize) -> MemoryAuditSink {
        MemoryAuditSink {
            fail_after: Some(n),
            ..MemoryAuditSink::default()
        }
    }

    /// A copy of everything accepted, in order.
    pub fn events(&self) -> Vec<AuditEvent> {
        self.events.lock().unwrap().clone()
    }

    /// How many records are held.
    pub fn len(&self) -> usize {
        self.events.lock().unwrap().len()
    }

    /// True when nothing has been recorded.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl AuditSink for MemoryAuditSink {
    fn record(&self, event: &AuditEvent) -> Result<(), AuditError> {
        let mut events = self.events.lock().unwrap();
        if let Some(limit) = self.fail_after
            && events.len() >= limit
        {
            {
                drop(events);
                let err = AuditError::Io {
                    path: "<memory>".to_string(),
                    reason: "sink configured to fail".to_string(),
                };
                self.failures.fetch_add(1, Ordering::Relaxed);
                if let Ok(mut g) = self.last_error.lock() {
                    *g = Some(err.to_string());
                }
                return Err(err);
            }
        }
        events.push(event.clone());
        Ok(())
    }

    fn failures(&self) -> u64 {
        self.failures.load(Ordering::Relaxed)
    }

    fn last_error(&self) -> Option<String> {
        self.last_error.lock().ok().and_then(|g| g.clone())
    }
}

/// Wraps a backend so every attempt is accounted for.
///
/// A decorator rather than a hook inside each backend, for two reasons. The first is obvious:
/// three backends would each have to remember to log, and the point of an audit trail is that
/// forgetting is not an option. The second matters more here — the refusals most worth logging
/// are produced by the shared content check in [`run_script`](super::backends), deep inside
/// the shell backends, so per-backend logging would cover the shell tiers and miss
/// [`AppSandboxBackend`](super::backends::AppSandboxBackend), which has no shell and refuses
/// for a reason of its own.
///
/// Composes in both directions: wrap a backend before handing it to
/// [`ContractBackend`](super::backend::ContractBackend) and the wire projection is unchanged.
/// The audit trail is a device-side concern and adds nothing to what crosses the seam.
pub struct AuditedBackend {
    inner: Arc<dyn ExecutionBackend>,
    sink: Arc<dyn AuditSink>,
    next_id: AtomicU64,
}

impl AuditedBackend {
    /// Wrap `inner` so every `exec` is written to `sink`.
    pub fn new(inner: Arc<dyn ExecutionBackend>, sink: Arc<dyn AuditSink>) -> AuditedBackend {
        AuditedBackend {
            inner,
            sink,
            next_id: AtomicU64::new(1),
        }
    }

    /// The sink, so a caller can read [`AuditSink::failures`] after the fact.
    pub fn sink(&self) -> &Arc<dyn AuditSink> {
        &self.sink
    }

    /// The wrapped backend, when the caller needs it.
    pub fn inner(&self) -> &Arc<dyn ExecutionBackend> {
        &self.inner
    }
}

#[async_trait::async_trait]
impl ExecutionBackend for AuditedBackend {
    fn name(&self) -> &'static str {
        self.inner.name()
    }

    fn dialect(&self) -> Option<ShellDialect> {
        self.inner.dialect()
    }

    fn profile(&self) -> &HostProfile {
        self.inner.profile()
    }

    async fn exec(&self, request: ExecRequest) -> Result<ExecRecord, BackendError> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let attempted = AuditEvent::attempted(id, self.inner.name(), &request);

        // Fail closed *here*: this is the last point at which nothing has happened yet.
        if let Err(e) = self.sink.record(&attempted) {
            return Err(BackendError::Backend(format!(
                "refusing to run: no audit record, no command — §4.6.1 makes the record a \
                 precondition, and a sink that cannot accept one ({e}) is not a reason to \
                 run something unaccounted for"
            )));
        }

        let result = self.inner.exec(request).await;
        let finished = AuditEvent::finished(&attempted, &result);

        // And *not* fail closed here: the command already ran. The sink has counted the loss;
        // rewriting the outcome to match would be the worse lie.
        let _ = self.sink.record(&finished);

        result
    }
}

impl std::fmt::Debug for AuditedBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditedBackend")
            .field("inner", &self.inner.name())
            .field("next_id", &self.next_id.load(Ordering::Relaxed))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A backend that returns what the test told it to, and counts how often it was asked.
    /// The counter is the point: fail-closed is only proven if "never entered" is observable.
    struct FakeBackend {
        profile: HostProfile,
        name: &'static str,
        result: Mutex<Option<Result<ExecRecord, BackendError>>>,
        calls: AtomicU64,
    }

    impl FakeBackend {
        fn returning(result: Result<ExecRecord, BackendError>) -> FakeBackend {
            FakeBackend {
                profile: HostProfile::assemble(
                    &crate::host::probe::ProbeOutput::nothing_ran(),
                    "com.example.agent",
                ),
                name: "fake(shell)",
                result: Mutex::new(Some(result)),
                calls: AtomicU64::new(0),
            }
        }
    }

    #[async_trait::async_trait]
    impl ExecutionBackend for FakeBackend {
        fn name(&self) -> &'static str {
            self.name
        }

        fn dialect(&self) -> Option<ShellDialect> {
            Some(ShellDialect::MkSh)
        }

        fn profile(&self) -> &HostProfile {
            &self.profile
        }

        async fn exec(&self, _request: ExecRequest) -> Result<ExecRecord, BackendError> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            self.result
                .lock()
                .unwrap()
                .clone()
                .unwrap_or_else(|| Err(BackendError::Backend("test backend is exhausted".into())))
        }
    }

    fn record(uid: Option<u32>, context: Option<&str>) -> ExecRecord {
        ExecRecord {
            stdout: "ro.build.type=user".into(),
            stderr: String::new(),
            exit_code: Some(0),
            selinux_denials: Vec::new(),
            uid,
            context: context.map(str::to_string),
            duration_ms: 42,
            truncated: false,
            timed_out: false,
        }
    }

    fn read_request() -> ExecRequest {
        ExecRequest::read("getprop ro.build.type", "session-alpha")
    }

    fn audited(
        result: Result<ExecRecord, BackendError>,
        sink: Arc<dyn AuditSink>,
    ) -> (Arc<FakeBackend>, AuditedBackend) {
        let fake = Arc::new(FakeBackend::returning(result));
        let audited = AuditedBackend::new(fake.clone(), sink);
        (fake, audited)
    }

    #[tokio::test]
    async fn every_field_the_adr_names_is_in_the_record() {
        // §4.6.1: capability / 实际 uid / SELinux 域 / 命令 / exit code / 耗时 / avc 拒绝.
        // Asserted one field at a time, because "the struct has the fields" is not the
        // property — the property is that the *values* land, from the right side of the run.
        let sink = Arc::new(MemoryAuditSink::new());
        let denial = "avc: denied { read } for comm=\"getprop\" \
                      scontext=u:r:shell:s0 tcontext=u:object_r:system_data_file:s0 \
                      tclass=file permissive=0";
        let mut rec = record(Some(2000), Some("u:r:shell:s0"));
        rec.stderr = denial.to_string();
        rec.selinux_denials = crate::host::denial::parse_denials(denial);
        let (_fake, audited) = audited(Ok(rec), sink.clone());

        audited.exec(read_request()).await.unwrap();
        let events = sink.events();
        let finished = events.last().expect("a terminal record");
        assert_eq!(finished.capability, "android:shell:read");
        assert_eq!(finished.session_id, "session-alpha");
        assert_eq!(finished.backend, "fake(shell)");
        assert_eq!(finished.command, "getprop ro.build.type");
        assert_eq!(finished.uid, Some(2000));
        assert_eq!(finished.context.as_deref(), Some("u:r:shell:s0"));
        assert_eq!(finished.duration_ms, 42);
        assert_eq!(
            finished.outcome,
            AuditOutcome::Completed {
                exit_code: Some(0),
                timed_out: false,
                selinux_blocked: true,
                truncated: false,
            }
        );
        assert_eq!(finished.selinux_denials.len(), 1);
    }

    #[tokio::test]
    async fn a_refusal_is_recorded_with_the_rule_that_refused() {
        // The reason the refusal kind had to survive into `BackendError`: `rm -rf /data` and a
        // mislabelled `settings put` both arrive as "the port refused to run this", and in a
        // log they are opposite incidents.
        let cases = [
            (
                BackendError::Refused {
                    reason: "`rm` is not runnable at any tier".into(),
                    kind: RefusalKind::Banned,
                },
                RefusalKind::Banned,
            ),
            (
                BackendError::Refused {
                    reason: "labelled read but `settings put` writes".into(),
                    kind: RefusalKind::Mismatch,
                },
                RefusalKind::Mismatch,
            ),
            (
                BackendError::Refused {
                    reason: "cannot be classified".into(),
                    kind: RefusalKind::Opaque,
                },
                RefusalKind::Opaque,
            ),
        ];
        for (err, kind) in cases {
            let reason = match &err {
                BackendError::Refused { reason, .. } => reason.clone(),
                other => panic!("expected a refusal, got {other:?}"),
            };
            let sink = Arc::new(MemoryAuditSink::new());
            let (fake, audited) = audited(Err(err), sink.clone());
            let res = audited.exec(read_request()).await;
            assert!(res.is_err(), "a refusal stays a refusal");
            assert_eq!(fake.calls.load(Ordering::Relaxed), 1);

            let finished = sink.events().pop().unwrap();
            assert_eq!(
                finished.outcome,
                AuditOutcome::Refused { kind, reason },
                "the log must say which rule refused"
            );
            // Nothing ran, so nothing may claim an identity.
            assert_eq!(finished.uid, None);
            assert_eq!(finished.context, None);
            assert_eq!(finished.duration_ms, 0);
        }
    }

    #[tokio::test]
    async fn the_attempt_is_recorded_before_the_device_is_touched() {
        // Fail-closed, and proven where it matters: the backend was never entered. A test that
        // only checked the error message would pass against an implementation that ran the
        // command *and then* complained about the log.
        let sink = Arc::new(MemoryAuditSink::failing_after(0));
        let (fake, audited) = audited(Ok(record(Some(2000), None)), sink.clone());
        let err = audited.exec(read_request()).await.unwrap_err();
        assert!(
            fake.calls.load(Ordering::Relaxed) == 0,
            "the command ran despite the audit write failing"
        );
        assert!(matches!(err, BackendError::Backend(_)), "{err:?}");
        assert!(err.to_string().contains("no audit record"), "{err}");
        assert_eq!(sink.len(), 0);
    }

    #[tokio::test]
    async fn a_lost_terminal_record_does_not_rewrite_history() {
        // The other half of the same decision: once the command has run, an audit failure must
        // not turn it into a failure. The caller would retry a mutation that already happened.
        let sink = Arc::new(MemoryAuditSink::failing_after(1));
        let (fake, audited) = audited(Ok(record(Some(2000), Some("u:r:shell:s0"))), sink.clone());
        let rec = audited.exec(read_request()).await.unwrap();
        assert_eq!(rec.exit_code, Some(0));
        assert_eq!(fake.calls.load(Ordering::Relaxed), 1);
        assert_eq!(sink.len(), 1, "only the Attempted half got through");
        assert_eq!(sink.failures(), 1);
        assert!(sink.last_error().unwrap().contains("configured to fail"));
    }

    #[tokio::test]
    async fn the_two_halves_of_one_attempt_share_an_id() {
        // Correlation is the only reason a reader can tell "attempt with no outcome" apart
        // from "two attempts, one of them refused".
        let sink = Arc::new(MemoryAuditSink::new());
        let (_fake, audited) = audited(Ok(record(Some(2000), None)), sink.clone());
        audited.exec(read_request()).await.unwrap();
        let events = sink.events();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].id, events[1].id);
        assert_eq!(events[0].outcome, AuditOutcome::Attempted);
        assert_ne!(events[0].id, 0, "ids start at 1 so 0 stays unused");
    }

    #[tokio::test]
    async fn each_attempt_gets_its_own_id() {
        let sink = Arc::new(MemoryAuditSink::new());
        let (_fake, audited) = audited(Ok(record(Some(2000), None)), sink.clone());
        audited.exec(read_request()).await.unwrap();
        audited.exec(read_request()).await.unwrap();
        let ids: Vec<u64> = sink.events().iter().map(|e| e.id).collect();
        assert_eq!(ids, vec![1, 1, 2, 2]);
    }

    #[tokio::test]
    async fn privilege_not_granted_keeps_the_identity_it_observed() {
        // §7.4's proof, in the log: "asked for root, did not get it" is only evidence if the
        // record also says what it got instead.
        let sink = Arc::new(MemoryAuditSink::new());
        let (_fake, audited) = audited(
            Err(BackendError::PrivilegeNotGranted {
                observed_uid: Some(2000),
                observed_context: Some("u:r:shell:s0".into()),
            }),
            sink.clone(),
        );
        audited.exec(read_request()).await.unwrap_err();
        let finished = sink.events().pop().unwrap();
        assert_eq!(finished.outcome, AuditOutcome::PrivilegeNotGranted);
        assert_eq!(finished.uid, Some(2000));
        assert_eq!(finished.context.as_deref(), Some("u:r:shell:s0"));
    }

    #[tokio::test]
    async fn a_timeout_is_a_completion() {
        // A killed command still ran, still has an identity and still cost time. Recording it
        // as a backend failure would lose all three, which is the mistake `ExecRecord` already
        // refuses to make.
        let sink = Arc::new(MemoryAuditSink::new());
        let mut rec = record(Some(0), Some("u:r:magisk:s0"));
        rec.timed_out = true;
        rec.exit_code = None;
        rec.duration_ms = 5_000;
        let (_fake, audited) = audited(Ok(rec), sink.clone());
        audited.exec(read_request()).await.unwrap();
        let finished = sink.events().pop().unwrap();
        assert_eq!(
            finished.outcome,
            AuditOutcome::Completed {
                exit_code: None,
                timed_out: true,
                selinux_blocked: false,
                truncated: false,
            }
        );
        assert_eq!(finished.duration_ms, 5_000);
    }

    #[test]
    fn a_long_command_is_capped_and_says_so() {
        let long = "getprop ".to_string() + &"x".repeat(MAX_COMMAND_BYTES * 2);
        let (kept, truncated) = cap_command(&long);
        assert_eq!(kept.len(), MAX_COMMAND_BYTES);
        assert!(truncated);

        // The panic case: an ASCII lead byte followed by 2-byte glyphs puts the cap exactly
        // inside a character, so `&s[..MAX_COMMAND_BYTES]` is not a valid slice at all.
        let straddling = "a".to_string() + &"é".repeat(MAX_COMMAND_BYTES);
        assert!(straddling.len() > MAX_COMMAND_BYTES);
        assert!(
            !straddling.is_char_boundary(MAX_COMMAND_BYTES),
            "the fixture no longer straddles a character, so it tests nothing"
        );
        let (kept, truncated) = cap_command(&straddling);
        assert!(truncated);
        assert_eq!(
            kept.len(),
            MAX_COMMAND_BYTES - 1,
            "must back off to a boundary"
        );
        assert_eq!(
            kept.chars().count(),
            MAX_COMMAND_BYTES / 2,
            "'a' + n glyphs"
        );
        assert!(
            straddling.starts_with(&kept),
            "the cap keeps a prefix, not a subset"
        );

        let (short, truncated) = cap_command("ps");
        assert_eq!(short, "ps");
        assert!(!truncated);
    }

    #[tokio::test]
    async fn the_decorator_delegates_what_it_does_not_change() {
        // If wrapping a backend changed its reported dialect or profile, tool registration
        // (§4.5) would depend on whether auditing happened to be switched on.
        let sink = Arc::new(MemoryAuditSink::new());
        let (fake, audited) = audited(Ok(record(None, None)), sink);
        assert_eq!(audited.name(), fake.name());
        assert_eq!(audited.dialect(), fake.dialect());
        assert_eq!(audited.profile(), fake.profile());
    }

    // ── Storage ──────────────────────────────────────────────────────────────

    fn temp_path(tag: &str) -> PathBuf {
        static N: AtomicU64 = AtomicU64::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "acowork-audit-{}-{tag}-{n}.jsonl",
            std::process::id()
        ))
    }

    fn cleanup(path: &Path) {
        let _ = std::fs::remove_file(path);
        let mut tmp = path.as_os_str().to_os_string();
        tmp.push(".tmp");
        let _ = std::fs::remove_file(PathBuf::from(tmp));
    }

    #[test]
    fn the_log_is_one_json_object_per_line_and_reads_back() {
        let path = temp_path("roundtrip");
        let sink = FileAuditSink::new(&path);
        let attempted = AuditEvent::attempted(7, "fake(shell)", &read_request());
        let finished =
            AuditEvent::finished(&attempted, &Ok(record(Some(2000), Some("u:r:shell:s0"))));
        sink.record(&attempted).unwrap();
        sink.record(&finished).unwrap();

        let text = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2);
        let back: Vec<AuditEvent> = lines
            .iter()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(back, vec![attempted, finished]);
        assert_eq!(sink.failures(), 0);
        cleanup(&path);
    }

    #[test]
    fn the_context_is_in_the_local_log_and_nowhere_else() {
        // Both directions of §7.1, pinned here because the two halves are easy to confuse:
        // the audit file is *supposed* to hold the raw context (it is the device's own record,
        // and §4.6.1 names the SELinux domain as a field), and the contract projection is
        // supposed to drop it. A future change that "sanitises everything uniformly" would
        // destroy the audit trail, and this test is what makes that a deliberate decision.
        let path = temp_path("context");
        let sink = FileAuditSink::new(&path);
        let attempted = AuditEvent::attempted(1, "fake(shell)", &read_request());
        let event = AuditEvent::finished(&attempted, &Ok(record(Some(2000), Some("u:r:shell:s0"))));
        sink.record(&event).unwrap();

        let logged = std::fs::read_to_string(&path).unwrap();
        assert!(
            logged.contains("u:r:shell:s0"),
            "the local audit record must keep the domain: {logged}"
        );

        // The other half: the *same* run, projected the way the wire projects it. Rule R13
        // forbids the raw context on the wire; this asserts the two channels really do differ.
        let wire =
            serde_json::to_string(&record(Some(2000), Some("u:r:shell:s0")).to_contract()).unwrap();
        assert!(!wire.contains("u:r:"), "the wire view leaked: {wire}");
        cleanup(&path);
    }

    #[test]
    fn the_log_stops_growing_at_its_cap_and_keeps_the_newest() {
        // Rotation is the difference between an audit trail and a device that fills its own
        // partition. Asserted on *content*, not just size: a cap that keeps the oldest lines
        // would pass a size check and still be useless after the fact.
        let path = temp_path("rotate");
        let cap = 2048;
        let sink = FileAuditSink::with_max_bytes(&path, cap);
        let request = ExecRequest::read("getprop ro.build.type", "session-alpha");

        let total = 40;
        for i in 0..total {
            let mut event = AuditEvent::attempted(i, "fake(shell)", &request);
            // Make each line distinguishable and roughly the same size.
            event.command = format!("getprop marker.{i:03}");
            sink.record(&event).unwrap();
        }

        let text = std::fs::read_to_string(&path).unwrap();
        let size = text.len() as u64;
        assert!(size <= cap, "file outgrew its cap: {size} bytes over {cap}");
        let kept: Vec<AuditEvent> = text
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert!(
            kept.len() >= 4,
            "rotation kept almost nothing: {}",
            kept.len()
        );
        assert_eq!(
            kept.last().unwrap().id,
            total - 1,
            "the newest record must survive"
        );
        assert!(
            !kept.iter().any(|e| e.id < 10),
            "old records survived rotation: {:?}",
            kept.iter().map(|e| e.id).collect::<Vec<_>>()
        );
        // Ids in the file stay ordered, so a reader can still tell what came after what.
        assert!(kept.windows(2).all(|w| w[0].id < w[1].id));
        assert_eq!(sink.failures(), 0);
        cleanup(&path);
    }

    #[test]
    fn a_sink_that_cannot_write_says_so() {
        // `/proc` is not writable by anyone, and unlike a chmod'd directory it is unwritable
        // on every machine the test runs on, including a device.
        let sink = FileAuditSink::new("/proc/acowork-audit-test.jsonl");
        let event = AuditEvent::attempted(1, "fake(shell)", &read_request());
        let err = sink.record(&event).unwrap_err();
        assert!(err.to_string().contains("/proc"), "{err}");
        assert_eq!(sink.failures(), 1);
        assert!(sink.last_error().is_some());
    }

    #[test]
    fn an_unwritable_path_names_itself_in_the_error() {
        // The failure message is the only diagnostic a node operator gets, and "I/O error"
        // without a path is not one.
        let err = AuditError::Io {
            path: "/data/local/tmp/audit.jsonl".into(),
            reason: "No space left on device".into(),
        };
        let text = err.to_string();
        assert!(text.contains("/data/local/tmp/audit.jsonl"), "{text}");
        assert!(text.contains("No space left on device"), "{text}");
    }
}
