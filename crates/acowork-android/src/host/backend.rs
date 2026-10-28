//! The Android execution mechanism.
//!
//! # What moved out of this file
//!
//! An earlier revision defined the authorization gate here: `AttributionVerdict`,
//! `AttributionTier`, `LockOutcome`, `DeviceWriteLock`, `LocalReadiness`,
//! `AuthorizationContext`, `Denial`, `Grant` and an `authorize` function. All nine are
//! gone. They were **rules**, and rules that live in a platform crate are rules the
//! next platform has to reimplement — and will reimplement slightly differently, which
//! is how "uniform rules" quietly becomes "similar intentions".
//!
//! They now live in `acowork-platform-contract`, where a second platform inherits them
//! by depending on the crate rather than by copying the file. What remains here is the
//! part that is genuinely Android:
//!
//! | Kept here | Why it is Android's |
//! |---|---|
//! | [`ExecRequest`] | A POSIX request: a shell script, a working directory, an environment. An ESP32 has none of the three. |
//! | [`ExecRecord`] | Carries the uid and SELinux context that *actually* ran, so a silent privilege drop is detectable. |
//! | [`ApprovalToken`] | Opaque proof of a human approval. What an approval *is* belongs to the port. |
//! | [`SessionWriteLock`] | The contract lock plus the holder's session id, which ADR-AND-001 §7.2 requires a refusal to name. |
//! | [`ExecutionBackend`] | The three Android backends and their shell dialects. |
//!
//! # Why the session lock wraps the contract lock
//!
//! The contract's [`ResourceLock`] enforces the rule — one mutating action at a time,
//! TTL-bounded, no queueing, no preemption — and is deliberately identity-free, because
//! "session" is not a concept a microcontroller port necessarily has. ADR-AND-001 §7.2
//! nonetheless requires a refusal to name the holder so a human can decide to switch
//! devices or contact them.
//!
//! So the rule stays in the contract and the identity stays here. [`SessionWriteLock`]
//! pairs the two, and neither layer had to compromise: the contract did not grow a
//! `String` it cannot justify, and Android did not lose a requirement its ADR states.
//!
//! # B1 — the two authorities, and where the conjunction happens
//!
//! ADR-AND-001 §7.4 requires the device to decide locally whether "the requester is the
//! node owner". Upstream ADR-087 D1/D5 put owner truth in the Gateway's
//! `node_owners.json`, keep it out of the MQTT proto, and state that the Runtime does not
//! model owners at all. §7.1 meanwhile forbids the Gateway from making gating decisions.
//! Read literally, every path is closed.
//!
//! They stop conflicting once the question is split, which is what the contract's
//! [`Gate`](acowork_platform_contract::Gate) now does:
//!
//! | Question | Authority | Why |
//! |---|---|---|
//! | *Who* may ask for a write-tier action? | Gateway → [`AttributionVerdict`](acowork_platform_contract::AttributionVerdict) | ADR-087 D1/D5: owner truth lives in `node_owners.json`. The device cannot and must not reconstruct it. |
//! | *What* is possible here, and is it safe now? | Device → [`HostProfile`] + dangerous-mode + [`SessionWriteLock`] | Only the device has the probed facts, the local session switch, and the lock state. |
//!
//! The device receives the answer as an **opaque verdict**, never an identity. That
//! satisfies ADR-087's "Node 不感知用户" — a boolean is not a user — while preserving
//! ADR-AND-001's requirement that the final conjunction is evaluated on the device.
//!
//! This does revise §7.1's blanket "Gateway 不做门控判定": the Gateway makes an
//! *attribution* judgment, not a *capability* judgment. Recorded as blocker **B1**.

use std::collections::BTreeMap;
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Mutex;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use acowork_platform_contract::{
    Budget, ExecOutcome, ExecOutput as ContractExecOutput, ExecutionError, ExitStatus, GateView,
    HostCapability, LockOutcome, ResourceLock,
};

use crate::host::capability::Capability;
use crate::host::commands::RefusalKind;
use crate::host::denial::SelinuxDenial;
use crate::host::facts::{SelinuxDomain, ShellDialect};
use crate::host::profile::HostProfile;

/// Device write-lock TTL (ADR-AND-001 §7.2).
///
/// Ten minutes is the ADR's number, not the contract's: how long a write sequence may
/// legitimately take is a platform question, and the contract deliberately does not pick
/// one. A session that dies mid-write therefore wedges the device for at most this long,
/// which is the tradeoff the TTL exists to bound.
pub const WRITE_LOCK_TTL: Duration = Duration::from_secs(600);

/// Default per-command timeout for read-tier shell invocations.
pub const DEFAULT_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Default output cap.
///
/// `logcat -d` on a busy device can emit megabytes, and an unattended node has no one to
/// notice the OOM. The cap is enforced by the contract's [`ContractExecOutput::push`], so
/// a backend that streams through it cannot forget.
pub const DEFAULT_OUTPUT_CAP: usize = 1 << 20;

/// Opaque proof that a human approved one specific action this session.
///
/// Carries no payload the backend interprets: the gate checks presence and the approval
/// subsystem owns everything else. Keeping it opaque is what stops a backend from
/// inventing its own approval semantics — and it is why the contract's
/// [`LocalReadiness`](acowork_platform_contract::LocalReadiness) takes a `bool` rather
/// than this type.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ApprovalToken(String);

impl ApprovalToken {
    /// Wrap a raw approval value.
    pub fn new(value: impl Into<String>) -> ApprovalToken {
        ApprovalToken(value.into())
    }
}

/// A command to execute.
///
/// The Android request shape, and the clearest example of contract rule R10: this struct
/// is POSIX all the way down — a shell script, a directory, an environment. None of it
/// generalises, so the contract does not define it. What the contract requires instead is
/// that this type can answer three questions, which the [`GateView`] impl below does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecRequest {
    /// The script body. **Passed via stdin, never in argv** — argv is world-readable
    /// through `ps`, which would leak sensitive arguments to any other process on the
    /// device (ADR-AND-001 §4.7).
    pub script: String,
    /// Working directory, when the command must not inherit the Runtime's.
    pub cwd: Option<PathBuf>,
    /// Extra environment variables, merged over the backend's base environment.
    pub env: BTreeMap<String, String>,
    /// Timeout and output cap. The contract requires both to exist; it does not pick
    /// the numbers, because a phone and a microcontroller differ by orders of magnitude.
    pub budget: Budget,
    /// The capability this command exercises, as a contract ID.
    ///
    /// Stored as [`HostCapability`] rather than the local [`Capability`] enum because
    /// the gate consumes it and [`GateView::capability`] must return a reference — a
    /// conversion on the fly would have nowhere to point. Use [`ExecRequest::new`] to
    /// build one from the enum.
    pub capability: HostCapability,
    /// Present when a human approved this action.
    pub approval_token: Option<ApprovalToken>,
    /// How to undo it, required by contract rule R8 for irreversible capabilities.
    ///
    /// On Android only `android:fs:system` is irreversible — there is no snapshot of
    /// `/system` to restore from — so in practice this is "reflash the stock image".
    /// Making the model state that is the point: it is the cost of the action, and R8
    /// exists so the cost is acknowledged before the write rather than discovered after.
    pub rollback_plan: Option<String>,
    /// The session asking, for lock accounting and the audit trail.
    pub session_id: String,
}

impl ExecRequest {
    /// A request for a specific capability, with sane Android defaults.
    pub fn new(
        capability: Capability,
        script: impl Into<String>,
        session_id: impl Into<String>,
    ) -> ExecRequest {
        ExecRequest {
            script: script.into(),
            cwd: None,
            env: BTreeMap::new(),
            budget: Budget {
                timeout: Some(DEFAULT_READ_TIMEOUT),
                output_cap: DEFAULT_OUTPUT_CAP,
            },
            capability: capability.id(),
            approval_token: None,
            rollback_plan: None,
            session_id: session_id.into(),
        }
    }

    /// A read-tier request, which needs no approval and takes no lock.
    pub fn read(script: impl Into<String>, session_id: impl Into<String>) -> ExecRequest {
        ExecRequest::new(Capability::ShellRead, script, session_id)
    }

    /// The local capability handle, if this request names one of the Android five.
    ///
    /// `None` means the request carries an ID outside this port's vocabulary, which the
    /// gate refuses on rule R5 before any backend sees it.
    pub fn android_capability(&self) -> Option<Capability> {
        crate::host::capability::lookup(&self.capability)
    }
}

impl GateView for ExecRequest {
    fn capability(&self) -> &HostCapability {
        &self.capability
    }

    fn budget(&self) -> &Budget {
        &self.budget
    }

    fn rollback_plan(&self) -> Option<&str> {
        self.rollback_plan.as_deref()
    }
}

/// What actually happened, as an audit record.
///
/// ADR-AND-001 §4.7 plus the N3 requirement that diagnostics travel with the error.
/// `uid` and `context` are the reason this type is richer than the contract's
/// [`ExecOutcome`]: they let a caller prove which identity *really* ran the command,
/// which is the only way to catch a privileged helper that silently dropped privilege.
/// A platform-neutral outcome cannot carry them, because most platforms have no uids.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecRecord {
    /// Captured standard output.
    pub stdout: String,
    /// Captured standard error. Also the source of `selinux_denials`.
    pub stderr: String,
    /// `None` when the process was killed rather than exiting (timeout or signal).
    pub exit_code: Option<i32>,
    /// Structurally extracted from stderr, so callers never re-parse.
    pub selinux_denials: Vec<SelinuxDenial>,
    /// The uid that actually ran the command.
    pub uid: Option<u32>,
    /// The SELinux context that actually ran the command.
    pub context: Option<String>,
    /// Wall-clock execution time, for the audit record.
    pub duration_ms: u64,
    /// True when either stream hit [`Budget::output_cap`].
    pub truncated: bool,
    /// True when the process was killed for exceeding [`Budget::timeout`].
    ///
    /// This lives on the record rather than being returned as a `BackendError` because a
    /// timed-out command still produced evidence: partial stdout, whatever stderr said, and
    /// — since [`script`](super::script) puts the identity prologue *first* — proof of which
    /// uid and SELinux domain ran it. Routing a timeout through the error channel would
    /// discard exactly the information that makes a hang auditable, and would leave the
    /// caller unable to answer "what did it manage to do before you killed it".
    ///
    /// The contract already has this shape: [`ExecOutcome::result`] is a `Result` *inside* a
    /// struct that carries both streams. `timed_out` is what lets the Android record project
    /// onto it faithfully, with [`ExecRecord::exit_code`] `None` meaning "we do not know how
    /// it ended" rather than "it ran out of time" — those two are different facts and a
    /// caller may need to tell them apart.
    pub timed_out: bool,
}

impl ExecRecord {
    /// True when the command completed with exit status 0.
    pub fn succeeded(&self) -> bool {
        self.exit_code == Some(0)
    }

    /// True when SELinux actually blocked something. `permissive=1` records are
    /// logged-but-allowed and do not count.
    pub fn was_blocked_by_selinux(&self) -> bool {
        self.selinux_denials.iter().any(|d| !d.permissive)
    }

    /// Project onto the contract's platform-neutral outcome.
    ///
    /// Lossy by design: the uid, context, denial records and duration stay on the
    /// device, because the contract's shape has no field for them and rule R13 keeps
    /// them off the wire anyway. `timed_out` is the deliberate exception — the contract
    /// *does* model it, as `Err(ExecutionError::TimedOut)` inside a result that still
    /// carries both streams, which is the shape this field exists to reproduce.
    pub fn to_contract(&self) -> ExecOutcome {
        let result = if self.timed_out {
            Err(ExecutionError::TimedOut)
        } else {
            match self.exit_code {
                Some(code) => Ok(ExitStatus::Code(code)),
                // No exit code means the process was killed rather than exiting.
                None => Ok(ExitStatus::Terminated),
            }
        };
        // Redaction, not omission: §7.1 keeps `observed-denials` *detail* off the wire, and
        // the detail is the context pair, not the fact that a policy refused something. The
        // raw lines stay in this record and in the audit log; what crosses carries the
        // permissions, the object class and the target type, which is everything needed to
        // decide a next step and nothing that identifies the handset.
        let stdout = crate::host::denial::redact_denials(&self.stdout);
        let mut stderr = crate::host::denial::redact_denials(&self.stderr);
        if self.was_blocked_by_selinux() {
            let blocked = self
                .selinux_denials
                .iter()
                .filter(|d| !d.permissive)
                .count();
            let logged = self.selinux_denials.len() - blocked;
            let mut hint = format!(
                "\nselinux: {blocked} enforced denial(s) against this run (domain: {})",
                domain_class(self.context.as_deref())
            );
            if logged > 0 {
                hint.push_str(&format!(
                    "; {logged} more were logged while permissive, which is not why this failed"
                ));
            }
            hint.push_str(
                ". The raw records name labels assigned to this device, so they are withheld \
                 here and kept in the audit log on the device.",
            );
            stderr.push_str(&hint);
        }
        ExecOutcome {
            result,
            stdout: ContractExecOutput {
                bytes: stdout.into_bytes(),
                truncated: self.truncated,
            },
            stderr: ContractExecOutput {
                bytes: stderr.into_bytes(),
                truncated: self.truncated,
            },
        }
    }
}

/// Why a backend could not carry out a request.
///
/// Distinct from a non-zero exit code: this is the backend failing to run the thing at
/// all. Carries diagnostics because "it failed" is actionable for nobody.
///
/// Note what is *not* here. A timeout is not an error variant — it is
/// [`ExecRecord::timed_out`], because a killed command still returns output and an identity,
/// and the record is the only channel that can carry them. Likewise, a command that ran and
/// exited non-zero is not an error: that is the script's answer, not the backend's.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BackendError {
    /// The privileged helper could not be reached: no `su`, or the prompt was denied.
    EscalationUnavailable(String),
    /// The backend asked for privilege and did not get it.
    ///
    /// A [`RootShellBackend`](super::backend) exists to run a script as uid 0. If the
    /// identity that actually ran it is not uid 0 — Magisk configured to grant shell
    /// instead of root, a `su` that silently falls through, a policy that demotes the
    /// child — then the script ran, but not as the thing the caller asked for, and its
    /// result cannot be trusted for a privileged operation. Reporting that as a plain
    /// success with a non-zero exit code would let a silently unprivileged run look like
    /// an ordinary command failure.
    ///
    /// This is the check ADR-AND-001 §7.4 asks for: escalation is only real if it is
    /// *proved*, and the proof is the uid and domain observed inside the script.
    PrivilegeNotGranted {
        /// uid that actually ran the script, when the identity probe produced one.
        observed_uid: Option<u32>,
        /// SELinux domain that actually ran it, when the probe produced one. A uid of 0
        /// in an unprivileged domain is still not the privilege that was asked for.
        observed_context: Option<String>,
    },
    /// The backend itself broke: spawn failure, I/O error.
    Backend(String),
    /// The port declined to start this script, before the device was touched.
    ///
    /// This is the ADR-AND-001 §4.4 auto-pass being enforced on the *content* rather than
    /// on the label: `android:shell:read` is cheap because the commands under it cannot
    /// change the device, and a request labelled `read` that runs `setprop` does not belong
    /// to it. See [`commands`](super::commands).
    ///
    /// Distinct from [`BackendError::Backend`]: nothing is broken, and re-sending the same
    /// request unchanged will fail identically. The caller's options are to drop the command
    /// or to re-send it under the capability it names.
    Refused {
        /// The [`Refusal`](super::commands::Refusal)'s message, verbatim — R9's actionable
        /// text is exactly what a caller on the other side of the port needs.
        reason: String,
        /// Which rule refused. The message says what to do next; this says what *happened*,
        /// and the audit trail (§4.6.1) needs the second one: a hard-ban attempt and a
        /// mislabel look similar in prose and are opposite incidents in a log.
        kind: RefusalKind,
    },
}

/// Name the *class* of an SELinux domain, never the string it was derived from.
///
/// ADR-AND-001 §7.1 draws the privacy line here: the Gateway may learn that a command ran
/// in the shell domain rather than a privileged one — that is a policy fact, and without it
/// a refusal is unactionable — but it must not receive the raw context. The raw string is
/// not merely identifying: on the APK tier it carries MLS categories
/// (`u:r:untrusted_app:s0:c512,c768`) that encode *which app* the process is, and the
/// category set differs per install, so it is a device fingerprint as much as a policy
/// label. `SelinuxDomain::Other` keeps the type field for local use, and this function is
/// where that field stops: an unrecognised domain is reported as unrecognised.
fn domain_class(context: Option<&str>) -> &'static str {
    match context.map(SelinuxDomain::parse) {
        None => "no domain was observed",
        Some(SelinuxDomain::UntrustedApp) => "an app-sandbox domain",
        Some(SelinuxDomain::Shell) => "the shell domain",
        Some(SelinuxDomain::Magisk) => "a su/magisk domain",
        Some(SelinuxDomain::Other(_)) => "an unrecognised domain",
        Some(SelinuxDomain::Unreadable) => "an unreadable domain",
    }
}

impl BackendError {
    /// Project onto the contract's error type.
    ///
    /// This is the sanitizer at the seam. Everything the device knows goes in; only what
    /// §7.1 allows to leave the device comes out. Two things survive on purpose: the uid
    /// (a platform constant — 2000 means shell, 0 means root — not device detail) and the
    /// *class* of the SELinux domain, which is what makes a silent privilege drop
    /// explainable to a caller who cannot see the device. The raw context, the denial
    /// strings and the paths do not: they stay on [`ExecRecord`] and in
    /// [`Display`](std::fmt::Display), which are the local channels.
    pub fn to_contract(&self) -> ExecutionError {
        match self {
            BackendError::EscalationUnavailable(why) => {
                ExecutionError::BackendUnavailable(why.clone())
            }
            BackendError::PrivilegeNotGranted {
                observed_uid,
                observed_context,
            } => ExecutionError::BackendUnavailable(format!(
                "privilege was asked for but not granted: ran as uid {observed_uid:?} and {ctx} \
                 (the raw SELinux context stays on the device)",
                ctx = domain_class(observed_context.as_deref())
            )),
            BackendError::Backend(why) => ExecutionError::Rejected(why.clone()),
            // The kind is dropped here on purpose. It is an audit classification (§4.6.1),
            // and the caller across the port cannot act on it — the message already names
            // the next step. It stays in the local record.
            BackendError::Refused { reason, .. } => ExecutionError::Rejected(reason.clone()),
        }
    }
}

impl std::fmt::Display for BackendError {
    /// The local, operator-facing form.
    ///
    /// Unlike [`to_contract`](Self::to_contract) this does print the raw SELinux context —
    /// ADR-AND-001 N3 wants the real diagnostics in the log, and §7.1 only forbids sending
    /// them off the device. Do not route this string into anything that crosses the port.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BackendError::EscalationUnavailable(why) => {
                write!(f, "privilege escalation unavailable: {why}")
            }
            BackendError::PrivilegeNotGranted {
                observed_uid,
                observed_context,
            } => write!(
                f,
                "asked to run as root, ran as uid {observed_uid:?} in context \
                 {observed_context:?}: the su grant did not deliver uid 0, so this result \
                 must not be treated as a privileged one"
            ),
            BackendError::Backend(why) => write!(f, "execution backend failed: {why}"),
            BackendError::Refused { reason, .. } => {
                write!(f, "the port refused to run this: {reason}")
            }
        }
    }
}

impl std::error::Error for BackendError {}

/// The Android execution mechanism.
///
/// Three implementations are expected (ADR-AND-001 §4.2): `ShellBackend` (app uid,
/// bash, `$PREFIX`), `AppSandboxBackend` (scoped storage, **no shell**), and
/// `RootShellBackend` (`su -c` mksh plus toybox/busybox).
///
/// ADR-AND-001 §7.5 item 2: on the APK profile, *file* operations stay on `std::fs` and
/// are **not** routed through this trait. Files do not need a shell, and unifying them
/// for symmetry would be abstraction ahead of need. `AppSandboxBackend` exists to answer
/// "there is no shell here" honestly, not to become a general file API.
#[async_trait::async_trait]
pub trait ExecutionBackend: Send + Sync {
    /// Stable identifier for logs and the audit trail.
    fn name(&self) -> &'static str;

    /// The dialect this backend's shell speaks, or `None` when it has no shell. Drives
    /// tool registration (ADR-AND-001 §4.5) and the tool description.
    fn dialect(&self) -> Option<ShellDialect>;

    /// The profile this backend was built from.
    fn profile(&self) -> &HostProfile;

    /// Execute one command.
    ///
    /// Implementations must:
    /// - pass `request.script` through **stdin**, never argv;
    /// - populate `uid` and `context` with the identity that *actually* ran, so a
    ///   silent privilege drop is detectable;
    /// - run stderr through [`crate::host::denial::parse_denials`] before returning, so
    ///   callers never re-parse;
    /// - honour `request.budget.timeout`, and when it fires report it as
    ///   [`ExecRecord::timed_out`] with the partial output and the observed identity
    ///   intact — **not** as a [`BackendError`], which would discard the evidence;
    /// - honour `request.budget.output_cap` and set [`ExecRecord::truncated`].
    ///
    /// Implementations may assume the gate has already run. The gate is what calls
    /// this, and it does not call it on a refusal.
    async fn exec(&self, request: ExecRequest) -> Result<ExecRecord, BackendError>;
}

/// Adapts an Android backend to the contract's platform-neutral trait.
///
/// This is the seam that lets Android-specific code be driven by contract-level code:
/// the gate decides against [`GateView`], then hands the request to a
/// [`acowork_platform_contract::ExecutionBackend`], and neither knows the request has a
/// `cwd`. The projection loses the Android diagnostics, which is correct — they are for
/// the device's own audit trail, not for the wire.
pub struct ContractBackend<'a, B: ExecutionBackend> {
    inner: &'a B,
}

impl<'a, B: ExecutionBackend> ContractBackend<'a, B> {
    /// Wrap an Android backend.
    pub fn new(inner: &'a B) -> ContractBackend<'a, B> {
        ContractBackend { inner }
    }
}

impl<B: ExecutionBackend + Sync> acowork_platform_contract::ExecutionBackend
    for ContractBackend<'_, B>
{
    type Request = ExecRequest;
    // Boxed rather than an opaque `impl Future`: the contract trait is generic over the
    // future type precisely so a multi-threaded host can require `Send`, which Android
    // needs and a single-threaded target does not.
    type ExecuteFuture<'c>
        = Pin<Box<dyn Future<Output = ExecOutcome> + Send + 'c>>
    where
        Self: 'c;

    fn execute(&self, request: ExecRequest) -> Self::ExecuteFuture<'_> {
        Box::pin(async move {
            match self.inner.exec(request).await {
                Ok(record) => record.to_contract(),
                Err(err) => ExecOutcome::failed(err.to_contract()),
            }
        })
    }
}

/// Outcome of a session-level lock attempt.
///
/// ADR-AND-001 §7.2: no queueing and no preemption. Queueing hides the failure from the
/// model, which then resubmits; preemption interrupts someone else's half-finished write
/// sequence and leaves a state harder to recover than a deadlock. So the only two
/// outcomes are "yours" and "someone else's, here is who".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionLockOutcome {
    /// This session holds the lock.
    Acquired,
    /// Another session holds it and has not expired.
    HeldBy {
        /// The holding session. §7.2 requires naming it so the caller can decide to
        /// switch devices or contact the holder — which is exactly the information the
        /// contract's identity-free lock cannot carry.
        holder: String,
        /// Remaining TTL. Never a queue position, because there is no queue.
        retry_after: Duration,
    },
}

/// The device write lock, with holder identity.
///
/// Held by a **session**, not an agent (§7.2): debugging is a bounded activity while an
/// agent is long-lived, and an agent-held lock would let a crashed or forgetful agent
/// disable device-wide writes permanently with no way to explain why.
///
/// The implementation is an in-process serialization point — one device, one Node Agent,
/// so a distributed lock would be pure over-engineering (§7.2). The actual mutual
/// exclusion and TTL live in the contract's [`ResourceLock`]; this type adds only the
/// holder's session id.
#[derive(Debug)]
pub struct SessionWriteLock {
    inner: ResourceLock,
    holder: Mutex<Option<String>>,
}

impl SessionWriteLock {
    /// A lock with the ADR's ten-minute TTL.
    pub fn new() -> SessionWriteLock {
        SessionWriteLock::with_ttl(WRITE_LOCK_TTL)
    }

    /// A lock with a custom TTL, for tests and for ports with different write budgets.
    pub fn with_ttl(ttl: Duration) -> SessionWriteLock {
        SessionWriteLock {
            inner: ResourceLock::new(ttl),
            holder: Mutex::new(None),
        }
    }

    /// The underlying contract lock, for constructing a
    /// [`Gate`](acowork_platform_contract::Gate) caller's `LocalReadiness`.
    pub fn inner(&self) -> &ResourceLock {
        &self.inner
    }

    /// Try to take the lock for `session`. Never blocks, never queues.
    pub fn try_acquire(&self, session: &str, now: Duration) -> SessionLockOutcome {
        match self.inner.try_acquire(now) {
            LockOutcome::Acquired => {
                self.set_holder(session);
                SessionLockOutcome::Acquired
            }
            LockOutcome::Busy { retry_after, .. } => {
                // The contract lock does not know who holds it, so read the identity
                // this layer recorded. If it is missing the holder crashed between
                // acquiring and recording; say so rather than naming nobody.
                let holder = self
                    .current_holder()
                    .unwrap_or_else(|| "<expired session>".to_string());
                SessionLockOutcome::HeldBy {
                    holder,
                    retry_after,
                }
            }
        }
    }

    /// Extend the TTL while a mutating command runs (§7.2: "每条 mutating 命令执行时
    /// 自动续期").
    ///
    /// Only the holder may renew. Renewing someone else's hold would let a session
    /// extend a lock it does not own, which is preemption by another name.
    pub fn renew(&self, session: &str, now: Duration) -> SessionLockOutcome {
        if self.current_holder().as_deref() != Some(session) {
            return self.try_acquire(session, now);
        }
        // Re-acquiring from a released state is the only renewal the contract lock
        // offers, so release and retake. The window is not observable: this is an
        // in-process lock and the caller is the holder.
        self.inner.release();
        match self.inner.try_acquire(now) {
            LockOutcome::Acquired => SessionLockOutcome::Acquired,
            LockOutcome::Busy { retry_after, .. } => SessionLockOutcome::HeldBy {
                holder: self
                    .current_holder()
                    .unwrap_or_else(|| "<unknown>".to_string()),
                retry_after,
            },
        }
    }

    /// Release, if this session holds it.
    ///
    /// Expiry releases too, but never hands the lock to a waiter — §7.2: "只释放，不自动
    /// 抢占". A non-holder's release is ignored, so a late release from a session that
    /// already lost the lock to TTL expiry cannot free someone else's hold.
    pub fn release(&self, session: &str) {
        let mut holder = self.holder.lock().expect("lock poisoned");
        if holder.as_deref() == Some(session) {
            *holder = None;
            drop(holder);
            self.inner.release();
        }
    }

    /// The lock fact the gate needs, from this session's point of view.
    ///
    /// A session that already holds the lock sees [`LockState::Available`], which is what
    /// makes re-entrant read-then-write sequences work without the gate refusing the
    /// second call.
    pub fn lock_state(&self, session: &str, now: Duration) -> acowork_platform_contract::LockState {
        use acowork_platform_contract::LockState;
        if self.current_holder().as_deref() == Some(session) {
            return LockState::Available;
        }
        match self.inner.holder(now) {
            None => LockState::Available,
            Some(held_for) => LockState::Busy {
                retry_after: self.inner.ttl().saturating_sub(held_for),
            },
        }
    }

    /// Who holds the lock, if anyone.
    pub fn current_holder(&self) -> Option<String> {
        self.holder.lock().expect("lock poisoned").clone()
    }

    fn set_holder(&self, session: &str) {
        *self.holder.lock().expect("lock poisoned") = Some(session.to_string());
    }
}

impl Default for SessionWriteLock {
    fn default() -> Self {
        SessionWriteLock::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::facts::{
        AppletSet, BuildType, DeviceFacts, FsRoot, Privilege, SelinuxDomain, SelinuxState, SuProbe,
        VerityState,
    };
    use crate::host::profile::{HostProfileName, ShellPaths};
    use acowork_platform_contract::{CapabilityTable, HostDescription};

    fn rooted_profile() -> HostProfile {
        HostProfile {
            name: HostProfileName::RootShell,
            privilege: Privilege::ShellUid,
            selinux: SelinuxState::Enforcing,
            context: Some("u:r:shell:s0".to_string()),
            domain: SelinuxDomain::Shell,
            shell: Some(ShellDialect::MkSh),
            shell_executed: true,
            dialects: [ShellDialect::MkSh].into_iter().collect(),
            applets: AppletSet::parse_list("cat\nsetprop\nmount\nps\n"),
            fs_roots: vec![FsRoot {
                path: "/data/local/tmp".to_string(),
                writable: true,
                own_package: false,
            }],
            evidence: crate::host::facts::EvidenceSurface::default(),
            su: SuProbe {
                uid: Some(0),
                context: Some("u:r:magisk:s0".to_string()),
                prompt_denied: false,
                unavailable: false,
            },
            system_remountable: true,
            caps: CapabilityTable::new(
                crate::host::capability::PLATFORM,
                crate::host::capability::android_vocabulary(),
            )
            .unwrap(),
            device: DeviceFacts {
                build_type: BuildType::UserDebug,
                debuggable: true,
                secure: false,
                adb_secure: false,
                api_level: Some(34),
                abi: Some("arm64-v8a".to_string()),
                verity: VerityState::NotEnforcing,
            },
            paths: ShellPaths::default(),
        }
    }

    #[test]
    fn a_read_request_answers_the_three_gate_questions() {
        // R10: the contract never sees `script`, `cwd` or `env`. It sees these three.
        let r = ExecRequest::read("logcat -d", "s-1");
        assert_eq!(GateView::capability(&r).as_str(), "android:shell:read");
        assert_eq!(GateView::budget(&r).timeout, Some(DEFAULT_READ_TIMEOUT));
        assert_eq!(GateView::rollback_plan(&r), None);
        assert_eq!(r.android_capability(), Some(Capability::ShellRead));
    }

    #[test]
    fn a_request_outside_the_vocabulary_has_no_local_handle() {
        let mut r = ExecRequest::read("true", "s-1");
        r.capability = HostCapability::parse("android:kernel:write").unwrap();
        assert_eq!(r.android_capability(), None);
        // The gate refuses this on R5 before any backend sees it.
    }

    #[test]
    fn the_lock_is_single_flight_and_names_the_holder() {
        // ADR-AND-001 §7.2: a refusal must say who holds it, which the contract's
        // identity-free lock cannot do on its own.
        let lock = SessionWriteLock::new();
        let t0 = Duration::ZERO;
        assert_eq!(lock.try_acquire("s-1", t0), SessionLockOutcome::Acquired);
        match lock.try_acquire("s-2", Duration::from_secs(5)) {
            SessionLockOutcome::HeldBy {
                holder,
                retry_after,
            } => {
                assert_eq!(holder, "s-1", "the refusal must name the holding session");
                assert_eq!(retry_after, Duration::from_secs(595));
            }
            other => panic!("expected HeldBy, got {other:?}"),
        }
    }

    #[test]
    fn the_holder_sees_the_lock_as_available() {
        // Without this, a session that locks and then issues a second mutating command
        // would be refused by its own hold.
        let lock = SessionWriteLock::new();
        lock.try_acquire("s-1", Duration::ZERO);
        assert_eq!(
            lock.lock_state("s-1", Duration::ZERO),
            acowork_platform_contract::LockState::Available
        );
        assert!(matches!(
            lock.lock_state("s-2", Duration::ZERO),
            acowork_platform_contract::LockState::Busy { .. }
        ));
    }

    #[test]
    fn a_non_holder_cannot_release_or_renew() {
        let lock = SessionWriteLock::new();
        lock.try_acquire("s-1", Duration::ZERO);
        // A late release from a session that lost the lock must not free it.
        lock.release("s-2");
        assert_eq!(lock.current_holder().as_deref(), Some("s-1"));
        // Renewing someone else's hold is preemption by another name.
        assert!(matches!(
            lock.renew("s-2", Duration::from_secs(1)),
            SessionLockOutcome::HeldBy { .. }
        ));
        assert_eq!(lock.current_holder().as_deref(), Some("s-1"));
    }

    #[test]
    fn the_holder_can_renew() {
        let lock = SessionWriteLock::with_ttl(Duration::from_secs(10));
        lock.try_acquire("s-1", Duration::ZERO);
        assert_eq!(
            lock.renew("s-1", Duration::from_secs(5)),
            SessionLockOutcome::Acquired
        );
        assert_eq!(lock.current_holder().as_deref(), Some("s-1"));
        // The renewal moved the expiry, so the lock is still held well past the
        // original ten seconds.
        assert!(lock.inner().holder(Duration::from_secs(12)).is_some());
    }

    #[test]
    fn an_expired_hold_is_reclaimable_by_another_session() {
        let lock = SessionWriteLock::with_ttl(Duration::from_secs(600));
        lock.try_acquire("s-1", Duration::ZERO);
        let later = Duration::from_secs(601);
        assert_eq!(
            lock.lock_state("s-2", later),
            acowork_platform_contract::LockState::Available
        );
        assert_eq!(lock.try_acquire("s-2", later), SessionLockOutcome::Acquired);
        assert_eq!(lock.current_holder().as_deref(), Some("s-2"));
    }

    #[test]
    fn release_by_the_holder_frees_the_device() {
        let lock = SessionWriteLock::new();
        lock.try_acquire("s-1", Duration::ZERO);
        lock.release("s-1");
        assert_eq!(lock.current_holder(), None);
        assert_eq!(
            lock.try_acquire("s-2", Duration::from_secs(1)),
            SessionLockOutcome::Acquired
        );
    }

    #[test]
    fn release_is_idempotent() {
        let lock = SessionWriteLock::new();
        lock.release("nobody");
        lock.release("nobody");
        assert_eq!(lock.current_holder(), None);
    }

    #[test]
    fn an_exec_record_projects_onto_the_contract_outcome() {
        let record = ExecRecord {
            stdout: "ok\n".to_string(),
            stderr: "".to_string(),
            exit_code: Some(0),
            selinux_denials: Vec::new(),
            uid: Some(0),
            context: Some("u:r:magisk:s0".to_string()),
            duration_ms: 12,
            truncated: false,
            timed_out: false,
        };
        let outcome = record.to_contract();
        assert!(outcome.succeeded());
        assert_eq!(outcome.stdout.as_text(), "ok\n");

        // R13: the projection drops the uid and context. They stay on the device.
        let json = serde_json::to_string(&outcome).unwrap();
        assert!(
            !json.contains("magisk"),
            "the SELinux context must not reach the wire"
        );
        assert!(!json.contains("\"uid\""), "the uid must not reach the wire");
    }

    #[test]
    fn a_killed_process_projects_as_terminated_not_as_a_code() {
        // `ExitStatus::Terminated` is the platform-neutral spelling of "killed by a
        // signal or a timeout". There is deliberately no `Signal` variant, because
        // signals are a Unix concept and the contract must not assume one.
        let record = ExecRecord {
            stdout: String::new(),
            stderr: String::new(),
            exit_code: None,
            selinux_denials: Vec::new(),
            uid: None,
            context: None,
            duration_ms: 30_000,
            truncated: false,
            timed_out: false,
        };
        assert_eq!(record.to_contract().result, Ok(ExitStatus::Terminated));
        assert!(!record.to_contract().succeeded());
    }

    #[test]
    fn backend_errors_project_onto_contract_errors() {
        assert!(matches!(
            BackendError::EscalationUnavailable("su: prompt denied".to_string()).to_contract(),
            ExecutionError::BackendUnavailable(_)
        ));
        assert!(matches!(
            BackendError::Backend("spawn failed".to_string()).to_contract(),
            ExecutionError::Rejected(_)
        ));
    }

    #[test]
    fn a_silent_privilege_drop_projects_as_unavailable_and_says_what_it_observed() {
        // The point of the variant is that the *observed* identity survives the projection:
        // "escalation did not happen" is only actionable if the caller can see what did.
        // What survives is the class of the identity, not the string — §7.1.
        let err = BackendError::PrivilegeNotGranted {
            observed_uid: Some(2000),
            observed_context: Some("u:r:shell:s0".to_string()),
        };
        match err.to_contract() {
            ExecutionError::BackendUnavailable(why) => {
                assert!(why.contains("2000"), "{why}");
                assert!(why.contains("the shell domain"), "{why}");
                assert!(!why.contains("u:r:"), "raw context crossed the seam: {why}");
            }
            other => panic!("expected BackendUnavailable, got {other:?}"),
        }
        assert!(err.to_string().contains("asked to run as root"), "{err}");
        // The local channel keeps the real context — N3 wants it in the log.
        assert!(err.to_string().contains("u:r:shell:s0"), "{err}");
    }

    #[test]
    fn an_mls_category_never_survives_the_contract_projection() {
        // The APK-tier shape of the leak. `u:r:untrusted_app:s0:c166,c232` identifies the
        // install, not just the policy, so a projection that round-trips the "domain class"
        // by lowercasing or truncating the string would still fingerprint the device.
        let err = BackendError::PrivilegeNotGranted {
            observed_uid: Some(10166),
            observed_context: Some("u:r:untrusted_app:s0:c166,c232".to_string()),
        };
        let projected = err.to_contract().to_string();
        for forbidden in ["u:r:", "s0:c", "c166", "c232", "untrusted_app"] {
            assert!(
                !projected.contains(forbidden),
                "projection leaked `{forbidden}`: {projected}"
            );
        }
        assert!(projected.contains("app-sandbox"), "{projected}");
    }

    #[test]
    fn a_missing_or_unreadable_domain_is_stated_as_such() {
        // "no domain was observed" and "an unreadable domain" are different facts from a
        // recognised one, and neither may be rendered as the empty string — a projection
        // that reads "ran as uid 0 and " would let a failed identity probe look like a
        // privileged run.
        let cases = [
            (None, "no domain was observed"),
            (Some(""), "an unreadable domain"),
            (Some("\0"), "an unreadable domain"),
            (Some("u:r:init:s0"), "an unrecognised domain"),
        ];
        for (context, expected) in cases {
            let err = BackendError::PrivilegeNotGranted {
                observed_uid: None,
                observed_context: context.map(str::to_string),
            };
            let projected = err.to_contract().to_string();
            assert!(projected.contains(expected), "{context:?} -> {projected}");
        }
    }

    #[test]
    fn a_timeout_is_a_record_field_not_an_error() {
        // Both halves of the decision: the record still carries the evidence, and the
        // contract projection still says TimedOut.
        let record = ExecRecord {
            stdout: "partial".into(),
            stderr: String::new(),
            exit_code: None,
            selinux_denials: Vec::new(),
            uid: Some(0),
            context: Some("u:r:magisk:s0".into()),
            duration_ms: 30_000,
            truncated: false,
            timed_out: true,
        };
        let outcome = record.to_contract();
        assert_eq!(outcome.result, Err(ExecutionError::TimedOut));
        assert!(!outcome.succeeded());
        assert_eq!(
            String::from_utf8_lossy(&outcome.stdout.bytes),
            "partial",
            "a timeout must not discard the output produced before it"
        );
        assert_eq!(record.uid, Some(0), "nor the identity that ran it");
    }

    #[test]
    fn a_failed_contract_outcome_carries_an_actionable_message() {
        // R9, end to end: an Android backend error becomes a message a model can act on.
        let outcome = ExecOutcome::failed(
            BackendError::EscalationUnavailable("the superuser prompt was declined".to_string())
                .to_contract(),
        );
        assert!(!outcome.succeeded());
        assert!(
            outcome
                .stderr
                .as_text()
                .contains("superuser prompt was declined")
        );
    }

    /// A backend that records what it was asked to run.
    struct RecordingBackend {
        profile: HostProfile,
        calls: Mutex<Vec<String>>,
    }

    #[async_trait::async_trait]
    impl ExecutionBackend for RecordingBackend {
        fn name(&self) -> &'static str {
            "recording"
        }
        fn dialect(&self) -> Option<ShellDialect> {
            Some(ShellDialect::MkSh)
        }
        fn profile(&self) -> &HostProfile {
            &self.profile
        }
        async fn exec(&self, request: ExecRequest) -> Result<ExecRecord, BackendError> {
            self.calls.lock().unwrap().push(request.script.clone());
            Ok(ExecRecord {
                stdout: "done\n".to_string(),
                stderr: String::new(),
                exit_code: Some(0),
                selinux_denials: Vec::new(),
                uid: Some(2000),
                context: Some("u:r:shell:s0".to_string()),
                duration_ms: 1,
                truncated: false,
                timed_out: false,
            })
        }
    }

    #[tokio::test]
    async fn the_contract_adapter_drives_an_android_backend() {
        // The seam that lets contract-level code drive Android-specific mechanism
        // without either knowing the other's request shape.
        use acowork_platform_contract::ExecutionBackend as ContractBackendTrait;

        let backend = RecordingBackend {
            profile: rooted_profile(),
            calls: Mutex::new(Vec::new()),
        };
        let adapter = ContractBackend::new(&backend);
        let outcome = adapter
            .execute(ExecRequest::read("getprop ro.build.type", "s-1"))
            .await;
        assert!(outcome.succeeded());
        assert_eq!(outcome.stdout.as_text(), "done\n");
        assert_eq!(backend.calls.lock().unwrap()[0], "getprop ro.build.type");
    }

    #[tokio::test]
    async fn the_adapter_projects_a_backend_error_into_an_outcome() {
        use acowork_platform_contract::ExecutionBackend as ContractBackendTrait;

        struct FailingBackend {
            profile: HostProfile,
        }
        #[async_trait::async_trait]
        impl ExecutionBackend for FailingBackend {
            fn name(&self) -> &'static str {
                "failing"
            }
            fn dialect(&self) -> Option<ShellDialect> {
                None
            }
            fn profile(&self) -> &HostProfile {
                &self.profile
            }
            async fn exec(&self, _request: ExecRequest) -> Result<ExecRecord, BackendError> {
                Err(BackendError::EscalationUnavailable(
                    "no su binary".to_string(),
                ))
            }
        }

        let backend = FailingBackend {
            profile: rooted_profile(),
        };
        let adapter = ContractBackend::new(&backend);
        let outcome = adapter.execute(ExecRequest::read("id", "s-1")).await;
        assert!(!outcome.succeeded());
        assert!(outcome.stderr.as_text().contains("no su binary"));
    }

    #[test]
    fn the_profile_satisfies_the_contract_host_description() {
        // The whole point of the rewiring: an Android profile *is* a contract host.
        let p = rooted_profile();
        assert_eq!(p.platform(), "android");
        assert_eq!(p.profile_name(), "root-shell");
        assert_eq!(
            p.privilege(),
            Some(acowork_platform_contract::PrivilegeLevel::Elevated)
        );
        assert_eq!(
            p.escalation(),
            acowork_platform_contract::EscalationModel::PerCallHelper
        );
        assert!(p.is_r3_conformant(), "a shell-uid node conforms to R3");
    }

    #[test]
    fn a_root_node_violates_r3() {
        // ADR-AND-001 §4.1 expressed as a rule the gate enforces rather than a sentence
        // in a document.
        let mut p = rooted_profile();
        p.privilege = Privilege::Root;
        assert!(!p.runtime_is_unprivileged());
        assert!(!p.is_r3_conformant());
        assert_eq!(
            p.privilege(),
            Some(acowork_platform_contract::PrivilegeLevel::Unrestricted)
        );
    }

    #[test]
    fn a_device_with_no_working_su_reports_no_escalation() {
        let mut p = rooted_profile();
        p.su = SuProbe {
            uid: None,
            context: None,
            prompt_denied: true,
            unavailable: false,
        };
        p.privilege = Privilege::AppUid;
        assert_eq!(
            p.escalation(),
            acowork_platform_contract::EscalationModel::None
        );
    }

    #[test]
    fn the_reported_summary_carries_no_device_identifiers() {
        // R13 / ADR-AND-001 §7.1. The profile *has* a model, a fingerprint and a
        // SELinux context; the summary must not.
        let p = rooted_profile();
        let json = serde_json::to_string(&p.summary()).unwrap();
        for forbidden in ["arm64-v8a", "u:r:shell", "u:r:magisk", "/data/local/tmp"] {
            assert!(
                !json.contains(forbidden),
                "`{forbidden}` leaked into the summary: {json}"
            );
        }
        // But the capability IDs are there, because those are the point of reporting.
        assert!(json.contains("android"), "{json}");
    }
}
