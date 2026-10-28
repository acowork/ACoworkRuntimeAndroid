//! The `ExecutionBackend` contract and the authorization gate in front of it.
//!
//! # Dependency direction
//!
//! ADR-AND-001 §4.2: three backend implementations depend on this contract; the
//! engine depends on no concrete backend. That direction is what keeps the
//! upstream回流 path clean — what gets added is a trait implementation and a
//! capability declaration, not a fork of the loop.
//!
//! This module deliberately has **no dependency on the engine, on
//! `acowork-runtime`, or on `acowork-core`**. Upstream design doc 30 §9 places
//! `ExecutionBackend` "在引擎内部" and EIP "在引擎外部", and §5/§9 disagree about
//! whether the Android engine is a crate compiled into `acowork-runtime` or a
//! consumer of a published Host crate (blocker **B3**). Staying dependency-free
//! makes this module valid under either ruling, so the ambiguity does not have to
//! be resolved before the probe and the backends can be built and tested.
//!
//! # The authorization gate: two authorities, one composition point
//!
//! ADR-AND-001 §7.4 rules `放行 = 设备本地开关 ∧ 归属门控`. Upstream ADR-087 D5
//! rules that the enforcement point is the Gateway reverse proxy and that
//! "Runtime 不引入 owner 概念（它拿不到也不该拿归属真相）", with D1 adding that
//! owner data never enters the MQTT proto because "Node 不感知用户". Read
//! literally the two are incompatible, and ADR-AND-001 §7.1 compounds it by
//! forbidding the Gateway from making any allow decision.
//!
//! The resolution implemented here is a decomposition rather than a compromise —
//! the two documents are answering different questions:
//!
//! | Question | Authority | Why there |
//! |---|---|---|
//! | *Who* may ask for a write-tier action? | Gateway → [`AttributionVerdict`] | ADR-087 D1/D5: owner truth lives in `node_owners.json` and is enforced at the reverse proxy. The device cannot and must not reconstruct it. |
//! | *What* is possible on this device, and is it safe right now? | Device → [`HostProfile`] + `dangerous-mode` + [`DeviceWriteLock`] | Only the device knows the probed facts, the local session switch, and whether another session is mid-write. |
//!
//! The device receives the attribution answer as an **opaque verdict**, never as
//! an identity. That satisfies ADR-087's "Node 不感知用户" (a boolean is not a
//! user) while preserving ADR-AND-001's requirement that the final conjunction is
//! evaluated on the device, where the probed facts are. Neither authority
//! duplicates the other, so there is no second source of truth to drift.
//!
//! This does revise ADR-AND-001 §7.1's blanket "Gateway 不做门控判定": the Gateway
//! makes an *attribution* judgment, not a *capability* judgment. Recorded as
//! blocker **B1** with this proposal attached.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::host::capability::{Capability, explain_gaps};
use crate::host::denial::SelinuxDenial;
use crate::host::facts::ShellDialect;
use crate::host::profile::HostProfile;

/// DeviceWriteLock TTL (ADR-AND-001 §7.2).
pub const WRITE_LOCK_TTL: Duration = Duration::from_secs(600);

/// Opaque proof that a human approved one specific action this session.
///
/// Deliberately carries no payload the backend interprets: the gate only checks
/// presence, and the approval subsystem owns everything else. Keeping it opaque
/// is what stops a backend from inventing its own approval semantics.
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
/// Mirrors the narrow interface in ADR-AND-001 §4.7 field for field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecRequest {
    /// The script body. **Passed via stdin, never in argv** — argv is
    /// world-readable through `ps`, which would leak sensitive arguments to any
    /// other process on the device (ADR-AND-001 §4.7).
    pub script: String,
    /// Working directory for the command, when it must not inherit the Runtime's.
    pub cwd: Option<PathBuf>,
    /// Extra environment variables. Merged over the backend's base environment.
    pub env: BTreeMap<String, String>,
    /// Kill the command after this long; reported as [`BackendError::TimedOut`].
    pub timeout: Duration,
    /// The capability this command needs. Used for gating and for the audit
    /// record; a backend must refuse a request whose capability it cannot honour.
    pub capability: Capability,
    /// Present when a human approved this action.
    pub approval_token: Option<ApprovalToken>,
    /// The session asking, for DeviceWriteLock accounting and the audit trail.
    pub session_id: String,
}

impl ExecRequest {
    /// A read-tier request, which needs no approval and takes no lock.
    pub fn read(script: impl Into<String>, session_id: impl Into<String>) -> ExecRequest {
        ExecRequest {
            script: script.into(),
            cwd: None,
            env: BTreeMap::new(),
            timeout: Duration::from_secs(30),
            capability: Capability::ShellRead,
            approval_token: None,
            session_id: session_id.into(),
        }
    }
}

/// What actually happened.
///
/// ADR-AND-001 §4.7 plus the N3 requirement that diagnostics travel with the
/// error: `uid` and `context` let a backend prove which identity really ran the
/// command, which is the only way to catch "the helper silently dropped
/// privilege".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecOutput {
    /// Captured standard output.
    pub stdout: String,
    /// Captured standard error. Also the source of `selinux_denials`.
    pub stderr: String,
    /// `None` when the process was killed rather than exiting (timeout/signal).
    pub exit_code: Option<i32>,
    /// Structurally extracted from stderr, so callers never re-parse.
    pub selinux_denials: Vec<SelinuxDenial>,
    /// The uid that actually ran the command.
    pub uid: Option<u32>,
    /// The SELinux context that actually ran the command.
    pub context: Option<String>,
    /// Wall-clock execution time, for the audit record.
    pub duration_ms: u64,
}

impl ExecOutput {
    /// True when the command completed with exit status 0.
    pub fn succeeded(&self) -> bool {
        self.exit_code == Some(0)
    }

    /// True when SELinux actually blocked something (`permissive=1` records are
    /// logged-but-allowed and do not count).
    pub fn was_blocked_by_selinux(&self) -> bool {
        self.selinux_denials.iter().any(|d| !d.permissive)
    }
}

/// Why a backend could not carry out a request.
///
/// Carries the diagnostics N3 requires, because "it failed" is not actionable —
/// for a model or for a human.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BackendError {
    /// The request was refused before execution.
    Unauthorized(Denial),
    /// The privileged helper could not be reached (no `su`, prompt denied).
    EscalationUnavailable(String),
    /// The command ran but was killed by the timeout.
    /// The command ran past its timeout and was killed.
    TimedOut {
        /// How long the command ran before it was killed.
        after: Duration,
    },
    /// The backend itself broke (spawn failure, I/O error).
    Backend(String),
}

impl std::fmt::Display for BackendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BackendError::Unauthorized(d) => write!(f, "{}", d.message()),
            BackendError::EscalationUnavailable(why) => {
                write!(f, "privilege escalation unavailable: {why}")
            }
            BackendError::TimedOut { after } => {
                write!(f, "command timed out after {}ms", after.as_millis())
            }
            BackendError::Backend(why) => write!(f, "execution backend failed: {why}"),
        }
    }
}

impl std::error::Error for BackendError {}

/// The execution contract.
///
/// Three implementations are expected (ADR-AND-001 §4.2): `TermuxBackend`
/// (app uid, bash, `$PREFIX`), `AppSandboxBackend` (scoped storage, **no shell**),
/// and `RootShellBackend` (`su -c` mksh plus toybox/busybox).
///
/// Note ADR-AND-001 §7.5 item 2: on the APK profile, *file* operations stay on
/// `std::fs` and are **not** routed through this trait. Files do not need a shell,
/// and unifying them for the sake of symmetry would be abstraction ahead of need.
/// So `AppSandboxBackend` exists to answer "there is no shell here" honestly, not
/// to become a general file API.
#[async_trait::async_trait]
pub trait ExecutionBackend: Send + Sync {
    /// Stable identifier for logs and the audit trail.
    fn name(&self) -> &'static str;

    /// The dialect this backend's shell speaks, or `None` when it has no shell.
    /// Drives tool registration (ADR-AND-001 §4.5) and the tool description.
    fn dialect(&self) -> Option<ShellDialect>;

    /// The profile this backend was built from.
    fn profile(&self) -> &HostProfile;

    /// Execute one command.
    ///
    /// Implementations must:
    /// - pass `request.script` through **stdin**, never argv;
    /// - populate `uid` and `context` with the identity that *actually* ran, so a
    ///   silent privilege drop is detectable;
    /// - run stderr through [`crate::host::denial::parse_denials`] before
    ///   returning, so callers never re-parse;
    /// - honour `request.timeout` and report it as [`BackendError::TimedOut`].
    async fn exec(&self, request: ExecRequest) -> Result<ExecOutput, BackendError>;
}

// ── Attribution: the Gateway's half of the conjunction ─────────────────────

/// The Gateway's answer to "may this requester ask for a write-tier action?".
///
/// Opaque by design: it carries no user id, no owner name and no role. ADR-087
/// D1/D5 keep owner truth in the Gateway and out of the data plane, and a verdict
/// is the smallest thing that preserves that while still letting the device
/// complete its own conjunction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttributionVerdict {
    /// The requester satisfied the Gateway's owner/admin gate.
    Granted,
    /// The node has no owner. ADR-AND-001 §7.4: `android:fs:system` and
    /// `android:selinux:permissive` are **never** opened on an unowned node, even
    /// if the device is rooted and `dangerous-mode` is on.
    UnownedNode,
    /// The Gateway refused this requester.
    Denied,
    /// No verdict reached the device. Fail closed — an absent answer is not a
    /// permissive one.
    Absent,
}

impl AttributionVerdict {
    /// True only for [`AttributionVerdict::Granted`]. Every other variant refuses.
    pub fn granted(&self) -> bool {
        matches!(self, AttributionVerdict::Granted)
    }
}

/// Which ADR-087 tier a capability maps onto.
///
/// **Provisional.** ADR-AND-001 §7.4 only rules on `android:fs:system` and
/// `android:selinux:permissive`, and the gate below implements exactly that. But
/// ADR-087 D4 puts "安装/卸载" under `manage = owner ∨ admin`, and
/// `android:shell:write` covers `pm install` — so whether that capability also
/// needs attribution is an open upstream question, recorded as **B11**.
///
/// It is exposed as data rather than baked into the gate so that the question can
/// be answered by changing one match arm, and so the provisional mapping is
/// visible and testable instead of implicit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttributionTier {
    /// No attribution needed; the read tier is whitelist auto-approved.
    None,
    /// ADR-087 `use = owner ∨ guest ∨ admin`.
    Use,
    /// ADR-087 `manage = owner ∨ admin`.
    Manage,
}

impl Capability {
    /// The provisional ADR-087 tier for this capability. See [`AttributionTier`].
    pub fn attribution_tier(&self) -> AttributionTier {
        match self {
            Capability::ShellRead => AttributionTier::None,
            // Covers `pm install` / `am start`, which ADR-087 D4 reads as manage.
            Capability::ShellWrite => AttributionTier::Manage,
            Capability::FsOutsideApp => AttributionTier::Use,
            Capability::FsSystem => AttributionTier::Manage,
            Capability::SelinuxPermissive => AttributionTier::Manage,
        }
    }
}

// ── DeviceWriteLock: the device's serialization point ──────────────────────

/// Outcome of a lock attempt.
///
/// ADR-AND-001 §7.2: no queueing and no preemption. Queueing hides the failure
/// from the model, which then resubmits; preemption interrupts someone else's
/// half-finished write sequence and leaves a state harder to recover than a
/// deadlock. So the only two outcomes are "yours" and "someone else's, here is
/// who".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LockOutcome {
    /// This session holds the lock.
    Acquired,
    /// Held by another session and not expired. The error must name the holder —
    /// §7.2 requires "立即返回明确错误（含持有者标识）" so that the model or the
    /// human can decide to switch devices or contact the holder.
    /// Another session holds it. Names the holder, per ADR-AND-001 §7.2.
    HeldBy {
        /// The session that holds it. §7.2 requires naming the holder so the
        /// caller can decide to switch devices or contact them.
        holder: String,
        /// Remaining TTL. Never a queue position — there is no queue.
        expires_in: Duration,
    },
}

/// The per-device write lock.
///
/// Held by a **session**, not an agent (§7.2): debugging is a bounded activity
/// while an agent is a long-lived entity, and an agent-held lock would let a
/// crashed or forgetful agent disable device-wide writes permanently with no way
/// to explain why.
///
/// The implementation belongs in the Node Agent as an in-process serialization
/// point — one device, one Node Agent, so a distributed lock would be pure
/// over-engineering (§7.2). The trait exists so the gate can be tested against a
/// fake and so the Node-side implementation stays swappable.
pub trait DeviceWriteLock: Send + Sync {
    /// Try to take the lock for `session`. Never blocks, never queues.
    fn try_acquire(&self, session: &str) -> LockOutcome;

    /// Extend the TTL while a mutating command runs (§7.2: "每条 mutating 命令
    /// 执行时自动续期").
    fn renew(&self, session: &str) -> LockOutcome;

    /// Release, if this session holds it. Expiry releases too, but never hands
    /// the lock to a waiter — §7.2: "只释放，不自动抢占".
    fn release(&self, session: &str);
}

/// Device-local readiness: everything the device alone can decide.
#[derive(Debug, Clone)]
pub struct LocalReadiness {
    /// The `--dangerous-mode` CLI flag (ADR-AND-001 §7.3). Per-session, never
    /// persisted, and there is deliberately no APK UI switch: the APK profile has
    /// neither a shell nor `su`, so `android:fs:system` is unreachable there and a
    /// toggle would only mislead.
    pub dangerous_mode: bool,
    /// Result of the lock attempt for this session.
    pub lock: LockOutcome,
}

/// Everything the gate needs, from both authorities.
#[derive(Debug, Clone)]
pub struct AuthorizationContext {
    /// The Gateway's half.
    pub attribution: AttributionVerdict,
    /// The device's half.
    pub local: LocalReadiness,
}

/// Why a request was refused.
///
/// Every variant names the missing condition, because ADR-AND-001 N3 requires
/// diagnostics to travel with the error and android-host-probe.md §4 requires the
/// feedback to be actionable rather than a bare "denied".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Denial {
    /// The probed facts do not support this capability on this host.
    /// The probed facts do not support this capability on this host.
    NotDeclared {
        /// The capability that is not a fact about this host.
        capability: Capability,
        /// Which probed fact is missing, in words a model can act on.
        reason: String,
    },
    /// A human approval is required and none was presented.
    /// A human approval is required and none was presented.
    ApprovalMissing {
        /// The capability that needs a human approval.
        capability: Capability,
    },
    /// `--dangerous-mode` is off.
    /// The session was not started with `--dangerous-mode`.
    DangerousModeOff {
        /// The system-tier capability that needs `--dangerous-mode`.
        capability: Capability,
    },
    /// Another session holds the device write lock.
    /// Another session holds the device write lock.
    LockHeldBy {
        /// The session currently holding the device write lock.
        holder: String,
        /// Remaining TTL on that hold.
        expires_in: Duration,
    },
    /// The Gateway did not grant attribution.
    AttributionRefused {
        /// The capability that was not authorised.
        capability: Capability,
        /// The Gateway's answer, so the caller can tell unowned from refused.
        verdict: AttributionVerdict,
    },
}

impl Denial {
    /// The sentence returned to the caller.
    pub fn message(&self) -> String {
        match self {
            Denial::NotDeclared { capability, reason } => format!(
                "`{capability}` is not available on this host: {reason}. \
                 This is a property of the device, not of the request — \
                 do not retry on this node."
            ),
            Denial::ApprovalMissing { capability } => format!(
                "`{capability}` requires explicit human approval and none was \
                 presented. Request approval; do not work around it."
            ),
            Denial::DangerousModeOff { capability } => format!(
                "`{capability}` needs the session started with \
                 `--dangerous-mode`. It is off, and it is never persisted — \
                 the session has to be restarted with the flag."
            ),
            Denial::LockHeldBy { holder, expires_in } => format!(
                "Another session ({holder}) holds this device's write lock for \
                 another {}s. Requests are not queued and the lock is not \
                 preempted; switch devices or contact the holder.",
                expires_in.as_secs()
            ),
            Denial::AttributionRefused {
                capability,
                verdict,
            } => {
                let why = match verdict {
                    AttributionVerdict::UnownedNode => {
                        "this node has no registered owner, and an unowned node \
                         never exposes system-partition or SELinux writes"
                    }
                    AttributionVerdict::Denied => {
                        "the Gateway refused this requester under the owner gate"
                    }
                    AttributionVerdict::Absent => {
                        "no attribution verdict reached this device, and the gate \
                         fails closed"
                    }
                    AttributionVerdict::Granted => "granted (internal inconsistency)",
                };
                // N3 requires the diagnostic to be actionable. Nothing the model
                // can do changes an attribution verdict, so the actionable part is
                // exactly that: stop, and say who could unblock it. Omitting this
                // is what turns a policy refusal into a retry loop.
                format!(
                    "`{capability}` was not authorised: {why}. Do not retry — \
                     this needs the node owner or an administrator, not a \
                     different command."
                )
            }
        }
    }
}

/// A granted request, with the conditions that were checked.
///
/// Returned rather than a bare `Ok(())` so the audit record (ADR-AND-001 §4.6
/// item 1) can be written from the grant itself, without re-deriving anything.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    /// The capability that was granted, for the audit record.
    pub capability: Capability,
    /// True when the device write lock must be held for the duration.
    pub holds_write_lock: bool,
    /// True when this grant depended on a Gateway attribution verdict.
    pub attribution_checked: bool,
}

/// Decide whether a request may proceed.
///
/// The single composition point for both authorities. Order matters and is
/// cheapest-first, so the most common refusal (capability not declared on this
/// host) short-circuits before any lock or verdict is consulted:
///
/// 1. capability declared by the profile — a fact about the device
/// 2. approval present, if the capability needs one
/// 3. write lock held, if the capability mutates device-global state
/// 4. `dangerous-mode` on, if the capability is system-tier
/// 5. attribution granted, if the capability is system-tier
///
/// Steps 4 and 5 are the §7.4 conjunction, and both default to refusal.
pub fn authorize(
    request: &ExecRequest,
    profile: &HostProfile,
    ctx: &AuthorizationContext,
) -> Result<Grant, Denial> {
    let cap = request.capability;

    // 1. Is this capability a fact about this device?
    if !profile.caps.contains(cap) {
        let reason = explain_gaps(profile)
            .into_iter()
            .find(|gap| gap.capability == cap)
            .map(|gap| gap.reason)
            .unwrap_or_else(|| {
                // Reaching this arm means the declared set and the derivation
                // disagree: `assemble` always sets `caps = derive(facts)`, so the
                // only way to get here is a profile that outlived the facts it was
                // built from (a `setenforce`, a remount, or a Magisk policy change
                // since startup — the re-probe events of android-host-probe.md §6).
                // Say so, and say what to do, rather than emitting a shrug.
                "the host profile is stale — the probed facts now support this \
                 capability but it was not declared at startup. Re-probe the host."
                    .to_string()
            });
        return Err(Denial::NotDeclared {
            capability: cap,
            reason,
        });
    }

    // 2. Human approval.
    if cap.requires_approval() && request.approval_token.is_none() {
        return Err(Denial::ApprovalMissing { capability: cap });
    }

    // 3. Device write lock — mutating commands only (§4.6 item 5: read 类不锁).
    let holds_write_lock = cap.is_mutating();
    if holds_write_lock && let LockOutcome::HeldBy { holder, expires_in } = &ctx.local.lock {
        return Err(Denial::LockHeldBy {
            holder: holder.clone(),
            expires_in: *expires_in,
        });
    }

    // 4 + 5. The §7.4 conjunction, for the system tier only.
    let attribution_checked = cap.requires_dangerous_mode();
    if attribution_checked {
        if !ctx.local.dangerous_mode {
            return Err(Denial::DangerousModeOff { capability: cap });
        }
        if !ctx.attribution.granted() {
            return Err(Denial::AttributionRefused {
                capability: cap,
                verdict: ctx.attribution,
            });
        }
    }

    Ok(Grant {
        capability: cap,
        holds_write_lock,
        attribution_checked,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::capability::{CapabilitySet, derive_capabilities};
    use crate::host::facts::{
        AppletSet, BuildType, DeviceFacts, FsRoot, Privilege, SelinuxDomain, SelinuxState, SuProbe,
        VerityState,
    };
    use crate::host::profile::HostProfileName;

    fn root_profile() -> HostProfile {
        let mut profile = HostProfile {
            name: HostProfileName::RootShell,
            privilege: Privilege::AppUid,
            selinux: SelinuxState::Enforcing,
            context: None,
            domain: SelinuxDomain::UntrustedApp,
            shell: Some(ShellDialect::MkSh),
            dialects: [ShellDialect::MkSh].into_iter().collect(),
            applets: AppletSet::new(),
            fs_roots: vec![FsRoot {
                path: "/data/local/tmp".to_string(),
                writable: true,
                own_package: false,
            }],
            su: SuProbe {
                uid: Some(0),
                context: Some("u:r:magisk:s0".to_string()),
                prompt_denied: false,
                unavailable: false,
            },
            system_remountable: true,
            caps: CapabilitySet::new(),
            device: DeviceFacts {
                build_type: BuildType::UserDebug,
                debuggable: true,
                secure: false,
                adb_secure: false,
                api_level: Some(34),
                abi: None,
                verity: VerityState::NotEnforcing,
            },
        };
        profile.caps = derive_capabilities(&profile);
        profile
    }

    fn ctx(dangerous: bool, attribution: AttributionVerdict) -> AuthorizationContext {
        AuthorizationContext {
            attribution,
            local: LocalReadiness {
                dangerous_mode: dangerous,
                lock: LockOutcome::Acquired,
            },
        }
    }

    fn req(cap: Capability, approved: bool) -> ExecRequest {
        ExecRequest {
            script: "getprop ro.build.type".to_string(),
            cwd: None,
            env: BTreeMap::new(),
            timeout: Duration::from_secs(30),
            capability: cap,
            approval_token: approved.then(|| ApprovalToken::new("tok")),
            session_id: "s-1".to_string(),
        }
    }

    #[test]
    fn read_tier_needs_no_approval_lock_or_attribution() {
        let grant = authorize(
            &req(Capability::ShellRead, false),
            &root_profile(),
            &ctx(false, AttributionVerdict::Absent),
        )
        .unwrap();
        assert_eq!(grant.capability, Capability::ShellRead);
        assert!(!grant.holds_write_lock);
        assert!(!grant.attribution_checked);
    }

    #[test]
    fn undeclared_capability_is_refused_with_the_missing_fact_named() {
        // A host with no shell: ShellRead is genuinely not derivable, so the
        // refusal has to name that fact rather than just say "denied".
        let mut profile = root_profile();
        profile.shell = None;
        profile.dialects.clear();
        profile.caps = derive_capabilities(&profile);

        let err = authorize(
            &req(Capability::ShellRead, false),
            &profile,
            &ctx(true, AttributionVerdict::Granted),
        )
        .unwrap_err();
        match err {
            Denial::NotDeclared { capability, reason } => {
                assert_eq!(capability, Capability::ShellRead);
                assert!(
                    reason.contains("shell"),
                    "reason should name the missing fact: {reason}"
                );
            }
            other => panic!("expected NotDeclared, got {other:?}"),
        }
    }

    #[test]
    fn a_stale_profile_says_it_is_stale_instead_of_shrugging() {
        // Declared caps emptied behind the derivation's back: the shape a profile
        // takes when the device changed underneath it since startup.
        let mut profile = root_profile();
        profile.caps = CapabilitySet::new();

        let err = authorize(
            &req(Capability::ShellRead, false),
            &profile,
            &ctx(true, AttributionVerdict::Granted),
        )
        .unwrap_err();
        match err {
            Denial::NotDeclared { reason, .. } => {
                assert!(reason.contains("stale"), "{reason}");
                assert!(reason.contains("Re-probe"), "{reason}");
            }
            other => panic!("expected NotDeclared, got {other:?}"),
        }
    }

    #[test]
    fn write_tier_requires_approval() {
        let err = authorize(
            &req(Capability::ShellWrite, false),
            &root_profile(),
            &ctx(false, AttributionVerdict::Absent),
        )
        .unwrap_err();
        assert_eq!(
            err,
            Denial::ApprovalMissing {
                capability: Capability::ShellWrite
            }
        );
    }

    #[test]
    fn write_tier_with_approval_needs_no_attribution_per_the_adr() {
        // ADR-AND-001 §7.4 gates only fs:system and selinux:permissive on owner.
        let grant = authorize(
            &req(Capability::ShellWrite, true),
            &root_profile(),
            &ctx(false, AttributionVerdict::Absent),
        )
        .unwrap();
        assert!(grant.holds_write_lock);
        assert!(
            !grant.attribution_checked,
            "shell:write is not attribution-gated by §7.4 as written"
        );
    }

    #[test]
    fn mutating_command_is_refused_while_another_session_holds_the_lock() {
        let mut context = ctx(true, AttributionVerdict::Granted);
        context.local.lock = LockOutcome::HeldBy {
            holder: "s-other".to_string(),
            expires_in: Duration::from_secs(42),
        };
        let err = authorize(
            &req(Capability::ShellWrite, true),
            &root_profile(),
            &context,
        )
        .unwrap_err();
        match err {
            Denial::LockHeldBy { holder, expires_in } => {
                assert_eq!(holder, "s-other");
                assert_eq!(expires_in, Duration::from_secs(42));
            }
            other => panic!("expected LockHeldBy, got {other:?}"),
        }
    }

    #[test]
    fn lock_error_message_names_the_holder_and_says_no_queueing() {
        let msg = Denial::LockHeldBy {
            holder: "s-other".to_string(),
            expires_in: Duration::from_secs(42),
        }
        .message();
        assert!(msg.contains("s-other"), "{msg}");
        assert!(msg.contains("not queued"), "{msg}");
    }

    #[test]
    fn system_tier_needs_both_dangerous_mode_and_attribution() {
        let profile = root_profile();
        let r = req(Capability::FsSystem, true);

        // Neither condition.
        assert!(matches!(
            authorize(&r, &profile, &ctx(false, AttributionVerdict::Absent)).unwrap_err(),
            Denial::DangerousModeOff { .. }
        ));
        // Local switch only.
        assert!(matches!(
            authorize(&r, &profile, &ctx(true, AttributionVerdict::Absent)).unwrap_err(),
            Denial::AttributionRefused { .. }
        ));
        // Attribution only.
        assert!(matches!(
            authorize(&r, &profile, &ctx(false, AttributionVerdict::Granted)).unwrap_err(),
            Denial::DangerousModeOff { .. }
        ));
        // Both: granted.
        let grant = authorize(&r, &profile, &ctx(true, AttributionVerdict::Granted)).unwrap();
        assert!(grant.attribution_checked);
        assert!(grant.holds_write_lock);
    }

    #[test]
    fn unowned_node_never_opens_the_system_tier_even_when_rooted_and_flagged() {
        // ADR-AND-001 §7.4, verbatim.
        let err = authorize(
            &req(Capability::FsSystem, true),
            &root_profile(),
            &ctx(true, AttributionVerdict::UnownedNode),
        )
        .unwrap_err();
        assert_eq!(
            err,
            Denial::AttributionRefused {
                capability: Capability::FsSystem,
                verdict: AttributionVerdict::UnownedNode
            }
        );
        assert!(err.message().contains("no registered owner"));
    }

    #[test]
    fn absent_verdict_fails_closed() {
        assert!(!AttributionVerdict::Absent.granted());
        assert!(matches!(
            authorize(
                &req(Capability::SelinuxPermissive, true),
                &root_profile(),
                &ctx(true, AttributionVerdict::Absent)
            )
            .unwrap_err(),
            Denial::AttributionRefused { .. }
        ));
    }

    #[test]
    fn every_denial_message_is_actionable() {
        let denials = [
            Denial::NotDeclared {
                capability: Capability::FsSystem,
                reason: "dm-verity is enforcing".to_string(),
            },
            Denial::ApprovalMissing {
                capability: Capability::ShellWrite,
            },
            Denial::DangerousModeOff {
                capability: Capability::FsSystem,
            },
            Denial::LockHeldBy {
                holder: "s-2".to_string(),
                expires_in: Duration::from_secs(10),
            },
            Denial::AttributionRefused {
                capability: Capability::FsSystem,
                verdict: AttributionVerdict::Denied,
            },
        ];
        for d in &denials {
            let msg = d.message();
            // ADR-AND-001 N3: diagnostics travel with the error. "Too terse" is
            // the failure mode this guards — a bare "denied" gives a model
            // nothing to do but retry.
            assert!(msg.len() > 30, "too terse to act on: {msg}");
            assert!(
                msg.contains("do not retry")
                    || msg.contains("Do not retry")
                    || msg.contains("not retry")
                    || msg.contains("switch devices")
                    || msg.contains("Request approval")
                    || msg.contains("restarted")
                    || msg.contains("Re-probe")
                    || msg.contains("not available on this host"),
                "message must state a next step: {msg}"
            );
        }
        // Every capability-scoped refusal names the capability. The lock refusal
        // is deliberately not one of them: the lock is about *when*, not *what*,
        // and naming a capability there would imply the capability is the problem.
        for d in denials
            .iter()
            .filter(|d| !matches!(d, Denial::LockHeldBy { .. }))
        {
            assert!(d.message().contains("android:"), "{}", d.message());
        }
    }

    #[test]
    fn write_lock_ttl_is_ten_minutes() {
        assert_eq!(WRITE_LOCK_TTL, Duration::from_secs(600));
    }

    #[test]
    fn attribution_tier_mapping_is_the_provisional_one() {
        // Provisional pending B11. Asserted so a change is a deliberate act.
        assert_eq!(
            Capability::ShellRead.attribution_tier(),
            AttributionTier::None
        );
        assert_eq!(
            Capability::ShellWrite.attribution_tier(),
            AttributionTier::Manage
        );
        assert_eq!(
            Capability::FsOutsideApp.attribution_tier(),
            AttributionTier::Use
        );
        assert_eq!(
            Capability::FsSystem.attribution_tier(),
            AttributionTier::Manage
        );
        assert_eq!(
            Capability::SelinuxPermissive.attribution_tier(),
            AttributionTier::Manage
        );
    }

    #[test]
    fn dangerous_mode_capabilities_are_exactly_the_system_tier() {
        for cap in Capability::all() {
            assert_eq!(
                cap.requires_dangerous_mode(),
                matches!(cap, Capability::FsSystem | Capability::SelinuxPermissive),
                "{cap} dangerous-mode classification drifted from ADR-AND-001 §7.4"
            );
        }
    }

    #[test]
    fn exec_output_distinguishes_a_real_block_from_permissive_logging() {
        let blocked = ExecOutput {
            stdout: String::new(),
            stderr: String::new(),
            exit_code: Some(1),
            selinux_denials: vec![SelinuxDenial {
                permissions: vec!["read".to_string()],
                scontext: None,
                tcontext: None,
                tclass: None,
                permissive: false,
                path: None,
                comm: None,
            }],
            uid: Some(0),
            context: None,
            duration_ms: 12,
        };
        assert!(blocked.was_blocked_by_selinux());

        let mut logged = blocked.clone();
        logged.selinux_denials[0].permissive = true;
        assert!(!logged.was_blocked_by_selinux());
    }
}
