//! Install execution structure — serialization and idempotency for
//! agent package installation.
//!
//! Installation is a *backend* concern: callers submit an intent and
//! must not need to coordinate with each other. Two axes are therefore
//! kept deliberately separate, because conflating them is what allowed
//! a single user intent to land three package instances:
//!
//! | axis | question answered | carrier |
//! |------|-------------------|---------|
//! | serialization | how many installs run at once? | [`InstallScheduler`] (one in-flight per node) |
//! | idempotency | may *this install* be executed twice? | the **instance identity** ([`InstallRequest::instance_id`]) |
//!
//! The unit of an installation is the instance, so the instance id *is*
//! the identity of the job: submitting the same `instance_id` twice
//! (replay, retry, a second caller making the same request) is one
//! install, and a job can never be enqueued twice — which also means
//! two jobs can never race for the same `{agent_id}/{instance_id}/`
//! landing directory.
//!
//! Neither axis constrains **how many instances one package may have**.
//! ADR-073 makes multiple instances of the same `agent_id` a legal
//! state: two installs of the same package with two different instance
//! ids are two jobs, two instances, by design.
//!
//! Declarative "make sure it exists" semantics live in
//! [`InstallKind::Ensure`], and they are a **precondition**, not a
//! deduplication key: an `Ensure` re-checks at execution time whether
//! any instance of the package already exists. That check — not the
//! queue's identity rule — is what collapses two independent "ensure
//! the System Agent is installed" calls into one installed instance.
//!
//! The model is pure data plus a synchronous scheduler — no I/O, no
//! async runtime. Hosts (the Node's install gate, the Gateway's
//! coordinator) own the worker loop and the side effects.

pub mod scheduler;

use crate::agent_instance_id::AgentInstanceId;
use crate::operation::OperationId;

pub use scheduler::{AdmitOutcome, InstallCompletion, InstallScheduler};

/// What the caller is asking for.
///
/// The distinction decides **whether the existence precondition
/// applies** at execution time. It is not a deduplication key — that is
/// always the instance identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallKind {
    /// Explicit "install one more copy".
    ///
    /// Every distinct instance id yields a new instance; the same
    /// package may be installed N times (ADR-073 multi-instance). The
    /// existence precondition is never applied, because "an instance of
    /// this package already exists" is not a reason to refuse another
    /// copy.
    Install,
    /// Declarative "make sure this package exists on this node".
    ///
    /// The existence precondition is applied at execution time: if any
    /// instance of the package is already installed, the request is a
    /// no-op ([`super::InstallOutcome::AlreadySatisfied`]) instead of
    /// landing a second copy. Used by `POST /api/agents/ensure` and the
    /// Desktop onboarding wizard — both are "ensure" calls, not "install
    /// one more" calls.
    Ensure,
}

/// Where the package payload comes from.
///
/// The payload half of a ticket: the scheduler moves *work*, it never
/// touches package bytes, so the executor needs the origin described in
/// domain terms rather than as a host-specific handle. Both variants
/// exist on both hosting shapes — the Node fetches a registry URL over
/// MQTT (`ADR-055 §6.20`) or installs a locally spooled file, and the
/// Gateway installs a bundled directory or a registry URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstallSource {
    /// Fetch the package from a Gateway-hosted registry URL.
    Registry {
        /// Package URL as advertised by the Gateway.
        url: String,
    },
    /// Read the package from a path that already exists on the host.
    LocalFile {
        /// Absolute path of the package directory or archive.
        path: String,
    },
}

impl InstallSource {
    /// Registry origin.
    pub fn registry(url: impl Into<String>) -> Self {
        Self::Registry { url: url.into() }
    }

    /// Local-path origin.
    pub fn local_file(path: impl Into<String>) -> Self {
        Self::LocalFile { path: path.into() }
    }
}

/// Lifecycle position of one installation, as observed by a host.
///
/// Hosts project this onto their own status surface (the Node's
/// retained inventory, the Gateway's `OperationStore`); the scheduler
/// itself only distinguishes queued / running / terminal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstallPhase {
    /// Admitted, waiting for the node's single install slot.
    Queued,
    /// Handed to the worker; the install is executing.
    Running,
    /// Package landed and is present in the install table.
    Ready,
    /// Install failed; the package state on disk is undefined and must
    /// not be assumed present.
    Failed,
    /// Declarative request whose precondition was already satisfied —
    /// nothing was executed.
    AlreadySatisfied,
}

impl InstallPhase {
    /// Whether no further transition will follow.
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::Ready | Self::Failed | Self::AlreadySatisfied
        )
    }
}

/// An untouched installation intent, as submitted by a caller.
///
/// Built by the host adapter (HTTP handler, control-plane handler,
/// bootstrap path) from its own inputs; it is the only shape the
/// scheduler accepts.
#[derive(Debug, Clone)]
pub struct InstallRequest {
    /// ADR-059 §6 correlation id — carried end-to-end and used as the
    /// scheduler's ticket key.
    pub operation_id: OperationId,
    /// Package identity (`manifest.agent_id`).
    pub agent_id: String,
    /// ADR-073 instance identity, minted by the Gateway before the
    /// request reaches any queue.
    ///
    /// This is the **identity of the install**: submitting the same
    /// instance id again is the same install, whichever caller sends it.
    pub instance_id: AgentInstanceId,
    /// Explicit vs. declarative semantics — see [`InstallKind`].
    pub kind: InstallKind,
    /// Where the package payload comes from — see [`InstallSource`].
    pub source: InstallSource,
    /// `ADR-055 §6.20` development mode: the package is read from the
    /// source as-is (no signature requirement, no copy into the store).
    pub dev_mode: bool,
    /// Instance already present in the caller's install table, resolved
    /// before submitting.
    ///
    /// Only honored for [`InstallKind::Ensure`]; an explicit
    /// [`InstallKind::Install`] ignores it, because "it is already
    /// installed" is not a reason to refuse another copy.
    pub already_installed: Option<AgentInstanceId>,
}

impl InstallRequest {
    /// An explicit install of one more copy.
    pub fn install(
        operation_id: OperationId,
        agent_id: impl Into<String>,
        instance_id: AgentInstanceId,
        source: InstallSource,
    ) -> Self {
        Self {
            operation_id,
            agent_id: agent_id.into(),
            instance_id,
            kind: InstallKind::Install,
            source,
            dev_mode: false,
            already_installed: None,
        }
    }

    /// A declarative "ensure present" request.
    pub fn ensure(
        operation_id: OperationId,
        agent_id: impl Into<String>,
        instance_id: AgentInstanceId,
        source: InstallSource,
    ) -> Self {
        Self {
            operation_id,
            agent_id: agent_id.into(),
            instance_id,
            kind: InstallKind::Ensure,
            source,
            dev_mode: false,
            already_installed: None,
        }
    }

    /// Mark the request as a development-mode install.
    pub fn with_dev_mode(mut self, dev_mode: bool) -> Self {
        self.dev_mode = dev_mode;
        self
    }

    /// Tell the scheduler that an instance of this package already
    /// exists (honored for [`InstallKind::Ensure`] only).
    pub fn with_already_installed(mut self, instance_id: AgentInstanceId) -> Self {
        self.already_installed = Some(instance_id);
        self
    }
}

/// A request that occupies a queue slot.
///
/// Snapshotted at admission; the scheduler hands it out to the worker
/// with [`InstallPhase::Running`] and holds it until completion.
#[derive(Debug, Clone)]
pub struct InstallTicket {
    /// See [`InstallRequest::operation_id`].
    pub operation_id: OperationId,
    /// See [`InstallRequest::agent_id`].
    pub agent_id: String,
    /// See [`InstallRequest::instance_id`].
    pub instance_id: AgentInstanceId,
    /// See [`InstallKind`].
    pub kind: InstallKind,
    /// See [`InstallSource`].
    pub source: InstallSource,
    /// See [`InstallRequest::dev_mode`].
    pub dev_mode: bool,
    /// Position in the lifecycle at the moment this ticket was handed
    /// out ([`InstallPhase::Queued`] for an [`AdmitOutcome::Accepted`]
    /// snapshot, [`InstallPhase::Running`] once the worker owns it).
    pub phase: InstallPhase,
}

/// Terminal (or no-op) result of one queued installation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstallOutcome {
    /// The package was installed and is present in the install table.
    Ready {
        /// ADR-073 instance identity that landed.
        instance_id: AgentInstanceId,
    },
    /// Nothing was executed: the declarative precondition already held.
    AlreadySatisfied {
        /// Pre-existing instance that satisfied the request.
        instance_id: AgentInstanceId,
    },
    /// The install failed; the on-disk package state must be treated as
    /// unknown.
    Failed {
        /// Human-readable failure reason (host-formatted).
        message: String,
    },
}

impl InstallOutcome {
    /// The lifecycle phase this outcome terminates in.
    pub fn phase(&self) -> InstallPhase {
        match self {
            Self::Ready { .. } => InstallPhase::Ready,
            Self::AlreadySatisfied { .. } => InstallPhase::AlreadySatisfied,
            Self::Failed { .. } => InstallPhase::Failed,
        }
    }

    /// Whether the package is present after this outcome.
    pub fn is_satisfied(&self) -> bool {
        matches!(self, Self::Ready { .. } | Self::AlreadySatisfied { .. })
    }

    /// The instance the request resolved to, when one exists.
    pub fn instance_id(&self) -> Option<&AgentInstanceId> {
        match self {
            Self::Ready { instance_id } | Self::AlreadySatisfied { instance_id } => {
                Some(instance_id)
            }
            Self::Failed { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn instance() -> AgentInstanceId {
        AgentInstanceId::new()
    }

    fn source() -> InstallSource {
        InstallSource::local_file("D:/tmp/com.test.agent")
    }

    #[test]
    fn explicit_install_is_not_an_ensure_request() {
        let req = InstallRequest::install(
            OperationId::new(),
            "com.test.agent",
            instance(),
            source(),
        );
        assert_eq!(req.kind, InstallKind::Install);
        // An explicit install carries no "already installed" shortcut.
        assert!(req.already_installed.is_none());
    }

    #[test]
    fn ensure_request_can_carry_a_known_instance() {
        let existing = instance();
        let req = InstallRequest::ensure(
            OperationId::new(),
            "com.test.agent",
            instance(),
            source(),
        )
        .with_already_installed(existing.clone());
        assert_eq!(req.kind, InstallKind::Ensure);
        assert_eq!(req.already_installed, Some(existing));
    }

    #[test]
    fn outcome_phase_and_instance_projection() {
        let id = instance();
        let ready = InstallOutcome::Ready {
            instance_id: id.clone(),
        };
        assert_eq!(ready.phase(), InstallPhase::Ready);
        assert!(ready.phase().is_terminal());
        assert!(ready.is_satisfied());
        assert_eq!(ready.instance_id(), Some(&id));

        let failed = InstallOutcome::Failed {
            message: "boom".to_string(),
        };
        assert_eq!(failed.phase(), InstallPhase::Failed);
        assert!(!failed.is_satisfied());
        assert!(failed.instance_id().is_none());
    }
}
