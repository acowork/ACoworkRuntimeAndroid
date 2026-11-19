//! ADR-059 §6 — operation contract: ids, states, and records for
//! every mutation API (install, provider write, identity write, …).
//!
//! The contract gives clients a closed loop for asynchronous
//! mutations: submit with an optional `expected_version` → receive an
//! `OperationId` + `OperationState` → observe the terminal state via
//! the operation id (poll / MQTT event). The Gateway tracks accepted
//! operations in [`crate::operation_store`] and transitions them as
//! the underlying side effects complete.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error_codes::StructuredErrorBody;

/// Stable opaque identifier for a mutation operation (UUID v4).
///
/// Carried end-to-end: HTTP ack, MQTT `NodeControlCommand.request_id`,
/// `NodeEvent.request_id`, and the operation store key. The wire form
/// is the lowercase hyphenated UUID string.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct OperationId(String);

impl OperationId {
    /// Generate a fresh UUID v4 operation id.
    pub fn new() -> Self {
        Self(uuid::Uuid::new_v4().to_string())
    }

    /// The underlying UUID string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<String> for OperationId {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for OperationId {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl Default for OperationId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for OperationId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Lifecycle state of a mutation operation.
///
/// ```text
/// Accepted ──► Committed ──► Running ──► Completed
///     │            │             │
///     └────────────┴─────────────┴──► Failed
/// ```
///
/// - `Accepted` — the mutation was accepted and queued; it may be
///   waiting on a dependency (e.g. NodeReady) before dispatch.
/// - `Committed` — the mutation was handed to its executor (the MQTT
///   publish is queued); the outcome is not yet known.
/// - `Running` — the executor reported start (a NodeEvent with
///   `status=ok` for installs that progress).
/// - `Completed` — the side effect finished successfully.
/// - `Failed` — the side effect failed; `terminal_error` carries the
///   structured reason.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationState {
    Accepted,
    Committed,
    Running,
    Completed,
    Failed,
}

impl OperationState {
    /// Whether the operation has reached a terminal state.
    pub fn is_terminal(self) -> bool {
        matches!(self, OperationState::Completed | OperationState::Failed)
    }
}

/// Full record of a mutation operation as tracked by the Gateway.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationRecord {
    pub operation_id: OperationId,
    /// The resource version the client expected when submitting
    /// (`0` / absent → no precondition, optimistic).
    pub expected_version: u64,
    /// The resource version observed once the mutation committed
    /// (`providers.version + 1`, `user_profile_list.version + 1`, …).
    pub resource_version: Option<u64>,
    pub state: OperationState,
    /// Structured terminal error (state = Failed).
    pub terminal_error: Option<StructuredErrorBody>,
    pub created_at: DateTime<Utc>,
    /// Hard deadline — an operation past this without completing is
    /// expired (`OperationExpired` on any late query).
    pub deadline_at: DateTime<Utc>,
}

impl OperationRecord {
    /// Default operation lifetime (ms). The Gateway may extend this
    /// for operations observed running.
    pub const DEFAULT_DEADLINE_MS: i64 = 60_000;

    /// Open a new operation in `Accepted` state with the given
    /// precondition version.
    pub fn new(expected_version: u64) -> Self {
        let now = Utc::now();
        Self {
            operation_id: OperationId::new(),
            expected_version,
            resource_version: None,
            state: OperationState::Accepted,
            terminal_error: None,
            created_at: now,
            deadline_at: now + chrono::Duration::milliseconds(Self::DEFAULT_DEADLINE_MS),
        }
    }

    /// Whether the operation's deadline has passed.
    pub fn is_expired(&self, now: DateTime<Utc>) -> bool {
        now > self.deadline_at && !self.state.is_terminal()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operation_id_is_uuid_v4_unique() {
        let a = OperationId::new();
        let b = OperationId::new();
        assert_ne!(a, b);
        assert_eq!(a.as_str().len(), 36);
        // UUID v4 variant bits (position 14 == '4').
        let chars: Vec<char> = a.as_str().chars().collect();
        assert_eq!(chars[14], '4');
    }

    #[test]
    fn operation_id_serde_round_trip() {
        let id = OperationId::new();
        let json = serde_json::to_string(&id).unwrap();
        let back: OperationId = serde_json::from_str(&json).unwrap();
        assert_eq!(back, id);
        assert_eq!(back.as_str(), id.as_str());
    }

    #[test]
    fn record_state_machine_transitions() {
        let mut record = OperationRecord::new(0);
        assert_eq!(record.state, OperationState::Accepted);
        assert!(!record.state.is_terminal());

        record.state = OperationState::Committed;
        record.state = OperationState::Running;
        assert!(!record.state.is_terminal());

        record.state = OperationState::Completed;
        assert!(record.state.is_terminal());
    }

    #[test]
    fn expired_after_deadline() {
        let record = OperationRecord::new(0);
        let past = record.deadline_at + chrono::Duration::seconds(1);
        assert!(record.is_expired(past));
        assert!(!record.is_expired(record.created_at));
    }
}
