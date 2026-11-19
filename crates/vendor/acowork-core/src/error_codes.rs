//! ADR-059 §6.3 — structured error codes for the operation contract.
//!
//! Every mutation API returns a [`StructuredErrorBody`] on failure so a
//! client can distinguish *why* an operation failed and *what to do*
//! next, without parsing human-readable message text:
//!
//! - [`StructuredErrorCode::DependencyNotReady`] — the operation depends
//!   on a subsystem (e.g. a Node's control plane) that has not
//!   announced readiness. Retry once the bootstrap phase is READY.
//! - [`StructuredErrorCode::OperationUncertain`] — the mutation was
//!   dispatched but its outcome could not be confirmed (MQTT dropped /
//!   Gateway restarted). Re-check via the operation id.
//! - [`StructuredErrorCode::OperationExpired`] — the operation's
//!   deadline passed without completion.
//! - [`StructuredErrorCode::ResourceVersionConflict`] — the client's
//!   `expected_version` does not match the current resource version.
//! - [`StructuredErrorCode::HandshakeTimeout`] — a bootstrap handshake
//!   (e.g. the desktop ↔ gateway readiness probe) timed out.
//!
//! The body carries ONLY protocol-level fields (ADR-059 §5.4.4 OCP
//! boundary): no capability names, no subsystem generations, no process
//! ids. Phase names are plain strings in SCREAMING_SNAKE_CASE matching
//! the `BootstrapPhase` serde representation (`BOOTING`, `READY`, …).

use serde::{Deserialize, Serialize};

use crate::operation::OperationId;

/// Stable machine-readable error code. The wire representation is the
/// snake_case serde name (`dependency_not_ready`, `operation_uncertain`,
/// …) — the set is closed by the protocol; adding a code is a protocol
/// change, not a library change.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StructuredErrorCode {
    /// A dependency subsystem has not announced readiness yet.
    DependencyNotReady,
    /// The mutation was dispatched but its outcome is unknown.
    OperationUncertain,
    /// The operation's deadline passed without completing.
    OperationExpired,
    /// `expected_version` does not match the current resource version.
    ResourceVersionConflict,
    /// A bootstrap handshake timed out.
    HandshakeTimeout,
}

/// Retry guidance for transient failures.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct RetryHint {
    /// Suggested delay before retrying, in milliseconds.
    pub retry_after_ms: Option<u64>,
    /// Maximum number of retries the protocol permits for this code.
    pub retry_count: u32,
}

/// The structured error body returned by mutation APIs on failure.
///
/// Every field is optional: a body only carries the fields its code
/// needs (e.g. `dependency_not_ready` carries `current_phase` /
/// `phase_detail` / `retry_hint`; `resource_version_conflict` carries
/// `current_version` / `client_expected_version`). Absent fields are
/// OMITTED from the wire (OCP, ADR-059 §5.4.4) — consumers MUST treat
/// an absent field as "not provided", never as a default value.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct StructuredErrorBody {
    pub code: StructuredErrorCode,
    /// Aggregated bootstrap phase at failure time, SCREAMING_SNAKE_CASE
    /// (`BOOTING` / `READY` / `DEGRADED` / `FAILED` / `SHUTTING_DOWN`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_phase: Option<String>,
    /// Human-readable phase detail (subsystem-level diagnostic).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phase_detail: Option<String>,
    /// Retry guidance (retry-aware clients).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_hint: Option<RetryHint>,
    /// The operation that failed, when one was accepted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<OperationId>,
    /// Phase observed before the failure (handshake timeout).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_known_phase: Option<String>,
    /// Current resource version (version-conflict diagnostics).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_version: Option<u64>,
    /// The version the client expected (version-conflict diagnostics).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_expected_version: Option<u64>,
    /// Operation lease deadline in ms since epoch (expiry diagnostics).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lease_deadline_ms: Option<u64>,
    /// Endpoint that failed the handshake (handshake timeout).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    /// Handshake deadline in ms since epoch (handshake timeout).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deadline_ms: Option<u64>,
}

impl Default for StructuredErrorBody {
    /// Empty body — every field is `None` / zero. Construct-then-fill
    /// pattern for callers that don't want to enumerate all 10 optional
    /// fields (e.g. ad-hoc 503 / 422 responses layered on top of the
    /// closed `StructuredErrorCode` set).
    fn default() -> Self {
        Self {
            code: StructuredErrorCode::OperationUncertain,
            current_phase: None,
            phase_detail: None,
            retry_hint: None,
            operation_id: None,
            last_known_phase: None,
            current_version: None,
            client_expected_version: None,
            lease_deadline_ms: None,
            endpoint: None,
            deadline_ms: None,
        }
    }
}

impl StructuredErrorBody {
    /// `dependency_not_ready` — carries only the phase picture and a
    /// retry hint (ADR-059 §6.3: the client retries once phase = READY).
    pub fn dependency_not_ready(
        current_phase: Option<String>,
        phase_detail: Option<String>,
        retry_after_ms: u64,
    ) -> Self {
        Self {
            code: StructuredErrorCode::DependencyNotReady,
            current_phase,
            phase_detail,
            retry_hint: Some(RetryHint {
                retry_after_ms: Some(retry_after_ms),
                retry_count: u32::MAX,
            }),
            operation_id: None,
            last_known_phase: None,
            current_version: None,
            client_expected_version: None,
            lease_deadline_ms: None,
            endpoint: None,
            deadline_ms: None,
        }
    }

    /// `resource_version_conflict` — carries both version numbers so
    /// the client can re-base and retry.
    pub fn resource_version_conflict(current_version: u64, client_expected_version: u64) -> Self {
        Self {
            code: StructuredErrorCode::ResourceVersionConflict,
            current_phase: None,
            phase_detail: None,
            retry_hint: Some(RetryHint {
                retry_after_ms: Some(0),
                retry_count: u32::MAX,
            }),
            operation_id: None,
            last_known_phase: None,
            current_version: Some(current_version),
            client_expected_version: Some(client_expected_version),
            lease_deadline_ms: None,
            endpoint: None,
            deadline_ms: None,
        }
    }

    /// `operation_uncertain` — the mutation was dispatched but its
    /// outcome is unknown (MQTT dropped / Gateway restarted). Carries
    /// only the operation id: the client re-checks by id and must never
    /// blindly retry (ADR-059 §6.3).
    pub fn operation_uncertain(operation_id: &str) -> Self {
        Self {
            code: StructuredErrorCode::OperationUncertain,
            current_phase: None,
            phase_detail: None,
            retry_hint: None,
            operation_id: Some(OperationId::from(operation_id.to_string())),
            last_known_phase: None,
            current_version: None,
            client_expected_version: None,
            lease_deadline_ms: None,
            endpoint: None,
            deadline_ms: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_code_serde_round_trip() {
        // The wire name is the snake_case code — clients match on it.
        for (code, wire) in [
            (StructuredErrorCode::DependencyNotReady, "dependency_not_ready"),
            (StructuredErrorCode::OperationUncertain, "operation_uncertain"),
            (StructuredErrorCode::OperationExpired, "operation_expired"),
            (
                StructuredErrorCode::ResourceVersionConflict,
                "resource_version_conflict",
            ),
            (StructuredErrorCode::HandshakeTimeout, "handshake_timeout"),
        ] {
            let json = serde_json::to_string(&code).unwrap();
            assert_eq!(json, format!("\"{wire}\""));
            let back: StructuredErrorCode = serde_json::from_str(&json).unwrap();
            assert_eq!(back, code);
        }
    }

    #[test]
    fn dependency_not_ready_body_carries_only_phase_fields() {
        let body = StructuredErrorBody::dependency_not_ready(
            Some("BOOTING".to_string()),
            Some("node.local not ready".to_string()),
            500,
        );
        let json = serde_json::to_value(&body).unwrap();
        assert_eq!(json["code"], "dependency_not_ready");
        assert_eq!(json["current_phase"], "BOOTING");
        assert_eq!(json["phase_detail"], "node.local not ready");
        assert_eq!(json["retry_hint"]["retry_after_ms"], 500);
        // OCP: no operation / version / deadline fields on this code.
        assert!(json.get("operation_id").is_none());
        assert!(json.get("current_version").is_none());
        assert!(json.get("lease_deadline_ms").is_none());
    }

    #[test]
    fn version_conflict_body_carries_both_versions() {
        let body = StructuredErrorBody::resource_version_conflict(7, 5);
        let json = serde_json::to_value(&body).unwrap();
        assert_eq!(json["code"], "resource_version_conflict");
        assert_eq!(json["current_version"], 7);
        assert_eq!(json["client_expected_version"], 5);
        assert!(json.get("phase_detail").is_none());
    }

    #[test]
    fn operation_uncertain_body_carries_only_operation_id() {
        let body = StructuredErrorBody::operation_uncertain("op-123");
        let json = serde_json::to_value(&body).unwrap();
        assert_eq!(json["code"], "operation_uncertain");
        assert_eq!(json["operation_id"], "op-123");
        // OCP: no phase / version / retry fields on this code.
        assert!(json.get("current_phase").is_none());
        assert!(json.get("retry_hint").is_none());
        assert!(json.get("current_version").is_none());
        assert!(json.get("lease_deadline_ms").is_none());
    }

    /// `Default` is the construct-then-fill backbone for ad-hoc
    /// 503 / 422 responses layered on top of the closed
    /// `StructuredErrorCode` set (2026-09-07 incident follow-up).
    /// The contract: every optional field is `None`, `code` is the
    /// protocol-default `OperationUncertain`. Pinning this prevents
    /// drift if a new optional field is added to the struct — a
    /// `..Default::default()` spread must keep working at every
    /// call-site that adopts a new field.
    #[test]
    fn structured_error_body_default_has_all_optional_fields_none() {
        let body = StructuredErrorBody::default();
        // The protocol default for an unset code is `operation_uncertain`
        // (the most conservative classification; clients always re-check).
        assert_eq!(body.code, StructuredErrorCode::OperationUncertain);
        assert!(body.current_phase.is_none());
        assert!(body.phase_detail.is_none());
        assert!(body.retry_hint.is_none());
        assert!(body.operation_id.is_none());
        assert!(body.last_known_phase.is_none());
        assert!(body.current_version.is_none());
        assert!(body.client_expected_version.is_none());
        assert!(body.lease_deadline_ms.is_none());
        assert!(body.endpoint.is_none());
        assert!(body.deadline_ms.is_none());
    }

    /// The `..Default::default()` spread pattern must work for every
    /// optional field. After spreading, callers can overwrite only
    /// the fields they care about — the rest stay `None` and are
    /// omitted from the wire (OCP, ADR-059 §5.4.4).
    #[test]
    fn structured_error_body_default_spread_omits_unset_fields() {
        let body = StructuredErrorBody {
            code: StructuredErrorCode::HandshakeTimeout,
            phase_detail: Some("timeout agent=foo".to_string()),
            retry_hint: Some(RetryHint {
                retry_after_ms: Some(1500),
                retry_count: 5,
            }),
            ..Default::default()
        };
        let json = serde_json::to_value(&body).unwrap();
        assert_eq!(json["code"], "handshake_timeout");
        assert_eq!(json["phase_detail"], "timeout agent=foo");
        assert_eq!(json["retry_hint"]["retry_after_ms"], 1500);
        assert_eq!(json["retry_hint"]["retry_count"], 5);
        // Every other field absent on the wire.
        for omitted in [
            "current_phase",
            "operation_id",
            "last_known_phase",
            "current_version",
            "client_expected_version",
            "lease_deadline_ms",
            "endpoint",
            "deadline_ms",
        ] {
            assert!(
                json.get(omitted).is_none(),
                "field {omitted} must be absent when default = None; got {json}"
            );
        }
    }
}
