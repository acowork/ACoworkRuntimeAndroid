//! ADR-073 — Agent instance identity.
//!
//! The three-layer identity model:
//!
//! | field                | semantics                                      | mutable |
//! |----------------------|------------------------------------------------|---------|
//! | `agent_id`           | package identity (manifest reverse-domain)     | never   |
//! | `agent_instance_id`  | runtime instance (UUID v4, generated at install)| never  |
//! | `node_id`            | current location (where the instance runs)     | yes     |
//!
//! This module defines the middle layer: [`AgentInstanceId`]. It is an
//! opaque newtype over a UUID v4 string so the type system prevents
//! confusing an instance id with an `agent_id` (package id) at every
//! HashMap key, HTTP path variable and MQTT topic construction site.
//!
//! Invariants:
//! - generated ONLY by the Gateway at install time (never self-reported
//!   by Node / Desktop), guaranteeing global uniqueness,
//! - immutable — stays stable across node migration / DR / rebalancing,
//! - validated on parse: a non-UUID string is rejected.

use serde::{Deserialize, Serialize};

/// Stable instance identifier for one installed agent runtime (UUID v4).
///
/// All agent-dimension registries in the Gateway key by this type:
/// `installed_agents`, `running_agents`, `AgentRegistry`, and
/// `CapabilityKey`. The wire form is the lowercase hyphenated UUID
/// string (same convention as [`crate::operation::OperationId`]).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AgentInstanceId(String);

impl AgentInstanceId {
    /// Generate a fresh UUID v4 instance id.
    pub fn new() -> Self {
        Self(uuid::Uuid::new_v4().to_string())
    }

    /// Parse and validate an instance id from an untrusted string
    /// (HTTP path variable, MQTT topic part, control-plane payload).
    ///
    /// Accepts the canonical hyphenated form or the compact 32-hex
    /// simple form; rejects everything else with [`InstanceIdError`].
    pub fn from_string(id: String) -> Result<Self, InstanceIdError> {
        let uuid = uuid::Uuid::parse_str(&id).map_err(|e| InstanceIdError::Invalid(e.to_string()))?;
        Ok(Self(uuid.to_string()))
    }

    /// The underlying UUID string (canonical hyphenated form).
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Short human-readable form for UI/display (first 8 hex chars).
    /// NOT an identifier — collisions are possible; use [`Self::as_str`]
    /// for anything that must round-trip.
    pub fn short(&self) -> &str {
        // Canonical hyphenated form: "xxxxxxxx-xxxx-..." → first 8 chars.
        &self.0[..8.min(self.0.len())]
    }
}

impl std::str::FromStr for AgentInstanceId {
    type Err = InstanceIdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_string(s.to_string())
    }
}

impl Default for AgentInstanceId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for AgentInstanceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<AgentInstanceId> for String {
    fn from(id: AgentInstanceId) -> Self {
        id.0
    }
}

/// Validation/parse error for [`AgentInstanceId`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum InstanceIdError {
    /// The string is not a valid UUID.
    #[error("invalid agent instance id (expected UUID v4): {0}")]
    Invalid(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_generates_valid_uuid() {
        let id = AgentInstanceId::new();
        assert_eq!(id.as_str().len(), 36); // 8-4-4-4-12 hyphenated
        assert!(uuid::Uuid::parse_str(id.as_str()).is_ok());
    }

    #[test]
    fn from_string_accepts_hyphenated_and_simple() {
        let hyphenated = "3f8c2a1b-4d5e-6f7a-8b9c-0d1e2f3a4b5c";
        let simple = "3f8c2a1b4d5e6f7a8b9c0d1e2f3a4b5c";
        assert_eq!(
            AgentInstanceId::from_string(hyphenated.to_string())
                .unwrap()
                .as_str(),
            hyphenated
        );
        assert_eq!(
            AgentInstanceId::from_string(simple.to_string())
                .unwrap()
                .as_str(),
            hyphenated // normalized to hyphenated form
        );
    }

    #[test]
    fn from_string_rejects_non_uuid() {
        assert!(AgentInstanceId::from_string("com.acowork.senior-engineer".to_string()).is_err());
        assert!(AgentInstanceId::from_string("".to_string()).is_err());
        assert!(AgentInstanceId::from_string("3f8c2a1b".to_string()).is_err());
        assert!(AgentInstanceId::from_string("zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz".to_string()).is_err());
    }

    #[test]
    fn serde_roundtrip_is_transparent() {
        let id = AgentInstanceId::new();
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, format!("\"{}\"", id.as_str()));
        let back: AgentInstanceId = serde_json::from_str(&json).unwrap();
        assert_eq!(back, id);
    }

    #[test]
    fn distinct_instances_never_equal() {
        let a = AgentInstanceId::new();
        let b = AgentInstanceId::new();
        assert_ne!(a, b);
    }
}
