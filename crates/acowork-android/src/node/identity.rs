//! Persisted node identity (`{home}/identity.json`) — ADR-075 shape.
//!
//! `node_id` is a UUID v4 routing key. `node_name` is display-only.
//! `node_token` is the Gateway-issued long-lived credential (Phase 5a).

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::topics::{node_name_from_hostname, node_name_is_valid};

/// Enrollment lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnrollmentState {
    /// identity.json exists but the node has never completed enroll.
    Created,
    /// The node has received a successful enroll_result (or published
    /// with auth disabled and marked enrolled locally).
    Enrolled,
}

/// Persisted node identity.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeIdentity {
    /// Stable routing key (UUID v4).
    pub node_id: String,
    /// Display slug.
    pub node_name: String,
    /// Gateway-issued node token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_token: Option<String>,
    /// Last known Gateway MQTT `host:port`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway_addr: Option<String>,
    /// Enrollment lifecycle.
    #[serde(default = "default_enrollment_state")]
    pub enrollment: EnrollmentState,
    /// Unix seconds when the identity file was created.
    pub created_at: u64,
    /// Unix seconds of last successful enroll.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enrolled_at: Option<u64>,
}

fn default_enrollment_state() -> EnrollmentState {
    EnrollmentState::Created
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Why identity load/create failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityError {
    /// I/O failure.
    Io(String),
    /// JSON parse / validation failure.
    Invalid(String),
}

impl std::fmt::Display for IdentityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IdentityError::Io(e) | IdentityError::Invalid(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for IdentityError {}

impl NodeIdentity {
    /// `{home}/identity.json`.
    pub fn path(home: &Path) -> PathBuf {
        home.join("identity.json")
    }

    /// Load if present.
    pub fn load(home: &Path) -> Result<Option<NodeIdentity>, IdentityError> {
        let path = Self::path(home);
        if !path.exists() {
            return Ok(None);
        }
        let content = std::fs::read_to_string(&path)
            .map_err(|e| IdentityError::Io(format!("read {}: {e}", path.display())))?;
        // A zero-length file (interrupted write / wipe) must not block startup —
        // treat it as missing so `load_or_create` can mint a fresh identity.
        if content.trim().is_empty() {
            return Ok(None);
        }
        let identity: NodeIdentity = serde_json::from_str(&content)
            .map_err(|e| IdentityError::Invalid(format!("parse {}: {e}", path.display())))?;
        identity.validate()?;
        Ok(Some(identity))
    }

    /// Load or mint a new UUID identity. Idempotent on existing files.
    pub fn load_or_create(
        home: &Path,
        explicit_name: Option<&str>,
        gateway_addr: Option<&str>,
    ) -> Result<NodeIdentity, IdentityError> {
        if let Some(mut existing) = Self::load(home)? {
            if let Some(addr) = gateway_addr {
                existing.gateway_addr = Some(addr.to_string());
            }
            existing.save(home)?;
            return Ok(existing);
        }

        let node_name = match explicit_name {
            Some(name) => {
                if !node_name_is_valid(name) {
                    return Err(IdentityError::Invalid(format!(
                        "invalid node name `{name}` (2–32 of [a-z0-9-], not `local`)"
                    )));
                }
                name.to_string()
            }
            None => {
                let host = hostname();
                node_name_from_hostname(&host)
            }
        };

        let identity = NodeIdentity {
            node_id: Uuid::new_v4().to_string(),
            node_name,
            node_token: None,
            gateway_addr: gateway_addr.map(str::to_string),
            enrollment: EnrollmentState::Created,
            created_at: now_secs(),
            enrolled_at: None,
        };
        identity.save(home)?;
        Ok(identity)
    }

    /// Persist.
    pub fn save(&self, home: &Path) -> Result<(), IdentityError> {
        std::fs::create_dir_all(home)
            .map_err(|e| IdentityError::Io(format!("mkdir {}: {e}", home.display())))?;
        let path = Self::path(home);
        let content = serde_json::to_string_pretty(self)
            .map_err(|e| IdentityError::Invalid(format!("serialize identity: {e}")))?;
        std::fs::write(&path, content)
            .map_err(|e| IdentityError::Io(format!("write {}: {e}", path.display())))?;
        Ok(())
    }

    /// Mark enrolled and optionally store a node token.
    pub fn mark_enrolled(&mut self, gateway_addr: &str, node_token: Option<String>) {
        self.enrollment = EnrollmentState::Enrolled;
        self.enrolled_at = Some(now_secs());
        self.gateway_addr = Some(gateway_addr.to_string());
        if let Some(token) = node_token
            && !token.is_empty()
        {
            self.node_token = Some(token);
        }
    }

    fn validate(&self) -> Result<(), IdentityError> {
        if Uuid::parse_str(&self.node_id).is_err() {
            return Err(IdentityError::Invalid(format!(
                "node_id `{}` is not a UUID",
                self.node_id
            )));
        }
        if !node_name_is_valid(&self.node_name) {
            return Err(IdentityError::Invalid(format!(
                "node_name `{}` is not a valid slug",
                self.node_name
            )));
        }
        Ok(())
    }
}

fn hostname() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "android".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_or_create_is_idempotent() {
        let dir = std::env::temp_dir().join(format!(
            "acowork-android-id-{}-{}",
            std::process::id(),
            now_secs()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let a =
            NodeIdentity::load_or_create(&dir, Some("phone-1"), Some("127.0.0.1:19875")).unwrap();
        let b =
            NodeIdentity::load_or_create(&dir, Some("ignored"), Some("127.0.0.1:19875")).unwrap();
        assert_eq!(a.node_id, b.node_id);
        assert_eq!(b.node_name, "phone-1");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
