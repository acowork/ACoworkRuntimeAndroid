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
    /// The enrollment token whose acceptance produced `node_token`.
    ///
    /// The host UI re-presents whatever token it was started with, so
    /// without this record the same one-shot token would be replayed on
    /// every launch — and a replayed token is rejected as `Consumed`
    /// whenever broker auth is on. It is also what makes a re-scan mean
    /// something: the enrollment token is the only credential that
    /// carries a creator, and the creator is the node's owner
    /// (ADR-087 D2). A device that never re-enrolls therefore never
    /// gets an owner row, and `can_view` is fail-closed on a missing
    /// row — the node is online and invisible.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enrolled_with: Option<String>,
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
            enrolled_with: None,
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
}

/// What a join attempt should present, and with which credential it should
/// authenticate.
///
/// The two roles must stay separate. MQTT keeps authenticating with the
/// stored `node_token` — presenting a one-shot enrollment token there gets
/// `NotAuthorized` on CONNECT, which the client reads as a soft restart and
/// the Desktop sees as a 1 Hz offline/online flap. `/enroll` however must
/// carry the enrollment token, because that token is the only thing naming
/// the node's owner (ADR-087 D2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoinPlan {
    /// Credential for CONNECT.
    pub connect_token: String,
    /// Token to put in the `/enroll` payload.
    pub enroll_token: String,
    /// Whether `/enroll` must be published at all.
    pub enroll: bool,
    /// A presented token that has not been used yet — record it as
    /// `enrolled_with` once the Gateway accepts, so the next launch does not
    /// replay a spent credential.
    pub presented_fresh: Option<String>,
}

impl NodeIdentity {
    /// Decide how to join, given whatever enrollment token the caller was
    /// started with.
    ///
    /// The host UI re-presents the token it persisted in preferences on every
    /// launch, so "a token was passed in" cannot by itself mean "re-enroll" —
    /// only a token this identity has not consumed yet may trigger one.
    pub fn plan_join(&self, presented: Option<&str>) -> JoinPlan {
        let fresh = presented
            .filter(|t| !t.is_empty())
            .filter(|t| self.enrolled_with.as_deref() != Some(*t))
            .map(str::to_string);
        let connect_token = self
            .node_token
            .clone()
            .or_else(|| fresh.clone())
            .unwrap_or_default();
        let enroll_token = fresh.clone().unwrap_or_else(|| connect_token.clone());
        JoinPlan {
            presented_fresh: fresh.clone(),
            enroll: self.node_token.is_none() || fresh.is_some(),
            connect_token,
            enroll_token,
        }
    }

    /// Coerce what a human typed into a valid display slug, or `None` when
    /// nothing salvageable is left.
    ///
    /// The rules themselves stay with [`node_name_is_valid`]; this only maps
    /// intent onto them: `Mate10` means `mate10`, `My Phone` means
    /// `my-phone`. Without it, a capitalised name typed on the phone is
    /// rejected by validation and the field appears to do nothing — which is
    /// indistinguishable from the input being ignored, because the host UI has
    /// no other way to report it.
    pub fn normalize_name(input: &str) -> Option<String> {
        let slug: String = input
            .trim()
            .chars()
            .map(|c| {
                let lower = c.to_ascii_lowercase();
                if lower.is_ascii_alphanumeric() {
                    lower
                } else {
                    '-'
                }
            })
            .collect();
        let slug = slug
            .split('-')
            .filter(|part| !part.is_empty())
            .collect::<Vec<_>>()
            .join("-");
        node_name_is_valid(&slug).then_some(slug)
    }

    /// Rename this node: validate, persist `identity.json`, and keep the
    /// in-memory value equal to what actually reached the file.
    ///
    /// Returns `false` when the name is unchanged, so the caller can skip a
    /// pointless republish (ADR-075 D4 idempotence).
    pub fn set_name(&mut self, home: &Path, new_name: &str) -> Result<bool, IdentityError> {
        let new_name = new_name.trim();
        if !node_name_is_valid(new_name) {
            return Err(IdentityError::Invalid(format!(
                "invalid node name `{new_name}` (2–32 of [a-z0-9-], not `local`)"
            )));
        }
        if self.node_name == new_name {
            return Ok(false);
        }
        let previous = std::mem::replace(&mut self.node_name, new_name.to_string());
        if let Err(e) = self.save(home) {
            // Roll back. A name that lives only in memory would be stamped
            // into `identity.json` by the next heartbeat, so a rejected write
            // must not leave the display name changed either.
            self.node_name = previous;
            return Err(e);
        }
        Ok(true)
    }

    /// Mark enrolled, store the Gateway-issued node token, and record which
    /// enrollment token bought it.
    pub fn mark_enrolled(
        &mut self,
        gateway_addr: &str,
        node_token: Option<String>,
        enrolled_with: Option<String>,
    ) {
        self.enrollment = EnrollmentState::Enrolled;
        self.enrolled_at = Some(now_secs());
        self.gateway_addr = Some(gateway_addr.to_string());
        if let Some(token) = node_token
            && !token.is_empty()
        {
            self.node_token = Some(token);
        }
        // Keep the first record when a later enroll carried no token of its
        // own (anonymous/local join): clearing it would make the UI replay
        // an older enrollment token forever.
        if enrolled_with.is_some() {
            self.enrolled_with = enrolled_with;
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
    fn normalize_name_maps_what_a_human_typed_onto_the_slug_rules() {
        // The phone's name field has no error surface, so a capitalised name
        // used to look like "the input is ignored".
        assert_eq!(NodeIdentity::normalize_name("Mate10").as_deref(), Some("mate10"));
        assert_eq!(
            NodeIdentity::normalize_name("My Phone").as_deref(),
            Some("my-phone"),
            "spaces are word separators, not invalid input"
        );
        assert_eq!(NodeIdentity::normalize_name("  gpu--2  ").as_deref(), Some("gpu-2"));
    }

    #[test]
    fn normalize_name_refuses_what_it_cannot_salvage() {
        assert_eq!(NodeIdentity::normalize_name("我的手机"), None, "no slug characters at all");
        assert_eq!(NodeIdentity::normalize_name("a"), None, "shorter than the 2-char minimum");
        assert_eq!(NodeIdentity::normalize_name("LOCAL"), None, "reserved word stays reserved");
        assert_eq!(NodeIdentity::normalize_name(&"x".repeat(40)), None, "never truncate silently");
        assert_eq!(NodeIdentity::normalize_name("   "), None);
    }

    #[test]
    fn set_name_normalises_nothing_itself() {
        // Normalisation is the host UI's concern; the HTTP contract stays
        // strict so the Desktop dialog gets its 400 and shows the reason.
        let dir = std::env::temp_dir().join(format!(
            "acowork-setname-{}-{}",
            std::process::id(),
            now_secs()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut id = NodeIdentity::load_or_create(&dir, Some("phone-1"), None).unwrap();
        assert!(matches!(id.set_name(&dir, "Mate10"), Err(IdentityError::Invalid(_))));
        assert_eq!(id.node_name, "phone-1", "a rejected rename leaves the name alone");
        assert!(id.set_name(&dir, "mate10").unwrap());
        assert_eq!(NodeIdentity::load(&dir).unwrap().unwrap().node_name, "mate10");
        let _ = std::fs::remove_dir_all(&dir);
    }

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

    fn enrolled(
        node_token: Option<&str>,
        enrolled_with: Option<&str>,
    ) -> NodeIdentity {
        NodeIdentity {
            node_id: "00000000-0000-4000-8000-000000000001".into(),
            node_name: "phone-1".into(),
            node_token: node_token.map(str::to_string),
            gateway_addr: Some("127.0.0.1:19875".into()),
            enrollment: EnrollmentState::Created,
            created_at: 0,
            enrolled_at: None,
            enrolled_with: enrolled_with.map(str::to_string),
        }
    }

    #[test]
    fn first_join_presents_the_enrollment_token() {
        let plan = enrolled(None, None).plan_join(Some("enr-1"));
        assert!(plan.enroll, "a node that never enrolled must enroll");
        assert_eq!(plan.connect_token, "enr-1");
        assert_eq!(plan.enroll_token, "enr-1");
        assert_eq!(plan.presented_fresh.as_deref(), Some("enr-1"));
    }

    #[test]
    fn relaunch_with_the_same_token_does_not_re_enroll() {
        // The host UI re-presents whatever it persisted, so a token already
        // recorded as consumed must not trigger another `/enroll` — under
        // broker auth that reply is `Consumed`, and a device that replays it
        // on every start can never settle.
        let plan = enrolled(Some("nd-1"), Some("enr-1")).plan_join(Some("enr-1"));
        assert!(!plan.enroll);
        assert_eq!(plan.connect_token, "nd-1");
        assert_eq!(plan.presented_fresh, None);
    }

    #[test]
    fn a_new_token_re_enrolls_but_never_becomes_the_credential() {
        // The case that left an enrolled device invisible forever: it holds a
        // node_token, so it used to skip `/enroll` entirely, and the Gateway
        // never learned who owned it. Re-enrolling must present the new token
        // while CONNECT keeps using the stored one — presenting the enrollment
        // token as the credential gets `NotAuthorized` and flaps the node.
        let plan = enrolled(Some("nd-1"), Some("enr-1")).plan_join(Some("enr-2"));
        assert!(plan.enroll);
        assert_eq!(plan.enroll_token, "enr-2");
        assert_eq!(plan.connect_token, "nd-1");
        assert_eq!(plan.presented_fresh.as_deref(), Some("enr-2"));
    }

    #[test]
    fn join_without_any_token_still_announces_anonymous() {
        // Local/broker-less-auth joins: nothing to present, but the node must
        // still register itself.
        let plan = enrolled(None, None).plan_join(None);
        assert!(plan.enroll);
        assert_eq!(plan.connect_token, "");
        assert_eq!(plan.presented_fresh, None);
    }

    #[test]
    fn mark_enrolled_records_the_token_and_survives_a_reload() {
        let dir = std::env::temp_dir().join(format!(
            "acowork-android-enr-{}-{}",
            std::process::id(),
            now_secs()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let mut id = NodeIdentity::load_or_create(&dir, Some("phone-1"), Some("127.0.0.1:19875"))
            .unwrap();
        id.mark_enrolled(
            "127.0.0.1:19875",
            Some("nd-1".into()),
            Some("enr-1".into()),
        );
        id.save(&dir).unwrap();
        let back = NodeIdentity::load_or_create(&dir, Some("phone-1"), Some("127.0.0.1:19875"))
            .unwrap();
        assert_eq!(back.node_token.as_deref(), Some("nd-1"));
        assert_eq!(
            back.enrolled_with.as_deref(),
            Some("enr-1"),
            "the enrollment record must persist, or every launch replays the token"
        );

        // A later enroll that carried no token of its own must not erase it.
        let mut again = back;
        again.mark_enrolled("127.0.0.1:19875", Some("nd-2".into()), None);
        assert_eq!(again.enrolled_with.as_deref(), Some("enr-1"));
        assert_eq!(again.node_token.as_deref(), Some("nd-2"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
