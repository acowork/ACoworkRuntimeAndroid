//! Token payload, claims and the invariants that hold for both halves of
//! the contract (ADR-084 §决策 3).
//!
//! Moved from `acowork-gateway/src/auth/token.rs` verbatim: claim semantics
//! (`is_family_consistent`, `is_admin`), the two token kinds and the error
//! taxonomy are unchanged by the Ed25519 switch.

use serde::{Deserialize, Serialize};

/// Access-token lifetime (ADR-076 §决策 3).
pub const ACCESS_TTL_SECS: i64 = 15 * 60;
/// Refresh-token lifetime (ADR-076 §决策 3).
pub const REFRESH_TTL_SECS: i64 = 30 * 24 * 3600;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenKind {
    Access,
    Refresh,
}

impl TokenKind {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Access => "access",
            Self::Refresh => "refresh",
        }
    }

    fn parse(raw: &str) -> Option<Self> {
        match raw {
            "access" => Some(Self::Access),
            "refresh" => Some(Self::Refresh),
            _ => None,
        }
    }
}

/// Verified token payload.
#[derive(Debug, Clone, PartialEq)]
pub struct Claims {
    /// Subject — the `user_id`.
    pub sub: String,
    /// Role (`"user"` / `"admin"`); present on access tokens only.
    pub role: Option<String>,
    /// Refresh-token family id; present on refresh tokens only.
    pub family: Option<String>,
    pub kind: TokenKind,
    /// Issued-at (unix seconds).
    pub iat: i64,
    /// Expiry (unix seconds).
    pub exp: i64,
}

impl Claims {
    pub fn is_admin(&self) -> bool {
        self.role.as_deref() == Some("admin")
    }

    /// Whether this claim's refresh `family` is scoped to its subject.
    ///
    /// A family is minted as `{user_id}.{random}`, and revocation uses a
    /// `{user_id}.*` wildcard prefix. If the family ever belonged to a
    /// *different* subject it would match that subject's wildcard instead of
    /// its own — an authorization blur — so the binding is checked at verify
    /// time, not just at sign time.
    pub fn is_family_consistent(&self) -> bool {
        match &self.family {
            Some(f) => f.starts_with(&format!("{}.", self.sub)),
            None => true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenError {
    Malformed,
    BadSignature,
    Expired,
    WrongKind,
}

impl std::fmt::Display for TokenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Malformed => "malformed token",
            Self::BadSignature => "invalid token signature",
            Self::Expired => "token expired",
            Self::WrongKind => "wrong token kind",
        };
        f.write_str(s)
    }
}

impl std::error::Error for TokenError {}

/// The JSON body inside a token. Shared by [`super::TokenIssuer`] (writes)
/// and [`super::TokenVerifier`] (reads) — not part of the public API.
#[derive(Serialize, Deserialize)]
pub(crate) struct Payload {
    pub(crate) sub: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) role: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) family: Option<String>,
    pub(crate) kind: String,
    pub(crate) iat: i64,
    pub(crate) exp: i64,
}

impl Payload {
    pub(crate) fn encode(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("payload serializes")
    }

    /// Parse the body into [`Claims`], rejecting an unknown `kind`.
    ///
    /// Clock and family checks are the caller's job — see
    /// [`super::TokenVerifier::verify`], which runs them *after* the
    /// signature check.
    pub(crate) fn decode(raw: &[u8]) -> Result<Claims, TokenError> {
        let p: Payload = serde_json::from_slice(raw).map_err(|_| TokenError::Malformed)?;
        let kind = TokenKind::parse(&p.kind).ok_or(TokenError::Malformed)?;
        Ok(Claims {
            sub: p.sub,
            role: p.role,
            family: p.family,
            kind,
            iat: p.iat,
            exp: p.exp,
        })
    }
}

/// Current unix time in seconds.
pub fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claims(sub: &str, family: Option<&str>) -> Claims {
        Claims {
            sub: sub.to_string(),
            role: None,
            family: family.map(str::to_string),
            kind: TokenKind::Refresh,
            iat: 0,
            exp: 0,
        }
    }

    #[test]
    fn family_must_be_scoped_to_its_subject() {
        assert!(claims("u-1", Some("u-1.fam")).is_family_consistent());
        // A family belonging to another subject would match *that*
        // subject's revocation wildcard — the blur this guards against.
        assert!(!claims("u-1", Some("u-2.fam")).is_family_consistent());
        // Access tokens carry no family.
        assert!(claims("u-1", None).is_family_consistent());
    }

    #[test]
    fn admin_role_only_for_the_admin_claim() {
        let mut c = claims("u-1", None);
        assert!(!c.is_admin());
        c.role = Some("admin".to_string());
        assert!(c.is_admin());
        c.role = Some("user".to_string());
        assert!(!c.is_admin());
    }

    #[test]
    fn unknown_kind_is_malformed() {
        let raw = br#"{"sub":"u-1","kind":"sudo","iat":0,"exp":0}"#;
        assert_eq!(Payload::decode(raw), Err(TokenError::Malformed));
    }
}
