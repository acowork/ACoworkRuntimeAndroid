//! Ed25519 token issuance (ADR-084 §决策 3).
//!
//! Holds the signing key. This type only exists inside `acowork-user` (the
//! credential authority) — the Gateway gets [`super::TokenVerifier`] and
//! never sees a private key.

use std::path::{Path, PathBuf};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use ed25519_dalek::{Signer as _, SigningKey};

use super::claims::{ACCESS_TTL_SECS, Payload, REFRESH_TTL_SECS, TokenKind};
use super::verifier::TokenVerifier;

/// The exact header we emit. Verification never reads it back — the
/// signature covers these bytes, and the algorithm is fixed at Ed25519
/// (a caller-supplied `alg` is never trusted).
const HEADER_JSON: &str = r#"{"alg":"EdDSA","typ":"JWT"}"#;

/// Mints login tokens with the Ed25519 private key (ADR-084 §决策 3).
///
/// Deliberately exposes **no** `verify`: the ADR puts signing in
/// `acowork-user` and verification in the Gateway, so the Gateway must not
/// be able to reach this type.
pub struct TokenIssuer {
    key: SigningKey,
}

impl TokenIssuer {
    /// Build an issuer from an Ed25519 signing key.
    pub fn new(key: SigningKey) -> Self {
        Self { key }
    }

    /// The public half, for a co-located verifier.
    ///
    /// Used by the single-process tests and by the Gateway during the
    /// M0→M1 migration window, where signing has not moved out yet. After
    /// M1 the Gateway loads a [`TokenVerifier`] from the public-key file
    /// instead and never constructs an issuer.
    pub fn verifier(&self) -> TokenVerifier {
        TokenVerifier::new(self.key.verifying_key())
    }

    /// Load the signing key from `key_path`, generating and persisting a
    /// fresh pair on first run.
    ///
    /// Persists two files:
    /// - `key_path` — the raw 32-byte private seed, `0600` on Unix. It mints
    ///   logins, so it must not be world-readable.
    /// - [`public_key_path`] — the raw 32-byte public key, re-written on
    ///   every load so a missing or stale copy self-heals before the
    ///   Gateway tries to read it.
    ///
    /// Both writes are atomic (temp sibling + rename): a bare write could
    /// leave a truncated key on crash, and a short key would invalidate
    /// every live session at next boot.
    pub fn load_or_generate(key_path: &Path) -> Result<Self, String> {
        let key = match std::fs::read(key_path) {
            Ok(bytes) => {
                let seed: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
                    format!(
                        "auth signing key at {} must be 32 bytes, got {}",
                        key_path.display(),
                        bytes.len()
                    )
                })?;
                SigningKey::from_bytes(&seed)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let mut seed = [0u8; 32];
                rand::fill(&mut seed);
                let key = SigningKey::from_bytes(&seed);
                if let Some(parent) = key_path.parent() {
                    std::fs::create_dir_all(parent)
                        .map_err(|e| format!("failed to create auth dir: {e}"))?;
                }
                write_owner_only(key_path, &seed)?;
                tracing::info!(path = %key_path.display(), "generated new auth signing key");
                key
            }
            Err(e) => {
                return Err(format!(
                    "failed to read auth signing key {}: {e}",
                    key_path.display()
                ));
            }
        };

        let pub_path = public_key_path(key_path);
        write_atomic(&pub_path, &key.verifying_key().to_bytes())?;
        Ok(Self { key })
    }

    /// Sign a short-lived access token.
    pub fn sign_access(&self, user_id: &str, role: &str, now: i64) -> String {
        self.sign(&Payload {
            sub: user_id.to_string(),
            role: Some(role.to_string()),
            family: None,
            kind: TokenKind::Access.as_str().to_string(),
            iat: now,
            exp: now + ACCESS_TTL_SECS,
        })
    }

    /// Sign a long-lived refresh token belonging to `family`.
    ///
    /// The family must be scoped to the subject (`{user_id}.{random}`) —
    /// revocation wildcards depend on it. An unscoped family is a
    /// programming error, so it panics in debug and is rejected at verify
    /// time regardless.
    pub fn sign_refresh(&self, user_id: &str, family: &str, now: i64) -> String {
        debug_assert!(
            family.starts_with(&format!("{user_id}.")),
            "refresh family must be scoped to its subject: {family} for {user_id}"
        );
        self.sign(&Payload {
            sub: user_id.to_string(),
            role: None,
            family: Some(family.to_string()),
            kind: TokenKind::Refresh.as_str().to_string(),
            iat: now,
            exp: now + REFRESH_TTL_SECS,
        })
    }

    fn sign(&self, payload: &Payload) -> String {
        let header = B64.encode(HEADER_JSON);
        let body = B64.encode(payload.encode());
        let signing_input = format!("{header}.{body}");
        let sig = self.key.sign(signing_input.as_bytes());
        format!("{signing_input}.{}", B64.encode(sig.to_bytes()))
    }
}

/// The public-key file beside the private key (`ed25519.key` → `ed25519.pub`).
pub fn public_key_path(key_path: &Path) -> PathBuf {
    key_path.with_extension("pub")
}

#[cfg(unix)]
fn write_owner_only(path: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let tmp = path.with_extension("tmp");
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)
        .map_err(|e| format!("failed to create auth signing key: {e}"))?;
    f.write_all(bytes)
        .map_err(|e| format!("failed to write auth signing key: {e}"))?;
    f.sync_all()
        .map_err(|e| format!("failed to sync auth signing key: {e}"))?;
    commit(&tmp, path, "auth signing key")
}

#[cfg(not(unix))]
fn write_owner_only(path: &Path, bytes: &[u8]) -> Result<(), String> {
    write_atomic(path, bytes)
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, bytes).map_err(|e| format!("failed to write {}: {e}", path.display()))?;
    commit(&tmp, path, "token key")
}

fn commit(tmp: &Path, path: &Path, what: &str) -> Result<(), String> {
    std::fs::rename(tmp, path).map_err(|e| {
        let _ = std::fs::remove_file(tmp);
        format!("failed to commit {what}: {e}")
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::TokenError;

    /// Fixed seed so tests are deterministic; the *value* is irrelevant.
    fn issuer() -> TokenIssuer {
        TokenIssuer::new(SigningKey::from_bytes(&[7u8; 32]))
    }

    fn verifier() -> TokenVerifier {
        issuer().verifier()
    }

    fn temp_dir(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("acowork-auth-{tag}-{nanos}"));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn access_roundtrip() {
        let t = issuer().sign_access("u-1", "admin", 1000);
        let c = verifier().verify(&t, 1001).unwrap();
        assert_eq!(c.sub, "u-1");
        assert_eq!(c.role.as_deref(), Some("admin"));
        assert!(c.is_admin());
        assert_eq!(c.kind, TokenKind::Access);
        assert_eq!(c.exp, 1000 + ACCESS_TTL_SECS);
    }

    #[test]
    fn refresh_roundtrip_and_kind_check() {
        // Family is minted as `{user_id}.{random}` — scoped to the subject.
        let t = issuer().sign_refresh("u-1", "u-1.fam-9", 1000);
        let c = verifier().verify(&t, 1001).unwrap();
        assert_eq!(c.family.as_deref(), Some("u-1.fam-9"));
        assert_eq!(c.kind, TokenKind::Refresh);
        assert!(c.is_family_consistent());

        // A refresh token must not pass an access check.
        assert_eq!(
            verifier().verify_kind(&t, TokenKind::Access, 1001),
            Err(TokenError::WrongKind)
        );
    }

    #[test]
    fn refresh_family_must_match_subject() {
        let s = issuer();
        let v = verifier();
        // Hand-craft a refresh token whose family belongs to a *different*
        // user. If accepted, `u-2` would match the `u-1.*` wildcard when
        // user 1's password changes. Verify must reject it.
        let cross_user = s.sign(&Payload {
            sub: "u-2".into(),
            role: None,
            family: Some("u-1.abc".into()),
            kind: "refresh".into(),
            iat: 1000,
            exp: 1000 + REFRESH_TTL_SECS,
        });
        assert_eq!(v.verify(&cross_user, 1001), Err(TokenError::Malformed));

        // Same-subject family verifies; an adjacent id (`u-10`) must not
        // accidentally satisfy the `u-1.` prefix.
        assert!(v.verify(&s.sign_refresh("u-1", "u-1.abc", 1000), 1001).is_ok());
        let adjacent = s.sign(&Payload {
            sub: "u-10".into(),
            role: None,
            family: Some("u-1.abc".into()),
            kind: "refresh".into(),
            iat: 1000,
            exp: 1000 + REFRESH_TTL_SECS,
        });
        assert_eq!(v.verify(&adjacent, 1001), Err(TokenError::Malformed));
    }

    #[test]
    fn expired_token_rejected() {
        let t = issuer().sign_access("u-1", "user", 1000);
        assert_eq!(
            verifier().verify(&t, 1000 + ACCESS_TTL_SECS + 1),
            Err(TokenError::Expired)
        );
    }

    #[test]
    fn tampered_payload_rejected() {
        let t = issuer().sign_access("u-1", "user", 1000);
        let parts: Vec<&str> = t.split('.').collect();
        // Swap in a payload claiming admin, keeping the original signature.
        let forged = B64.encode(
            Payload {
                sub: "u-1".into(),
                role: Some("admin".into()),
                family: None,
                kind: "access".into(),
                iat: 1000,
                exp: 1000 + ACCESS_TTL_SECS,
            }
            .encode(),
        );
        let forged_token = format!("{}.{}.{}", parts[0], forged, parts[2]);
        assert_eq!(
            verifier().verify(&forged_token, 1001),
            Err(TokenError::BadSignature)
        );
    }

    /// The signature covers the header, and the verifier ignores the `alg`
    /// it names — so rewriting the header to `alg=none` (the classic JWT
    /// forgery) still fails. Guards against a future "optimisation" that
    /// starts reading `alg` back out.
    #[test]
    fn header_tampering_rejected() {
        let t = issuer().sign_access("u-1", "admin", 1000);
        let parts: Vec<&str> = t.split('.').collect();
        let header = B64.encode(r#"{"alg":"none","typ":"JWT"}"#);
        let forged = format!("{header}.{}.{}", parts[1], parts[2]);
        assert_eq!(verifier().verify(&forged, 1001), Err(TokenError::BadSignature));
    }

    #[test]
    fn wrong_key_rejected() {
        let t = issuer().sign_access("u-1", "user", 1000);
        let other = TokenIssuer::new(SigningKey::from_bytes(&[9u8; 32])).verifier();
        assert_eq!(other.verify(&t, 1001), Err(TokenError::BadSignature));
    }

    #[test]
    fn malformed_rejected() {
        let v = verifier();
        assert_eq!(v.verify("not-a-token", 1000), Err(TokenError::Malformed));
        assert_eq!(v.verify("a.b", 1000), Err(TokenError::Malformed));
        assert_eq!(v.verify("a.b.c.d", 1000), Err(TokenError::Malformed));
        // Valid base64, wrong length — must not panic on the array cast.
        assert_eq!(v.verify("a.b.c", 1000), Err(TokenError::Malformed));
    }

    #[test]
    fn key_is_persisted_and_reused() {
        let dir = temp_dir("persist");
        let path = dir.join("ed25519.key");

        let s1 = TokenIssuer::load_or_generate(&path).unwrap();
        let s2 = TokenIssuer::load_or_generate(&path).unwrap();
        // Reusing the on-disk key keeps a token minted by s1 valid under s2.
        let t1 = s1.sign_access("u-1", "user", 1000);
        assert!(s2.verifier().verify(&t1, 1001).is_ok());

        // The public key lands beside the private key, and a verifier can
        // boot from it alone — the M3 Gateway path.
        let pub_path = public_key_path(&path);
        assert!(pub_path.exists(), "public key must be written");
        let from_file = TokenVerifier::from_public_key_file(&pub_path).unwrap();
        assert!(from_file.verify(&t1, 1001).is_ok());

        // An unrelated key still rejects it.
        assert!(verifier().verify(&t1, 1001).is_err());

        // Atomic writes: no temp sibling left behind.
        assert!(!path.with_extension("tmp").exists());
        // Unix: the private key must be owner-only (0600).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "auth signing key must be 0600");
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn short_key_file_rejected() {
        let dir = temp_dir("short");
        let path = dir.join("ed25519.key");
        std::fs::write(&path, [0u8; 16]).unwrap();
        assert!(TokenIssuer::load_or_generate(&path).is_err());

        let pub_path = dir.join("ed25519.pub");
        std::fs::write(&pub_path, [0u8; 16]).unwrap();
        assert!(TokenVerifier::from_public_key_file(&pub_path).is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
