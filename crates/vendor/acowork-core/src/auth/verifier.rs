//! Ed25519 token verification (ADR-084 §决策 3).
//!
//! Holds only the public key: this is the token surface the Gateway
//! `auth_middleware` keeps after the split, and it can verify but never mint.

use std::path::Path;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};

use super::claims::{Claims, Payload, TokenError, TokenKind};

/// Length of an Ed25519 public key / signature, in bytes.
const PUBLIC_KEY_LEN: usize = 32;
const SIGNATURE_LEN: usize = 64;

/// Verifies login tokens with the Ed25519 public key.
pub struct TokenVerifier {
    key: VerifyingKey,
}

impl TokenVerifier {
    pub fn new(key: VerifyingKey) -> Self {
        Self { key }
    }

    /// Load the raw 32-byte public key from `path`.
    pub fn from_public_key_file(path: &Path) -> Result<Self, String> {
        let bytes = std::fs::read(path)
            .map_err(|e| format!("failed to read token public key {}: {e}", path.display()))?;
        let raw: [u8; PUBLIC_KEY_LEN] = bytes.as_slice().try_into().map_err(|_| {
            format!(
                "token public key at {} must be {PUBLIC_KEY_LEN} bytes, got {}",
                path.display(),
                bytes.len()
            )
        })?;
        let key = VerifyingKey::from_bytes(&raw)
            .map_err(|e| format!("invalid token public key at {}: {e}", path.display()))?;
        Ok(Self { key })
    }

    /// Verify a token's signature, expiry and family binding. Kind is not
    /// enforced here — use [`Self::verify_kind`] to reject a refresh token
    /// presented as an access token (or vice versa).
    pub fn verify(&self, token: &str, now: i64) -> Result<Claims, TokenError> {
        let mut parts = token.split('.');
        let (header, body, sig) = match (parts.next(), parts.next(), parts.next(), parts.next()) {
            (Some(h), Some(b), Some(s), None) => (h, b, s),
            _ => return Err(TokenError::Malformed),
        };

        // Signature first: nothing downstream of this line runs on an
        // unauthenticated payload.
        let sig_bytes = B64.decode(sig).map_err(|_| TokenError::Malformed)?;
        let raw_sig: [u8; SIGNATURE_LEN] =
            sig_bytes.as_slice().try_into().map_err(|_| TokenError::Malformed)?;
        let signature = Signature::from_bytes(&raw_sig);
        let signing_input = format!("{header}.{body}");
        self.key
            .verify(signing_input.as_bytes(), &signature)
            .map_err(|_| TokenError::BadSignature)?;

        let raw = B64.decode(body).map_err(|_| TokenError::Malformed)?;
        let claims = Payload::decode(&raw)?;

        if claims.exp < now {
            return Err(TokenError::Expired);
        }

        // The family must be scoped to the subject (see
        // `Claims::is_family_consistent`). Checked here, not just at sign
        // time, so a hand-crafted payload can never cross-wire revocation
        // wildcards between users.
        if !claims.is_family_consistent() {
            return Err(TokenError::Malformed);
        }

        Ok(claims)
    }

    /// Like [`Self::verify`] but also requires the token to be of `kind`.
    pub fn verify_kind(
        &self,
        token: &str,
        kind: TokenKind,
        now: i64,
    ) -> Result<Claims, TokenError> {
        let claims = self.verify(token, now)?;
        if claims.kind != kind {
            return Err(TokenError::WrongKind);
        }
        Ok(claims)
    }
}
