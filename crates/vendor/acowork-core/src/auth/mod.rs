//! Shared login-token contract (ADR-084 §决策 3).
//!
//! Extracted from the Gateway (`acowork-gateway/src/auth/token.rs`, formerly
//! HS256) so that the two halves of the split can share one codec without
//! depending on each other:
//!
//! - [`TokenIssuer`] — holds the Ed25519 **private** key. The credential
//!   authority lives in `acowork-user`.
//! - [`TokenVerifier`] — holds the Ed25519 **public** key. Loaded by the
//!   Gateway `auth_middleware` for the per-request check.
//!
//! Asymmetric on purpose: the Gateway verifies but cannot mint, so neither a
//! Gateway compromise nor a Gateway code path can hand out a login.
//!
//! ## Wire format
//!
//! A minimal JWT: `base64url(header).base64url(payload).base64url(sig)` with
//! header `{"alg":"EdDSA","typ":"JWT"}`. The header is **never read back** —
//! verification is always Ed25519 over the signing input, which closes the
//! classic `alg=none` forgery vector. The signature covers the header bytes,
//! so tampering with them still fails verification.
//!
//! Two token kinds share the codec:
//! - **access** — short-lived (15 min), carries `sub` + `role`.
//! - **refresh** — long-lived (30 days), carries `sub` + `family`. A family
//!   is rotated on every refresh; revoking a family kills every refresh token
//!   descended from it.

mod claims;
mod issuer;
mod verifier;

/// Trusted-identity headers the Gateway injects for the user service
/// (ADR-084 §决策 7).
///
/// Defined here, not in either process, because the two sides are separate
/// binaries and a one-sided rename would otherwise be a silent wire break.
/// The Gateway is their **only** trusted writer; both the Gateway's proxy and
/// the service's identity layer re-check that they agree.
pub const AUTH_USER_HEADER: &str = "x-auth-user";
/// Authenticated role (`admin` / `user`).
pub const AUTH_ROLE_HEADER: &str = "x-auth-role";
/// Admin-only "view as user X" scope (ADR-076 §决策 4).
pub const AUTH_AS_USER_HEADER: &str = "x-auth-as-user";

/// Machine credential a Node Agent presents to the Gateway's HTTP API
/// (ADR-055 Phase 5a, extended to agent→Gateway calls by ADR-076).
///
/// The Gateway's `auth_middleware` accepts the node's long-lived token on
/// this header as a trusted internal actor, so the holder may call any
/// `/api/*` route. It is **node-scoped, not agent- or user-scoped**: every
/// Runtime the node hosts presents the same value, and so does the node
/// itself (enrollment reconnect, package download).
///
/// The Gateway stamps this header's value as a [`NODE_TOKEN_TEMPLATE`]
/// placeholder on the MCP entries it injects itself (pm / doc), so the
/// credential reaches the Runtime without the Gateway ever seeing — or
/// persisting — a per-agent copy.
pub const NODE_TOKEN_HEADER: &str = "X-ACowork-Node-Token";

/// Placeholder the Gateway writes into [`NODE_TOKEN_HEADER`] when it
/// publishes the pm / doc MCP entries to `acowork/global/mcps`.
///
/// The Gateway has no per-Runtime token to substitute (the value is
/// node-scoped and the Gateway only mints it at enrollment), so it
/// publishes the template and the Runtime resolves it at connect time
/// from the credential the Node injected at spawn. Mirrors the existing
/// `{instance_id}` / `{agent_id}` template convention.
pub const NODE_TOKEN_TEMPLATE: &str = "{node_token}";

pub use claims::{ACCESS_TTL_SECS, REFRESH_TTL_SECS, Claims, TokenError, TokenKind, now_unix};
pub use issuer::TokenIssuer;
pub use verifier::TokenVerifier;
