//! Session config use case (ADR-047 §3.4).
//!
//! All external interfaces (HTTP, MQTT, CLI) go through this trait for
//! session config mutations and reads. Config persistence is immediate
//! (memory + meta.json + MQTT notification); LLM-side effects are
//! deferred to the next inference turn via version polling.

use std::sync::Arc;

use async_trait::async_trait;

use crate::agent::session_config::{SessionConfigDelta, SessionConfigSnapshot};
use crate::error::Result;

/// Signature of the idle-session context-usage recompute callback
/// (ADR-074 §11.1): recompute a session's context usage from its
/// persisted tokens and re-broadcast it, so the UI total refreshes
/// immediately after a `context_window` change on an idle session.
///
/// `session_id` identifies the session. A session with a running loop is
/// skipped inside the callback (the next per-turn usage push takes over).
/// The callback is injected late (Phase B, once `SessionManager` exists)
/// via [`RuntimeSessionConfigService::set_usage_recompute`]; it is
/// fire-and-forget (spawns its own task).
pub type UsageRecompute = Arc<dyn Fn(String) + Send + Sync>;

/// Usecase trait for session config mutations.
///
/// All external interfaces (HTTP, MQTT, CLI) go through this trait.
/// The implementation uses interior mutability (`Arc<RwLock<HashMap>>`),
/// so it can be safely wrapped in `Arc<dyn SessionConfigService>`.
#[async_trait]
pub trait SessionConfigService: Send + Sync {
    /// Apply a config change. Persistence is immediate.
    /// LLM-side effects are deferred to the next inference turn.
    async fn apply_config(&self, session_id: &str, delta: SessionConfigDelta) -> Result<()>;

    /// Read current config (HTTP GET /sessions/{sid}/config).
    async fn get_config(&self, session_id: &str) -> Result<SessionConfigSnapshot>;
}
