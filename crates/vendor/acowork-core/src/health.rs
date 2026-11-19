//! Health and SSE event contracts for Gateway-managed subprocesses.
//!
//! Every Gateway-managed subprocess (embed, LSP relay, etc.) MUST expose
//! `GET /health` and `GET /events` (SSE) endpoints conforming to these
//! contracts. The Gateway supervisor uses `/health` for bootstrap and
//! `/events` for ongoing liveness monitoring.
//!
//! # `/health` endpoint
//!
//! Returns a [`HealthResponse`] JSON body. The `status` field uses one of:
//! - `"ok"` — process is healthy and serving requests
//! - `"degraded"` — process is running but with reduced functionality
//! - `"starting"` — process is still initializing
//!
//! # `/events` endpoint (SSE)
//!
//! Streams [`BusEvent`]s as SSE frames. Event names are defined in
//! [`sse_event`]. The supervisor watches for `heartbeat` events (2s cadence)
//! and treats a 10s gap as a stuck process.

use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Standard health check response that every Gateway-managed subprocess
/// MUST return from `GET /health`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    /// "ok" | "degraded" | "starting"
    pub status: String,
    /// Process version (from CARGO_PKG_VERSION)
    pub version: String,
    /// Process name for diagnostics (e.g. "acowork-embed", "acowork-lsp-relay")
    pub process: String,
    /// Process-specific payload (model info for embed, language count for LSP relay)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

/// Standard SSE event names used by the supervisor.
pub mod sse_event {
    /// Periodic liveness signal (2s cadence).
    pub const HEARTBEAT: &str = "heartbeat";
    /// Application-level state transition.
    pub const STATE: &str = "state";
}

/// Recommended constants for supervisor configuration.
pub mod supervisor_defaults {
    use super::Duration;

    /// Heartbeat cadence from the subprocess (ms).
    pub const HEARTBEAT_INTERVAL_MS: u64 = 2000;
    /// Max gap between heartbeats before the supervisor considers the process stuck.
    pub const HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(10);
    /// Grace period after spawn before connection failures count as restart triggers.
    pub const STARTUP_GRACE: Duration = Duration::from_secs(10);
    /// Poll interval during startup grace.
    pub const STARTUP_POLL: Duration = Duration::from_secs(2);
    /// Minimum backoff between restart attempts.
    pub const RESTART_BACKOFF_MIN: Duration = Duration::from_secs(1);
    /// Maximum backoff between restart attempts.
    pub const RESTART_BACKOFF_MAX: Duration = Duration::from_secs(60);
    /// Sliding window for counting restart attempts.
    pub const RESTART_WINDOW: Duration = Duration::from_secs(5 * 60);
    /// Give up after this many restarts within `RESTART_WINDOW`.
    pub const MAX_RESTART_ATTEMPTS: u32 = 5;
    /// Max time an alive-but-unresponsive embed is tolerated before the
    /// supervisor force-kills and restarts it. A zombie PID keeps the
    /// "process alive" check true forever, so without this cap the
    /// supervisor would wait indefinitely instead of self-healing.
    pub const EMBED_STALE_TIMEOUT: Duration = Duration::from_secs(30);
}
