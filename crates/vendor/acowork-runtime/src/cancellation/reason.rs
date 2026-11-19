//! Cancellation reason taxonomy.
//!
//! Provides structured metadata for *why* a [`CancelHandle`](super::CancelHandle)
//! was flipped, so downstream code (logging, telemetry, user-visible error
//! messages) can disambiguate "user pressed Stop" from "budget exhausted".
//!
//! Phase 1 keeps the surface minimal: `Debug + Clone + PartialEq + Display`.
//! A future telemetry phase may add `serde::Serialize` if a structured pipeline
//! is wired in — no serde dependency is introduced here to keep Phase 1 scope
//! strictly bounded.

use std::fmt;

/// Why a [`CancelHandle`](super::CancelHandle) was cancelled.
///
/// `UserStop` carries both the *source* (which UI surface initiated the cancel)
/// and a free-form *reason* string supplied by that source (e.g. "user_requested",
/// "timeout", "rate_limited"). Other variants are explicit enum members because
/// they have well-defined semantics in the runtime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CancellationReason {
    /// A user-facing surface (ChatPanel, Debug server, CLI, test harness) requested
    /// the operation to stop.
    UserStop { source: StopSource, reason: String },
    /// Debugger paused execution (distinct from stop — see ADR §4.3).
    Pause,
    /// Debugger explicitly stopped the agent (rare; usually via `Pause + kill`).
    DebugStop,
    /// The agent exceeded its iteration budget (see ADR-014).
    IterationLimit,
    /// The agent exceeded its token / cost budget.
    BudgetExceeded(String),
    /// The owning session was closed (cleanup path).
    SessionClosed,
    /// Internal error path used by callers that need to surface a non-standard
    /// abort reason without adding a new enum variant.
    Error(String),
}

/// Where a stop request originated.
///
/// Useful for routing / permission checks: e.g. `StopSource::Cli` may bypass
/// certain safety prompts that `StopSource::ChatPanel` would not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StopSource {
    ChatPanel {
        agent_id: String,
        session_id: String,
    },
    DebugServer,
    Cli,
    Test,
}

impl fmt::Display for CancellationReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UserStop { source, reason } => {
                write!(f, "user_stop[source={}, reason=\"{}\"]", source, reason)
            }
            Self::Pause => write!(f, "pause"),
            Self::DebugStop => write!(f, "debug_stop"),
            Self::IterationLimit => write!(f, "iteration_limit"),
            Self::BudgetExceeded(msg) => write!(f, "budget_exceeded(\"{}\")", msg),
            Self::SessionClosed => write!(f, "session_closed"),
            Self::Error(msg) => write!(f, "error(\"{}\")", msg),
        }
    }
}

impl fmt::Display for StopSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ChatPanel {
                agent_id,
                session_id,
            } => write!(f, "chat_panel[agent={}, session={}]", agent_id, session_id),
            Self::DebugServer => write!(f, "debug_server"),
            Self::Cli => write!(f, "cli"),
            Self::Test => write!(f, "test"),
        }
    }
}
