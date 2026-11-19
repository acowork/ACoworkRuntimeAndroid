//! SessionHandle: external handle for interacting with a SessionTask.
//!
//! Provides a typed interface for sending messages to a session and
//! checking whether the session task is still alive.

use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;

use tokio::sync::mpsc;
use tokio::sync::watch;
use tokio::task::JoinHandle;

use super::session_task::SessionMessage;
use crate::agent::inbound::InboundMessage;
use crate::agent::session_state::{SessionRuntimeSnapshot, SessionStatus};
use crate::conversation::ConversationSession;
use crate::debug::DebugHandles;

/// External handle for interacting with a running SessionTask.
///
/// Callers (e.g., Gateway, Desktop App) use this handle to send
/// messages to a specific session without needing direct access to
/// the SessionTask or its AgentLoop.
pub struct SessionHandle {
    /// Unique session identifier
    pub session_id: String,
    /// Channel for sending messages to the SessionTask
    pub(crate) inbound_tx: mpsc::Sender<SessionMessage>,
    /// Direct sender into the underlying AgentLoop's inbound channel.
    ///
    /// Used to deliver pause-resume signals (Continue / Interrupt) WITHOUT
    /// going through SessionTask's main receive loop — which would otherwise
    /// deadlock whenever the AgentLoop is awaiting a Continue (the main
    /// loop cannot consume further SessionMessage values while blocked on
    /// `agent_loop.run().await`).
    pub(crate) agent_inbound_tx: mpsc::Sender<InboundMessage>,
    /// Join handle for the session's tokio task (for lifecycle observation)
    pub(crate) join_handle: JoinHandle<()>,
    /// Watch channel receiver for session status (ADR-014).
    /// The AgentLoop updates its status via the Sender half;
    /// the SessionHandle exposes this Receiver so SessionManager
    /// can read the current status without locking.
    pub(crate) status_rx: watch::Receiver<SessionStatus>,
    /// Timestamp of the last activity (message send, status change, etc.).
    /// Used by `SessionManager::evict_idle_sessions` to decide when a
    /// session can be safely released from memory.
    pub(crate) last_active_at: Mutex<Instant>,
    /// Shared pending debug handles for bypass injection while the agent
    /// loop is running. SessionManager writes the handles here when
    /// enabling debug mode on an active session, so the AgentLoop can
    /// pick them up at the start of each iteration without going through
    /// the SessionTask message channel (which is blocked on .run()).
    pub(crate) pending_debug_handles: Arc<tokio::sync::Mutex<Option<DebugHandles>>>,
    /// Shared snapshot of per-session state for the Gateway pull API.
    ///
    /// Owned by [`SessionState`]; shared with SessionHandle so
    /// [`SessionManager::snapshot_session_state`] can read it directly.
    /// Written by [`AgentLoop::emit_session_state`] on every status transition.
    pub(crate) snapshot: Arc<std::sync::RwLock<SessionRuntimeSnapshot>>,
    /// Per-session workspace ID. Single source of truth, shared with [`SessionCore`].
    /// Written synchronously by [`SessionManager::set_session_workspace`],
    /// read by `list_sessions` and `session_workspace_id`.
    pub(crate) workspace_id: Arc<RwLock<String>>,
    /// Resolved workspace directory path, shared with [`SessionCore`].
    /// Written synchronously by SessionManager alongside `workspace_id`,
    /// read by the HTTP tree/find handlers.
    pub(crate) current_work_dir: Arc<RwLock<Option<String>>>,
    /// ADR-047: shared conversation session handle.
    ///
    /// Allows `SessionManager` to call `ConversationSession::apply_config()`
    /// directly, bypassing the serial inference queue. `None` for sessions
    /// without persistent conversation (e.g. ephemeral sessions).
    pub(crate) conversation: Option<Arc<ConversationSession>>,
}

impl SessionHandle {
    /// Send a message to this session.
    ///
    /// Returns an error if the session task has stopped and the channel
    /// is closed, or if the channel is full.
    pub fn send(
        &self,
        msg: SessionMessage,
    ) -> Result<(), Box<tokio::sync::mpsc::error::TrySendError<SessionMessage>>> {
        self.touch();
        self.inbound_tx.try_send(msg).map_err(Box::new)
    }

    /// Deliver an out-of-band signal directly to the AgentLoop, bypassing
    /// SessionTask's main loop.
    ///
    /// This is the ONLY reliable path for Continue/Interrupt signals while
    /// the AgentLoop is blocked awaiting pause-resume: SessionTask cannot
    /// relay them because its own receive loop is suspended inside
    /// `agent_loop.run().await`.
    pub fn send_inbound(
        &self,
        msg: InboundMessage,
    ) -> Result<(), Box<tokio::sync::mpsc::error::TrySendError<InboundMessage>>> {
        self.touch();
        self.agent_inbound_tx.try_send(msg).map_err(Box::new)
    }

    /// Check whether the session task is still running.
    ///
    /// Returns `false` if the JoinHandle has been consumed (task completed)
    /// or if the inbound channel is closed.
    pub fn is_alive(&self) -> bool {
        !self.join_handle.is_finished() && !self.inbound_tx.is_closed()
    }

    /// Read the current session status (ADR-014).
    ///
    /// Uses a watch channel, so this is lock-free and non-blocking.
    /// The value is always the most recent status written by the AgentLoop.
    pub fn status(&self) -> SessionStatus {
        self.status_rx.borrow().clone()
    }

    /// Update `last_active_at` to now. Called automatically on `send`/`send_inbound`.
    pub fn touch(&self) {
        *self
            .last_active_at
            .lock()
            .expect("last_active_at mutex poisoned") = Instant::now();
    }

    /// Read the last active timestamp.
    pub fn last_active_at(&self) -> Instant {
        *self
            .last_active_at
            .lock()
            .expect("last_active_at mutex poisoned")
    }

    /// Read the current session state snapshot (for the Gateway pull API).
    ///
    /// Returns a clone of the snapshot shared with [`SessionState`].
    /// Always returns a value — the snapshot is initialized with defaults
    /// in [`SessionState::new`] and populated with persistent data during
    /// [`build_initial_session_state`].
    pub fn snapshot(&self) -> SessionRuntimeSnapshot {
        self.snapshot
            .read()
            .ok()
            .map(|guard| guard.clone())
            .unwrap_or_else(|| {
                // Fallback: return a minimal snapshot if the lock is poisoned.
                SessionRuntimeSnapshot {
                    session_id: self.session_id.clone(),
                    status: r#""idle""#.to_string(),
                    model: None,
                    provider: None,
                    account_id: None,
                    ratio: None,
                    todos_json: None,
                    context_usage: None,
                }
            })
    }
}
