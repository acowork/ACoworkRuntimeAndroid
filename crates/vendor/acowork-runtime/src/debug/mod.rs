//! Debug protocol module for Agent Runtime DevMode.
//!
//! ADR-048: the Debug Protocol runs on the same transports as the
//! production IPC channels - HTTP REST for RPC, MQTT pub/sub for
//! events:
//!
//! - [`protocol`]: shared data types (DebugPhase, ContextSections, ...)
//! - [`controller`]: DebugController - shared state (execution control, snapshots)
//! - [`events`]: [`DebugEventBus`] + [`DebugEventSender`] - broadcast
//!   event channel consumed by the MQTT publisher
//! - [`handlers`]: Debug RPC business logic (thin, transport-free)
//! - [`observer`]: [`DebugObserver`] trait + [`DebugObserverSlot`] enum dispatch
//! - [`observer_impl`]: [`DebugObserverImpl`] - concrete DevMode implementation
//!
//! RPC flow: `http/debug.rs` (axum routes) -> `usecases::DebugService`
//! -> `handlers` (this module). Event flow: AgentLoop ->
//! `DebugEventSender` -> `DebugEventBus` -> MQTT publisher ->
//! `acowork/agents/{id}/debug/events/{event_type}`.
//!
//! The legacy WebSocket + JSON-RPC server was removed by ADR-048 D4;
//! see `docs/adr/zh/ADR-048-debug-protocol-mqtt-http.md`.

use std::sync::Arc;
use tokio::sync::Notify;

use crate::debug::controller::DebugController;

pub mod controller;
pub mod events;
pub mod handlers;
pub mod observer;
pub mod observer_impl;
pub mod protocol;

// Re-export the primary types for convenience.
pub use events::{DebugEvent, DebugEventBus, DebugEventSender, TaggedEvent};
pub use observer::{ContextSnapshotRequest, DebugObserverSlot};
pub use observer_impl::DebugObserverImpl;

/// Bundle of debug-related handles injected into an AgentCore by SessionManager.
///
/// Each session gets its own independent instance so that debug state
/// (iteration counter, snapshots) is isolated per session.
#[derive(Clone)]
pub struct DebugHandles {
    pub debug_ctrl: Arc<tokio::sync::Mutex<DebugController>>,
    pub debug_event_tx: DebugEventSender,
    pub rewind_notify: Arc<Notify>,
    pub resume_notify: Arc<Notify>,
    /// Unified control-signal notify shared with `AgentCore::urgent_stop`.
    /// Fired by debug server (pause/stop) and chat-panel stop path so that
    /// every blocking `select!` in the agent loop wakes up immediately.
    pub control_notify: Arc<Notify>,
}
