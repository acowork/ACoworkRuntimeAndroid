//! Debug event bus (ADR-048).
//!
//! Replaces the legacy WebSocket event channel that lived in
//! `debug/server.rs`. The event bus is a `tokio::sync::broadcast`
//! channel carrying [`TaggedEvent`]s pushed by the AgentLoop:
//!
//! - **Producers**: per-session [`DebugEventSender`] handles (tag each
//!   event with the session ID at send time).
//! - **Consumer**: `mqtt::debug_events::DebugEventMqttPublisher`
//!   subscribes once and forwards every event to the MQTT broker on
//!   `acowork/agents/{agent_id}/debug/events/{event_type}` (QoS 0,
//!   not retained). The Desktop App subscribes there - see ADR-048
//!   §2.4.
//!
//! RPC (step / pause / resume / getState / ...) no longer flows
//! through this module at all: it goes over HTTP REST via
//! `http/debug.rs` -> `usecases::DebugService` -> `debug::handlers`.
//!
//! Why `broadcast` and not `mpsc`: the transport is pluggable and
//! there may be more than one consumer (e.g. a future in-process
//! recorder for `DebugRecordStepEvent`). Each subscriber owns its own
//! lag tracking; a slow subscriber never blocks the AgentLoop.

use tokio::sync::broadcast;

use super::protocol::{self, DebugPhase};

/// Buffer size for the debug event broadcast channel. With ~1-2 events
/// per iteration, 1024 is plenty for a developer tool. A subscriber
/// that falls behind gets `RecvError::Lagged` and re-syncs by calling
/// `GET /api/debug/state`.
const DEBUG_EVENT_CHANNEL_CAPACITY: usize = 1024;

// ── Event Types ───────────────────────────────────────────────────────

/// Events that AgentLoop can push to the debug event bus.
#[derive(Debug, Clone)]
pub enum DebugEvent {
    /// Agent execution state changed (paused, resumed, etc.)
    StateChanged {
        old_phase: DebugPhase,
        new_phase: DebugPhase,
        iteration: u32,
    },
    /// A conversation step completed
    Step {
        iteration: u32,
        phase: DebugPhase,
        input: Option<serde_json::Value>,
        output: Option<serde_json::Value>,
        usage: Option<protocol::DebugUsage>,
    },
    /// Context was built for an iteration
    ContextBuilt {
        iteration: u32,
        sections: protocol::ContextSections,
        total_token_estimate: usize,
        /// ADR-054 step 2: control params of the ChatRequest that built
        /// this snapshot — carried on the event so the panel's metadata
        /// bar renders without a follow-up RPC.
        request_params: protocol::RequestParams,
    },
    /// Execution state changed (Running/Paused/Stepping/Stopped)
    ExecutionStateChanged {
        new_state: super::controller::DebugState,
        iteration: u32,
    },
}

/// Wrapper that tags an event with its originating session ID.
///
/// `pub(crate)` visibility: the MQTT publisher
/// (`mqtt::debug_events::DebugEventMqttPublisher`) receives the raw
/// tagged events and publishes them to the broker.
#[derive(Debug, Clone)]
pub struct TaggedEvent {
    pub session_id: String,
    pub event: DebugEvent,
}

// ── Sender Handle ─────────────────────────────────────────────────────

/// Handle for sending events to the debug event bus.
///
/// Each session gets its own `DebugEventSender` with the session's ID
/// embedded, so events are automatically tagged at send time.
/// Clone is cheap - multiple senders can push events concurrently.
#[derive(Debug, Clone)]
pub struct DebugEventSender {
    tx: broadcast::Sender<TaggedEvent>,
    session_id: String,
}

impl DebugEventSender {
    /// Return the session ID that this sender tags events with.
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// Send a debug event to the event bus. Returns `true` if the event
    /// was accepted by the channel (note: broadcast may drop the event
    /// for receivers that lag; this returns whether the channel is
    /// still open).
    pub fn send(&self, event: DebugEvent) -> bool {
        self.tx
            .send(TaggedEvent {
                session_id: self.session_id.clone(),
                event,
            })
            .is_ok()
    }

    /// Check if the event channel is still open.
    pub fn is_open(&self) -> bool {
        // broadcast::Sender::receiver_count > 0 means at least one
        // subscriber is listening. If 0, send() will still succeed but
        // nobody will get it. We treat that as "not useful" for
        // senders that want to know if anyone cares.
        self.tx.receiver_count() > 0
    }

    /// Create a sender for a specific session, sharing the same underlying channel.
    pub fn for_session(&self, session_id: String) -> Self {
        Self {
            tx: self.tx.clone(),
            session_id,
        }
    }
}

// ── Event Bus ─────────────────────────────────────────────────────────

/// The debug event bus.
///
/// Owns the broadcast channel that all debug events flow through.
/// Created once per Runtime process by
/// `SessionManager::enable_debug_mode` when DevMode is active.
///
/// This replaces the legacy WebSocket server removed by ADR-048:
/// ADR-048 removed the WebSocket listener: a channel holder plus two
/// accessors. There is no server loop - the MQTT publisher spawned in
/// `enable_debug_mode` is the only consumer.
pub struct DebugEventBus {
    tx: broadcast::Sender<TaggedEvent>,
}

impl DebugEventBus {
    /// Create a new event bus with no subscribers yet.
    pub fn new() -> Self {
        let (tx, _rx) = broadcast::channel(DEBUG_EVENT_CHANNEL_CAPACITY);
        // The initial receiver is dropped immediately - keeping it
        // alive would make `send()` succeed even with zero real
        // subscribers, defeating `DebugEventSender::is_open()`.
        drop(_rx);
        Self { tx }
    }

    /// Subscribe to the event bus.
    ///
    /// Used by the MQTT events publisher to receive every
    /// [`TaggedEvent`] so it can republish them to the broker.
    pub fn subscribe(&self) -> broadcast::Receiver<TaggedEvent> {
        self.tx.subscribe()
    }

    /// Return the sender template. Clone it and call
    /// `for_session(session_id)` to create per-session senders.
    pub fn sender_template(&self) -> DebugEventSender {
        DebugEventSender {
            tx: self.tx.clone(),
            session_id: String::new(),
        }
    }
}

impl Default for DebugEventBus {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::debug::controller::DebugState;
    use crate::debug::protocol::DebugPhase;

    fn make_step_event(iteration: u32) -> DebugEvent {
        DebugEvent::Step {
            iteration,
            phase: DebugPhase::LlmCall,
            input: None,
            output: None,
            usage: None,
        }
    }

    #[test]
    fn bus_delivers_tagged_events_to_subscriber() {
        let bus = DebugEventBus::new();
        let mut rx = bus.subscribe();

        let sender = bus.sender_template().for_session("sess-1".into());
        assert!(sender.send(make_step_event(3)));

        let TaggedEvent { session_id, event } = rx.try_recv().expect("event should be delivered");
        assert_eq!(session_id, "sess-1");
        match event {
            DebugEvent::Step { iteration, .. } => assert_eq!(iteration, 3),
            other => panic!("expected Step, got {other:?}"),
        }
    }

    #[test]
    fn send_returns_true_with_subscriber_and_events_are_cloned() {
        let bus = DebugEventBus::new();
        let mut rx1 = bus.subscribe();
        let mut rx2 = bus.subscribe();

        let sender = bus.sender_template();
        assert!(sender.is_open(), "is_open with 2 subscribers");
        assert!(sender.send(DebugEvent::ExecutionStateChanged {
            new_state: DebugState::Paused,
            iteration: 7,
        }));

        // Both subscribers receive an independent clone.
        assert!(rx1.try_recv().is_ok());
        assert!(rx2.try_recv().is_ok());
    }

    #[test]
    fn is_open_false_without_subscribers() {
        let bus = DebugEventBus::new();
        let sender = bus.sender_template();
        assert!(
            !sender.is_open(),
            "no subscribers -> is_open() should be false"
        );
    }
}
