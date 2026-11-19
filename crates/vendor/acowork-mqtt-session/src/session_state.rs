//! Session state machine (ADR-039 §5.1).
//!
//! Provides a `tokio::sync::watch`-based broadcast so that external
//! consumers (Tauri events, DevMode, health ledger) can observe
//! the MQTT connection lifecycle in real time.

use std::sync::Arc;

use tokio::sync::watch;

/// The lifecycle state of an MQTT session.
///
/// ```mermaid
/// graph LR
///     Idle --> Connecting
///     Connecting --> Connected
///     Connecting --> Disconnected
///     Connected --> Reconnecting
///     Reconnecting --> Connected
///     Reconnecting --> Disconnected
///     Connected --> Disconnected
///     Disconnected --> Connecting
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SessionState {
    /// No connection attempt has been made yet.
    Idle,

    /// `AsyncClient` created, waiting for the first `ConnAck`.
    Connecting,

    /// `ConnAck` received, bootstrap completed. Ready for
    /// publish/subscribe.
    Connected,

    /// Was connected, lost the connection, waiting for rumqttc's
    /// automatic reconnect to deliver a new `ConnAck`.
    ///
    /// `reason` carries the transport / event-loop error that caused the
    /// drop. It lives on the *state* (not only on the `MqttStatus`
    /// callback) so that snapshot readers — `get_mqtt_status` and the
    /// Desktop's full-stack diagnostic panel — can report the real cause
    /// instead of a generic "reconnecting".
    Reconnecting {
        /// Human-readable reason for the connection drop.
        reason: String,
    },

    /// Permanently disconnected (fatal error or explicit shutdown).
    /// No further reconnect attempts will be made.
    Disconnected {
        /// Human-readable reason for disconnection.
        reason: String,
    },
}

impl SessionState {
    /// Returns `true` if the session is in a connected state and
    /// ready for publish/subscribe.
    pub fn is_connected(&self) -> bool {
        matches!(self, SessionState::Connected)
    }

    /// Returns `true` if the session is in a transient (non-terminal)
    /// state that may progress to `Connected`.
    pub fn is_transient(&self) -> bool {
        matches!(
            self,
            SessionState::Idle
                | SessionState::Connecting
                | SessionState::Reconnecting { .. }
        )
    }

    /// Returns `true` if the session is permanently stopped.
    pub fn is_terminal(&self) -> bool {
        matches!(self, SessionState::Disconnected { .. })
    }
}

impl std::fmt::Display for SessionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SessionState::Idle => write!(f, "idle"),
            SessionState::Connecting => write!(f, "connecting"),
            SessionState::Connected => write!(f, "connected"),
            SessionState::Reconnecting { reason } => {
                write!(f, "reconnecting ({reason})")
            }
            SessionState::Disconnected { reason } => {
                write!(f, "disconnected ({reason})")
            }
        }
    }
}

// ── watch channel wrappers ───────────────────────────────────

/// Sender side of the session-state broadcast.
///
/// Held by the event loop. Cloning is cheap (Arc inside).
#[derive(Clone)]
pub struct SessionStateTx {
    tx: watch::Sender<SessionState>,
}

impl SessionStateTx {
    /// Create a new broadcast channel with the given initial state.
    pub fn new(initial: SessionState) -> (Self, SessionStateRx) {
        let (tx, rx) = watch::channel(initial);
        (
            SessionStateTx { tx },
            SessionStateRx {
                rx: Arc::new(Mutex::new(rx)),
            },
        )
    }

    /// Update the state. Logs the transition at INFO level.
    ///
    /// Uses `send_modify` instead of `send` because `send` returns
    /// `Err` when there are no receivers – and in this architecture the
    /// receiver is usually not held (the `SessionStateRx` from `new()`
    /// is dropped).  `send_modify` unconditionally updates the stored
    /// value and provides a reference to the previous value, which is
    /// exactly what we need: `current()` reads via `borrow()` which
    /// always reflects the latest stored value regardless of receiver
    /// count.
    pub fn set(&self, state: SessionState) {
        let mut prev_str = String::new();
        self.tx.send_modify(|current| {
            if *current != state {
                prev_str = format!("{}", *current);
                tracing::info!(from = %prev_str, to = %state, "MQTT session state transition");
            }
            *current = state;
        });
    }

    /// Read the current state without subscribing.
    pub fn current(&self) -> SessionState {
        self.tx.borrow().clone()
    }

    /// Create a new receiver that can observe future state changes.
    /// The receiver will see the current state immediately on first
    /// `changed()` call.
    pub fn subscribe(&self) -> SessionStateRx {
        SessionStateRx {
            rx: Arc::new(Mutex::new(self.tx.subscribe())),
        }
    }
}

/// Receiver side of the session-state broadcast.
///
/// Held by external consumers (Tauri command handlers, DevMode,
/// health ledger). Cloning is NOT supported – wrap in `Arc` if
/// multiple consumers need the same receiver, or create multiple
/// receivers from the same `SessionStateTx` (not yet supported –
/// use `tokio::sync::broadcast` if fan-out is needed).
pub struct SessionStateRx {
    rx: Arc<Mutex<watch::Receiver<SessionState>>>,
}

use std::sync::Mutex;

impl SessionStateRx {
    /// Wait for the next state change, returning the new state.
    ///
    /// Returns `Err` if all senders have been dropped.
    pub async fn changed(&self) -> Result<SessionState, watch::error::SendError<SessionState>> {
        let mut rx = {
            // Clone the receiver out of the mutex so we don't hold
            // the lock across the `.await` below (clippy:
            // await_holding_lock).
            self.rx.lock().unwrap().clone()
        };
        rx.changed().await.map_err(|_| {
            watch::error::SendError(SessionState::Disconnected {
                reason: "sender dropped".into(),
            })
        })?;
        Ok(rx.borrow().clone())
    }

    /// Read the current state without waiting.
    pub fn current(&self) -> SessionState {
        self.rx.lock().unwrap().borrow().clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_transitions() {
        assert!(SessionState::Idle.is_transient());
        assert!(!SessionState::Idle.is_connected());

        assert!(SessionState::Connected.is_connected());
        assert!(!SessionState::Connected.is_transient());

        assert!(
            SessionState::Reconnecting {
                reason: "test".into()
            }
            .is_transient()
        );
        assert!(
            !SessionState::Reconnecting {
                reason: "test".into()
            }
            .is_connected()
        );

        let d = SessionState::Disconnected {
            reason: "test".into(),
        };
        assert!(d.is_terminal());
        assert!(!d.is_connected());
        assert!(!d.is_transient());
    }

    #[test]
    fn display_formats() {
        assert_eq!(SessionState::Idle.to_string(), "idle");
        assert_eq!(SessionState::Connected.to_string(), "connected");
        assert_eq!(
            SessionState::Disconnected {
                reason: "boom".into()
            }
            .to_string(),
            "disconnected (boom)"
        );
    }

    /// Regression: the drop reason must survive into the snapshot the
    /// Desktop's diagnostic panel reads. Before this, `Reconnecting`
    /// carried no reason at all, so `get_mqtt_status` had to hardcode
    /// "reconnecting" and the panel hid the real cause (e.g. a TLS
    /// handshake failure) behind a useless label.
    #[test]
    fn reconnecting_carries_the_drop_reason() {
        let state = SessionState::Reconnecting {
            reason: "eventloop error: Websocket: IO error".into(),
        };
        assert_eq!(
            state.to_string(),
            "reconnecting (eventloop error: Websocket: IO error)"
        );
        assert!(state.is_transient());
        assert!(!state.is_connected());
        assert!(!state.is_terminal());
    }

    /// A *different* reason is a real transition: the `set` path compares
    /// states to decide whether to log, so a changed cause must never be
    /// silently dropped as "same state".
    #[test]
    fn changed_reason_is_a_distinct_state() {
        let (tx, _rx) = SessionStateTx::new(SessionState::Connecting);
        tx.set(SessionState::Reconnecting {
            reason: "broker sent DISCONNECT".into(),
        });
        tx.set(SessionState::Reconnecting {
            reason: "poll watchdog timeout".into(),
        });
        assert_eq!(
            tx.current(),
            SessionState::Reconnecting {
                reason: "poll watchdog timeout".into()
            },
            "the latest reason must win"
        );
    }

    #[tokio::test]
    async fn watch_channel_delivers_changes() {
        let (tx, rx) = SessionStateTx::new(SessionState::Idle);
        assert_eq!(rx.current(), SessionState::Idle);

        tx.set(SessionState::Connecting);
        // Give the watch channel a tick to propagate.
        tokio::task::yield_now().await;

        let state = rx.changed().await.unwrap();
        assert_eq!(state, SessionState::Connecting);

        tx.set(SessionState::Connected);
        let state = rx.changed().await.unwrap();
        assert_eq!(state, SessionState::Connected);
    }

    #[tokio::test]
    async fn watch_channel_current_is_instant() {
        let (tx, rx) = SessionStateTx::new(SessionState::Connected);
        assert_eq!(tx.current(), SessionState::Connected);
        assert_eq!(rx.current(), SessionState::Connected);
    }

    /// Regression test: `set` must update the value even when no
    /// receiver is held.  This was the root cause of the MQTT
    /// "perpetually connecting" bug – `watch::Sender::send` returns
    /// `Err` (and does NOT update the stored value) when there are
    /// zero receivers.  The fix uses `send_modify` which unconditionally
    /// writes.
    #[test]
    fn set_works_without_receiver() {
        let (tx, _rx) = SessionStateTx::new(SessionState::Connecting);
        drop(_rx); // drop the only receiver

        tx.set(SessionState::Connected);
        assert_eq!(
            tx.current(),
            SessionState::Connected,
            "set() must update the value even with no receivers"
        );

        tx.set(SessionState::Reconnecting {
            reason: "test".into(),
        });
        assert_eq!(
            tx.current(),
            SessionState::Reconnecting {
                reason: "test".into()
            }
        );

        tx.set(SessionState::Disconnected {
            reason: "test".into(),
        });
        assert!(matches!(
            tx.current(),
            SessionState::Disconnected { .. }
        ));
    }

    /// `current()` on a clone must see writes from the original,
    /// and vice-versa – they share the same internal channel.
    #[test]
    fn clone_shares_state() {
        let (tx, _rx) = SessionStateTx::new(SessionState::Idle);
        let tx_clone = tx.clone();
        drop(_rx);

        tx_clone.set(SessionState::Connected);
        assert_eq!(tx.current(), SessionState::Connected);

        tx.set(SessionState::Reconnecting {
            reason: "test".into(),
        });
        assert_eq!(
            tx_clone.current(),
            SessionState::Reconnecting {
                reason: "test".into()
            }
        );
    }
}
