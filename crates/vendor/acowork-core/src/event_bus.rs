//! Generic event bus for Gateway-managed subprocesses.
//!
//! Publishes state transitions and periodic heartbeats over a
//! `tokio::sync::broadcast` channel. The `/events` SSE endpoint
//! subscribes to this bus and re-emits events to connected gateway
//! clients.
//!
//! Two event kinds share the same channel:
//!   - `BusEvent::State` — published whenever the subprocess's high-level
//!     state changes
//!   - `BusEvent::Heartbeat` — published periodically by the heartbeat task
//!
//! SSE consumers (gateway supervisor) treat missing heartbeats as the
//! "process stuck" signal. State events let the gateway learn the
//! subprocess's current status without polling.
//!
//! # Type parameter
//!
//! `S` is the application-specific state type. For embed it's
//! `EmbedState` (Starting, Loading, Ready, Error); for LSP relay it's
//! `LspRelayState` (Starting, Ready, Error).

use serde::Serialize;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::sync::broadcast;
use tokio::time;

/// Generic event flowing over the bus. Both kinds carry a `seq` for
/// client-side ordering checks.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BusEvent<S: Clone + Serialize> {
    /// Periodic liveness signal.
    Heartbeat { seq: u64 },
    /// Application-level state transition.
    State { seq: u64, state: S },
}

/// Bus for broadcasting events to all subscribers.
///
/// Cheap to clone (cheap to share via `Arc`). Uses `tokio::sync::broadcast`
/// internally. Each new subscriber starts receiving events from the moment
/// of subscription onwards — **broadcast does not replay historical events**.
/// The gateway's supervisor compensates for this by bootstrapping from
/// `/health` on connect.
#[derive(Clone)]
pub struct EventBus<S: Clone + Serialize + Send + Sync + 'static> {
    tx: broadcast::Sender<Arc<BusEvent<S>>>,
    seq: Arc<AtomicU64>,
}

impl<S: Clone + Serialize + Send + Sync + 'static> EventBus<S> {
    /// Create a new bus. `buffer` is the per-subscriber ring size; late
    /// subscribers see at most this many past events.
    pub fn new(buffer: usize) -> Self {
        let (tx, _) = broadcast::channel(buffer);
        Self {
            tx,
            seq: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Subscribe to the event stream. Returns a receiver that will see
    /// all events published from this point on (plus any buffered
    /// events that fit in the ring).
    pub fn subscribe(&self) -> broadcast::Receiver<Arc<BusEvent<S>>> {
        self.tx.subscribe()
    }

    /// Publish a state transition. Returns the assigned sequence number.
    pub fn publish_state(&self, state: S) -> u64 {
        let seq = self.seq.fetch_add(1, Ordering::Relaxed);
        let event = Arc::new(BusEvent::State { seq, state });
        // Ignore "no active subscribers" error — we just drop the event.
        let _ = self.tx.send(event);
        seq
    }

    /// Publish a heartbeat. Internal — the heartbeat task calls this.
    fn publish_heartbeat(&self) -> u64 {
        let seq = self.seq.fetch_add(1, Ordering::Relaxed);
        let event = Arc::new(BusEvent::Heartbeat { seq });
        let _ = self.tx.send(event);
        seq
    }

    /// Spawn a background task that publishes a heartbeat every
    /// `interval_ms` milliseconds. The task ends when the bus is dropped
    /// (channel closed).
    pub fn spawn_heartbeat(&self, interval_ms: u64) {
        let bus = self.clone();
        tokio::spawn(async move {
            let mut ticker = time::interval(Duration::from_millis(interval_ms));
            // Skip the immediate first tick so we don't fire instantly on spawn.
            ticker.tick().await;
            loop {
                ticker.tick().await;
                bus.publish_heartbeat();
            }
        });
    }
}
