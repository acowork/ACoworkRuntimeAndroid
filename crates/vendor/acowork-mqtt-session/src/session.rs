//! Shared MQTT session abstraction (ADR-039 §1.2).
//!
//! [`MqttSession`] bundles [`SessionStateTx`] and [`ReconnectPolicy`]
//! into a single handle. Both Runtime and Desktop construct one at
//! client creation time and hold it for the lifetime of the MQTT
//! connection.

use std::marker::PhantomData;

use crate::reconnect::ReconnectPolicy;
use crate::session_state::{SessionState, SessionStateRx, SessionStateTx};

/// Shared MQTT session handle.
///
/// Groups the session-state broadcast channel and the reconnect
/// policy. The type parameter `S` is a marker for the bootstrap-data
/// type (e.g. `BootstrapData` for Runtime, `()` for Desktop).
///
/// # Example
///
/// ```ignore
/// use acowork_mqtt_session::{MqttSession, SessionState};
///
/// let session = MqttSession::<MyBootstrapData>::new();
/// // later, in the event loop:
/// session.state.set(SessionState::Connected);
/// if let Some(backoff) = session.reconnect.backoff(class, n) {
///     tokio::time::sleep(backoff.duration).await;
/// }
/// ```
pub struct MqttSession<S> {
    /// Broadcast channel for session lifecycle state.
    pub state: SessionStateTx,
    /// Exponential backoff policy for reconnect attempts.
    pub reconnect: ReconnectPolicy,
    /// Kept alive so `state_rx()` / `state.subscribe()` can create new
    /// receivers. Without at least one live receiver, `watch::Sender::send`
    /// returns `Err(())` and downstream consumers see stale state.
    _rx: SessionStateRx,
    _marker: PhantomData<S>,
}

impl<S> Clone for MqttSession<S> {
    fn clone(&self) -> Self {
        Self {
            state: self.state.clone(),
            reconnect: self.reconnect.clone(),
            // Create a fresh independent receiver so the clone
            // does not share the same watch stream position.
            _rx: self.state.subscribe(),
            _marker: PhantomData,
        }
    }
}

impl<S> MqttSession<S> {
    /// Create a new session handle with the `Connecting` initial state
    /// and the default reconnect policy (500 ms initial, 30 s cap,
    /// 2× multiplier).
    pub fn new() -> Self {
        let (state, rx) = SessionStateTx::new(SessionState::Connecting);
        Self {
            state,
            reconnect: ReconnectPolicy::default(),
            _rx: rx,
            _marker: PhantomData,
        }
    }

    /// Create a new session handle with a custom reconnect policy.
    pub fn with_reconnect_policy(reconnect: ReconnectPolicy) -> Self {
        let (state, rx) = SessionStateTx::new(SessionState::Connecting);
        Self {
            state,
            reconnect,
            _rx: rx,
            _marker: PhantomData,
        }
    }

    /// Returns a new receiver that can observe future state changes.
    pub fn state_rx(&self) -> SessionStateRx {
        self.state.subscribe()
    }
}

impl<S> Default for MqttSession<S> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_default_is_connecting() {
        let s = MqttSession::<()>::new();
        assert!(!s.state.current().is_connected());
        assert!(s.state.current().is_transient());
    }

    #[test]
    fn session_clone_shares_state() {
        let s = MqttSession::<()>::new();
        let s2 = s.clone();
        s.state.set(SessionState::Connected);
        // Both handles see the same state through the shared watch channel.
        assert_eq!(s.state.current(), SessionState::Connected);
        assert_eq!(s2.state.current(), SessionState::Connected);
    }

    #[test]
    fn session_with_custom_reconnect() {
        use std::time::Duration;
        let policy = ReconnectPolicy {
            initial: Duration::from_secs(1),
            max: Duration::from_secs(10),
            multiplier: 3.0,
        };
        let s = MqttSession::<()>::with_reconnect_policy(policy.clone());
        assert_eq!(s.reconnect.initial, policy.initial);
        assert_eq!(s.reconnect.max, policy.max);
    }
}
