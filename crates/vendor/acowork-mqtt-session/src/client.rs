//! Unified MQTT client lifecycle (ADR-065 Step 3).
//!
//! [`MqttClient`] internalizes the entire poll loop — error
//! classification, exponential backoff, soft-restart, watchdog and
//! force-restart wake recovery — so the four MQTT clients (Desktop /
//! Node / Runtime / Gateway publisher) only implement their entity
//! differences via [`MqttClientHandler`].
//!
//! The poll loop structure (outer soft-restart + inner polling) is the
//! single implementation shared by all four clients. Timing constants
//! come from [`crate::config`]; error classification goes through the
//! shared `From<&ConnectionError>` adapter (ADR-065 §5.6) — no private
//! per-client adapters.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use rumqttc::{AsyncClient, Event, Incoming, MqttOptions, QoS, Transport};
use tokio::sync::Mutex;

use crate::config::{
    FATAL_BACKOFF, FATAL_STREAK_LIMIT, KEEPALIVE_INTERVAL, MqttClientConfig, MqttTransport,
    POLL_WATCHDOG_TIMEOUT,
};
use crate::err_class::{classify, ErrClass, ErrorDescriptor};
use crate::force_restart::ForceRestart;
use crate::reconnect::ReconnectPolicy;
use crate::session_state::{SessionState, SessionStateRx, SessionStateTx};

/// Entity-specific MQTT client behavior (ADR-065 §5.5).
///
/// Implementors provide the per-process differences: bootstrap steps,
/// publish handling, disconnect cleanup, error surfacing. The poll
/// loop, error classification, backoff, soft-restart and wake recovery
/// all live in [`MqttClient`].
///
/// All methods have default no-op implementations; implementors override
/// only what their role needs.
#[async_trait]
pub trait MqttClientHandler: Send + Sync + 'static {
    /// Called for every incoming PUBLISH.
    async fn on_publish(&self, _topic: &str, _payload: &[u8]) {}

    /// Called after every ConnAck (initial connect + reconnect), with
    /// the current `AsyncClient` so the handler can publish/subscribe
    /// (e.g. re-subscribe topics, publish retained status).
    ///
    /// Return `Err` to mark the connection degraded (e.g. bootstrap
    /// failed) — [`MqttClient`] then transitions to `Disconnected`.
    async fn on_connack(&self, _client: &AsyncClient) -> Result<(), String> {
        Ok(())
    }

    /// Called on broker-initiated DISCONNECT, with the current client
    /// handle so the handler can publish cleanup state (e.g. clear a
    /// retained snapshot).
    async fn on_disconnect(&self, _client: &AsyncClient) {}

    /// Called on every connection-level error (before backoff), with
    /// the current client handle.
    async fn on_error(&self, _client: &AsyncClient, _class: ErrClass, _error: &str) {}

    /// Called before each soft-restart so the handler can supply fresh
    /// CONNECT credentials `(username, password)` (e.g. the Node swaps
    /// its enrollment token for the Gateway-issued node_token after the
    /// enrollment reply, ADR-055 Phase 5a). `None` reuses the original
    /// options verbatim.
    ///
    /// Default no-op: most clients reuse the original options verbatim.
    async fn on_soft_restart(&self) -> Option<(String, String)> {
        None
    }
}

/// Error type for the unified MQTT client.
#[derive(Debug, thiserror::Error)]
pub enum MqttClientError {
    #[error("MQTT connection error: {0}")]
    Connection(String),
    #[error("MQTT publish error: {0}")]
    Publish(String),
    #[error("MQTT subscribe error: {0}")]
    Subscribe(String),
}

/// Guard that ties the event-loop polling task's lifetime to the
/// `MqttClient`. When the last `Arc<EventLoopGuard>` is dropped (i.e.
/// the `MqttClient` and every clone of it are dropped), the poll task
/// is aborted so the underlying TCP socket is released and the broker
/// can drop the previous `client_id` registration.
///
/// Without this `Drop` impl, `JoinHandle::drop()` only detaches the
/// task from the Tokio registry -- it does NOT abort the task. A stale
/// poll task would keep running with the old socket, racing against
/// every freshly-created client for the same `client_id` and causing
/// the broker to repeatedly log `Duplicate client_id, dropping
/// previous connection`. This is what the desktop hits when the user
/// switches the configured gateway URL while a previous client still
/// exists in `AppState::mqtt_client`.
struct EventLoopGuard {
    task: tokio::task::JoinHandle<()>,
}

impl Drop for EventLoopGuard {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Unified MQTT client with a fully internalized poll loop (ADR-065).
///
/// The poll task owns the `EventLoop` and recreates it on soft-restart;
/// the `AsyncClient` is shared via `Arc<Mutex<...>>` so publish callers
/// always observe the current handle.
pub struct MqttClient<B: MqttClientHandler> {
    shared_handle: Arc<Mutex<AsyncClient>>,
    state: SessionStateTx,
    force_restart: Arc<ForceRestart>,
    _eventloop_guard: Arc<EventLoopGuard>,
    _handler: Arc<B>,
}

impl<B: MqttClientHandler> Clone for MqttClient<B> {
    fn clone(&self) -> Self {
        Self {
            shared_handle: Arc::clone(&self.shared_handle),
            state: self.state.clone(),
            force_restart: Arc::clone(&self.force_restart),
            _eventloop_guard: Arc::clone(&self._eventloop_guard),
            _handler: Arc::clone(&self._handler),
        }
    }
}

/// Build rumqttc [`MqttOptions`] address + transport from the config.
///
/// rumqttc's address semantics are transport-dependent: for TCP the
/// `MqttOptions` "host" slot carries the plain host (paired with
/// `port`), while for Ws/Wss the slot must carry the FULL URL
/// (`eventloop.rs` feeds it to `split_url` for the TCP connect and to
/// `into_client_request` for the WS handshake — the path `/mqtt` is
/// part of the handshake URL). This helper centralizes that mapping so
/// every client gets it right without knowing rumqttc internals.
///
/// TLS for [`MqttTransport::Wss`] uses the platform root store
/// (`Transport::wss_with_default_config`) — the relay serves a normal
/// CA-signed certificate, so no custom trust anchors are needed.
fn build_mqtt_options(config: &MqttClientConfig) -> MqttOptions {
    match &config.transport {
        MqttTransport::Tcp => {
            MqttOptions::new(config.client_id.clone(), config.host.clone(), config.port)
        }
        MqttTransport::Wss { url } => {
            // The port slot is unused for WSS (rumqttc derives the port
            // from the URL, defaulting to 443 for the wss scheme); 443
            // keeps `broker_address()` sensible for diagnostics.
            let mut options = MqttOptions::new(config.client_id.clone(), url.clone(), 443);
            ensure_crypto_provider();
            options.set_transport(Transport::wss_with_default_config());
            options
        }
    }
}

/// Install the process-level rustls CryptoProvider before rumqttc builds
/// a WSS `ClientConfig`.
///
/// `Transport::wss_with_default_config()` resolves the provider via
/// feature auto-detection, which fails (panic) whenever the build graph
/// enables more than one provider feature — cargo feature unification
/// across a workspace can do exactly that (e.g. a dependency pulling
/// rustls `aws-lc-rs` next to the workspace's `ring`). Installing `ring`
/// explicitly makes WSS setup deterministic regardless of how features
/// unify downstream. Idempotent: a provider installed earlier by the
/// host application wins (the error is deliberately ignored).
fn ensure_crypto_provider() {
    static INSTALL: std::sync::Once = std::sync::Once::new();
    INSTALL.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

impl<B: MqttClientHandler> MqttClient<B> {
    /// Connect to the broker and start the poll task.
    ///
    /// Returns immediately after spawning the poll task — does NOT wait
    /// for the initial CONNACK. Call [`MqttClient::wait_for_connected`]
    /// if the caller needs to block on the first connection.
    ///
    /// `on_state_change` (optional) is invoked synchronously on every
    /// session-state transition (e.g. Desktop maps it to its
    /// `MqttStatus` Tauri event).
    pub async fn connect(
        config: MqttClientConfig,
        handler: B,
        on_state_change: Option<Arc<dyn Fn(SessionState) + Send + Sync>>,
    ) -> Result<Self, MqttClientError> {
        let mut options = build_mqtt_options(&config);
        options.set_keep_alive(KEEPALIVE_INTERVAL);
        options.set_clean_session(true);
        if let Some((username, password)) = &config.credentials {
            options.set_credentials(username.clone(), password.clone());
        }
        options.set_max_packet_size(config.max_packet_size, config.max_packet_size);
        if let Some(will) = &config.last_will {
            options.set_last_will(will.clone());
        }

        let (client, mut eventloop) = AsyncClient::new(options.clone(), config.queue_capacity);
        let shared_handle: Arc<Mutex<AsyncClient>> = Arc::new(Mutex::new(client));

        let (state_tx, _) = SessionStateTx::new(SessionState::Connecting);
        let poll_state_tx = state_tx.clone();
        let reconnect_policy = ReconnectPolicy::default();

        let task_shared_handle = Arc::clone(&shared_handle);
        let task_options = options;
        let task_handler = Arc::new(handler);
        let task_handler_poll = Arc::clone(&task_handler);
        let force_restart = Arc::new(ForceRestart::new());
        let task_force_restart = Arc::clone(&force_restart);
        let queue_capacity = config.queue_capacity;

        // Spawn the eventloop poller.
        //
        // Structure: outer loop (soft-restart) + inner loop (normal
        // polling).
        //
        // - Inner loop polls the current `EventLoop`. On retryable
        //   errors (E1/E5) it applies exponential backoff and continues.
        //   On "fatal" errors (E2/E3/E4/E6) it uses a fixed 60 s
        //   backoff.
        // - After `FATAL_STREAK_LIMIT` consecutive fatal errors the
        //   inner loop breaks to the outer loop, which drops the old
        //   `EventLoop` + `AsyncClient` and creates a fresh pair — a
        //   **soft-restart** that recovers from any internal state
        //   corruption without restarting the process.
        // - The new `AsyncClient` is swapped into `shared_handle` so
        //   publish callers automatically use the new handle.
        // - A force-restart request (wake recovery) breaks the inner
        //   loop at any point, including during a backoff.
        let poll_task = tokio::spawn(async move {
            let mut soft_restart_count: u32 = 0;
            let set_state = move |state: SessionState| {
                poll_state_tx.set(state.clone());
                if let Some(ref cb) = on_state_change {
                    cb(state);
                }
            };

            // ADR-065 wake-recovery hardening: incoming PUBLISH handlers
            // are dispatched to a dedicated serial consumer task instead
            // of being awaited inline on the event-loop poll task.
            //
            // `on_publish` implementations do real work — the Runtime
            // persists `acowork/global/*` catalogs to disk (sync fs
            // writes), the Gateway routes agent status, etc. A slow
            // publish handler used to stall the entire event loop: no
            // further MQTT events were polled, the outgoing queue filled
            // up, and every publish (state relay, heartbeats, replies)
            // blocked behind it — the process looked "sleeping" for tens
            // of seconds after a host suspend/resume (2026-09-07
            // incident). Ordering is preserved (single consumer) and the
            // unbounded channel needs no backpressure because control
            // traffic is small; the consumer task dies with the poll
            // task via the sender's drop.
            let (publish_tx, mut publish_rx) =
                tokio::sync::mpsc::unbounded_channel::<(String, Vec<u8>)>();
            let publish_handler = Arc::clone(&task_handler_poll);
            tokio::spawn(async move {
                while let Some((topic, payload)) = publish_rx.recv().await {
                    publish_handler.on_publish(&topic, &payload).await;
                }
            });

            loop {
                let mut consecutive_failures: u32 = 0;
                let mut fatal_streak: u32 = 0;

                loop {
                    // Persistent force-restart flag (ADR-065 §2.4):
                    // covers the window where the poll task is busy
                    // handling an event (not parked in select!) and
                    // would miss the Notify.
                    if task_force_restart.take() {
                        tracing::info!("MQTT force-restart requested (persistent flag)");
                        set_state(SessionState::Connecting);
                        break;
                    }
                    tokio::select! {
                        biased; // favour the force-restart signal
                        _ = task_force_restart.wait() => {
                            let _ = task_force_restart.take(); // consume the persistent flag
                            tracing::info!("MQTT force-restart requested (e.g. system wake)");
                            set_state(SessionState::Connecting);
                            break;
                        }
                        event_result = eventloop.poll() => {
                            match event_result {
                                Ok(Event::Incoming(Incoming::Publish(publish))) => {
                                    // Non-blocking hand-off to the serial
                                    // publish consumer (see the channel
                                    // setup above). `send` only fails when
                                    // the consumer task has exited — log at
                                    // debug, never stall the poll loop.
                                    if publish_tx
                                        .send((publish.topic, publish.payload.to_vec()))
                                        .is_err()
                                    {
                                        tracing::debug!(
                                            "MQTT publish consumer task exited; dropping incoming publish"
                                        );
                                    }
                                }
                                Ok(Event::Incoming(Incoming::ConnAck(_))) => {
                                    set_state(SessionState::Connected);
                                    consecutive_failures = 0;
                                    fatal_streak = 0;
                                    let poll_client = task_shared_handle.lock().await.clone();
                                    if let Err(e) = task_handler_poll.on_connack(&poll_client).await {
                                        tracing::error!(
                                            error = %e,
                                            "MQTT bootstrap after (re)connect failed"
                                        );
                                        set_state(SessionState::Disconnected {
                                            reason: format!("bootstrap failed: {e}"),
                                        });
                                    }
                                }
                                Ok(Event::Incoming(Incoming::Disconnect)) => {
                                    tracing::warn!(
                                        client_id = %task_options.client_id(),
                                        "MQTT broker sent DISCONNECT; entering Reconnecting state without break — \
                                         relying on next poll() to surface the socket error. \
                                         SessionState set to Reconnecting, on_disconnect callback fired."
                                    );
                                    set_state(SessionState::Reconnecting {
                                        reason: "broker sent DISCONNECT".to_string(),
                                    });
                                    let poll_client = task_shared_handle.lock().await.clone();
                                    task_handler_poll.on_disconnect(&poll_client).await;
                                }
                                Ok(_) => continue,
                                Err(e) => {
                                    let desc = ErrorDescriptor::from(&e);
                                    let class = classify(&desc);
                                    let poll_client = task_shared_handle.lock().await.clone();
                                    task_handler_poll
                                        .on_error(&poll_client, class, &e.to_string())
                                        .await;
                                    set_state(SessionState::Reconnecting {
                                        reason: format!("eventloop error: {e}"),
                                    });

                                    if class.is_fatal() {
                                        // E2/E3/E4/E6: the EventLoop's
                                        // internal state may be corrupt.
                                        // Use a long 60 s backoff; after
                                        // FATAL_STREAK_LIMIT consecutive
                                        // fatal errors, soft-restart.
                                        fatal_streak += 1;
                                        tracing::error!(
                                            error = %e,
                                            err_class = class.label(),
                                            fatal_streak,
                                            "MQTT fatal error"
                                        );
                                        if fatal_streak >= FATAL_STREAK_LIMIT {
                                            soft_restart_count += 1;
                                            tracing::warn!(
                                                soft_restart_count,
                                                "consecutive fatal errors - soft-restarting MQTT client"
                                            );
                                            break;
                                        }
                                        // 60 s backoff, interruptible by a
                                        // force-restart request (wake
                                        // recovery must never wait it out).
                                        if task_force_restart
                                            .interruptible_backoff(FATAL_BACKOFF, "fatal")
                                            .await
                                        {
                                            break;
                                        }
                                    } else {
                                        // E1/E5: retryable. Apply
                                        // exponential backoff.
                                        consecutive_failures += 1;
                                        if let Some(backoff) = reconnect_policy
                                            .backoff(class, consecutive_failures - 1)
                                            && task_force_restart
                                                .interruptible_backoff(
                                                    backoff.duration,
                                                    "retryable",
                                                )
                                                .await
                                        {
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                        // Watchdog: if poll() hasn't produced any event
                        // in POLL_WATCHDOG_TIMEOUT, the TCP socket is
                        // likely half-dead (e.g. after OS sleep/wake).
                        // Break to the soft-restart path to create a
                        // fresh connection. The sleep future is dropped
                        // (reset) every time poll() returns, so this
                        // only fires when the connection is silent.
                        _ = tokio::time::sleep(POLL_WATCHDOG_TIMEOUT) => {
                            tracing::warn!(
                                timeout_s = POLL_WATCHDOG_TIMEOUT.as_secs(),
                                "MQTT poll() watchdog timeout - forcing soft-restart (possible half-dead socket)"
                            );
                            set_state(SessionState::Reconnecting {
                                reason: format!(
                                    "poll watchdog timeout ({}s of silence)",
                                    POLL_WATCHDOG_TIMEOUT.as_secs()
                                ),
                            });
                            break;
                        }
                        // Fix-3 observability (shared, ADR-065 Step 4):
                        // if the poll loop has been idle for
                        // `keepalive × 0.8` or more, emit a trace-level
                        // message so future KeepAlive disconnects can be
                        // correlated with the idle window (e.g. long
                        // synchronous HTTP handlers like `POST
                        // /workspaces`). Trace-only — it does not spam
                        // INFO logs in normal operation. The sleep future
                        // is dropped (reset) every time poll() returns.
                        _ = tokio::time::sleep(KEEPALIVE_INTERVAL.mul_f32(0.8)) => {
                            let idle_s = KEEPALIVE_INTERVAL.as_secs() as f32 * 0.8;
                            tracing::trace!(
                                keepalive_s = KEEPALIVE_INTERVAL.as_secs(),
                                idle_s = idle_s,
                                "MQTT event loop idle near keepalive boundary — next PINGREQ imminent"
                            );
                            continue;
                        }
                    }
                }

                // ── Soft-restart: recreate client + EventLoop ──
                //
                // The old EventLoop is dropped (its TCP connection
                // closes). A fresh AsyncClient + EventLoop pair is
                // created with the same MqttOptions. The new AsyncClient
                // is swapped into the shared slot so publish callers
                // automatically use it.
                set_state(SessionState::Connecting);
                let mut fresh_options = task_options.clone();
                if let Some((username, password)) = task_handler_poll.on_soft_restart().await {
                    fresh_options.set_credentials(username, password);
                }
                let (new_client, new_eventloop) =
                    AsyncClient::new(fresh_options, queue_capacity);
                *task_shared_handle.lock().await = new_client;
                eventloop = new_eventloop;
                tracing::info!(
                    soft_restart_count,
                    "MQTT client soft-restarted with fresh EventLoop"
                );
            }
        });

        Ok(Self {
            shared_handle,
            state: state_tx,
            force_restart,
            _eventloop_guard: Arc::new(EventLoopGuard { task: poll_task }),
            _handler: task_handler,
        })
    }

    /// Clone of the shared inner client handle (swapped on soft-restart).
    pub fn shared_handle(&self) -> Arc<Mutex<AsyncClient>> {
        Arc::clone(&self.shared_handle)
    }

    /// Publish a raw binary payload.
    pub async fn publish_raw(
        &self,
        topic: &str,
        payload: Vec<u8>,
        qos: QoS,
        retain: bool,
    ) -> Result<(), MqttClientError> {
        self.shared_handle
            .lock()
            .await
            .publish(topic, qos, retain, payload)
            .await
            .map_err(|e| MqttClientError::Publish(format!("'{topic}': {e}")))?;
        Ok(())
    }

    /// Force a soft-restart of the MQTT event loop (wake recovery,
    /// diagnostics). Uses the shared `ForceRestart` (AtomicBool +
    /// Notify): a pending request is stored if nobody is waiting yet,
    /// so a call right after a connect is not lost.
    pub fn force_reconnect(&self) {
        self.force_restart.request();
    }

    /// Synchronously reset the session state to `Connecting` and request
    /// a soft-restart (wake recovery).
    ///
    /// Unlike [`MqttClient::force_reconnect`], this also flips the
    /// observable state immediately, so a subsequent
    /// [`MqttClient::wait_for_connected`] can never read a stale
    /// pre-sleep `Connected` value (the Desktop's `recover_after_wake`
    /// contract, ADR-065 Step 4).
    pub fn reset_to_connecting(&self) {
        self.state.set(SessionState::Connecting);
        self.force_restart.request();
    }

    /// Returns a new receiver that observes future state changes.
    pub fn state_rx(&self) -> SessionStateRx {
        self.state.subscribe()
    }

    /// Returns the current session state.
    pub fn current_state(&self) -> SessionState {
        self.state.current()
    }

    /// Wait for the client to reach `Connected` state.
    ///
    /// Returns `true` if connected within the timeout, `false`
    /// otherwise. Uses a simple polling loop instead of `subscribe()` +
    /// `changed()` to avoid the race where `Connected` is set between
    /// the subscribe and the `changed()` wait.
    pub async fn wait_for_connected(&self, timeout: Duration) -> bool {
        let deadline = tokio::time::Instant::now() + timeout;
        if self.state.current().is_connected() {
            return true;
        }
        while tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(100)).await;
            if self.state.current().is_connected() {
                return true;
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handler_defaults_are_noop() {
        // A handler that overrides nothing must compile and be callable.
        struct Noop;
        #[async_trait]
        impl MqttClientHandler for Noop {}

        let h = Noop;
        // The trait object must be Send + Sync (required by MqttClient).
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Noop>();
        let _ = h;
    }

    #[test]
    fn handler_with_ref_params_compiles() {
        // Regression guard for ADR-065 Step 4: an impl that overrides
        // methods with reference parameters (`&str`, `&[u8]`,
        // `&AsyncClient`) must compile under `#[async_trait]` — the
        // Node / Gateway / Runtime / Desktop handlers all do this.
        struct RefHandler;
        #[async_trait]
        impl MqttClientHandler for RefHandler {
            async fn on_publish(&self, _topic: &str, _payload: &[u8]) {}
            async fn on_connack(&self, _client: &AsyncClient) -> Result<(), String> {
                Ok(())
            }
            async fn on_disconnect(&self, _client: &AsyncClient) {}
            async fn on_error(&self, _client: &AsyncClient, _class: ErrClass, _error: &str) {}
            async fn on_soft_restart(&self) -> Option<(String, String)> {
                None
            }
        }
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<RefHandler>();
    }

    #[test]
    fn config_flows_into_client_error_type() {
        // Sanity: the error type is constructible and Display-able.
        let e = MqttClientError::Publish("boom".into());
        assert!(e.to_string().contains("boom"));
    }

    /// TCP configs address the broker by the plain host:port pair.
    #[test]
    fn tcp_config_uses_host_port_verbatim() {
        let cfg = MqttClientConfig::new("node:test", "127.0.0.1", 19875);
        let options = build_mqtt_options(&cfg);
        assert_eq!(options.broker_address(), ("127.0.0.1".to_string(), 19875));
    }

    /// WSS configs must land the FULL URL (scheme + authority + path)
    /// in the rumqttc broker_addr slot — rumqttc parses it with
    /// `split_url` for the TCP connect and uses it verbatim (including
    /// the `/mqtt` path) for the WebSocket handshake. A plain host
    /// here would connect to port 0 and fail the WS upgrade.
    #[test]
    fn wss_config_builds_url_addressed_options() {
        let mut cfg = MqttClientConfig::new("user:u-1:desktop:42", "ignored", 0);
        cfg.transport = MqttTransport::Wss {
            url: "wss://gw-abc.relay.example.com/mqtt".into(),
        };
        let options = build_mqtt_options(&cfg);
        assert_eq!(
            options.broker_address(),
            ("wss://gw-abc.relay.example.com/mqtt".to_string(), 443)
        );
    }

    #[tokio::test]
    async fn eventloop_guard_aborts_task_on_drop() {
        // Regression test for the desktop disconnect/reconnect loop:
        // prior to adding `impl Drop for EventLoopGuard`, dropping the
        // guard only detached the `JoinHandle` from the runtime registry
        // -- it did NOT abort the task. The stale poll task kept
        // running with the old TCP socket and raced against every
        // freshly-created client for the same `client_id`, producing
        // the broker error `Duplicate client_id, dropping previous
        // connection` in an infinite loop.
        //
        // This test asserts that dropping an `EventLoopGuard` causes
        // the wrapped task to be aborted, by polling `abort_handle()
        // .is_finished()` after the drop. If the `Drop` impl is
        // missing or broken, the task keeps sleeping and `is_finished`
        // stays false for the entire 2 s window.
        let task = tokio::spawn(async {
            tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
        });
        let abort_handle = task.abort_handle();

        let guard = EventLoopGuard { task };
        drop(guard);

        let mut finished = false;
        for _ in 0..100 {
            if abort_handle.is_finished() {
                finished = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(
            finished,
            "EventLoopGuard::drop did not abort the wrapped task within              2s; the Drop impl is missing or broken (this is the desktop              disconnect/reconnect-loop bug)."
        );
    }
}
