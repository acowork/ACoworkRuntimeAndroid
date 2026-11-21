//! Minimal MQTT session for Android Node ↔ Gateway (ADR-AND-003).
//!
//! Speaks rumqttc directly — no `acowork-mqtt-session` dependency. Covers:
//! CONNECT with `node:{id}` + optional password, LWT offline status,
//! subscribe enroll_result / control filters, publish enroll / info / ready /
//! status / events, and a background event loop with reconnect.

use std::sync::Arc;
use std::time::Duration;

use prost::Message;
use rumqttc::{AsyncClient, Event, Incoming, LastWill, MqttOptions, QoS, Transport};
use tokio::sync::{Mutex, Notify, RwLock, mpsc, watch};

use super::identity::NodeIdentity;
use super::proto::{
    DataEnvelope, NodeEnroll, NodeEnrollResult, NodeEvent, NodeInfo, NodeReady, data_envelope,
};
use super::topics::{
    NODE_PROTOCOL_VERSION, node_agent_control_filter, node_client_id, node_control_filter,
    node_enroll_result_topic, node_enroll_topic, node_info_topic, node_ready_topic,
    node_status_topic,
};

/// Inbound MQTT publish delivered to the serve loop.
#[derive(Debug, Clone)]
pub struct IncomingPublish {
    /// Topic string.
    pub topic: String,
    /// Raw payload bytes.
    pub payload: Vec<u8>,
}

/// Shared live CONNECT password (enrollment token → node_token).
pub type SharedCredentials = Arc<Mutex<Option<String>>>;

/// Shared rumqttc client. Reconnect keeps this handle: a second
/// `AsyncClient` with the same `node:{id}` is a duplicate session.
pub type SharedClient = Arc<Mutex<AsyncClient>>;

/// Handle returned by [`connect`].
pub struct MqttSession {
    /// rumqttc publish/subscribe handle (may be replaced on reconnect).
    pub client: SharedClient,
    /// Live password slot.
    pub credentials: SharedCredentials,
    /// Channel of inbound publishes (enroll_result + control).
    pub incoming: mpsc::UnboundedReceiver<IncomingPublish>,
    /// Fired when a ConnAck lands (first connect and every reconnect).
    pub connected: Arc<Notify>,
    /// One event per ConnAck after subscriptions are restored — serve
    /// re-announces status/info/ready/enroll on each.
    pub bootstrap: mpsc::UnboundedReceiver<()>,
    /// Stop flag for the poll task. A `watch`, deliberately: see `stop()`.
    stop_tx: watch::Sender<bool>,
    node_id: String,
}

impl MqttSession {
    /// Stop the background event loop.
    ///
    /// This is a level, not an edge. The previous `Notify::notify_waiters()`
    /// woke only the waiters registered at that instant, and the poll task
    /// re-creates its `notified()` future on every iteration — so a stop that
    /// landed while the task was inside `bootstrap_subscriptions` or the
    /// backoff branch was lost with nobody to receive it. The task then lived
    /// on holding the MQTT client id `node:{id}`; the next `start` opened a
    /// second client, the broker evicted one of them as a duplicate, and the
    /// pair kicked each other forever. Because every attempt still earned a
    /// CONNACK, the exponential backoff was reset to its 2s floor each time and
    /// never grew, so the node published `offline` on its LWT roughly twice a
    /// second and the Desktop could never see it online.
    pub fn stop(&self) {
        let _ = self.stop_tx.send(true);
    }

    /// Publish a protobuf [`DataEnvelope`].
    pub async fn publish_envelope(
        &self,
        topic: &str,
        envelope: &DataEnvelope,
        retain: bool,
    ) -> Result<(), MqttError> {
        let bytes = envelope.encode_to_vec();
        self.client
            .lock()
            .await
            .publish(topic, QoS::AtLeastOnce, retain, bytes)
            .await
            .map_err(|e| MqttError::Publish(e.to_string()))
    }

    /// Publish plain text (status online/offline).
    pub async fn publish_text(
        &self,
        topic: &str,
        text: &str,
        retain: bool,
    ) -> Result<(), MqttError> {
        self.client
            .lock()
            .await
            .publish(topic, QoS::AtLeastOnce, retain, text.as_bytes())
            .await
            .map_err(|e| MqttError::Publish(e.to_string()))
    }

    /// Clear a retained topic (empty payload, retain=true).
    pub async fn clear_retained(&self, topic: &str) -> Result<(), MqttError> {
        self.client
            .lock()
            .await
            .publish(topic, QoS::AtLeastOnce, true, Vec::<u8>::new())
            .await
            .map_err(|e| MqttError::Publish(e.to_string()))
    }

    /// Clear retained ready + set status offline (best-effort).
    pub async fn goodbye(&self) {
        let id = &self.node_id;
        let _ = self
            .client
            .lock()
            .await
            .publish(
                node_ready_topic(id),
                QoS::AtLeastOnce,
                true,
                Vec::<u8>::new(),
            )
            .await;
        let _ = self
            .publish_text(&node_status_topic(id), "offline", true)
            .await;
    }
}

/// MQTT failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MqttError {
    /// Client construction / options.
    Config(String),
    /// Publish failed.
    Publish(String),
    /// Subscribe failed.
    Subscribe(String),
}

impl std::fmt::Display for MqttError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MqttError::Config(e) | MqttError::Publish(e) | MqttError::Subscribe(e) => {
                write!(f, "{e}")
            }
        }
    }
}

impl std::error::Error for MqttError {}

/// Record an MQTT event-loop failure.
///
/// This must not be gated on `HOME`. An Android app process has no `HOME`
/// environment variable at all — its home is handed in explicitly as
/// `filesDir/acowork` — so the previous shape (`var_os("HOME")` or return)
/// meant every broker rejection on a phone went only to `eprintln!`, and
/// Zygote gives an app process a stderr that points at `/dev/null`. The
/// failure was therefore recorded nowhere, on the one platform where the
/// developer cannot also read the app's private files.
///
/// `tracing` is the channel that survives both worlds: on Android it reaches
/// logcat via `acowork-android-ffi::logcat`, on a desktop via the subscriber.
/// The `~/mqtt-error.log` fallback stays for the CLI, where `HOME` exists and
/// somebody may actually read it.
fn log_mqtt_error(msg: &str) {
    tracing::warn!("{msg}");
    let Some(home) = std::env::var_os("HOME") else {
        return;
    };
    let path = std::path::PathBuf::from(home).join("mqtt-error.log");
    let line = format!("{msg}\n");
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        use std::io::Write;
        let _ = file.write_all(line.as_bytes());
    }
}

fn build_options(client_id: &str, host: &str, port: u16, password: Option<&str>) -> MqttOptions {
    let node_id = client_id.strip_prefix("node:").unwrap_or(client_id);
    let status_topic = node_status_topic(node_id);
    let will = LastWill::new(&status_topic, "offline", QoS::AtLeastOnce, true);

    let mut opts = MqttOptions::new(client_id, host, port);
    opts.set_keep_alive(Duration::from_secs(30));
    opts.set_clean_session(true);
    opts.set_transport(Transport::Tcp);
    // Same ceiling as the broker and the desktop node (10 MiB). 256 KiB
    // made rumqttc drop the socket when a retained control/inventory
    // payload was larger, and the reconnect below then looked like a flap.
    opts.set_max_packet_size(10 * 1024 * 1024, 10 * 1024 * 1024);
    opts.set_last_will(will);
    if let Some(pw) = password {
        opts.set_credentials(client_id.to_string(), pw.to_string());
    }
    opts
}

/// Connect to the Gateway broker and start the poll task.
pub async fn connect(
    host: &str,
    port: u16,
    node_id: &str,
    initial_password: Option<String>,
) -> Result<MqttSession, MqttError> {
    let client_id = node_client_id(node_id);
    let opts = build_options(&client_id, host, port, initial_password.as_deref());
    let (client, eventloop) = AsyncClient::new(opts, 50);
    let shared_client: SharedClient = Arc::new(Mutex::new(client));
    let credentials: SharedCredentials = Arc::new(Mutex::new(initial_password));
    let (tx, rx) = mpsc::unbounded_channel();
    let (boot_tx, boot_rx) = mpsc::unbounded_channel();
    let connected = Arc::new(Notify::new());
    // Level-triggered stop: a `watch` keeps the value, so a `stop()` that
    // arrives while the task is between select! points is still observed.
    let (stop_tx, stop_rx) = watch::channel(false);

    let connected_task = Arc::clone(&connected);
    let mut stop_task = stop_rx;
    // A second receiver for the backoff wait: `changed()` reports transitions
    // against this receiver's own seen-version, so a clone made per pass would
    // start already-current and sleep out the whole backoff after a stop.
    let mut stop_backoff = stop_task.clone();
    let credentials_task = Arc::clone(&credentials);
    let shared_task = Arc::clone(&shared_client);
    let node_id_owned = node_id.to_string();
    let client_id_owned = client_id;

    tokio::spawn(async move {
        let mut eventloop = eventloop;
        // Floor backoff at 2s so a bad password / broker blip cannot LWT-flap at 1Hz.
        let mut backoff_ms: u64 = 2_000;
        loop {
            // Re-check the level at the top of every pass: `changed()` only
            // reports transitions it sees while registered, and this task is
            // not registered for the duration of the branches below.
            if *stop_task.borrow_and_update() {
                break;
            }
            tokio::select! {
                _ = stop_task.changed() => break,
                event = eventloop.poll() => {
                    match event {
                        Ok(Event::Incoming(Incoming::ConnAck(_))) => {
                            backoff_ms = 2_000;
                            connected_task.notify_waiters();
                            let client = shared_task.lock().await;
                            if bootstrap_subscriptions(&client, &node_id_owned)
                                .await
                                .is_ok()
                            {
                                let _ = boot_tx.send(());
                            }
                        }
                        Ok(Event::Incoming(Incoming::Publish(p))) => {
                            let _ = tx.send(IncomingPublish {
                                topic: p.topic,
                                payload: p.payload.to_vec(),
                            });
                        }
                        Ok(_) => {}
                        Err(e) => {
                            // Keep this EventLoop. `poll` clears the socket
                            // (`clean`) and the next `poll` reconnects.
                            // Building a new AsyncClient while the broker
                            // still has `node:{id}` makes rumqttd drop the
                            // live session (Duplicate client_id) and the
                            // LWT publishes offline — a 2s flap.
                            log_mqtt_error(&format!(
                                "acowork-android mqtt: {e} — retry in {backoff_ms}ms"
                            ));
                            tokio::select! {
                                _ = stop_backoff.changed() => break,
                                _ = tokio::time::sleep(Duration::from_millis(backoff_ms)) => {}
                            }
                            backoff_ms = (backoff_ms.saturating_mul(2)).min(30_000);
                            // Enrollment token is one-shot. After enroll, the
                            // serve loop stores node_token here; the next
                            // CONNECT must use it. The socket is already down
                            // (`poll` ran `clean`), so this does not open a
                            // second session.
                            if let Some(pw) = credentials_task.lock().await.clone() {
                                eventloop
                                    .mqtt_options
                                    .set_credentials(client_id_owned.clone(), pw);
                            }
                        }
                    }
                }
            }
        }
    });

    tokio::select! {
        _ = connected.notified() => {}
        _ = tokio::time::sleep(Duration::from_secs(8)) => {}
    }

    Ok(MqttSession {
        client: shared_client,
        credentials,
        incoming: rx,
        connected,
        bootstrap: boot_rx,
        stop_tx,
        node_id: node_id.to_string(),
    })
}

async fn bootstrap_subscriptions(client: &AsyncClient, node_id: &str) -> Result<(), MqttError> {
    for filter in [
        node_enroll_result_topic(node_id),
        node_control_filter(node_id),
        node_agent_control_filter(node_id),
    ] {
        client
            .subscribe(filter, QoS::AtLeastOnce)
            .await
            .map_err(|e| MqttError::Subscribe(e.to_string()))?;
    }
    Ok(())
}

/// Build a `DataEnvelope<NodeEnroll>`.
pub fn enroll_envelope(
    identity: &NodeIdentity,
    capabilities: Vec<String>,
    enrollment_token: &str,
) -> DataEnvelope {
    let enroll = NodeEnroll {
        node_id: identity.node_id.clone(),
        os: node_os(),
        arch: std::env::consts::ARCH.to_string(),
        node_version: env!("CARGO_PKG_VERSION").to_string(),
        protocol_version: NODE_PROTOCOL_VERSION,
        capabilities,
        enrollment_token: enrollment_token.to_string(),
    };
    DataEnvelope {
        version: 1,
        payload: Some(data_envelope::Payload::NodeEnroll(enroll)),
    }
}

/// Build a retained `DataEnvelope<NodeInfo>`.
pub fn info_envelope(
    identity: &NodeIdentity,
    capabilities: Vec<String>,
    http_endpoint: &str,
    agent_count: u32,
    max_agents: u32,
) -> DataEnvelope {
    let info = NodeInfo {
        node_id: identity.node_id.clone(),
        hostname: hostname(),
        os: node_os(),
        arch: std::env::consts::ARCH.to_string(),
        node_version: env!("CARGO_PKG_VERSION").to_string(),
        protocol_version: NODE_PROTOCOL_VERSION,
        capabilities,
        max_agents,
        agent_count,
        http_endpoint: http_endpoint.to_string(),
        node_name: identity.node_name.clone(),
    };
    DataEnvelope {
        version: 1,
        payload: Some(data_envelope::Payload::NodeInfo(info)),
    }
}

/// Build a retained `DataEnvelope<NodeReady>`.
pub fn ready_envelope(node_id: &str) -> DataEnvelope {
    DataEnvelope {
        version: 1,
        payload: Some(data_envelope::Payload::NodeReady(NodeReady {
            node_id: node_id.to_string(),
            protocol_version: NODE_PROTOCOL_VERSION,
        })),
    }
}

/// Build a `DataEnvelope<NodeEvent>`.
pub fn event_envelope(
    node_id: &str,
    request_id: &str,
    status: &str,
    message: &str,
) -> DataEnvelope {
    DataEnvelope {
        version: 1,
        payload: Some(data_envelope::Payload::NodeEvent(NodeEvent {
            node_id: node_id.to_string(),
            request_id: request_id.to_string(),
            status: status.to_string(),
            message: message.to_string(),
            result_json: None,
        })),
    }
}

/// Decode an enroll_result payload; `None` if not that shape.
pub fn decode_enroll_result(bytes: &[u8]) -> Option<NodeEnrollResult> {
    let envelope = DataEnvelope::decode(bytes).ok()?;
    match envelope.payload? {
        data_envelope::Payload::NodeEnrollResult(r) => Some(r),
        _ => None,
    }
}

/// Decode any control-plane [`DataEnvelope`].
pub fn decode_envelope(bytes: &[u8]) -> Result<DataEnvelope, prost::DecodeError> {
    DataEnvelope::decode(bytes)
}

/// Publish the full post-connect announcement set.
///
/// When `enroll` is false (already holding a Gateway-issued node_token),
/// skip `/enroll` — reconnect must only re-assert presence. Re-enrolling
/// on every ConnAck during an MQTT flap storms Gateway capability
/// registration and Desktop inventory refetch.
pub async fn announce(
    session: &MqttSession,
    identity: &NodeIdentity,
    capabilities: Vec<String>,
    http_endpoint: &str,
    agent_count: u32,
    enrollment_token: &str,
) -> Result<(), MqttError> {
    announce_with_enroll(
        session,
        identity,
        capabilities,
        http_endpoint,
        agent_count,
        enrollment_token,
        identity.node_token.is_none(),
    )
    .await
}

/// Like [`announce`], with explicit control over the `/enroll` publish.
pub async fn announce_with_enroll(
    session: &MqttSession,
    identity: &NodeIdentity,
    capabilities: Vec<String>,
    http_endpoint: &str,
    agent_count: u32,
    enrollment_token: &str,
    enroll: bool,
) -> Result<(), MqttError> {
    let id = &identity.node_id;
    session
        .publish_text(&node_status_topic(id), "online", true)
        .await?;
    if enroll {
        session
            .publish_envelope(
                &node_enroll_topic(id),
                &enroll_envelope(identity, capabilities.clone(), enrollment_token),
                false,
            )
            .await?;
    }
    session
        .publish_envelope(
            &node_info_topic(id),
            &info_envelope(identity, capabilities, http_endpoint, agent_count, 16),
            true,
        )
        .await?;
    session
        .publish_envelope(&node_ready_topic(id), &ready_envelope(id), true)
        .await?;
    Ok(())
}

/// Publish a NodeEvent on an explicit topic (PC `publish_event` shape).
///
/// Caller selects agent- vs node-scoped events via
/// `node_agent_events_topic` / `node_events_topic` after `parse_control_topic`.
pub async fn publish_event(
    session: &MqttSession,
    topic: &str,
    node_id: &str,
    request_id: &str,
    status: &str,
    message: &str,
) -> Result<(), MqttError> {
    session
        .publish_envelope(
            topic,
            &event_envelope(node_id, request_id, status, message),
            false,
        )
        .await
}

fn node_os() -> String {
    if cfg!(target_os = "android") {
        "android".into()
    } else {
        std::env::consts::OS.to_string()
    }
}

fn hostname() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "android".into())
}

/// Shared identity cell the MQTT / proxy / control paths all read.
pub type SharedIdentity = Arc<RwLock<NodeIdentity>>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::identity::{EnrollmentState, NodeIdentity};

    /// The poll task is not registered for a stop signal while it is inside
    /// `bootstrap_subscriptions()` or the error branches. A stop landing in
    /// that window still has to stop it: otherwise the next `start()` opens a
    /// second client under the same `node:{id}`, the broker kicks both, and the
    /// node never settles online.
    #[tokio::test]
    async fn stop_landed_while_the_poll_task_was_not_waiting_still_stops_it() {
        let (stop_tx, mut stop_rx) = watch::channel(false);

        let busy = tokio::spawn(async move {
            loop {
                // The un-registered window: work between `select!` points.
                tokio::time::sleep(Duration::from_millis(20)).await;
                if *stop_rx.borrow_and_update() {
                    return true;
                }
                tokio::select! {
                    _ = stop_rx.changed() => return true,
                    _ = tokio::time::sleep(Duration::from_millis(5)) => {}
                }
            }
        });

        // Signal while the task is parked in that window, not waiting.
        tokio::time::sleep(Duration::from_millis(1)).await;
        let _ = stop_tx.send(true);

        assert!(
            tokio::time::timeout(Duration::from_millis(300), busy)
                .await
                .expect("poll task never observed a stop that arrived outside its select! window")
                .expect("task panicked")
        );
    }

    /// Why the previous mechanism lost that signal: `notify_waiters()` is
    /// edge-triggered and stores no permit, so a task that was not waiting at
    /// that instant never learns a stop happened.
    #[tokio::test]
    async fn notify_waiters_is_edge_triggered_and_drops_the_signal() {
        let n = Arc::new(Notify::new());
        n.notify_waiters();

        assert!(
            tokio::time::timeout(Duration::from_millis(50), n.notified())
                .await
                .is_err(),
            "a waiter registered after the notification must not be woken"
        );
    }

    #[test]
    fn enroll_envelope_round_trips_through_prost() {
        let id = NodeIdentity {
            node_id: "00000000-0000-4000-8000-000000000001".into(),
            node_name: "phone-1".into(),
            node_token: None,
            gateway_addr: None,
            enrollment: EnrollmentState::Created,
            created_at: 0,
            enrolled_at: None,
            enrolled_with: None,
        };
        let env = enroll_envelope(&id, vec!["control_plane".into()], "tok");
        let bytes = env.encode_to_vec();
        let decoded = DataEnvelope::decode(bytes.as_slice()).unwrap();
        match decoded.payload.unwrap() {
            data_envelope::Payload::NodeEnroll(e) => {
                assert_eq!(e.node_id, id.node_id);
                assert_eq!(e.enrollment_token, "tok");
                assert_eq!(e.protocol_version, NODE_PROTOCOL_VERSION);
            }
            other => panic!("unexpected {other:?}"),
        }
    }
}
