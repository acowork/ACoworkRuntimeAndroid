//! MQTT client configuration + timing constants (ADR-065 §5.2).
//!
//! Single source of truth for the MQTT lifecycle timing parameters.
//! The four MQTT clients (Desktop / Node / Runtime / Gateway publisher)
//! MUST NOT override these — [`MqttClientConfig`] only exposes entity
//! fields (client_id / host / port / credentials / last_will / packet
//! size / queue capacity). Timing fields are deliberately absent so the
//! four clients cannot drift apart again (ADR-065 §2.3).

use std::time::Duration;

/// MQTT keepalive interval. Matches the broker's `connection_timeout_ms`
/// (5 s, see `core/acowork-gateway/src/mqtt/broker.rs`). A healthy
/// connection emits a PINGRESP within every keepalive interval, so the
/// broker never times out an alive client.
pub const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(5);

/// Watchdog timeout for `eventloop.poll()`. 1 × keepalive: silence for
/// 5 s means a half-dead socket (e.g. after OS sleep/wake where the
/// kernel hasn't detected the broken connection). The poll task breaks
/// to the soft-restart path, which drops the old EventLoop and creates
/// a fresh TCP connection.
///
/// History: Desktop/Node already used 5 s; Gateway used 20 s and
/// Runtime used 60 s (to dodge long HTTP handlers). ADR-065 §2.3 unifies
/// on 5 s — the correct fix for long handlers is "keep watchdog 5 s +
/// actively feed PINGREQ during long tasks", not widening the watchdog
/// (which also widens wake-recovery latency).
pub const POLL_WATCHDOG_TIMEOUT: Duration = Duration::from_secs(5);

/// Power-probe sampling interval (ADR-065 §5.2). Must be well below the
/// 5 s wake threshold so a resume is detected within ~2 s.
pub const POWER_PROBE_INTERVAL: Duration = Duration::from_secs(2);

/// Minimum *actual* sleep duration to trigger wake recovery (ADR-065
/// §5.2). We measure real sleep (biased − unbiased monotonic clocks),
/// not wall-clock gaps, so even a few seconds is significant; 5 s
/// filters timer imprecision.
pub const WAKE_DETECT_THRESHOLD: Duration = Duration::from_secs(5);

/// Fatal-error backoff (E2/E3/E4/E6). Interruptible by force-restart so
/// wake recovery never waits it out (ADR-065 §2.3).
pub const FATAL_BACKOFF: Duration = Duration::from_secs(60);

/// Consecutive fatal errors before a soft-restart (recreate client +
/// EventLoop from scratch).
pub const FATAL_STREAK_LIMIT: u32 = 3;

/// Default MQTT max packet size (10 MB). Mirrors
/// `acowork_core::defaults::GATEWAY_MQTT_MAX_PACKET_SIZE` — duplicated
/// here because `acowork-mqtt-session` must not depend on `acowork-core`.
pub const DEFAULT_MAX_PACKET_SIZE: usize = 10 * 1024 * 1024;

/// MQTT network transport (relay remote mode, design doc 24 §8.0).
///
/// All local / LAN clients use [`MqttTransport::Tcp`] — the transport
/// only diverges when a Desktop connects through the cloud relay, where
/// the broker is reached as a WebSocket inside the relay's TLS stream.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum MqttTransport {
    /// Plain TCP to `host:port` (default; every local client).
    #[default]
    Tcp,
    /// Secure WebSocket. `url` is the FULL broker address including
    /// scheme, authority and path — e.g. `wss://gw-abc.relay.example.com/mqtt`
    /// — exactly as rumqttc expects it in the `MqttOptions` "host" slot
    /// (`eventloop.rs` parses it with `split_url` for the TCP connect and
    /// uses it verbatim for the WS handshake). The `host` / `port` fields
    /// of [`MqttClientConfig`] are IGNORED for this transport.
    Wss { url: String },
}

/// Entity-only MQTT client configuration (ADR-065 §5.6).
///
/// Timing fields are deliberately NOT exposed — the single source of
/// truth lives in this crate's constants above.
#[derive(Debug, Clone)]
pub struct MqttClientConfig {
    /// MQTT client identifier (protocol §8.5 colon convention).
    pub client_id: String,
    /// Broker host. Used by [`MqttTransport::Tcp`] only; ignored by
    /// [`MqttTransport::Wss`] (which carries its full URL internally).
    pub host: String,
    /// Broker port. Used by [`MqttTransport::Tcp`] only.
    pub port: u16,
    /// Network transport (TCP vs WSS-through-relay). Defaults to TCP.
    pub transport: MqttTransport,    /// Optional CONNECT credentials `(username, password)`.
    pub credentials: Option<(String, String)>,
    /// Optional Last Will (broker publishes it if the client dies
    /// ungracefully).
    pub last_will: Option<rumqttc::LastWill>,
    /// Max packet size (in + out). Defaults to [`DEFAULT_MAX_PACKET_SIZE`].
    pub max_packet_size: usize,
    /// rumqttc `AsyncClient::new` request queue capacity.
    pub queue_capacity: usize,
}

impl MqttClientConfig {
    /// Create a config with the given identity and broker address.
    pub fn new(client_id: impl Into<String>, host: impl Into<String>, port: u16) -> Self {
        Self {
            client_id: client_id.into(),
            host: host.into(),
            port,
            transport: MqttTransport::Tcp,
            credentials: None,
            last_will: None,
            max_packet_size: DEFAULT_MAX_PACKET_SIZE,
            queue_capacity: 100,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timing_constants_are_unified() {
        // ADR-065 §2.3: keepalive == watchdog == 5 s; probe 2 s;
        // wake threshold 5 s; fatal backoff 60 s; streak 3.
        assert_eq!(KEEPALIVE_INTERVAL, Duration::from_secs(5));
        assert_eq!(POLL_WATCHDOG_TIMEOUT, Duration::from_secs(5));
        assert_eq!(POWER_PROBE_INTERVAL, Duration::from_secs(2));
        assert_eq!(WAKE_DETECT_THRESHOLD, Duration::from_secs(5));
        assert_eq!(FATAL_BACKOFF, Duration::from_secs(60));
        assert_eq!(FATAL_STREAK_LIMIT, 3);
    }

    #[test]
    fn config_defaults() {
        let cfg = MqttClientConfig::new("node:test", "127.0.0.1", 19875);
        assert_eq!(cfg.client_id, "node:test");
        assert_eq!(cfg.host, "127.0.0.1");
        assert_eq!(cfg.port, 19875);
        assert_eq!(cfg.transport, MqttTransport::Tcp);
        assert!(cfg.credentials.is_none());
        assert!(cfg.last_will.is_none());
        assert_eq!(cfg.max_packet_size, DEFAULT_MAX_PACKET_SIZE);
        assert_eq!(cfg.queue_capacity, 100);
    }

    #[test]
    fn wss_transport_overrides_host_port_semantics() {
        // Relay remote mode: the WSS URL is the single address — the
        // host/port pair is inert for this transport. The constructor
        // still defaults to TCP; WSS callers set the field explicitly.
        let mut cfg = MqttClientConfig::new("user:u-1:desktop:42", "ignored", 0);
        cfg.transport = MqttTransport::Wss {
            url: "wss://gw-abc.relay.example.com/mqtt".into(),
        };
        assert_eq!(
            cfg.transport,
            MqttTransport::Wss {
                url: "wss://gw-abc.relay.example.com/mqtt".into()
            }
        );
        // Default remains TCP — existing local clients never change
        // transport by accident.
        assert_eq!(
            MqttClientConfig::new("node:test", "127.0.0.1", 19875).transport,
            MqttTransport::default()
        );
    }

    #[test]
    fn config_is_cloneable() {
        let cfg = MqttClientConfig::new("node:test", "127.0.0.1", 19875);
        let cfg2 = cfg.clone();
        assert_eq!(cfg.client_id, cfg2.client_id);
    }
}
