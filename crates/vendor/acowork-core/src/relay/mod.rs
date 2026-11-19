//! Cloud relay tunnel protocol (design doc `24-cloud-relay-remote-access` v0.2).
//!
//! Shared by `acowork-relay` (server) and the Gateway `relay` client module:
//!
//! - [`proto`] — control frames exchanged on the tunnel's first yamux stream
//!   (newline-delimited JSON) plus the Ed25519 device-credential helpers.
//! - [`ws_stream`] — the WebSocket ↔ byte-stream adapter yamux needs.
//!
//! Design invariants (§5.2–§5.4):
//! - The tunnel is a single outbound WSS connection from the Gateway to the
//!   relay (`/tunnel` on the relay's service domain).
//! - Every data stream the relay opens toward the Gateway starts with a
//!   one-byte tag selecting the local listener to forward to.
//! - Device authentication is Ed25519 challenge-response with TOFU
//!   first-connect enrollment; the private key never leaves the Gateway.

pub mod driver;
pub mod proto;
pub mod ws_stream;

/// Grace period between "a farewell frame (Rejected/GOAWAY/Deregister)
/// was queued on a stream" and "the connection is torn down".
///
/// yamux 0.14 queues all stream writes through the single driver task; a
/// frame is only on the wire after one more driver poll cycle. Aborting
/// the driver immediately can drop the frame, so the peer would see a
/// bare connection close instead of the reason. Used by BOTH sides
/// (relay teardown paths, Gateway deregister).
pub const TEARDOWN_GRACE: std::time::Duration = std::time::Duration::from_millis(150);

/// Inactivity ceiling for one byte pipe (§5.2): a device-domain pipe on the
/// relay, or a tunnel stream forwarded to the Gateway's remote listener.
///
/// The quietest legitimate traffic on such a pipe is the Desktop's MQTT
/// client, which sends a PINGREQ every 5 s (`acowork-mqtt-session`
/// `KEEPALIVE_INTERVAL`), and an idle HTTP keep-alive connection is
/// disposable. 60 s is therefore ~12x margin over anything that must stay
/// open, while still recycling a wedged connection inside a minute rather
/// than leaving the client queueing on it indefinitely.
///
/// ponytail: inactivity cannot tell "wedged" from "thinking". A request
/// that stays silent end-to-end for >60 s is cut here — the only known
/// exposure is a NON-streaming provider call proxied through the Gateway
/// (streaming is safe: `Sse::keep_alive` comments every 15 s). Raise this
/// constant if such a call ever shows up over a relay link.
pub const PIPE_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// Stream tag: forward the stream to the Gateway remote HTTP listener
/// (`127.0.0.1:19877`, includes the `/mqtt` WebSocket bridge).
pub const STREAM_TAG_HTTP: u8 = 0x01;

/// Stream tag: forward the stream to the Gateway remote MQTT listener
/// (`127.0.0.1:19874`) as raw MQTT bytes.
///
/// Reserved for future use — in the v0.2 topology MQTT-over-WSS enters via
/// the HTTP listener's `/mqtt` route, so all current traffic is
/// [`STREAM_TAG_HTTP`]. The tag keeps the framing extensible without a
/// protocol change should a raw-MQTT path be needed later.
pub const STREAM_TAG_MQTT: u8 = 0x02;
