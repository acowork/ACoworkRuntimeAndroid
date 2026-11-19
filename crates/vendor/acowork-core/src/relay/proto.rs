//! Relay tunnel control protocol (design doc 24 §5.4, v0.2).
//!
//! Frames are newline-delimited JSON ("ndjson") exchanged on the tunnel's
//! first yamux stream. The handshake is an Ed25519 challenge-response:
//!
//! ```text
//! Gateway → relay:  Register { gw_id, pubkey, ts }
//! relay → Gateway:  Challenge { nonce }
//! Gateway → relay:  Proof { sig }          (Ed25519 over the nonce)
//! relay → Gateway:  Registered { session_id, keepalive_s }
//! ```
//!
//! First-connect enrollment is TOFU (trust on first use): the relay stores
//! the claimed public key and pins it for all later registrations. The
//! private key never leaves the Gateway (persisted as a `0600` file in the
//! Gateway config dir — see design doc 24 §7.3, v0.2.1: deliberately NOT
//! vault-backed, so the tunnel can come up before any vault unlock).

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

/// Domain-separation prefix for proof signatures, so a device key cannot be
/// tricked into signing some other protocol's payload with the same bytes.
const PROOF_PREFIX: &[u8] = b"acowork-relay-proof:";

/// Structured error body the relay writes back (as HTTP 502) when the target
/// gateway tunnel is not registered or is down (§5.3 "离线显式化").
pub const DEVICE_OFFLINE_BODY: &str = "{\"code\":\"DEVICE_OFFLINE\"}";

/// The control-protocol version this build speaks (`proto` field on
/// [`ControlFrame::Register`] / [`ControlFrame::Registered`]).
///
/// The wire format as originally specified — before any `proto` field
/// existed — is version **1**. Implementations predating this constant
/// never send `proto`, which decodes as 1 via `#[serde(default)]`.
pub const PROTO_VERSION: u16 = 1;

/// Oldest control-protocol version this build still accepts.
pub const MIN_SUPPORTED_PROTO: u16 = 1;

/// Whether a peer speaking `version` can be served. A relay that sees an
/// out-of-range `proto` replies [`ControlFrame::Rejected`] with
/// [`REASON_UNSUPPORTED_PROTO`] and drops the tunnel.
pub fn proto_is_supported(version: u16) -> bool {
    (MIN_SUPPORTED_PROTO..=PROTO_VERSION).contains(&version)
}

/// Rejection reason used when a peer announces an unsupported `proto`.
pub const REASON_UNSUPPORTED_PROTO: &str = "unsupported protocol version";

/// One control frame on the tunnel control stream.
///
/// Wire format: `{"type":"snake_case_variant", ...}` — one JSON document per
/// `\n`-terminated line.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ControlFrame {
    /// Gateway → relay: identify the device and claim the tunnel.
    Register {
        /// Random UUID v4 device identifier (OQ-4: no user semantics).
        gw_id: String,
        /// Ed25519 public key, URL-safe base64 (raw 32 bytes).
        pubkey: String,
        /// Unix seconds; audited for clock skew, not relied on for replay
        /// protection (the challenge nonce is).
        ts: u64,
        /// Control-protocol version. Absent on the wire means [`PROTO_VERSION`]
        /// (1) — the original format, so pre-versioning peers still parse.
        #[serde(default = "default_proto")]
        proto: u16,
        /// Optional extension names this peer supports, e.g. `["tenant.v1"]`.
        /// Purely advisory: unknown entries are ignored by the receiver, so
        /// adding one never breaks an older peer. A receiver must not infer
        /// behaviour from a capability it does not itself implement.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        caps: Vec<String>,
    },
    /// Relay → gateway: single-use challenge (URL-safe base64, 32 bytes).
    Challenge { nonce: String },
    /// Gateway → relay: Ed25519 signature over `PROOF_PREFIX || nonce`.
    Proof { sig: String },
    /// Relay → gateway: tunnel registration accepted.
    Registered {
        session_id: String,
        keepalive_s: u64,
        /// The protocol version the relay actually selected for this tunnel.
        /// Echoed so the Gateway can detect a relay that pinned an older
        /// version than the one it offered. Absent means 1.
        #[serde(default = "default_proto")]
        proto: u16,
        /// Extensions the relay supports, same advisory semantics as
        /// [`ControlFrame::Register::caps`].
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        relay_caps: Vec<String>,
    },
    /// Relay → gateway (existing tunnel): superseded by a newer registration,
    /// kicked by admin revocation, or shutting down.
    Goaway { reason: String },
    /// Registration rejected (bad proof, key mismatch, TOFU disabled, rate
    /// limited, ...). The relay closes the tunnel right after.
    Rejected { reason: String },
    /// Gateway → relay (on the authenticated control stream): rotate the
    /// pinned public key. `sig` proves possession of the OLD private key and
    /// is computed over `PROOF_PREFIX || b"rotate:" || new_pubkey`.
    RotateKey { new_pubkey: String, sig: String },
    /// Gateway → relay: graceful tunnel shutdown (relay drops the entry).
    Deregister,
    /// Gateway → relay: liveness probe (yamux 0.14 has no built-in
    /// keepalive; the control stream carries it instead). `ts` is the
    /// sender's Unix-millis clock for one-way delay observability.
    Ping { ts_ms: u64 },
    /// Relay → gateway: reply to [`ControlFrame::Ping`], echoing `ts_ms`.
    Pong { ts_ms: u64 },
}

/// serde default for the `proto` field: a frame that omits it predates
/// versioning and is, by definition, [`PROTO_VERSION`].
fn default_proto() -> u16 {
    PROTO_VERSION
}

/// Encode one frame as an ndjson line (with trailing `\n`).
pub fn encode_frame(frame: &ControlFrame) -> Result<String, serde_json::Error> {
    let mut line = serde_json::to_string(frame)?;
    line.push('\n');
    Ok(line)
}

/// Decode one frame from a single ndjson line (leading/trailing whitespace
/// including the `\n` is ignored).
///
/// Strict: an unknown `type` is an error. For the control stream prefer
/// [`read_control_frame`], which tolerates frames a peer added and this
/// build does not know.
pub fn decode_frame(line: &str) -> Result<ControlFrame, serde_json::Error> {
    serde_json::from_str(line.trim())
}

/// Max accepted length of one ndjson control line (bytes).
pub const MAX_CONTROL_LINE: usize = 8 * 1024;

/// Outcome of reading one line off the control stream.
#[derive(Debug, Clone, PartialEq)]
pub enum Frame {
    /// A frame this build understands.
    Known(ControlFrame),
    /// Well-formed JSON carrying a `type` we do not know. Callers **skip**
    /// these; the tunnel keeps running. See [`decode_frame_lenient`].
    UnknownFrame,
}

/// Read one ndjson control frame from a stream (up to and including the
/// terminating `\n`). Shared by the relay server, the Gateway
/// relay-client, and tests — one wire-reading implementation.
///
/// This is the **lenient** reader: an unrecognised frame type yields
/// [`Frame::UnknownFrame`] instead of an error, so a peer running a newer
/// protocol revision cannot tear down the tunnel by using a feature this
/// build lacks. Malformed input (bad JSON, missing `type`) still errors.
pub async fn read_control_frame<S>(stream: &mut S) -> Result<Frame, String>
where
    S: futures_util::io::AsyncRead + Unpin,
{
    let line = read_control_line(stream).await?;
    match decode_frame(&line) {
        Ok(frame) => Ok(Frame::Known(frame)),
        Err(e) => match serde_json::from_str::<serde_json::Value>(&line) {
            // Valid JSON that is not a frame we know: skip it. A `type` key
            // is what distinguishes "newer peer" from "garbage".
            Ok(value) if value.get("type").is_some() => Ok(Frame::UnknownFrame),
            // Either not JSON, or JSON without a discriminator: a real error.
            _ => Err(format!("invalid control frame: {e}")),
        },
    }
}

/// Read one ndjson control frame, expecting a known frame type.
pub async fn read_control_frame_known<S>(stream: &mut S) -> Result<ControlFrame, String>
where
    S: futures_util::io::AsyncRead + Unpin,
{
    loop {
        match read_control_frame(stream).await? {
            Frame::Known(frame) => return Ok(frame),
            // Skip and keep waiting — see `read_control_frame`.
            Frame::UnknownFrame => continue,
        }
    }
}

/// Read one raw ndjson line (up to and including the terminating `\n`),
/// validating length but not JSON.
async fn read_control_line<S>(stream: &mut S) -> Result<String, String>
where
    S: futures_util::io::AsyncRead + Unpin,
{
    use futures_util::io::AsyncReadExt as _;
    let mut line = Vec::new();
    loop {
        let mut byte = [0u8; 1];
        let n = stream.read(&mut byte).await.map_err(|e| e.to_string())?;
        if n == 0 {
            return Err("control stream closed mid-frame".into());
        }
        if byte[0] == b'\n' {
            break;
        }
        line.push(byte[0]);
        if line.len() > MAX_CONTROL_LINE {
            return Err(format!("control line exceeds {MAX_CONTROL_LINE} bytes"));
        }
    }
    std::str::from_utf8(&line)
        .map(str::to_owned)
        .map_err(|e| e.to_string())
}

/// Write one ndjson control frame to a stream and flush it.
pub async fn write_control_frame<W>(stream: &mut W, frame: &ControlFrame) -> Result<(), String>
where
    W: futures_util::io::AsyncWrite + Unpin,
{
    use futures_util::io::AsyncWriteExt as _;
    let line = encode_frame(frame).map_err(|e| e.to_string())?;
    stream
        .write_all(line.as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    stream.flush().await.map_err(|e| e.to_string())?;
    Ok(())
}

/// Generate a fresh single-use challenge nonce (URL-safe base64, 32 bytes).
pub fn generate_nonce() -> String {
    let mut bytes = [0u8; 32];
    rand::fill(&mut bytes);
    B64.encode(bytes)
}

/// Whether `s` is a well-formed device identifier (UUID v4).
///
/// gw-ids are random by design (OQ-4): they appear in the relay SNI, so they
/// must not carry user semantics, and their entropy is what makes TOFU
/// first-connect enrollment safe against squatting.
pub fn is_valid_gw_id(s: &str) -> bool {
    match uuid::Uuid::parse_str(s) {
        Ok(id) => id.get_version_num() == 4,
        Err(_) => false,
    }
}

/// Generate a fresh device keypair seed (raw 32 bytes) — the Gateway stores
/// it in the vault and derives the [`SigningKey`] on load.
pub fn generate_device_seed() -> [u8; 32] {
    let mut seed = [0u8; 32];
    rand::fill(&mut seed);
    seed
}

/// Encode a device public key for the wire (raw 32 bytes → URL-safe base64).
pub fn encode_pubkey(key: &VerifyingKey) -> String {
    B64.encode(key.as_bytes())
}

/// Decode a device public key from the wire representation.
pub fn decode_pubkey(s: &str) -> Result<VerifyingKey, String> {
    let bytes: [u8; 32] = B64
        .decode(s)
        .map_err(|e| format!("invalid pubkey base64: {e}"))?
        .try_into()
        .map_err(|v: Vec<u8>| format!("pubkey must be 32 bytes, got {}", v.len()))?;
    VerifyingKey::from_bytes(&bytes).map_err(|e| format!("invalid pubkey: {e}"))
}

/// Sign a challenge nonce: Ed25519 over `PROOF_PREFIX || nonce`.
pub fn sign_nonce(key: &SigningKey, nonce: &str) -> String {
    let mut payload = Vec::with_capacity(PROOF_PREFIX.len() + nonce.len());
    payload.extend_from_slice(PROOF_PREFIX);
    payload.extend_from_slice(nonce.as_bytes());
    B64.encode(key.sign(&payload).to_bytes())
}

/// Verify a challenge-nonce signature. Returns `false` on any mismatch —
/// callers must not distinguish signature errors from bad encodings.
pub fn verify_nonce_sig(key: &VerifyingKey, nonce: &str, sig_b64: &str) -> bool {
    let Ok(sig_bytes) = B64.decode(sig_b64) else {
        return false;
    };
    let Ok(sig) = Signature::from_slice(&sig_bytes) else {
        return false;
    };
    let mut payload = Vec::with_capacity(PROOF_PREFIX.len() + nonce.len());
    payload.extend_from_slice(PROOF_PREFIX);
    payload.extend_from_slice(nonce.as_bytes());
    key.verify(&payload, &sig).is_ok()
}

/// Sign a `RotateKey` request: Ed25519 over
/// `PROOF_PREFIX || b"rotate:" || new_pubkey` with the OLD private key.
pub fn sign_key_rotation(old_key: &SigningKey, new_pubkey: &str) -> String {
    let mut payload = Vec::new();
    payload.extend_from_slice(PROOF_PREFIX);
    payload.extend_from_slice(b"rotate:");
    payload.extend_from_slice(new_pubkey.as_bytes());
    B64.encode(old_key.sign(&payload).to_bytes())
}

/// Verify a `RotateKey` signature against the currently pinned public key.
pub fn verify_key_rotation(
    old_pubkey: &VerifyingKey,
    new_pubkey: &str,
    sig_b64: &str,
) -> bool {
    let Ok(sig_bytes) = B64.decode(sig_b64) else {
        return false;
    };
    let Ok(sig) = Signature::from_slice(&sig_bytes) else {
        return false;
    };
    let mut payload = Vec::new();
    payload.extend_from_slice(PROOF_PREFIX);
    payload.extend_from_slice(b"rotate:");
    payload.extend_from_slice(new_pubkey.as_bytes());
    old_pubkey.verify(&payload, &sig).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(frame: ControlFrame) {
        let line = encode_frame(&frame).unwrap();
        assert!(line.ends_with('\n'));
        let back = decode_frame(&line).unwrap();
        assert_eq!(back, frame);
    }

    #[test]
    fn frames_roundtrip() {
        roundtrip(ControlFrame::Register {
            gw_id: "0f1e2d3c-4b5a-4678-9abc-def012345678".into(),
            pubkey: "pub".into(),
            ts: 1_761_000_000,
            proto: PROTO_VERSION,
            caps: vec![],
        });
        roundtrip(ControlFrame::Challenge { nonce: "n".into() });
        roundtrip(ControlFrame::Proof { sig: "s".into() });
        roundtrip(ControlFrame::Registered {
            session_id: "sess".into(),
            keepalive_s: 30,
            proto: PROTO_VERSION,
            relay_caps: vec![],
        });
        roundtrip(ControlFrame::Goaway { reason: "superseded".into() });
        roundtrip(ControlFrame::Rejected { reason: "bad proof".into() });
        roundtrip(ControlFrame::RotateKey {
            new_pubkey: "np".into(),
            sig: "s".into(),
        });
        roundtrip(ControlFrame::Deregister);
        roundtrip(ControlFrame::Ping { ts_ms: 42 });
        roundtrip(ControlFrame::Pong { ts_ms: 42 });
    }

    /// The versioned fields must not change the meaning of the original
    /// format: a pre-versioning peer omits them, and must still interoperate.
    #[test]
    fn a_frame_without_proto_decodes_as_version_1() {
        // Exactly what a build predating `proto` put on the wire.
        let legacy = r#"{"type":"register","gw_id":"0f1e2d3c-4b5a-4678-9abc-def012345678","pubkey":"pub","ts":1761000000}"#;
        let frame = decode_frame(legacy).expect("legacy REGISTER must still parse");
        let ControlFrame::Register {
            gw_id, proto, caps, ..
        } = frame
        else {
            panic!("expected REGISTER, got {frame:?}");
        };
        assert_eq!(gw_id, "0f1e2d3c-4b5a-4678-9abc-def012345678");
        assert_eq!(proto, PROTO_VERSION);
        assert_eq!(proto, 1, "the original wire format is version 1");
        assert!(caps.is_empty(), "an omitted caps list means no extensions");

        let legacy = r#"{"type":"registered","session_id":"sess","keepalive_s":30}"#;
        let frame = decode_frame(legacy).expect("legacy REGISTERED must still parse");
        let ControlFrame::Registered { proto, .. } = frame else {
            panic!("expected REGISTERED, got {frame:?}");
        };
        assert_eq!(proto, 1);
    }

    /// Encoding the current version must be recognisable as-is: this is the
    /// contract other implementations (including out-of-tree ones) code
    /// against.
    #[test]
    fn current_frames_carry_their_version() {
        let line = encode_frame(&ControlFrame::Register {
            gw_id: "0f1e2d3c-4b5a-4678-9abc-def012345678".into(),
            pubkey: "pub".into(),
            ts: 1_761_000_000,
            proto: PROTO_VERSION,
            caps: vec!["tenant.v1".into()],
        })
        .unwrap();
        let value: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
        assert_eq!(value["proto"], PROTO_VERSION);
        assert_eq!(value["caps"][0], "tenant.v1");

        // An empty capability list is omitted rather than sent as `[]`.
        let line = encode_frame(&ControlFrame::Register {
            gw_id: "0f1e2d3c-4b5a-4678-9abc-def012345678".into(),
            pubkey: "pub".into(),
            ts: 1_761_000_000,
            proto: PROTO_VERSION,
            caps: vec![],
        })
        .unwrap();
        assert!(!line.contains("caps"), "empty caps should be omitted: {line}");

        let line = encode_frame(&ControlFrame::Registered {
            session_id: "sess".into(),
            keepalive_s: 30,
            proto: PROTO_VERSION,
            relay_caps: vec![],
        })
        .unwrap();
        let value: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
        assert_eq!(value["proto"], PROTO_VERSION);
    }

    #[test]
    fn proto_support_window() {
        assert!(proto_is_supported(PROTO_VERSION));
        assert!(proto_is_supported(MIN_SUPPORTED_PROTO));
        // A peer announcing a future revision must be refused, not guessed at.
        assert!(!proto_is_supported(PROTO_VERSION + 1));
        // And so must one from before the floor.
        assert!(!proto_is_supported(MIN_SUPPORTED_PROTO - 1));
    }

    /// Unknown frame types are the peer's business, not a protocol
    /// violation — see `read_control_frame`.
    #[tokio::test]
    async fn unknown_frame_types_are_skipped_not_fatal() {
        let mut stream = futures_util::io::Cursor::new(
            b"{\"type\":\"billing\",\"charge_id\":\"x\"}\n{\"type\":\"ping\",\"ts_ms\":7}\n"
                .to_vec()
                .into_boxed_slice(),
        );
        let frame = read_control_frame_known(&mut stream).await.unwrap();
        assert_eq!(frame, ControlFrame::Ping { ts_ms: 7 });
    }

    #[tokio::test]
    async fn malformed_frames_are_still_rejected() {
        // No `type` discriminator: garbage, not a future extension.
        let mut stream =
            futures_util::io::Cursor::new(b"{\"gw_id\":\"x\"}\n".to_vec().into_boxed_slice());
        assert!(read_control_frame(&mut stream).await.is_err());

        // Not JSON at all.
        let mut stream = futures_util::io::Cursor::new(b"not json\n".to_vec().into_boxed_slice());
        assert!(read_control_frame(&mut stream).await.is_err());
    }

    #[test]
    fn tag_names_are_snake_case() {
        let line = encode_frame(&ControlFrame::Deregister).unwrap();
        assert_eq!(line.trim(), r#"{"type":"deregister"}"#);
        let line = encode_frame(&ControlFrame::RotateKey {
            new_pubkey: "np".into(),
            sig: "s".into(),
        })
        .unwrap();
        assert!(line.contains(r#""type":"rotate_key""#));
    }

    #[test]
    fn gw_id_validation() {
        assert!(is_valid_gw_id("0f1e2d3c-4b5a-4678-9abc-def012345678"));
        // v1 UUIDs and garbage are rejected.
        assert!(!is_valid_gw_id("0f1e2d3c-4b5a-1678-9abc-def012345678"));
        assert!(!is_valid_gw_id("not-a-uuid"));
        assert!(!is_valid_gw_id(""));
    }

    #[test]
    fn nonce_sign_verify() {
        let seed = generate_device_seed();
        let key = SigningKey::from_bytes(&seed);
        let nonce = generate_nonce();
        let sig = sign_nonce(&key, &nonce);
        assert!(verify_nonce_sig(&key.verifying_key(), &nonce, &sig));
        // Wrong nonce / tampered signature / garbage all fail closed.
        assert!(!verify_nonce_sig(&key.verifying_key(), &generate_nonce(), &sig));
        assert!(!verify_nonce_sig(
            &key.verifying_key(),
            &nonce,
            &format!("{}x", &sig[..sig.len() - 1])
        ));
        assert!(!verify_nonce_sig(&key.verifying_key(), &nonce, "!!"));
    }

    #[test]
    fn key_rotation_sign_verify() {
        let old_seed = generate_device_seed();
        let old_key = SigningKey::from_bytes(&old_seed);
        let new_seed = generate_device_seed();
        let new_key = SigningKey::from_bytes(&new_seed);
        let new_pub = encode_pubkey(&new_key.verifying_key());
        let sig = sign_key_rotation(&old_key, &new_pub);
        assert!(verify_key_rotation(&old_key.verifying_key(), &new_pub, &sig));
        // Signed by the wrong key.
        assert!(!verify_key_rotation(&new_key.verifying_key(), &new_pub, &sig));
        // Different new_pubkey than what was signed.
        let other_pub = encode_pubkey(&old_key.verifying_key());
        assert!(!verify_key_rotation(&old_key.verifying_key(), &other_pub, &sig));
    }

    #[test]
    fn pubkey_codec_roundtrip() {
        let seed = generate_device_seed();
        let key = SigningKey::from_bytes(&seed);
        let encoded = encode_pubkey(&key.verifying_key());
        assert_eq!(decode_pubkey(&encoded).unwrap(), key.verifying_key());
        assert!(decode_pubkey("not-base64!!").is_err());
        assert!(decode_pubkey("").is_err());
    }
}
