//! Device-bridge protocol between a Runtime engine and the Android host app.
//!
//! The engine process cannot call Camera2, AudioRecord, BluetoothGatt, or
//! UsbManager. It sends one JSON line per call over a filesystem Unix socket
//! that only the app can create, and the app process performs the SDK call.
//! See `docs/design/zh/android-device-tools.md`.

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// `ACOWORK_DEVICE_BRIDGE` value is `{socket path}|{token}`.
pub const ENV_BRIDGE: &str = "ACOWORK_DEVICE_BRIDGE";

/// Socket file name under the node home (`filesDir/acowork`).
pub const SOCKET_FILE: &str = "device-bridge.sock";

/// Token file name under the node home. Mode is the directory's, which is app-private.
pub const TOKEN_FILE: &str = "device-bridge.token";

/// Protocol version carried on every request and response.
pub const PROTOCOL_VERSION: u32 = 1;

/// Tool names the Android host registers when the bridge is present.
pub const TOOL_NAMES: &[&str] = &[
    "android_device_status",
    "android_photo",
    "android_video_record",
    "android_audio_record",
    "android_audio_play",
    "android_ble_scan",
    "android_ble_gatt",
    "android_usb_hid",
    "android_use",
];

/// One tool call from the engine.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DeviceRequest {
    /// [`PROTOCOL_VERSION`].
    pub v: u32,
    /// Correlation id. The response echoes it.
    pub id: String,
    /// Shared secret read from [`TOKEN_FILE`].
    pub token: String,
    /// Tool name. One of [`TOOL_NAMES`].
    pub tool: String,
    /// Agent id for the audit line. Empty when the caller has none.
    #[serde(default)]
    pub agent_id: String,
    /// Agent work directory. Captures are written under `{work_dir}/device-captures`.
    #[serde(default)]
    pub work_dir: String,
    /// Tool arguments. Shape is the tool's JSON schema.
    pub args: Value,
}

/// One tool result from the app process.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DeviceResponse {
    /// [`PROTOCOL_VERSION`].
    pub v: u32,
    /// Echo of [`DeviceRequest::id`].
    pub id: String,
    /// `false` when `error` is set.
    pub ok: bool,
    /// Stable code: `permission_required`, `unsupported_api`, `invalid_argument`,
    /// `busy`, `bridge_unavailable`. Absent on success.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    /// Human-readable failure, safe to show to the model.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Short summary. Structured fields live in [`Self::data`].
    #[serde(default)]
    pub content: String,
    /// Structured result. Large payloads are replaced by a file descriptor
    /// (`path`, `length`, `sha256`, `prefix`) when the app spills them.
    #[serde(default)]
    pub data: Value,
}

/// Failure to exchange a single request. The tool turns this into `bridge_unavailable`.
#[derive(Debug)]
pub enum DeviceError {
    /// Socket or token is missing, or this platform has no Unix sockets.
    Unavailable(String),
    /// The peer closed or the read exceeded the deadline.
    Io(String),
    /// The peer did not return one JSON object.
    Protocol(String),
}

impl std::fmt::Display for DeviceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DeviceError::Unavailable(m) | DeviceError::Io(m) | DeviceError::Protocol(m) => {
                write!(f, "{m}")
            }
        }
    }
}

impl std::error::Error for DeviceError {}

/// `true` when this process can reach the host device bridge.
pub fn bridge_active() -> bool {
    bridge_endpoint().is_some()
}

/// Socket path and token. Prefers [`ENV_BRIDGE`], then `ACOWORK_NODE_HOME`,
/// then `$HOME`, each plus the token file.
///
/// The engine child may be spawned without [`ENV_BRIDGE`]. Node still
/// points `ACOWORK_NODE_HOME` at the app-private data dir, where the host
/// writes [`TOKEN_FILE`].
pub fn bridge_endpoint() -> Option<(PathBuf, String)> {
    if let Ok(raw) = std::env::var(ENV_BRIDGE) {
        if let Some(ep) = parse_endpoint(&raw) {
            return Some(ep);
        }
    }
    for key in ["ACOWORK_NODE_HOME", "HOME"] {
        if let Some(home) = std::env::var_os(key) {
            if let Some(value) = endpoint_from_home(std::path::Path::new(&home)) {
                return parse_endpoint(&value);
            }
        }
    }
    None
}

/// Parse `{path}|{token}`. The token is the substring after the first `|`.
pub fn parse_endpoint(raw: &str) -> Option<(PathBuf, String)> {
    let (path, token) = raw.split_once('|')?;
    let token = token.trim();
    if path.is_empty() || token.is_empty() {
        return None;
    }
    Some((PathBuf::from(path), token.to_string()))
}

/// Value to put in the child environment when `home` already has a token file.
///
/// The socket file is created by the app before the engine is spawned. The
/// token file is the signal that the bridge was started; a missing socket is
/// still passed through so the tool can return `bridge_unavailable` instead of
/// silently omitting the tools.
pub fn endpoint_from_home(home: &Path) -> Option<String> {
    let token = std::fs::read_to_string(home.join(TOKEN_FILE)).ok()?;
    let token = token.trim();
    if token.is_empty() {
        return None;
    }
    let sock = home.join(SOCKET_FILE);
    Some(format!("{}|{token}", sock.display()))
}

/// Send `req` and wait up to `timeout` for one JSON line back.
pub fn call(sock: &Path, req: &DeviceRequest, timeout: Duration) -> Result<DeviceResponse, DeviceError> {
    #[cfg(unix)]
    {
        unix_call(sock, req, timeout)
    }
    #[cfg(not(unix))]
    {
        let _ = (sock, req, timeout);
        Err(DeviceError::Unavailable(
            "device bridge sockets are unix-only".into(),
        ))
    }
}

#[cfg(unix)]
fn connect_with_retry(sock: &Path) -> Result<std::os::unix::net::UnixStream, DeviceError> {
    use std::os::unix::net::UnixStream;
    use std::thread;
    use std::time::Duration as StdDuration;

    let mut last = None;
    for attempt in 0..6u32 {
        match UnixStream::connect(sock) {
            Ok(stream) => return Ok(stream),
            Err(e) => {
                let retryable = matches!(
                    e.kind(),
                    std::io::ErrorKind::NotFound
                        | std::io::ErrorKind::ConnectionRefused
                        | std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::Interrupted
                );
                last = Some(e);
                if !retryable || attempt == 5 {
                    break;
                }
                thread::sleep(StdDuration::from_millis(20u64 << attempt.min(4)));
            }
        }
    }
    let e = last.unwrap();
    Err(DeviceError::Unavailable(format!(
        "connect {}: {e}",
        sock.display()
    )))
}

#[cfg(unix)]
fn unix_call(
    sock: &Path,
    req: &DeviceRequest,
    timeout: Duration,
) -> Result<DeviceResponse, DeviceError> {
    use std::io::{BufReader, Write};

    // The stream type is named in full in connect_with_retry's signature; it
    // needs no import here because only its methods are used.
    let mut stream = connect_with_retry(sock)?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|e| DeviceError::Io(e.to_string()))?;
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .map_err(|e| DeviceError::Io(e.to_string()))?;

    let mut line = serde_json::to_vec(req).map_err(|e| DeviceError::Protocol(e.to_string()))?;
    line.push(b'\n');
    stream
        .write_all(&line)
        .map_err(|e| DeviceError::Io(e.to_string()))?;
    stream.flush().map_err(|e| DeviceError::Io(e.to_string()))?;

    let mut reader = BufReader::new(stream);
    let mut buf = Vec::new();
    // One response line. Characteristics and raw descriptors can be large;
    // the app spills past its own budget, so this cap only stops a runaway peer.
    const MAX_LINE: usize = 8 * 1024 * 1024;
    loop {
        let mut chunk = [0u8; 8192];
        let n = std::io::Read::read(&mut reader, &mut chunk).map_err(|e| {
            if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut
            {
                DeviceError::Io(format!("device bridge timed out after {}ms", timeout.as_millis()))
            } else {
                DeviceError::Io(e.to_string())
            }
        })?;
        if n == 0 {
            return Err(DeviceError::Protocol("device bridge closed before a response".into()));
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > MAX_LINE {
            return Err(DeviceError::Protocol("device bridge response exceeds 8MB".into()));
        }
        if let Some(pos) = buf.iter().position(|b| *b == b'\n') {
            let response: DeviceResponse = serde_json::from_slice(&buf[..pos])
                .map_err(|e| DeviceError::Protocol(e.to_string()))?;
            return Ok(response);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn endpoint_split_keeps_the_path_free_of_the_token() {
        let (path, token) = parse_endpoint("/data/user/0/app/device-bridge.sock|abc").unwrap();
        assert_eq!(path, PathBuf::from("/data/user/0/app/device-bridge.sock"));
        assert_eq!(token, "abc");
    }

    #[test]
    fn endpoint_rejects_a_missing_half() {
        assert!(parse_endpoint("only-path").is_none());
        assert!(parse_endpoint("|token").is_none());
        assert!(parse_endpoint("path|").is_none());
    }

    #[test]
    fn request_round_trips_as_one_object() {
        let req = DeviceRequest {
            v: PROTOCOL_VERSION,
            id: "1".into(),
            token: "t".into(),
            tool: "android_photo".into(),
            agent_id: "agent".into(),
            work_dir: "/work".into(),
            args: json!({"lens_facing": "back", "jpeg_quality": 90}),
        };
        let bytes = serde_json::to_vec(&req).unwrap();
        let back: DeviceRequest = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(back, req);
    }

    #[test]
    fn tool_name_list_matches_the_design() {
        assert_eq!(TOOL_NAMES.len(), 9);
        assert!(TOOL_NAMES.contains(&"android_usb_hid"));
        assert!(TOOL_NAMES.contains(&"android_device_status"));
        assert!(TOOL_NAMES.contains(&"android_use"));
    }

    #[cfg(unix)]
    #[test]
    fn call_round_trips_against_a_fake_bridge() {
        use std::io::{BufRead, BufReader, Write};
        use std::os::unix::net::UnixListener;

        let dir = std::env::temp_dir().join(format!("acowork-bridge-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join(SOCKET_FILE);
        let listener = UnixListener::bind(&sock).unwrap();
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            let req: DeviceRequest = serde_json::from_str(line.trim_end()).unwrap();
            assert_eq!(req.token, "secret");
            assert_eq!(req.tool, "android_device_status");
            let resp = DeviceResponse {
                v: PROTOCOL_VERSION,
                id: req.id,
                ok: true,
                error_code: None,
                error: None,
                content: "device status".into(),
                data: json!({"sdk_int": 35}),
            };
            let mut out = stream;
            let mut bytes = serde_json::to_vec(&resp).unwrap();
            bytes.push(b'\n');
            out.write_all(&bytes).unwrap();
        });

        let req = DeviceRequest {
            v: PROTOCOL_VERSION,
            id: "req-1".into(),
            token: "secret".into(),
            tool: "android_device_status".into(),
            agent_id: "agent".into(),
            work_dir: "/work".into(),
            args: json!({}),
        };
        let resp = call(&sock, &req, Duration::from_secs(2)).unwrap();
        assert!(resp.ok);
        assert_eq!(resp.id, "req-1");
        assert_eq!(resp.data["sdk_int"], 35);
        server.join().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
