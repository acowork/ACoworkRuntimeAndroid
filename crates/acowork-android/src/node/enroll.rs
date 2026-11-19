//! Gateway enrollment shape (ADR-AND-003 §2.4).
//!
//! Field semantics mirror upstream `NodeEnroll` / the retained `NodeInfo` snapshot. This
//! module does **not** speak MQTT yet — the wire codec and broker client are a follow-on
//! slice. What it does provide is the payload a Node must be able to build from local facts,
//! plus a cheap HTTP reachability probe so `serve --gateway-http` fails closed when the
//! control plane is simply not there.

use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// The enrollment request a Node will publish once the MQTT adapter lands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrollRequest {
    /// Stable node id (UUID). Routing key — never the display name.
    pub node_id: String,
    /// `std::env::consts::OS` spelling, or `"android"` when running on-device.
    pub os: String,
    /// `std::env::consts::ARCH`.
    pub arch: String,
    /// This binary's version.
    pub node_version: String,
    /// Control-plane protocol version spoken by this node.
    pub protocol_version: u32,
    /// Capability tags ([`super::tags::capability_tags`]).
    pub capabilities: Vec<String>,
    /// One-time enrollment token (plaintext only in this message).
    pub enrollment_token: String,
}

impl EnrollRequest {
    /// Build from operator inputs + already-computed tags.
    pub fn new(
        node_id: impl Into<String>,
        capabilities: Vec<String>,
        enrollment_token: impl Into<String>,
    ) -> EnrollRequest {
        EnrollRequest {
            node_id: node_id.into(),
            os: if cfg!(target_os = "android") {
                "android".to_string()
            } else {
                std::env::consts::OS.to_string()
            },
            arch: std::env::consts::ARCH.to_string(),
            node_version: env!("CARGO_PKG_VERSION").to_string(),
            // Match upstream `NODE_PROTOCOL_VERSION` (currently 2).
            protocol_version: super::topics::NODE_PROTOCOL_VERSION,
            capabilities,
            enrollment_token: enrollment_token.into(),
        }
    }
}

/// Result of poking the Gateway's HTTP port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GatewayReachability {
    /// TCP connect to the parsed host:port succeeded.
    Reachable {
        /// Address that answered.
        addr: String,
    },
    /// Could not connect (refused, timed out, DNS failure, …).
    Unreachable {
        /// Why.
        reason: String,
    },
}

/// Why enrollment prep failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnrollError {
    /// `--gateway-http` was not a usable URL.
    BadGatewayUrl(String),
}

impl std::fmt::Display for EnrollError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EnrollError::BadGatewayUrl(e) => write!(f, "bad --gateway-http URL: {e}"),
        }
    }
}

impl std::error::Error for EnrollError {}

/// TCP reachability of the Gateway HTTP endpoint (default port 19876 when absent).
///
/// This is deliberately not an HTTP GET: we must not depend on a particular path existing
/// before MQTT enroll is wired, and a refused TCP connect is already enough to tell the
/// operator the control plane is not there.
pub fn check_gateway_http(gateway_http: &str) -> Result<GatewayReachability, EnrollError> {
    let addr = parse_gateway_socket(gateway_http)?;
    match TcpStream::connect_timeout(&addr, Duration::from_secs(2)) {
        Ok(_) => Ok(GatewayReachability::Reachable {
            addr: addr.to_string(),
        }),
        Err(e) => Ok(GatewayReachability::Unreachable {
            reason: e.to_string(),
        }),
    }
}

fn parse_gateway_socket(raw: &str) -> Result<SocketAddr, EnrollError> {
    let trimmed = raw.trim();
    let without_scheme = trimmed
        .strip_prefix("http://")
        .or_else(|| trimmed.strip_prefix("https://"))
        .unwrap_or(trimmed);
    let hostport = without_scheme
        .split('/')
        .next()
        .unwrap_or(without_scheme)
        .trim();
    if hostport.is_empty() {
        return Err(EnrollError::BadGatewayUrl(
            "empty host after stripping scheme".into(),
        ));
    }
    let with_port = if hostport.contains(':') {
        hostport.to_string()
    } else {
        format!("{hostport}:19876")
    };
    with_port
        .to_socket_addrs()
        .map_err(|e| EnrollError::BadGatewayUrl(e.to_string()))?
        .next()
        .ok_or_else(|| EnrollError::BadGatewayUrl(format!("no addresses for `{with_port}`")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enroll_request_serialises_the_protocol_fields() {
        let req = EnrollRequest::new(
            "node-1",
            vec![
                "control_plane".into(),
                "android:host-profile:system-shell".into(),
            ],
            "one-time-token",
        );
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"node_id\":\"node-1\""));
        assert!(json.contains("android:host-profile:system-shell"));
        assert!(json.contains("one-time-token"));
        assert!(!json.contains("/data/"));
    }

    #[test]
    fn gateway_url_defaults_http_port() {
        let addr = parse_gateway_socket("http://127.0.0.1").unwrap();
        assert_eq!(addr.port(), 19876);
    }

    #[test]
    fn gateway_url_keeps_explicit_port() {
        let addr = parse_gateway_socket("http://127.0.0.1:19876/").unwrap();
        assert_eq!(addr.port(), 19876);
    }
}
