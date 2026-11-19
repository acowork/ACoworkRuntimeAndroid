//! Shared `HOST:PORT` parsing for CLI / env / config inputs.
//!
//! Both the Gateway (`--http-addr`, `--mqtt-addr`) and the Node Agent
//! (`--gateway`, `--addr`) accept listen / peer addresses as a single
//! `HOST:PORT` string. Keeping the parser here guarantees identical,
//! tested semantics across crates:
//!
//! - plain `host:port` (`127.0.0.1:19876`, `localhost:19875`)
//! - bare host without a port → the caller-supplied `default_port` is used
//! - IPv6 MUST be bracketed when a port follows (`[::1]:19876`,
//!   `[fd00::1]:19875`); a bare multi-colon string (`::1`, `fe80::1%eth0`)
//!   is treated as an IPv6 *host* and gets the default port — brackets are
//!   the only unambiguous way to attach a port to IPv6.
//!
//! Error type is a plain `String` so this module stays dependency-free;
//! callers map it into their own error variants.

/// A parsed listen / peer address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostPort {
    /// Host part (no brackets — an IPv6 literal is stored bare, e.g.
    /// `::1`, `fe80::1%eth0`).
    pub host: String,
    /// Port part (`1..=65535`; `0` is rejected).
    pub port: u16,
}

impl std::fmt::Display for HostPort {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Re-bracket IPv6 literals so the output round-trips through
        // [`parse_host_port`].
        if self.host.contains(':') {
            write!(f, "[{}]:{}", self.host, self.port)
        } else {
            write!(f, "{}:{}", self.host, self.port)
        }
    }
}

/// Parse `input` as `HOST[:PORT]` (see module docs for the exact grammar).
pub fn parse_host_port(input: &str, default_port: u16) -> Result<HostPort, String> {
    let raw = input.trim();
    if raw.is_empty() {
        return Err("empty address".to_string());
    }
    if default_port == 0 {
        return Err("default_port must be 1-65535".to_string());
    }

    // Bracketed IPv6: `[::1]` or `[::1]:19876`.
    if let Some(rest) = raw.strip_prefix('[') {
        let end = rest
            .find(']')
            .ok_or_else(|| format!("unterminated IPv6 bracket in '{input}'"))?;
        let host = &rest[..end];
        if host.is_empty() {
            return Err(format!("empty IPv6 host in '{input}'"));
        }
        let tail = &rest[end + 1..];
        if tail.is_empty() {
            return Ok(HostPort {
                host: host.to_string(),
                port: default_port,
            });
        }
        let port_str = tail
            .strip_prefix(':')
            .ok_or_else(|| format!("expected ':<port>' after ']' in '{input}'"))?;
        return Ok(HostPort {
            host: host.to_string(),
            port: parse_port(port_str, input)?,
        });
    }

    // Bare `host:port` — but only when the input has exactly one colon.
    // A multi-colon input is an IPv6 literal with no port (`::1`,
    // `fe80::1%eth0`); attaching a port to IPv6 requires brackets.
    if let Some((host, port_str)) = raw.rsplit_once(':')
        && !host.contains(':')
    {
        if host.is_empty() {
            return Err(format!("missing host in '{input}'"));
        }
        return Ok(HostPort {
            host: host.to_string(),
            port: parse_port(port_str, input)?,
        });
    }

    // Host only (IPv4 / hostname / bare IPv6) → default port.
    if raw.contains(':') && !raw.contains('[') {
        // Bare IPv6 literal (multi-colon) — keep as the host.
        return Ok(HostPort {
            host: raw.to_string(),
            port: default_port,
        });
    }

    Ok(HostPort {
        host: raw.to_string(),
        port: default_port,
    })
}

fn parse_port(s: &str, input: &str) -> Result<u16, String> {
    let port: u16 = s
        .parse()
        .map_err(|_| format!("invalid port '{s}' in '{input}'"))?;
    if port == 0 {
        return Err(format!("port must be 1-65535 (got 0) in '{input}'"));
    }
    Ok(port)
}

/// Normalize a configured *bind* host into a valid *connect* target.
///
/// `0.0.0.0` and `::` are "unspecified" addresses: legal for a
/// listener, but NOT legal as a TCP connect target (Windows rejects
/// the connect outright; elsewhere the semantics are ambiguous).
/// Callers that connect to a service they themselves bound (e.g. the
/// Gateway's internal MQTT client → its embedded broker, or a package
/// download URL derived from the HTTP bind host) must pass the bind
/// host through this helper first: IPv4 unspecified → `127.0.0.1`,
/// IPv6 unspecified → `::1`. Every other input (hostname, concrete
/// IP) is returned unchanged.
pub fn connect_host(host: &str) -> &str {
    match host.parse::<std::net::IpAddr>() {
        Ok(ip) if ip.is_unspecified() => {
            if ip.is_ipv4() {
                "127.0.0.1"
            } else {
                "::1"
            }
        }
        _ => host,
    }
}

/// Detect the first non-loopback IPv4 address of this host (best effort).
///
/// Uses the UDP "connect" trick: `connect` on a datagram socket does not
/// send any packets — it only asks the kernel to resolve the route and
/// assign the local source address, which is then read back via
/// `local_addr` (targets the well-known anycast `1.1.1.1`; no traffic is
/// emitted). Returns `None` when no non-loopback IPv4 route exists, so
/// callers fall back to `127.0.0.1`.
pub fn detect_non_loopback_ipv4() -> Option<String> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("1.1.1.1:80").ok()?;
    let addr = socket.local_addr().ok()?;
    match addr.ip() {
        std::net::IpAddr::V4(v4) if !v4.is_loopback() && !v4.is_unspecified() => {
            Some(v4.to_string())
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_with_port() {
        let hp = parse_host_port("192.168.1.20:19876", 19876).unwrap();
        assert_eq!(hp.host, "192.168.1.20");
        assert_eq!(hp.port, 19876);
    }

    #[test]
    fn hostname_with_port() {
        let hp = parse_host_port("localhost:29875", 19875).unwrap();
        assert_eq!(hp.host, "localhost");
        assert_eq!(hp.port, 29875);
    }

    #[test]
    fn bare_host_uses_default_port() {
        let hp = parse_host_port("0.0.0.0", 19876).unwrap();
        assert_eq!(hp.host, "0.0.0.0");
        assert_eq!(hp.port, 19876);
    }

    #[test]
    fn bare_hostname_uses_default_port() {
        let hp = parse_host_port("gw-host", 19876).unwrap();
        assert_eq!(hp.host, "gw-host");
        assert_eq!(hp.port, 19876);
    }

    #[test]
    fn bracketed_ipv6_with_port() {
        let hp = parse_host_port("[::1]:19876", 19876).unwrap();
        assert_eq!(hp.host, "::1");
        assert_eq!(hp.port, 19876);
        let hp = parse_host_port("[fd00::1]:20000", 19876).unwrap();
        assert_eq!(hp.host, "fd00::1");
        assert_eq!(hp.port, 20000);
    }

    #[test]
    fn bracketed_ipv6_without_port_uses_default() {
        let hp = parse_host_port("[::1]", 19875).unwrap();
        assert_eq!(hp.host, "::1");
        assert_eq!(hp.port, 19875);
    }

    #[test]
    fn bare_ipv6_uses_default_port() {
        let hp = parse_host_port("::1", 19876).unwrap();
        assert_eq!(hp.host, "::1");
        assert_eq!(hp.port, 19876);
        let hp = parse_host_port("fe80::1%eth0", 19876).unwrap();
        assert_eq!(hp.host, "fe80::1%eth0");
        assert_eq!(hp.port, 19876);
    }

    #[test]
    fn connect_host_normalizes_unspecified_addresses() {
        // IPv4 wildcard bind → loopback connect target.
        assert_eq!(connect_host("0.0.0.0"), "127.0.0.1");
        // IPv6 wildcard (canonical and expanded spellings).
        assert_eq!(connect_host("::"), "::1");
        assert_eq!(connect_host("::0"), "::1");
        assert_eq!(connect_host("0:0:0:0:0:0:0:0"), "::1");
        // Concrete addresses and hostnames pass through unchanged.
        assert_eq!(connect_host("127.0.0.1"), "127.0.0.1");
        assert_eq!(connect_host("192.168.1.20"), "192.168.1.20");
        assert_eq!(connect_host("::1"), "::1");
        assert_eq!(connect_host("localhost"), "localhost");
        assert_eq!(connect_host("gw-host"), "gw-host");
    }

    #[test]
    fn display_round_trips_ipv6() {
        let hp = parse_host_port("[fd00::1]:20000", 19876).unwrap();
        assert_eq!(hp.to_string(), "[fd00::1]:20000");
    }

    #[test]
    fn rejects_invalid_inputs() {
        assert!(parse_host_port("", 19876).is_err());
        assert!(parse_host_port(":19876", 19876).is_err());
        assert!(parse_host_port("host:notaport", 19876).is_err());
        assert!(parse_host_port("host:0", 19876).is_err());
        assert!(parse_host_port("host:99999", 19876).is_err());
        assert!(parse_host_port("[::1", 19876).is_err());
        assert!(parse_host_port("[]:19876", 19876).is_err());
        assert!(parse_host_port("[::1]junk", 19876).is_err());
    }

    #[test]
    fn whitespace_is_trimmed() {
        let hp = parse_host_port("  127.0.0.1:19876  ", 19876).unwrap();
        assert_eq!(hp.host, "127.0.0.1");
        assert_eq!(hp.port, 19876);
    }
}
