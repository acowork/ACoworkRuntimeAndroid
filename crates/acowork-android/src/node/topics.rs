//! MQTT topic helpers for the Node control plane (ADR-055 §6.2 shape).
//!
//! Spelling matches upstream `acowork_core::node` so a Gateway dump is comparable.
//! This module is local — it does not import upstream.

/// Node control-plane protocol version spoken by this build.
pub const NODE_PROTOCOL_VERSION: u32 = 2;

/// Default reverse-proxy port (`/agents/{id}/*` → Runtime loopback).
pub const NODE_PROXY_PORT: u16 = 19900;

/// Base port for per-agent loopback HTTP ports.
pub const NODE_HTTP_PORT_BASE: u16 = 19901;

/// Default MQTT broker port on the Gateway.
pub const GATEWAY_MQTT_PORT: u16 = 19875;

/// MQTT client_id: `node:{node_id}`.
pub fn node_client_id(node_id: &str) -> String {
    format!("node:{node_id}")
}

/// `acowork/nodes/{node_id}/status`
pub fn node_status_topic(node_id: &str) -> String {
    format!("acowork/nodes/{node_id}/status")
}

/// `acowork/nodes/{node_id}/ready`
pub fn node_ready_topic(node_id: &str) -> String {
    format!("acowork/nodes/{node_id}/ready")
}

/// `acowork/nodes/{node_id}/info`
pub fn node_info_topic(node_id: &str) -> String {
    format!("acowork/nodes/{node_id}/info")
}

/// `acowork/nodes/{node_id}/events`
pub fn node_events_topic(node_id: &str) -> String {
    format!("acowork/nodes/{node_id}/events")
}

/// `acowork/nodes/{node_id}/agents/{instance_id}/events`
pub fn node_agent_events_topic(node_id: &str, instance_id: &str) -> String {
    format!("acowork/nodes/{node_id}/agents/{instance_id}/events")
}

/// `acowork/nodes/{node_id}/agents/{instance_id}/installed`
pub fn node_agent_installed_topic(node_id: &str, instance_id: &str) -> String {
    format!("acowork/nodes/{node_id}/agents/{instance_id}/installed")
}

/// `acowork/nodes/{node_id}/enroll`
pub fn node_enroll_topic(node_id: &str) -> String {
    format!("acowork/nodes/{node_id}/enroll")
}

/// `acowork/nodes/{node_id}/enroll_result`
pub fn node_enroll_result_topic(node_id: &str) -> String {
    format!("acowork/nodes/{node_id}/enroll_result")
}

/// Node-scoped control filter: `acowork/nodes/{node_id}/control/+`
pub fn node_control_filter(node_id: &str) -> String {
    format!("acowork/nodes/{node_id}/control/+")
}

/// Agent-scoped control filter: `acowork/nodes/{node_id}/agents/+/control/+`
pub fn node_agent_control_filter(node_id: &str) -> String {
    format!("acowork/nodes/{node_id}/agents/+/control/+")
}

/// Parse a control-plane topic into `(node_id, optional instance_id)`.
///
/// Returns `None` when the topic is not a control command for `own_node_id`.
/// Routing only — UUID shape is the handler's job (ADR-073).
pub fn parse_control_topic(topic: &str, own_node_id: &str) -> Option<(String, Option<String>)> {
    let agent_prefix = format!("acowork/nodes/{own_node_id}/agents/");
    let node_prefix = format!("acowork/nodes/{own_node_id}/control/");
    if let Some(rest) = topic.strip_prefix(&agent_prefix) {
        // rest = {instance_id}/control/{cmd}
        let mut parts = rest.splitn(3, '/');
        let instance_id = parts.next().unwrap_or("");
        let control = parts.next().unwrap_or("");
        if !instance_id.is_empty() && control == "control" {
            return Some((own_node_id.to_string(), Some(instance_id.to_string())));
        }
        return None;
    }
    if topic.strip_prefix(&node_prefix).is_some() {
        return Some((own_node_id.to_string(), None));
    }
    None
}

/// Validate a display slug (ADR-075 D2 subset).
pub fn node_name_is_valid(name: &str) -> bool {
    if name.len() < 2 || name.len() > 32 || name == "local" {
        return false;
    }
    let bytes = name.as_bytes();
    let is_alnum = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    if !is_alnum(bytes[0]) || !is_alnum(bytes[bytes.len() - 1]) {
        return false;
    }
    let mut prev_hyphen = false;
    for &b in &bytes[1..bytes.len() - 1] {
        if b == b'-' {
            if prev_hyphen {
                return false;
            }
            prev_hyphen = true;
        } else if is_alnum(b) {
            prev_hyphen = false;
        } else {
            return false;
        }
    }
    true
}

/// Slug a hostname into a valid `node_name`, or `"android-node"`.
pub fn node_name_from_hostname(hostname: &str) -> String {
    let mut out = String::new();
    for c in hostname.chars() {
        let lower = c.to_ascii_lowercase();
        if lower.is_ascii_alphanumeric() {
            out.push(lower);
        } else if (lower == '-' || lower == '_' || lower == '.')
            && !out.ends_with('-')
            && !out.is_empty()
        {
            out.push('-');
        }
    }
    while out.ends_with('-') {
        out.pop();
    }
    if out.len() < 2 {
        return "android-node".into();
    }
    if out.len() > 32 {
        out.truncate(32);
        while out.ends_with('-') {
            out.pop();
        }
    }
    if node_name_is_valid(&out) {
        out
    } else {
        "android-node".into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn topics_spell_the_upstream_shape() {
        assert_eq!(node_enroll_topic("n1"), "acowork/nodes/n1/enroll");
        assert_eq!(
            node_enroll_result_topic("n1"),
            "acowork/nodes/n1/enroll_result"
        );
        assert_eq!(node_client_id("n1"), "node:n1");
    }

    #[test]
    fn node_name_rejects_local_and_short() {
        assert!(!node_name_is_valid("local"));
        assert!(!node_name_is_valid("a"));
        assert!(node_name_is_valid("phone-1"));
    }

    #[test]
    fn parse_control_topic_routes_agent_and_node() {
        let nid = "33980531-7c19-4e49-84f2-e6cbd7a2c170";
        let aid = "79a3e29e-ed52-4ad0-88b0-4d64506fe25f";
        assert_eq!(
            parse_control_topic(&format!("acowork/nodes/{nid}/control/ping"), nid),
            Some((nid.to_string(), None))
        );
        assert_eq!(
            parse_control_topic(
                &format!("acowork/nodes/{nid}/agents/{aid}/control/start"),
                nid
            ),
            Some((nid.to_string(), Some(aid.to_string())))
        );
        assert_eq!(
            node_agent_events_topic(nid, aid),
            format!("acowork/nodes/{nid}/agents/{aid}/events")
        );
        assert_eq!(
            node_events_topic(nid),
            format!("acowork/nodes/{nid}/events")
        );
    }
}
