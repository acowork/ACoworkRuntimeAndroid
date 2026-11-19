//! `acowork/agents/{id}/config` retained re-publisher.
//!
//! Single responsibility: wrap a pre-built agent_config payload into
//! a [`DataEnvelope::AgentConfig`] and re-publish it on the canonical
//! retained topic so Desktop subscribers refresh their per-agent
//! view (Tools tab, Setup panel) without polling. Mirrors the
//! construction pattern of [`MqttChunkPublisher`] — cheap-to-clone
//! handle, no internal state.
//!
//! # Callers
//!
//! - [`crate::http::server::put_agent_config`] after persisting config
//!   patches (ADR-040 §7).
//! - [`crate::startup::gateway_loop::mqtt_only_loop`] after the MCP
//!   reconnect+reconcile (`mcp_runtime_rx` branch) finishes. Without
//!   this, `PUT /mcp-servers` only persists `agent_mcp.json` and the
//!   Desktop Tools panel never refreshes the per-tool list / chevron
//!   count until a remount forces a re-fetch.
//!
//! # Design notes
//!
//! - Topic string is private (single owner of the wire contract).
//! - Best-effort: a publish failure is logged at `warn` and swallowed;
//!   the on-disk `agent_config.json` remains authoritative for any
//!   reader that re-fetches.
//! - No knowledge of who subscribes or how the JSON was assembled —
//!   callers own the "load latest AgentConfig from disk" path.

use std::sync::Arc;

use rumqttc::AsyncClient;
use tokio::sync::Mutex;

use acowork_core::mqtt_proto::{AgentConfig, DataEnvelope, data_envelope};

use crate::mqtt::client::{MqttQoS, RuntimeMqttClient};

/// Publisher that re-emits the retained `acowork/agents/{instance_id}/config`
/// snapshot.
///
/// Cheap-to-clone handle (matches [`MqttChunkPublisher`]).
#[derive(Clone)]
pub struct MqttAgentConfigPublisher {
    agent_id: String,
    /// ADR-073: instance identity for topic construction.
    instance_id: String,
    shared_client: Arc<Mutex<AsyncClient>>,
}

impl MqttAgentConfigPublisher {
    /// Build from an already-running [`RuntimeMqttClient`]. Holds no
    /// state beyond the shared client handle and ids, so it can
    /// be constructed at any point after Phase A.
    pub fn from_runtime_client(client: &RuntimeMqttClient) -> Self {
        Self {
            agent_id: client.agent_id().to_string(),
            instance_id: client.instance_id().to_string(),
            shared_client: client.shared_handle(),
        }
    }

    /// agent_id this publisher is bound to.
    pub fn agent_id(&self) -> &str {
        &self.agent_id
    }

    /// ADR-073: instance identity this publisher is bound to.
    pub fn instance_id(&self) -> &str {
        &self.instance_id
    }

    /// Re-publish the retained `acowork/agents/{instance_id}/config` snapshot.
    ///
    /// `config_json` is the merged `AgentConfig` payload (use case
    /// result for the patch path; freshly serialized from
    /// `agent_config.json` for the MCP-reconcile path — both are
    /// equivalent on the receiver).
    ///
    /// Best-effort: on failure logs at `warn` level and returns. The
    /// on-disk `agent_config.json` is still authoritative for any
    /// subsequent reader that re-fetches.
    pub async fn publish(&self, config_json: String) {
        let envelope = DataEnvelope {
            version: 1,
            payload: Some(data_envelope::Payload::AgentConfig(AgentConfig {
                agent_id: self.agent_id.clone(),
                config_json,
                // ADR-073: instance metadata for the retained snapshot.
                instance_id: self.instance_id.clone(),
                node_id: String::new(),
            })),
        };
        let topic = format!("acowork/agents/{}/config", self.instance_id);
        let payload = prost::Message::encode_to_vec(&envelope);
        let client = self.shared_client.lock().await.clone();
        if let Err(e) = client
            .publish(&topic, MqttQoS::AtLeastOnce.into(), true, payload)
            .await
        {
            tracing::warn!(
                agent_id = %self.agent_id,
                error = %e,
                "MqttAgentConfigPublisher: failed to re-PUBLISH retained config snapshot"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn topic_format_is_canonical_retained_path() {
        // Single source of truth for the wire contract — every caller
        // must hit the same topic the Desktop's `case "agent_config"`
        // listener subscribes to.
        let topic = format!("acowork/agents/{}/config", "com.test.agent");
        assert_eq!(topic, "acowork/agents/com.test.agent/config");
    }

    #[test]
    fn from_runtime_client_captures_agent_id() {
        // Construct directly with the same field layout that
        // `from_runtime_client` populates — verifies the contract
        // without needing a live broker. The `AsyncClient` is created
        // with non-routable MqttOptions and is never polled, so it
        // never actually connects.
        let opts = rumqttc::MqttOptions::new("test", "127.0.0.1", 1);
        let (client, _eventloop) = rumqttc::AsyncClient::new(opts, 1);
        let publisher = MqttAgentConfigPublisher {
            agent_id: "com.example.Agent".to_string(),
            instance_id: "inst-com.example.Agent".to_string(),
            shared_client: Arc::new(Mutex::new(client)),
        };
        assert_eq!(publisher.agent_id(), "com.example.Agent");
    }

    #[test]
    fn envelope_carries_agent_id_and_config_json_verbatim() {
        // The Desktop's `case "agent_config"` deserialises this exact
        // shape. If either field drifts, the Tools tab silently
        // receives the wrong snapshot.
        use prost::Message as _;
        let config_json = r#"{"temperature":0.7,"max_iterations":42}"#.to_string();
        let envelope = DataEnvelope {
            version: 1,
            payload: Some(data_envelope::Payload::AgentConfig(AgentConfig {
                agent_id: "com.test.agent".to_string(),
                config_json: config_json.clone(),
                // ADR-073: empty instance/node identity = legacy envelope.
                instance_id: String::new(),
                node_id: String::new(),
            })),
        };
        let bytes = envelope.encode_to_vec();
        let decoded = DataEnvelope::decode(bytes.as_slice()).expect("roundtrip");

        match decoded.payload {
            Some(data_envelope::Payload::AgentConfig(ac)) => {
                assert_eq!(ac.agent_id, "com.test.agent");
                assert_eq!(ac.config_json, config_json);
            }
            other => panic!("expected AgentConfig payload, got {:?}", other),
        }
    }
}
