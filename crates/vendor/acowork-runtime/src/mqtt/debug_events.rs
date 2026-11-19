//! Debug protocol MQTT events publisher (ADR-048).
//!
//! `DebugEventMqttPublisher` consumes the per-session `DebugEventSender`
//! mpsc and PUBLISHes each event to the local MQTT broker on
//! `acowork/agents/{agent_id}/debug/events/{event_type}`.
//!
//! ## Wire shape
//!
//! Every event is wrapped in a [`DataEnvelope`] with one of the
//! `Debug*Event` payload variants. Topics carry the event name as a
//! suffix so Desktop can subscribe to the wildcard
//! `acowork/agents/{id}/debug/events/#` and dispatch by suffix.
//!
//! ## Lifecycle
//!
//! Spawned by `startup::subsystems::phase_c_spawn_subsystems` once
//! DevMode is enabled. Runs until the agent shuts down (the mpsc
//! sender in `DebugEventSender` keeps it alive — when the SessionManager
//! is dropped, the channel closes and `run` returns).
//!
//! ## Why a separate task (and not part of `DebugService`)
//!
//! The events path is fire-and-forget push, not RPC. Pushing it into the
//! service would force the service to know about MQTT topics, protobuf
//! encoding, and serialization — violating the ADR-040 "external adapter
//! → use case → internal module" layering. The publisher is a thin
//! transport adapter that calls nothing but the protobuf encoder and
//! `MqttClient::publish_envelope`.

use std::sync::Arc;

use acowork_core::mqtt_proto::{
    DataEnvelope, DebugContextBuiltEvent, DebugStateChangeEvent, DebugStepEvent, data_envelope,
};
use tokio::sync::broadcast;

use crate::debug::events::{DebugEvent, TaggedEvent};
use crate::mqtt::client::{MqttQoS, RuntimeMqttClient};

/// Topic prefix for debug events.
///
/// Full topic: `acowork/agents/{agent_id}/debug/events/{event_type}`.
/// The Desktop App subscribes to `acowork/agents/{id}/debug/events/#`
/// and dispatches by the trailing `event_type` segment.
const DEBUG_EVENTS_TOPIC_PREFIX: &str = "acowork/agents";

const DEBUG_EVENTS_TOPIC_MIDDLE: &str = "debug/events";

/// Publisher: drains the per-session DebugEvent broadcast bus and
/// PUBLISHes each event to the local MQTT broker.
///
/// `event_rx` is the receiver end of the `broadcast::Sender` that all
/// per-session `DebugEventSender`s share — it's obtained via
/// `DebugEventBus::subscribe()`.
///
/// `agent_id` is embedded into every topic so subscribers know which
/// agent the event originated from.
pub struct DebugEventMqttPublisher {
    agent_id: String,
    mqtt_client: Arc<RuntimeMqttClient>,
    event_rx: broadcast::Receiver<TaggedEvent>,
}

impl DebugEventMqttPublisher {
    /// Create a new publisher. Pass the broadcast receiver obtained
    /// from `DebugEventBus::subscribe()`.
    pub fn new(
        agent_id: String,
        mqtt_client: Arc<RuntimeMqttClient>,
        event_rx: broadcast::Receiver<TaggedEvent>,
    ) -> Self {
        Self {
            agent_id,
            mqtt_client,
            event_rx,
        }
    }

    /// Run the publisher until the event bus closes.
    ///
    /// Each iteration: receive a tagged event, encode the protobuf
    /// payload, PUBLISH on `acowork/agents/{id}/debug/events/{event_type}`.
    /// Errors are logged but never propagated — debug events are
    /// best-effort.
    pub async fn run(mut self) {
        tracing::info!(
            agent_id = %self.agent_id,
            "DebugEventMqttPublisher started — forwarding debug events to MQTT broker"
        );
        loop {
            match self.event_rx.recv().await {
                Ok(tagged) => {
                    let TaggedEvent { session_id, event } = tagged;
                    if let Err(e) = self.publish_event(&session_id, event).await {
                        tracing::warn!(
                            session_id = %session_id,
                            error = %e,
                            "DebugEventMqttPublisher: failed to publish event"
                        );
                    }
                }
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    // Subscriber fell behind the broadcast channel. Log
                    // and continue — desktop will re-sync via
                    // `GET /api/debug/state` after reconnect.
                    tracing::warn!(
                        lagged = n,
                        agent_id = %self.agent_id,
                        "DebugEventMqttPublisher: lagged, dropped events"
                    );
                }
                Err(broadcast::error::RecvError::Closed) => {
                    // Event bus closed (Runtime shutting down).
                    break;
                }
            }
        }
        tracing::info!(
            agent_id = %self.agent_id,
            "DebugEventMqttPublisher stopped — event bus closed"
        );
    }

    /// Translate one `DebugEvent` into a `DataEnvelope` and PUBLISH it
    /// on the per-event-type sub-topic.
    async fn publish_event(
        &self,
        session_id: &str,
        event: DebugEvent,
    ) -> Result<(), crate::mqtt::client::RuntimeMqttClientError> {
        let (suffix, payload) = encode_event(session_id, event);
        let envelope = DataEnvelope {
            version: 1,
            payload: Some(payload),
        };
        let topic = format!(
            "{}/{}/{}/{}",
            DEBUG_EVENTS_TOPIC_PREFIX, self.agent_id, DEBUG_EVENTS_TOPIC_MIDDLE, suffix
        );
        // ADR-048 §2.4: QoS 0 + Retained=false. DevMode is a developer
        // tool; dropping 1-2 events on reconnect is acceptable. The
        // desktop reconnects and re-fetches the latest state via
        // `GET /api/debug/state`.
        self.mqtt_client
            .publish_envelope(&topic, &envelope, MqttQoS::AtMostOnce, false)
            .await
    }
}

/// Map `(DebugEvent, session_id)` → `(topic_suffix, DataEnvelope payload)`.
///
/// Kept as a free function so it can be unit-tested without spinning up
/// an `RuntimeMqttClient`. Returns the trailing event-type segment so
/// the topic can be assembled by the caller.
fn encode_event(session_id: &str, event: DebugEvent) -> (String, data_envelope::Payload) {
    match event {
        DebugEvent::Step {
            iteration,
            phase,
            input,
            output,
            usage,
        } => {
            let (prompt, completion, total) = match usage {
                Some(u) => (u.prompt_tokens, u.completion_tokens, u.total_tokens),
                None => (0, 0, 0),
            };
            let msg = DebugStepEvent {
                session_id: session_id.to_string(),
                iteration,
                phase: format!("{:?}", phase),
                input: input.map(|v| v.to_string()).unwrap_or_default(),
                output: output.map(|v| v.to_string()).unwrap_or_default(),
                prompt_tokens: prompt,
                completion_tokens: completion,
                total_tokens: total,
            };
            (
                "onStep".to_string(),
                data_envelope::Payload::DebugStepEvent(msg),
            )
        }
        DebugEvent::ContextBuilt {
            iteration,
            sections,
            total_token_estimate,
            request_params,
        } => {
            // Convert the wire-friendly `ContextSections` (with `SectionMeta`
            // metadata only) into the protobuf `SectionMeta` map. The proto
            // SectionMeta is freshly defined here for the debug events;
            // reusing the same field shape keeps the wire format consistent
            // with the agent loop's debug snapshots.
            // ADR-054: `ContextSections` is now a Vec<SectionMeta> — iterate
            // instead of hardcoding the 7 fields so future sections
            // (messages, todo_context, workspace_prompt_file, ...) flow
            // through with zero changes here.
            let sections_map = sections
                .sections
                .iter()
                .map(|meta| {
                    (
                        meta.key.clone(),
                        acowork_core::mqtt_proto::SectionMeta {
                            size_bytes: meta.size_bytes as u64,
                            token_estimate: meta.token_estimate as u64,
                            hash: meta.hash.clone(),
                        },
                    )
                })
                .collect::<std::collections::HashMap<_, _>>();
            let msg = DebugContextBuiltEvent {
                session_id: session_id.to_string(),
                iteration,
                total_token_estimate: total_token_estimate as u64,
                sections: sections_map,
                request_params: Some(acowork_core::mqtt_proto::RequestParams {
                    model: request_params.model.clone(),
                    temperature: request_params.temperature,
                    max_tokens: request_params.max_tokens,
                    reasoning_effort: request_params.reasoning_effort.clone(),
                    thinking_mode: request_params.thinking_mode.clone(),
                }),
            };
            (
                "onContextBuilt".to_string(),
                data_envelope::Payload::DebugContextBuiltEvent(msg),
            )
        }
        DebugEvent::ExecutionStateChanged {
            new_state,
            iteration,
        } => {
            let msg = DebugStateChangeEvent {
                session_id: session_id.to_string(),
                new_state: serde_json::to_string(&new_state)
                    .unwrap_or_default()
                    .trim_matches('"')
                    .to_string(),
                iteration,
            };
            (
                "onStateChange".to_string(),
                data_envelope::Payload::DebugStateChangeEvent(msg),
            )
        }
        DebugEvent::StateChanged {
            old_phase,
            new_phase,
            iteration,
        } => {
            // Map DebugPhase changes to the onStateChange topic too,
            // since the legacy WebSocket emitted two different events
            // (state vs phase change) and the desktop treats them as
            // the same kind of UI update. Reuse the StateChange
            // message type and encode the new_phase in the new_state
            // field (the desktop pattern-matches on the new_state
            // string — for DebugPhase values it gets the phase name).
            let msg = DebugStateChangeEvent {
                session_id: session_id.to_string(),
                new_state: format!("{:?}", new_phase),
                iteration,
            };
            // log old_phase to avoid the unused warning; the field
            // exists for legacy protocol compatibility.
            let _ = old_phase;
            (
                "onStateChange".to_string(),
                data_envelope::Payload::DebugStateChangeEvent(msg),
            )
        }
    }
}

// DebugBreakpointEvent and DebugRecordStepEvent are defined in the
// proto and reserved for future handler additions (setBreakpoint /
// recording). They are not emitted by the current handlers.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::debug::protocol::{ContextSections, DebugPhase, DebugUsage, SectionMeta};

    #[test]
    fn encode_step_event() {
        let (suffix, payload) = encode_event(
            "sess-1",
            DebugEvent::Step {
                iteration: 7,
                phase: DebugPhase::LlmCall,
                input: Some(serde_json::json!({"x": 1})),
                output: Some(serde_json::json!({"y": 2})),
                usage: Some(DebugUsage {
                    prompt_tokens: 100,
                    completion_tokens: 50,
                    total_tokens: 150,
                }),
            },
        );
        assert_eq!(suffix, "onStep");
        match payload {
            data_envelope::Payload::DebugStepEvent(msg) => {
                assert_eq!(msg.session_id, "sess-1");
                assert_eq!(msg.iteration, 7);
                assert_eq!(msg.phase, "LlmCall");
                assert_eq!(msg.input, r#"{"x":1}"#);
                assert_eq!(msg.output, r#"{"y":2}"#);
                assert_eq!(msg.prompt_tokens, 100);
                assert_eq!(msg.total_tokens, 150);
            }
            _ => panic!("expected DebugStepEvent payload"),
        }
    }

    #[test]
    fn encode_context_built_event() {
        let sections = ContextSections {
            sections: vec![
                SectionMeta {
                    key: "system_prompt".to_string(),
                    size_bytes: 100,
                    token_estimate: 25,
                    hash: "h1".to_string(),
                },
                SectionMeta {
                    key: "workspace_context".to_string(),
                    size_bytes: 0,
                    token_estimate: 0,
                    hash: String::new(),
                },
                SectionMeta {
                    key: "environment".to_string(),
                    size_bytes: 0,
                    token_estimate: 0,
                    hash: String::new(),
                },
                SectionMeta {
                    key: "tool_definitions".to_string(),
                    size_bytes: 0,
                    token_estimate: 0,
                    hash: String::new(),
                },
                SectionMeta {
                    key: "skill_instructions".to_string(),
                    size_bytes: 0,
                    token_estimate: 0,
                    hash: String::new(),
                },
                SectionMeta {
                    key: "retrieved_memory".to_string(),
                    size_bytes: 0,
                    token_estimate: 0,
                    hash: String::new(),
                },
                SectionMeta {
                    key: "identity_context".to_string(),
                    size_bytes: 0,
                    token_estimate: 0,
                    hash: String::new(),
                },
            ],
        };
        let (suffix, payload) = encode_event(
            "sess-1",
            DebugEvent::ContextBuilt {
                iteration: 3,
                sections,
                total_token_estimate: 25,
                request_params: crate::debug::protocol::RequestParams {
                    model: "gpt-4o".to_string(),
                    temperature: Some(0.7),
                    max_tokens: Some(2048),
                    reasoning_effort: None,
                    thinking_mode: None,
                },
            },
        );
        assert_eq!(suffix, "onContextBuilt");
        match payload {
            data_envelope::Payload::DebugContextBuiltEvent(msg) => {
                assert_eq!(msg.session_id, "sess-1");
                assert_eq!(msg.iteration, 3);
                assert_eq!(msg.total_token_estimate, 25);
                assert_eq!(msg.sections.len(), 7, "all 7 sections must be encoded");
                let sys = msg.sections.get("system_prompt").unwrap();
                assert_eq!(sys.size_bytes, 100);
                assert_eq!(sys.token_estimate, 25);
                assert_eq!(sys.hash, "h1");
                // ADR-054 step 2: request params ride the event.
                let rp = msg.request_params.expect("request_params must be set");
                assert_eq!(rp.model, "gpt-4o");
                assert_eq!(rp.temperature, Some(0.7));
                assert_eq!(rp.max_tokens, Some(2048));
            }
            _ => panic!("expected DebugContextBuiltEvent payload"),
        }
    }

    #[test]
    fn encode_state_change_event() {
        let (suffix, payload) = encode_event(
            "sess-1",
            DebugEvent::ExecutionStateChanged {
                new_state: crate::debug::controller::DebugState::Paused,
                iteration: 4,
            },
        );
        assert_eq!(suffix, "onStateChange");
        match payload {
            data_envelope::Payload::DebugStateChangeEvent(msg) => {
                assert_eq!(msg.session_id, "sess-1");
                assert_eq!(msg.iteration, 4);
                assert_eq!(msg.new_state, "Paused");
            }
            _ => panic!("expected DebugStateChangeEvent payload"),
        }
    }
}
