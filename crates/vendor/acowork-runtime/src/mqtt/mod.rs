//! MQTT module — Runtime MQTT client (ADR-033 Phase 2).
//!
//! The Runtime connects to the Gateway's embedded MQTT broker as a
//! `rumqttc` client (`client_id: "agent:{agent_id}"`). It publishes
//! agent lifecycle data (status, meta, config) as Retained messages
//! and subscribes to global resource updates + control commands.
//!
//! See `docs/zh/protocols/mqtt.md` §3.2 and §5.1.

pub mod agent_config_publisher;
pub mod available_cache;
pub mod client;
pub mod control_handler;
pub mod debug_events;

pub use agent_config_publisher::MqttAgentConfigPublisher;
pub use available_cache::{AvailableResourceCache, SharedAvailableCache, new_shared_cache};
pub use client::{
    MqttChunkPublisher, MqttConnectConfig, RuntimeMqttClient, RuntimeMqttClientError,
    ToolApprovalNeededEvent,
};
pub use debug_events::DebugEventMqttPublisher;
