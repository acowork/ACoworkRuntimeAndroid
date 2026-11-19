//! Android-side Node Agent pieces: engine spawn contract, process table,
//! Gateway tags, identity, MQTT session, reverse proxy, package inventory.
//!
//! This is **not** a dependency on upstream `acowork-node`. ADR-AND-003: the
//! Android port speaks the Gateway protocol and runs its own node+runtime.

pub mod control;
pub mod engine;
pub mod enroll;
pub mod identity;
pub mod mqtt;
pub mod package;
pub mod process;
pub mod proto;
pub mod proxy;
pub mod tags;
pub mod topics;

pub use control::{ControlCtx, handle_control, refresh_info, set_node_home, start_agent, sync_ports_from_table};
pub use engine::{EngineError, EngineSpec, RuntimeLaunch};
pub use enroll::{EnrollError, EnrollRequest, GatewayReachability, check_gateway_http};
pub use identity::{EnrollmentState, IdentityError, NodeIdentity};
pub use mqtt::{
    IncomingPublish, MqttError, MqttSession, SharedCredentials, SharedIdentity, announce,
    connect as mqtt_connect, decode_enroll_result, decode_envelope, publish_event,
};
pub use package::{
    InstalledPackage, ManifestSummary, PackageError, PackageInventory, download_package,
};
pub use process::{ProcessError, ProcessTable, RuntimeHandle, RuntimeStatus};
pub use proxy::{
    PortTable, ProxyError, ProxyHandle, ProxyState, shared_identity, start as proxy_start,
    sync_ports,
};
pub use tags::{capability_tags, tag_cap, tag_dialect, tag_privilege, tag_profile};
pub use topics::{
    GATEWAY_MQTT_PORT, NODE_HTTP_PORT_BASE, NODE_PROTOCOL_VERSION, NODE_PROXY_PORT,
    node_agent_events_topic, node_agent_installed_topic, node_client_id, node_enroll_result_topic,
    node_enroll_topic, node_events_topic, node_info_topic, node_name_from_hostname,
    node_name_is_valid, node_ready_topic, node_status_topic, parse_control_topic,
};
