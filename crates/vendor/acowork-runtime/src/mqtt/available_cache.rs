//! Global resource available cache (ADR-033 Phase 2).
//!
//! In-memory cache of the latest `acowork/global/{kind}` Retained messages.
//! Updated by the Runtime MQTT client's event loop as it receives
//! `Available*` payloads. The Runtime queries this cache to know which
//! providers, MCPs, embedding models, LSP relays, and the
//! active user profile are currently available (health-check verified
//! by Gateway; user profile is authoritative per ADR-042).
//!
//! See `docs/zh/protocols/mqtt.md` §3.1.1 and §4.

use std::sync::Arc;

use tokio::sync::RwLock;

use acowork_core::mqtt_proto::{
    AvailableEmbeddingModels, AvailableLsps, AvailableMcps, AvailableProviders,
    AvailableUsers, BootstrapState, DataEnvelope,
};

/// Global-resource snapshot that carries a monotonic `version` used to
/// reject stale retained re-delivery (ADR-059 §5.3).
///
/// Implemented for every `Available*` proto message that has a `version`
/// field. The `bootstrap` snapshot is handled separately — its staleness
/// check also involves `instance_id` (a Gateway generation switch).
trait Versioned {
    fn version(&self) -> u64;
}

macro_rules! impl_versioned {
    ($($ty:ty),* $(,)?) => {
        $(
            impl Versioned for $ty {
                fn version(&self) -> u64 { self.version }
            }
        )*
    };
}

impl_versioned!(
    AvailableProviders,
    AvailableMcps,
    AvailableEmbeddingModels,
    AvailableLsps,
    AvailableUsers,
);

/// In-memory snapshot of all global resource available states.
///
/// Updated atomically when new Retained messages arrive on `acowork/global/#`.
#[derive(Debug, Clone, Default)]
pub struct AvailableResourceCache {
    pub providers: Option<AvailableProviders>,
    pub mcps: Option<AvailableMcps>,
    pub embedding_models: Option<AvailableEmbeddingModels>,
    pub lsps: Option<AvailableLsps>,
    /// ADR-042: Active user profile (Gateway-authoritative). None until
    /// the first `acowork/global/user_profile` retained is received, or
    /// when no user has been created yet.
    pub user_profile: Option<AvailableUsers>,
    /// ADR-059 Phase 5.3: latest accepted Gateway bootstrap snapshot
    /// (`acowork/global/bootstrap` retained). None until the first
    /// snapshot arrives. Stale retained re-delivery (same `instance_id`
    /// with a lower `version`) is rejected in [`Self::update_from_mqtt`];
    /// a different `instance_id` switches the Gateway generation and
    /// drops every old-generation resource snapshot above.
    pub bootstrap: Option<BootstrapState>,
}

impl AvailableResourceCache {
    /// Create a new empty cache.
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether `incoming` should replace the currently cached snapshot
    /// for a resource slot.
    ///
    /// Returns `true` when no snapshot is cached yet (first delivery)
    /// or when the incoming `version` has not gone backwards. Returns
    /// `false` for a stale retained re-delivery — the broker may
    /// re-deliver an older retained payload after a reconnect, and a
    /// `version` that went backwards is never a newer snapshot, so the
    /// caller must keep the cached one.
    fn is_newer_or_first<T: Versioned>(&self, current: &Option<T>, incoming: &T) -> bool {
        match current {
            Some(cur) => incoming.version() >= cur.version(),
            None => true,
        }
    }

    /// Update the cache from an incoming MQTT message.
    ///
    /// `topic` should be an `acowork/global/{kind}` topic.
    /// `payload` should be a protobuf-encoded `DataEnvelope`.
    pub fn update_from_mqtt(&mut self, topic: &str, payload: &[u8]) {
        let envelope: DataEnvelope = match prost::Message::decode(payload) {
            Ok(e) => e,
            Err(e) => {
                tracing::warn!(
                    topic,
                    error = %e,
                    "Failed to decode DataEnvelope from global resource topic"
                );
                return;
            }
        };

        let payload = match envelope.payload {
            Some(p) => p,
            None => return,
        };

        match payload {
            acowork_core::mqtt_proto::data_envelope::Payload::AvailableProviders(p) => {
                // ADR-059 §5.3: reject stale retained re-delivery (see
                // `is_newer_or_first`).
                if !self.is_newer_or_first(&self.providers, &p) {
                    tracing::warn!(
                        stale_version = p.version,
                        current_version = self.providers.as_ref().map(|c| c.version).unwrap_or(0),
                        "Rejected stale AvailableProviders retained re-delivery"
                    );
                    return;
                }
                tracing::debug!(
                    version = p.version,
                    count = p.providers.len(),
                    "Cached AvailableProviders"
                );
                self.providers = Some(p);
            }
            acowork_core::mqtt_proto::data_envelope::Payload::AvailableMcps(p) => {
                // ADR-059 §5.3: reject stale retained re-delivery (see
                // `is_newer_or_first`).
                if !self.is_newer_or_first(&self.mcps, &p) {
                    tracing::warn!(
                        stale_version = p.version,
                        current_version = self.mcps.as_ref().map(|c| c.version).unwrap_or(0),
                        "Rejected stale AvailableMcps retained re-delivery"
                    );
                    return;
                }
                tracing::debug!(
                    version = p.version,
                    count = p.servers.len(),
                    "Cached AvailableMcps"
                );
                self.mcps = Some(p);
            }
            acowork_core::mqtt_proto::data_envelope::Payload::AvailableEmbeddingModels(p) => {
                // ADR-059 §5.3: reject stale retained re-delivery (see
                // `is_newer_or_first`).
                if !self.is_newer_or_first(&self.embedding_models, &p) {
                    tracing::warn!(
                        stale_version = p.version,
                        current_version = self
                            .embedding_models
                            .as_ref()
                            .map(|c| c.version)
                            .unwrap_or(0),
                        "Rejected stale AvailableEmbeddingModels retained re-delivery"
                    );
                    return;
                }
                tracing::debug!(
                    version = p.version,
                    count = p.models.len(),
                    active_model = %p.active_model_id,
                    "Cached AvailableEmbeddingModels"
                );
                self.embedding_models = Some(p);
            }
            acowork_core::mqtt_proto::data_envelope::Payload::AvailableLsps(p) => {
                // ADR-059 §5.3: reject stale retained re-delivery (see
                // `is_newer_or_first`).
                if !self.is_newer_or_first(&self.lsps, &p) {
                    tracing::warn!(
                        stale_version = p.version,
                        current_version = self.lsps.as_ref().map(|c| c.version).unwrap_or(0),
                        "Rejected stale AvailableLsps retained re-delivery"
                    );
                    return;
                }
                tracing::debug!(
                    ready = p.ready,
                    endpoint = %p.endpoint,
                    "Cached AvailableLsps"
                );
                self.lsps = Some(p);
            }
            acowork_core::mqtt_proto::data_envelope::Payload::AvailableUsers(p) => {
                // Note: an empty `active_user` (no user created yet) is a
                // legitimate newer state, so only `version` regression is
                // rejected here — never the payload content.
                // ADR-059 §5.3: reject stale retained re-delivery (see
                // `is_newer_or_first`).
                if !self.is_newer_or_first(&self.user_profile, &p) {
                    tracing::warn!(
                        stale_version = p.version,
                        current_version =
                            self.user_profile.as_ref().map(|c| c.version).unwrap_or(0),
                        "Rejected stale AvailableUsers retained re-delivery"
                    );
                    return;
                }
                let active = p
                    .active_user
                    .as_ref()
                    .map(|u| u.user_id.as_str())
                    .unwrap_or("");
                tracing::debug!(
                    version = p.version,
                    active_user_id = %active,
                    "Cached AvailableUsers"
                );
                self.user_profile = Some(p);
            }
            acowork_core::mqtt_proto::data_envelope::Payload::BootstrapState(bs) => {
                // ADR-059 §5.3 / Phase 5.3: single-snapshot atomicity.
                // Reject stale retained re-delivery by `instance_id` +
                // `version`, and treat a different `instance_id` as a
                // Gateway generation switch: the old generation's
                // resource snapshots may still linger on the broker, so
                // they must NOT keep being used as if they belonged to
                // the current instance.
                if bs.instance_id.is_empty() {
                    tracing::warn!(
                        "Rejected BootstrapState with empty instance_id (protocol violation)"
                    );
                    return;
                }
                if let Some(cur) = &self.bootstrap {
                    if cur.instance_id == bs.instance_id {
                        if bs.version < cur.version {
                            tracing::warn!(
                                instance_id = %bs.instance_id,
                                stale_version = bs.version,
                                current_version = cur.version,
                                "Rejected stale BootstrapState retained re-delivery (version went backwards)"
                            );
                            return;
                        }
                    } else {
                        // New Gateway generation — drop every resource
                        // snapshot cached from the previous instance so
                        // nothing downstream uses old-generation keys /
                        // catalogs (cold start, hot restart and reconnect
                        // share this single path).
                        tracing::info!(
                            old_instance_id = %cur.instance_id,
                            new_instance_id = %bs.instance_id,
                            "BootstrapState generation switch - cleared old-generation resource snapshots"
                        );
                        self.providers = None;
                        self.mcps = None;
                        self.embedding_models = None;
                        self.lsps = None;
                        self.user_profile = None;
                    }
                }
                tracing::info!(
                    instance_id = %bs.instance_id,
                    version = bs.version,
                    phase = ?acowork_core::mqtt_proto::BootstrapPhase::try_from(bs.phase).ok(),
                    "Cached BootstrapState (Gateway generation)"
                );
                self.bootstrap = Some(bs);
            }
            _ => {
                // Not a global resource payload — ignore
            }
        }
    }

    /// Check if a provider is in the available list AND callable.
    ///
    /// ADR-056: a provider is callable when it either carries a non-empty
    /// API key (cloud) or points at a local base_url (self-hosted Ollama
    /// etc. — empty key by design). This mirrors
    /// `AgentCore::is_default_compact_provider_available`, which is what
    /// `resolve_distill_model` actually consults at distillation time.
    ///
    /// Note: the proto `ProviderRef` carries the decrypted key (empty for
    /// local providers) and `base_url`, so no Vault round-trip is needed.
    #[allow(dead_code)]
    pub fn is_provider_available(&self, provider_id: &str) -> bool {
        let Some(available) = self.providers.as_ref() else {
            return false;
        };
        available.providers.iter().any(|pr| {
            pr.id == provider_id
                && (!pr.api_key.is_empty() || crate::providers::is_local_base_url(&pr.base_url))
        })
    }

    /// Check if an MCP server is in the available list.
    #[allow(dead_code)]
    pub fn is_mcp_available(&self, mcp_id: &str) -> bool {
        self.mcps
            .as_ref()
            .map(|p| p.servers.iter().any(|s| s.id == mcp_id))
            .unwrap_or(false)
    }

    /// Get the embedding endpoint if an embedding model is loaded.
    pub fn embed_endpoint(&self) -> Option<String> {
        self.embedding_models
            .as_ref()
            .filter(|e| !e.endpoint.is_empty() && !e.active_model_id.is_empty())
            .map(|e| e.endpoint.clone())
    }

    /// Get the full active embedding config (endpoint, model id, dimension)
    /// if an embedding model is loaded. Used by agent boot to recover the
    /// config that the Gateway forgot to inject as env vars (Bug1).
    pub fn embedding_config(&self) -> Option<(String, String, usize)> {
        self.embedding_models
            .as_ref()
            .filter(|e| !e.endpoint.is_empty() && !e.active_model_id.is_empty())
            .map(|e| {
                (
                    e.endpoint.clone(),
                    e.active_model_id.clone(),
                    e.active_dimension as usize,
                )
            })
    }

    /// Get the LSP relay endpoint if it's ready.
    pub fn lsp_endpoint(&self) -> Option<String> {
        self.lsps
            .as_ref()
            .filter(|l| l.ready && !l.endpoint.is_empty())
            .map(|l| l.endpoint.clone())
    }

    /// ADR-059 Phase 5.3: the latest accepted Gateway bootstrap
    /// snapshot, or `None` before the first `acowork/global/bootstrap`
    /// retained arrives.
    pub fn bootstrap_snapshot(&self) -> Option<&BootstrapState> {
        self.bootstrap.as_ref()
    }

    /// ADR-059 Phase 5.3: `true` when the current Gateway instance
    /// reports the aggregated `READY` phase.
    pub fn is_bootstrap_ready(&self) -> bool {
        self.bootstrap
            .as_ref()
            .map(|b| b.phase == acowork_core::mqtt_proto::BootstrapPhase::Ready as i32)
            .unwrap_or(false)
    }

    /// ADR-059 Phase 5.3: `instance_id` of the latest accepted
    /// snapshot — the Gateway generation currently considered
    /// authoritative. `None` before the first snapshot arrives.
    pub fn bootstrap_instance_id(&self) -> Option<&str> {
        self.bootstrap.as_ref().map(|b| b.instance_id.as_str())
    }

    /// ADR-042: Get the active user profile as the full
    /// `acowork_core::protocol::UserProfile` struct (used by
    /// `format_user_profile_context` to build identity_context).
    ///
    /// Returns `None` when:
    /// - The cache hasn't received the first `acowork/global/user_profile`
    ///   retained yet (Runtime just started), OR
    /// - The Gateway hasn't created any user (empty active_user).
    ///
    /// The `custom` HashMap is reconstructed from the JSON-serialised
    /// `custom_json` field; an empty string decodes to an empty map.
    pub fn active_user_profile(&self) -> Option<acowork_core::protocol::UserProfile> {
        let p = self.user_profile.as_ref()?;
        let active = p.active_user.as_ref()?;
        if active.user_id.is_empty() {
            return None;
        }
        let custom: std::collections::HashMap<String, String> =
            serde_json::from_str(&active.custom_json).unwrap_or_else(|e| {
                tracing::warn!(
                    user_id = %active.user_id,
                    error = %e,
                    "Failed to parse UserProfileRef.custom_json; using empty map"
                );
                Default::default()
            });
        Some(acowork_core::protocol::UserProfile {
            user_id: active.user_id.clone(),
            display_name: active.display_name.clone(),
            language: active.language.clone(),
            timezone: active.timezone.clone(),
            city: active.city.clone(),
            country: active.country.clone(),
            occupation: active.occupation.clone(),
            avatar: None,         // not carried in UserProfileRef
            builtin_avatar: None, // not carried in UserProfileRef
            communication_style: active.communication_style.clone(),
            custom,
            created_at: String::new(), // not carried in UserProfileRef
            updated_at: String::new(), // not carried in UserProfileRef
            is_active: true,           // subscribed topic only carries active
        })
    }
}

/// Thread-safe shared AvailableResourceCache.
pub type SharedAvailableCache = Arc<RwLock<AvailableResourceCache>>;

/// Create a new shared AvailableResourceCache.
pub fn new_shared_cache() -> SharedAvailableCache {
    Arc::new(RwLock::new(AvailableResourceCache::new()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_update_from_mqtt_providers() {
        let mut cache = AvailableResourceCache::new();
        let envelope = DataEnvelope {
            version: 1,
            payload: Some(
                acowork_core::mqtt_proto::data_envelope::Payload::AvailableProviders(
                    AvailableProviders {
                        version: 5,
                        // ADR-056: No global default compact model in this fixture.
                        #[allow(deprecated)]
                        default_compact_model: None,
                        default_compact_models: vec![],
                        providers: vec![
                            acowork_core::mqtt_proto::ProviderRef {
                                id: "openai".to_string(),
                                base_url: "https://api.openai.com/v1".to_string(),
                                protocol_type: acowork_core::mqtt_proto::LlmProtocol::Openai as i32,
                                models: vec![],
                                compact_model: String::new(),
                                custom: false,
                                api_key: "sk-test".to_string(),
                                account_id: String::new(),
                            },
                            // Local provider — empty key by design, still callable.
                            acowork_core::mqtt_proto::ProviderRef {
                                id: "ollama-local".to_string(),
                                base_url: "http://localhost:11434/v1".to_string(),
                                protocol_type: acowork_core::mqtt_proto::LlmProtocol::Ollama as i32,
                                models: vec![],
                                compact_model: String::new(),
                                custom: false,
                                api_key: String::new(),
                                account_id: String::new(),
                            },
                        ],
                    },
                ),
            ),
        };
        let payload = prost::Message::encode_to_vec(&envelope);

        cache.update_from_mqtt("acowork/global/providers", &payload);

        // Cloud provider with key → available; unknown provider → not.
        assert!(cache.is_provider_available("openai"));
        assert!(!cache.is_provider_available("anthropic"));
        assert_eq!(cache.providers.as_ref().unwrap().version, 5);
    }

    #[test]
    fn test_is_provider_available_local_provider_without_key() {
        // ADR-056 §9.1 ①: local provider (empty api_key + local base_url)
        // counts as available — distillation can target it without a key.
        let mut cache = AvailableResourceCache::new();
        let envelope = DataEnvelope {
            version: 1,
            payload: Some(
                acowork_core::mqtt_proto::data_envelope::Payload::AvailableProviders(
                    AvailableProviders {
                        version: 1,
                        #[allow(deprecated)]
                        default_compact_model: None,
                        default_compact_models: vec![],
                        providers: vec![acowork_core::mqtt_proto::ProviderRef {
                            id: "ollama-local".to_string(),
                            base_url: "http://localhost:11434/v1".to_string(),
                            protocol_type: acowork_core::mqtt_proto::LlmProtocol::Ollama as i32,
                            models: vec![],
                            compact_model: String::new(),
                            custom: false,
                            api_key: String::new(),
                            account_id: String::new(),
                        }],
                    },
                ),
            ),
        };
        cache.update_from_mqtt(
            "acowork/global/providers",
            &prost::Message::encode_to_vec(&envelope),
        );
        assert!(cache.is_provider_available("ollama-local"));
    }

    #[test]
    fn test_is_provider_available_cloud_without_key_is_unavailable() {
        // ADR-056 §9.1 ②: cloud provider with empty api_key is NOT callable
        // (key revoked / never configured) → distillation falls back.
        let mut cache = AvailableResourceCache::new();
        let envelope = DataEnvelope {
            version: 1,
            payload: Some(
                acowork_core::mqtt_proto::data_envelope::Payload::AvailableProviders(
                    AvailableProviders {
                        version: 1,
                        #[allow(deprecated)]
                        default_compact_model: None,
                        default_compact_models: vec![],
                        providers: vec![acowork_core::mqtt_proto::ProviderRef {
                            id: "anthropic".to_string(),
                            base_url: "https://api.anthropic.com/v1".to_string(),
                            protocol_type: acowork_core::mqtt_proto::LlmProtocol::Anthropic as i32,
                            models: vec![],
                            compact_model: String::new(),
                            custom: false,
                            api_key: String::new(),
                            account_id: String::new(),
                        }],
                    },
                ),
            ),
        };
        cache.update_from_mqtt(
            "acowork/global/providers",
            &prost::Message::encode_to_vec(&envelope),
        );
        assert!(!cache.is_provider_available("anthropic"));
    }

    #[test]
    fn test_is_provider_available_unknown_provider() {
        // ADR-056 §9.1 ③: provider absent from the available list → not available.
        let mut cache = AvailableResourceCache::new();
        let envelope = DataEnvelope {
            version: 1,
            payload: Some(
                acowork_core::mqtt_proto::data_envelope::Payload::AvailableProviders(
                    AvailableProviders {
                        version: 1,
                        #[allow(deprecated)]
                        default_compact_model: None,
                        default_compact_models: vec![],
                        providers: vec![],
                    },
                ),
            ),
        };
        cache.update_from_mqtt(
            "acowork/global/providers",
            &prost::Message::encode_to_vec(&envelope),
        );
        assert!(!cache.is_provider_available("ghost-provider"));
    }

    #[test]
    fn test_update_from_mqtt_invalid_payload() {
        let mut cache = AvailableResourceCache::new();
        cache.update_from_mqtt("acowork/global/providers", b"not protobuf");
        assert!(
            cache.providers.is_none(),
            "invalid payload should not update cache"
        );
    }

    #[test]
    fn test_embed_endpoint() {
        let mut cache = AvailableResourceCache::new();

        // No embedding models → no endpoint
        assert!(cache.embed_endpoint().is_none());

        // With active model
        cache.embedding_models = Some(AvailableEmbeddingModels {
            version: 1,
            models: vec![],
            active_model_id: "bge-small".to_string(),
            active_dimension: 512,
            endpoint: "http://127.0.0.1:18080/v1".to_string(),
            active_provider_id: String::new(),
            active_api_key: String::new(),
            active_base_url: String::new(),
        });
        assert_eq!(
            cache.embed_endpoint().as_deref(),
            Some("http://127.0.0.1:18080/v1")
        );
    }

    #[test]
    fn test_lsp_endpoint() {
        let mut cache = AvailableResourceCache::new();

        // No LSP → no endpoint
        assert!(cache.lsp_endpoint().is_none());

        // LSP not ready
        cache.lsps = Some(AvailableLsps {
            version: 1,
            endpoint: "http://127.0.0.1:19878".to_string(),
            ready: false,
        });
        assert!(cache.lsp_endpoint().is_none());

        // LSP ready
        cache.lsps = Some(AvailableLsps {
            version: 1,
            endpoint: "http://127.0.0.1:19878".to_string(),
            ready: true,
        });
        assert_eq!(
            cache.lsp_endpoint().as_deref(),
            Some("http://127.0.0.1:19878")
        );
    }

    // ── ADR-042: user_profile topic tests ─────────────────────────────

    #[test]
    fn test_update_from_mqtt_user_profile() {
        use acowork_core::mqtt_proto::UserProfileRef;
        let mut cache = AvailableResourceCache::new();

        let envelope = DataEnvelope {
            version: 1,
            payload: Some(
                acowork_core::mqtt_proto::data_envelope::Payload::AvailableUsers(AvailableUsers {
                    version: 7,
                    active_user: Some(UserProfileRef {
                        user_id: "u-1".to_string(),
                        display_name: "大鱼".to_string(),
                        language: "zh-CN".to_string(),
                        timezone: "Asia/Shanghai".to_string(),
                        city: Some("Beijing".to_string()),
                        country: Some("CN".to_string()),
                        occupation: Some("Software Engineer".to_string()),
                        communication_style: Some("concise".to_string()),
                        custom_json: r#"{"theme":"dark"}"#.to_string(),
                    }),
                }),
            ),
        };
        let payload = prost::Message::encode_to_vec(&envelope);

        cache.update_from_mqtt("acowork/global/user_profile", &payload);

        let profile = cache
            .active_user_profile()
            .expect("active user should be present");
        assert_eq!(profile.user_id, "u-1");
        assert_eq!(profile.display_name, "大鱼");
        assert_eq!(profile.language, "zh-CN");
        assert_eq!(profile.timezone, "Asia/Shanghai");
        assert_eq!(profile.city.as_deref(), Some("Beijing"));
        assert_eq!(profile.occupation.as_deref(), Some("Software Engineer"));
        assert_eq!(profile.communication_style.as_deref(), Some("concise"));
        assert_eq!(
            profile.custom.get("theme").map(String::as_str),
            Some("dark")
        );
        assert!(profile.is_active); // wire always carries active
    }

    #[test]
    fn test_active_user_profile_empty_when_no_user() {
        // Empty active_user (no user created yet) → None.
        let mut cache = AvailableResourceCache::new();
        cache.update_from_mqtt(
            "acowork/global/user_profile",
            &prost::Message::encode_to_vec(&DataEnvelope {
                version: 1,
                payload: Some(
                    acowork_core::mqtt_proto::data_envelope::Payload::AvailableUsers(
                        AvailableUsers {
                            version: 0,
                            active_user: None,
                        },
                    ),
                ),
            }),
        );
        assert!(cache.active_user_profile().is_none());
    }

    /// Boot-time contract for `agent_init` identity wait (ADR-042).
    /// After a retained `acowork/global/user_profile` with no active user
    /// is received, `user_profile` is `Some` (envelope landed) while
    /// `active_user_profile()` is `None` (no user). `agent_init` MUST
    /// treat this as a definitive answer and not poll until timeout.
    /// Regression test for the 5-second stall on first agent boot when
    /// the gateway had no active user yet.
    #[test]
    fn test_boot_contract_empty_user_is_definitive() {
        let mut cache = AvailableResourceCache::new();
        cache.update_from_mqtt(
            "acowork/global/user_profile",
            &prost::Message::encode_to_vec(&DataEnvelope {
                version: 3,
                payload: Some(
                    acowork_core::mqtt_proto::data_envelope::Payload::AvailableUsers(
                        AvailableUsers {
                            version: 3,
                            active_user: None,
                        },
                    ),
                ),
            }),
        );
        // envelope has landed:
        assert!(cache.user_profile.is_some(), "envelope should be cached");
        // but there is no active user to format:
        assert!(
            cache.active_user_profile().is_none(),
            "no active user means identity_context is None"
        );
    }

    #[test]
    fn test_active_user_profile_invalid_custom_json() {
        // Bad JSON in custom_json should not crash — fall back to empty map.
        let mut cache = AvailableResourceCache::new();
        cache.update_from_mqtt(
            "acowork/global/user_profile",
            &prost::Message::encode_to_vec(&DataEnvelope {
                version: 1,
                payload: Some(
                    acowork_core::mqtt_proto::data_envelope::Payload::AvailableUsers(
                        AvailableUsers {
                            version: 1,
                            active_user: Some(acowork_core::mqtt_proto::UserProfileRef {
                                user_id: "u-1".into(),
                                display_name: "Test".into(),
                                language: "en-US".into(),
                                timezone: "UTC".into(),
                                city: None,
                                country: None,
                                occupation: None,
                                communication_style: None,
                                custom_json: "not valid json".into(),
                            }),
                        },
                    ),
                ),
            }),
        );
        let profile = cache
            .active_user_profile()
            .expect("should still return Some");
        assert!(profile.custom.is_empty());
    }

    // ── ADR-059 Phase 5.3: bootstrap snapshot + stale rejection ──────

    /// Encode a BootstrapState fixture into a DataEnvelope payload.
    fn bootstrap_envelope(instance_id: &str, version: u64, phase: i32) -> Vec<u8> {
        prost::Message::encode_to_vec(&DataEnvelope {
            version: 1,
            payload: Some(
                acowork_core::mqtt_proto::data_envelope::Payload::BootstrapState(BootstrapState {
                    protocol_version: 1,
                    instance_id: instance_id.to_string(),
                    version,
                    phase,
                    phase_detail: "test".to_string(),
                    issued_at_ms: 0,
                }),
            ),
        })
    }

    #[test]
    fn test_bootstrap_first_snapshot_accepted() {
        let mut cache = AvailableResourceCache::new();
        assert!(cache.bootstrap_snapshot().is_none());
        assert!(!cache.is_bootstrap_ready());

        cache.update_from_mqtt(
            "acowork/global/bootstrap",
            &bootstrap_envelope(
                "gen-A",
                1,
                acowork_core::mqtt_proto::BootstrapPhase::Booting as i32,
            ),
        );

        let bs = cache.bootstrap_snapshot().expect("first snapshot accepted");
        assert_eq!(bs.instance_id, "gen-A");
        assert_eq!(bs.version, 1);
        assert_eq!(cache.bootstrap_instance_id(), Some("gen-A"));
        assert!(!cache.is_bootstrap_ready());
    }

    #[test]
    fn test_bootstrap_ready_phase() {
        let mut cache = AvailableResourceCache::new();
        cache.update_from_mqtt(
            "acowork/global/bootstrap",
            &bootstrap_envelope(
                "gen-A",
                2,
                acowork_core::mqtt_proto::BootstrapPhase::Ready as i32,
            ),
        );
        assert!(cache.is_bootstrap_ready());
    }

    #[test]
    fn test_bootstrap_same_instance_version_monotonic() {
        let mut cache = AvailableResourceCache::new();
        cache.update_from_mqtt(
            "acowork/global/bootstrap",
            &bootstrap_envelope(
                "gen-A",
                3,
                acowork_core::mqtt_proto::BootstrapPhase::Booting as i32,
            ),
        );
        // Newer version, same instance → accepted.
        cache.update_from_mqtt(
            "acowork/global/bootstrap",
            &bootstrap_envelope(
                "gen-A",
                4,
                acowork_core::mqtt_proto::BootstrapPhase::Ready as i32,
            ),
        );
        let bs = cache.bootstrap_snapshot().unwrap();
        assert_eq!(bs.version, 4);
        assert!(cache.is_bootstrap_ready());
        // Identical version (retained re-delivery) → idempotent accept.
        cache.update_from_mqtt(
            "acowork/global/bootstrap",
            &bootstrap_envelope(
                "gen-A",
                4,
                acowork_core::mqtt_proto::BootstrapPhase::Ready as i32,
            ),
        );
        assert_eq!(cache.bootstrap_snapshot().unwrap().version, 4);
    }

    #[test]
    fn test_bootstrap_stale_version_rejected() {
        let mut cache = AvailableResourceCache::new();
        cache.update_from_mqtt(
            "acowork/global/bootstrap",
            &bootstrap_envelope(
                "gen-A",
                5,
                acowork_core::mqtt_proto::BootstrapPhase::Ready as i32,
            ),
        );
        // Older version, same instance → rejected, current snapshot kept.
        cache.update_from_mqtt(
            "acowork/global/bootstrap",
            &bootstrap_envelope(
                "gen-A",
                3,
                acowork_core::mqtt_proto::BootstrapPhase::Booting as i32,
            ),
        );
        let bs = cache.bootstrap_snapshot().unwrap();
        assert_eq!(bs.version, 5);
        assert!(cache.is_bootstrap_ready());
    }

    #[test]
    fn test_bootstrap_generation_switch_clears_old_resources() {
        let mut cache = AvailableResourceCache::new();
        // Seed old-generation resources + READY snapshot.
        cache.update_from_mqtt(
            "acowork/global/providers",
            &prost::Message::encode_to_vec(&DataEnvelope {
                version: 1,
                payload: Some(
                    acowork_core::mqtt_proto::data_envelope::Payload::AvailableProviders(
                        AvailableProviders {
                            version: 9,
                            #[allow(deprecated)]
                            default_compact_model: None,
                            default_compact_models: vec![],
                            providers: vec![acowork_core::mqtt_proto::ProviderRef {
                                id: "openai".to_string(),
                                base_url: "https://api.openai.com/v1".to_string(),
                                protocol_type: acowork_core::mqtt_proto::LlmProtocol::Openai as i32,
                                models: vec![],
                                compact_model: String::new(),
                                custom: false,
                                api_key: "sk-old-generation".to_string(),
                                account_id: String::new(),
                            }],
                        },
                    ),
                ),
            }),
        );
        cache.update_from_mqtt(
            "acowork/global/user_profile",
            &prost::Message::encode_to_vec(&DataEnvelope {
                version: 1,
                payload: Some(
                    acowork_core::mqtt_proto::data_envelope::Payload::AvailableUsers(
                        AvailableUsers {
                            version: 4,
                            active_user: Some(acowork_core::mqtt_proto::UserProfileRef {
                                user_id: "u-old".into(),
                                display_name: "Old".into(),
                                language: "en".into(),
                                timezone: "UTC".into(),
                                city: None,
                                country: None,
                                occupation: None,
                                communication_style: None,
                                custom_json: "{}".into(),
                            }),
                        },
                    ),
                ),
            }),
        );
        cache.update_from_mqtt(
            "acowork/global/bootstrap",
            &bootstrap_envelope(
                "gen-A",
                6,
                acowork_core::mqtt_proto::BootstrapPhase::Ready as i32,
            ),
        );
        assert!(cache.providers.is_some());
        assert!(cache.user_profile.is_some());

        // New generation BOOTING snapshot → accepted; old resources cleared.
        cache.update_from_mqtt(
            "acowork/global/bootstrap",
            &bootstrap_envelope(
                "gen-B",
                1,
                acowork_core::mqtt_proto::BootstrapPhase::Booting as i32,
            ),
        );
        assert_eq!(cache.bootstrap_instance_id(), Some("gen-B"));
        assert!(
            cache.providers.is_none(),
            "old-generation providers must be cleared"
        );
        assert!(
            cache.user_profile.is_none(),
            "old-generation user profile must be cleared"
        );
        assert!(!cache.is_bootstrap_ready());

        // New generation reaches READY.
        cache.update_from_mqtt(
            "acowork/global/bootstrap",
            &bootstrap_envelope(
                "gen-B",
                2,
                acowork_core::mqtt_proto::BootstrapPhase::Ready as i32,
            ),
        );
        assert!(cache.is_bootstrap_ready());
        // A further generation switch (another Gateway restart) follows
        // the same rule: accept the new instance_id and drop every
        // resource snapshot cached from the previous generation. A
        // stale same-topic re-delivery cannot resurrect the old
        // generation because the broker keeps only the latest retained
        // payload per topic (old snapshots are overwritten, not
        // re-delivered alongside the new one).
        cache.update_from_mqtt(
            "acowork/global/bootstrap",
            &bootstrap_envelope(
                "gen-C",
                1,
                acowork_core::mqtt_proto::BootstrapPhase::Booting as i32,
            ),
        );
        assert_eq!(cache.bootstrap_instance_id(), Some("gen-C"));
        assert!(
            cache.providers.is_none() && cache.user_profile.is_none(),
            "generation switch must clear previous-generation resources"
        );
    }

    #[test]
    fn test_bootstrap_empty_instance_id_rejected() {
        let mut cache = AvailableResourceCache::new();
        cache.update_from_mqtt("acowork/global/bootstrap", &bootstrap_envelope("", 1, 0));
        assert!(
            cache.bootstrap_snapshot().is_none(),
            "empty instance_id must be rejected"
        );
    }

    #[test]
    fn test_bootstrap_invalid_payload_ignored() {
        let mut cache = AvailableResourceCache::new();
        cache.update_from_mqtt("acowork/global/bootstrap", b"not protobuf");
        assert!(cache.bootstrap_snapshot().is_none());
    }

    #[test]
    fn test_providers_stale_version_rejected() {
        let mut cache = AvailableResourceCache::new();
        let providers = |version: u64| {
            prost::Message::encode_to_vec(&DataEnvelope {
                version: 1,
                payload: Some(
                    acowork_core::mqtt_proto::data_envelope::Payload::AvailableProviders(
                        AvailableProviders {
                            version,
                            #[allow(deprecated)]
                            default_compact_model: None,
                            default_compact_models: vec![],
                            providers: vec![],
                        },
                    ),
                ),
            })
        };
        cache.update_from_mqtt("acowork/global/providers", &providers(7));
        assert_eq!(cache.providers.as_ref().unwrap().version, 7);
        // Version went backwards → stale re-delivery, keep version 7.
        cache.update_from_mqtt("acowork/global/providers", &providers(5));
        assert_eq!(cache.providers.as_ref().unwrap().version, 7);
        // Identical version (re-delivery) → idempotent accept.
        cache.update_from_mqtt("acowork/global/providers", &providers(7));
        assert_eq!(cache.providers.as_ref().unwrap().version, 7);
        // Newer version → accepted.
        cache.update_from_mqtt("acowork/global/providers", &providers(8));
        assert_eq!(cache.providers.as_ref().unwrap().version, 8);
    }

    #[test]
    fn test_users_empty_active_user_newer_version_accepted() {
        // An empty active_user with a NEWER version is a legitimate state
        // (user deleted / not created yet) and must not be rejected.
        let mut cache = AvailableResourceCache::new();
        cache.update_from_mqtt(
            "acowork/global/user_profile",
            &prost::Message::encode_to_vec(&DataEnvelope {
                version: 1,
                payload: Some(
                    acowork_core::mqtt_proto::data_envelope::Payload::AvailableUsers(
                        AvailableUsers {
                            version: 2,
                            active_user: Some(acowork_core::mqtt_proto::UserProfileRef {
                                user_id: "u-1".into(),
                                display_name: "Test".into(),
                                language: "en-US".into(),
                                timezone: "UTC".into(),
                                city: None,
                                country: None,
                                occupation: None,
                                communication_style: None,
                                custom_json: "{}".into(),
                            }),
                        },
                    ),
                ),
            }),
        );
        cache.update_from_mqtt(
            "acowork/global/user_profile",
            &prost::Message::encode_to_vec(&DataEnvelope {
                version: 1,
                payload: Some(
                    acowork_core::mqtt_proto::data_envelope::Payload::AvailableUsers(
                        AvailableUsers {
                            version: 3,
                            active_user: None,
                        },
                    ),
                ),
            }),
        );
        assert!(cache.user_profile.is_some());
        assert_eq!(cache.user_profile.as_ref().unwrap().version, 3);
        assert!(cache.active_user_profile().is_none());
    }
}
