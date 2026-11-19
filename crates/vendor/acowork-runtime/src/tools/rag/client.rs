//! HttpRagProvider - HTTP client for the ACowork RAG standard query protocol.
//!
//! Formerly known as `RagClient` (renamed in ADR-051 C3).
//! `RagClient` is kept as a type alias for backward compatibility.
//!
//! HttpRagProvider is a pure HTTP client. It does NOT implement any RAG engine
//! logic. It sends standard query requests to enterprise RAG endpoints and
//! parses the responses. Timeout and error handling ensure RAG unavailability
//! never blocks Agent execution.
//!
//! Implements `acowork_core::rag::RagProvider` trait (ADR-051 §5.1).

use std::time::Duration;

use acowork_core::RagToolConfig;
use acowork_core::rag::RagProvider;
use async_trait::async_trait;

use super::types::{AnnotatedRagResult, RagQueryRequest, RagQueryResponse, RagResultItem};

/// Authentication credential for RAG service
#[derive(Debug, Clone)]
pub enum RagAuthCredential {
    /// No authentication required
    None,
    /// Bearer token (Authorization: Bearer <token>)
    Bearer(String),
    /// API key (X-API-Key: <key>)
    ApiKey(String),
}

impl RagAuthCredential {
    /// Parse auth_ref and auth_type from manifest into a credential.
    ///
    /// `auth_ref` format: "vault:<provider_name>" (e.g., "vault:rag_enterprise_key")
    /// The actual key value is obtained from Vault via the gRPC handshake
    /// (AgentHello carries the API key distribution).
    ///
    /// # Arguments
    /// * `auth_ref` - Vault reference string from manifest
    /// * `auth_type` - "bearer" or "api_key"
    /// * `key_value` - The actual key/token value obtained from Vault
    pub fn from_vault_ref(
        auth_ref: Option<&str>,
        auth_type: &str,
        key_value: Option<&str>,
    ) -> Self {
        match (auth_ref, key_value) {
            (Some(_), Some(value)) => match auth_type {
                "api_key" => RagAuthCredential::ApiKey(value.to_string()),
                _ => RagAuthCredential::Bearer(value.to_string()),
            },
            // No auth_ref means no authentication needed
            // or key_value is None means key not found in Vault
            _ => RagAuthCredential::None,
        }
    }

    /// Extract the Vault provider name from a vault reference string.
    ///
    /// Returns `Some(provider_name)` if auth_ref starts with "vault:",
    /// otherwise `None`.
    pub fn vault_provider_name(auth_ref: &str) -> Option<&str> {
        auth_ref.strip_prefix("vault:")
    }
}

/// Configuration for HttpRagProvider, derived from manifest `RagToolConfig`.
#[derive(Debug, Clone)]
pub struct RagClientConfig {
    /// RAG service endpoint URL
    pub endpoint: String,
    /// Collection / index name
    pub collection: Option<String>,
    /// Authentication credential
    pub auth: RagAuthCredential,
    /// Default max results per query
    pub default_max_results: u32,
    /// Default score threshold
    pub default_score_threshold: f32,
    /// Query timeout
    pub timeout: Duration,
    /// Tool name (for source annotation)
    pub tool_name: String,
}

impl RagClientConfig {
    /// Build RagClientConfig from manifest RagToolConfig + resolved auth.
    pub fn from_manifest(rag: &RagToolConfig, tool_name: String, auth: RagAuthCredential) -> Self {
        Self {
            endpoint: rag.endpoint.clone(),
            collection: rag.collection.clone(),
            auth,
            default_max_results: rag.max_results,
            default_score_threshold: rag.score_threshold,
            timeout: Duration::from_secs(rag.timeout_secs),
            tool_name,
        }
    }
}

/// HTTP-based RAG provider - sends standard protocol requests to enterprise RAG services.
///
/// Implements `acowork_core::rag::RagProvider` trait.
/// Renamed from `RagClient` in ADR-051 C3. `RagClient` remains as a type alias.
pub struct HttpRagProvider {
    config: RagClientConfig,
    http: reqwest::Client,
}

/// Backward-compat type alias (ADR-051 C3).
pub type RagClient = HttpRagProvider;

impl HttpRagProvider {
    /// Create a new HttpRagProvider with the given configuration.
    pub fn new(config: RagClientConfig) -> Self {
        let http = reqwest::Client::builder()
            .timeout(config.timeout)
            .build()
            .expect("Failed to build reqwest client for RAG");
        Self { config, http }
    }

    /// Query the RAG service with the given query text.
    ///
    /// Uses manifest defaults for top_k and score_threshold.
    /// On timeout or error, returns an empty vector (graceful degradation).
    pub async fn query(&self, query_text: &str) -> Vec<AnnotatedRagResult> {
        self.query_with_params(query_text, None, None, None).await
    }

    /// Query the RAG service with custom parameters.
    ///
    /// This is used by the `rag_query` tool for explicit LLM-triggered queries.
    pub async fn query_with_params(
        &self,
        query_text: &str,
        top_k: Option<u32>,
        score_threshold: Option<f32>,
        filters: Option<serde_json::Value>,
    ) -> Vec<AnnotatedRagResult> {
        let top_k = top_k.unwrap_or(self.config.default_max_results);
        let score_threshold = score_threshold.or(Some(self.config.default_score_threshold));

        let mut request = RagQueryRequest::new(query_text.to_string(), top_k);
        request.collection = self.config.collection.clone();
        request.score_threshold = score_threshold;
        request.filters = filters;

        let response = self.send_request(&request).await;
        match response {
            Ok(resp) => self.annotate_results(resp.results),
            Err(e) => {
                tracing::warn!(
                    "RAG query failed (endpoint={}): {} - degrading to empty results",
                    self.config.endpoint,
                    e
                );
                vec![]
            }
        }
    }

    /// Send the HTTP request to the RAG endpoint
    async fn send_request(
        &self,
        request: &RagQueryRequest,
    ) -> Result<RagQueryResponse, RagClientError> {
        let mut req_builder = self.http.post(&self.config.endpoint).json(request);

        // Apply authentication
        match &self.config.auth {
            RagAuthCredential::None => {}
            RagAuthCredential::Bearer(token) => {
                req_builder = req_builder.bearer_auth(token);
            }
            RagAuthCredential::ApiKey(key) => {
                req_builder = req_builder.header("X-API-Key", key.as_str());
            }
        }

        let resp = req_builder.send().await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(RagClientError::HttpError {
                status: status.as_u16(),
                body,
            });
        }

        let rag_response: RagQueryResponse = resp.json().await?;
        Ok(rag_response)
    }

    /// Annotate RAG results with source labels for LLM context injection
    fn annotate_results(&self, items: Vec<RagResultItem>) -> Vec<AnnotatedRagResult> {
        let source_label = format!("[RAG:{}]", self.config.tool_name);
        items
            .into_iter()
            .map(|item| AnnotatedRagResult {
                item,
                source_label: source_label.clone(),
                tool_name: self.config.tool_name.clone(),
            })
            .collect()
    }

    /// Get the configured endpoint URL (for permission validation)
    pub fn endpoint(&self) -> &str {
        &self.config.endpoint
    }

    /// Get the tool name
    pub fn tool_name(&self) -> &str {
        &self.config.tool_name
    }
}

/// Implement RagProvider trait (ADR-051 §5.1).
///
/// HttpRagProvider is the default production implementation of RagProvider.
/// The trait methods delegate to the existing query methods.
#[async_trait]
impl RagProvider for HttpRagProvider {
    async fn query(&self, query_text: &str) -> Vec<AnnotatedRagResult> {
        // Delegate to the inherent method (same name, same behavior).
        HttpRagProvider::query(self, query_text).await
    }

    async fn query_with_params(
        &self,
        query_text: &str,
        top_k: Option<u32>,
        score_threshold: Option<f32>,
        filters: Option<serde_json::Value>,
    ) -> Vec<AnnotatedRagResult> {
        HttpRagProvider::query_with_params(self, query_text, top_k, score_threshold, filters).await
    }

    fn name(&self) -> &str {
        &self.config.tool_name
    }
}

/// RAG client errors
#[derive(Debug, thiserror::Error)]
pub enum RagClientError {
    #[error("HTTP request failed: {0}")]
    RequestFailed(#[from] reqwest::Error),
    #[error("RAG service returned HTTP {status}: {body}")]
    HttpError { status: u16, body: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> RagClientConfig {
        RagClientConfig {
            endpoint: "https://rag.example.com/v1/query".to_string(),
            collection: Some("test_docs".to_string()),
            auth: RagAuthCredential::None,
            default_max_results: 5,
            default_score_threshold: 0.7,
            timeout: Duration::from_secs(10),
            tool_name: "enterprise_knowledge".to_string(),
        }
    }

    #[test]
    fn test_rag_client_new() {
        let client = HttpRagProvider::new(test_config());
        assert_eq!(client.endpoint(), "https://rag.example.com/v1/query");
        assert_eq!(client.tool_name(), "enterprise_knowledge");
    }

    #[test]
    fn test_rag_client_alias_compat() {
        // Verify RagClient alias works
        let client: RagClient = RagClient::new(test_config());
        assert_eq!(client.tool_name(), "enterprise_knowledge");
    }

    #[test]
    fn test_rag_provider_name() {
        let client = HttpRagProvider::new(test_config());
        assert_eq!(RagProvider::name(&client), "enterprise_knowledge");
    }

    #[test]
    fn test_annotate_results() {
        let client = HttpRagProvider::new(test_config());
        let items = vec![
            RagResultItem {
                content: "test content 1".to_string(),
                source_url: Some("https://example.com/doc1".to_string()),
                chunk_id: Some("chunk-1".to_string()),
                score: 0.9,
            },
            RagResultItem {
                content: "test content 2".to_string(),
                source_url: None,
                chunk_id: None,
                score: 0.7,
            },
        ];
        let annotated = client.annotate_results(items);
        assert_eq!(annotated.len(), 2);
        assert_eq!(annotated[0].source_label, "[RAG:enterprise_knowledge]");
        assert_eq!(annotated[0].item.score, 0.9);
    }

    #[test]
    fn test_rag_client_config_from_manifest() {
        let rag = RagToolConfig {
            endpoint: "https://rag.corp.example.com/v1/query".to_string(),
            collection: Some("product_docs".to_string()),
            auth_ref: Some("vault:rag_enterprise_key".to_string()),
            auth_type: "bearer".to_string(),
            max_results: 5,
            score_threshold: 0.7,
            timeout_secs: 10,
        };
        let config = RagClientConfig::from_manifest(
            &rag,
            "enterprise_knowledge".to_string(),
            RagAuthCredential::Bearer("test-token".to_string()),
        );
        assert_eq!(config.endpoint, "https://rag.corp.example.com/v1/query");
        assert_eq!(config.collection.as_deref(), Some("product_docs"));
        assert_eq!(config.default_max_results, 5);
        assert_eq!(config.timeout, Duration::from_secs(10));
    }

    #[tokio::test]
    async fn test_rag_client_query_timeout_degrades() {
        // Use a non-routable endpoint to trigger timeout/connection failure
        let mut config = test_config();
        config.endpoint = "https://10.255.255.1/v1/query".to_string();
        config.timeout = Duration::from_millis(100);
        let client = HttpRagProvider::new(config);
        let results = client.query("test query").await;
        // Should gracefully degrade to empty results
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn test_rag_provider_trait_query_degrades() {
        // Verify trait method also degrades gracefully
        let mut config = test_config();
        config.endpoint = "https://10.255.255.1/v1/query".to_string();
        config.timeout = Duration::from_millis(100);
        let provider = HttpRagProvider::new(config);
        let results = RagProvider::query(&provider, "test query").await;
        assert!(results.is_empty());
    }

    #[test]
    fn test_rag_auth_credential_variants() {
        let none = RagAuthCredential::None;
        let bearer = RagAuthCredential::Bearer("token123".to_string());
        let api_key = RagAuthCredential::ApiKey("key456".to_string());
        // Just verify they construct
        assert!(matches!(none, RagAuthCredential::None));
        assert!(matches!(bearer, RagAuthCredential::Bearer(_)));
        assert!(matches!(api_key, RagAuthCredential::ApiKey(_)));
    }

    #[test]
    fn test_rag_auth_from_vault_ref() {
        // Bearer from vault ref
        let cred = RagAuthCredential::from_vault_ref(
            Some("vault:rag_enterprise_key"),
            "bearer",
            Some("my-secret-token"),
        );
        assert!(matches!(cred, RagAuthCredential::Bearer(ref s) if s == "my-secret-token"));

        // API key from vault ref
        let cred = RagAuthCredential::from_vault_ref(
            Some("vault:rag_enterprise_key"),
            "api_key",
            Some("my-api-key"),
        );
        assert!(matches!(cred, RagAuthCredential::ApiKey(ref s) if s == "my-api-key"));

        // No auth_ref -> None
        let cred = RagAuthCredential::from_vault_ref(None, "bearer", None);
        assert!(matches!(cred, RagAuthCredential::None));

        // auth_ref but no key_value -> None (key not found in Vault)
        let cred =
            RagAuthCredential::from_vault_ref(Some("vault:rag_enterprise_key"), "bearer", None);
        assert!(matches!(cred, RagAuthCredential::None));
    }

    #[test]
    fn test_vault_provider_name() {
        assert_eq!(
            RagAuthCredential::vault_provider_name("vault:rag_enterprise_key"),
            Some("rag_enterprise_key")
        );
        assert_eq!(
            RagAuthCredential::vault_provider_name("not-a-vault-ref"),
            None
        );
        assert_eq!(RagAuthCredential::vault_provider_name("vault:"), Some(""));
    }
}
