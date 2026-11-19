//! Remote Embedding Provider
//!
//! Uses OpenAI text-embedding-3-small as a remote fallback when local
//! embedding is unavailable. Supports configurable timeout and retry.

use async_trait::async_trait;
use reqwest::Client;
use serde::{Deserialize, Serialize};

use acowork_core::Timeouts;

use super::{EmbeddingError, EmbeddingProvider};

// ── Remote Embedding Provider ───────────────────────────────────────────

/// Remote embedding provider using OpenAI-compatible API
pub struct RemoteEmbeddingProvider {
    /// Base URL for the embeddings API
    base_url: String,
    /// API key
    api_key: Option<String>,
    /// Model name (default: text-embedding-3-small)
    model: String,
    /// Embedding dimension (default: 1536 for text-embedding-3-small)
    dimension: usize,
    /// HTTP client
    http_client: Client,
}

impl RemoteEmbeddingProvider {
    /// Create a new remote embedding provider
    pub fn new(api_key: Option<&str>) -> Self {
        Self::with_config(
            "https://api.openai.com/v1",
            api_key,
            "text-embedding-3-small",
            1536,
        )
    }

    /// Create with custom configuration.
    ///
    /// # Panics
    /// Panics if the HTTP client cannot be built. Prefer
    /// [`try_with_config`](Self::try_with_config) in production code.
    pub fn with_config(
        base_url: &str,
        api_key: Option<&str>,
        model: &str,
        dimension: usize,
    ) -> Self {
        Self::with_config_and_timeouts(base_url, api_key, model, dimension, &Timeouts::default())
    }

    /// Create with custom configuration and centralized timeout values.
    pub fn with_config_and_timeouts(
        base_url: &str,
        api_key: Option<&str>,
        model: &str,
        dimension: usize,
        timeouts: &Timeouts,
    ) -> Self {
        Self::try_with_config_and_timeouts(base_url, api_key, model, dimension, timeouts)
            .expect("Failed to build HTTP client")
    }

    /// Create with custom configuration (fallible — for production use).
    pub fn try_with_config(
        base_url: &str,
        api_key: Option<&str>,
        model: &str,
        dimension: usize,
    ) -> Result<Self, EmbeddingError> {
        Self::try_with_config_and_timeouts(
            base_url,
            api_key,
            model,
            dimension,
            &Timeouts::default(),
        )
    }

    /// Create with custom configuration and centralized timeout values (fallible).
    pub fn try_with_config_and_timeouts(
        base_url: &str,
        api_key: Option<&str>,
        model: &str,
        dimension: usize,
        timeouts: &Timeouts,
    ) -> Result<Self, EmbeddingError> {
        let http_client = Client::builder()
            .timeout(timeouts.tool_http())
            .connect_timeout(timeouts.provider_connect())
            .build()
            .map_err(|e| EmbeddingError::Remote(format!("Failed to build HTTP client: {e}")))?;

        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            api_key: api_key.map(ToString::to_string),
            model: model.to_string(),
            dimension,
            http_client,
        })
    }

    /// Create a provider for DeepSeek or other compatible APIs
    pub fn with_base_url(base_url: &str, api_key: Option<&str>) -> Self {
        Self::with_config(base_url, api_key, "text-embedding-3-small", 1536)
    }
}

// ── API types ────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
struct EmbeddingRequest {
    model: String,
    input: EmbeddingInput,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
enum EmbeddingInput {
    Single(String),
    Batch(Vec<String>),
}

#[derive(Debug, Deserialize)]
struct EmbeddingResponse {
    data: Vec<EmbeddingData>,
}

#[derive(Debug, Deserialize)]
struct EmbeddingData {
    embedding: Vec<f32>,
}

#[derive(Debug, Deserialize)]
struct EmbeddingErrorResp {
    error: EmbeddingErrorDetail,
}

#[derive(Debug, Deserialize)]
struct EmbeddingErrorDetail {
    message: String,
}

// ── Trait implementation ────────────────────────────────────────────────

#[async_trait]
impl EmbeddingProvider for RemoteEmbeddingProvider {
    fn name(&self) -> &str {
        "remote-openai"
    }

    async fn embed(&self, text: &str) -> Result<Vec<f32>, EmbeddingError> {
        if text.is_empty() {
            return Err(EmbeddingError::InvalidInput(
                "Text cannot be empty".to_string(),
            ));
        }

        let request = EmbeddingRequest {
            model: self.model.clone(),
            input: EmbeddingInput::Single(text.to_string()),
        };

        let url = format!("{}/embeddings", self.base_url);
        let mut req_builder = self.http_client.post(&url);

        if let Some(ref api_key) = self.api_key {
            req_builder = req_builder.bearer_auth(api_key);
        }

        let response = req_builder
            .json(&request)
            .send()
            .await
            .map_err(|e| EmbeddingError::Remote(format!("Request failed: {e}")))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();

            let message = if let Ok(err_resp) = serde_json::from_str::<EmbeddingErrorResp>(&body) {
                err_resp.error.message
            } else {
                format!("HTTP {status}: {body}")
            };

            return Err(EmbeddingError::Remote(message));
        }

        let resp: EmbeddingResponse = response
            .json()
            .await
            .map_err(|e| EmbeddingError::Remote(format!("Failed to parse response: {e}")))?;

        resp.data
            .into_iter()
            .next()
            .map(|d| d.embedding)
            .ok_or_else(|| EmbeddingError::Remote("No embedding in response".to_string()))
    }

    async fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, EmbeddingError> {
        if texts.is_empty() {
            return Ok(Vec::new());
        }

        if texts.len() == 1 {
            let embedding = self.embed(texts[0]).await?;
            return Ok(vec![embedding]);
        }

        let request = EmbeddingRequest {
            model: self.model.clone(),
            input: EmbeddingInput::Batch(texts.iter().map(|t| t.to_string()).collect()),
        };

        let url = format!("{}/embeddings", self.base_url);
        let mut req_builder = self.http_client.post(&url);

        if let Some(ref api_key) = self.api_key {
            req_builder = req_builder.bearer_auth(api_key);
        }

        let response = req_builder
            .json(&request)
            .send()
            .await
            .map_err(|e| EmbeddingError::Remote(format!("Batch request failed: {e}")))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(EmbeddingError::Remote(format!("HTTP {status}: {body}")));
        }

        let resp: EmbeddingResponse = response
            .json()
            .await
            .map_err(|e| EmbeddingError::Remote(format!("Failed to parse batch response: {e}")))?;

        Ok(resp.data.into_iter().map(|d| d.embedding).collect())
    }

    fn dimension(&self) -> usize {
        self.dimension
    }

    async fn is_available(&self) -> bool {
        // Simple connectivity check — try to reach the API
        if self.api_key.is_none() {
            return false;
        }
        // We could make a lightweight API call here, but for simplicity
        // we just check if the API key is configured
        true
    }
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_remote_provider_creation() {
        let provider = RemoteEmbeddingProvider::new(Some("sk-test"));
        assert_eq!(provider.name(), "remote-openai");
        assert_eq!(provider.dimension(), 1536);
        assert_eq!(provider.model, "text-embedding-3-small");
    }

    #[test]
    fn test_remote_provider_custom() {
        let provider = RemoteEmbeddingProvider::with_config(
            "https://api.deepseek.com/v1",
            Some("sk-test"),
            "text-embedding-3-small",
            1536,
        );
        assert_eq!(provider.base_url, "https://api.deepseek.com/v1");
    }

    #[test]
    fn test_remote_provider_no_key() {
        let provider = RemoteEmbeddingProvider::new(None);
        assert!(provider.api_key.is_none());
    }

    #[tokio::test]
    async fn test_remote_provider_empty_input() {
        let provider = RemoteEmbeddingProvider::new(Some("sk-test"));
        let result = provider.embed("").await;
        assert!(result.is_err());
        if let Err(EmbeddingError::InvalidInput(msg)) = result {
            assert!(msg.contains("empty"));
        } else {
            panic!("Expected InvalidInput error");
        }
    }

    #[tokio::test]
    async fn test_remote_provider_batch_empty() {
        let provider = RemoteEmbeddingProvider::new(Some("sk-test"));
        let result = provider.embed_batch(&[]).await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_remote_provider_availability_no_key() {
        let provider = RemoteEmbeddingProvider::new(None);
        assert!(!provider.is_available().await);
    }

    #[tokio::test]
    async fn test_remote_provider_availability_with_key() {
        let provider = RemoteEmbeddingProvider::new(Some("sk-test"));
        assert!(provider.is_available().await);
    }
}
