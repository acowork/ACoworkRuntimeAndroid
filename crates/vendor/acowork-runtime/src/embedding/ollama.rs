//! Ollama Embedding Provider
//!
//! Uses Ollama's `/api/embed` endpoint for local embedding generation.
//! Default model: nomic-embed-text (768 dimensions).

use async_trait::async_trait;
use reqwest::Client;
use serde::{Deserialize, Serialize};

use acowork_core::Timeouts;

use super::{EmbeddingError, EmbeddingProvider};

/// Ollama embedding provider using the `/api/embed` endpoint.
///
/// # API Format
///
/// ```text
/// POST /api/embed
/// {"model": "nomic-embed-text", "input": ["text1", "text2"]}
///
/// Response: {"embeddings": [[0.1, 0.2, ...], ...]}
/// ```
pub struct OllamaEmbeddingProvider {
    /// Ollama server base URL (default: http://localhost:11434).
    base_url: String,
    /// Embedding model name (default: nomic-embed-text).
    model: String,
    /// Embedding vector dimension.
    dimension: usize,
    /// Shared HTTP client.
    http_client: Client,
}

impl OllamaEmbeddingProvider {
    /// Create a new Ollama embedding provider with defaults.
    ///
    /// Uses `http://localhost:11434` and `nomic-embed-text` (768d).
    pub fn new() -> Self {
        Self::with_config("http://localhost:11434", "nomic-embed-text", 768)
    }

    /// Create an Ollama embedding provider with a custom base URL.
    pub fn with_base_url(base_url: &str) -> Self {
        Self::with_config(base_url, "nomic-embed-text", 768)
    }

    /// Create with full configuration.
    pub fn with_config(base_url: &str, model: &str, dimension: usize) -> Self {
        Self::with_config_and_timeouts(base_url, model, dimension, &Timeouts::default())
    }

    /// Create with full configuration and centralized timeout values.
    pub fn with_config_and_timeouts(
        base_url: &str,
        model: &str,
        dimension: usize,
        timeouts: &Timeouts,
    ) -> Self {
        Self::try_with_config_and_timeouts(base_url, model, dimension, timeouts)
            .expect("Failed to build HTTP client for Ollama embedding")
    }

    /// Create a new Ollama embedding provider with defaults (fallible).
    ///
    /// Uses `http://localhost:11434` and `nomic-embed-text` (768d).
    pub fn try_new() -> Result<Self, EmbeddingError> {
        Self::try_with_config("http://localhost:11434", "nomic-embed-text", 768)
    }

    /// Create with full configuration (fallible — for production use).
    pub fn try_with_config(
        base_url: &str,
        model: &str,
        dimension: usize,
    ) -> Result<Self, EmbeddingError> {
        Self::try_with_config_and_timeouts(base_url, model, dimension, &Timeouts::default())
    }

    /// Create with full configuration and centralized timeout values (fallible).
    pub fn try_with_config_and_timeouts(
        base_url: &str,
        model: &str,
        dimension: usize,
        timeouts: &Timeouts,
    ) -> Result<Self, EmbeddingError> {
        let http_client = Client::builder()
            .timeout(timeouts.tool_http())
            .connect_timeout(timeouts.provider_connect())
            .build()
            .map_err(|e| EmbeddingError::Local(format!("Failed to build HTTP client: {e}")))?;

        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            model: model.to_string(),
            dimension,
            http_client,
        })
    }
}

impl Default for OllamaEmbeddingProvider {
    fn default() -> Self {
        Self::new()
    }
}

// ── Ollama Embedding API types ───────────────────────────────────────────

#[derive(Debug, Serialize)]
struct OllamaEmbeddingRequest {
    model: String,
    input: OllamaEmbeddingInput,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
enum OllamaEmbeddingInput {
    Single(String),
    Batch(Vec<String>),
}

#[derive(Debug, Deserialize)]
struct OllamaEmbeddingResponse {
    embeddings: Vec<Vec<f32>>,
}

// ── Trait implementation ────────────────────────────────────────────────

#[async_trait]
impl EmbeddingProvider for OllamaEmbeddingProvider {
    fn name(&self) -> &str {
        "ollama-embed"
    }

    async fn embed(&self, text: &str) -> Result<Vec<f32>, EmbeddingError> {
        if text.is_empty() {
            return Err(EmbeddingError::InvalidInput(
                "Text cannot be empty".to_string(),
            ));
        }

        let request = OllamaEmbeddingRequest {
            model: self.model.clone(),
            input: OllamaEmbeddingInput::Single(text.to_string()),
        };

        let url = format!("{}/api/embed", self.base_url);

        let response = self
            .http_client
            .post(&url)
            .json(&request)
            .send()
            .await
            .map_err(|e| EmbeddingError::Local(format!("Ollama embed request failed: {e}")))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(EmbeddingError::Local(format!(
                "Ollama embed HTTP {status}: {body}"
            )));
        }

        let resp: OllamaEmbeddingResponse = response.json().await.map_err(|e| {
            EmbeddingError::Local(format!("Failed to parse Ollama embed response: {e}"))
        })?;

        resp.embeddings
            .into_iter()
            .next()
            .ok_or_else(|| EmbeddingError::Local("No embedding in Ollama response".to_string()))
    }

    async fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, EmbeddingError> {
        if texts.is_empty() {
            return Ok(Vec::new());
        }

        if texts.len() == 1 {
            let embedding = self.embed(texts[0]).await?;
            return Ok(vec![embedding]);
        }

        let request = OllamaEmbeddingRequest {
            model: self.model.clone(),
            input: OllamaEmbeddingInput::Batch(texts.iter().map(|t| t.to_string()).collect()),
        };

        let url = format!("{}/api/embed", self.base_url);

        let response = self
            .http_client
            .post(&url)
            .json(&request)
            .send()
            .await
            .map_err(|e| EmbeddingError::Local(format!("Ollama batch embed failed: {e}")))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(EmbeddingError::Local(format!(
                "Ollama batch embed HTTP {status}: {body}"
            )));
        }

        let resp: OllamaEmbeddingResponse = response.json().await.map_err(|e| {
            EmbeddingError::Local(format!("Failed to parse Ollama batch embed response: {e}"))
        })?;

        Ok(resp.embeddings)
    }

    fn dimension(&self) -> usize {
        self.dimension
    }

    async fn is_available(&self) -> bool {
        // Lightweight health check — ping the Ollama server
        let url = format!("{}/api/tags", self.base_url);
        match self.http_client.get(&url).send().await {
            Ok(resp) => resp.status().is_success(),
            Err(_) => false,
        }
    }
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ollama_embedding_provider_creation() {
        let provider = OllamaEmbeddingProvider::new();
        assert_eq!(provider.name(), "ollama-embed");
        assert_eq!(provider.dimension(), 768);
        assert_eq!(provider.model, "nomic-embed-text");
        assert_eq!(provider.base_url, "http://localhost:11434");
    }

    #[test]
    fn test_ollama_embedding_provider_custom() {
        let provider = OllamaEmbeddingProvider::with_config(
            "http://192.168.1.100:11434",
            "mxbai-embed-large",
            1024,
        );
        assert_eq!(provider.base_url, "http://192.168.1.100:11434");
        assert_eq!(provider.model, "mxbai-embed-large");
        assert_eq!(provider.dimension(), 1024);
    }

    #[tokio::test]
    async fn test_ollama_embedding_provider_empty_input() {
        let provider = OllamaEmbeddingProvider::new();
        let result = provider.embed("").await;
        assert!(result.is_err());
        if let Err(EmbeddingError::InvalidInput(msg)) = result {
            assert!(msg.contains("empty"));
        } else {
            panic!("Expected InvalidInput error");
        }
    }

    #[tokio::test]
    async fn test_ollama_embedding_provider_batch_empty() {
        let provider = OllamaEmbeddingProvider::new();
        let result = provider.embed_batch(&[]).await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }
}
