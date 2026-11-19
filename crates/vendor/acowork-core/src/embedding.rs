//! Embedding provider trait and error types.
//!
//! This trait is shared across the workspace:
//! - `acowork-memory` uses it in `MemoryManager::retrieve()` for auto-embedding.
//! - `acowork-runtime` provides concrete implementations
//!   (`RemoteEmbeddingProvider`, `OllamaEmbeddingProvider`, `FallbackEmbeddingProvider`).
//!
//! Design ref: ADR-051 §4.2 (Phase 2 - moved from acowork-runtime to acowork-core)

use async_trait::async_trait;

/// Embedding generation trait.
///
/// Implementations:
/// - `FallbackEmbeddingProvider` (acowork-runtime) - chains ONNX -> Ollama -> Remote
/// - `RemoteEmbeddingProvider` (acowork-runtime) - OpenAI-compatible API
/// - `OllamaEmbeddingProvider` (acowork-runtime) - local Ollama `/api/embed`
#[async_trait]
pub trait EmbeddingProvider: Send + Sync {
    /// Provider name (e.g. "remote", "ollama", "onnx").
    fn name(&self) -> &str;

    /// Generate embedding for a single text.
    async fn embed(&self, text: &str) -> Result<Vec<f32>, EmbeddingError>;

    /// Generate embeddings for multiple texts (batch).
    async fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, EmbeddingError>;

    /// Get the dimension of embeddings produced by this provider.
    fn dimension(&self) -> usize;

    /// Check if this provider is available (e.g., model loaded, API reachable).
    async fn is_available(&self) -> bool;
}

/// Embedding generation errors.
#[derive(Debug, thiserror::Error)]
pub enum EmbeddingError {
    #[error("Local embedding error: {0}")]
    Local(String),

    #[error("Remote embedding error: {0}")]
    Remote(String),

    #[error("Timeout: embedding generation exceeded {0}ms")]
    Timeout(u64),

    #[error("Provider unavailable: {0}")]
    Unavailable(String),

    #[error("Invalid input: {0}")]
    InvalidInput(String),
}
