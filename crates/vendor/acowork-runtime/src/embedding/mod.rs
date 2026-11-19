//! Embedding generation module
//!
//! Provides embedding generation with:
//! - Remote: OpenAI-compatible API (text-embedding-3-small, etc.)
//! - Ollama: local embedding via Ollama's `/api/embed`
//! - ONNX: local embedding via acowork-embed (OpenAI-compatible API)
//! - Extensible via [`EmbeddingProvider`] trait for custom/local backends
//!
//! Fallback chain: ONNX local (5s) → Ollama (2s) → Remote API (5s).
//! Each provider has its own base timeout and consecutive failure tracking.
//! After exceeding the failure threshold, a provider is temporarily skipped.
//!
//! # Concurrency-aware timeouts
//!
//! Providers with a serialized backend (the ONNX session is guarded by a
//! single mutex) make concurrent attempts queue behind each other, so a fixed
//! wall-clock timeout fires on queued attempts before they ever get to run.
//! Each attempt's effective timeout is therefore scaled by the number of
//! attempts currently in flight on that entry (`base × inflight`, capped at
//! [`MAX_EFFECTIVE_TIMEOUT_MS`]). See `ProviderEntry::scaled_timeout_ms`.

pub mod ollama;
pub mod remote;

// ADR-051 P2: EmbeddingProvider trait + EmbeddingError moved to acowork-core.
pub use acowork_core::{EmbeddingError, EmbeddingProvider};

/// The live embedding provider, behind one shared mutable cell.
///
/// `AgentCore` owns the cell and its `Clone` shares it (`Arc::clone`), so the
/// copy a session runs and the `Arc<AgentCore>` snapshot published for the
/// conversation indexer and the HTTP layer read the same cell. Setting
/// `AgentCore::embedding_provider` cannot do that: it mutates one copy, and
/// every other copy keeps whatever the model was when it was cloned. That is
/// how a model switch left the indexer embedding with the previous model
/// against a store that had already been re-embedded - its dimension guard
/// deferred the sweep forever, silently, and the memory panel reported a
/// dimension the process no longer used.
///
/// One cell, one writer (`update_embedding_provider` / `clear_embedding_provider`),
/// many readers: there is no second copy to invalidate and nothing to re-publish.
pub type SharedEmbedProvider =
    Arc<std::sync::RwLock<Option<Arc<dyn EmbeddingProvider>>>>;

use async_trait::async_trait;
use std::sync::Arc;

/// Configuration for the embedding fallback chain
#[derive(Debug, Clone)]
pub struct EmbeddingConfig {
    /// Base timeout in milliseconds for each embedding request (default: 2000).
    /// This is the per-attempt budget for a single in-flight request; the
    /// effective timeout is scaled by the in-flight concurrency (see
    /// [`ProviderEntry::scaled_timeout_ms`]).
    pub timeout_ms: u64,
    /// Number of consecutive failures before switching to fallback (default: 5)
    pub failure_threshold: u32,
    /// Whether to prefer local embeddings when available (default: true)
    pub prefer_local: bool,
    /// Maximum batch size for batch embedding (default: 32)
    pub max_batch_size: usize,
}

impl Default for EmbeddingConfig {
    fn default() -> Self {
        Self {
            timeout_ms: 2000,
            failure_threshold: 5,
            prefer_local: true,
            max_batch_size: 32,
        }
    }
}

/// Maximum effective timeout budget for a single embedding attempt.
///
/// Concurrent attempts scale their budget by the in-flight count (`base ×
/// inflight`), but the budget is capped so a genuinely stuck backend fails
/// fast instead of blocking the caller for minutes under heavy concurrency.
const MAX_EFFECTIVE_TIMEOUT_MS: u64 = 60_000;

// ── Provider entry (for the providers chain) ────────────────────────────

/// Entry in the provider fallback chain.
///
/// Each provider has its own base timeout and consecutive failure counter.
/// After exceeding `failure_threshold` consecutive failures, the provider
/// is temporarily skipped until a subsequent success resets the counter.
struct ProviderEntry {
    provider: Box<dyn EmbeddingProvider>,
    /// Per-provider base timeout in milliseconds (single in-flight request).
    timeout_ms: u64,
    /// Consecutive failure counter (atomic for thread safety).
    consecutive_failures: std::sync::atomic::AtomicU32,
    /// Number of embedding attempts currently in flight through this entry,
    /// across all concurrent callers sharing this chain. Used to scale the
    /// per-attempt timeout so it covers the queue-wait on serialized
    /// backends (e.g. the single ONNX session mutex).
    inflight: std::sync::atomic::AtomicU32,
}

impl ProviderEntry {
    fn new(provider: Box<dyn EmbeddingProvider>, timeout_ms: u64) -> Self {
        Self {
            provider,
            timeout_ms,
            consecutive_failures: std::sync::atomic::AtomicU32::new(0),
            inflight: std::sync::atomic::AtomicU32::new(0),
        }
    }

    fn is_degraded(&self, threshold: u32) -> bool {
        self.consecutive_failures
            .load(std::sync::atomic::Ordering::Relaxed)
            >= threshold
    }

    fn record_failure(&self, threshold: u32) {
        let failures = self
            .consecutive_failures
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            + 1;
        if failures == threshold {
            tracing::warn!(
                provider = self.provider.name(),
                failures,
                threshold,
                "Embedding provider exceeded failure threshold, temporarily skipping"
            );
        }
    }

    fn record_success(&self) {
        self.consecutive_failures
            .store(0, std::sync::atomic::Ordering::Relaxed);
    }

    /// Effective timeout for one attempt, scaled by the current in-flight
    /// concurrency on this entry.
    ///
    /// A serialized backend (ONNX mutex) serves concurrent attempts one at a
    /// time; the k-th queued attempt actually finishes after ~k × T where T is
    /// the single-attempt service time. A fixed budget would fire on queued
    /// attempts before they get to run, so the budget is `base × inflight`.
    /// `multiplier` additionally scales per-unit work (e.g. batch chunk size).
    /// Always capped at [`MAX_EFFECTIVE_TIMEOUT_MS`].
    fn scaled_timeout_ms(&self, multiplier: u64) -> u64 {
        let inflight = self
            .inflight
            .load(std::sync::atomic::Ordering::Relaxed)
            .max(1) as u64;
        (self.timeout_ms * multiplier * inflight).min(MAX_EFFECTIVE_TIMEOUT_MS)
    }
}

/// RAII guard holding one in-flight slot on a [`ProviderEntry`].
///
/// The slot must be acquired **before** the wall-clock timeout is computed so
/// the budget covers the queue wait behind already-running attempts. The slot
/// is released on drop — including on timeout, error, and early return.
struct InflightGuard<'a> {
    entry: &'a ProviderEntry,
}

impl<'a> InflightGuard<'a> {
    fn acquire(entry: &'a ProviderEntry) -> Self {
        entry.inflight.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Self { entry }
    }
}

impl Drop for InflightGuard<'_> {
    fn drop(&mut self) {
        self.entry
            .inflight
            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    }
}

// ── FallbackEmbeddingProvider ───────────────────────────────────────────

/// Embedding provider with automatic fallback through a chain of providers.
///
/// # Provider Chain
///
/// The providers are tried in order. For each provider:
/// 1. If it has exceeded `failure_threshold` consecutive failures, skip it.
/// 2. Otherwise, attempt embedding with its per-provider timeout.
/// 3. On success, reset its failure counter and return the result.
/// 4. On failure/timeout, increment its failure counter and try the next provider.
///
/// If all providers fail, return the last error.
///
/// # Backward Compatibility
///
/// The `new(primary, fallback, config)` constructor still works, creating a
/// two-entry providers chain. The new `with_providers()` constructor allows
/// building longer chains (e.g., ONNX → Ollama → Remote).
pub struct FallbackEmbeddingProvider {
    /// Ordered provider chain. Try each in sequence until one succeeds.
    providers: Vec<ProviderEntry>,
    /// Configuration
    config: EmbeddingConfig,
    /// Locked embedding dimension. When set, only providers whose `dimension()`
    /// matches this value are used. This prevents dimension mismatch when the
    /// Grafeo HNSW index has been created with a specific dimension.
    locked_dim: Option<usize>,
}

impl FallbackEmbeddingProvider {
    /// Create a new fallback embedding provider with the classic two-layer pattern.
    ///
    /// This is backward-compatible with the previous API.
    /// Internally converts to a providers chain with two entries.
    pub fn new(
        primary: Option<Box<dyn EmbeddingProvider>>,
        fallback: Box<dyn EmbeddingProvider>,
        config: EmbeddingConfig,
    ) -> Self {
        let mut providers = Vec::new();

        if let Some(primary) = primary {
            providers.push(ProviderEntry::new(primary, config.timeout_ms));
        }
        providers.push(ProviderEntry::new(fallback, 5000)); // Remote: 5s timeout

        Self {
            providers,
            config,
            locked_dim: None,
        }
    }

    /// Create with a full providers chain.
    ///
    /// Each `(provider, timeout_ms)` tuple defines one entry in the chain.
    /// Providers are tried in the order given.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let fallback = FallbackEmbeddingProvider::with_providers(
    ///     vec![
    ///         (Box::new(onnx_provider), 5000),     // ONNX local: 5s base timeout
    ///         (Box::new(ollama_provider), 2000),    // Ollama: 2s base timeout
    ///         (Box::new(remote_provider), 5000),   // Remote API: 5s base timeout
    ///     ],
    ///     EmbeddingConfig::default(),
    /// );
    /// ```
    ///
    /// The base timeouts are scaled by the in-flight concurrency on each
    /// entry (see [`ProviderEntry::scaled_timeout_ms`]) so queued attempts
    /// on serialized backends are not killed before they get to run.
    pub fn with_providers(
        providers: Vec<(Box<dyn EmbeddingProvider>, u64)>,
        config: EmbeddingConfig,
    ) -> Self {
        let providers = providers
            .into_iter()
            .map(|(provider, timeout_ms)| ProviderEntry::new(provider, timeout_ms))
            .collect();
        Self {
            providers,
            config,
            locked_dim: None,
        }
    }

    /// Create with only a remote fallback (no local provider).
    pub fn remote_only(fallback: Box<dyn EmbeddingProvider>) -> Self {
        Self::new(None, fallback, EmbeddingConfig::default())
    }

    /// Lock the provider chain to a specific embedding dimension.
    ///
    /// When set, `embed()` and `embed_batch()` will skip any provider whose
    /// `dimension()` does not match `dim`. This is critical when a Grafeo
    /// HNSW index has been created with a fixed dimension: using a provider
    /// with a different dimension would corrupt the index.
    ///
    /// Returns `self` for chaining.
    pub fn with_locked_dimension(mut self, dim: usize) -> Self {
        self.locked_dim = Some(dim);
        self
    }

    /// Update the locked dimension at runtime (e.g., after migration).
    pub fn set_locked_dimension(&mut self, dim: usize) {
        self.locked_dim = Some(dim);
    }

    /// Returns `true` if the provider's dimension matches the locked dimension
    /// (or if no dimension is locked).
    fn dimension_matches(&self, entry: &ProviderEntry) -> bool {
        match self.locked_dim {
            Some(dim) => entry.provider.dimension() == dim,
            None => true,
        }
    }
}

#[async_trait]
impl EmbeddingProvider for FallbackEmbeddingProvider {
    fn name(&self) -> &str {
        // Return the name of the first non-degraded provider
        for entry in &self.providers {
            if !entry.is_degraded(self.config.failure_threshold) {
                return entry.provider.name();
            }
        }
        // All degraded — return the last provider's name
        self.providers
            .last()
            .map(|e| e.provider.name())
            .unwrap_or("fallback(empty)")
    }

    async fn embed(&self, text: &str) -> Result<Vec<f32>, EmbeddingError> {
        let mut last_error =
            EmbeddingError::Unavailable("All embedding providers failed".to_string());

        for entry in &self.providers {
            // Skip degraded providers
            if entry.is_degraded(self.config.failure_threshold) {
                continue;
            }
            // Skip providers with mismatched dimension
            if !self.dimension_matches(entry) {
                tracing::debug!(
                    provider = entry.provider.name(),
                    provider_dim = entry.provider.dimension(),
                    locked_dim = self.locked_dim,
                    "Skipping provider: dimension mismatch"
                );
                continue;
            }

            // Hold one in-flight slot for the duration of this attempt so the
            // timeout budget covers the queue wait behind concurrent attempts
            // on serialized backends (ONNX session mutex). Released on drop.
            let _inflight = InflightGuard::acquire(entry);
            let effective_timeout_ms = entry.scaled_timeout_ms(1);

            match tokio::time::timeout(
                std::time::Duration::from_millis(effective_timeout_ms),
                entry.provider.embed(text),
            )
            .await
            {
                Ok(Ok(embedding)) => {
                    entry.record_success();
                    return Ok(embedding);
                }
                Ok(Err(e)) => {
                    tracing::warn!(
                        provider = entry.provider.name(),
                        error = %e,
                        "Embedding provider failed"
                    );
                    entry.record_failure(self.config.failure_threshold);
                    last_error = e;
                }
                Err(_) => {
                    tracing::warn!(
                        provider = entry.provider.name(),
                        timeout_ms = effective_timeout_ms,
                        "Embedding provider timed out"
                    );
                    entry.record_failure(self.config.failure_threshold);
                    last_error = EmbeddingError::Timeout(effective_timeout_ms);
                }
            }
        }

        tracing::error!(error = %last_error, "All embedding providers failed");
        Err(last_error)
    }

    async fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, EmbeddingError> {
        if texts.is_empty() {
            return Ok(Vec::new());
        }

        let mut all_embeddings = Vec::with_capacity(texts.len());

        for chunk in texts.chunks(self.config.max_batch_size) {
            let mut chunk_ok = false;
            let mut last_err =
                EmbeddingError::Unavailable("All embedding providers failed".to_string());

            for entry in &self.providers {
                // Skip degraded providers
                if entry.is_degraded(self.config.failure_threshold) {
                    continue;
                }
                // Skip providers with mismatched dimension
                if !self.dimension_matches(entry) {
                    continue;
                }

                // Hold one in-flight slot for this chunk attempt so the budget
                // covers queue wait on serialized backends; scale additionally
                // by chunk size (per-unit work).
                let _inflight = InflightGuard::acquire(entry);
                let timeout = entry.scaled_timeout_ms(chunk.len().max(1) as u64);

                match tokio::time::timeout(
                    std::time::Duration::from_millis(timeout),
                    entry.provider.embed_batch(chunk),
                )
                .await
                {
                    Ok(Ok(embeddings)) => {
                        entry.record_success();
                        all_embeddings.extend(embeddings);
                        chunk_ok = true;
                        break; // This chunk succeeded, move to next chunk
                    }
                    Ok(Err(e)) => {
                        tracing::warn!(
                            provider = entry.provider.name(),
                            error = %e,
                            "Batch embedding provider failed"
                        );
                        entry.record_failure(self.config.failure_threshold);
                        last_err = e;
                    }
                    Err(_) => {
                        tracing::warn!(
                            provider = entry.provider.name(),
                            "Batch embedding provider timed out"
                        );
                        entry.record_failure(self.config.failure_threshold);
                        last_err = EmbeddingError::Timeout(timeout);
                    }
                }
            }

            if !chunk_ok {
                tracing::error!(error = %last_err, "All embedding providers failed for batch chunk");
                return Err(last_err);
            }
        }

        // Validate we got the right number of embeddings
        if all_embeddings.len() != texts.len() {
            return Err(EmbeddingError::Unavailable(format!(
                "Expected {} embeddings, got {}",
                texts.len(),
                all_embeddings.len()
            )));
        }

        Ok(all_embeddings)
    }

    fn dimension(&self) -> usize {
        // When a dimension is locked, return it directly.
        if let Some(dim) = self.locked_dim {
            return dim;
        }
        // Return the dimension of the first non-degraded provider.
        // (Grafeo index was initialised with this value.)
        // When all providers are degraded, return the last provider's dimension.
        for entry in &self.providers {
            if !entry.is_degraded(self.config.failure_threshold) {
                return entry.provider.dimension();
            }
        }
        self.providers
            .last()
            .map(|e| e.provider.dimension())
            .unwrap_or(0)
    }

    async fn is_available(&self) -> bool {
        for entry in &self.providers {
            if !entry.is_degraded(self.config.failure_threshold)
                && entry.provider.is_available().await
            {
                return true;
            }
        }
        false
    }
}

// ── Arc delegate wrapper ────────────────────────────────────────────────

/// Wraps an `Arc<dyn EmbeddingProvider>` into a `Box<dyn EmbeddingProvider>`.
///
/// This is needed when we want to use an existing shared provider as a
/// fallback entry in a new `FallbackEmbeddingProvider` chain. The `new()`
/// constructor requires `Box<dyn EmbeddingProvider>`, but `AgentCore`
/// stores providers as `Arc<dyn EmbeddingProvider>`.
pub struct ArcDelegateEmbeddingProvider {
    inner: Arc<dyn EmbeddingProvider>,
}

impl ArcDelegateEmbeddingProvider {
    /// Create a new delegate from an Arc.
    pub fn from_arc(arc: Arc<dyn EmbeddingProvider>) -> Self {
        Self { inner: arc }
    }
}

#[async_trait]
impl EmbeddingProvider for ArcDelegateEmbeddingProvider {
    fn name(&self) -> &str {
        self.inner.name()
    }

    async fn embed(&self, text: &str) -> Result<Vec<f32>, EmbeddingError> {
        self.inner.embed(text).await
    }

    async fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, EmbeddingError> {
        self.inner.embed_batch(texts).await
    }

    fn dimension(&self) -> usize {
        self.inner.dimension()
    }

    async fn is_available(&self) -> bool {
        self.inner.is_available().await
    }
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Fake provider that serializes access through a shared tokio mutex and
    /// sleeps per call — models the serialized ONNX session backend.
    #[derive(Clone)]
    struct SerializedSlowProvider {
        serializer: Arc<tokio::sync::Mutex<()>>,
        delay: std::time::Duration,
        dim: usize,
    }

    #[async_trait]
    impl EmbeddingProvider for SerializedSlowProvider {
        fn name(&self) -> &str {
            "fake-serialized"
        }

        async fn embed(&self, text: &str) -> Result<Vec<f32>, EmbeddingError> {
            let _guard = self.serializer.lock().await;
            tokio::time::sleep(self.delay).await;
            Ok(vec![text.len() as f32; self.dim])
        }

        async fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, EmbeddingError> {
            let _guard = self.serializer.lock().await;
            tokio::time::sleep(self.delay.mul_f32(texts.len() as f32)).await;
            Ok(texts
                .iter()
                .map(|t| vec![t.len() as f32; self.dim])
                .collect())
        }

        fn dimension(&self) -> usize {
            self.dim
        }

        async fn is_available(&self) -> bool {
            true
        }
    }

    /// Fake provider that never returns (used to exercise the timeout path).
    #[derive(Clone)]
    struct HangingProvider;

    #[async_trait]
    impl EmbeddingProvider for HangingProvider {
        fn name(&self) -> &str {
            "fake-hanging"
        }

        async fn embed(&self, _text: &str) -> Result<Vec<f32>, EmbeddingError> {
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            Ok(Vec::new())
        }

        async fn embed_batch(&self, _texts: &[&str]) -> Result<Vec<Vec<f32>>, EmbeddingError> {
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            Ok(Vec::new())
        }

        fn dimension(&self) -> usize {
            8
        }

        async fn is_available(&self) -> bool {
            true
        }
    }

    /// Regression test for the concurrent-timeout bug: three concurrent
    /// `embed` calls against a serialized backend must all succeed.
    ///
    /// Single-attempt service time is 100ms; base timeout is 150ms. Without
    /// in-flight scaling the second and third calls (finishing at ~200ms and
    /// ~300ms) would be killed by the fixed 150ms budget. With scaling the
    /// budgets are 150/300/450ms and all three complete.
    ///
    /// Determinism: `tokio::join!` polls its futures in argument order, and
    /// `fetch_add` happens synchronously before the first `.await`, so the
    /// in-flight rank matches the serializer lock queue order.
    #[tokio::test]
    async fn concurrent_embed_scales_timeout_by_inflight() {
        let provider = SerializedSlowProvider {
            serializer: Arc::new(tokio::sync::Mutex::new(())),
            delay: std::time::Duration::from_millis(100),
            dim: 8,
        };

        let fallback = FallbackEmbeddingProvider::with_providers(
            vec![(Box::new(provider), 150)],
            EmbeddingConfig {
                failure_threshold: 5,
                ..Default::default()
            },
        );

        let (a, b, c) = tokio::join!(
            fallback.embed("aaaa"),
            fallback.embed("bbbb"),
            fallback.embed("cccc"),
        );

        for (idx, res) in [a, b, c].into_iter().enumerate() {
            let emb = res.unwrap_or_else(|e| panic!("call {} failed: {e}", idx + 1));
            assert_eq!(emb.len(), 8);
            assert!(emb.iter().all(|v| v.is_finite()));
        }
    }

    /// Concurrent `embed_batch` calls also scale by in-flight concurrency
    /// (plus chunk size), so queued batch attempts must not be killed.
    #[tokio::test]
    async fn concurrent_embed_batch_scales_timeout_by_inflight() {
        let provider = SerializedSlowProvider {
            serializer: Arc::new(tokio::sync::Mutex::new(())),
            delay: std::time::Duration::from_millis(100),
            dim: 8,
        };

        let fallback = FallbackEmbeddingProvider::with_providers(
            vec![(Box::new(provider), 150)],
            EmbeddingConfig {
                failure_threshold: 5,
                ..Default::default()
            },
        );

        let texts1 = ["aaaa", "bbbb"];
        let texts2 = ["cccc", "dddd"];
        let (r1, r2) = tokio::join!(
            fallback.embed_batch(&texts1),
            fallback.embed_batch(&texts2),
        );

        let e1 = r1.expect("batch 1 must succeed");
        let e2 = r2.expect("batch 2 must succeed");
        assert_eq!(e1.len(), 2);
        assert_eq!(e2.len(), 2);
        for emb in e1.iter().chain(e2.iter()) {
            assert_eq!(emb.len(), 8);
        }
    }

    /// The timeout path itself must still work: a genuinely stuck backend is
    /// killed at the scaled budget and the failure is recorded.
    #[tokio::test]
    async fn hanging_provider_still_times_out() {
        let provider = Box::new(HangingProvider);

        let fallback = FallbackEmbeddingProvider::with_providers(
            vec![(provider, 100)],
            EmbeddingConfig {
                failure_threshold: 5,
                ..Default::default()
            },
        );

        let start = std::time::Instant::now();
        let res = fallback.embed("x").await;
        let elapsed = start.elapsed();

        assert!(res.is_err(), "hanging provider must time out");
        assert!(
            elapsed < std::time::Duration::from_secs(5),
            "timeout must fire promptly, took {elapsed:?}"
        );
    }

    /// `scaled_timeout_ms` unit checks: linear in in-flight count, chunk
    /// multiplier applied, and the cap at [`MAX_EFFECTIVE_TIMEOUT_MS`] holds.
    #[test]
    fn scaled_timeout_ms_is_linear_and_capped() {
        let provider = Box::new(HangingProvider);
        let entry = ProviderEntry::new(provider, 5_000);

        // Single in-flight attempt: base timeout.
        assert_eq!(entry.scaled_timeout_ms(1), 5_000);
        // Chunk multiplier scales per-unit work.
        assert_eq!(entry.scaled_timeout_ms(4), 20_000);

        // Three concurrent attempts: budget covers the queue wait.
        entry.inflight.fetch_add(3, std::sync::atomic::Ordering::Relaxed);
        assert_eq!(entry.scaled_timeout_ms(1), 15_000);
        assert_eq!(entry.scaled_timeout_ms(2), 30_000);

        // Heavy concurrency is capped, not unbounded.
        entry.inflight.fetch_add(100_000, std::sync::atomic::Ordering::Relaxed);
        assert_eq!(entry.scaled_timeout_ms(1), MAX_EFFECTIVE_TIMEOUT_MS);
        assert_eq!(entry.scaled_timeout_ms(32), MAX_EFFECTIVE_TIMEOUT_MS);
    }

    /// The RAII in-flight guard must be released on success, error, and
    /// timeout so the counter never leaks across attempts.
    #[tokio::test]
    async fn inflight_guard_released_on_all_outcomes() {
        let provider = SerializedSlowProvider {
            serializer: Arc::new(tokio::sync::Mutex::new(())),
            delay: std::time::Duration::from_millis(20),
            dim: 8,
        };

        // Success path: inflight returns to zero after completion.
        let ok_fallback = FallbackEmbeddingProvider::with_providers(
            vec![(Box::new(provider), 5_000)],
            EmbeddingConfig {
                failure_threshold: 5,
                ..Default::default()
            },
        );
        let _ = ok_fallback.embed("ok").await.unwrap();
        assert_eq!(
            ok_fallback.providers[0]
                .inflight
                .load(std::sync::atomic::Ordering::Relaxed),
            0,
            "inflight must be released after success"
        );

        // Timeout path (hanging provider only): guard released after timeout.
        let timeout_fallback = FallbackEmbeddingProvider::with_providers(
            vec![(Box::new(HangingProvider), 100)],
            EmbeddingConfig {
                failure_threshold: 5,
                ..Default::default()
            },
        );
        assert!(timeout_fallback.embed("fail").await.is_err());
        assert_eq!(
            timeout_fallback.providers[0]
                .inflight
                .load(std::sync::atomic::Ordering::Relaxed),
            0,
            "inflight must be released after timeout"
        );
    }

    /// Failure-threshold default protects background consolidation work from
    /// transient spikes: a single timeout must not degrade the provider.
    #[test]
    fn single_failure_does_not_degrade_provider() {
        let provider = Box::new(HangingProvider);
        let entry = ProviderEntry::new(provider, 100);
        let threshold = EmbeddingConfig::default().failure_threshold;

        assert_eq!(threshold, 5, "default failure_threshold must be 5");
        entry.record_failure(threshold);
        assert!(!entry.is_degraded(threshold), "1 failure < threshold 5");
        entry.record_failure(threshold);
        entry.record_failure(threshold);
        entry.record_failure(threshold);
        assert!(!entry.is_degraded(threshold));
        entry.record_failure(threshold);
        assert!(entry.is_degraded(threshold), "5 consecutive failures degrade");
    }

    /// Default config uses the new sane base timeout and failure threshold.
    #[test]
    fn default_config_uses_sane_timeouts() {
        let cfg = EmbeddingConfig::default();
        assert_eq!(cfg.timeout_ms, 2000, "base timeout default must be 2000ms");
        assert_eq!(cfg.failure_threshold, 5, "failure threshold default must be 5");
    }

    /// `new()` constructor path: the primary provider uses `config.timeout_ms`
    /// as its base; a hanging primary must time out and the fallback must then
    /// serve the request.
    #[tokio::test]
    async fn new_constructor_primary_uses_config_timeout() {
        let fallback = FallbackEmbeddingProvider::new(
            Some(Box::new(HangingProvider)),
            Box::new(SerializedSlowProvider {
                serializer: Arc::new(tokio::sync::Mutex::new(())),
                delay: std::time::Duration::from_millis(10),
                dim: 8,
            }),
            EmbeddingConfig {
                timeout_ms: 100,
                failure_threshold: 5,
                ..Default::default()
            },
        );

        let start = std::time::Instant::now();
        let emb = fallback
            .embed("x")
            .await
            .expect("fallback must serve after primary timeout");
        let elapsed = start.elapsed();

        assert_eq!(emb.len(), 8);
        assert!(
            elapsed < std::time::Duration::from_secs(2),
            "primary timeout + fallback must be prompt, took {elapsed:?}"
        );
        // The primary must have actually been attempted (and timed out), not
        // skipped: it records a failure.
        assert!(
            fallback.providers[0]
                .consecutive_failures
                .load(std::sync::atomic::Ordering::Relaxed)
                >= 1,
            "hanging primary must have recorded a timeout failure"
        );
    }

    /// `embed_batch` splits inputs into chunks of `max_batch_size`; each chunk
    /// is attempted independently and the scaled timeout applies per chunk.
    #[tokio::test]
    async fn embed_batch_multi_chunk_succeeds() {
        let provider = SerializedSlowProvider {
            serializer: Arc::new(tokio::sync::Mutex::new(())),
            delay: std::time::Duration::from_millis(10),
            dim: 8,
        };
        let fallback = FallbackEmbeddingProvider::with_providers(
            vec![(Box::new(provider), 200)],
            EmbeddingConfig {
                failure_threshold: 5,
                max_batch_size: 2,
                ..Default::default()
            },
        );

        let texts = ["a", "bb", "ccc", "dddd", "eeeee"];
        let res = fallback
            .embed_batch(&texts)
            .await
            .expect("multi-chunk batch must succeed");
        assert_eq!(res.len(), 5);
        for (emb, t) in res.iter().zip(texts.iter()) {
            assert_eq!(emb.len(), 8);
            assert_eq!(emb[0], t.len() as f32, "embedding must match its input");
        }
    }

    /// A provider already degraded past `failure_threshold` is skipped without
    /// acquiring an in-flight slot — no hang, no counter leak.
    #[tokio::test]
    async fn degraded_provider_skipped_inflight_stays_zero() {
        let fallback = FallbackEmbeddingProvider::with_providers(
            vec![(Box::new(HangingProvider), 100)],
            EmbeddingConfig {
                failure_threshold: 2,
                ..Default::default()
            },
        );

        // Two hangs reach the failure threshold.
        assert!(fallback.embed("x").await.is_err());
        assert!(fallback.embed("y").await.is_err());
        assert!(fallback.providers[0].is_degraded(2));

        // Third call: skipped immediately — fast error, inflight never taken.
        let start = std::time::Instant::now();
        let res = fallback.embed("z").await;
        let elapsed = start.elapsed();
        assert!(res.is_err());
        assert!(
            elapsed < std::time::Duration::from_secs(1),
            "degraded provider must be skipped fast, took {elapsed:?}"
        );
        assert_eq!(
            fallback.providers[0]
                .inflight
                .load(std::sync::atomic::Ordering::Relaxed),
            0,
            "degraded skip must not acquire in-flight slot"
        );
    }
}
