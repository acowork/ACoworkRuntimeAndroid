//! Retry + fallback chain for LLM providers
//!
//! Adapted from zeroclaw/src/providers/reliable.rs
//! ACowork deviation: uses acowork-core Provider trait instead of ZeroClaw's.
//! SPDX-License-Identifier: MIT OR Apache-2.0

use std::sync::{Arc, Mutex};
use std::time::Duration;

use acowork_core::providers::error_patterns::{is_balance_exhausted, is_retryable};
use acowork_core::providers::traits::{
    ChatMessage, ChatRequest, ChatResponse, Provider, ProviderError, StreamEvent,
};
use async_trait::async_trait;
use futures_core::Stream;
use rand::RngExt;
use tokio::sync::Notify;
use tokio::time::sleep;

use crate::agent::loop_::{ChunkEvent, SessionChunkEvent};
use crate::agent::session_state::{RetryPauseInfo, SessionStatus};

/// Threshold (ms) above which the retry wait triggers UX (countdown + skip button).
const UX_WAIT_THRESHOLD_MS: u64 = 10_000;

/// Shared state for 429 retry UX.
///
/// Written by [`ReliableProvider`] when entering a retry wait whose duration
/// exceeds [`UX_WAIT_THRESHOLD_MS`]. Read by external observers (SessionTask,
/// Gateway) to decide whether to trigger `skip_notify`.
#[derive(Debug, Clone)]
pub struct RetryWaitState {
    /// Wait duration in milliseconds
    pub wait_ms: u64,
    /// Current retry attempt (1-based)
    pub attempt: u32,
    /// Maximum retry attempts
    pub max_attempts: u32,
    /// Name of the provider being retried
    pub provider_name: String,
}

/// External handle for controlling a retry wait.
///
/// Held by [`AgentCore`] so that [`SessionTask`] can wake up a paused
/// retry when the user presses "Skip Wait" (via the existing
/// `continue_execution` API).
pub struct RetryWaitHandle {
    /// Current retry wait state, shared with [`ReliableProvider`]
    pub state: Arc<Mutex<Option<RetryWaitState>>>,
    /// Notify to wake the retry loop early (user skip)
    pub skip_notify: Arc<Notify>,
}

impl Default for RetryWaitHandle {
    fn default() -> Self {
        Self::new()
    }
}

impl RetryWaitHandle {
    /// Create a new retry-wait handle pair.
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(None)),
            skip_notify: Arc::new(Notify::new()),
        }
    }
}

/// Retry configuration
#[derive(Debug, Clone)]
pub struct RetryConfig {
    /// Maximum number of retry attempts
    pub max_attempts: u32,
    /// Backoff strategy
    pub backoff: BackoffStrategy,
    /// Maximum wait time in milliseconds
    pub max_wait_ms: u64,
    /// Whether server-suggested Retry-After should override computed backoff.
    pub honor_retry_after: bool,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            backoff: BackoffStrategy::Exponential { base_ms: 1000 },
            max_wait_ms: 10000,
            honor_retry_after: true,
        }
    }
}

impl From<&acowork_core::RetryConfig> for RetryConfig {
    fn from(config: &acowork_core::RetryConfig) -> Self {
        Self {
            max_attempts: config.max_attempts,
            backoff: BackoffStrategy::Exponential {
                base_ms: config.backoff_base_ms,
            },
            max_wait_ms: config.backoff_cap_ms,
            honor_retry_after: config.honor_retry_after,
        }
    }
}

/// Backoff strategy for retries
#[derive(Debug, Clone)]
pub enum BackoffStrategy {
    /// Fixed delay between retries
    Fixed { delay_ms: u64 },
    /// Exponential backoff with base delay
    Exponential { base_ms: u64 },
}

impl BackoffStrategy {
    /// Calculate wait duration for a given attempt
    pub fn wait_duration(&self, attempt: u32) -> Duration {
        match self {
            BackoffStrategy::Fixed { delay_ms } => Duration::from_millis(*delay_ms),
            BackoffStrategy::Exponential { base_ms } => {
                let delay = base_ms * 2u64.saturating_pow(attempt);
                Duration::from_millis(delay)
            }
        }
    }
}

/// Reliable provider that wraps another provider with retry and fallback logic
pub struct ReliableProvider {
    /// Primary provider
    primary: Arc<dyn Provider>,
    /// Fallback providers in priority order
    fallbacks: Vec<Arc<dyn Provider>>,
    /// Retry configuration
    retry_config: RetryConfig,
    /// Retry wait control handle (429 UX). Shared with AgentCore.
    retry_wait_handle: Option<RetryWaitHandle>,
    /// Session status for emitting retry-pause state transitions.
    session_status: Option<Arc<std::sync::RwLock<SessionStatus>>>,
    /// Chunk sender for emitting SessionStateChanged events.
    chunk_sender: Option<tokio::sync::mpsc::Sender<SessionChunkEvent>>,
    /// Session ID for tagging chunk events.
    session_id: Option<String>,
}

impl ReliableProvider {
    /// Create a new reliable provider with retry logic
    pub fn new(primary: Arc<dyn Provider>, retry_config: RetryConfig) -> Self {
        Self {
            primary,
            fallbacks: Vec::new(),
            retry_config,
            retry_wait_handle: None,
            session_status: None,
            chunk_sender: None,
            session_id: None,
        }
    }

    /// Add a fallback provider
    pub fn with_fallback(mut self, provider: Arc<dyn Provider>) -> Self {
        self.fallbacks.push(provider);
        self
    }

    /// Enable 429 retry UX: pause status emission + user-skippable wait.
    ///
    /// Callers (e.g. `AgentCore` during session init) must call this to
    /// wire up the retry-wait handle, session status slot, and chunk
    /// sender so that long retry waits (> 10 s) surface to the frontend.
    pub fn with_retry_ux(
        mut self,
        handle: RetryWaitHandle,
        session_status: Arc<std::sync::RwLock<SessionStatus>>,
        chunk_sender: tokio::sync::mpsc::Sender<SessionChunkEvent>,
        session_id: String,
    ) -> Self {
        self.retry_wait_handle = Some(handle);
        self.session_status = Some(session_status);
        self.chunk_sender = Some(chunk_sender);
        self.session_id = Some(session_id);
        self
    }

    /// Emit [`SessionStatus::Paused`] with retry_info so the frontend
    /// shows a countdown timer and skip button.
    fn emit_retry_pause(&self, wait_ms: u64, attempt: u32, provider_name: &str) {
        if let Some(ref status_lock) = self.session_status
            && let Ok(mut guard) = status_lock.write()
        {
            *guard = SessionStatus::Paused {
                iteration: None,
                max_iterations: None,
                retry_info: Some(RetryPauseInfo {
                    wait_ms,
                    attempt,
                    max_attempts: self.retry_config.max_attempts,
                    provider: provider_name.to_string(),
                }),
                reason: None,
                message: None,
            };
        }
        if let Some(ref tx) = self.chunk_sender
            && let Some(ref sid) = self.session_id
        {
            let status = self
                .session_status
                .as_ref()
                .and_then(|l| l.read().ok())
                .map(|g| g.clone())
                .unwrap_or(SessionStatus::Idle);
            let status = serde_json::to_string(&status).unwrap_or_else(|_| r#""idle""#.to_string());
            // ADR-043: emit a minimal SessionState with just status.
            // Other fields (message_count, tokens) are 0 - this is a transient
            // status that will be corrected on the next emit_session_state().
            let _ = tx.try_send(SessionChunkEvent {
                session_id: sid.clone(),
                event: ChunkEvent::SessionStateChanged {
                    state: acowork_core::mqtt_proto::SessionState {
                        session_id: sid.clone(),
                        status,
                        ..Default::default()
                    },
                },
            });
        }
    }

    /// Restore [`SessionStatus::LlmAwaitingFirstChunk`] after retry wait (timeout or skip).
    ///
    /// ADR-049: `Streaming` is split into 3 sub-states. After a retry wait we
    /// are about to issue a new LLM HTTP request, so we re-enter the TTFT
    /// wait phase (`LlmAwaitingFirstChunk`), not active streaming.
    fn emit_streaming_resume(&self) {
        if let Some(ref status_lock) = self.session_status
            && let Ok(mut guard) = status_lock.write()
        {
            *guard = SessionStatus::LlmAwaitingFirstChunk;
        }
        if let Some(ref tx) = self.chunk_sender
            && let Some(ref sid) = self.session_id
        {
            let status = self
                .session_status
                .as_ref()
                .and_then(|l| l.read().ok())
                .map(|g| g.clone())
                .unwrap_or(SessionStatus::Idle);
            let status = serde_json::to_string(&status).unwrap_or_else(|_| r#""idle""#.to_string());
            let _ = tx.try_send(SessionChunkEvent {
                session_id: sid.clone(),
                event: ChunkEvent::SessionStateChanged {
                    state: acowork_core::mqtt_proto::SessionState {
                        session_id: sid.clone(),
                        status,
                        ..Default::default()
                    },
                },
            });
        }
    }

    /// Sleep for a retry wait duration, with optional UX support.
    ///
    /// When `wait_ms >= UX_WAIT_THRESHOLD_MS` AND UX is wired up
    /// (`retry_wait_handle` / `session_status` / `chunk_sender` all set),
    /// this method:
    /// 1. Emits [`SessionStatus::Paused`] with `retry_info` → frontend countdown
    /// 2. Uses `tokio::select!` so a `skip_notify` from the outside wakes
    ///    the loop immediately
    /// 3. Restores [`SessionStatus::LlmAwaitingFirstChunk`] on wake
    ///    (ADR-049: the post-wake HTTP request is in the TTFT wait phase)
    ///
    /// When UX is not wired up (CLI mode, or short waits), falls back to
    /// plain `sleep(wait).await`.
    async fn retry_sleep(&self, wait_ms: u64, attempt: u32) {
        let use_ux = wait_ms >= UX_WAIT_THRESHOLD_MS
            && self.retry_wait_handle.is_some()
            && self.session_status.is_some()
            && self.chunk_sender.is_some();

        if !use_ux {
            sleep(Duration::from_millis(wait_ms)).await;
            return;
        }

        // Emit paused status with retry info for the frontend
        let provider_name = self.primary.name().to_string();
        self.emit_retry_pause(wait_ms, attempt, &provider_name);

        // Update shared RetryWaitState so external observers can read it
        if let Some(ref handle) = self.retry_wait_handle
            && let Ok(mut guard) = handle.state.lock()
        {
            *guard = Some(RetryWaitState {
                wait_ms,
                attempt,
                max_attempts: self.retry_config.max_attempts,
                provider_name: provider_name.clone(),
            });
        }

        tracing::info!(
            wait_ms = wait_ms,
            attempt = attempt,
            "Retry wait with UX: emitting paused status, waiting with skip support"
        );

        // Wait with skip support
        if let Some(ref handle) = self.retry_wait_handle {
            tokio::select! {
                _ = sleep(Duration::from_millis(wait_ms)) => {
                    tracing::debug!("Retry wait completed normally");
                }
                _ = handle.skip_notify.notified() => {
                    tracing::info!("Retry wait skipped by user");
                }
            }
        }

        // Clear shared state
        if let Some(ref handle) = self.retry_wait_handle
            && let Ok(mut guard) = handle.state.lock()
        {
            *guard = None;
        }

        // Restore streaming status
        self.emit_streaming_resume();
    }

    /// Compute effective wait duration for a retry attempt.
    ///
    /// Prefers the server-suggested `retry_after_ms` (from HTTP Retry-After header)
    /// over the backoff strategy. Applies cap via `max_wait_ms` and adds ±25% jitter.
    fn compute_wait(&self, attempt: u32, retry_after_ms: Option<u64>) -> Duration {
        // Prefer server-suggested wait time when configured; otherwise fall back to backoff strategy.
        let base_ms = if self.retry_config.honor_retry_after {
            retry_after_ms.unwrap_or_else(|| {
                self.retry_config.backoff.wait_duration(attempt).as_millis() as u64
            })
        } else {
            self.retry_config.backoff.wait_duration(attempt).as_millis() as u64
        };

        // Cap at max_wait_ms
        let capped_ms = base_ms.min(self.retry_config.max_wait_ms);

        // Apply jitter ±25% (uniform distribution in [0.75, 1.25])
        let factor: f64 = rand::rng().random_range(0.75..=1.25);
        let jittered_ms = (capped_ms as f64 * factor) as u64;

        Duration::from_millis(jittered_ms)
    }
}

#[async_trait]
impl Provider for ReliableProvider {
    fn name(&self) -> &str {
        self.primary.name()
    }

    async fn chat(&self, request: ChatRequest) -> acowork_core::error::Result<ChatResponse> {
        // Collect all candidate providers: primary + fallbacks
        let candidates: Vec<&Arc<dyn Provider>> = std::iter::once(&self.primary)
            .chain(self.fallbacks.iter())
            .collect();

        let mut last_provider_error: Option<ProviderError> = None;

        for provider in candidates {
            for attempt in 0..self.retry_config.max_attempts {
                match provider.chat(request.clone()).await {
                    Ok(response) => return Ok(response),
                    Err(ref e) if !is_retryable(e) || is_balance_exhausted(e) => {
                        if let acowork_core::AcoworkError::Provider(pe) = e {
                            last_provider_error = Some(pe.clone());
                        }
                        tracing::warn!(
                            provider = %provider.name(),
                            error = %e,
                            "Non-retryable error, trying next provider"
                        );
                        break;
                    }
                    Err(ref e) if attempt + 1 < self.retry_config.max_attempts => {
                        let retry_after_ms = match e {
                            acowork_core::AcoworkError::Provider(pe) => pe.retry_after_ms,
                            _ => None,
                        };
                        let wait = self.compute_wait(attempt, retry_after_ms);
                        let wait_ms = wait.as_millis() as u64;
                        tracing::warn!(
                            provider = %provider.name(),
                            attempt = attempt + 1,
                            max = self.retry_config.max_attempts,
                            wait_ms = wait_ms,
                            has_retry_after = retry_after_ms.is_some(),
                            error = %e,
                            "Retrying provider"
                        );
                        self.retry_sleep(wait_ms, attempt + 1).await;
                    }
                    Err(ref e) => {
                        if let acowork_core::AcoworkError::Provider(pe) = e {
                            last_provider_error = Some(pe.clone());
                        }
                        tracing::error!(
                            provider = %provider.name(),
                            attempts = self.retry_config.max_attempts,
                            error = %e,
                            "Retries exhausted for provider"
                        );
                        break;
                    }
                }
            }
        }

        Err(acowork_core::AcoworkError::Provider(
            last_provider_error.unwrap_or_else(|| {
                ProviderError::unknown("All providers failed (primary + fallbacks)".to_string())
            }),
        ))
    }

    async fn chat_stream(
        &self,
        request: ChatRequest,
    ) -> acowork_core::error::Result<Box<dyn Stream<Item = StreamEvent> + Send>> {
        // Collect all candidate providers: primary + fallbacks
        let candidates: Vec<&Arc<dyn Provider>> = std::iter::once(&self.primary)
            .chain(self.fallbacks.iter())
            .collect();

        let mut last_provider_error: Option<ProviderError> = None;

        for provider in candidates {
            for attempt in 0..self.retry_config.max_attempts {
                match provider.chat_stream(request.clone()).await {
                    Ok(stream) => return Ok(stream),
                    Err(ref e) if !is_retryable(e) || is_balance_exhausted(e) => {
                        if let acowork_core::AcoworkError::Provider(pe) = e {
                            last_provider_error = Some(pe.clone());
                        }
                        tracing::warn!(
                            provider = %provider.name(),
                            error = %e,
                            "Non-retryable stream error, trying next provider"
                        );
                        break; // Move to next provider
                    }
                    Err(ref e) if attempt + 1 < self.retry_config.max_attempts => {
                        let retry_after_ms = match e {
                            acowork_core::AcoworkError::Provider(pe) => pe.retry_after_ms,
                            _ => None,
                        };
                        let wait = self.compute_wait(attempt, retry_after_ms);
                        let wait_ms = wait.as_millis() as u64;
                        tracing::warn!(
                            provider = %provider.name(),
                            attempt = attempt + 1,
                            max = self.retry_config.max_attempts,
                            wait_ms = wait_ms,
                            has_retry_after = retry_after_ms.is_some(),
                            error = %e,
                            "Retrying stream establishment"
                        );
                        self.retry_sleep(wait_ms, attempt + 1).await;
                    }
                    Err(ref e) => {
                        if let acowork_core::AcoworkError::Provider(pe) = e {
                            last_provider_error = Some(pe.clone());
                        }
                        tracing::error!(
                            provider = %provider.name(),
                            attempts = self.retry_config.max_attempts,
                            error = %e,
                            "Stream retries exhausted for provider"
                        );
                        break; // Try next provider
                    }
                }
            }
        }

        Err(acowork_core::AcoworkError::Provider(
            last_provider_error.unwrap_or_else(|| {
                ProviderError::network("All providers failed for streaming".to_string())
            }),
        ))
    }

    async fn chat_token_count(&self, messages: &[ChatMessage]) -> acowork_core::error::Result<u64> {
        self.primary.chat_token_count(messages).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_backoff_fixed() {
        let backoff = BackoffStrategy::Fixed { delay_ms: 1000 };
        assert_eq!(backoff.wait_duration(0), Duration::from_millis(1000));
        assert_eq!(backoff.wait_duration(2), Duration::from_millis(1000));
    }

    #[test]
    fn test_backoff_exponential() {
        let backoff = BackoffStrategy::Exponential { base_ms: 1000 };
        assert_eq!(backoff.wait_duration(0), Duration::from_millis(1000));
        assert_eq!(backoff.wait_duration(1), Duration::from_millis(2000));
        assert_eq!(backoff.wait_duration(2), Duration::from_millis(4000));
    }

    #[test]
    fn test_retry_config_from_core_config() {
        let core = acowork_core::RetryConfig {
            max_attempts: 5,
            backoff_base_ms: 250,
            backoff_cap_ms: 2_000,
            honor_retry_after: false,
        };
        let runtime = RetryConfig::from(&core);
        assert_eq!(runtime.max_attempts, 5);
        assert_eq!(runtime.max_wait_ms, 2_000);
        assert!(!runtime.honor_retry_after);
        assert_eq!(runtime.backoff.wait_duration(0), Duration::from_millis(250));
    }

    #[test]
    fn test_is_retryable() {
        let err =
            acowork_core::AcoworkError::Provider(ProviderError::network("timeout".to_string()));
        assert!(is_retryable(&err));

        let err = acowork_core::AcoworkError::Provider(ProviderError::from_status_code(
            401,
            "401 unauthorized".to_string(),
        ));
        assert!(!is_retryable(&err));

        let err = acowork_core::AcoworkError::RateLimited("too many requests".to_string());
        assert!(is_retryable(&err));
    }

    #[test]
    fn test_is_balance_exhausted_generic() {
        let err = acowork_core::AcoworkError::Provider(ProviderError::unknown(
            "insufficient_quota".to_string(),
        ));
        assert!(is_balance_exhausted(&err));

        let err = acowork_core::AcoworkError::Provider(ProviderError::unknown(
            "out of credits".to_string(),
        ));
        assert!(is_balance_exhausted(&err));
    }

    #[test]
    fn test_is_balance_exhausted_minimax_codes() {
        let err = acowork_core::AcoworkError::Provider(ProviderError::unknown(
            "Error code 1113: balance exhausted".to_string(),
        ));
        assert!(is_balance_exhausted(&err));

        let err = acowork_core::AcoworkError::Provider(ProviderError::unknown(
            "Code 1311: insufficient balance".to_string(),
        ));
        assert!(is_balance_exhausted(&err));
    }

    #[test]
    fn test_is_balance_exhausted_non_matching() {
        let err = acowork_core::AcoworkError::Provider(ProviderError::from_status_code(
            500,
            "500 internal error".to_string(),
        ));
        assert!(!is_balance_exhausted(&err));
    }

    #[test]
    fn test_is_minimax_balance_code() {
        assert!(
            acowork_core::providers::error_patterns::is_minimax_balance_code("error code 1113")
        );
        assert!(acowork_core::providers::error_patterns::is_minimax_balance_code("code 1311"));
        assert!(!acowork_core::providers::error_patterns::is_minimax_balance_code("generic error"));
    }
}
