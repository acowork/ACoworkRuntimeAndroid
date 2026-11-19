//! Error types for acowork-runtime
use thiserror::Error;

use acowork_core::providers::error_patterns::{is_balance_exhausted, is_retryable};

#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Core error: {0}")]
    Core(#[from] acowork_core::AcoworkError),

    #[error("Provider error: {0}")]
    Provider(acowork_core::providers::ProviderError),

    #[error("Stream error: {0}")]
    StreamError(acowork_core::providers::StreamError),

    #[error("Tool error: {0}")]
    Tool(String),

    #[error("IPC error: {0}")]
    Ipc(String),

    #[error("Package error: {0}")]
    Package(String),

    #[error("Config error: {0}")]
    Config(String),

    #[error("Budget exceeded: {0}")]
    BudgetExceeded(String),

    #[error("Loop detected: {0}")]
    LoopDetected(String),

    #[error("Context overflow: {0}")]
    ContextOverflow(String),

    /// LLM-based context compaction (5-level plan) failed — every distill
    /// tier was exhausted or the plan could not fit. The session must NOT
    /// keep looping afterwards (context would keep growing while the UI
    /// already showed an error); the agent loop treats this as terminal
    /// (GiveUp → Idle).
    #[error("Context compaction failed: {0}")]
    CompactionFailed(String),

    /// ADR-083: compaction ended WITHOUT a summary because the user
    /// cancelled it or the end-to-end deadline expired. History is left
    /// untouched and the session returns to Idle (non-retryable, same as
    /// [`RuntimeError::CompactionFailed`]) so the user can switch model
    /// and retry. Distinct from `CompactionFailed` so callers can suppress
    /// the generic error bubble — the `CompactionCancelled` chunk event
    /// already told the frontend what happened.
    #[error("Context compaction cancelled: {0}")]
    CompactionCancelled(String),

    #[error("Unsupported model: {0}")]
    UnsupportedModel(String),

    #[error("Manifest error: {0}")]
    Manifest(#[from] acowork_core::manifest::ManifestError),

    #[error("Sign error: {0}")]
    Sign(String),

    #[error("Memory error: {0}")]
    Memory(String),

    /// LLM summary quality/format gate failure (distillation & compaction).
    ///
    /// See [`crate::episode_distill::SummaryError`] — retryable variants
    /// (`Empty`, `MissingBlock`) step down the distillation target chain,
    /// while `LowQuality` discards the output (quality-over-nothing).
    #[error("Summary error: {0}")]
    Summary(#[from] crate::episode_distill::SummaryError),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Tool timeout: {0}")]
    ToolTimeout(String),

    #[error("WASM error: {0}")]
    Wasm(String),

    #[error("WASM fuel exhausted: {0}")]
    WasmFuelExhausted(String),

    #[error("WASM memory limit exceeded: {0}")]
    WasmMemoryLimit(String),
}

pub type Result<T> = std::result::Result<T, RuntimeError>;

impl RuntimeError {
    /// Whether this error is a transient, retryable failure (network /
    /// transport / stream). Auth, 429 (quota), and other permanent errors
    /// return `false` — they should surface to the user instead of retrying.
    ///
    /// This is the single source of truth for the agent iteration retry
    /// logic (`loop_.rs`). It deliberately includes `Core(Provider(..))`
    /// errors — which is what `reliable.rs` surfaces after its own bounded
    /// retry budget is exhausted on connection/network failures — so the
    /// iteration loop retries those too. Previously only
    /// `RuntimeError::StreamError` was retried, which let network errors
    /// fall straight through to Idle (the root cause of the 2026-09-02
    /// 03:33 session death after a machine-sleep wake).
    pub fn is_retryable(&self) -> bool {
        match self {
            RuntimeError::StreamError(se) => se.retryable,
            RuntimeError::Core(e) => is_retryable(e) && !is_balance_exhausted(e),
            _ => false,
        }
    }

    /// Extract user-friendly error info as `(user_message, detail, error_type)`.
    ///
    /// - `user_message`: short, readable summary for default frontend display
    /// - `detail`: raw error string for the expandable "Details" section
    /// - `error_type`: stringified `ProviderErrorType` for conditional rendering
    pub fn error_info(&self) -> (String, String, String) {
        match self {
            RuntimeError::Provider(pe) => {
                let user_message = if pe.user_message.is_empty() {
                    pe.message.clone()
                } else {
                    pe.user_message.clone()
                };
                (
                    user_message,
                    pe.message.clone(),
                    format!("{:?}", pe.error_type),
                )
            }
            RuntimeError::Core(acowork_core::AcoworkError::Provider(pe)) => {
                let user_message = if pe.user_message.is_empty() {
                    pe.message.clone()
                } else {
                    pe.user_message.clone()
                };
                (
                    user_message,
                    pe.message.clone(),
                    format!("{:?}", pe.error_type),
                )
            }
            RuntimeError::StreamError(se) => {
                let user_message = acowork_core::ProviderError::compute_user_message(
                    &se.error_type,
                    None,
                );
                (
                    user_message,
                    se.message.clone(),
                    format!("{:?}", se.error_type),
                )
            }
            RuntimeError::ContextOverflow(msg) => {
                (
                    "Context too long. History compressed.".to_string(),
                    msg.clone(),
                    "ContextOverflow".to_string(),
                )
            }
            RuntimeError::CompactionFailed(msg) => {
                (
                    "Context compaction failed. The conversation cannot continue safely — start a new conversation, switch to a larger-context model, or retry compression manually."
                        .to_string(),
                    msg.clone(),
                    "ContextOverflow".to_string(),
                )
            }
            RuntimeError::CompactionCancelled(msg) => {
                (
                    "Context compaction was cancelled.".to_string(),
                    msg.clone(),
                    "CompactionCancelled".to_string(),
                )
            }
            RuntimeError::BudgetExceeded(msg) => {
                (
                    "Budget exceeded.".to_string(),
                    msg.clone(),
                    "BudgetExceeded".to_string(),
                )
            }
            RuntimeError::LoopDetected(msg) => {
                (
                    "The agent appears to be stuck in a loop. Try continuing, or send a new message to guide it.".to_string(),
                    msg.clone(),
                    "LoopDetected".to_string(),
                )
            }
            RuntimeError::UnsupportedModel(msg) => {
                (
                    "Model does not support agent mode (context window too small).".to_string(),
                    msg.clone(),
                    "UnsupportedModel".to_string(),
                )
            }
            _ => {
                let detail = self.to_string();
                (
                    "Unexpected error. See details.".to_string(),
                    detail,
                    "Unknown".to_string(),
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use acowork_core::providers::ProviderError;
    use acowork_core::providers::StreamError;

    #[test]
    fn is_retryable_network_core_error() {
        // What `reliable.rs` surfaces after its bounded retry budget is
        // exhausted on a connection failure: Core(Provider(network)).
        let err = RuntimeError::Core(acowork_core::AcoworkError::Provider(
            ProviderError::network("error sending request for url".to_string()),
        ));
        assert!(
            err.is_retryable(),
            "network errors must be retried at iteration level"
        );
    }

    #[test]
    fn is_retryable_stream() {
        let retryable = StreamError {
            message: "stream was reset".into(),
            error_type: acowork_core::providers::traits::ProviderErrorType::StreamDecodeError,
            retryable: true,
            status_code: None,
        };
        assert!(RuntimeError::StreamError(retryable).is_retryable());

        let non_retryable = StreamError {
            message: "bad request".into(),
            error_type: acowork_core::providers::traits::ProviderErrorType::ClientError,
            retryable: false,
            status_code: None,
        };
        assert!(!RuntimeError::StreamError(non_retryable).is_retryable());
    }

    #[test]
    fn is_retryable_io() {
        let err = RuntimeError::Core(acowork_core::AcoworkError::Io(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "tcp timeout",
        )));
        assert!(err.is_retryable());
    }

    #[test]
    fn is_retryable_non_retryable_provider_errors() {
        // 401 / auth — never retry.
        let auth = RuntimeError::Core(acowork_core::AcoworkError::Provider(
            ProviderError::from_status_code(401, "unauthorized".into()),
        ));
        assert!(!auth.is_retryable());

        // 429 stays retryable (transient rate limit / budget — original policy).
        let rate = RuntimeError::Core(acowork_core::AcoworkError::Provider(
            ProviderError::from_status_code(429, "too many requests".into()),
        ));
        assert!(rate.is_retryable());

        // Balance exhausted must never be retried even if marked retryable.
        let balance = RuntimeError::Core(acowork_core::AcoworkError::Provider(
            ProviderError::unknown("insufficient_quota".into()),
        ));
        assert!(!balance.is_retryable());
    }

    #[test]
    fn is_retryable_unknown_errors() {
        assert!(!RuntimeError::Tool("tool failed".into()).is_retryable());
        assert!(!RuntimeError::LoopDetected("loop".into()).is_retryable());
    }
}
