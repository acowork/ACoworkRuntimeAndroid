//! Future helpers for combining [`CancelHandle`] with other futures.
//!
//! The primary export is [`select_on_cancel`], which races an arbitrary
//! `Result`-producing future against a cancellation handle. When the handle
//! is cancelled, the inner future is **dropped**, which performs cleanup of any
//! resources it holds (e.g. an in-flight `reqwest::send().await` is aborted).
//!
//! This is the key primitive that fixes the LLM TTFT stop bug (ADR §1.3,
//! §4.4) without requiring a Provider trait refactor.

use std::future::Future;

use super::token::CancelHandle;

/// Race a future against a cancellation handle.
///
/// The inner future's `Output` must be a `Result<T, E>`. The error type is
/// generic (`E`) so callers from different layers can use whatever error
/// they already produce — `select_on_cancel` does not care about the
/// concrete error variant. In particular, this lets us wrap a
/// `provider.chat_stream()` future that returns `acowork_core::error::Result`
/// without forcing it through a `RuntimeError` conversion.
///
/// Returns:
/// - `Ok(Some(value))` — the inner future completed first; `value` is its result.
/// - `Ok(None)` — the handle was cancelled; the inner future was dropped.
/// - `Err(e)` — the inner future failed before cancellation.
///
/// # Drop semantics (key design point — see ADR §4.4)
///
/// When the cancellation branch wins, `fut` is dropped at the `select!` await
/// point. For futures holding resources, this performs automatic cleanup:
/// dropping an in-flight `reqwest::send().await` aborts the HTTP request and
/// releases the connection. The runtime therefore returns control to the user
/// within milliseconds of `cancel()` being called, regardless of how deep the
/// inner future is in its setup (TCP connect, TLS handshake, waiting for SSE
/// headers, etc.).
///
/// # Trade-off (documented in ADR §7.1 R1)
///
/// After cancellation, the original task may continue executing in the
/// background for a short period until its I/O completes or times out at the
/// OS level. This is acceptable: the user perceives an immediate stop, and the
/// background task self-cleans. A future improvement may expose an explicit
/// abort handle to forcibly terminate the task, but that requires a Provider
/// trait refactor (out of scope per ADR §8).
///
/// # Cancel race
///
/// If `cancel()` is called *before* `select_on_cancel` is awaited, the
/// `biased;` ordering ensures the cancel branch wins on first poll — the
/// inner future is never spawned.
pub async fn select_on_cancel<T, E, F>(handle: CancelHandle, fut: F) -> Result<Option<T>, E>
where
    F: Future<Output = Result<T, E>>,
{
    tokio::select! {
        // biased: prefer the cancel branch on first poll. This makes the
        // "cancel-before-await" case resolve immediately rather than racing
        // against an already-cancellable inner future.
        biased;
        _ = handle.cancelled() => Ok(None),
        result = fut => result.map(Some),
    }
}
