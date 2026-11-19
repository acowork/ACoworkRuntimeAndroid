//! Agent token accounting use case.
//!
//! ADR-028 / ADR-040 / ADR-066: wraps AgentCore's atomic token counters
//! behind a trait so the HTTP server (list_sessions) and loop context
//! (push_token) share the same accumulation path without depending on
//! AgentCore's internal field layout.
//!
//! ADR-066: the tuple shapes grow from 2-tuples to 4-tuples — input,
//! output, cache_read, cache_write — mirroring the Provider-reported
//! fields in `UsageInfo` and the persisted `SessionTokens`.

use acowork_core::providers::traits::UsageInfo;

/// Token accounting methods — synchronous, lock-free via atomics.
///
/// Not `#[async_trait]` because all operations are in-process atomic
/// reads/writes with no I/O.
pub trait AgentTokenService: Send + Sync {
    /// Accumulate usage from a completed LLM call into the agent-level
    /// counters (atomic add).
    fn accumulate_llm_usage(&self, usage: &UsageInfo);

    /// Merge a freshly-scanned-on-disk total into the in-process counter
    /// using `max(counter, scanned)`. Idempotent — repeated calls with
    /// the same value are no-ops.
    ///
    /// ADR-066: the scanned tuple carries four fields
    /// `(input, output, cache_read, cache_write)`.  Pass `None` for any
    /// dimension whose scan yielded no data (e.g. legacy meta files
    /// without cache fields, or empty agent directories).
    fn merge_token_totals(&self, scanned: (Option<u64>, Option<u64>, Option<u64>, Option<u64>));

    /// Snapshot the current agent-scoped cumulative token totals.
    ///
    /// Returns `(input_tokens, output_tokens, cache_read_tokens,
    /// cache_write_tokens)`.  All four are always present (zero is a
    /// valid baseline before the first LLM call).
    fn agent_token_totals(&self) -> (u64, u64, u64, u64);

    /// Snapshot a single session's token totals if known.
    fn session_token_totals(&self, session_id: &str) -> Option<(u64, u64)>;
}
