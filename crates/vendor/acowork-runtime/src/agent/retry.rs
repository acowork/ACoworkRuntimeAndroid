//! Retry policy for LLM calls.
//!
//! Extracted from the agent loop so the policy is a pure function that can be
//! unit-tested in isolation. The loop owns the side effects (sleeping,
//! transitioning session status, surfacing `RetryPauseInfo`); this module only
//! answers "given an error and the current retry counters, what should the
//! loop do?".
//!
//! # Policy (root cause: 2026-09-02 03:33 incident)
//!
//! The original iteration-level retry only matched `RuntimeError::StreamError`,
//! so a `Core(Provider(network))` error — exactly what `reliable.rs` surfaces
//! after its bounded provider retries are exhausted — fell straight through to
//! the terminal `Idle` branch. The agent loop died instead of recovering.
//!
//! The new policy has three retry tiers:
//!
//! 1. **Fast retry** (3 attempts, exponential 1s → 2s → 4s capped at 10s) —
//!    for transient blips. Auto-retries inline without surfacing UI.
//!
//! 2. **Long retry** (3 attempts, 5 minutes each) — for outages that take
//!    longer than a few seconds. Surfaces `RetryPauseInfo` to the frontend
//!    (`RetryWaitBanner`) so the user can skip the wait or let it expire
//!    for an automatic retry.
//!
//! 3. **Persistent recovery** (unbounded attempts, exponential 5m → 10m →
//!    20m → 30m cap) — used after the bounded budgets are exhausted but the
//!    error is still a transient network/transport failure. **Does NOT enter
//!    `Idle`** — the machine may be asleep (the 03:33 root cause) or the
//!    network temporarily down. Keeps the session in `Paused` and continues
//!    retrying until the network recovers, the user stops, or a
//!    non-retryable error surfaces.
//!
//! Non-retryable errors (`Tool`, `LoopDetected`, 401/auth, quota-exhausted,
//! etc.) skip all retry tiers and return `GiveUp`.

use crate::error::RuntimeError;

/// Maximum fast retries per LLM call.
pub const MAX_ITERATION_RETRIES: u32 = 3;

/// Maximum long retries per LLM call.
pub const MAX_LONG_RETRIES: u32 = 3;

/// Each long-retry pause duration.
pub const LONG_RETRY_WAIT_MS: u64 = 5 * 60 * 1000;

/// Backoff ceiling for the persistent recovery tier (30 minutes).
pub const MAX_PERSISTENT_BACKOFF_MS: u64 = 30 * 60 * 1000;

/// What the agent loop should do when an iteration produces a retryable error.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum RetryAction {
    /// Retry inline with a short delay (1s → 2s → 4s capped at 10s).
    FastRetry {
        backoff_ms: u64,
        attempt: u32,
        max_attempts: u32,
    },
    /// Pause with `RetryPauseInfo`; auto-retry when the timer expires (or
    /// sooner if the user clicks "Retry Now"). Each pause is 5 minutes.
    LongRetry {
        wait_ms: u64,
        attempt: u32,
        max_attempts: u32,
    },
    /// Fast + long retry budgets are exhausted but the error is still a
    /// transient network / transport failure. Keep the session in `Paused`
    /// and continue retrying with exponential backoff (5m → 10m → 20m →
    /// 30m cap) until the network recovers, the user stops, or a
    /// non-retryable error surfaces.
    Persistent { wait_ms: u64, attempt: u32 },
    /// The error is not retryable — return it and end the loop.
    GiveUp,
}

/// Decide what the agent loop should do when an iteration produces an error.
/// Counters track how many retries have been used **for the current LLM call**;
/// they reset on the next successful iteration.
///
/// Pure function — no I/O, no time. The caller is responsible for actually
/// sleeping the backoff and transitioning session status.
pub fn decide_retry_action(
    error: &RuntimeError,
    fast_count: u32,
    long_count: u32,
    persistent_count: u32,
) -> RetryAction {
    if !error.is_retryable() {
        return RetryAction::GiveUp;
    }

    if fast_count < MAX_ITERATION_RETRIES {
        // Exponential: 1s, 2s, 4s (capped at 10s).
        let backoff_ms = std::cmp::min(1_000u64.saturating_mul(2u64.pow(fast_count)), 10_000);
        return RetryAction::FastRetry {
            backoff_ms,
            attempt: fast_count + 1,
            max_attempts: MAX_ITERATION_RETRIES,
        };
    }

    if long_count < MAX_LONG_RETRIES {
        return RetryAction::LongRetry {
            wait_ms: LONG_RETRY_WAIT_MS,
            attempt: long_count + 1,
            max_attempts: MAX_LONG_RETRIES,
        };
    }

    // Persistent recovery: 5m, 10m, 20m, 30m cap.
    let exp = LONG_RETRY_WAIT_MS.saturating_mul(1u64 << persistent_count.min(3));
    let wait_ms = std::cmp::min(exp, MAX_PERSISTENT_BACKOFF_MS);
    RetryAction::Persistent {
        wait_ms,
        attempt: persistent_count + 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use acowork_core::providers::ProviderError;

    /// Build the kind of error `reliable.rs` surfaces after its provider-level
    /// retry budget is exhausted on a network failure. This is the exact error
    /// that killed the 03:33 session in the 2026-09-02 incident.
    fn network_err() -> RuntimeError {
        RuntimeError::Core(acowork_core::AcoworkError::Provider(
            ProviderError::network(
                "error sending request for url (ark.cn-beijing.volces.com)".to_string(),
            ),
        ))
    }

    fn io_err() -> RuntimeError {
        RuntimeError::Core(acowork_core::AcoworkError::Io(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "tcp timeout",
        )))
    }

    fn auth_err() -> RuntimeError {
        RuntimeError::Core(acowork_core::AcoworkError::Provider(
            ProviderError::from_status_code(401, "unauthorized".into()),
        ))
    }

    fn rate_limit_err() -> RuntimeError {
        RuntimeError::Core(acowork_core::AcoworkError::Provider(
            ProviderError::from_status_code(429, "too many requests".into()),
        ))
    }

    fn quota_err() -> RuntimeError {
        RuntimeError::Core(acowork_core::AcoworkError::Provider(
            ProviderError::unknown("insufficient_quota".into()),
        ))
    }

    // ── Fast retry tier ──────────────────────────────────────────────

    #[test]
    fn first_network_error_uses_fast_retry_at_1s() {
        let action = decide_retry_action(&network_err(), 0, 0, 0);
        assert_eq!(
            action,
            RetryAction::FastRetry {
                backoff_ms: 1_000,
                attempt: 1,
                max_attempts: MAX_ITERATION_RETRIES,
            }
        );
    }

    #[test]
    fn second_network_error_fast_retry_backs_off_to_2s() {
        let action = decide_retry_action(&network_err(), 1, 0, 0);
        assert_eq!(
            action,
            RetryAction::FastRetry {
                backoff_ms: 2_000,
                attempt: 2,
                max_attempts: MAX_ITERATION_RETRIES,
            }
        );
    }

    #[test]
    fn third_network_error_fast_retry_backs_off_to_4s() {
        let action = decide_retry_action(&network_err(), 2, 0, 0);
        assert_eq!(
            action,
            RetryAction::FastRetry {
                backoff_ms: 4_000,
                attempt: 3,
                max_attempts: MAX_ITERATION_RETRIES,
            }
        );
    }

    #[test]
    fn io_error_uses_fast_retry() {
        let action = decide_retry_action(&io_err(), 0, 0, 0);
        assert!(matches!(
            action,
            RetryAction::FastRetry {
                backoff_ms: 1_000,
                ..
            }
        ));
    }

    #[test]
    fn rate_limit_error_is_retryable_at_fast_tier() {
        // 429 keeps original policy (may be budget exhaustion OR server-side
        // throttling — let the retry tier handle both).
        let action = decide_retry_action(&rate_limit_err(), 0, 0, 0);
        assert!(matches!(action, RetryAction::FastRetry { .. }));
    }

    // ── Long retry tier ──────────────────────────────────────────────

    #[test]
    fn network_error_after_fast_budget_promotes_to_long_retry() {
        let action = decide_retry_action(&network_err(), MAX_ITERATION_RETRIES, 0, 0);
        assert_eq!(
            action,
            RetryAction::LongRetry {
                wait_ms: LONG_RETRY_WAIT_MS,
                attempt: 1,
                max_attempts: MAX_LONG_RETRIES,
            }
        );
    }

    #[test]
    fn network_error_increments_long_attempt_counter() {
        let action = decide_retry_action(&network_err(), MAX_ITERATION_RETRIES, 1, 0);
        assert_eq!(
            action,
            RetryAction::LongRetry {
                wait_ms: LONG_RETRY_WAIT_MS,
                attempt: 2,
                max_attempts: MAX_LONG_RETRIES,
            }
        );
    }

    #[test]
    fn third_long_retry_attempt_keeps_5_minute_wait() {
        let action = decide_retry_action(&network_err(), MAX_ITERATION_RETRIES, 2, 0);
        assert_eq!(
            action,
            RetryAction::LongRetry {
                wait_ms: LONG_RETRY_WAIT_MS,
                attempt: 3,
                max_attempts: MAX_LONG_RETRIES,
            }
        );
    }

    // ── Persistent recovery tier ─────────────────────────────────────
    // This is the new tier added to address the 2026-09-02 03:33 root
    // cause: before, the agent loop entered Idle after the bounded budget
    // was exhausted even on transient network errors. Now it stays in
    // Paused and keeps retrying until the network recovers.

    #[test]
    fn network_error_after_long_budget_enters_persistent_at_5m() {
        let action =
            decide_retry_action(&network_err(), MAX_ITERATION_RETRIES, MAX_LONG_RETRIES, 0);
        assert_eq!(
            action,
            RetryAction::Persistent {
                wait_ms: 5 * 60 * 1000,
                attempt: 1,
            }
        );
    }

    #[test]
    fn second_persistent_attempt_doubles_to_10m() {
        let action =
            decide_retry_action(&network_err(), MAX_ITERATION_RETRIES, MAX_LONG_RETRIES, 1);
        assert_eq!(
            action,
            RetryAction::Persistent {
                wait_ms: 10 * 60 * 1000,
                attempt: 2,
            }
        );
    }

    #[test]
    fn third_persistent_attempt_doubles_to_20m() {
        let action =
            decide_retry_action(&network_err(), MAX_ITERATION_RETRIES, MAX_LONG_RETRIES, 2);
        assert_eq!(
            action,
            RetryAction::Persistent {
                wait_ms: 20 * 60 * 1000,
                attempt: 3,
            }
        );
    }

    #[test]
    fn fourth_persistent_attempt_caps_at_30m() {
        let action =
            decide_retry_action(&network_err(), MAX_ITERATION_RETRIES, MAX_LONG_RETRIES, 3);
        assert_eq!(
            action,
            RetryAction::Persistent {
                wait_ms: 30 * 60 * 1000,
                attempt: 4,
            }
        );
    }

    #[test]
    fn persistent_backoff_caps_at_30m_for_high_attempt_counts() {
        // persistent_count = 10, 50, 100 — must stay at 30m cap.
        for n in [10u32, 50, 100] {
            let action =
                decide_retry_action(&network_err(), MAX_ITERATION_RETRIES, MAX_LONG_RETRIES, n);
            assert_eq!(
                action,
                RetryAction::Persistent {
                    wait_ms: MAX_PERSISTENT_BACKOFF_MS,
                    attempt: n + 1,
                },
                "persistent_count={n} must cap at 30m"
            );
        }
    }

    #[test]
    fn io_error_also_enters_persistent_recovery() {
        let action = decide_retry_action(&io_err(), MAX_ITERATION_RETRIES, MAX_LONG_RETRIES, 0);
        let expected_wait = 5 * 60 * 1000;
        assert!(matches!(
            action,
            RetryAction::Persistent { wait_ms, .. } if wait_ms == expected_wait
        ));
    }

    // ── GiveUp tier ──────────────────────────────────────────────────

    #[test]
    fn auth_error_is_non_retryable_gives_up_immediately() {
        let action = decide_retry_action(&auth_err(), 0, 0, 0);
        assert_eq!(action, RetryAction::GiveUp);
    }

    #[test]
    fn quota_error_is_non_retryable_even_if_provider_says_retryable() {
        // quota errors must never be retried, even when the underlying
        // ProviderError marks itself retryable.
        let action = decide_retry_action(&quota_err(), 0, 0, 0);
        assert_eq!(action, RetryAction::GiveUp);
    }

    #[test]
    fn tool_error_is_non_retryable() {
        let action = decide_retry_action(&RuntimeError::Tool("boom".into()), 0, 0, 0);
        assert_eq!(action, RetryAction::GiveUp);
    }

    #[test]
    fn loop_detected_error_is_non_retryable() {
        let action = decide_retry_action(&RuntimeError::LoopDetected("loop".into()), 0, 0, 0);
        assert_eq!(action, RetryAction::GiveUp);
    }

    // ── Counter monotonicity invariants ───────────────────────────────
    // The caller is expected to pass monotonically increasing counters.
    // These tests pin down which tier each counter prefix selects so a
    // future refactor that "optimizes" the order doesn't accidentally
    // demote a transient error to GiveUp.

    #[test]
    fn network_error_at_fast_zero_long_zero_persistent_zero_is_fast() {
        assert!(matches!(
            decide_retry_action(&network_err(), 0, 0, 0),
            RetryAction::FastRetry { .. }
        ));
    }

    #[test]
    fn network_error_at_fast_max_long_zero_persistent_zero_is_long() {
        assert!(matches!(
            decide_retry_action(&network_err(), MAX_ITERATION_RETRIES, 0, 0),
            RetryAction::LongRetry { .. }
        ));
    }

    #[test]
    fn network_error_at_fast_max_long_max_persistent_zero_is_persistent() {
        assert!(matches!(
            decide_retry_action(&network_err(), MAX_ITERATION_RETRIES, MAX_LONG_RETRIES, 0),
            RetryAction::Persistent { .. }
        ));
    }
}
