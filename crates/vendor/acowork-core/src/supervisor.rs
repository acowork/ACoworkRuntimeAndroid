//! Supervisor building blocks for Gateway-managed subprocess monitoring.
//!
//! Provides reusable components shared by embed supervisor and LSP relay
//! supervisor:
//!
//! - [`RestartHistory`] — tracks consecutive restart attempts within a
//!   sliding window, enforcing a maximum-attempts cap.
//! - [`backoff_with_jitter`] — exponential backoff with ±20% jitter,
//!   clamped to a configurable range.
//! - [`SseFrame`] / [`parse_sse_frame`] — minimal SSE frame parser for
//!   the `/events` stream.
//! - [`HeartbeatWatchdog`] — periodic liveness check that fires when no
//!   heartbeat is received within a configurable timeout.

use std::time::{Duration, Instant};

// ── Restart history ─────────────────────────────────────────────────────

/// Tracks consecutive restart attempts within a sliding window.
///
/// Used to enforce a maximum-restarts policy: if the subprocess crashes
/// more than N times within the window, the supervisor gives up.
pub struct RestartHistory {
    /// Timestamps of recent restarts within the window.
    attempts: Vec<Instant>,
}

impl RestartHistory {
    /// Create a new empty history.
    pub fn new() -> Self {
        Self {
            attempts: Vec::new(),
        }
    }

    /// Record a restart attempt, pruning anything older than `window`.
    /// Returns the number of attempts now in the window (after pruning).
    pub fn record(&mut self, window: Duration) -> usize {
        let now = Instant::now();
        self.attempts
            .retain(|t| now.duration_since(*t) < window);
        self.attempts.push(now);
        self.attempts.len()
    }
}

impl Default for RestartHistory {
    fn default() -> Self {
        Self::new()
    }
}

// ── Backoff ─────────────────────────────────────────────────────────────

/// Compute exponential backoff with ±20% jitter, clamped to `[min, max]`.
///
/// The base delay is `min * 2^attempt`, capped at `max`. A random ±20%
/// jitter is then applied to avoid thundering-herd restarts.
pub fn backoff_with_jitter(attempt: u32, min: Duration, max: Duration) -> Duration {
    let exp = 1u64 << attempt.min(6); // cap shift to avoid overflow
    let base_ms = (min.as_millis() as u64).saturating_mul(exp);
    let capped_ms = base_ms.min(max.as_millis() as u64);
    // ±20% jitter
    let jitter = (capped_ms as f64 * 0.2) as u64;
    let low = capped_ms.saturating_sub(jitter);
    let high = capped_ms.saturating_add(jitter);
    let chosen = if high > low {
        low + (Instant::now().elapsed().subsec_nanos() as u64) % (high - low + 1)
    } else {
        capped_ms
    };
    Duration::from_millis(chosen)
}

// ── SSE frame parsing ───────────────────────────────────────────────────

/// Parsed SSE frame from the `/events` stream.
///
/// The `State` variant carries the raw JSON payload; the caller is
/// responsible for deserializing it into the application-specific
/// state type.
#[derive(Debug, Clone)]
pub enum SseFrame {
    /// `event: heartbeat` frame.
    Heartbeat,
    /// `event: state` frame with raw JSON data payload.
    State(String),
    /// SSE comment line (e.g. `:lagged:3`).
    Comment(String),
}

/// Minimal SSE frame parser.
///
/// Handles the subset that axum's `Sse` produces: `event: <name>`,
/// `data: <payload>`, blank line, and `:comment` lines.
/// Returns `None` for unparseable frames.
pub fn parse_sse_frame(frame: &str) -> Option<SseFrame> {
    let mut event_name: Option<String> = None;
    let mut data_lines: Vec<String> = Vec::new();

    for line in frame.lines() {
        if let Some(rest) = line.strip_prefix("event:") {
            event_name = Some(rest.trim().to_string());
        } else if let Some(rest) = line.strip_prefix("data:") {
            data_lines.push(rest.trim_start().to_string());
        } else if let Some(rest) = line.strip_prefix(':') {
            // SSE comment. If no event was collected, this is a no-op;
            // surface it so the caller can log lagged lines, etc.
            if event_name.is_none() && data_lines.is_empty() {
                return Some(SseFrame::Comment(rest.trim().to_string()));
            }
        }
        // Other fields (id:, retry:) are ignored.
    }

    let payload = data_lines.join("\n");
    match event_name.as_deref() {
        Some("heartbeat") => Some(SseFrame::Heartbeat),
        Some("state") => Some(SseFrame::State(payload)),
        _ => None,
    }
}

// ── Heartbeat watchdog ──────────────────────────────────────────────────

/// Status returned by [`HeartbeatWatchdog::tick`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeartbeatStatus {
    /// Heartbeat is fresh — process is alive.
    Ok,
    /// No heartbeat received within the configured timeout.
    Timeout {
        /// Seconds since the last heartbeat was received.
        elapsed_secs: u64,
    },
}

/// Periodic liveness checker for SSE heartbeat streams.
///
/// Wraps a `tokio::time::Interval` and an `Instant` tracking the last
/// received heartbeat. Call [`tick`](Self::tick) in a `tokio::select!`
/// loop and [`beat`](Self::beat) on every received heartbeat event.
///
/// The first call to `tick()` is always `Ok` — this skips the immediate
/// first tick of the underlying interval so the watchdog doesn't fire
/// instantly on spawn.
pub struct HeartbeatWatchdog {
    interval: tokio::time::Interval,
    last_heartbeat: Instant,
    timeout: Duration,
    first_tick: bool,
}

impl HeartbeatWatchdog {
    /// Create a new watchdog.
    ///
    /// `check_interval` is how often the watchdog checks for staleness
    /// (typically 2s). `timeout` is the max allowed gap between heartbeats
    /// (typically 10s).
    pub fn new(check_interval: Duration, timeout: Duration) -> Self {
        Self {
            interval: tokio::time::interval(check_interval),
            last_heartbeat: Instant::now(),
            timeout,
            first_tick: true,
        }
    }

    /// Wait for the next check tick, then return whether the heartbeat
    /// is still fresh.
    ///
    /// The first call always returns `Ok` (skips the immediate tick).
    pub async fn tick(&mut self) -> HeartbeatStatus {
        self.interval.tick().await;
        if self.first_tick {
            self.first_tick = false;
            return HeartbeatStatus::Ok;
        }
        if self.last_heartbeat.elapsed() > self.timeout {
            HeartbeatStatus::Timeout {
                elapsed_secs: self.last_heartbeat.elapsed().as_secs(),
            }
        } else {
            HeartbeatStatus::Ok
        }
    }

    /// Reset the heartbeat timer. Call this on every received heartbeat
    /// event from the SSE stream.
    pub fn beat(&mut self) {
        self.last_heartbeat = Instant::now();
    }
}
