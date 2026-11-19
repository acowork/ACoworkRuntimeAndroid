//! System sleep/wake detection (ADR-065 Step 1).
//!
//! Extracted from the Desktop app (`apps/acowork-desktop/src-tauri/src/lib.rs`
//! `mod power`) and the Node Agent (`core/acowork-node/src/power.rs`) into the
//! shared `acowork-mqtt-session` crate so every MQTT client recovers from OS
//! sleep/wake with identical timing and a single implementation.
//!
//! On Windows Modern Standby / macOS / Linux suspend the whole process
//! freezes. After wake the MQTT poll task can stall on the stale TCP
//! connection until its watchdog fires (2026-08 incident: 5 sleep/wake
//! cycles, each freezing node + embed for 3-16 minutes; the LSP relay
//! heartbeat accumulated the exact sleep durations, e.g. 944 s).
//!
//! Detection uses a biased/unbiased monotonic clock pair:
//!
//!   • **biased**   — includes time spent in sleep / suspend
//!   • **unbiased** — excludes time spent in sleep / suspend
//!
//! If `biased_delta - unbiased_delta > threshold`, the system was genuinely
//! asleep — not merely idle or backgrounded.
//!
//! Platform implementations:
//!   • Windows: `GetTickCount64()` (biased) vs `QueryUnbiasedInterruptTime()` (unbiased)
//!   • macOS:   `clock_gettime(CLOCK_MONOTONIC_RAW)` (biased) vs `CLOCK_UPTIME_RAW` (unbiased)
//!   • Linux:   `clock_gettime(CLOCK_BOOTTIME)` (biased) vs `CLOCK_MONOTONIC` (unbiased)

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use crate::config::WAKE_DETECT_THRESHOLD;

static LAST_BIASED_MS: AtomicU64 = AtomicU64::new(0);
static LAST_UNBIASED_MS: AtomicU64 = AtomicU64::new(0);

/// Power-probe sampling interval (ADR-065 §5.2). Must be well below the
/// 5 s wake threshold so a resume is detected within ~2 s. Single source
/// of truth — all processes that need wake recovery use this constant.
pub use crate::config::POWER_PROBE_INTERVAL;

// ── Windows FFI ──────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
unsafe extern "system" {
    fn GetTickCount64() -> u64;
    fn QueryUnbiasedInterruptTime(unbiased_time: *mut u64) -> i32;
}

/// Returns `(biased_ms, unbiased_ms)` where biased includes time spent
/// in sleep / suspend and unbiased excludes it. Returns `None` on API
/// failure or on unsupported platforms.
fn sample() -> Option<(u64, u64)> {
    #[cfg(target_os = "windows")]
    {
        unsafe {
            let biased_ms = GetTickCount64();
            let mut unbiased_100ns: u64 = 0;
            if QueryUnbiasedInterruptTime(&mut unbiased_100ns) == 0 {
                return None; // API failure
            }
            Some((biased_ms, unbiased_100ns / 10_000))
        }
    }

    #[cfg(target_os = "macos")]
    {
        // CLOCK_MONOTONIC_RAW advances during sleep; CLOCK_UPTIME_RAW does not.
        sample_unix(libc::CLOCK_MONOTONIC_RAW, libc::CLOCK_UPTIME_RAW)
    }

    #[cfg(target_os = "linux")]
    {
        // CLOCK_BOOTTIME includes suspend time; CLOCK_MONOTONIC does not.
        sample_unix(libc::CLOCK_BOOTTIME, libc::CLOCK_MONOTONIC)
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    {
        None // Unsupported platform — no sleep detection
    }
}

/// Shared `clock_gettime` helper for macOS and Linux.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn sample_unix(
    biased_clk: libc::clockid_t,
    unbiased_clk: libc::clockid_t,
) -> Option<(u64, u64)> {
    fn read_clk(clk: libc::clockid_t) -> Option<u64> {
        let mut ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        if unsafe { libc::clock_gettime(clk, &mut ts) } != 0 {
            return None;
        }
        Some((ts.tv_sec as u64) * 1_000 + (ts.tv_nsec as u64) / 1_000_000)
    }
    Some((read_clk(biased_clk)?, read_clk(unbiased_clk)?))
}

/// Pure classification: given two clock-sample pairs, did the system
/// genuinely sleep between them? Public for unit tests — see the
/// regression suite in the `tests` module for the ADR-065 §7 #4
/// simulated 12 s sleep scenario.
///
/// Inputs are `(biased_ms, unbiased_ms)` from
/// [`sample`] / platform `clock_gettime`; outputs are platform-agnostic.
/// A first call (any `prev_* == 0`) is treated as baseline-seeding and
/// returns `false` so callers don't false-positive at startup.
pub fn is_resume_gap(
    prev_biased_ms: u64,
    prev_unbiased_ms: u64,
    biased_ms: u64,
    unbiased_ms: u64,
) -> bool {
    if prev_biased_ms == 0 || prev_unbiased_ms == 0 {
        return false; // First call — seed values, don't trigger
    }
    let biased_delta = biased_ms.saturating_sub(prev_biased_ms);
    let unbiased_delta = unbiased_ms.saturating_sub(prev_unbiased_ms);
    let sleep_ms = biased_delta.saturating_sub(unbiased_delta);
    sleep_ms > WAKE_DETECT_THRESHOLD.as_millis() as u64
}

/// Returns `true` if the system was genuinely asleep (not merely idle
/// or backgrounded) since the last call.
///
/// Updates the clock baseline on every call so that subsequent calls
/// measure sleep since the *last* call, not since boot. The first call
/// only seeds the baseline and returns `false`. Callers poll this on a
/// fixed interval and run their recovery action on `true`.
pub fn detect_resume() -> bool {
    let Some((biased_ms, unbiased_ms)) = sample() else {
        return false; // API failure or unsupported platform
    };

    let prev_biased = LAST_BIASED_MS.swap(biased_ms, Ordering::Relaxed);
    let prev_unbiased = LAST_UNBIASED_MS.swap(unbiased_ms, Ordering::Relaxed);

    if is_resume_gap(prev_biased, prev_unbiased, biased_ms, unbiased_ms) {
        let biased_delta = biased_ms.saturating_sub(prev_biased);
        let unbiased_delta = unbiased_ms.saturating_sub(prev_unbiased);
        let sleep_ms = biased_delta.saturating_sub(unbiased_delta);
        tracing::info!(
            sleep_ms,
            biased_delta_ms = biased_delta,
            unbiased_delta_ms = unbiased_delta,
            "Actual system sleep detected"
        );
        true
    } else {
        false
    }
}

/// Background task that polls [`detect_resume`] on a fixed interval and
/// invokes `on_resume` when genuine system sleep/wake is detected.
///
/// ADR-065 §5.4: every process that needs wake recovery (Desktop / Node /
/// Runtime) runs this loop with [`POWER_PROBE_INTERVAL`]. `on_resume` is
/// the process-specific recovery action (e.g. force-reconnect the MQTT
/// client via the shared [`crate::ForceRestart`]).
///
/// The callback indirection (rather than taking a [`crate::ForceRestart`]
/// directly) is deliberate: the Desktop's MQTT client is created lazily
/// after this loop starts, so the recovery action must resolve the client
/// at wake time. Step 3/4 (`MqttClient<B>`) will let the client own the
/// probe loop and pass its `ForceRestart` directly.
pub async fn run_power_probe_loop(
    on_resume: impl Fn() + Send + Sync + 'static,
    interval: Duration,
    label: &'static str,
) {
    let mut tick = tokio::time::interval(interval);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        if detect_resume() {
            tracing::warn!(label, "System sleep/wake detected — forcing reconnect");
            on_resume();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_call_seeds_baseline_without_triggering() {
        // The first invocation only seeds the baseline, so it must
        // never report a resume.
        assert!(!detect_resume());
        // An immediate second call sees no sleep and must not trigger.
        assert!(!detect_resume());
    }

    #[test]
    fn sample_reads_monotonic_pairs() {
        // On every supported platform the clocks must return increasing
        // pairs; biased >= unbiased always (biased includes sleep).
        let (biased, unbiased) = sample().expect("clock sampling must work");
        assert!(biased >= unbiased);
    }

    // ── is_resume_gap (ADR-065 §7 #4 clock-mocking regression) ─────
    //
    // We deliberately do NOT mock `sample()` or freeze real time — both
    // would require either a global clock injection point or a real
    // 12-second `tokio::time::sleep`, neither of which is worth the
    // test complexity. Instead `is_resume_gap` is the pure classifier
    // (`sample()` → boolean decision) and these tests pin its behaviour
    // directly. `detect_resume()` is then a 4-line wrapper that feeds
    // `sample()` into `is_resume_gap`, exercised by `sample_reads_monotonic_pairs`.

    #[test]
    fn is_resume_gap_first_call_seeds_without_triggering() {
        // Either prev_* == 0 means baseline seeding — never wake.
        assert!(!is_resume_gap(0, 0, 12_000, 12_000));
        assert!(!is_resume_gap(1_000, 0, 13_000, 12_000));
        assert!(!is_resume_gap(0, 1_000, 13_000, 12_000));
    }

    #[test]
    fn is_resume_gap_no_sleep_returns_false() {
        // Back-to-back reads: biased advances the same as unbiased,
        // so sleep_ms = 0. Must not trigger.
        let baseline = 1_000_000;
        assert!(!is_resume_gap(baseline, baseline, baseline + 50, baseline + 50));
    }

    #[test]
    fn is_resume_gap_under_threshold_returns_false() {
        // 3 s of "sleep" — well below the 5 s threshold.
        // Both clocks advance 3 s; the gap (biased - unbiased) is 0.
        let baseline = 1_000_000;
        assert!(!is_resume_gap(baseline, baseline, baseline + 3_000, baseline + 3_000));
        // 4.99 s of sleep — still below threshold.
        assert!(!is_resume_gap(
            baseline,
            baseline,
            baseline + 4_990,
            baseline
        ));
    }

    #[test]
    fn is_resume_gap_simulated_12s_sleep_returns_true() {
        // ADR-065 §7 #4 headline regression test. Simulates a 12-second
        // OS sleep by feeding is_resume_gap two synthetic clock samples:
        //   t0: biased=1_000_000 ms, unbiased=1_000_000 ms
        //   t1: biased=1_012_000 ms (12 s of biased time elapsed),
        //        unbiased=1_000_000 ms (kernel is awake for 0 s of it)
        // The classifier must compute sleep_ms = 12_000 > 5_000
        // (WAKE_DETECT_THRESHOLD) and return true.
        //
        // The full chain — `detect_resume()` returning true →
        // `run_power_probe_loop` calling `on_resume()` →
        // `ForceRestart::request()` — is the integration this protects.
        // See `force_restart::tests::wait_immediate_permit` /
        // `force_restart::tests::interruptible_backoff_true` for the
        // downstream side; here we pin the classification bit.
        let prev_biased = 1_000_000u64;
        let prev_unbiased = 1_000_000u64;
        let biased_after_wake = prev_biased + 12_000; // 12 s of biased time
        let unbiased_after_wake = prev_unbiased; // 0 s of awake time
        assert!(
            is_resume_gap(
                prev_biased,
                prev_unbiased,
                biased_after_wake,
                unbiased_after_wake
            ),
            "12 s of biased time with 0 s of awake time must classify as a wake event"
        );
    }

    #[test]
    fn is_resume_gap_at_threshold_returns_false() {
        // Boundary check: sleep_ms == WAKE_DETECT_THRESHOLD must NOT
        // trigger (the classifier uses `>`, not `>=`, so jitter exactly
        // at the threshold is filtered). 5 s wake threshold — see
        // `config::WAKE_DETECT_THRESHOLD`.
        let baseline = 1_000_000;
        let sleep_ms = WAKE_DETECT_THRESHOLD.as_millis() as u64;
        assert!(!is_resume_gap(
            baseline,
            baseline,
            baseline + sleep_ms,
            baseline
        ));
    }

    #[test]
    fn is_resume_gap_just_over_threshold_returns_true() {
        // 1 ms over the 5 s threshold.
        let baseline = 1_000_000;
        let sleep_ms = WAKE_DETECT_THRESHOLD.as_millis() as u64 + 1;
        assert!(is_resume_gap(
            baseline,
            baseline,
            baseline + sleep_ms,
            baseline
        ));
    }
}
