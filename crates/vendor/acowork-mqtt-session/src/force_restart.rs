//! Force-restart signal for MQTT event-loop poll tasks (ADR-065 Step 2).
//!
//! Extracted from the Desktop app (`apps/acowork-desktop/src-tauri/src/
//! mqtt_client.rs`) and the Node Agent (`core/acowork-node/src/control/
//! mqtt.rs`) into the shared `acowork-mqtt-session` crate so every MQTT
//! client uses identical force-restart semantics (ADR-065 §5.3).
//!
//! The Desktop combined a `tokio::sync::Notify` with a persistent
//! `AtomicBool` flag; the Node used a bare `Notify` and could lose a
//! request issued while the poll task was busy handling an event (the
//! `select!`-outside race, ADR-065 §2.4). The shared type unifies on the
//! Desktop's stronger semantics: a request is never lost.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

/// Force-restart signal for an MQTT event-loop poll task.
///
/// Combines a `tokio::sync::Notify` (fast wake-up while the poll task is
/// parked in `select!`) with a persistent `AtomicBool` flag (covers the
/// window where the poll task is busy handling an event and would miss
/// the notification). Consumers must call [`ForceRestart::take`] to
/// atomically consume the pending request, so a request is never lost.
#[derive(Debug, Default)]
pub struct ForceRestart {
    notify: tokio::sync::Notify,
    requested: AtomicBool,
}

impl ForceRestart {
    /// Create a new, unset force-restart signal.
    pub fn new() -> Self {
        Self::default()
    }

    /// Request a soft-restart of the MQTT event loop.
    ///
    /// Idempotent: sets the persistent flag and wakes any waiter.
    /// `notify_one` (not `notify_waiters`) so a request issued while the
    /// poll task is NOT yet parked in `select!` stores a permit — the
    /// task's next `notified()` resolves immediately instead of waiting
    /// for the flag check at the top of the loop. (A request issued with
    /// no waiters through `notify_waiters` would be lost entirely,
    /// leaving the poll task to finish its current backoff before
    /// noticing the flag.)
    pub fn request(&self) {
        self.requested.store(true, Ordering::SeqCst);
        self.notify.notify_one();
    }

    /// Atomically consume the persistent request flag.
    ///
    /// Returns `true` if a restart was requested and not yet handled.
    pub fn take(&self) -> bool {
        self.requested.swap(false, Ordering::SeqCst)
    }

    /// Wait for a force-restart request.
    ///
    /// Fast path while the poll task is parked in `select!`. Resolves
    /// immediately if a permit is already stored (a request issued while
    /// nobody was waiting). Callers should also check [`ForceRestart::take`]
    /// at the top of their loop to cover the busy-handling window, and
    /// consume the persistent flag after `wait()` resolves.
    pub async fn wait(&self) {
        self.notify.notified().await;
    }

    /// Sleep for `dur` unless a force-restart is requested, in which case
    /// return `true` so the caller can break to the soft-restart path.
    ///
    /// The force-restart signal must be able to interrupt a backoff
    /// sleep, not only `poll()`: after a system wake the poll task often
    /// returns a fatal IO error (e.g. 10053) instead of hanging, and an
    /// uninterruptible 60 s fatal backoff leaves the process offline for
    /// the whole minute (desktop-app wake incident, 2026-08 — recovery
    /// took exactly 60 s because `sleep(60s).await` sat outside any
    /// `select!`, so the wake-triggered force-restart could not break it).
    pub async fn interruptible_backoff(&self, dur: Duration, kind: &str) -> bool {
        tokio::select! {
            _ = tokio::time::sleep(dur) => false,
            _ = self.wait() => {
                let _ = self.take(); // consume the persistent flag
                tracing::info!(kind, "Force-restart requested during backoff");
                true
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn request_sets_persistent_flag_until_taken() {
        let fr = ForceRestart::new();
        assert!(!fr.take(), "no request yet");
        fr.request();
        assert!(fr.take(), "request must be visible");
        assert!(!fr.take(), "request must be consumed exactly once");
    }

    #[test]
    fn request_is_idempotent() {
        let fr = ForceRestart::new();
        fr.request();
        fr.request(); // second request must not be lost
        assert!(fr.take());
    }

    #[tokio::test]
    async fn wait_resolves_when_requested_while_parked() {
        let fr = Arc::new(ForceRestart::new());
        let fr2 = Arc::clone(&fr);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            fr2.request();
        });
        fr.wait().await; // must resolve promptly
    }

    #[tokio::test]
    async fn wait_resolves_immediately_when_permit_stored() {
        let fr = ForceRestart::new();
        fr.request(); // permit stored while nobody is waiting
        tokio::time::timeout(Duration::from_millis(100), fr.wait())
            .await
            .expect("stored permit must resolve immediately");
    }

    #[tokio::test]
    async fn interruptible_backoff_returns_false_after_duration() {
        let fr = ForceRestart::new();
        let interrupted = fr.interruptible_backoff(Duration::from_millis(20), "test").await;
        assert!(
            !interrupted,
            "must not report interrupted when no signal arrived"
        );
    }

    #[tokio::test]
    async fn interruptible_backoff_returns_true_on_request() {
        let fr = Arc::new(ForceRestart::new());
        let fr2 = Arc::clone(&fr);
        // Wake the helper while it is still inside the sleep future,
        // i.e. NOT during a poll() iteration. Regression for the
        // 2026-08 wake incident where bare `sleep(60s).await` sat
        // outside any `select!` and the notify could not break it.
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            fr2.request();
        });
        let interrupted = fr.interruptible_backoff(Duration::from_secs(60), "test").await;
        assert!(
            interrupted,
            "must return true when requested before duration elapsed"
        );
    }
}
