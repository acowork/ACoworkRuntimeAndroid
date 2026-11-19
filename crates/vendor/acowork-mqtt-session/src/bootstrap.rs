//! Bootstrap contract (ADR-039 §4).
//!
//! Defines the [`BootstrapAction`] trait — the five-step idempotent
//! contract that must be executed after every `ConnAck` (initial
//! connect + reconnect). Both Runtime and Desktop implement this.
//!
//! The five steps are:
//! 1. PUBLISH `status = online` (Retained, QoS 1) — cancel Last Will
//! 2. PUBLISH `meta` (Retained, QoS 1) — capability descriptor
//! 3. PUBLISH `config` (Retained, QoS 1) — runtime configuration
//! 4. SUBSCRIBE `acowork/global/#` (QoS 1) — global resources
//! 5. SUBSCRIBE business control tree (QoS 1) — control commands
//!
//! The contract is **idempotent**: calling it multiple times must not
//! cause double subscriptions or duplicate retained messages. See
//! `docs/adr/zh/ADR-039-mqtt-client-lifecycle.md` §4.

use async_trait::async_trait;

/// Bootstrap five-step idempotent contract.
///
/// # Implementing
///
/// Each step has a default no-op implementation returning `Ok(())`.
/// Implementors override only the steps relevant to their role:
///
/// - **Runtime**: overrides all five steps (publish status/meta/config,
///   subscribe global/control).
/// - **Desktop**: overrides steps 4–5 (subscribe global/agent-lifecycle);
///   steps 1–3 are no-ops because Desktop does not publish retained
///   status/meta/config (that's the Runtime's job).
///
/// `run_bootstrap()` is provided as the single entry-point that
/// executes steps 1–5 **in order**, aborting on the first error.
///
/// # Idempotency
///
/// Implementations MUST be idempotent. For publish (steps 1–3) this is
/// achieved by using retained messages (same-topic, same-payload
/// overwrite). For subscribe (steps 4–5) this is achieved by the
/// broker treating duplicate subscriptions as a set operation.
#[async_trait]
pub trait BootstrapAction {
    /// The error type returned by each bootstrap step.
    type Error: std::fmt::Display;

    /// Step 1: PUBLISH `status = online` (Retained, QoS 1).
    ///
    /// Default: no-op (Desktop does not publish agent status).
    async fn publish_status(&self) -> Result<(), Self::Error> {
        Ok(())
    }

    /// Step 2: PUBLISH `meta` (Retained, QoS 1).
    ///
    /// Default: no-op.
    async fn publish_meta(&self) -> Result<(), Self::Error> {
        Ok(())
    }

    /// Step 3: PUBLISH `config` (Retained, QoS 1).
    ///
    /// Default: no-op.
    async fn publish_config(&self) -> Result<(), Self::Error> {
        Ok(())
    }

    /// Step 4: SUBSCRIBE `acowork/global/#` (QoS 1).
    ///
    /// Default: no-op. Desktop should override to also subscribe
    /// agent lifecycle topics.
    async fn subscribe_global_resources(&self) -> Result<(), Self::Error> {
        Ok(())
    }

    /// Step 5: SUBSCRIBE business control tree (QoS 1).
    ///
    /// Default: no-op.
    async fn subscribe_control_tree(&self) -> Result<(), Self::Error> {
        Ok(())
    }

    /// Execute all five bootstrap steps in order.
    ///
    /// Steps 1–3 first ("self-announce"), then steps 4–5 ("receive").
    /// Aborts on the first error — the caller should handle the
    /// failure (e.g. publish `status=degraded`).
    async fn run_bootstrap(&self) -> Result<(), Self::Error> {
        self.publish_status().await?;
        self.publish_meta().await?;
        self.publish_config().await?;
        self.subscribe_global_resources().await?;
        self.subscribe_control_tree().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// A test implementor that counts how many times each step runs.
    struct CountingBootstrap {
        call_count: AtomicU32,
    }

    #[async_trait]
    impl BootstrapAction for CountingBootstrap {
        type Error = String;

        async fn publish_status(&self) -> Result<(), Self::Error> {
            self.call_count.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
        async fn publish_meta(&self) -> Result<(), Self::Error> {
            self.call_count.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
        async fn publish_config(&self) -> Result<(), Self::Error> {
            self.call_count.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
        async fn subscribe_global_resources(&self) -> Result<(), Self::Error> {
            self.call_count.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
        async fn subscribe_control_tree(&self) -> Result<(), Self::Error> {
            self.call_count.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    #[tokio::test]
    async fn run_bootstrap_calls_all_five_steps() {
        let bootstrap = CountingBootstrap {
            call_count: AtomicU32::new(0),
        };
        bootstrap.run_bootstrap().await.unwrap();
        assert_eq!(bootstrap.call_count.load(Ordering::SeqCst), 5);
    }

    #[tokio::test]
    async fn run_bootstrap_is_idempotent() {
        let bootstrap = CountingBootstrap {
            call_count: AtomicU32::new(0),
        };
        // Run twice — should succeed both times.
        bootstrap.run_bootstrap().await.unwrap();
        bootstrap.run_bootstrap().await.unwrap();
        // 5 steps × 2 runs = 10 calls.
        assert_eq!(bootstrap.call_count.load(Ordering::SeqCst), 10);
    }

    /// A bootstrap that fails on step 2.
    struct FailingBootstrap;

    #[async_trait]
    impl BootstrapAction for FailingBootstrap {
        type Error = String;

        async fn publish_status(&self) -> Result<(), Self::Error> {
            Ok(())
        }
        async fn publish_meta(&self) -> Result<(), Self::Error> {
            Err("meta publish failed".into())
        }
    }

    #[tokio::test]
    async fn run_bootstrap_aborts_on_first_error() {
        let bootstrap = FailingBootstrap;
        let result = bootstrap.run_bootstrap().await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "meta publish failed");
    }

    /// A bootstrap that only implements the last two steps (Desktop-style).
    struct DesktopStyleBootstrap {
        subscribe_count: AtomicU32,
    }

    #[async_trait]
    impl BootstrapAction for DesktopStyleBootstrap {
        type Error = String;

        async fn subscribe_global_resources(&self) -> Result<(), Self::Error> {
            self.subscribe_count.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
        async fn subscribe_control_tree(&self) -> Result<(), Self::Error> {
            self.subscribe_count.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    #[tokio::test]
    async fn desktop_style_only_runs_subscribe_steps() {
        let bootstrap = DesktopStyleBootstrap {
            subscribe_count: AtomicU32::new(0),
        };
        // Steps 1-3 are no-ops → succeed silently.
        // Steps 4-5 are overridden → increment counter.
        bootstrap.run_bootstrap().await.unwrap();
        assert_eq!(bootstrap.subscribe_count.load(Ordering::SeqCst), 2);
    }
}
