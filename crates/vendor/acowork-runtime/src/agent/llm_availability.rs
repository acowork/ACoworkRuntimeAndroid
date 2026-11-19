//! Three-state LLM availability registry.
//!
//! Polls [`SharedAvailableCache`] every [`POLL_INTERVAL`] and computes the
//! effective [`LlmAvailability`] for the `SessionConfig.llm_availability`
//! wire field.
//!
//! Frontend contract (see proto `enum LlmAvailability`):
//! - `UNSPECIFIED` → "not yet synced", never render a banner
//! - `LOADING` → grey placeholder strip
//! - `CONFIGURED` → silent
//! - `MISSING` → red misconfigured banner
//!
//! Why poll rather than watch: `AvailableResourceCache` uses `RwLock`, not
//! `watch`. Switching to a watch channel would touch every cache-mutator
//! call site (MQTT client event loop, `update_from_mqtt`); 100 ms covers
//! the ~50 ms startup vault-ready race with margin and keeps this change
//! independent.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;
use tokio::time::{MissedTickBehavior, interval};

use acowork_core::mqtt_proto::{AvailableProviders, BootstrapPhase, BootstrapState};

use crate::mqtt::SharedAvailableCache;

/// Re-export the wire enum so downstream modules don't have to reach into
/// `acowork_core::mqtt_proto` directly.
pub use acowork_core::mqtt_proto::LlmAvailability as WireAvailability;

/// Polling cadence. One tick is enough to capture the ~50 ms vault-ready
/// startup race; user-initiated provider edits propagate within this bound.
pub const POLL_INTERVAL: Duration = Duration::from_millis(100);

/// Runtime-side view of LLM availability, mirroring the proto enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LlmAvailability {
    Unspecified,
    Loading,
    Configured,
    Missing,
}

impl LlmAvailability {
    pub fn from_wire(w: WireAvailability) -> Self {
        match w {
            WireAvailability::Unspecified => Self::Unspecified,
            WireAvailability::Loading => Self::Loading,
            WireAvailability::Configured => Self::Configured,
            WireAvailability::Missing => Self::Missing,
        }
    }

    pub fn as_wire(self) -> WireAvailability {
        match self {
            Self::Unspecified => WireAvailability::Unspecified,
            Self::Loading => WireAvailability::Loading,
            Self::Configured => WireAvailability::Configured,
            Self::Missing => WireAvailability::Missing,
        }
    }

    /// Integer tag (matches the proto `repr(i32)`).
    pub fn as_i32(self) -> i32 {
        self.as_wire() as i32
    }
}

/// Pure decision function — no I/O, no cache access. Easy to unit-test.
fn compute(
    bootstrap: Option<&BootstrapState>,
    providers: Option<&AvailableProviders>,
) -> LlmAvailability {
    let phase = bootstrap
        .and_then(|b| BootstrapPhase::try_from(b.phase).ok())
        .unwrap_or(BootstrapPhase::Unspecified);
    if phase != BootstrapPhase::Ready {
        return LlmAvailability::Loading;
    }
    // `bootstrap=Ready` but `providers=None` is a retained re-delivery
    // race, not a real misconfiguration. After a (remote) Gateway
    // restart the Runtime's cache layer clears old-generation resource
    // snapshots the moment a new `acowork/global/bootstrap` arrives
    // (see `AvailableResourceCache::update_from_mqtt` → generation
    // switch); `acowork/global/providers` is a separate retained topic
    // and the broker does not guarantee cross-topic ordering, so we can
    // observe `providers=None` for tens of milliseconds before its
    // retained payload lands. Reporting Missing here would surface a
    // false yellow "LLM 未配置" banner on the Desktop for that window.
    // Per ADR-059 §5.3 (single-snapshot atomicity) the bootstrap phase
    // is the only authoritative cross-topic signal — so Loading is the
    // honest verdict until the providers snapshot itself arrives.
    // A genuinely empty vault always travels as `providers=Some([])`
    // (the Gateway's `MqttGlobalResourcesPublisher` always emits a
    // non-None envelope once its ready barrier lifts), which still
    // maps to Missing via the empty-list branch below.
    let Some(p) = providers else {
        return LlmAvailability::Loading;
    };
    if p.providers.is_empty() {
        return LlmAvailability::Missing;
    }
    // Callable = either a non-empty api_key (cloud) or a non-empty
    // base_url (local-only providers like Ollama). Empty on both → the
    // vault snapshot still hasn't unlocked, or the user disabled every
    // key, so report Missing.
    if p.providers
        .iter()
        .any(|pr| !pr.api_key.is_empty() || !pr.base_url.is_empty())
    {
        LlmAvailability::Configured
    } else {
        LlmAvailability::Missing
    }
}

/// Owns the cached availability and exposes a `watch::Receiver` so the
/// chunk_relay task can react on every transition.
pub struct LlmAvailabilityRegistry {
    cache: SharedAvailableCache,
    state: watch::Sender<LlmAvailability>,
}

impl LlmAvailabilityRegistry {
    /// Build a registry seeded with the cache's current state.
    pub fn new(cache: SharedAvailableCache) -> Self {
        let initial = match cache.try_read() {
            Ok(g) => compute(g.bootstrap.as_ref(), g.providers.as_ref()),
            Err(_) => LlmAvailability::Unspecified,
        };
        let (state, _) = watch::channel(initial);
        Self { cache, state }
    }

    /// Snapshot the current availability.
    pub fn current(&self) -> LlmAvailability {
        *self.state.borrow()
    }

    /// Subscribe to availability changes. Same value does NOT re-fire
    /// (we only `send` on actual transitions — see [`Self::spawn_poller`]).
    pub fn subscribe(&self) -> watch::Receiver<LlmAvailability> {
        self.state.subscribe()
    }

    /// Spawn the background poller. Re-evaluates `compute()` every
    /// [`POLL_INTERVAL`]; if the result differs from the current state,
    /// the watch channel fans out to all subscribers. If `try_read`
    /// fails (cache is being mutated), the previous state is preserved
    /// and the tick is skipped — the poller never blocks.
    pub fn spawn_poller(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut ticker = interval(POLL_INTERVAL);
            ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
            loop {
                ticker.tick().await;
                let next = match self.cache.try_read() {
                    Ok(g) => compute(g.bootstrap.as_ref(), g.providers.as_ref()),
                    Err(_) => continue,
                };
                if next != *self.state.borrow() {
                    let _ = self.state.send(next);
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mqtt::available_cache::AvailableResourceCache;
    use acowork_core::mqtt_proto::{BootstrapState, ProviderRef};

    fn bs(phase: BootstrapPhase) -> BootstrapState {
        BootstrapState {
            protocol_version: 1,
            instance_id: "8c9d0e1f-2a3b-4024-8354-046e7f8a9b0c".to_string(),
            version: 1,
            phase: phase as i32,
            phase_detail: String::new(),
            issued_at_ms: 0,
        }
    }

    fn providers(entries: Vec<ProviderRef>) -> AvailableProviders {
        AvailableProviders {
            version: 1,
            providers: entries,
            #[allow(deprecated)]
            default_compact_model: None,
            default_compact_models: vec![],
        }
    }

    fn provider(id: &str, api_key: &str, base_url: &str) -> ProviderRef {
        ProviderRef {
            id: id.to_string(),
            base_url: base_url.to_string(),
            protocol_type: 1,
            models: vec![],
            compact_model: String::new(),
            custom: false,
            api_key: api_key.to_string(),
            account_id: String::new(),
        }
    }

    #[test]
    fn loading_when_bootstrap_unset() {
        assert_eq!(compute(None, None), LlmAvailability::Loading);
    }

    #[test]
    fn loading_when_bootstrap_booting() {
        let s = bs(BootstrapPhase::Booting);
        assert_eq!(compute(Some(&s), None), LlmAvailability::Loading);
    }

    #[test]
    fn loading_when_bootstrap_degraded() {
        let s = bs(BootstrapPhase::Degraded);
        assert_eq!(
            compute(Some(&s), None),
            LlmAvailability::Loading,
            "degraded vault → still loading, no misconfig banner"
        );
    }

    #[test]
    fn loading_when_bootstrap_failed() {
        let s = bs(BootstrapPhase::Failed);
        assert_eq!(compute(Some(&s), None), LlmAvailability::Loading);
    }

    #[test]
    fn loading_when_providers_none() {
        // `bootstrap=Ready` but `providers=None` is the retained
        // re-delivery race after a (remote) Gateway restart — not a
        // real misconfiguration. See the long-form comment in
        // `compute()` and ADR-059 §5.3.
        let s = bs(BootstrapPhase::Ready);
        assert_eq!(compute(Some(&s), None), LlmAvailability::Loading);
    }

    #[test]
    fn missing_when_providers_empty() {
        let s = bs(BootstrapPhase::Ready);
        let p = providers(vec![]);
        assert_eq!(compute(Some(&s), Some(&p)), LlmAvailability::Missing);
    }

    #[test]
    fn missing_when_all_unusable() {
        let s = bs(BootstrapPhase::Ready);
        let p = providers(vec![provider("p1", "", ""), provider("p2", "", "")]);
        assert_eq!(compute(Some(&s), Some(&p)), LlmAvailability::Missing);
    }

    #[test]
    fn configured_when_api_key_present() {
        let s = bs(BootstrapPhase::Ready);
        let p = providers(vec![
            provider("p1", "", ""),
            provider("p2", "sk-valid", "https://api.example.com"),
        ]);
        assert_eq!(compute(Some(&s), Some(&p)), LlmAvailability::Configured);
    }

    #[test]
    fn configured_when_local_base_url_only() {
        let s = bs(BootstrapPhase::Ready);
        let p = providers(vec![provider("local-ollama", "", "http://localhost:11434")]);
        assert_eq!(
            compute(Some(&s), Some(&p)),
            LlmAvailability::Configured,
            "Ollama-style local provider is callable"
        );
    }

    #[tokio::test]
    async fn registry_emits_on_transition() {
        let cache: SharedAvailableCache =
            Arc::new(tokio::sync::RwLock::new(AvailableResourceCache::new()));
        let registry = Arc::new(LlmAvailabilityRegistry::new(cache.clone()));
        let _poller = Arc::clone(&registry).spawn_poller();
        let mut rx = registry.subscribe();

        assert_eq!(
            registry.current(),
            LlmAvailability::Loading,
            "empty cache → initial Loading"
        );

        // Bootstrap becomes Ready but providers retained has not yet
        // landed — this is the post-restart retained race window, NOT
        // a real misconfiguration. State must stay Loading until the
        // providers payload arrives (see `compute()` long-form
        // comment), with no spurious transition to Missing.
        {
            let mut g = cache.write().await;
            g.bootstrap = Some(bs(BootstrapPhase::Ready));
        }
        // Drain any pending state-change notifications so the next
        // assertion only sees transitions caused by the providers
        // write below.
        rx.borrow_and_update();
        // Let one poll tick run, then assert no transition fired and
        // the current state is still Loading.
        tokio::time::sleep(POLL_INTERVAL * 2).await;
        assert_eq!(
            *rx.borrow(),
            LlmAvailability::Loading,
            "post-restart race window must stay Loading, not flash Missing"
        );

        // Add a usable provider → Configured.
        {
            let mut g = cache.write().await;
            g.providers = Some(providers(vec![provider("p1", "sk-x", "https://api.test")]));
        }
        assert!(wait_for_change(&mut rx, LlmAvailability::Configured, POLL_INTERVAL * 5).await);
    }

    #[test]
    fn wire_roundtrip() {
        for a in [
            LlmAvailability::Unspecified,
            LlmAvailability::Loading,
            LlmAvailability::Configured,
            LlmAvailability::Missing,
        ] {
            assert_eq!(LlmAvailability::from_wire(a.as_wire()), a);
        }
    }

    async fn wait_for_change(
        rx: &mut watch::Receiver<LlmAvailability>,
        target: LlmAvailability,
        budget: Duration,
    ) -> bool {
        let deadline = std::time::Instant::now() + budget;
        loop {
            if *rx.borrow_and_update() == target {
                return true;
            }
            if std::time::Instant::now() >= deadline {
                return false;
            }
            // Wait up to one poll tick for the next change notification.
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            let tick = POLL_INTERVAL.min(remaining);
            if tokio::time::timeout(tick, rx.changed()).await.is_err() {
                continue; // re-check current value
            }
        }
    }
}
