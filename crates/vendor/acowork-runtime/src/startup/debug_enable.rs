//! Runtime DevMode activation — shared between startup and HTTP route.
//!
//! Originally DevMode was a startup-only flag (`config.dev_mode`); the
//! Runtime's debug HTTP routes (`/api/debug/*`) returned 503 if the
//! agent was started without `--dev-mode`. The legacy workaround was
//! to restart the agent, which the Desktop exposed as the "Restart in
//! Debug" context-menu action (now deprecated — see ADR-048 follow-up).
//!
//! `enable_debug_mode_and_fill_slot` is the idempotent entry point
//! used in both places:
//!
//!   - **Startup path** (`subsystems::phase_c_spawn_subsystems`) when
//!     the Runtime was launched with `dev_mode: true`. The slot is
//!     populated at boot, so the very first `/api/debug/*` request
//!     already has a service behind it.
//!   - **Runtime path** (`http/debug::post_enable`) — Gateway proxies
//!     `POST /api/agents/{id}/debug/enable` here when the Desktop
//!     flips DevMode on for an agent that was started without it.
//!
//! The helper takes only the already-wired slots (debug service slot,
//! MQTT client slot) and the SessionManager handle, so both call sites
//! are symmetric: no HTTP server restart, no agent restart, no
//! duplicate event-bus registration.
//!
//! Idempotency: the inner `SessionManager::enable_debug_mode` early-
// returns when `runtime_debug_handles` is already set; this helper layers
//! an additional guard on the debug service slot so the caller knows
//! whether it triggered the wiring or just confirmed it was already
//! active. Either way the HTTP routes become usable on return.

use std::sync::Arc;

use crate::http::server::{SharedMqttClientSlot, SharedSessionManagerSlot};

/// Outcome of [`enable_debug_mode_and_fill_slot`] — distinguishes a
/// fresh activation from a no-op confirmation so the Desktop can show
/// a different toast / refresh different state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DebugEnableOutcome {
    /// DevMode was already active (slot was non-empty before the call).
    /// No wiring happened; the helper just confirmed the existing state.
    AlreadyEnabled,
    /// DevMode was activated by this call. Per-session controllers,
    /// event senders, MQTT publisher, and the debug service slot have
    /// all been populated.
    NewlyEnabled,
    /// SessionManager handle was missing from the slot — Runtime
    /// reached this code path before Phase B finished wiring
    /// SessionManager. The caller should surface a 503 and retry.
    SessionManagerUnavailable,
}

/// Idempotently enable DevMode and publish the built `DebugService`
/// into the HTTP server's late-bind slot.
///
/// `debug_service_slot` is filled only when the call actually flipped
/// DevMode on. If the slot was already populated the helper returns
/// [`DebugEnableOutcome::AlreadyEnabled`] without touching the
/// underlying wiring.
///
/// `debug_port` is retained for API parity with the original config
/// knob but is unused at runtime — ADR-048 removed the legacy WS
/// listener and DevMode is now pure HTTP + MQTT.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn enable_debug_mode_and_fill_slot(
    debug_service_slot: &Arc<tokio::sync::Mutex<Option<Arc<dyn crate::usecases::DebugService>>>>,
    mqtt_client_slot: &SharedMqttClientSlot,
    session_manager_slot: &SharedSessionManagerSlot,
    debug_port: u32,
) -> DebugEnableOutcome {
    // Idempotency guard — the slot is the authoritative "is DevMode
    // active?" signal for the HTTP layer (the underlying
    // SessionManager.runtime_debug_handles is private). If the slot is
    // already filled, DevMode was activated at startup or by an
    // earlier enable call; report AlreadyEnabled and bail.
    {
        let guard = debug_service_slot.lock().await;
        if guard.is_some() {
            return DebugEnableOutcome::AlreadyEnabled;
        }
    }

    // Resolve the SessionManager handle from the late-bind slot.
    // Phase B writes the handle in once, so by the time the HTTP
    // route can be reached the slot should always be populated; the
    // Option wrapper exists for tests / partial boots.
    let session_manager = {
        let guard = session_manager_slot.read().await;
        match guard.as_ref() {
            Some(sm) => sm.clone(),
            None => return DebugEnableOutcome::SessionManagerUnavailable,
        }
    };

    // Snapshot the MQTT client (if connected). `SharedRuntimeMqttClient`
    // is `Arc<Mutex<RuntimeMqttClient>>`; we lock briefly to clone the
    // inner `RuntimeMqttClient` (which is `Clone` — it carries cheap
    // Arc internals), then re-wrap in a fresh `Arc` so the caller
    // signature `Option<Arc<RuntimeMqttClient>>` is satisfied.
    // enable_debug_mode tolerates None — debug events just won't
    // reach the broker in that case (the same warning is logged
    // inside the SessionManager).
    let mqtt_client: Option<Arc<crate::mqtt::RuntimeMqttClient>> = {
        let guard = mqtt_client_slot.lock().await;
        match guard.as_ref() {
            Some(shared) => {
                let client = shared.lock().await.clone();
                Some(Arc::new(client))
            }
            None => None,
        }
    };

    // Run the wiring. enable_debug_mode is internally idempotent
    // (early-returns when runtime_debug_handles is Some) but we
    // already gated on the slot above, so this always runs the
    // first-time path here.
    let mut sm = session_manager.lock().await;
    sm.enable_debug_mode(debug_port, mqtt_client).await;
    drop(sm);

    // Publish the freshly-built DebugService into the HTTP slot.
    // debug_service() is the canonical accessor (same one Phase C
    // uses at startup).
    let svc_opt = session_manager.lock().await.debug_service();
    match svc_opt {
        Some(svc) => {
            let svc_dyn: Arc<dyn crate::usecases::DebugService> = svc;
            *debug_service_slot.lock().await = Some(svc_dyn);
            tracing::info!(
                debug_port,
                "DevMode enabled at runtime — debug service slot populated"
            );
            DebugEnableOutcome::NewlyEnabled
        }
        None => {
            // Should not happen — enable_debug_mode always builds a
            // service before returning. Log loudly so the on-call
            // engineer sees the asymmetry, but report NewlyEnabled so
            // the Desktop can retry; the slot will be filled on a
            // subsequent enable call (after the wiring bug is fixed).
            tracing::error!("enable_debug_mode returned without a DebugService — slot stays empty");
            DebugEnableOutcome::NewlyEnabled
        }
    }
}

/// Outcome of [`disable_debug_mode_and_clear_slot`] — distinguishes a
/// real teardown from a no-op confirmation so the Desktop can decide
/// whether to refresh agent state (Gateway side) or just treat the
/// click as a confirmation toast (Runtime was already off).
///
/// The triple mirrors [`DebugEnableOutcome`] so the two HTTP handlers
/// (`/api/debug/enable` and `/api/debug/disable`) read uniformly. The
/// `SessionManagerUnavailable` variant is shared verbatim — it has
/// the same semantic on both paths (Phase B hasn't wired the slot
/// yet, retry shortly).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DebugDisableOutcome {
    /// DevMode was active and has now been torn down by this call —
    /// the per-session controllers, event senders, runtime handles,
    /// and the late-bind DebugService slot are all cleared.
    NewlyDisabled,
    /// DevMode was already off before this call — the helper just
    /// confirmed the state. No wiring happened.
    AlreadyDisabled,
    /// SessionManager handle was missing from the slot — Runtime
    /// reached this code path before Phase B finished wiring
    /// SessionManager. The caller should surface a 503 and retry.
    SessionManagerUnavailable,
}

/// Idempotently tear down DevMode and clear the HTTP server's
/// late-bind DebugService slot. Symmetric counterpart to
/// [`enable_debug_mode_and_fill_slot`].
///
/// The function takes only the already-wired slots (debug service
/// slot + SessionManager handle), matching the enable helper's
/// signature, so the HTTP route handler stays a thin wire-format
/// wrapper. No HTTP server restart, no agent restart, no event-bus
/// unregistration step (the broadcast channel is dropped when the
/// last `DebugEventSender` reference inside `SessionManager` is
/// cleared by `disable_debug_mode`).
///
/// Idempotency: if DevMode is already off (the slot is empty), the
/// helper returns [`DebugDisableOutcome::AlreadyDisabled`] without
/// touching SessionManager. This matches the contract of
/// [`enable_debug_mode_and_fill_slot`] so the two endpoints form a
/// symmetric pair.
pub(crate) async fn disable_debug_mode_and_clear_slot(
    debug_service_slot: &Arc<tokio::sync::Mutex<Option<Arc<dyn crate::usecases::DebugService>>>>,
    session_manager_slot: &SharedSessionManagerSlot,
) -> DebugDisableOutcome {
    // Idempotency guard — symmetric to the enable helper. If the
    // slot is already empty, DevMode was never enabled (or has
    // already been disabled by an earlier call); report
    // `AlreadyDisabled` and bail without touching SessionManager.
    {
        let guard = debug_service_slot.lock().await;
        if guard.is_none() {
            return DebugDisableOutcome::AlreadyDisabled;
        }
    }

    // Resolve the SessionManager handle. Phase B writes the handle
    // in once; if it is missing we cannot push `DisableDebugMode` to
    // live sessions and the call is unsafe to attempt, so we report
    // `SessionManagerUnavailable` and let the caller 503 + retry.
    let session_manager = {
        let guard = session_manager_slot.read().await;
        match guard.as_ref() {
            Some(sm) => sm.clone(),
            None => return DebugDisableOutcome::SessionManagerUnavailable,
        }
    };

    // Tear down the per-session observers, then clear the late-bind
    // DebugService slot. The slot is cleared *after* the inner
    // teardown so it reflects the true state by the time the HTTP
    // handler returns. If `disable_debug_mode` itself fails the slot
    // would leak (stale Service pointing at torn-down state), but the
    // method has no failure path today — it is pure in-memory state
    // manipulation.
    {
        let mut sm = session_manager.lock().await;
        sm.disable_debug_mode().await;
    }

    *debug_service_slot.lock().await = None;
    tracing::info!(
        "DevMode disabled at runtime — debug service slot cleared, /api/debug/* routes return 503 again"
    );
    DebugDisableOutcome::NewlyDisabled
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::agent_core::{AgentCore, BuiltinToolEntry};
    use crate::agent::session::session_manager::{SessionManager, SessionManagerConfig};
    use crate::config::RuntimeConfig;
    use acowork_core::providers::mock::MockProvider;
    use std::sync::Arc;

    /// Build a minimal `SessionManager` for unit tests. Mirrors the
    /// helper used by `session_manager::tests::enable_debug_mode_populates_event_senders_for_existing_sessions`
    /// so the helper-under-test can be exercised without standing up
    /// the full Phase A/B/C boot sequence.
    async fn build_test_session_manager() -> Arc<tokio::sync::Mutex<SessionManager>> {
        let config = RuntimeConfig::default();
        let manifest = acowork_core::AgentManifest::from_toml(
            r#"
            agent_id = "com.test.debug_enable"
            version = "1.0.0"
            name = "Test debug-enable"
            description = "Pin enable_debug_mode_and_fill_slot behavior"
            author = "test"
            runtime_version = "0.1.0"

            [llm]
            provider = "mock"
            model = "test-model"
            "#,
        )
        .unwrap();
        let provider = Arc::new(MockProvider::single_text("test"));
        let core = Arc::new(AgentCore::new(
            config,
            manifest,
            provider,
            Vec::<BuiltinToolEntry>::new(),
        ));
        Arc::new(tokio::sync::Mutex::new(SessionManager::new(
            core,
            SessionManagerConfig::default(),
        )))
    }

    /// 1. First call fills the slot and returns `NewlyEnabled`.
    /// 2. Second call is a no-op and returns `AlreadyEnabled`.
    /// 3. `SessionManagerUnavailable` is reported when the slot is empty.
    /// 4. The handler-tolerated `None` MQTT client does not panic.
    #[tokio::test]
    async fn enable_debug_mode_and_fill_slot_is_idempotent() {
        let session_manager = build_test_session_manager().await;
        let mqtt_client_slot: SharedMqttClientSlot = Arc::new(tokio::sync::Mutex::new(None));
        let session_manager_slot: SharedSessionManagerSlot =
            Arc::new(tokio::sync::RwLock::new(Some(session_manager.clone())));
        let debug_service_slot: Arc<
            tokio::sync::Mutex<Option<Arc<dyn crate::usecases::DebugService>>>,
        > = Arc::new(tokio::sync::Mutex::new(None));

        // 1. Empty slot → NewlyEnabled.
        let outcome = enable_debug_mode_and_fill_slot(
            &debug_service_slot,
            &mqtt_client_slot,
            &session_manager_slot,
            19876,
        )
        .await;
        assert_eq!(
            outcome,
            DebugEnableOutcome::NewlyEnabled,
            "first call should report NewlyEnabled"
        );
        assert!(
            debug_service_slot.lock().await.is_some(),
            "slot should be filled after first call"
        );

        // 2. Non-empty slot → AlreadyEnabled (idempotency).
        let outcome2 = enable_debug_mode_and_fill_slot(
            &debug_service_slot,
            &mqtt_client_slot,
            &session_manager_slot,
            19876,
        )
        .await;
        assert_eq!(
            outcome2,
            DebugEnableOutcome::AlreadyEnabled,
            "second call should report AlreadyEnabled"
        );

        // 3. Empty session_manager_slot → SessionManagerUnavailable.
        let empty_sm_slot: SharedSessionManagerSlot = Arc::new(tokio::sync::RwLock::new(None));
        let fresh_slot: Arc<tokio::sync::Mutex<Option<Arc<dyn crate::usecases::DebugService>>>> =
            Arc::new(tokio::sync::Mutex::new(None));
        let outcome3 =
            enable_debug_mode_and_fill_slot(&fresh_slot, &mqtt_client_slot, &empty_sm_slot, 19876)
                .await;
        assert_eq!(
            outcome3,
            DebugEnableOutcome::SessionManagerUnavailable,
            "missing SessionManager should report SessionManagerUnavailable"
        );
        assert!(
            fresh_slot.lock().await.is_none(),
            "slot should stay empty when SessionManager is unavailable"
        );
    }

    /// DebugService is callable through the slot after a single
    /// `enable_debug_mode_and_fill_slot` call — this is the contract
    /// the HTTP `/api/debug/*` routes depend on.
    #[tokio::test]
    async fn filled_slot_serves_debug_state_rpc() {
        let session_manager = build_test_session_manager().await;
        let mqtt_client_slot: SharedMqttClientSlot = Arc::new(tokio::sync::Mutex::new(None));
        let session_manager_slot: SharedSessionManagerSlot =
            Arc::new(tokio::sync::RwLock::new(Some(session_manager.clone())));
        let debug_service_slot: Arc<
            tokio::sync::Mutex<Option<Arc<dyn crate::usecases::DebugService>>>,
        > = Arc::new(tokio::sync::Mutex::new(None));

        let outcome = enable_debug_mode_and_fill_slot(
            &debug_service_slot,
            &mqtt_client_slot,
            &session_manager_slot,
            0,
        )
        .await;
        assert_eq!(outcome, DebugEnableOutcome::NewlyEnabled);

        // The slot now holds a real DebugService. Calling a no-op
        // RPC (state with a non-existent session_id) should return
        // SessionNotFound, NOT 503 / "Debug service not ready".
        let svc = debug_service_slot
            .lock()
            .await
            .as_ref()
            .expect("slot must be populated")
            .clone();
        let err = svc
            .get_state("nonexistent-session")
            .await
            .expect_err("state for unknown session should be an error");
        assert!(
            matches!(err, crate::debug::handlers::DebugError::SessionNotFound(_)),
            "expected SessionNotFound, got {:?}",
            err
        );
    }

    /// `disable_debug_mode_and_clear_slot` round-trip:
    /// 1. With an empty slot: returns `AlreadyDisabled` and does
    ///    not touch SessionManager.
    /// 2. With a filled slot: returns `NewlyDisabled`, empties the
    ///    slot, and clears SessionManager-side debug state.
    /// 3. With an empty SessionManager slot: returns
    ///    `SessionManagerUnavailable` and the service slot stays
    ///    as it was (we leave the stale Service in place so a
    ///    retry can re-issue the call after Phase B lands — same
    ///    pattern as `enable_*` on missing SessionManager).
    #[tokio::test]
    async fn disable_debug_mode_and_clear_slot_is_idempotent() {
        let session_manager = build_test_session_manager().await;
        let mqtt_client_slot: SharedMqttClientSlot = Arc::new(tokio::sync::Mutex::new(None));
        let session_manager_slot: SharedSessionManagerSlot =
            Arc::new(tokio::sync::RwLock::new(Some(session_manager.clone())));
        let debug_service_slot: Arc<
            tokio::sync::Mutex<Option<Arc<dyn crate::usecases::DebugService>>>,
        > = Arc::new(tokio::sync::Mutex::new(None));

        // 1. Empty slot → AlreadyDisabled.
        let outcome =
            disable_debug_mode_and_clear_slot(&debug_service_slot, &session_manager_slot).await;
        assert_eq!(
            outcome,
            DebugDisableOutcome::AlreadyDisabled,
            "empty slot should report AlreadyDisabled"
        );

        // 2. Enable, then disable → NewlyDisabled + empty slot.
        let _ = enable_debug_mode_and_fill_slot(
            &debug_service_slot,
            &mqtt_client_slot,
            &session_manager_slot,
            0,
        )
        .await;
        assert!(
            debug_service_slot.lock().await.is_some(),
            "enable should have populated the slot"
        );
        let outcome2 =
            disable_debug_mode_and_clear_slot(&debug_service_slot, &session_manager_slot).await;
        assert_eq!(
            outcome2,
            DebugDisableOutcome::NewlyDisabled,
            "after enable, disable should report NewlyDisabled"
        );
        assert!(
            debug_service_slot.lock().await.is_none(),
            "slot should be empty after disable"
        );

        // SessionManager-side state should match: the runtime
        // handles and per-session controller/sender maps are all
        // empty.
        {
            let sm = session_manager.lock().await;
            assert!(
                sm.runtime_debug_handles.is_none(),
                "runtime_debug_handles should be cleared after disable"
            );
            let controllers = sm.debug_controllers.read().await;
            assert!(
                controllers.is_empty(),
                "debug_controllers should be cleared after disable"
            );
            let senders = sm.debug_event_senders.read().await;
            assert!(
                senders.is_empty(),
                "debug_event_senders should be cleared after disable"
            );
        }

        // 3. Missing SessionManager handle → SessionManagerUnavailable.
        // We populate a fresh debug_service_slot so the helper is
        // not short-circuited by the idempotency guard; the guard
        // then sees a non-empty slot and tries to acquire the
        // SessionManager slot, which is empty.
        let leaked_slot: Arc<tokio::sync::Mutex<Option<Arc<dyn crate::usecases::DebugService>>>> =
            Arc::new(tokio::sync::Mutex::new(Some(Arc::new(
                crate::usecases::RuntimeDebugService::new(
                    Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new())),
                    Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new())),
                ),
            ))));
        let empty_sm_slot: SharedSessionManagerSlot = Arc::new(tokio::sync::RwLock::new(None));
        let outcome3 = disable_debug_mode_and_clear_slot(&leaked_slot, &empty_sm_slot).await;
        assert_eq!(
            outcome3,
            DebugDisableOutcome::SessionManagerUnavailable,
            "missing SessionManager should report SessionManagerUnavailable"
        );
    }

    /// Calling `disable_*` is safe to issue twice in a row — the
    /// second call short-circuits to `AlreadyDisabled` and the slot
    /// stays empty. This is the contract the Desktop relies on when
    /// the user double-clicks the "Exit Debug" button.
    #[tokio::test]
    async fn disable_is_safe_to_double_call() {
        let session_manager = build_test_session_manager().await;
        let mqtt_client_slot: SharedMqttClientSlot = Arc::new(tokio::sync::Mutex::new(None));
        let session_manager_slot: SharedSessionManagerSlot =
            Arc::new(tokio::sync::RwLock::new(Some(session_manager.clone())));
        let debug_service_slot: Arc<
            tokio::sync::Mutex<Option<Arc<dyn crate::usecases::DebugService>>>,
        > = Arc::new(tokio::sync::Mutex::new(None));

        let _ = enable_debug_mode_and_fill_slot(
            &debug_service_slot,
            &mqtt_client_slot,
            &session_manager_slot,
            0,
        )
        .await;

        let first =
            disable_debug_mode_and_clear_slot(&debug_service_slot, &session_manager_slot).await;
        assert_eq!(first, DebugDisableOutcome::NewlyDisabled);
        let second =
            disable_debug_mode_and_clear_slot(&debug_service_slot, &session_manager_slot).await;
        assert_eq!(
            second,
            DebugDisableOutcome::AlreadyDisabled,
            "second disable should be a no-op"
        );
        assert!(
            debug_service_slot.lock().await.is_none(),
            "slot should stay empty after double disable"
        );
    }
}
