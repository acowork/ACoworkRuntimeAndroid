//! RuntimeAgentTokenService — wraps AgentCore's atomic token counters.
//!
//! ADR-028 / ADR-040: this is the sole source of truth for token accounting.

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

use acowork_core::providers::traits::UsageInfo;

use crate::agent::agent_core::AgentCore;
use crate::usecases::agent_token::AgentTokenService;

pub struct RuntimeAgentTokenService {
    core: Arc<AgentCore>,
    /// Per-session token snapshots. Keyed by session_id.
    /// Updated by the agent loop push path; read by list_sessions.
    session_tokens: Mutex<HashMap<String, (u64, u64)>>,
}

impl RuntimeAgentTokenService {
    pub fn new(core: Arc<AgentCore>) -> Self {
        Self {
            core,
            session_tokens: Mutex::new(HashMap::new()),
        }
    }

    /// Record a per-session token snapshot (called from loop context push).
    pub async fn record_session_tokens(&self, session_id: &str, input: u64, output: u64) {
        let mut map = self.session_tokens.lock().await;
        map.insert(session_id.to_string(), (input, output));
    }

    /// Remove a session's token tracking (e.g. on session delete).
    pub async fn forget_session(&self, session_id: &str) {
        let mut map = self.session_tokens.lock().await;
        map.remove(session_id);
    }
}

impl AgentTokenService for RuntimeAgentTokenService {
    fn accumulate_llm_usage(&self, usage: &UsageInfo) {
        self.core.accumulate_llm_usage(usage);
    }

    fn merge_token_totals(&self, scanned: (Option<u64>, Option<u64>, Option<u64>, Option<u64>)) {
        self.core.merge_token_totals(scanned);
    }

    fn agent_token_totals(&self) -> (u64, u64, u64, u64) {
        self.core.agent_token_totals()
    }

    fn session_token_totals(&self, session_id: &str) -> Option<(u64, u64)> {
        self.session_tokens
            .try_lock()
            .ok()
            .and_then(|map| map.get(session_id).copied())
    }
}

// ── Test helpers ────────────────────────────────────────────────────

/// No-op token service for tests that don't need real token accounting.
#[cfg(test)]
pub(crate) struct NoopAgentTokenService;

#[cfg(test)]
impl AgentTokenService for NoopAgentTokenService {
    fn accumulate_llm_usage(&self, _: &UsageInfo) {}
    fn merge_token_totals(&self, _: (Option<u64>, Option<u64>, Option<u64>, Option<u64>)) {}
    fn agent_token_totals(&self) -> (u64, u64, u64, u64) {
        (0, 0, 0, 0)
    }
    fn session_token_totals(&self, _: &str) -> Option<(u64, u64)> {
        None
    }
}

// ── RuntimeAgentTokenService integration tests ───────────────────────
//
// These tests cover the wiring between `RuntimeAgentTokenService` (the
// trait impl that callers see) and the underlying `AgentCore` atomic
// counters — including the ADR-066 cache dimensions that the noop /
// in-memory test helpers deliberately do not implement.

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use acowork_core::AgentManifest;
    use acowork_core::providers::mock::MockProvider;
    use acowork_core::providers::traits::UsageInfo;

    use crate::agent::agent_core::AgentCore;
    use crate::config::RuntimeConfig;

    fn make_test_core() -> AgentCore {
        let config = RuntimeConfig {
            history_max_tokens: 8000,
            ..RuntimeConfig::default()
        };
        let manifest = AgentManifest::from_toml(
            r#"
            agent_id = "com.test.token-service"
            version = "1.0.0"
            name = "Token service test"
            description = "ADR-066 token service integration"
            author = "test"
            runtime_version = "0.1.0"

            [llm]
            provider = "mock"
            model = "test-model"
            "#,
        )
        .unwrap();
        let provider = Arc::new(MockProvider::single_text("test"));
        AgentCore::new(config, manifest, provider, vec![])
    }

    /// `accumulate_llm_usage` and `agent_token_totals` round-trip the
    /// ADR-066 cache dimensions end-to-end: write four counters through
    /// the trait method, read them back through the trait method.
    #[tokio::test]
    async fn test_runtime_token_service_cache_round_trip() {
        let svc = RuntimeAgentTokenService::new(Arc::new(make_test_core()));

        assert_eq!(svc.agent_token_totals(), (0, 0, 0, 0));

        svc.accumulate_llm_usage(&UsageInfo {
            prompt_tokens: 1000,
            completion_tokens: 200,
            cache_read_tokens: 400,
            cache_write_tokens: 100,
            ..Default::default()
        });
        svc.accumulate_llm_usage(&UsageInfo {
            prompt_tokens: 3500,
            completion_tokens: 450,
            cache_read_tokens: 1200,
            cache_write_tokens: 0,
            ..Default::default()
        });

        assert_eq!(
            svc.agent_token_totals(),
            (4500, 650, 1600, 100),
            "RuntimeAgentTokenService must forward cache counters verbatim to AgentCore"
        );
    }

    /// `record_session_tokens` / `forget_session` / `session_token_totals`
    /// are the per-session path that the loop_context push path depends
    /// on. A `forget_session` that leaks an entry would keep stale
    /// (input, output) snapshots on disk forever.
    #[tokio::test]
    async fn test_runtime_token_service_session_tokens_lifecycle() {
        let svc = RuntimeAgentTokenService::new(Arc::new(make_test_core()));

        // Empty: no session tracked yet.
        assert_eq!(svc.session_token_totals("sess-1"), None);

        // record_session_tokens inserts.
        svc.record_session_tokens("sess-1", 1234, 567).await;
        assert_eq!(svc.session_token_totals("sess-1"), Some((1234, 567)));

        // Updating overwrites (not atomic-max — that's for agent-level totals).
        svc.record_session_tokens("sess-1", 9999, 8888).await;
        assert_eq!(
            svc.session_token_totals("sess-1"),
            Some((9999, 8888)),
            "second record_session_tokens replaces prior snapshot"
        );

        // forget_session removes.
        svc.forget_session("sess-1").await;
        assert_eq!(
            svc.session_token_totals("sess-1"),
            None,
            "forget_session must drop the entry"
        );

        // forget_session on unknown id is a no-op (does not panic).
        svc.forget_session("never-existed").await;
        assert_eq!(svc.session_token_totals("never-existed"), None);
    }
}
