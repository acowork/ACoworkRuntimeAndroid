//! Debug protocol use case service (ADR-040 + ADR-048).
//!
//! Defines the [`DebugService`] trait — the business-logic abstraction
//! that the new HTTP routes (`http/debug.rs`) and MQTT events publisher
//! both depend on. The implementation
//! [`crate::usecases::RuntimeDebugService`] (in `debug_service_impl.rs`)
//! delegates to the handler functions in
//! [`crate::debug::handlers`].
//!
//! ## Why a trait (ADR-040)
//!
//! Before ADR-048, the WebSocket server in `debug/server.rs` reached into
//! the `DebugController` directly via closures. HTTP routes would have to
//! replicate that logic or import a concrete server struct. By extracting
//! the business logic into a trait, every transport (HTTP, MQTT, future
//! CLI) depends only on the abstract `DebugService` — keeping the
//! "external adapter → use case → internal module" layering of ADR-040.
//!
//! ## Migration phasing (ADR-048)
//!
//! - **D1** (this commit): trait + impl exist, but are not yet called by
//!   any transport. The WebSocket server still owns the routing closure.
//! - **D2**: HTTP routes call `DebugService` via the late-bind slot.
//! - **D3**: MQTT events publisher is added (transport-level, not via
//!   the trait).
//! - **D4**: WebSocket server is deleted; only HTTP + MQTT remain.
//!
//! All 10 currently-implemented handlers are migrated. The remaining 12
//! (breakpoints / messages / skills / recording) are not in scope for
//! this refactor — they can be added to the trait later without changing
//! the transport wiring.

use async_trait::async_trait;

use crate::debug::handlers::{DebugError, DebugStateSnapshot, ReExecuteOutcome, StepOutcome};
use crate::debug::protocol::{
    GetContextSnapshotParams, GetContextSnapshotResult, GetSectionParams, GetSectionResult,
    PatchContextParams, RewindParams, RewindResult, StepGranularity,
};

// Re-export `DebugError` for downstream callers (HTTP handlers, MQTT
// publisher) — keeps the trait's error story uniform.
pub use crate::debug::handlers::DebugError as DebugServiceError;

/// The debug-protocol business-logic trait.
///
/// Each method maps 1-to-1 to a `debugger.*` RPC method that the
/// DebugProtocol previously exposed over WebSocket. Methods return
/// either a typed success value or [`DebugError`].
///
/// Implementations are expected to acquire the per-session `DebugController`
/// lock internally — the trait hides locking from the transport.
#[async_trait]
pub trait DebugService: Send + Sync {
    /// `debugger.resume` — transition any state → Running.
    async fn resume(&self, session_id: &str) -> Result<(), DebugError>;

    /// `debugger.pause` — transition any state → Paused; wakes blocked
    /// `select!` branches via control_notify.
    async fn pause(&self, session_id: &str) -> Result<(), DebugError>;

    /// `debugger.step` — execute one step from Paused → Stepping.
    /// Returns whether the step was accepted or ignored (e.g. not paused).
    async fn step(
        &self,
        session_id: &str,
        granularity: StepGranularity,
    ) -> Result<StepOutcome, DebugError>;

    /// `debugger.stop` — terminate the agent loop.
    async fn stop(&self, session_id: &str) -> Result<(), DebugError>;

    /// `debugger.getState` — full state snapshot.
    async fn get_state(&self, session_id: &str) -> Result<DebugStateSnapshot, DebugError>;

    /// `debugger.getContextSnapshot` — snapshot metadata for one iteration.
    async fn get_context_snapshot(
        &self,
        session_id: &str,
        params: GetContextSnapshotParams,
    ) -> Result<GetContextSnapshotResult, DebugError>;

    /// `debugger.getSection` — full section content for one iteration.
    async fn get_section(
        &self,
        session_id: &str,
        params: GetSectionParams,
    ) -> Result<GetSectionResult, DebugError>;

    /// `debugger.rewind` — rewind to a previous iteration. If currently
    /// Stopped, transitions to Paused first.
    async fn rewind(
        &self,
        session_id: &str,
        params: RewindParams,
    ) -> Result<RewindResult, DebugError>;

    /// `debugger.patchContext` — merge patches into the snapshot; patches
    /// persist until `reExecute` is called.
    async fn patch_context(
        &self,
        session_id: &str,
        params: PatchContextParams,
    ) -> Result<(), DebugError>;

    /// `debugger.reExecute` — re-run the current iteration with any
    /// pending patches applied.
    async fn re_execute(&self, session_id: &str) -> Result<ReExecuteOutcome, DebugError>;

    /// ADR-063 §3.7.5 L2 reload — re-read every `prompts/<file>.md` from
    /// disk and overwrite the per-agent `AgentCore` `Arc<RwLock<Option<String>>>`
    /// fields so the next LLM call uses the new directive. **Agent-wide**
    /// (not per-session) because `AgentCore` is shared across every
    /// session of the same agent. The Debug panel calls this after
    /// `PUT /agents/{id}/prompts/{name}`; Phase C also calls it when
    /// DevMode is enabled so an existing install's edits take effect
    /// without a Runtime restart.
    ///
    /// Errors are surfaced as `DebugError::Internal` — the failure mode
    /// here is filesystem (`prompts/` missing mid-reload, IO error).
    /// The HTTP transport maps `Internal` → 422 (see ADR-048 §error
    /// mapping table in `http/debug.rs`).
    async fn reload_prompts(&self) -> Result<(), DebugError>;
}
