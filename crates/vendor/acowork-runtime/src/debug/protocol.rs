//! Shared data types for the Debug Protocol.
//!
//! ADR-048: the JSON-RPC 2.0 framing (over WebSocket) was removed.
//! These types are the transport-neutral DTOs shared by:
//! - debug/handlers.rs (business logic)
//! - http/debug.rs (HTTP REST routes serialize them as JSON)
//! - debug/events.rs (DebugEvent payloads)
//! - mqtt/debug_events.rs (protobuf encoding)
//!
//! See docs/design/10-debug-protocol.md and
//! docs/adr/zh/ADR-048-debug-protocol-mqtt-http.md.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

// ── Execution Control ─────────────────────────────────────────────────
// ── Execution Control Methods ─────────────────────────────────────────

/// Parameters for `debugger.step`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepParams {
    /// Step granularity (iteration or phase)
    #[serde(default = "default_granularity")]
    pub granularity: StepGranularity,
}

fn default_granularity() -> StepGranularity {
    StepGranularity::Iteration
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StepGranularity {
    Iteration,
    Phase,
}

// ── State Query Types ─────────────────────────────────────────────────

/// Debug execution phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum DebugPhase {
    BudgetCheck,
    BuildContext,
    LlmCall,
    ParseResponse,
    ToolExecution,
    AppendHistory,
    Idle,
}

/// Result of `debugger.getState`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetStateResult {
    pub iteration: u32,
    pub phase: DebugPhase,
    pub messages: Vec<serde_json::Value>,
    pub snapshot_ids: Vec<String>,
    pub usage: DebugUsage,
    /// Whether the debug controller is currently paused
    pub paused: bool,
    /// Current execution state: "Running", "Paused", "Stepping", or "Stopped"
    pub state: String,
}

/// Token usage summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebugUsage {
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    pub total_tokens: u64,
}

// ── Context Snapshot Types ────────────────────────────────────────────

/// Control parameters of the ChatRequest that produced a context snapshot.
///
/// ADR-054: previously invisible to the debug panel. `max_tokens` is the
/// final value after capabilities + hard-cap + safety compression in
/// `ContextBuilder::build()`; it is captured at the snapshot call site
/// (it isn't a `ContextBuilder` field).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RequestParams {
    /// Actual model used for the LLM call.
    pub model: String,
    /// Temperature override, if any (build() falls back to DEFAULT_TEMPERATURE).
    pub temperature: Option<f64>,
    /// Final max_tokens (post capping), if sent to the provider.
    pub max_tokens: Option<u32>,
    /// Reasoning effort ("auto" | "off" | "low" | "medium" | "high" | "max").
    pub reasoning_effort: Option<String>,
    /// Anthropic thinking mode ("extended" | "adaptive").
    pub thinking_mode: Option<String>,
}

/// Section metadata (same as in controller for serialization).
///
/// `key` names the section ("system_prompt", "workspace_context", ...).
/// ADR-054: `ContextSections` moved from a 7-field struct to a
/// content-addressed `Vec<SectionMeta>` so new sections (messages,
/// todo_context, workspace_prompt_file, ...) need no protocol change.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionMeta {
    pub key: String,
    pub size_bytes: usize,
    pub token_estimate: usize,
    pub hash: String,
}

/// Result of `debugger.getContextSnapshot`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetContextSnapshotResult {
    pub iteration: u32,
    pub built_at: String,
    pub sections: ContextSections,
    pub total_token_estimate: usize,
    pub phase: DebugPhase,
    /// ADR-054: control params of the ChatRequest that built this snapshot.
    pub request_params: RequestParams,
}

/// Context sections of one iteration (metadata only, ordered by the
/// same injection order as `ContextBuilder::build()`).
///
/// ADR-054: was a struct of 7 hardcoded fields; now a list so the UI can
/// render whatever sections the backend actually produced without a
/// frontend/backend re-deploy in lockstep.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextSections {
    pub sections: Vec<SectionMeta>,
}

/// Parameters for `debugger.getContextSnapshot` and `debugger.getSection`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetContextSnapshotParams {
    pub iteration: u32,
}

/// Parameters for `debugger.getSection`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetSectionParams {
    pub iteration: u32,
    /// One of: system_prompt, workspace_context, environment,
    /// tool_definitions, skill_instructions, retrieved_memory,
    /// identity_context
    pub section: String,
}

/// Result of `debugger.getSection`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetSectionResult {
    pub content: String,
    pub hash: String,
    pub token_count: usize,
}

// ── Context Editing Types ─────────────────────────────────────────────

/// Parameters for `debugger.rewind`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RewindParams {
    pub to_iteration: u32,
}

/// Result of `debugger.rewind`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RewindResult {
    pub rewound_to_iteration: u32,
    pub messages_trimmed_to: usize,
}

/// Parameters for `debugger.patchContext`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatchContextParams {
    pub patches: PatchSet,
}

/// Set of patches to apply to context sections.
///
/// ADR-054: was a struct of 7 `Option<T>` fields; now a content-addressed
/// `HashMap<String, PatchValue>` so new sections (messages, todo_context,
/// ambiguous_confirmation_hint, workspace_prompt_file) need no struct
/// change. `apply_patches()` validates keys against the known section
/// list and rejects unknown ones (typo safety).
///
/// Multiple `patchContext` calls are merged incrementally: each call
/// overwrites only the sections it specifies, leaving previously patched
/// sections intact.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PatchSet {
    /// Key = section name ("system_prompt" / "messages" / ...)
    #[serde(flatten)]
    pub patches: HashMap<String, PatchValue>,
}

/// Value of a single context patch.
///
/// `Text` is for string-valued sections (system_prompt, workspace_context,
/// environment, skill_instructions, messages); `Json` is for JSON-valued
/// sections (tool_definitions, retrieved_memory, identity_context).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum PatchValue {
    Text { value: String },
    Json { value: serde_json::Value },
}

impl PatchValue {
    /// The wire variant name ("text" | "json") — used in type-mismatch errors.
    pub fn variant_name(&self) -> &'static str {
        match self {
            PatchValue::Text { .. } => "text",
            PatchValue::Json { .. } => "json",
        }
    }
}

impl PatchSet {
    /// Merge another PatchSet into this one, overwriting only the sections
    /// that the other PatchSet specifies. Sections absent from the other
    /// set are left unchanged in this one.
    pub fn merge(&mut self, other: PatchSet) {
        self.patches.extend(other.patches);
    }
}

/// Error produced while applying a [`PatchSet`] to a [`ContextBuilder`].
///
/// ADR-054 §6: keying patches by string loses compile-time section names,
/// so unknown keys must be rejected at apply time instead of silently
/// ignored (typo safety).
///
/// Validation is centralized in `ContextBuilder::resolve_patch` (the single
/// source of truth shared with `handle_patch_context`) — it rejects unknown
/// keys with [`PatchError::UnknownSection`] and value/section type
/// mismatches with [`PatchError::TypeMismatch`].
#[derive(Debug, thiserror::Error)]
pub enum PatchError {
    #[error("Unknown section: {0}")]
    UnknownSection(String),
    #[error("Section {section} expects {expected} patch, got {actual}")]
    TypeMismatch {
        section: String,
        expected: &'static str,
        actual: &'static str,
    },
}

/// Parameters for `debugger.editMessage`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EditMessageParams {
    pub index: usize,
    pub content: serde_json::Value,
}

/// Parameters for `debugger.rollback`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RollbackParams {
    pub target_index: usize,
}

// ── Event Notification Types ──────────────────────────────────────────

/// Parameters for `debugger.onStep` event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnStepParams {
    pub iteration: u32,
    pub phase: DebugPhase,
    pub input: Option<serde_json::Value>,
    pub output: Option<serde_json::Value>,
    pub usage: Option<DebugUsage>,
}

/// Parameters for `debugger.onStateChange` event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnStateChangeParams {
    pub old_phase: DebugPhase,
    pub new_phase: DebugPhase,
    pub iteration: u32,
}

/// Parameters for `debugger.onContextBuilt` event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnContextBuiltParams {
    pub iteration: u32,
    pub sections: ContextSections,
    pub total_token_estimate: usize,
}
