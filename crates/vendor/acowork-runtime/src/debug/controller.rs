//! DebugController — shared state for the Debug Protocol.
//!
//! Manages execution control state, conversation snapshots,
//! and context snapshots. Wrapped in `Arc<tokio::sync::Mutex<>>` for
//! safe sharing between the WebSocket server and AgentLoop.

use std::collections::HashMap;
use std::sync::Arc;

use acowork_core::providers::traits::ChatMessage;
use serde::{Deserialize, Serialize};
use tokio::sync::Notify;

use super::protocol::{ContextSections, DebugPhase, DebugUsage, RequestParams, SectionMeta};

// ── Debug Execution State ─────────────────────────────────────────────

/// Current execution state of the debug session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum DebugState {
    /// Running — agent loop is executing freely
    Running,
    /// Paused — agent loop is waiting for a Continue/Step command
    Paused,
    /// Stepping — agent loop will execute one step then auto-Pause
    Stepping,
    /// Stopped — agent loop has been terminated
    Stopped,
}

// ── Conversation Snapshot ─────────────────────────────────────────────

/// Lightweight conversation snapshot (per iteration).
///
/// Uses `message_count` instead of deep-copying the message array —
/// messages are append-only, so a rollback only needs to truncate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConversationSnapshot {
    /// Snapshot ID (incrementing counter)
    pub id: String,
    /// Corresponding iteration number
    pub iteration: u32,
    /// Number of messages when this snapshot was taken
    pub message_count: usize,
    /// Cumulative LLM usage at snapshot time
    pub cumulative_usage: DebugUsage,
    /// Timestamp (milliseconds since epoch)
    pub timestamp_ms: i64,
}

// ── Context Snapshot ──────────────────────────────────────────────────

/// A snapshot of the context building result for one iteration.
///
/// Stores metadata only (size/token/hash). Section content is stored
/// separately and returned via `getSection` (lazy loading).
#[derive(Debug, Clone)]
pub struct ContextSnapshot {
    pub iteration: u32,
    pub built_at: chrono::DateTime<chrono::Utc>,
    pub sections: ContextSnapshotSections,
    pub total_token_estimate: usize,
    /// ADR-054: control params of the ChatRequest that built this snapshot.
    pub request_params: RequestParams,
}

/// The context sections of one snapshot, ordered by `build()` injection order.
///
/// ADR-054: was a struct of 7 hardcoded fields; now a content-addressed
/// `Vec<NamedSection>` so new sections (messages, todo_context,
/// workspace_prompt_file, ...) require no struct change and the UI can
/// render whatever the backend produced.
#[derive(Debug, Clone)]
pub struct ContextSnapshotSections {
    /// Sections in `build()` injection order (n ≤ ~11, linear lookup is fine)
    pub sections: Vec<NamedSection>,
}

/// A named context section with its content and metadata.
#[derive(Debug, Clone)]
pub struct NamedSection {
    /// Section key ("system_prompt", "messages", ...)
    pub key: String,
    pub content: SectionContent,
}

impl NamedSection {
    /// Convert to serializable metadata (without content).
    pub fn to_meta(&self) -> SectionMeta {
        SectionMeta {
            key: self.key.clone(),
            size_bytes: self.content.size_bytes,
            token_estimate: self.content.token_estimate,
            hash: self.content.hash.clone(),
        }
    }
}

impl ContextSnapshotSections {
    /// Look up a section by key (O(n), n ≤ ~11 — no index needed).
    pub fn find(&self, key: &str) -> Option<&NamedSection> {
        self.sections.iter().find(|s| s.key == key)
    }

    /// Mutable lookup by key — used to refresh metadata in place.
    pub fn find_mut(&mut self, key: &str) -> Option<&mut NamedSection> {
        self.sections.iter_mut().find(|s| s.key == key)
    }

    /// Get the content of a section by key (for lazy fetch).
    pub fn get_content(&self, key: &str) -> Option<&SectionContent> {
        self.find(key).map(|s| &s.content)
    }

    /// Total token estimate across all sections.
    pub fn total_token_estimate(&self) -> usize {
        self.sections.iter().map(|s| s.content.token_estimate).sum()
    }
}

/// Content of a single context section with metadata.
#[derive(Debug, Clone)]
pub struct SectionContent {
    /// Full text content
    pub content: String,
    /// Byte size of the content
    pub size_bytes: usize,
    /// Estimated token count
    pub token_estimate: usize,
    /// SHA-256 hash of the content (for diff detection)
    pub hash: String,
}

impl SectionContent {
    /// Create a SectionContent with a token estimate.
    ///
    /// Uses [`crate::token::count_text`] — the single unified entry point
    /// for all token counting in ACowork.
    pub fn new(content: String) -> Self {
        let token_estimate = crate::token::count_text(&content);
        Self::build(content, token_estimate)
    }

    /// Create a SectionContent with a pre-computed token estimate.
    ///
    /// Use this when the caller has already counted tokens externally
    /// (e.g. from a cached `TokenCounter` instance) to avoid redundant work.
    /// Prefer [`new`] for one-off constructions.
    pub fn with_token_count(content: String, token_estimate: usize) -> Self {
        Self::build(content, token_estimate)
    }

    /// Create a metadata-only SectionContent — content is NOT stored.
    ///
    /// ADR-054 step 4: the `messages` section carries only size/token/hash
    /// metadata in the snapshot; the actual content is lazy-loaded via
    /// `getSection(iteration, "messages")` from `messages_by_iteration`.
    pub fn metadata_only(size_bytes: usize, token_estimate: usize, hash: String) -> Self {
        Self {
            content: String::new(),
            size_bytes,
            token_estimate,
            hash,
        }
    }

    /// Internal constructor shared by [`new`] and [`with_token_count`].
    fn build(content: String, token_estimate: usize) -> Self {
        use sha2::{Digest, Sha256};

        let size_bytes = content.len();
        let hash = {
            let mut hasher = Sha256::new();
            hasher.update(content.as_bytes());
            format!("{:x}", hasher.finalize())
        };

        Self {
            content,
            size_bytes,
            token_estimate,
            hash,
        }
    }
}

impl From<&ContextSnapshotSections> for ContextSections {
    fn from(s: &ContextSnapshotSections) -> Self {
        Self {
            sections: s.sections.iter().map(|ns| ns.to_meta()).collect(),
        }
    }
}

// ── DebugController ───────────────────────────────────────────────────

/// Shared debug controller, accessed by HTTP debug routes and AgentLoop.
pub struct DebugController {
    /// Current execution state
    pub state: DebugState,
    /// Current phase of the iteration
    pub phase: DebugPhase,
    /// Current iteration number
    pub iteration: u32,
    /// Conversation snapshots (indexed by iteration)
    pub conversation_snapshots: Vec<ConversationSnapshot>,
    /// Context snapshots (indexed by iteration)
    pub context_snapshots: HashMap<u32, ContextSnapshot>,
    /// Conversation messages per iteration (ADR-054 step 4).
    ///
    /// `Arc<Vec<ChatMessage>>` shares the underlying buffer across the
    /// history snapshots; each iteration holds one clone of the (possibly
    /// trimmed) history as it was when the context was built. Content is
    /// lazy-loaded via `getSection(iteration, "messages")` and never
    /// serialized into `ContextSnapshot` itself.
    pub messages_by_iteration: HashMap<u32, Arc<Vec<ChatMessage>>>,
    /// Pending patches for context re-execution
    pub pending_patches: Option<super::protocol::PatchSet>,
    /// Target iteration for rewind (set by `debugger.rewind`, consumed by SessionTask)
    pub rewind_target: Option<u32>,
    /// Flag indicating re-execute was requested (set by `debugger.reExecute`, consumed by SessionTask)
    pub re_execute_pending: bool,
    /// Notification signal for pending rewind.
    ///
    /// The RPC handler calls `notify_one()` after setting `rewind_target`.
    /// The agent loop (via `await_debug_resume`) and the SessionTask
    /// (via `tokio::select!`) await this notify to consume the rewind
    /// without polling.  This makes rewind a first-class event in the
    /// debug lifecycle instead of a polling-based side channel.
    pub rewind_notify: Arc<Notify>,
    /// Notification signal for resume requests.
    ///
    /// When the user presses resume but the agent loop has already
    /// completed (e.g. after rewind was issued post-completion),
    /// the SessionTask is blocked waiting for the next ChatMessage
    /// and cannot detect the state change.  The resume handler calls
    /// `notify_one()` so the SessionTask wakes up and re-runs the
    /// agent loop with the saved user message.
    pub resume_notify: Arc<Notify>,
    /// Unified control-signal notification.
    ///
    /// Fired by the debug server (pause/stop) and by `fire_urgent_stop`
    /// (chat-panel stop) so that every blocking wait point in the agent
    /// loop receives immediate wakeup for ALL control signals (Stop,
    /// Pause, DebugStop).  This Arc is shared with `AgentCore::urgent_stop`
    /// so that both the debug server and the chat-panel path fire the
    /// same edge-triggered Notify.
    pub control_notify: Arc<Notify>,
}

impl DebugController {
    /// Create a new DebugController in Stepping state (auto-pause after first iteration).
    pub fn new() -> Self {
        Self {
            state: DebugState::Stepping,
            phase: DebugPhase::Idle,
            iteration: 0,
            conversation_snapshots: Vec::new(),
            context_snapshots: HashMap::new(),
            messages_by_iteration: HashMap::new(),
            pending_patches: None,
            rewind_target: None,
            re_execute_pending: false,
            rewind_notify: Arc::new(Notify::const_new()),
            resume_notify: Arc::new(Notify::const_new()),
            control_notify: Arc::new(Notify::const_new()),
        }
    }

    /// Create a conversation snapshot at the current state.
    pub fn create_conversation_snapshot(
        &mut self,
        message_count: usize,
        usage: DebugUsage,
    ) -> ConversationSnapshot {
        let snap = ConversationSnapshot {
            id: format!("snap-{}", self.conversation_snapshots.len()),
            iteration: self.iteration,
            message_count,
            cumulative_usage: usage,
            timestamp_ms: chrono::Utc::now().timestamp_millis(),
        };
        self.conversation_snapshots.push(snap.clone());
        snap
    }

    /// Store a context snapshot for the given iteration.
    pub fn store_context_snapshot(&mut self, snapshot: ContextSnapshot) {
        self.context_snapshots.insert(snapshot.iteration, snapshot);
    }

    /// Get a context snapshot by iteration.
    pub fn get_context_snapshot(&self, iteration: u32) -> Option<&ContextSnapshot> {
        self.context_snapshots.get(&iteration)
    }

    /// Store the conversation messages for an iteration (ADR-054 step 4).
    pub fn store_messages(&mut self, iteration: u32, messages: Arc<Vec<ChatMessage>>) {
        self.messages_by_iteration.insert(iteration, messages);
    }

    /// Store the conversation messages for an iteration AND refresh the
    /// `messages` section metadata in the context snapshot.
    ///
    /// Called at iteration completion: the stored messages then include
    /// the current iteration's assistant reply / tool results, which the
    /// context-build snapshot (captured before the LLM call) cannot
    /// contain. The size/token/hash metadata is recomputed so
    /// `getSection(iteration, "messages")` returns values consistent with
    /// the lazy-loaded content.
    pub fn store_messages_with_meta(&mut self, iteration: u32, messages: Arc<Vec<ChatMessage>>) {
        self.messages_by_iteration
            .insert(iteration, messages.clone());

        if let Some(snap) = self.context_snapshots.get_mut(&iteration)
            && let Some(section) = snap.sections.find_mut("messages")
        {
            let json = serde_json::to_string(&*messages).unwrap_or_default();
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(json.as_bytes());
            section.content = SectionContent::metadata_only(
                json.len(),
                crate::token::count_text(&json),
                format!("{:x}", hasher.finalize()),
            );
            snap.total_token_estimate = snap.sections.total_token_estimate();
        }
    }

    /// Get the conversation messages for an iteration, if stored.
    pub fn get_messages(&self, iteration: u32) -> Option<&Arc<Vec<ChatMessage>>> {
        self.messages_by_iteration.get(&iteration)
    }

    /// Take the rewind target, clearing it from the controller.
    /// Returns the target iteration if set.
    pub fn take_rewind_target(&mut self) -> Option<u32> {
        self.rewind_target.take()
    }

    /// Notify consumers that a rewind is pending.
    ///
    /// Called by the RPC handler after setting `rewind_target`.
    /// Wakes up any task waiting on `rewind_notify.notified()`.
    pub fn notify_rewind(&self) {
        self.rewind_notify.notify_one();
    }

    /// Clone the rewind notification handle.
    ///
    /// Used by `AgentCore` to pass the notify to `SessionTask`
    /// without holding the controller mutex.
    pub fn rewind_notify_handle(&self) -> Arc<Notify> {
        self.rewind_notify.clone()
    }

    /// Clone the resume notification handle.
    ///
    /// Used by `AgentCore` to pass the notify to `SessionTask`
    /// without holding the controller mutex.
    pub fn resume_notify_handle(&self) -> Arc<Notify> {
        self.resume_notify.clone()
    }

    /// Clone the control notification handle.
    ///
    /// Used to share the same `Arc<Notify>` between `AgentCore::urgent_stop`
    /// and `DebugController` so that both chat-panel stop and debug pause/stop
    /// fire the same edge-triggered notify.
    pub fn control_notify_handle(&self) -> Arc<Notify> {
        self.control_notify.clone()
    }

    /// Fire the control notification — wakes one blocked `select!` branch.
    ///
    /// Called by `debugger.pause` and `debugger.stop` RPC handlers to
    /// immediately interrupt the agent loop's in-flight blocking waits
    /// (LLM streaming, tool execution, approval wait).
    pub fn notify_control(&self) {
        self.control_notify.notify_one();
    }

    /// Set the re-execute pending flag.
    pub fn set_re_execute_pending(&mut self) {
        self.re_execute_pending = true;
    }

    /// Take the re-execute pending flag, clearing it.
    /// Returns true if re-execute was requested.
    pub fn take_re_execute_pending(&mut self) -> bool {
        let was_pending = self.re_execute_pending;
        self.re_execute_pending = false;
        was_pending
    }

    /// Truncate conversation snapshots after the given iteration.
    /// Retains only snapshots whose iteration <= target.
    pub fn truncate_snapshots_after(&mut self, target_iteration: u32) {
        self.conversation_snapshots
            .retain(|s| s.iteration <= target_iteration);
        self.context_snapshots
            .retain(|&iter, _| iter <= target_iteration);
        // ADR-054 step 4: messages are tied to the same iteration space —
        // drop everything after the rewind target to keep memory bounded.
        self.messages_by_iteration
            .retain(|&iter, _| iter <= target_iteration);
    }

    /// Clear all stored state (for restarting).
    pub fn reset(&mut self) {
        self.state = DebugState::Stepping;
        self.phase = DebugPhase::Idle;
        self.iteration = 0;
        self.conversation_snapshots.clear();
        self.context_snapshots.clear();
        self.messages_by_iteration.clear();
        self.pending_patches = None;
        self.rewind_target = None;
        self.re_execute_pending = false;
    }
}

impl Default for DebugController {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use acowork_core::providers::traits::MessageRole;

    fn chat_message(role: MessageRole, content: &str) -> ChatMessage {
        ChatMessage {
            role,
            content: content.to_string(),
            ..Default::default()
        }
    }

    fn snapshot_with_messages_meta(iteration: u32) -> ContextSnapshot {
        let named = vec![NamedSection {
            key: "messages".to_string(),
            content: SectionContent::metadata_only(0, 0, "stale-hash".to_string()),
        }];
        ContextSnapshot {
            iteration,
            built_at: chrono::Utc::now(),
            sections: ContextSnapshotSections { sections: named },
            total_token_estimate: 0,
            request_params: RequestParams {
                model: "gpt-4o".to_string(),
                temperature: None,
                max_tokens: None,
                reasoning_effort: None,
                thinking_mode: None,
            },
        }
    }

    #[test]
    fn store_messages_with_meta_updates_messages_and_section_meta() {
        let mut ctrl = DebugController::new();
        ctrl.store_context_snapshot(snapshot_with_messages_meta(1));

        let messages = Arc::new(vec![
            chat_message(MessageRole::User, "hello"),
            chat_message(MessageRole::Assistant, "hi there"),
        ]);
        ctrl.store_messages_with_meta(1, messages);

        // messages_by_iteration updated.
        assert_eq!(ctrl.get_messages(1).unwrap().len(), 2);
        // Section meta refreshed: hash differs from the stale value and
        // size/token reflect the actual serialized content.
        let snap = ctrl.get_context_snapshot(1).unwrap();
        let sec = snap.sections.find("messages").unwrap();
        assert_ne!(sec.content.hash, "stale-hash");
        assert!(sec.content.size_bytes > 0);
        assert!(sec.content.token_estimate > 0);
        assert!(snap.total_token_estimate > 0);
    }

    #[test]
    fn store_messages_with_meta_without_snapshot_is_meta_noop() {
        let mut ctrl = DebugController::new();
        let messages = Arc::new(vec![chat_message(MessageRole::User, "hello")]);
        ctrl.store_messages_with_meta(2, messages);

        // Messages are stored regardless.
        assert_eq!(ctrl.get_messages(2).unwrap().len(), 1);
        // No context snapshot for iteration 2 — no panic, nothing to refresh.
        assert!(ctrl.get_context_snapshot(2).is_none());
    }
}
