//! Session control use case.
//!
//! ADR-040: wraps session lifecycle and config mutation operations behind
//! a trait so the gateway loop dispatch does not directly depend on
//! SessionManager internals.
//!
//! **Implementation status (ADR-040 P2-D/H — shelved):** `SessionManager`
//! mutation methods require `&mut self`, which is incompatible with
//! `Arc<dyn SessionControlService>`. The trait currently serves as
//! architectural documentation; the production `gateway_loop::dispatch_inbound`
//! calls `session_manager.*` directly. A future rework of SessionManager
//! to use interior mutability would unlock a proper impl.

use async_trait::async_trait;

use crate::error::Result;

/// Session control methods — create, close, delete, reconfigure.
#[async_trait]
pub trait SessionControlService: Send + Sync {
    /// Create a new session, optionally with a pre-determined id.
    async fn create_session(&self, session_id: Option<String>) -> Result<String>;

    /// Close a session (mark as idle, release resources).
    async fn close_session(&self, session_id: &str) -> Result<()>;

    /// Delete a session and its persisted data.
    async fn delete_session(&self, session_id: &str) -> Result<()>;

    /// Open a previously closed session.
    async fn open_session(&self, session_id: &str) -> Result<()>;

    /// Update the human-readable title of a session.
    async fn update_title(&self, session_id: &str, title: String) -> Result<()>;

    /// Switch the LLM model for a session.
    async fn model_switch(&self, session_id: &str, model: String, provider: String) -> Result<()>;

    /// Change the reasoning effort level for a session.
    async fn reasoning_effort(&self, session_id: &str, effort: String) -> Result<()>;

    /// Switch the workspace for a session.
    async fn workspace_switch(&self, session_id: &str, workspace_id: String) -> Result<()>;

    /// Send a message to a session for processing.
    async fn send_message(
        &self,
        session_id: &str,
        content: String,
        attachments: Vec<serde_json::Value>,
    ) -> Result<()>;

    /// Stop generation (interrupt) for a session.
    async fn stop_generation(&self, session_id: &str) -> Result<()>;

    /// Continue execution after a pause.
    async fn continue_execution(&self, session_id: &str, continue_from: String) -> Result<()>;
}
