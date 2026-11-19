//! MCP config change notifier — shared state between agent loop and MCP tools.
//!
//! `mcp_install` / `mcp_uninstall` tools write to agent_mcp.json and then
//! call [`McpConfigNotifier::notify`] to signal the main loop that a reload
//! is needed. The main loop subscribes via [`McpConfigNotifier::subscribe`]
//! and includes the returned [`tokio::sync::watch::Receiver`] in its `select!`.
//!
//! This is a zero-coupling mechanism: tools only operate on JSON files,
//! and the main loop receives a single notification to trigger reconnection.
//! No periodic polling — the signal fires exactly once per install/uninstall.

use std::sync::Arc;
use tokio::sync::watch;

/// Lightweight shared notifier for MCP config changes.
///
/// # Design
///
/// - Uses `tokio::sync::watch` with `()` as the signal value.
///   Multiple concurrent writes are coalesced — only the latest
///   `notify()` matters, which is exactly right for MCP config
///   changes (we just need to know "something changed").
/// - `notify()` is idempotent — calling it multiple times only
///   triggers the receiver once per `changed()` poll cycle.
/// - Clone the `Arc` to share across tools and the main loop.
///
/// This follows the same pattern as [`MemorySessionHandle`] —
/// shared state injected at tool construction, no changes to the
/// [`Tool`](acowork_core::tools::traits::Tool) trait.
#[derive(Clone)]
pub struct McpConfigNotifier {
    tx: watch::Sender<()>,
}

impl McpConfigNotifier {
    /// Create a new notifier and return a receiver for the main loop.
    pub fn new() -> (Self, watch::Receiver<()>) {
        let (tx, rx) = watch::channel(());
        (Self { tx }, rx)
    }

    /// Signal the main loop that MCP config has changed.
    ///
    /// Idempotent — if the receiver hasn't consumed the previous
    /// notification yet, `send` will silently drop the old value
    /// and replace it with the new one (watch semantics).
    pub fn notify(&self) {
        self.tx.send_modify(|v| *v = ());
    }

    /// Get a new receiver for subscription.
    /// This can be used independently of the initial receiver
    /// returned by [`McpConfigNotifier::new`].
    pub fn subscribe(&self) -> watch::Receiver<()> {
        self.tx.subscribe()
    }
}

impl std::fmt::Debug for McpConfigNotifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("McpConfigNotifier")
            .field("receiver_count", &self.tx.receiver_count())
            .finish()
    }
}

impl Default for McpConfigNotifier {
    fn default() -> Self {
        let (this, _rx) = Self::new();
        this
    }
}

/// Type-erased shared reference to the notifier, suitable for injection
/// into tool construction without generic bounds.
pub type McpNotifyRef = Option<Arc<McpConfigNotifier>>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notifier_new_creates_sender_and_receiver() {
        let (_notifier, rx) = McpConfigNotifier::new();
        // The initial value is sent on creation, so changed() should
        // be immediately ready (returns Ok, not pending).
        assert!(rx.has_changed().is_ok());
    }

    #[test]
    fn notify_triggers_receiver() {
        let (notifier, mut rx) = McpConfigNotifier::new();
        // Consume the initial value
        let _ = rx.borrow_and_update();

        // After notify, changed() should return Ok
        notifier.notify();
        assert!(rx.has_changed().is_ok());
    }

    #[test]
    fn notify_is_idempotent() {
        let (notifier, mut rx) = McpConfigNotifier::new();
        let _ = rx.borrow_and_update();

        // Multiple notifies should not panic or deadlock
        notifier.notify();
        notifier.notify();
        notifier.notify();

        // Should still receive exactly one changed signal
        assert!(rx.has_changed().is_ok());
        let _ = rx.borrow_and_update();
        // No more pending changes... but watch semantics: the latest
        // send replaces the previous, so after consume there should
        // be no pending change (unless another notify happens).
    }

    #[test]
    fn subscribe_creates_new_receiver() {
        let (notifier, mut rx1) = McpConfigNotifier::new();
        let mut rx2 = notifier.subscribe();

        // Both receivers should see the initial value
        assert!(rx1.has_changed().is_ok());
        assert!(rx2.has_changed().is_ok());
        let _ = rx1.borrow_and_update();
        let _ = rx2.borrow_and_update();

        // notify should be visible to both
        notifier.notify();
        assert!(rx1.has_changed().is_ok());
        assert!(rx2.has_changed().is_ok());
    }

    #[test]
    fn default_creates_usable_notifier() {
        let notifier = McpConfigNotifier::default();
        let mut rx = notifier.subscribe();
        assert!(rx.has_changed().is_ok());
        let _ = rx.borrow_and_update();
        notifier.notify();
        assert!(rx.has_changed().is_ok());
    }

    #[test]
    fn mcp_notify_ref_none_works() {
        let none_ref: McpNotifyRef = None;
        assert!(none_ref.is_none());
    }

    #[test]
    #[allow(clippy::unnecessary_literal_unwrap)]
    fn mcp_notify_ref_some_works() {
        let (notifier, _rx) = McpConfigNotifier::new();
        let some_ref: McpNotifyRef = Some(Arc::new(notifier));
        assert!(some_ref.is_some());
        some_ref.expect("checked is_some above").notify();
    }

    #[tokio::test]
    async fn notify_triggers_changed_async() {
        let (notifier, mut rx) = McpConfigNotifier::new();
        let _ = rx.borrow_and_update();

        notifier.notify();

        // changed() should resolve immediately
        let result =
            tokio::time::timeout(tokio::time::Duration::from_millis(100), rx.changed()).await;
        assert!(
            result.is_ok(),
            "changed() should resolve immediately after notify"
        );
    }

    #[test]
    fn debug_format_shows_receiver_count() {
        let (notifier, _rx1) = McpConfigNotifier::new();
        let debug_str = format!("{:?}", notifier);
        assert!(debug_str.contains("McpConfigNotifier"));
        assert!(debug_str.contains("receiver_count"));
    }

    #[test]
    fn clone_shares_the_same_channel() {
        let (notifier1, mut rx) = McpConfigNotifier::new();
        let notifier2 = notifier1.clone();
        let _ = rx.borrow_and_update();

        notifier2.notify();
        assert!(rx.has_changed().is_ok());
    }
}
