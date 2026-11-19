//! Workspace module (ADR-058).
//!
//! Hosts the workspace-synchronization filesystem watcher — the
//! authoritative event source that pushes workspace file changes to
//! the Desktop via MQTT. This is deliberately separate from
//! [`crate::security::fs_watcher`], which continues to serve the
//! security audit log: same `notify` backend, different consumers and
//! lifecycles.
//!
//! Existing workspace logic (HTTP CRUD handlers in `http/server.rs`,
//! usecases, `tools/workspace_resolver.rs`) is NOT migrated here — the
//! watcher only hooks into their call sites (see ADR-058 §3.6).

pub mod fs_watcher;
pub mod watcher_set;

pub use fs_watcher::{WorkspaceFsEventSink, WorkspaceFsWatcher, WorkspaceFsWatcherError};
pub use watcher_set::{SharedWorkspaceWatcherSet, WorkspaceWatcherSet};
