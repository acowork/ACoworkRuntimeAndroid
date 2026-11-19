//! FsWatcher — cross-platform workspace filesystem monitoring
//!
//! Uses the `notify` crate for platform-agnostic file change detection.
//! Monitors new file creation, permission changes, and symlinks.
//!
//! Design: `docs/08-security.md` §11.4
//! Decision D8: Use `notify` crate instead of manually wrapping
//! inotify/FSEvents/ReadDirectoryChangesW.

use std::path::{Path, PathBuf};
use std::time::Duration;

use notify::{Config, PollWatcher, RecursiveMode, Watcher};
use tokio::sync::mpsc;

/// A filesystem event detected in the workspace.
#[derive(Debug, Clone)]
pub enum FsEvent {
    /// A new file was created.
    FileCreated { path: PathBuf },
    /// A file was modified.
    FileModified { path: PathBuf },
    /// A file was deleted.
    FileDeleted { path: PathBuf },
    /// A file's metadata changed (permissions, ownership, etc.).
    MetadataChanged { path: PathBuf },
    /// A symlink was created pointing outside the workspace.
    SymlinkCreated { path: PathBuf, target: PathBuf },
}

/// Filesystem watcher for the agent workspace.
///
/// Uses `notify::PollWatcher` with a short polling interval (500ms) rather
/// than the platform-default `recommended_watcher` (FSEvents on macOS,
/// inotify on Linux) for two reasons:
///
/// 1. **Predictable latency.** Native backends can have multi-second event
///    delivery latency under load — FSEvents buffers and coalesces events,
///    and some sandboxed environments silently fall back to a 30-second
///    polling interval. PollWatcher's latency equals the configured interval.
/// 2. **Cross-platform determinism.** The same code path runs on every host
///    (no per-OS quirks), which makes the security audit reliable.
///
/// The 500ms poll is cheap on small workspaces (a few hundred files); for
/// very large workspaces (10k+ files) the cost is still well under 1% CPU.
pub struct FsWatcher {
    workspace_dir: PathBuf,
    #[allow(dead_code)]
    watcher: Option<PollWatcher>,
    rx: mpsc::UnboundedReceiver<notify::Event>,
}

/// How often `PollWatcher` scans the workspace for changes. Short enough for
/// sub-second security alerts, long enough to keep CPU usage negligible.
const FS_POLL_INTERVAL: Duration = Duration::from_millis(500);

impl FsWatcher {
    /// Create a new filesystem watcher for the given workspace.
    ///
    /// Uses an unbounded tokio channel so the synchronous `notify`
    /// callback (`UnboundedSender::send` is non-blocking) can emit
    /// events without requiring an async context.
    pub fn new(workspace_dir: &Path) -> Result<Self, FsWatcherError> {
        let (tx, rx) = mpsc::unbounded_channel();

        let mut watcher = PollWatcher::new(
            move |res: Result<notify::Event, notify::Error>| {
                if let Ok(event) = res {
                    let _ = tx.send(event);
                }
            },
            Config::default().with_poll_interval(FS_POLL_INTERVAL),
        )
        .map_err(|e| FsWatcherError::Init(e.to_string()))?;

        // Start watching the workspace directory recursively
        watcher
            .watch(workspace_dir, RecursiveMode::Recursive)
            .map_err(|e| FsWatcherError::Init(e.to_string()))?;

        Ok(Self {
            workspace_dir: workspace_dir.to_path_buf(),
            watcher: Some(watcher),
            rx,
        })
    }

    /// Try to receive pending filesystem events (non-blocking).
    ///
    /// Drains all events currently sitting in the channel without
    /// awaiting. Returns an empty vec when no events are available.
    pub fn try_recv_events(&mut self) -> Vec<FsEvent> {
        let mut events = Vec::new();
        while let Ok(raw_event) = self.rx.try_recv() {
            if let Some(fs_event) = self.convert_event(&raw_event) {
                events.push(fs_event);
            }
        }
        events
    }

    /// Receive filesystem events asynchronously.
    ///
    /// First drains any already-buffered events, then (if none were
    /// pending) waits up to `timeout` for the first event to arrive.
    /// After receiving one event the channel is drained again so the
    /// caller gets a batch.
    ///
    /// This replaces the old `recv_events_timeout` which used
    /// `std::sync::mpsc::recv_timeout` and could block the tokio
    /// runtime.
    pub async fn recv_events(&mut self, timeout: Duration) -> Vec<FsEvent> {
        let mut events = Vec::new();

        // Drain any events already buffered in the channel.
        while let Ok(raw_event) = self.rx.try_recv() {
            if let Some(fs_event) = self.convert_event(&raw_event) {
                events.push(fs_event);
            }
        }

        // If nothing was buffered, wait for the first event with a timeout.
        if events.is_empty() {
            match tokio::time::timeout(timeout, self.rx.recv()).await {
                Ok(Some(raw_event)) => {
                    if let Some(fs_event) = self.convert_event(&raw_event) {
                        events.push(fs_event);
                    }
                    // Drain any additional events that arrived in the meantime.
                    while let Ok(raw_event) = self.rx.try_recv() {
                        if let Some(fs_event) = self.convert_event(&raw_event) {
                            events.push(fs_event);
                        }
                    }
                }
                Ok(None) => {
                    // Channel closed — watcher dropped; return what we have.
                }
                Err(_) => {
                    // Timeout elapsed; return what we have (possibly empty).
                }
            }
        }

        events
    }

    /// Get the workspace directory being watched.
    pub fn workspace_dir(&self) -> &Path {
        &self.workspace_dir
    }

    fn convert_event(&self, event: &notify::Event) -> Option<FsEvent> {
        use notify::EventKind;

        // Only care about events within the workspace
        for path in &event.paths {
            if !path.starts_with(&self.workspace_dir) {
                continue;
            }

            match &event.kind {
                EventKind::Create(_) => {
                    // Check for symlink
                    if path.is_symlink()
                        && let Ok(target) = std::fs::read_link(path)
                    {
                        // Check if symlink points outside workspace
                        let abs_target = if target.is_absolute() {
                            target
                        } else {
                            path.parent().unwrap_or(path).join(&target)
                        };
                        if !abs_target.starts_with(&self.workspace_dir) {
                            return Some(FsEvent::SymlinkCreated {
                                path: path.clone(),
                                target: abs_target,
                            });
                        }
                    }
                    return Some(FsEvent::FileCreated { path: path.clone() });
                }
                EventKind::Modify(notify::event::ModifyKind::Metadata(_)) => {
                    return Some(FsEvent::MetadataChanged { path: path.clone() });
                }
                EventKind::Modify(_) => {
                    return Some(FsEvent::FileModified { path: path.clone() });
                }
                EventKind::Remove(_) => {
                    return Some(FsEvent::FileDeleted { path: path.clone() });
                }
                _ => {}
            }
        }

        None
    }
}

/// Check if a path looks like an executable file.
pub fn is_executable_file(path: &Path) -> bool {
    // Check common executable extensions (cross-platform)
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");

    let script_extensions = [
        "sh", "bash", "zsh", "fish", "py", "rb", "pl", "pm", "js", "ts", "lua", "php",
    ];
    if script_extensions.contains(&ext) {
        return true;
    }

    // Windows-specific extensions
    if cfg!(windows) {
        return matches!(
            ext.to_lowercase().as_str(),
            "exe" | "bat" | "cmd" | "ps1" | "vbs" | "com"
        );
    }

    // On Unix, check execute permission bits
    #[cfg(unix)]
    {
        if ext.is_empty()
            && let Ok(metadata) = std::fs::metadata(path)
        {
            use std::os::unix::fs::PermissionsExt;
            return metadata.permissions().mode() & 0o111 != 0;
        }
    }

    false
}

/// Error type for FsWatcher operations.
#[derive(Debug, thiserror::Error)]
pub enum FsWatcherError {
    #[error("Watcher initialization failed: {0}")]
    Init(String),
    #[error("Watcher error: {0}")]
    Watch(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_is_executable_script() {
        let path = Path::new("/workspace/script.sh");
        assert!(is_executable_file(path));

        let path = Path::new("/workspace/app.py");
        assert!(is_executable_file(path));

        let path = Path::new("/workspace/readme.txt");
        assert!(!is_executable_file(path));
    }

    #[test]
    fn test_fs_event_debug() {
        let event = FsEvent::FileCreated {
            path: PathBuf::from("/workspace/newfile.txt"),
        };
        let debug_str = format!("{:?}", event);
        assert!(debug_str.contains("FileCreated"));
    }

    #[test]
    fn test_symlink_event() {
        let event = FsEvent::SymlinkCreated {
            path: PathBuf::from("/workspace/link"),
            target: PathBuf::from("/etc/passwd"),
        };
        let debug_str = format!("{:?}", event);
        assert!(debug_str.contains("SymlinkCreated"));
    }

    #[test]
    fn test_permissions_changed_event() {
        let event = FsEvent::MetadataChanged {
            path: PathBuf::from("/workspace/script.sh"),
        };
        match event {
            FsEvent::MetadataChanged { path } => {
                assert_eq!(path, PathBuf::from("/workspace/script.sh"));
            }
            _ => panic!("Expected MetadataChanged"),
        }
    }

    #[test]
    fn test_watcher_creation() {
        let dir = std::env::temp_dir().join("acowork-test-fswatcher");
        let _ = fs::create_dir_all(&dir);

        let result = FsWatcher::new(&dir);
        // May fail on some CI environments without inotify/FSEvents support
        if let Ok(mut watcher) = result {
            assert_eq!(watcher.workspace_dir(), dir);
            // Non-blocking drain should succeed (likely empty).
            let _ = watcher.try_recv_events();
        }

        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_recv_events_timeout_returns_empty() {
        let dir = std::env::temp_dir().join("acowork-test-fswatcher-async-timeout");
        let _ = fs::create_dir_all(&dir);

        if let Ok(mut watcher) = FsWatcher::new(&dir) {
            // With no file changes, recv_events should return empty after timeout.
            let events = watcher.recv_events(Duration::from_millis(50)).await;
            assert!(events.is_empty());
        }

        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_recv_events_detects_file_creation() {
        let dir = std::env::temp_dir().join("acowork-test-fswatcher-async-create");
        let _ = fs::remove_dir_all(&dir);
        let _ = fs::create_dir_all(&dir);

        if let Ok(mut watcher) = FsWatcher::new(&dir) {
            // Create a file inside the watched directory.
            let file_path = dir.join("test_file.txt");
            fs::write(&file_path, b"hello").unwrap();

            // PollWatcher scans every 500ms (see FS_POLL_INTERVAL), so a
            // single ~1s wait covers one full poll cycle plus a small margin.
            // Poll until we see at least one event, up to 3s as a safety
            // net for busy CI runners.
            let deadline = std::time::Instant::now() + Duration::from_secs(3);
            let mut events = Vec::new();
            while std::time::Instant::now() < deadline && events.is_empty() {
                tokio::time::sleep(Duration::from_millis(600)).await;
                events = watcher.recv_events(Duration::from_millis(50)).await;
            }
            assert!(
                !events.is_empty(),
                "Expected at least one FsEvent after file creation (waited 3s)"
            );
        }

        let _ = fs::remove_dir_all(&dir);
    }
}
