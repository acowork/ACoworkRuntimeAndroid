//! Path resolution helpers shared across the workspace.
//!
//! Single source of truth for how any tool turns a user-supplied path string
//! into an absolute filesystem path. Centralising this logic prevents the
//! drift historically seen in `file_read` / `file_write` / `file_edit`, where
//! `trim_start_matches('/')` was applied before joining against `work_dir`,
//! producing nonexistent nested paths such as
//! `<work_dir>/Users/<work_dir>/...` whenever an absolute path was passed in
//! (especially after `PathGuardedTool` rewrote a relative path to absolute).
//!
//! Rules:
//! - Absolute paths (POSIX leading `/` or Windows drive letter) pass through
//!   unchanged. The caller is responsible for any allow-list check; this
//!   module performs no permission or sandbox logic.
//! - Relative paths are joined onto `work_dir` when `work_dir` is `Some` and
//!   non-empty. When `work_dir` is `None` or empty, the path is returned
//!   unchanged so callers retain control over `cwd` semantics.
//! - No filesystem I/O, no symlink canonicalisation — string-level only,
//!   safe to call before the target file exists.

use std::path::{Path, PathBuf};

/// Returns true when `path` is already absolute on the host filesystem.
///
/// Recognises POSIX absolute paths (leading `/`) and Windows drive-letter
/// paths (e.g. `C:\foo` or `C:/foo`). Other schemes (UNC `\\?\`, volume
/// GUIDs) are not expected from tool callers.
pub fn is_absolute(path: &str) -> bool {
    path.starts_with('/')
        || (path.len() > 2
            && path.as_bytes()[1] == b':'
            && path.as_bytes()[0].is_ascii_alphabetic())
}

/// Resolve a user-supplied path against an optional work directory.
///
/// See module-level docs for the full rule set. This function never touches
/// the filesystem and is safe to call before the target exists.
pub fn resolve(path: &str, work_dir: Option<&str>) -> PathBuf {
    if is_absolute(path) {
        PathBuf::from(path)
    } else {
        match work_dir {
            Some(wd) if !wd.is_empty() => Path::new(wd).join(path),
            _ => PathBuf::from(path),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn posix_absolute_is_detected() {
        assert!(is_absolute("/"));
        assert!(is_absolute("/Users/nicholas/projects/AgentCowork/overview.md"));
    }

    #[test]
    fn relative_path_is_not_absolute() {
        assert!(!is_absolute("overview.md"));
        assert!(!is_absolute("docs/AGENTS.md"));
        assert!(!is_absolute(""));
    }

    #[test]
    fn windows_drive_letter_is_absolute() {
        assert!(is_absolute(r"C:\Users\foo"));
        assert!(is_absolute("C:/Users/foo"));
        // Non-letter drive prefix must not be misclassified.
        assert!(!is_absolute("1:/foo"));
        // Too short to be a drive letter.
        assert!(!is_absolute("C:"));
    }

    #[test]
    fn absolute_path_passes_through_unchanged() {
        let abs = "/Users/nicholas/projects/AgentCowork/overview.md";
        assert_eq!(resolve(abs, Some("/tmp")), PathBuf::from(abs));
        assert_eq!(resolve(abs, None), PathBuf::from(abs));
    }

    #[test]
    fn relative_path_joins_work_dir() {
        assert_eq!(
            resolve("overview.md", Some("/Users/nicholas/projects/AgentCowork")),
            PathBuf::from("/Users/nicholas/projects/AgentCowork/overview.md")
        );
        assert_eq!(
            resolve("docs/AGENTS.md", Some("/Users/nicholas/projects/AgentCowork")),
            PathBuf::from("/Users/nicholas/projects/AgentCowork/docs/AGENTS.md")
        );
    }

    #[test]
    fn missing_or_empty_work_dir_returns_path_as_is() {
        assert_eq!(resolve("overview.md", None), PathBuf::from("overview.md"));
        assert_eq!(resolve("overview.md", Some("")), PathBuf::from("overview.md"));
    }

    /// Regression: previously `file_read` / `file_write` / `file_edit` called
    /// `trim_start_matches('/')` and then `Path::new(work_dir).join(path)`,
    /// producing `<work_dir>/<work_dir>/<file>` for absolute inputs. After
    /// `PathGuardedTool` started rewriting relative paths to absolute, this
    /// became a hard ENOENT in every file-tool call.
    #[test]
    fn regression_double_join_does_not_happen() {
        let work_dir = "/Users/nicholas/projects/AgentCowork";
        let user_path = "/Users/nicholas/projects/AgentCowork/overview.md";
        assert_eq!(resolve(user_path, Some(work_dir)), PathBuf::from(user_path));
    }
}
