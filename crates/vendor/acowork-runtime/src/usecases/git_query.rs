//! Git query use case (ADR-078).
//!
//! Git operations for the Desktop Git Status Bar: `status`, `diff`,
//! `log` (read-only) and `revert` (the single user-requested WRITE that
//! discards uncommitted changes). All git execution happens in the
//! **Runtime** (the authoritative workspace owner, ADR-009 v2) via the
//! system git CLI — the Gateway only reverse-proxies these endpoints
//! (ADR-033 Phase 2) and never touches the filesystem.
//!
//! Security invariants (ADR-078 §1.3):
//! - **read-only except revert**: every read command runs with
//!   `GIT_OPTIONAL_LOCKS=0` so git cannot take optional locks (e.g. the
//!   index stat-cache refresh `git status` would otherwise perform);
//!   `revert` (a write) skips that flag but is confirm-dialog guarded on
//!   the client and validates its target like every other path;
//! - **paths never escape the workspace**: diff/log paths are
//!   canonicalized and must stay under the workspace root; status
//!   output is filtered by the workspace-root prefix before it leaves
//!   the Runtime;
//! - **no absolute paths leak**: response paths are always relative to
//!   the workspace root; `repo_root` is never returned.
//!
//! The types here are the canonical wire-format DTOs for `/git/*`. Field
//! names mirror the contract consumed by the Desktop `gitStore`
//! (camelCase via `#[serde(rename_all = "camelCase")]`). Keep them
//! aligned end-to-end (Runtime HTTP → Gateway reverse proxy → Desktop).

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// All error variants git operations can produce.
///
/// The HTTP layer maps each variant to a deterministic status code via
/// [`GitError::http_status`].
#[derive(Debug, Error)]
pub enum GitError {
    /// The requested workspace_id does not exist in `agent_workspaces.json`.
    /// Maps to HTTP 404.
    #[error("workspace not found: {0}")]
    WorkspaceNotFound(String),

    /// A filesystem path component tried to escape the workspace root
    /// (".." traversal, absolute path, etc.). Maps to HTTP 400.
    #[error("invalid path: {0}")]
    InvalidPath(String),

    /// The workspace is not inside a git repository (repo discovery
    /// failed, max 6 levels up). For `/git/status` this surfaces as
    /// `is_repo: false` + `error: "not_a_repo"` inside a 200 response;
    /// for `/git/diff` + `/git/log` it is a real error (400).
    #[error("not a git repository: {0}")]
    NotARepo(String),

    /// The `git` binary is missing / could not be spawned. For
    /// `/git/status` this surfaces as `is_repo: false` +
    /// `error: "git_unavailable"` inside a 200 response; for diff/log
    /// it is a 503.
    #[error("git unavailable: {0}")]
    GitUnavailable(String),

    /// The git command exited non-zero (other than "not a repo").
    #[error("git command failed: {0}")]
    GitFailed(String),

    /// The git command exceeded the timeout budget (default 10s).
    #[error("git command timed out after {0}s")]
    Timeout(u64),

    /// Invalid querystring / parameter combination. Maps to HTTP 400.
    #[error("bad request: {0}")]
    BadRequest(String),

    /// Generic I/O failure. Maps to HTTP 500.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// Response not valid UTF-8. Maps to HTTP 500.
    #[error("invalid UTF-8: {0}")]
    InvalidUtf8(String),
}

impl GitError {
    /// Map this error to an HTTP status code.
    pub fn http_status(&self) -> u16 {
        match self {
            GitError::WorkspaceNotFound(_) => 404,
            GitError::InvalidPath(_) => 400,
            GitError::NotARepo(_) => 400,
            GitError::GitUnavailable(_) => 503,
            GitError::Timeout(_) => 504,
            GitError::GitFailed(_) | GitError::Io(_) | GitError::InvalidUtf8(_) => 500,
            GitError::BadRequest(_) => 400,
        }
    }
}

// ── Status DTOs ────────────────────────────────────────────────────────────

/// Index (staged) state of a change, mapped from porcelain XY column X.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum GitIndexStatus {
    Added,
    Modified,
    Deleted,
    Renamed,
    /// Merge conflict (unmerged paths: `UU`/`AU`/`UD`/`UA`/`DU`/`AA`/`DD`).
    /// Deliberately distinct from `unmodified` so a conflicted file is
    /// never silently shown as "clean" (ADR-078 invariant 5).
    Conflicted,
    Unmodified,
}

/// Worktree state of a change, mapped from porcelain XY column Y.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum GitWorktreeStatus {
    Modified,
    Deleted,
    Untracked,
    /// Merge conflict (unmerged paths — see [`GitIndexStatus::Conflicted`]).
    Conflicted,
    Unmodified,
}

/// One changed file in `git status`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GitChangeDto {
    /// Workspace-root-relative path (never absolute, forward slashes).
    pub path: String,
    /// Old path for renames (workspace-root-relative), else None.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old_path: Option<String>,
    pub index: GitIndexStatus,
    pub worktree: GitWorktreeStatus,
    /// True when the index differs from HEAD (staged).
    pub staged: bool,
}

/// Response for `GET /git/status`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GitStatusResponse {
    pub is_repo: bool,
    /// Current branch name (`HEAD` when detached). None when not a repo.
    /// When `rev` is set, this is overwritten with the commit's display
    /// label (`"<short_sha> <subject prefix>"`) so the Git Status Bar
    /// can render the commit the user picked from the history dropdown
    /// without an extra round-trip.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub branch: Option<String>,
    /// `"not_a_repo"` | `"git_unavailable"` | null — explicit error
    /// states, never a silent degradation (ADR-078 §1.3 invariant 5).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// True when the porcelain output hit the entry/byte cap and was
    /// truncated (ADR-078 decision 4 — `--untracked-files=all` can
    /// explode on un-ignored directories).
    #[serde(default)]
    pub truncated: bool,
    #[serde(default)]
    pub changes: Vec<GitChangeDto>,
    /// Echo of the requested `rev` (None for working-tree status).
    /// Lets the Desktop cache entries by `(groupKey, rev)` and still
    /// know which view each cache slot is rendering.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rev: Option<String>,
}

/// Querystring for `GET /git/status`.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct GitStatusParams {
    #[serde(default)]
    pub workspace_id: Option<String>,
    /// Optional git revision: when set, the response's `changes` lists
    /// the files touched by that commit (parsed from
    /// `git diff-tree --name-status -z`) instead of the current
    /// working-tree status. The legacy working-tree semantics survive
    /// as the default (`rev = None`). The Desktop's Git Status Bar
    /// history dropdown uses this to render "files in commit X" without
    /// a dedicated endpoint. Pass `""` explicitly to opt into the
    /// working-tree semantics (same as omitting the param).
    #[serde(default)]
    pub rev: Option<String>,
}

// ── Diff DTOs ──────────────────────────────────────────────────────────────

/// How the diff should be rendered by the Monaco DiffEditor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum GitDiffKind {
    Modified,
    Untracked,
    Deleted,
    Binary,
    NoChange,
}

/// Response for `GET /git/diff` — two full texts for the DiffEditor
/// (original = `base_ref`, modified = `head_ref`).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GitDiffResponse {
    pub kind: GitDiffKind,
    /// `base_ref` version; `""` for untracked / missing; full text for deleted.
    pub original: String,
    /// `head_ref` version; `""` for deleted.
    pub modified: String,
    /// Canonical SHA for `base_ref` after `git rev-parse <base_ref>^{commit}`.
    /// `None` only when `base_ref` could not be resolved (the caller used a
    /// non-rev like the empty string or a malformed shorthand) — in
    /// practice this is unreachable because the `diff` handler already
    /// rejects empty / invalid refs with `GitError::BadRequest` before
    /// reaching this struct.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub base_rev: Option<String>,
    /// Canonical SHA for `head_ref` after `git rev-parse <head_ref>^{commit}`.
    /// `None` when `head_ref` was the empty string (working tree) — the
    /// client renders this as "Working Tree" instead of a commit id.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub head_rev: Option<String>,
}

/// Querystring for `GET /git/diff`.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct GitDiffParams {
    #[serde(default)]
    pub workspace_id: Option<String>,
    /// Workspace-root-relative path (validated, then converted to
    /// repo-root-relative before reaching git — ADR-078 decision 3).
    pub path: String,
    /// Base revision: any git rev (HEAD, branch, tag, full/short hash).
    /// Default `"HEAD"`. Must not be empty.
    #[serde(default)]
    pub base_ref: Option<String>,
    /// Compare revision: `""` (default) means the working tree on disk
    /// (preserves the pre-existing worktree-vs-HEAD semantics including
    /// untracked / deleted handling). Any non-empty value is treated as
    /// a git rev resolved via `git show <rev>:<path>` (e.g. a commit
    /// hash, branch, tag, or `:path` for the index).
    #[serde(default)]
    pub head_ref: Option<String>,
}

// ── Log DTOs ───────────────────────────────────────────────────────────────

/// One commit in the file history.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GitCommitDto {
    /// Full commit hash.
    pub hash: String,
    /// Abbreviated commit hash (git `%h`).
    pub short_hash: String,
    pub author: String,
    /// ISO 8601 strict commit date (git `%aI`).
    pub date: String,
    pub subject: String,
}

/// Response for `GET /git/log` — one page of the file / repo history,
/// plus pagination metadata so the client can render "Page X of Y" and
/// `Prev` / `Next` controls (the diff banner's `CommitPicker`).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GitLogResponse {
    pub commits: Vec<GitCommitDto>,
    pub pagination: GitLogPagination,
}

/// Pagination metadata for [`GitLogResponse`]. `totalCount` is the
/// total commits in the (filtered) history, not just the page — the
/// client uses it to render "Showing X-Y of Z" and to decide whether
/// to surface the search + pagination chrome (when `totalCount <=
/// pageSize` the controls collapse, matching the session list pattern).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GitLogPagination {
    /// 1-indexed page number.
    pub current_page: u32,
    /// Total pages given `pageSize` and `totalCount`.
    pub total_pages: u32,
    pub page_size: u32,
    pub total_count: u32,
}

/// Querystring for `GET /git/log`.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct GitLogParams {
    #[serde(default)]
    pub workspace_id: Option<String>,
    /// Workspace-root-relative path; empty = repository-wide history.
    #[serde(default)]
    pub path: Option<String>,
    /// Max commits. Default 50, hard cap 200 (ADR-078 decision 4).
    #[serde(default)]
    pub limit: Option<u32>,
    /// Commits to skip from the start of the history (newest-first).
    /// `skip = (currentPage - 1) * pageSize`. Default 0.
    #[serde(default)]
    pub skip: Option<u32>,
}

// ── Revert DTOs ────────────────────────────────────────────────────────────

/// Body for `POST /git/revert` — discard the uncommitted changes of a
/// single path, restoring it to HEAD (untracked files are deleted,
/// matching IDE "Discard Changes" semantics). This is the one
/// deliberate WRITE operation in the git API family (the read-only
/// `GIT_OPTIONAL_LOCKS=0` convention does not apply to it); it is
/// guarded by the same path-traversal validation as diff/log.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct GitRevertParams {
    #[serde(default)]
    pub workspace_id: Option<String>,
    /// Workspace-root-relative path of the change to revert.
    pub path: String,
    /// Old path of a staged rename (`GitChangeDto.oldPath`), when the
    /// row being reverted is a rename. Restored from HEAD before the
    /// new path is discarded so both halves of the rename unwind.
    #[serde(default)]
    pub old_path: Option<String>,
}

/// Response for `POST /git/revert` — echoes the reverted path(s).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GitRevertResponse {
    /// Workspace-root-relative path that was reverted.
    pub path: String,
    /// Old path restored for renames, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old_path: Option<String>,
}

// ── Service trait ──────────────────────────────────────────────────────────

/// Read-only git query operations, implemented by
/// [`crate::usecases::RuntimeGitQueryService`]. ADR-040 layering: the
/// HTTP handlers depend on this trait, never on the concrete service.
///
/// [`revert`](Self::revert) is the single write operation — it discards
/// uncommitted changes and is explicitly requested by the user via the
/// Desktop context menu (destructive, confirm-dialog guarded on the
/// client).
#[async_trait]
pub trait GitQueryService: Send + Sync {
    async fn status(&self, params: &GitStatusParams) -> Result<GitStatusResponse, GitError>;
    async fn diff(&self, params: &GitDiffParams) -> Result<GitDiffResponse, GitError>;
    async fn log(&self, params: &GitLogParams) -> Result<GitLogResponse, GitError>;
    async fn revert(&self, params: &GitRevertParams) -> Result<GitRevertResponse, GitError>;
}
