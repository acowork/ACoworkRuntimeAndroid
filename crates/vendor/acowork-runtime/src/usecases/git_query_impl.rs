//! RuntimeGitQueryService — implements [`GitQueryService`] (ADR-078).
//!
//! Executes read-only git commands via the system git CLI inside the
//! Runtime process (the authoritative workspace owner, ADR-009 v2). The
//! Gateway only reverse-proxies these endpoints — it never touches the
//! filesystem (ADR-009 red line).
//!
//! Command conventions (ADR-078 decision 2):
//! - `std::process::Command` + `spawn_blocking` (project convention,
//!   see `tools/builtin/shell.rs` — avoids `tokio::process::Command`'s
//!   async named-pipe I/O issues on Windows);
//! - no shell string interpolation; args via `Command::arg`, `--`
//!   separator guards dash-leading paths;
//! - `cwd = repo_root`; uniform timeout (10s);
//! - `GIT_OPTIONAL_LOCKS=0` (read-only guarantee, ADR-078 §1.3
//!   invariant 1) + `LC_ALL=C` (stable English stderr for error
//!   matching) on every READ command — the single write command
//!   (`revert`) goes through `run_git_mut` and skips the lock guard;
//! - stdout capped (status 1 MiB / 5000 entries; diff pre-checks blob
//!   sizes before reading, > 2 MiB degrades to `kind=binary`).

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use async_trait::async_trait;

use crate::usecases::WorkspaceError;
use crate::usecases::git_query::{
    GitChangeDto, GitCommitDto, GitDiffKind, GitDiffParams, GitDiffResponse, GitError,
    GitIndexStatus, GitLogPagination, GitLogParams, GitLogResponse, GitQueryService,
    GitRevertParams, GitRevertResponse, GitStatusParams, GitStatusResponse, GitWorktreeStatus,
};
use crate::usecases::workspace_mutation_impl::{resolve_within_static, resolve_workspace_root};

/// Max levels to walk up from the workspace root looking for `.git`
/// (ADR-078 decision 3 — covers the "workspace is a repo subdirectory"
/// topology without crossing into unrelated outer repos).
const MAX_REPO_UP: usize = 6;
/// Default git command timeout (ADR-078 decision 2).
const GIT_TIMEOUT: Duration = Duration::from_secs(10);
/// Status porcelain output byte cap — beyond this we truncate at the
/// last complete NUL-terminated entry and flag `truncated`.
const STATUS_BYTE_CAP: usize = 1 << 20; // 1 MiB
/// Status porcelain entry cap.
const STATUS_ENTRY_CAP: usize = 5_000;
/// Max diff side size — larger blobs/files degrade to `kind=binary`
/// (ADR-078 decision 4, revision 2026-09-14).
const DIFF_SIZE_CAP: u64 = 2 * 1024 * 1024; // 2 MiB
/// Default / max `git log` limit (ADR-078 decision 4).
const LOG_DEFAULT_LIMIT: u32 = 50;
const LOG_MAX_LIMIT: u32 = 200;

/// Captured stdout/stderr of a git invocation.
struct GitOutput {
    status: std::process::ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

/// Read-outcome of a git blob (`git show HEAD:<path>` / `git show :<path>`).
enum BlobRead {
    /// The rev:path does not exist (e.g. untracked file in HEAD).
    Missing,
    /// The blob exceeds [`DIFF_SIZE_CAP`] — caller returns `kind=binary`.
    TooLarge,
    /// Raw blob bytes.
    Ok(Vec<u8>),
}

/// Concrete [`GitQueryService`] implementation (ADR-040).
///
/// Holds only the agent `work_dir` (resolved once at boot) — like the
/// workspace query service, it resolves `workspace_id` to an absolute
/// path via `agent_workspaces.json`; HTTP handlers never see the
/// filesystem layout directly.
pub struct RuntimeGitQueryService {
    work_dir: PathBuf,
    _agent_id: String,
    /// The git executable path. `"git"` in production (resolved via PATH);
    /// tests inject a non-existent path to exercise the `git_unavailable`
    /// state without mutating the process-global PATH (which would poison
    /// parallel tests).
    git_bin: String,
}

impl RuntimeGitQueryService {
    pub fn new(work_dir: PathBuf, agent_id: String) -> Self {
        Self::new_with_git_bin(work_dir, agent_id, "git".to_string())
    }

    /// Test-only constructor: override the git executable (see
    /// [`RuntimeGitQueryService::git_bin`]).
    pub fn new_with_git_bin(work_dir: PathBuf, agent_id: String, git_bin: String) -> Self {
        Self {
            work_dir,
            _agent_id: agent_id,
            git_bin,
        }
    }
}

// ── Command plumbing ───────────────────────────────────────────────────────

/// Base git command with `cwd = repo_root`.
fn git_cmd(git_bin: &str, repo_root: &Path) -> Command {
    let mut cmd = Command::new(git_bin);
    cmd.current_dir(repo_root);
    cmd
}

/// Run a git command under the ADR-078 conventions:
/// `GIT_OPTIONAL_LOCKS=0` + `LC_ALL=C`, 10s timeout via
/// `spawn_blocking` + `tokio::time::timeout`.
///
/// NOTE: on timeout the spawned process is not killed (v1 accepts a
/// rare stray `git` process — these commands are sub-second in
/// practice, and `Command::output()` drains both pipes so there is no
/// deadlock risk).
async fn run_git(cmd: Command) -> Result<GitOutput, GitError> {
    run_git_op(cmd, true).await
}

/// Run a git command that must be able to WRITE (the `revert` path):
/// same timeout / `LC_ALL=C` conventions as [`run_git`], but without
/// the `GIT_OPTIONAL_LOCKS=0` read-only guard — restoring the index +
/// worktree needs the index lock.
async fn run_git_mut(cmd: Command) -> Result<GitOutput, GitError> {
    run_git_op(cmd, false).await
}

/// Shared plumbing for [`run_git`] / [`run_git_mut`].
async fn run_git_op(mut cmd: Command, optional_locks: bool) -> Result<GitOutput, GitError> {
    if optional_locks {
        cmd.env("GIT_OPTIONAL_LOCKS", "0");
    }
    cmd.env("LC_ALL", "C");
    let handle = tokio::task::spawn_blocking(move || cmd.output());
    match tokio::time::timeout(GIT_TIMEOUT, handle).await {
        Err(_) => Err(GitError::Timeout(GIT_TIMEOUT.as_secs())),
        Ok(Err(join_err)) => Err(GitError::GitFailed(format!(
            "spawn_blocking join error: {join_err}"
        ))),
        Ok(Ok(Err(io_err))) => {
            if io_err.kind() == std::io::ErrorKind::NotFound {
                Err(GitError::GitUnavailable(io_err.to_string()))
            } else {
                Err(GitError::Io(io_err))
            }
        }
        Ok(Ok(Ok(out))) => Ok(GitOutput {
            status: out.status,
            stdout: out.stdout,
            stderr: out.stderr,
        }),
    }
}

/// Repo discovery: walk up from the workspace root (max 6 levels) until
/// a `.git` entry (directory, or file for worktrees / submodules /
/// `gitdir:` pointers) is found. The parent of `.git` is the repo root.
fn discover_repo_root(workspace_root: &Path) -> Option<PathBuf> {
    let mut dir: Option<&Path> = Some(workspace_root);
    for _ in 0..=MAX_REPO_UP {
        let d = dir?;
        if d.join(".git").exists() {
            return Some(d.to_path_buf());
        }
        dir = d.parent();
    }
    None
}

/// Map a WorkspaceError to a GitError (HTTP layer maps both to
/// deterministic status codes).
fn workspace_to_git_error(e: WorkspaceError) -> GitError {
    match e {
        WorkspaceError::WorkspaceNotFound(id) => GitError::WorkspaceNotFound(id),
        WorkspaceError::InvalidPath(p) => GitError::InvalidPath(p),
        other => GitError::GitFailed(other.to_string()),
    }
}

/// `git status` stderr — "not a git repository" (git emits it even
/// under `LC_ALL=C`; versions vary slightly in wording).
fn looks_like_not_a_repo(stderr: &str) -> bool {
    stderr.contains("not a git repository")
}

// ── Porcelain `-z` parsing (ADR-078 decision 2/3) ──────────────────────────

/// Parse `git status --porcelain=v1 -z --branch` output.
///
/// Returns `(changes, branch, truncated)`. porcelain paths are
/// repo-root-relative; every change is filtered to the workspace root
/// (paths outside the workspace are dropped — ADR-078 decision 3, the
/// "workspace is a repo subdirectory" topology). Response paths are
/// workspace-root-relative with forward slashes.
fn parse_status_porcelain(
    raw: &[u8],
    workspace_root: &Path,
    repo_root: &Path,
) -> (Vec<GitChangeDto>, String, bool) {
    let mut changes = Vec::new();
    let mut branch = "HEAD".to_string();
    let mut truncated = false;

    let cap_end = truncate_at_nul(raw, STATUS_BYTE_CAP);
    if cap_end < raw.len() {
        truncated = true;
    }
    let slice = &raw[..cap_end];
    let mut entries = slice.split(|&b| b == 0);

    // First entry (with `--branch`) is the `## <branch>` header.
    if let Some(first) = entries.next().filter(|f| f.starts_with(b"## ")) {
        branch = parse_branch_line(&first[3..]);
    }

    while let Some(entry) = entries.next() {
        // `XY <path>` — X = index status, Y = worktree status.
        // Valid entries always have a space at index 2 (X and Y are both
        // single status chars, possibly spaces, e.g. ` M a.rs`).
        if entry.len() < 4 || entry[2] != b' ' {
            continue;
        }
        let x = entry[0] as char;
        let y = entry[1] as char;
        let path = String::from_utf8_lossy(&entry[3..]).into_owned();
        // Rename entries are two NUL-separated paths: `R  <new>\0<old>`.
        let old = if x == 'R' || y == 'R' {
            entries
                .next()
                .map(|p| String::from_utf8_lossy(p).into_owned())
        } else {
            None
        };

        if let Some(change) = make_change(x, y, &path, old.as_deref(), workspace_root, repo_root) {
            changes.push(change);
        }
        if changes.len() >= STATUS_ENTRY_CAP {
            truncated = true;
            break;
        }
    }

    (changes, branch, truncated)
}

/// Find the largest byte prefix of `raw` (≤ `cap`) that ends at a NUL
/// boundary, so no entry is split mid-path.
fn truncate_at_nul(raw: &[u8], cap: usize) -> usize {
    if raw.len() <= cap {
        return raw.len();
    }
    match raw[..cap].iter().rposition(|&b| b == 0) {
        Some(pos) => pos + 1,
        None => 0,
    }
}

/// Parse the `## <branch>` header line (ADR-078 decision 5 — the
/// header already carries ahead/behind, but v1 shows only the name).
fn parse_branch_line(line: &[u8]) -> String {
    let s = String::from_utf8_lossy(line);
    let s = s.trim();
    // Detached HEAD.
    if s.starts_with("HEAD (no branch)") {
        return "HEAD".to_string();
    }
    // Empty repository (git <2.35: "Initial commit on main").
    for prefix in ["No commits yet on ", "Initial commit on "] {
        if let Some(rest) = s.strip_prefix(prefix) {
            return rest.trim().to_string();
        }
    }
    // "main" | "main...origin/main [ahead 1, behind 2]".
    s.split("...").next().unwrap_or("HEAD").trim().to_string()
}

/// Index status from porcelain column X.
fn index_status(x: char) -> GitIndexStatus {
    match x {
        'M' | 'T' => GitIndexStatus::Modified,
        'A' => GitIndexStatus::Added,
        'D' => GitIndexStatus::Deleted,
        'R' | 'C' => GitIndexStatus::Renamed,
        _ => GitIndexStatus::Unmodified,
    }
}

/// Worktree status from porcelain column Y.
fn worktree_status(y: char) -> GitWorktreeStatus {
    match y {
        'M' | 'T' => GitWorktreeStatus::Modified,
        // Lowercase `m` = submodule has modified content (porcelain v1).
        'm' => GitWorktreeStatus::Modified,
        'D' => GitWorktreeStatus::Deleted,
        '?' => GitWorktreeStatus::Untracked,
        _ => GitWorktreeStatus::Unmodified,
    }
}

/// True when the porcelain XY pair denotes an unmerged (conflicted) path.
/// Porcelain v1 encodes conflicts as X/Y ∈ {A, D, U} (ours/theirs state):
/// `UU`, `AU`, `UD`, `UA`, `DU`, `AA`, `DD`. `U` never appears outside
/// conflicts, and `AA`/`DD` cannot be produced by staged+worktree combos
/// (a staged add is `A `, a worktree add is `??`).
fn is_unmerged(x: char, y: char) -> bool {
    x == 'U' || y == 'U' || (x == 'A' && y == 'A') || (x == 'D' && y == 'D')
}

/// Convert a repo-root-relative porcelain path to a workspace-root-
/// relative path, or `None` when it lies outside the workspace root
/// (dropped by the ADR-078 decision 3 range filter).
fn repo_to_workspace_rel(
    repo_root: &Path,
    workspace_root: &Path,
    repo_rel: &str,
) -> Option<String> {
    let abs = repo_root.join(repo_rel);
    let rel = abs.strip_prefix(workspace_root).ok()?;
    Some(rel.to_string_lossy().replace('\\', "/"))
}

/// Build a [`GitChangeDto`] from porcelain XY + paths, applying the
/// workspace-root range filter.
fn make_change(
    x: char,
    y: char,
    path_repo_rel: &str,
    old_repo_rel: Option<&str>,
    workspace_root: &Path,
    repo_root: &Path,
) -> Option<GitChangeDto> {
    let ws_path = repo_to_workspace_rel(repo_root, workspace_root, path_repo_rel)?;
    let ws_old = old_repo_rel.and_then(|o| repo_to_workspace_rel(repo_root, workspace_root, o));
    // Unmerged paths map both columns to Conflicted so a conflicted file is
    // never silently rendered as "clean" (ADR-078 invariant 5). `staged` stays
    // false — a conflict is unresolved, not staged.
    let (index, worktree, staged) = if is_unmerged(x, y) {
        (
            GitIndexStatus::Conflicted,
            GitWorktreeStatus::Conflicted,
            false,
        )
    } else {
        let index = index_status(x);
        (
            index,
            worktree_status(y),
            index != GitIndexStatus::Unmodified,
        )
    };
    Some(GitChangeDto {
        path: ws_path,
        old_path: ws_old,
        index,
        worktree,
        staged,
    })
}

/// Status sort: conflicts first, then staged, then M / U / D / A / R groups
/// (ADR-078 decision 4 — v1 fixed order, no user sorting).
fn status_sort_key(c: &GitChangeDto) -> (u8, u8, &str) {
    if c.index == GitIndexStatus::Conflicted || c.worktree == GitWorktreeStatus::Conflicted {
        return (0, 0, &c.path); // conflicts always on top
    }
    let staged_rank = if c.staged { 0 } else { 1 };
    let type_rank = if c.worktree == GitWorktreeStatus::Untracked {
        1 // U
    } else if c.index == GitIndexStatus::Modified || c.worktree == GitWorktreeStatus::Modified {
        0 // M
    } else if c.index == GitIndexStatus::Deleted || c.worktree == GitWorktreeStatus::Deleted {
        2 // D
    } else if c.index == GitIndexStatus::Added {
        3 // A
    } else if c.index == GitIndexStatus::Renamed {
        4 // R
    } else {
        5
    };
    (staged_rank, type_rank, &c.path)
}

// ── Blob read helpers ──────────────────────────────────────────────────────

/// Parse `git diff-tree -r --name-status -z --no-commit-id --root <rev>`.
///
/// Record layout (every field NUL-terminated, per `-z`):
/// - non-rename/copy: `<status>\0<path>\0`
/// - rename/copy:     `<status>\0<new_path>\0<old_path>\0`
///
/// `<status>` is one letter optionally followed by a score or type info
/// (`M`, `A`, `D`, `R<score>`, `C<score>`, `T<type>`). We only inspect
/// the leading byte.
///
/// `truncated` is set when the byte cap was hit (mirrors the working-tree
/// `parse_status_porcelain` truncation contract so the same UI flag works
/// for both code paths).
fn parse_diff_tree_name_status(
    raw: &[u8],
    repo_root: &Path,
    workspace_root: &Path,
) -> (Vec<GitChangeDto>, bool) {
    let mut changes = Vec::new();
    let mut truncated = false;

    let cap_end = truncate_at_nul(raw, STATUS_BYTE_CAP);
    if cap_end < raw.len() {
        truncated = true;
    }
    let slice = &raw[..cap_end];
    let mut tokens = slice.split(|&b| b == 0).peekable();

    while let Some(status_tok) = tokens.next() {
        if status_tok.is_empty() {
            continue;
        }
        let status = status_tok[0] as char;
        // Each record consumes one or two path tokens.
        let path_tok = match tokens.next() {
            Some(t) if !t.is_empty() => t,
            _ => continue,
        };
        // `R` / `C` records consume a second path token (the old path).
        let old_path_tok = if status == 'R' || status == 'C' {
            tokens.next()
        } else {
            None
        };

        let path = String::from_utf8_lossy(path_tok).into_owned();
        let old_path = old_path_tok.map(|p| String::from_utf8_lossy(p).into_owned());

        if let Some(change) = make_commit_change(
            status,
            &path,
            old_path.as_deref(),
            workspace_root,
            repo_root,
        ) {
            changes.push(change);
        }
        if changes.len() >= STATUS_ENTRY_CAP {
            truncated = true;
            break;
        }
    }

    (changes, truncated)
}

/// Map a `git diff-tree` status letter to (index, worktree, staged).
///
/// A commit's file list is a single-axis view (M/A/D/R/C/T vs parent)
/// — the legacy dual-axis worktree semantics don't apply. We mirror the
/// change on both columns and force `staged = false`: the "staged" badge
/// in GitStatusPanel is reserved for index-vs-worktree divergence, and a
/// historical commit has neither index nor worktree. Setting it true
/// here would make every row of a commit's file list look "已暂存".
fn make_commit_change(
    status: char,
    path: &str,
    old_path: Option<&str>,
    workspace_root: &Path,
    repo_root: &Path,
) -> Option<GitChangeDto> {
    let ws_path = repo_to_workspace_rel(repo_root, workspace_root, path)?;
    let ws_old = old_path.and_then(|o| repo_to_workspace_rel(repo_root, workspace_root, o));
    let (index, worktree) = match status {
        'M' | 'T' => (GitIndexStatus::Modified, GitWorktreeStatus::Modified),
        'A' => (GitIndexStatus::Added, GitWorktreeStatus::Untracked),
        'D' => (GitIndexStatus::Deleted, GitWorktreeStatus::Deleted),
        'R' | 'C' => (GitIndexStatus::Renamed, GitWorktreeStatus::Modified),
        // `U` (unmerged) and unknown statuses: surface as Modified so the
        // file is never silently hidden.
        _ => (GitIndexStatus::Modified, GitWorktreeStatus::Modified),
    };
    Some(GitChangeDto {
        path: ws_path,
        old_path: ws_old,
        index,
        worktree,
        staged: false,
    })
}
async fn cat_file_size(
    git_bin: &str,
    repo_root: &Path,
    rev: &str,
    path: &str,
) -> Result<Option<u64>, GitError> {
    let mut cmd = git_cmd(git_bin, repo_root);
    cmd.arg("cat-file").arg("-s").arg(format!("{rev}:{path}"));
    let out = run_git(cmd).await?;
    if !out.status.success() {
        return Ok(None);
    }
    let s = String::from_utf8_lossy(&out.stdout);
    Ok(s.trim().parse::<u64>().ok())
}

/// Resolve `rev` to a canonical commit SHA.
///
/// Uses `git rev-parse --verify <rev>^{commit}` so the result is always
/// a commit SHA (not a tree / blob SHA), and `<rev>^` first-parent
/// shorthand is expanded to the parent commit's full SHA. This is the
/// authoritative form to surface to the UI — the client never has to
/// reason about git's `<sha>^` / `<sha>~N` shorthand or whether
/// `HEAD` resolves to a branch tip.
///
/// Returns `GitError::BadRequest` if the ref is unknown to the repo,
/// so the caller maps to a clean 4xx rather than a misleading 5xx.
async fn rev_parse_commit(git_bin: &str, repo_root: &Path, rev: &str) -> Result<String, GitError> {
    let mut cmd = git_cmd(git_bin, repo_root);
    cmd.arg("rev-parse")
        .arg("--verify")
        .arg(format!("{rev}^{{commit}}"));
    let out = run_git(cmd).await?;
    if !out.status.success() {
        return Err(GitError::BadRequest(format!(
            "rev-parse failed for {rev:?}: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// Count commits in the repo history that touch `repo_rel_path`
/// (already validated as repo-root-relative by the caller, or `None`
/// for repo-wide). Powers `GitLogPagination.totalCount` so the client
/// can render "Page X of Y" + decide whether to surface the search /
/// pagination chrome.
///
/// `git rev-list --count HEAD -- <path>` is O(n) but sub-100ms for
/// repos under ~100k commits. We accept an already-validated
/// repo-root-relative path so this helper doesn't repeat
/// `resolve_within_static` (which the caller has already done for
/// `git log -- <path>`).
async fn rev_list_count(
    git_bin: &str,
    repo_root: &Path,
    repo_rel_path: Option<&str>,
) -> Result<u32, GitError> {
    let mut cmd = git_cmd(git_bin, repo_root);
    cmd.arg("rev-list").arg("--count").arg("HEAD");
    if let Some(p) = repo_rel_path.filter(|p| !p.is_empty()) {
        cmd.arg("--").arg(p);
    }
    let out = run_git(cmd).await?;
    if !out.status.success() {
        return Err(GitError::GitFailed(format!(
            "rev-list --count failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(String::from_utf8_lossy(&out.stdout)
        .trim()
        .parse::<u32>()
        .unwrap_or(0))
}

/// Find the previous commit in `path`'s file-history — i.e. the commit
/// that immediately precedes `head_ref` when listing commits that touched
/// `path` (newest first). Used by `diff_two_refs` to pick the base ref
/// that matches what the user sees in the diff banner's `CommitPicker`
/// dropdown (which also lists by file).
///
/// Returns:
/// - `Some(prev_sha)` — `head_ref` is the newest commit touching `path`
///   AND there's at least one older commit touching `path` too.
/// - `None` — `path` has no history yet, or `head_ref` is the only
///   commit touching `path`, or `head_ref` itself isn't in
///   `path`'s file-history (caller should fall back to first-parent).
///
/// Implementation: `git log -n 2 --pretty=%H <head_ref> -- <path>`.
/// Line 1 is the newest file-history commit (expected to be `head_ref`);
/// line 2 is the previous one. We don't validate line 1 == `head_ref`
/// because the caller decides whether to use this signal — the function
/// is a pure lookup and intentionally does not error on the
/// head-not-in-file-history case (the contract is "give me line 2 of
/// `git log` or None").
async fn file_history_prev(
    git_bin: &str,
    repo_root: &Path,
    head_ref: &str,
    path: &str,
) -> Result<Option<String>, GitError> {
    let mut cmd = git_cmd(git_bin, repo_root);
    cmd.args(["log", "-n", "2", "--pretty=%H", head_ref, "--", path]);
    let out = run_git(cmd).await?;
    if !out.status.success() {
        // `git log` on a non-existent path or rev exits non-zero —
        // not an error for this helper (caller falls back).
        return Ok(None);
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let lines: Vec<&str> = text.lines().collect();
    if lines.len() < 2 {
        // File has only one (or zero) commits touching it — no prev.
        return Ok(None);
    }
    Ok(Some(lines[1].trim().to_string()))
}

/// Newest commit that touched `path`, walking back from `at_ref` — line 1
/// of `git log <at_ref> -- <path>`, i.e. exactly the commit the diff
/// banner's `CommitPicker` renders as its first row.
///
/// Used by the working-tree diff variants so the base banner label is a
/// commit the (file-scoped) picker can actually show. `HEAD` is the wrong
/// label when HEAD did not touch `path`: the file's last committed state
/// is, by definition, the newest commit that did. Without this the banner
/// displays HEAD while the picker lists file-history — HEAD is then
/// absent from the menu and unsearchable.
///
/// Returns `None` when `path` has no history reachable from `at_ref`
/// (untracked file, newly-created path, or a path outside the tree), so
/// the caller keeps its original base ref.
///
/// Implementation: `git log -n 1 --pretty=%H <at_ref> -- <path>`.
async fn file_history_head(
    git_bin: &str,
    repo_root: &Path,
    at_ref: &str,
    path: &str,
) -> Result<Option<String>, GitError> {
    let mut cmd = git_cmd(git_bin, repo_root);
    cmd.args(["log", "-n", "1", "--pretty=%H", at_ref, "--", path]);
    let out = run_git(cmd).await?;
    if !out.status.success() {
        // Non-existent path / rev — not an error for this helper.
        return Ok(None);
    }
    let text = String::from_utf8_lossy(&out.stdout);
    Ok(text
        .lines()
        .next()
        .map(|l| l.trim().to_string())
        .filter(|s| !s.is_empty()))
}

/// `git show <rev>:<path>` — raw blob bytes for a diff side, with
/// size pre-check (`cat-file -s` before reading, so a huge blob never
/// enters memory — ADR-078 decision 4 > 2 MiB → `TooLarge`). `rev` is
/// `"HEAD"` or `""` (index).
async fn read_blob(
    git_bin: &str,
    repo_root: &Path,
    rev: &str,
    path: &str,
) -> Result<BlobRead, GitError> {
    let Some(size) = cat_file_size(git_bin, repo_root, rev, path).await? else {
        return Ok(BlobRead::Missing);
    };
    if size > DIFF_SIZE_CAP {
        return Ok(BlobRead::TooLarge);
    }
    let mut cmd = git_cmd(git_bin, repo_root);
    cmd.arg("show").arg(format!("{rev}:{path}"));
    let out = run_git(cmd).await?;
    if !out.status.success() {
        return Ok(BlobRead::Missing);
    }
    Ok(BlobRead::Ok(out.stdout))
}

// ── Trait impl ─────────────────────────────────────────────────────────────

#[async_trait]
impl GitQueryService for RuntimeGitQueryService {
    async fn status(&self, params: &GitStatusParams) -> Result<GitStatusResponse, GitError> {
        let workspace_root = resolve_workspace_root(&self.work_dir, params.workspace_id.as_deref())
            .map_err(workspace_to_git_error)?;
        let canonical_ws = std::fs::canonicalize(&workspace_root).unwrap_or(workspace_root);

        let Some(repo_root) = discover_repo_root(&canonical_ws) else {
            // Explicit non-repo state — not an error (ADR-078 invariant 5).
            return Ok(GitStatusResponse {
                is_repo: false,
                branch: None,
                error: Some("not_a_repo".to_string()),
                truncated: false,
                changes: vec![],
                rev: None,
            });
        };

        // ADR-XXX: rev=Some(h) → list files touched by commit h
        // (parsed via `git diff-tree -r --name-status -z --root --no-commit-id h`).
        // rev=None or rev=Some("") → current working-tree status (legacy path).
        let trimmed_rev = params
            .rev
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty());

        if let Some(rev) = trimmed_rev {
            return self.status_for_commit(&repo_root, &canonical_ws, rev).await;
        }

        let mut cmd = git_cmd(&self.git_bin, &repo_root);
        cmd.args([
            "status",
            "--porcelain=v1",
            "-z",
            "--untracked-files=all",
            "--branch",
        ]);
        let out = match run_git(cmd).await {
            Ok(out) => out,
            Err(GitError::GitUnavailable(_msg)) => {
                // ADR-078 decision 4 / invariant 5: a missing git binary is
                // an explicit UI state for /git/status (200 + is_repo:false
                // + error:"git_unavailable"), NOT a 5xx — the Desktop shows
                // the dedicated empty state, never a generic error.
                return Ok(GitStatusResponse {
                    is_repo: false,
                    branch: None,
                    error: Some("git_unavailable".to_string()),
                    truncated: false,
                    changes: vec![],
                    rev: None,
                });
            }
            Err(e) => return Err(e),
        };
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            if looks_like_not_a_repo(&stderr) {
                return Ok(GitStatusResponse {
                    is_repo: false,
                    branch: None,
                    error: Some("not_a_repo".to_string()),
                    truncated: false,
                    changes: vec![],
                    rev: None,
                });
            }
            return Err(GitError::GitFailed(format!(
                "git status: {}",
                stderr.trim()
            )));
        }

        let (mut changes, branch, truncated) =
            parse_status_porcelain(&out.stdout, &canonical_ws, &repo_root);
        changes.sort_by(|a, b| status_sort_key(a).cmp(&status_sort_key(b)));

        Ok(GitStatusResponse {
            is_repo: true,
            branch: Some(branch),
            error: None,
            truncated,
            changes,
            rev: None,
        })
    }

    async fn diff(&self, params: &GitDiffParams) -> Result<GitDiffResponse, GitError> {
        // ADR-078 extension: accept arbitrary `base_ref` / `head_ref` so the
        // frontend can compare any two git revisions. The legacy semantics
        // (worktree vs HEAD) survive as the defaults - `base_ref` defaults
        // to "HEAD", `head_ref` defaults to "" which routes through
        // `diff_with_worktree` below (preserving untracked / deleted handling).
        let base_ref = params.base_ref.as_deref().unwrap_or("HEAD");
        let head_ref = params.head_ref.as_deref().unwrap_or("");
        if base_ref.is_empty() {
            return Err(GitError::BadRequest(
                "base_ref must not be empty (use \"HEAD\" for the current branch tip)".into(),
            ));
        }

        let (canonical_ws, _, _) =
            resolve_within_static(&self.work_dir, params.workspace_id.as_deref(), &params.path)
                .map_err(workspace_to_git_error)?;

        let repo_root = discover_repo_root(&canonical_ws)
            .ok_or_else(|| GitError::NotARepo(canonical_ws.display().to_string()))?;

        // ADR-078 decision 3: workspace-relative -> absolute -> validate ->
        // strip repo_root prefix -> repo-root-relative.
        let abs_path = canonical_ws.join(&params.path);
        let repo_rel = abs_path
            .strip_prefix(&repo_root)
            .map_err(|_| GitError::InvalidPath("path is outside the repository root".into()))?
            .to_string_lossy()
            .replace('\\', "/");

        if head_ref.is_empty() {
            self.diff_with_worktree(&repo_root, &abs_path, &repo_rel, base_ref)
                .await
        } else {
            self.diff_two_refs(&repo_root, &repo_rel, base_ref, head_ref)
                .await
        }
    }

    async fn log(&self, params: &GitLogParams) -> Result<GitLogResponse, GitError> {
        let workspace_root = resolve_workspace_root(&self.work_dir, params.workspace_id.as_deref())
            .map_err(workspace_to_git_error)?;
        let canonical_ws = std::fs::canonicalize(&workspace_root).unwrap_or(workspace_root);

        let repo_root = discover_repo_root(&canonical_ws)
            .ok_or_else(|| GitError::NotARepo(canonical_ws.display().to_string()))?;

        let limit = params.limit.unwrap_or(LOG_DEFAULT_LIMIT).min(LOG_MAX_LIMIT);
        // `skip` is 0-indexed: skip=0 returns the first `limit` commits,
        // skip=limit returns the next `limit`, etc. Caller computes
        // `skip = (currentPage - 1) * pageSize`.
        let skip = params.skip.unwrap_or(0);

        // Resolve `path` (workspace-root-relative) to repo-root-relative once,
        // then reuse for `git log -- <repo_rel>` AND `git rev-list --count ... -- <repo_rel>`.
        // Doing the resolution twice would risk divergence if the
        // workspace layout changed mid-call, plus we'd double the
        // filesystem stats `resolve_within_static` performs.
        let repo_rel: Option<String> = match params.path.as_deref().filter(|p| !p.is_empty()) {
            None => None,
            Some(path) => {
                let (canonical_ws, _, _) =
                    resolve_within_static(&self.work_dir, params.workspace_id.as_deref(), path)
                        .map_err(workspace_to_git_error)?;
                let rel = canonical_ws
                    .join(path)
                    .strip_prefix(&repo_root)
                    .map_err(|_| {
                        GitError::InvalidPath("path is outside the repository root".into())
                    })?
                    .to_string_lossy()
                    .replace('\\', "/");
                Some(rel)
            }
        };

        let mut cmd = git_cmd(&self.git_bin, &repo_root);
        cmd.args([
            "log",
            "--no-ext-diff",
            "--skip",
            &skip.to_string(),
            "-n",
            &limit.to_string(),
            "--pretty=format:%H%x1f%h%x1f%an%x1f%aI%x1f%s",
        ]);
        if let Some(rel) = repo_rel.as_deref() {
            cmd.arg("--").arg(rel);
        }

        let out = run_git(cmd).await?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            if looks_like_not_a_repo(&stderr) {
                return Err(GitError::NotARepo(stderr.trim().to_string()));
            }
            return Err(GitError::GitFailed(format!("git log: {}", stderr.trim())));
        }

        let text = String::from_utf8_lossy(&out.stdout);
        let commits: Vec<GitCommitDto> = text
            .lines()
            .filter(|l| !l.is_empty())
            .map(|line| {
                let mut parts = line.splitn(5, '\x1f');
                let hash = parts.next().unwrap_or("").to_string();
                let short_hash = parts.next().unwrap_or("").to_string();
                let author = parts.next().unwrap_or("").to_string();
                let date = parts.next().unwrap_or("").to_string();
                let subject = parts.next().unwrap_or("").to_string();
                GitCommitDto {
                    hash,
                    short_hash,
                    author,
                    date,
                    subject,
                }
            })
            .collect();

        // `totalCount` powers the client's "Page X of Y" + search / pagination
        // chrome collapse. `git rev-list --count` is O(n) but stays sub-100ms
        // for repos up to ~100k commits; we already pay this kind of cost
        // elsewhere in the status path. Failure here is non-fatal — fall back
        // to "at least the page we got back" so the dropdown still works on
        // a partially-broken repo (mirrors how `assemble_diff` / `read_blob`
        // degrade on `Missing`).
        let total_count = match rev_list_count(&self.git_bin, &repo_root, repo_rel.as_deref()).await
        {
            Ok(n) => n,
            Err(_) => skip + commits.len() as u32,
        };
        let total_pages = if limit == 0 {
            0
        } else {
            total_count.div_ceil(limit).max(1)
        };
        // `limit > 0` is guaranteed by the guard above; the `checked_div`
        // dance keeps clippy's `manual_checked_ops` lint happy.
        let current_page = if limit == 0 {
            1
        } else {
            // SAFETY: limit > 0 (guarded above).
            skip.checked_div(limit).unwrap_or(0) + 1
        };

        Ok(GitLogResponse {
            commits,
            pagination: GitLogPagination {
                current_page,
                total_pages,
                page_size: limit,
                total_count,
            },
        })
    }

    /// `POST /git/revert` — discard the uncommitted changes of one path,
    /// restoring it to HEAD. The one deliberate WRITE in the git API
    /// family; the Desktop guards it with a confirm dialog.
    ///
    /// Semantics (verified against real git, Windows CRLF included):
    /// - modified / deleted / conflicted → `git restore --source=HEAD`
    ///   rewrites index + worktree from HEAD;
    /// - staged-added / staged rename-new-path (in the index but not in
    ///   HEAD) → the same `git restore --source=HEAD` REMOVES them from
    ///   index and worktree, no `git rm` needed;
    /// - rename rows → restore `old_path` first (splits the rename back
    ///   into a staged-add, see ADR-078 DTO `oldPath`), then the row path;
    /// - untracked (pathspec matches nothing) → delete the file directly
    ///   (IDE "Discard Changes" semantics).
    async fn revert(&self, params: &GitRevertParams) -> Result<GitRevertResponse, GitError> {
        // Trust boundary: a bare `path` would resolve to the workspace
        // root and `git restore --source=HEAD -- .` would nuke the whole
        // working tree. Reject it like every other invalid path.
        if params.path.trim().is_empty() {
            return Err(GitError::BadRequest(
                "path must not be empty (revert targets a single file)".into(),
            ));
        }

        let (canonical_ws, _, _) =
            resolve_within_static(&self.work_dir, params.workspace_id.as_deref(), &params.path)
                .map_err(workspace_to_git_error)?;
        let repo_root = discover_repo_root(&canonical_ws)
            .ok_or_else(|| GitError::NotARepo(canonical_ws.display().to_string()))?;

        // Restore `old_path` (the rename source, which IS in HEAD) before
        // the row path so the index stops recording the rename and the new
        // path is left as a plain staged-add — which the same command then
        // unwinds (removed from index + worktree).
        let mut targets: Vec<(String, PathBuf)> = Vec::with_capacity(2);
        if let Some(old) = params.old_path.as_deref().filter(|o| !o.is_empty()) {
            let (_, _, _) = resolve_within_static(&self.work_dir, params.workspace_id.as_deref(), old)
                .map_err(workspace_to_git_error)?;
            targets.push((old.to_string(), canonical_ws.join(old)));
        }
        targets.push((params.path.clone(), canonical_ws.join(&params.path)));

        for (ws_rel, abs) in &targets {
            let repo_rel = abs
                .strip_prefix(&repo_root)
                .map_err(|_| {
                    GitError::InvalidPath("path is outside the repository root".into())
                })?
                .to_string_lossy()
                .replace('\\', "/");

            let mut cmd = git_cmd(&self.git_bin, &repo_root);
            cmd.args(["restore", "--staged", "--worktree", "--source=HEAD", "--"]);
            cmd.arg(&repo_rel);
            let out = run_git_mut(cmd).await?;
            if out.status.success() {
                continue;
            }
            let stderr = String::from_utf8_lossy(&out.stderr);
            if stderr.contains("did not match any file(s) known to git") {
                // Untracked: no source to restore from — discard the file
                // itself (IDE "Discard" semantics). Already-gone is fine.
                match std::fs::remove_file(abs) {
                    Ok(()) => continue,
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                    Err(e) => return Err(GitError::Io(e)),
                }
            }
            if looks_like_not_a_repo(&stderr) {
                return Err(GitError::NotARepo(stderr.trim().to_string()));
            }
            return Err(GitError::GitFailed(format!(
                "git restore {}: {}",
                ws_rel,
                stderr.trim()
            )));
        }

        Ok(GitRevertResponse {
            path: params.path.clone(),
            old_path: params.old_path.clone(),
        })
    }
}

impl RuntimeGitQueryService {
    /// ADR-XXX: list files touched by commit `rev`. Backend for the
    /// Git Status Bar history dropdown. Drives off `git diff-tree
    /// -r --name-status -z --no-commit-id --root <rev>`:
    ///
    /// - `--root` makes the initial commit work (its "parent" is the
    ///   empty tree, so without `--root` it returns nothing);
    /// - `-r` recurses into subtrees;
    /// - `-z` NUL-separates every field, including rename paths;
    /// - `--no-commit-id` suppresses the commit hash header so only
    ///   the change records are emitted.
    ///
    /// The output format per record (NUL-terminated):
    /// - `<status>\0<path>\0` for non-rename/copy;
    /// - `<status>\0<new>\0<old>\0` for rename/copy.
    ///
    /// `<status>` is a single letter optionally followed by a score
    /// (`M`, `A`, `D`, `R<score>`, `C<score>`, `T<type>`).
    ///
    /// Merge commits: `git diff-tree` returns the diff against the
    /// first parent — that is what the user expects from "files in
    /// this commit" (the alternative, `--cc`, folds common changes
    /// across parents and is rarely what a human wants).
    async fn status_for_commit(
        &self,
        repo_root: &Path,
        workspace_root: &Path,
        rev: &str,
    ) -> Result<GitStatusResponse, GitError> {
        // 1. Resolve the commit label (short SHA + subject prefix) for the
        //    bar header — separate command so we can degrade gracefully if
        //    it fails (the diff-tree output below is the source of truth).
        let label_cmd = {
            let mut c = git_cmd(&self.git_bin, repo_root);
            c.args(["log", "-1", "--format=%h %s"]);
            c.arg(rev);
            c
        };
        let label = match run_git(label_cmd).await {
            Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).trim().to_string(),
            _ => rev.to_string(),
        };

        // 2. diff-tree -r --name-status -z --no-commit-id --root <rev>
        let mut cmd = git_cmd(&self.git_bin, repo_root);
        cmd.args([
            "diff-tree",
            "-r",
            "--name-status",
            "-z",
            "--no-commit-id",
            "--root",
        ]);
        cmd.arg(rev);
        let out = match run_git(cmd).await {
            Ok(o) => o,
            Err(GitError::GitUnavailable(_)) => {
                return Ok(GitStatusResponse {
                    is_repo: true,
                    branch: Some(label),
                    error: Some("git_unavailable".to_string()),
                    truncated: false,
                    changes: vec![],
                    rev: Some(rev.to_string()),
                });
            }
            Err(e) => return Err(e),
        };
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            // Unresolvable rev → BadRequest so the Desktop surfaces a
            // real error instead of silently rendering "0 files" for
            // a typo'd hash.
            return Err(GitError::BadRequest(format!(
                "git diff-tree {rev}: {}",
                stderr.trim()
            )));
        }

        let (mut changes, truncated) =
            parse_diff_tree_name_status(&out.stdout, repo_root, workspace_root);
        changes.sort_by(|a, b| status_sort_key(a).cmp(&status_sort_key(b)));

        Ok(GitStatusResponse {
            is_repo: true,
            branch: Some(label),
            error: None,
            truncated,
            changes,
            rev: Some(rev.to_string()),
        })
    }
    /// Single-path `git status --porcelain=v1 -z` → `(x, y, old)` for
    /// the requested repo-relative path, or `None` when the path is not
    /// in the status output (tracked & clean).
    ///
    /// Scans the full status output instead of `-- <path>`: git's pathspec
    /// matches the *old* path of a rename pair (and returns nothing for
    /// the new path), so a single-path query would miss `R` entries.
    async fn path_status(
        &self,
        repo_root: &Path,
        repo_rel: &str,
    ) -> Result<Option<(char, char, Option<String>)>, GitError> {
        let mut cmd = git_cmd(&self.git_bin, repo_root);
        cmd.args(["status", "--porcelain=v1", "-z", "--untracked-files=all"]);
        let out = run_git(cmd).await?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            if looks_like_not_a_repo(&stderr) {
                return Err(GitError::NotARepo(stderr.trim().to_string()));
            }
            return Err(GitError::GitFailed(format!(
                "git status: {}",
                stderr.trim()
            )));
        }

        let cap_end = truncate_at_nul(&out.stdout, STATUS_BYTE_CAP);
        let mut entries = out.stdout[..cap_end].split(|&b| b == 0);
        while let Some(entry) = entries.next() {
            // `XY <path>` (no `##` header — `--branch` is omitted here).
            if entry.len() < 4 || entry[2] != b' ' {
                continue;
            }
            let x = entry[0] as char;
            let y = entry[1] as char;
            let path = String::from_utf8_lossy(&entry[3..]).into_owned();
            // Rename: current entry is the new path, next is the old.
            let old = if x == 'R' || y == 'R' {
                entries
                    .next()
                    .map(|p| String::from_utf8_lossy(p).into_owned())
            } else {
                None
            };
            if path == repo_rel || old.as_deref() == Some(repo_rel) {
                return Ok(Some((x, y, old)));
            }
        }
        Ok(None)
    }

    /// Working-tree variant: `original = base_ref:<path>`, `modified =
    /// <working-tree>`. Mirrors the original ADR-078 implementation
    /// (untracked / deleted / staged) but parameterises the base ref
    /// instead of hard-coding "HEAD". `head_rev` is always `None`
    /// (working tree → client renders "Working Tree").
    async fn diff_with_worktree(
        &self,
        repo_root: &Path,
        abs_path: &Path,
        repo_rel: &str,
        base_ref: &str,
    ) -> Result<GitDiffResponse, GitError> {
        // Resolve base_ref to a canonical SHA up front — the UI labels
        // both diff-side banners with the first 7 chars, so `<sha>^`
        // / `HEAD` must be normalised server-side (UI has no git
        // knowledge, per ADR-009 v2 — git semantics live here).
        //
        // When the caller passes the default `"HEAD"`, promote it to the
        // file-history head (newest commit touching this path). HEAD is
        // only the right label when HEAD itself touched the file; if a
        // later commit moved HEAD forward by editing *other* files, the
        // file's last committed state is still the earlier commit — and
        // that earlier commit is what the banner's `CommitPicker`
        // (`git log -- <path>`) lists as its first row. Labelling with
        // HEAD instead makes that label unselectable / unsearchable in
        // the menu. An explicit caller-chosen base (any sha) is honoured
        // verbatim. Blob content is unchanged: `F1:path == HEAD:path`
        // whenever no commit between them touched `path`.
        let effective_base_ref = if base_ref == "HEAD" {
            match file_history_head(&self.git_bin, repo_root, base_ref, repo_rel).await? {
                Some(head_sha) => head_sha,
                None => base_ref.to_string(),
            }
        } else {
            base_ref.to_string()
        };
        let base_rev = rev_parse_commit(&self.git_bin, repo_root, &effective_base_ref).await?;
        // A tracked-and-clean file simply has no `git status` entry. Treat
        // it as `XY = "  "` and fall through, so the shared code below reads
        // `effective_base_ref:<path>` vs the working tree and therefore
        // honours an explicit caller-chosen base. (A separate `diff_clean`
        // branch used to re-derive the base from HEAD here, so comparing an
        // older commit against "Working Tree" on a clean file silently
        // rendered as an empty diff.)
        let (x, y, rename_old) = self
            .path_status(repo_root, repo_rel)
            .await?
            .unwrap_or((' ', ' ', None));
        let head_repo_rel = if x == 'R' || y == 'R' {
            rename_old.as_deref().unwrap_or(repo_rel)
        } else {
            repo_rel
        };
        let is_untracked = x == '?' && y == '?';
        let is_worktree_deleted = y == 'D';
        let original = if is_untracked {
            Vec::new()
        } else {
            match read_blob(&self.git_bin, repo_root, &effective_base_ref, head_repo_rel).await? {
                BlobRead::Missing => Vec::new(),
                BlobRead::TooLarge => return Ok(binary_diff_response(Some(base_rev), None)),
                BlobRead::Ok(bytes) => bytes,
            }
        };
        let modified = if is_worktree_deleted {
            Vec::new()
        } else {
            match std::fs::metadata(abs_path) {
                Ok(md) if md.len() > DIFF_SIZE_CAP => {
                    return Ok(binary_diff_response(Some(base_rev), None));
                }
                Ok(_) => std::fs::read(abs_path)?,
                Err(_) => Vec::new(),
            }
        };
        Ok(assemble_diff(
            original,
            modified,
            is_untracked,
            is_worktree_deleted,
            Some(base_rev),
            None,
        ))
    }

    /// Two-ref variant: `original = base_ref:<path>`, `modified =
    /// head_ref:<path>`. No working-tree involvement - used when the
    /// caller wants to compare two commits (or commit vs index).
    /// Both refs are canonicalised up front so the UI can label both
    /// banners with a clean first-7-chars hash regardless of whether
    /// the caller passed `<sha>^`, a branch name, or `HEAD`.
    ///
    /// Base ref semantics: when the caller passes `head_ref^` (the
    /// frontend's "first-parent" shortcut), we promote it to the
    /// **file-history predecessor** of `head_ref` on `path`. This keeps
    /// the diff banner label consistent with the `CommitPicker` list
    /// (which is `git log -- <path>`, also file-history):
    ///
    /// - The right banner = `head_ref`'s commit hash (list line 1).
    /// - The left banner  = the commit that last touched `path` before
    ///   `head_ref` (list line 2, when present).
    ///
    /// Git's first-parent `<head>^` is NOT the same as the file-history
    /// predecessor: if `<head>^` did not touch `path`, the predecessor
    /// is some earlier commit that did. Showing `<head>^` on the left
    /// banner when the picker's second row points elsewhere is the bug
    /// this function fixes. Fallback to first-parent happens when
    /// `path` has no older commit (file was introduced in `head_ref`).
    ///
    /// Any other `base_ref` is honoured verbatim: `X` vs `X` reports no
    /// changes, and `A` vs `B` compares exactly those two blobs.
    async fn diff_two_refs(
        &self,
        repo_root: &Path,
        repo_rel: &str,
        base_ref: &str,
        head_ref: &str,
    ) -> Result<GitDiffResponse, GitError> {
        // `rev_parse_commit` is sub-millisecond; do both sides up
        // front so a malformed ref surfaces here (clean 4xx) rather
        // than buried inside `git show <rev>:<path>` stderr (which
        // `read_blob` silently maps to `Missing`).
        //
        // `:` is git's index-stage shorthand — `git show :<path>` reads
        // the staged blob. It is not a commit-ish, so the canonical-SHA
        // step (`rev-parse "<head_ref>^{commit}"`) and the file-history
        // predecessor lookup both reject it. The index blob is reachable
        // through `read_blob` with `rev=""` (formatted as `:path` — see
        // its doc comment); `head_rev` is `None` because the index has
        // no canonical SHA to surface to the UI.
        let requested_base_rev = rev_parse_commit(&self.git_bin, repo_root, base_ref).await?;
        let head_rev: Option<String> = if head_ref == ":" {
            None
        } else {
            Some(rev_parse_commit(&self.git_bin, repo_root, head_ref).await?)
        };
        // Promote the caller's first-parent shorthand (`<head>^`, what the
        // Git status panel sends when opening "commit X vs X^") to the
        // file-history predecessor of `head_ref` on `path`. That is the
        // authoritative "what did this file look like right before
        // head_ref's edit" answer — and matches the row above head in
        // the diff banner's `CommitPicker` (`git log -- <path>`).
        //
        // Every other base_ref is an explicit user choice (both diff-side
        // banners send canonical SHAs) and is honoured verbatim. Overriding
        // it unconditionally was the bug: picking the same commit on both
        // sides still rendered X-vs-predecessor as a diff, and any
        // arbitrary two-commit comparison silently became
        // predecessor-vs-head.
        // Skipped for `:` — there is no file-history predecessor of an
        // index ref; the caller's `base_ref` stands verbatim.
        let (effective_base_ref, base_rev) =
            if head_ref != ":" && base_ref == format!("{head_ref}^") {
                match file_history_prev(&self.git_bin, repo_root, head_ref, repo_rel).await? {
                    // File-history had a predecessor. Use it as the actual base
                    // ref so `read_blob` reads the same blob the banner label
                    // promises, and the diff content is the file-scoped diff
                    // (matches IDE / GitKraken default behaviour).
                    Some(prev_sha) => {
                        let prev_canonical =
                            rev_parse_commit(&self.git_bin, repo_root, &prev_sha).await?;
                        (prev_sha, prev_canonical)
                    }
                    // No predecessor (path first appears in head_ref, or head_ref
                    // is the only commit touching path). Honour the caller's
                    // base_ref verbatim — preserves the existing first-parent
                    // semantics for file-introducing commits.
                    None => (base_ref.to_string(), requested_base_rev),
                }
            } else {
                (base_ref.to_string(), requested_base_rev)
            };
        let original = match read_blob(&self.git_bin, repo_root, &effective_base_ref, repo_rel)
            .await?
        {
            BlobRead::Missing => return Ok(binary_diff_response(Some(base_rev), head_rev.clone())),
            BlobRead::TooLarge => return Ok(binary_diff_response(Some(base_rev), head_rev.clone())),
            BlobRead::Ok(bytes) => bytes,
        };
        let modified_for_blob = if head_ref == ":" { "" } else { head_ref };
        let modified = match read_blob(&self.git_bin, repo_root, modified_for_blob, repo_rel).await? {
            BlobRead::Missing => Vec::new(),
            BlobRead::TooLarge => return Ok(binary_diff_response(Some(base_rev), head_rev)),
            BlobRead::Ok(bytes) => bytes,
        };
        Ok(assemble_diff(
            original,
            modified,
            false,
            false,
            Some(base_rev),
            head_rev,
        ))
    }
}

/// A binary-degraded diff (no content returned — ADR-078 decision 4).
/// `base_rev` / `head_rev` are forwarded so the client can still label
/// the two sides even when the binary blob is hidden.
fn binary_diff_response(base_rev: Option<String>, head_rev: Option<String>) -> GitDiffResponse {
    GitDiffResponse {
        kind: GitDiffKind::Binary,
        original: String::new(),
        modified: String::new(),
        base_rev,
        head_rev,
    }
}

/// Final kind classification + UTF-8 conversion. Binary is detected via
/// a NUL byte in either side (sufficient for a text editor context).
/// `base_rev` / `head_rev` are forwarded so the client can label both
/// sides with the canonical commit SHA even for the no-content paths.
fn assemble_diff(
    original: Vec<u8>,
    modified: Vec<u8>,
    is_untracked: bool,
    is_deleted: bool,
    base_rev: Option<String>,
    head_rev: Option<String>,
) -> GitDiffResponse {
    let kind = if is_untracked {
        GitDiffKind::Untracked
    } else if is_deleted {
        GitDiffKind::Deleted
    } else if original.contains(&0) || modified.contains(&0) {
        GitDiffKind::Binary
    } else if original == modified {
        GitDiffKind::NoChange
    } else {
        GitDiffKind::Modified
    };
    // ADR-078 decision 4: binary diffs degrade to a placeholder — no
    // content is returned (mirrors binary_diff_response for >2 MiB).
    let (original, modified) = if kind == GitDiffKind::Binary {
        (String::new(), String::new())
    } else {
        (
            String::from_utf8_lossy(&original).into_owned(),
            String::from_utf8_lossy(&modified).into_owned(),
        )
    };
    GitDiffResponse {
        kind,
        original,
        modified,
        base_rev,
        head_rev,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    /// Skip-guard for integration tests that need a real git binary.
    fn git_available() -> bool {
        std::process::Command::new("git")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    /// Run git in `dir` with deterministic author identity + the same
    /// read-only lock convention as `run_git`.
    fn git_in<I, S>(dir: &Path, args: I) -> std::process::Output
    where
        I: IntoIterator<Item = S>,
        S: AsRef<std::ffi::OsStr>,
    {
        std::process::Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(args)
            .env("GIT_AUTHOR_NAME", "test")
            .env("GIT_AUTHOR_EMAIL", "test@test.local")
            .env("GIT_COMMITTER_NAME", "test")
            .env("GIT_COMMITTER_EMAIL", "test@test.local")
            .env("GIT_OPTIONAL_LOCKS", "0")
            .output()
            .expect("git spawn failed")
    }

    /// `git init -b main` + one committed file (`a.txt` = "hello\n").
    fn init_repo(dir: &Path) {
        let init = git_in(dir, ["init", "-q", "-b", "main"]);
        assert!(init.status.success(), "git init failed: {:?}", init);
        std::fs::write(dir.join("a.txt"), "hello\n").unwrap();
        assert!(git_in(dir, ["add", "."]).status.success());
        let c = git_in(dir, ["commit", "-q", "-m", "init"]);
        assert!(c.status.success(), "git commit failed: {:?}", c);
    }

    // ── parse_branch_line ──────────────────────────────────────────────

    #[test]
    fn branch_line_plain() {
        assert_eq!(parse_branch_line(b"main"), "main");
    }

    #[test]
    fn branch_line_with_tracking_info() {
        // `--branch` header already carries ahead/behind — v1 shows only
        // the name (ADR-078 decision 5).
        assert_eq!(
            parse_branch_line(b"main...origin/main [ahead 1, behind 2]"),
            "main"
        );
    }

    #[test]
    fn branch_line_detached_head() {
        assert_eq!(parse_branch_line(b"HEAD (no branch)"), "HEAD");
    }

    #[test]
    fn branch_line_empty_repo() {
        assert_eq!(parse_branch_line(b"No commits yet on main"), "main");
        assert_eq!(parse_branch_line(b"Initial commit on dev"), "dev");
    }

    // ── parse_status_porcelain (pure, no git) ───────────────────────────

    #[test]
    fn porcelain_parses_worktree_modified_and_untracked() {
        let ws = Path::new("/repo");
        let repo = Path::new("/repo");
        let raw = b"## main\x00 M src/main.rs\x00?? new.txt\x00";
        let (changes, branch, truncated) = parse_status_porcelain(raw, ws, repo);
        assert_eq!(branch, "main");
        assert!(!truncated);
        assert_eq!(changes.len(), 2);
        assert_eq!(changes[0].path, "src/main.rs");
        assert_eq!(changes[0].worktree, GitWorktreeStatus::Modified);
        assert!(!changes[0].staged);
        assert_eq!(changes[1].worktree, GitWorktreeStatus::Untracked);
        assert!(!changes[1].staged);
    }

    #[test]
    fn porcelain_parses_staged_and_index_worktree_combos() {
        let ws = Path::new("/repo");
        let repo = Path::new("/repo");
        let raw = b"## main\x00M  staged.rs\x00MM both.rs\x00 D deleted.rs\x00";
        let (changes, _, _) = parse_status_porcelain(raw, ws, repo);
        assert_eq!(changes.len(), 3);
        assert_eq!(changes[0].path, "staged.rs");
        assert_eq!(changes[0].index, GitIndexStatus::Modified);
        assert!(changes[0].staged);
        assert_eq!(changes[1].path, "both.rs");
        assert_eq!(changes[1].index, GitIndexStatus::Modified);
        assert_eq!(changes[1].worktree, GitWorktreeStatus::Modified);
        assert!(changes[1].staged);
        assert_eq!(changes[2].path, "deleted.rs");
        assert_eq!(changes[2].worktree, GitWorktreeStatus::Deleted);
        assert!(!changes[2].staged);
    }

    #[test]
    fn porcelain_rename_captures_old_path() {
        let ws = Path::new("/repo");
        let repo = Path::new("/repo");
        let raw = b"## main\x00R  new.txt\x00old.txt\x00";
        let (changes, _, _) = parse_status_porcelain(raw, ws, repo);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].path, "new.txt");
        assert_eq!(changes[0].old_path.as_deref(), Some("old.txt"));
        assert_eq!(changes[0].index, GitIndexStatus::Renamed);
        assert!(changes[0].staged);
    }

    #[test]
    fn porcelain_utf8_paths_survive_z_mode() {
        let ws = Path::new("/repo");
        let repo = Path::new("/repo");
        let raw = "## main\x00?? 中文文件.txt\x00".as_bytes();
        let (changes, _, _) = parse_status_porcelain(raw, ws, repo);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].path, "中文文件.txt");
    }

    #[test]
    fn porcelain_filters_outside_workspace_paths() {
        let ws = Path::new("/repo/sub/ws");
        let repo = Path::new("/repo");
        let raw = b"## main\x00 M sub/ws/inside.rs\x00 M outside.rs\x00?? sub/ws/u.txt\x00";
        let (changes, _, _) = parse_status_porcelain(raw, ws, repo);
        assert_eq!(changes.len(), 2);
        assert_eq!(changes[0].path, "inside.rs");
        assert_eq!(changes[1].path, "u.txt");
    }

    #[test]
    fn diff_tree_rows_are_never_marked_staged() {
        // Regression: a historical commit's file list has no index/worktree
        // semantics, so the "staged" badge in GitStatusPanel must not appear
        // on commit-mode rows. Setting `staged: true` here used to make every
        // row of a commit's file list render as "已暂存".
        let ws = Path::new("/repo");
        let repo = Path::new("/repo");
        let raw = b"M\0src/a.rs\0A\0src/new.rs\0D\0src/gone.rs\0R\0new.txt\0old.txt\0";
        let (changes, _) = parse_diff_tree_name_status(raw, repo, ws);
        assert_eq!(changes.len(), 4);
        for c in &changes {
            assert!(!c.staged, "commit-mode row must not be staged: {}", c.path);
        }
        // Index/worktree columns are mirrored to a sensible single-axis view.
        assert_eq!(changes[0].index, GitIndexStatus::Modified);
        assert_eq!(changes[1].index, GitIndexStatus::Added);
        assert_eq!(changes[2].index, GitIndexStatus::Deleted);
        assert_eq!(changes[3].index, GitIndexStatus::Renamed);
        assert_eq!(changes[3].old_path.as_deref(), Some("old.txt"));
    }

    #[test]
    fn porcelain_unmerged_maps_to_conflicted() {
        let ws = Path::new("/repo");
        let repo = Path::new("/repo");
        // UU (both modified) + AA (both added) + UD (deleted by them).
        let raw = b"## main\x00UU uu.txt\x00AA aa.txt\x00UD ud.txt\x00";
        let (changes, _, _) = parse_status_porcelain(raw, ws, repo);
        assert_eq!(changes.len(), 3);
        for c in &changes {
            assert_eq!(c.index, GitIndexStatus::Conflicted);
            assert_eq!(c.worktree, GitWorktreeStatus::Conflicted);
            assert!(
                !c.staged,
                "conflict must not be shown as staged: {}",
                c.path
            );
        }
        // Conflicts sort ahead of staged+modified entries.
        let mut dtos = changes.clone();
        dtos.push(GitChangeDto {
            path: "staged.rs".into(),
            old_path: None,
            index: GitIndexStatus::Modified,
            worktree: GitWorktreeStatus::Unmodified,
            staged: true,
        });
        dtos.sort_by(|a, b| status_sort_key(a).cmp(&status_sort_key(b)));
        assert!(
            dtos[0].path.starts_with("uu.txt")
                || dtos[0].path.starts_with("aa.txt")
                || dtos[0].path.starts_with("ud.txt")
        );
    }

    #[test]
    fn porcelain_type_change_and_submodule_modified() {
        let ws = Path::new("/repo");
        let repo = Path::new("/repo");
        // `T  ` = staged file-type change (symlink↔file); ` m` = submodule
        // with modified content; ` D` = worktree deleted.
        let raw = b"## main\x00T  t.txt\x00 m sub\x00 D gone.rs\x00";
        let (changes, _, _) = parse_status_porcelain(raw, ws, repo);
        assert_eq!(changes.len(), 3);
        assert_eq!(changes[0].index, GitIndexStatus::Modified); // T
        assert!(changes[0].staged);
        assert_eq!(changes[1].worktree, GitWorktreeStatus::Modified); // m
        assert!(!changes[1].staged);
        assert_eq!(changes[2].worktree, GitWorktreeStatus::Deleted);
    }

    #[test]
    fn truncate_at_nul_keeps_entries_whole() {
        let raw = b"## main\x00 M a.rs\x00 M b.rs\x00";
        // cap 落在第二条 entry 内部 → 截断到最后一个完整 NUL 边界
        // （保留 header + 完整的第一条，丢弃被切开的第二条）
        let end = truncate_at_nul(raw, 20);
        assert!(end <= 20);
        assert_eq!(end, 16); // `## main` + NUL + ` M a.rs` + NUL
        assert!(raw[..end].ends_with(b"\x00"));
        assert_eq!(&raw[..end], b"## main\x00 M a.rs\x00");
        // 截断后的切片解析完整（no split path）；truncated 标志由全局
        // STATUS_BYTE_CAP 决定，切片本身不会再次触发
        let (changes, _, _) =
            parse_status_porcelain(&raw[..end], Path::new("/repo"), Path::new("/repo"));
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].path, "a.rs");
    }

    // ── repo discovery ──────────────────────────────────────────────────

    #[test]
    fn discover_repo_root_walks_up_but_limited_to_6() {
        let tmp = tempdir().unwrap();
        let root = tmp.path();
        std::fs::create_dir_all(root.join(".git")).unwrap();
        let mut deep = root.to_path_buf();
        for i in 0..8 {
            deep = deep.join(format!("d{i}"));
        }
        std::fs::create_dir_all(&deep).unwrap();

        // workspace == repo root
        assert_eq!(discover_repo_root(root), Some(root.to_path_buf()));
        // 6 层深（d0..d5）→ 可发现
        let depth6 = root.join("d0/d1/d2/d3/d4/d5");
        assert_eq!(discover_repo_root(&depth6), Some(root.to_path_buf()));
        // 8 层深 → 超出 MAX_REPO_UP
        assert_eq!(discover_repo_root(&deep), None);
    }

    #[test]
    fn discover_repo_root_none_when_not_a_repo() {
        let tmp = tempdir().unwrap();
        assert_eq!(discover_repo_root(tmp.path()), None);
    }

    // ── path coordinate conversion ──────────────────────────────────────

    #[test]
    fn repo_to_workspace_rel_strips_repo_prefix_and_rejects_outside() {
        let repo = Path::new("/repo");
        let ws = Path::new("/repo/sub/ws");
        assert_eq!(
            repo_to_workspace_rel(repo, ws, "sub/ws/file.rs").as_deref(),
            Some("file.rs")
        );
        assert_eq!(repo_to_workspace_rel(repo, ws, "outside.rs"), None);
    }

    #[test]
    fn make_change_rename_old_path_and_staged_flag() {
        let ws = Path::new("/repo");
        let repo = Path::new("/repo");
        let c = make_change('R', ' ', "new.txt", Some("old.txt"), ws, repo).unwrap();
        assert_eq!(c.path, "new.txt");
        assert_eq!(c.old_path.as_deref(), Some("old.txt"));
        assert_eq!(c.index, GitIndexStatus::Renamed);
        assert!(c.staged);
    }

    #[test]
    fn status_sort_key_puts_staged_first() {
        let mk = |path: &str, staged: bool| GitChangeDto {
            path: path.to_string(),
            old_path: None,
            index: if staged {
                GitIndexStatus::Modified
            } else {
                GitIndexStatus::Unmodified
            },
            worktree: GitWorktreeStatus::Modified,
            staged,
        };
        assert!(status_sort_key(&mk("a.rs", true)) < status_sort_key(&mk("b.rs", false)));
        // same staged+M rank, tie-broken by path → compare the (u8,u8) prefix
        let (r1, t1, _) = status_sort_key(&mk("a.rs", true));
        let (r2, t2, _) = status_sort_key(&mk("z.rs", true));
        assert_eq!((r1, t1), (r2, t2));
    }

    // ── integration: real git repo ──────────────────────────────────────

    #[tokio::test]
    async fn integration_status_modified_untracked_rename() {
        if !git_available() {
            eprintln!("skipping: git binary not available");
            return;
        }
        let tmp = tempdir().unwrap();
        let ws = tmp.path().join("ws");
        std::fs::create_dir_all(&ws).unwrap();
        init_repo(&ws);

        let svc = RuntimeGitQueryService::new(ws.clone(), "agent-1".to_string());

        // clean repo
        let st = svc.status(&GitStatusParams::default()).await.unwrap();
        assert!(st.is_repo);
        assert_eq!(st.branch.as_deref(), Some("main"));
        assert!(st.changes.is_empty());

        // modified + untracked (UTF-8 path) + staged rename
        std::fs::write(ws.join("a.txt"), "hello world\n").unwrap();
        std::fs::write(ws.join("新文件.txt"), "中文\n").unwrap();
        std::fs::write(ws.join("b.txt"), "b\n").unwrap();
        assert!(git_in(&ws, ["add", "b.txt"]).status.success());
        assert!(
            git_in(&ws, ["commit", "-q", "-m", "second"])
                .status
                .success()
        );
        assert!(git_in(&ws, ["mv", "b.txt", "b2.txt"]).status.success());

        let st = svc.status(&GitStatusParams::default()).await.unwrap();
        assert!(st.is_repo);
        let names: Vec<&str> = st.changes.iter().map(|c| c.path.as_str()).collect();
        assert!(names.contains(&"a.txt"), "names: {names:?}");
        assert!(names.contains(&"新文件.txt"), "names: {names:?}");
        let renamed = st.changes.iter().find(|c| c.path == "b2.txt").unwrap();
        assert_eq!(renamed.old_path.as_deref(), Some("b.txt"));
        assert!(renamed.staged);
        let untracked = st.changes.iter().find(|c| c.path == "新文件.txt").unwrap();
        assert_eq!(untracked.worktree, GitWorktreeStatus::Untracked);
        assert!(!untracked.staged);
    }

    #[tokio::test]
    async fn integration_status_does_not_touch_git_index() {
        if !git_available() {
            eprintln!("skipping: git binary not available");
            return;
        }
        let tmp = tempdir().unwrap();
        let ws = tmp.path().join("ws");
        std::fs::create_dir_all(&ws).unwrap();
        init_repo(&ws);

        // ADR-078 §7.1 read-only regression: `git status` would otherwise
        // refresh the index stat-cache (writing `.git/index`) on a
        // stat-dirty worktree. With `GIT_OPTIONAL_LOCKS=0` neither the
        // mtime nor the content of `.git/index` may change.
        let index = ws.join(".git/index");
        let mtime_before = std::fs::metadata(&index).unwrap().modified().unwrap();
        let content_before = std::fs::read(&index).unwrap();

        // Stat-dirty the worktree so git would want to refresh the cache.
        std::fs::write(ws.join("a.txt"), "dirty\n").unwrap();

        let svc = RuntimeGitQueryService::new(ws.clone(), "agent-1".to_string());
        let st = svc.status(&GitStatusParams::default()).await.unwrap();
        assert!(st.is_repo);
        assert_eq!(st.changes.len(), 1);

        let mtime_after = std::fs::metadata(&index).unwrap().modified().unwrap();
        let content_after = std::fs::read(&index).unwrap();
        assert_eq!(
            content_after, content_before,
            ".git/index content must not change (GIT_OPTIONAL_LOCKS=0)"
        );
        assert_eq!(
            mtime_after, mtime_before,
            ".git/index mtime must not change (GIT_OPTIONAL_LOCKS=0)"
        );
    }

    #[tokio::test]
    async fn integration_git_unavailable_surfaces_explicitly() {
        if !git_available() {
            eprintln!("skipping: git binary not available");
            return;
        }
        // ADR-078 §7.2: git missing from the environment must surface an
        // explicit state (status → is_repo:false + error:"git_unavailable",
        // diff/log → GitUnavailable), never a silent degradation. The repo
        // is created with the real git first (discovery needs `.git`), then
        // the service is pointed at a non-existent binary — no process-global
        // PATH mutation, so parallel tests stay isolated.
        let tmp = tempdir().unwrap();
        let ws = tmp.path().join("ws");
        std::fs::create_dir_all(&ws).unwrap();
        init_repo(&ws);
        let svc = RuntimeGitQueryService::new_with_git_bin(
            ws.clone(),
            "agent-1".to_string(),
            "/nonexistent/git-adr078-test".to_string(),
        );

        let st = svc.status(&GitStatusParams::default()).await.unwrap();
        assert!(!st.is_repo);
        assert_eq!(st.error.as_deref(), Some("git_unavailable"));

        let d = svc
            .diff(&GitDiffParams {
                workspace_id: None,
                path: "a.txt".into(),
                ..Default::default()
            })
            .await;
        assert!(matches!(d, Err(GitError::GitUnavailable(_))), "{d:?}");

        let lg = svc.log(&GitLogParams::default()).await;
        assert!(matches!(lg, Err(GitError::GitUnavailable(_))), "{lg:?}");
    }

    #[tokio::test]
    async fn integration_diff_five_kinds() {
        if !git_available() {
            eprintln!("skipping: git binary not available");
            return;
        }
        let tmp = tempdir().unwrap();
        let ws = tmp.path().join("ws");
        std::fs::create_dir_all(&ws).unwrap();
        init_repo(&ws);
        let svc = RuntimeGitQueryService::new(ws.clone(), "agent-1".to_string());

        // NoChange — tracked & clean
        let d = svc
            .diff(&GitDiffParams {
                workspace_id: None,
                path: "a.txt".into(),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(d.kind, GitDiffKind::NoChange);

        // Modified
        std::fs::write(ws.join("a.txt"), "hello world\n").unwrap();
        let d = svc
            .diff(&GitDiffParams {
                workspace_id: None,
                path: "a.txt".into(),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(d.kind, GitDiffKind::Modified);
        assert_eq!(d.original, "hello\n");
        assert_eq!(d.modified, "hello world\n");

        // Untracked — original is empty
        std::fs::write(ws.join("new.txt"), "new\n").unwrap();
        let d = svc
            .diff(&GitDiffParams {
                workspace_id: None,
                path: "new.txt".into(),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(d.kind, GitDiffKind::Untracked);
        assert_eq!(d.original, "");
        assert_eq!(d.modified, "new\n");

        // Deleted — HEAD text preserved, modified empty
        std::fs::remove_file(ws.join("a.txt")).unwrap();
        let d = svc
            .diff(&GitDiffParams {
                workspace_id: None,
                path: "a.txt".into(),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(d.kind, GitDiffKind::Deleted);
        assert_eq!(d.original, "hello\n"); // HEAD still holds the initial content
        assert_eq!(d.modified, "");
        std::fs::write(ws.join("a.txt"), "hello world\n").unwrap();

        // Binary — NUL byte on either side degrades to kind=binary
        std::fs::write(ws.join("bin.dat"), [0u8, 1, 2, 3]).unwrap();
        assert!(git_in(&ws, ["add", "bin.dat"]).status.success());
        assert!(
            git_in(&ws, ["commit", "-q", "-m", "add bin"])
                .status
                .success()
        );
        std::fs::write(ws.join("bin.dat"), [0u8, 9, 9, 9]).unwrap();
        let d = svc
            .diff(&GitDiffParams {
                workspace_id: None,
                path: "bin.dat".into(),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(d.kind, GitDiffKind::Binary);
        assert!(d.original.is_empty() && d.modified.is_empty());
    }

    #[tokio::test]
    async fn integration_diff_rename_uses_old_path_for_head() {
        if !git_available() {
            eprintln!("skipping: git binary not available");
            return;
        }
        let tmp = tempdir().unwrap();
        let ws = tmp.path().join("ws");
        std::fs::create_dir_all(&ws).unwrap();
        init_repo(&ws);
        std::fs::write(ws.join("b.txt"), "b\n").unwrap();
        assert!(git_in(&ws, ["add", "b.txt"]).status.success());
        assert!(
            git_in(&ws, ["commit", "-q", "-m", "add b"])
                .status
                .success()
        );
        assert!(git_in(&ws, ["mv", "b.txt", "b2.txt"]).status.success());
        // content unchanged → NoChange; original must come from HEAD:old-path
        let svc = RuntimeGitQueryService::new(ws.clone(), "agent-1".to_string());
        let d = svc
            .diff(&GitDiffParams {
                workspace_id: None,
                path: "b2.txt".into(),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(d.kind, GitDiffKind::NoChange);
        assert_eq!(d.original, "b\n");
        assert_eq!(d.modified, "b\n");
    }

    #[tokio::test]
    async fn integration_diff_cached_1_reads_index() {
        if !git_available() {
            eprintln!("skipping: git binary not available");
            return;
        }
        let tmp = tempdir().unwrap();
        let ws = tmp.path().join("ws");
        std::fs::create_dir_all(&ws).unwrap();
        init_repo(&ws);
        std::fs::write(ws.join("c.txt"), "c\n").unwrap();
        assert!(git_in(&ws, ["add", "c.txt"]).status.success());
        assert!(
            git_in(&ws, ["commit", "-q", "-m", "add c"])
                .status
                .success()
        );
        std::fs::write(ws.join("c.txt"), "c staged\n").unwrap();
        assert!(git_in(&ws, ["add", "c.txt"]).status.success());

        let svc = RuntimeGitQueryService::new(ws.clone(), "agent-1".to_string());
        let d = svc
            .diff(&GitDiffParams {
                workspace_id: None,
                path: "c.txt".into(),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(d.kind, GitDiffKind::Modified);
        assert_eq!(d.original, "c\n");
        assert_eq!(d.modified, "c staged\n");
    }

    #[tokio::test]
    async fn integration_diff_rejects_path_traversal() {
        if !git_available() {
            eprintln!("skipping: git binary not available");
            return;
        }
        let tmp = tempdir().unwrap();
        let ws = tmp.path().join("ws");
        std::fs::create_dir_all(&ws).unwrap();
        init_repo(&ws);
        let svc = RuntimeGitQueryService::new(ws.clone(), "agent-1".to_string());
        let r = svc
            .diff(&GitDiffParams {
                workspace_id: None,
                path: "../evil.txt".into(),
                ..Default::default()
            })
            .await;
        match r {
            Err(GitError::InvalidPath(_)) => {}
            other => panic!("expected InvalidPath, got {other:?}"),
        }
        let r = svc
            .log(&GitLogParams {
                workspace_id: None,
                path: Some("/etc/passwd".into()),
                limit: None,
                skip: None,
            })
            .await;
        match r {
            Err(GitError::InvalidPath(_)) => {}
            other => panic!("expected InvalidPath, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn integration_workspace_subdir_of_repo_coordinates() {
        if !git_available() {
            eprintln!("skipping: git binary not available");
            return;
        }
        let tmp = tempdir().unwrap();
        let repo = tmp.path().join("repo");
        std::fs::create_dir_all(repo.join("sub/ws")).unwrap();
        init_repo(&repo); // repo/a.txt committed
        // workspace-tracked file
        std::fs::write(repo.join("sub/ws/tracked.txt"), "t\n").unwrap();
        assert!(
            git_in(&repo, ["add", "sub/ws/tracked.txt"])
                .status
                .success()
        );
        assert!(
            git_in(&repo, ["commit", "-q", "-m", "add tracked"])
                .status
                .success()
        );
        // modify inside + outside the workspace
        std::fs::write(repo.join("sub/ws/tracked.txt"), "t2\n").unwrap();
        std::fs::write(repo.join("outside.txt"), "out\n").unwrap();

        let svc = RuntimeGitQueryService::new(repo.join("sub/ws"), "agent-1".to_string());

        // status is range-filtered to the workspace
        let st = svc.status(&GitStatusParams::default()).await.unwrap();
        assert!(st.is_repo);
        assert_eq!(st.changes.len(), 1, "changes: {:?}", st.changes);
        assert_eq!(st.changes[0].path, "tracked.txt");

        // diff: workspace-relative → repo-root-relative conversion
        let d = svc
            .diff(&GitDiffParams {
                workspace_id: None,
                path: "tracked.txt".into(),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(d.kind, GitDiffKind::Modified);
        assert_eq!(d.original, "t\n");
        assert_eq!(d.modified, "t2\n");

        // log: repo-wide (2 commits) and path-scoped (1 commit)
        let lg = svc.log(&GitLogParams::default()).await.unwrap();
        assert_eq!(lg.commits.len(), 2);
        let lg = svc
            .log(&GitLogParams {
                workspace_id: None,
                path: Some("tracked.txt".into()),
                limit: None,
                skip: None,
            })
            .await
            .unwrap();
        assert_eq!(lg.commits.len(), 1);
    }

    #[tokio::test]
    async fn integration_log_limit_and_subject() {
        if !git_available() {
            eprintln!("skipping: git binary not available");
            return;
        }
        let tmp = tempdir().unwrap();
        let ws = tmp.path().join("ws");
        std::fs::create_dir_all(&ws).unwrap();
        init_repo(&ws);
        for i in 0..5 {
            std::fs::write(ws.join("a.txt"), format!("v{i}\n")).unwrap();
            assert!(git_in(&ws, ["add", "a.txt"]).status.success());
            let msg = format!("c{i}");
            assert!(
                git_in(&ws, ["commit", "-q", "-m", msg.as_str()])
                    .status
                    .success()
            );
        }
        let svc = RuntimeGitQueryService::new(ws.clone(), "agent-1".to_string());
        let lg = svc
            .log(&GitLogParams {
                workspace_id: None,
                path: None,
                limit: Some(3),
                skip: None,
            })
            .await
            .unwrap();
        assert_eq!(lg.commits.len(), 3);
        assert_eq!(lg.commits[0].subject, "c4"); // newest first
        // over-cap limit clamps to LOG_MAX_LIMIT (200)
        let lg = svc
            .log(&GitLogParams {
                workspace_id: None,
                path: None,
                limit: Some(9999),
                skip: None,
            })
            .await
            .unwrap();
        assert_eq!(lg.commits.len(), 6);
    }

    // ── revert (the one write op) ──────────────────────────────────────

    #[tokio::test]
    async fn integration_revert_restores_modified_and_deleted() {
        if !git_available() {
            eprintln!("skipping: git binary not available");
            return;
        }
        let tmp = tempdir().unwrap();
        let ws = tmp.path().join("ws");
        std::fs::create_dir_all(&ws).unwrap();
        init_repo(&ws);
        let svc = RuntimeGitQueryService::new(ws.clone(), "agent-1".to_string());

        // unstaged worktree modification → back to HEAD content
        // (git's worktree copy may carry CRLF under core.autocrlf —
        // normalize before comparing, the revert itself is correct).
        std::fs::write(ws.join("a.txt"), "dirty\n").unwrap();
        let resp = svc
            .revert(&GitRevertParams {
                workspace_id: None,
                path: "a.txt".into(),
                old_path: None,
            })
            .await
            .unwrap();
        assert_eq!(resp.path, "a.txt");
        let content = std::fs::read_to_string(ws.join("a.txt")).unwrap().replace("\r\n", "\n");
        assert_eq!(content, "hello\n");
        assert!(svc.status(&GitStatusParams::default()).await.unwrap().changes.is_empty());

        // worktree deletion → file restored
        std::fs::remove_file(ws.join("a.txt")).unwrap();
        svc.revert(&GitRevertParams {
            workspace_id: None,
            path: "a.txt".into(),
            old_path: None,
        })
        .await
        .unwrap();
        let content = std::fs::read_to_string(ws.join("a.txt")).unwrap().replace("\r\n", "\n");
        assert_eq!(content, "hello\n");
        assert!(svc.status(&GitStatusParams::default()).await.unwrap().changes.is_empty());
    }

    #[tokio::test]
    async fn integration_revert_removes_staged_added_and_untracked() {
        if !git_available() {
            eprintln!("skipping: git binary not available");
            return;
        }
        let tmp = tempdir().unwrap();
        let ws = tmp.path().join("ws");
        std::fs::create_dir_all(&ws).unwrap();
        init_repo(&ws);
        let svc = RuntimeGitQueryService::new(ws.clone(), "agent-1".to_string());

        // staged-added (in index, not in HEAD) → removed from index + disk
        std::fs::write(ws.join("b.txt"), "new\n").unwrap();
        assert!(git_in(&ws, ["add", "b.txt"]).status.success());
        svc.revert(&GitRevertParams {
            workspace_id: None,
            path: "b.txt".into(),
            old_path: None,
        })
        .await
        .unwrap();
        assert!(!ws.join("b.txt").exists());
        assert!(svc.status(&GitStatusParams::default()).await.unwrap().changes.is_empty());

        // untracked → file deleted (IDE "Discard" semantics)
        std::fs::write(ws.join("c.txt"), "untracked\n").unwrap();
        svc.revert(&GitRevertParams {
            workspace_id: None,
            path: "c.txt".into(),
            old_path: None,
        })
        .await
        .unwrap();
        assert!(!ws.join("c.txt").exists());
        assert!(svc.status(&GitStatusParams::default()).await.unwrap().changes.is_empty());
    }

    #[tokio::test]
    async fn integration_revert_unwinds_rename() {
        if !git_available() {
            eprintln!("skipping: git binary not available");
            return;
        }
        let tmp = tempdir().unwrap();
        let ws = tmp.path().join("ws");
        std::fs::create_dir_all(&ws).unwrap();
        init_repo(&ws);
        let svc = RuntimeGitQueryService::new(ws.clone(), "agent-1".to_string());

        assert!(git_in(&ws, ["mv", "a.txt", "renamed.txt"]).status.success());
        let st = svc.status(&GitStatusParams::default()).await.unwrap();
        assert_eq!(st.changes.len(), 1);
        assert_eq!(st.changes[0].old_path.as_deref(), Some("a.txt"));

        svc.revert(&GitRevertParams {
            workspace_id: None,
            path: "renamed.txt".into(),
            old_path: Some("a.txt".into()),
        })
        .await
        .unwrap();

        assert!(ws.join("a.txt").exists());
        assert!(!ws.join("renamed.txt").exists());
        assert!(svc.status(&GitStatusParams::default()).await.unwrap().changes.is_empty());
    }

    #[tokio::test]
    async fn integration_revert_rejects_empty_path() {
        if !git_available() {
            eprintln!("skipping: git binary not available");
            return;
        }
        let tmp = tempdir().unwrap();
        let ws = tmp.path().join("ws");
        std::fs::create_dir_all(&ws).unwrap();
        init_repo(&ws);
        let svc = RuntimeGitQueryService::new(ws.clone(), "agent-1".to_string());

        // Trust boundary: empty path would resolve to the workspace root
        // and revert the whole tree — must be rejected before any git runs.
        let err = svc
            .revert(&GitRevertParams {
                workspace_id: None,
                path: "".into(),
                old_path: None,
            })
            .await
            .unwrap_err();
        assert!(matches!(err, GitError::BadRequest(_)), "got {err:?}");
    }
}
