//! ADR-078 git-refresh nudge — the bridge between a shell tool call and
//! the `git-changed` MQTT event.
//!
//! Lives in `agent/` rather than `workspace/` because it is called from
//! the tool-execution loop, and what it needs is the two late-bind
//! handles every session already has: the MQTT client slot and the
//! workspace resolver.
//!
//! The whole feature is three steps:
//!
//! 1. [`maybe_nudge_after_shell`] — after a shell tool returns, ask
//!    [`crate::security::git_mutate::may_mutate_git`] whether the command
//!    could have touched index/HEAD.
//! 2. Map the workspace the command actually ran in back to a workspace
//!    **id** (the topic needs the id; the loop only knows the resolved
//!    directory path).
//! 3. Publish a bare [`GitStatusChanged`] nudge. No git state travels
//!    on the wire — the Desktop re-reads `GET /git/status`.
//!
//! The one design constraint worth restating: this module decides *when
//! to look*, never *what the answer is*. A false positive costs one
//! debounced HTTP fetch; a false negative costs what the user already
//! has today. See [`crate::security::git_mutate`] for the gap list.

use crate::tools::workspace_resolver::SharedResolver;

/// The late-bind handles the nudge needs, bundled so `AgentCore` carries
/// one `Option` instead of two.
///
/// `Clone` is load-bearing: `AgentCore` is cloned once per session
/// (see `AgentCore::clone_for_session`), and every clone must share the
/// same handles so a nudge is published exactly once per tool call
/// regardless of which session clone runs it.
#[derive(Clone)]
pub(crate) struct GitNudgeSlots {
    /// ADR-040 late-bind MQTT client slot (the same Arc the HTTP server
    /// and the workspace watcher set hold).
    pub(crate) mqtt_slot: crate::http::server::SharedMqttClientSlot,
    /// Shared resolver, used to turn the tool's `work_dir` back into a
    /// workspace id.
    pub(crate) resolver: SharedResolver,
}

/// After a shell tool call running in `work_dir`, publish a
/// `git-changed` nudge when `params["command"]` may have mutated git
/// state.
///
/// `params` is the **already-parsed** tool arguments — the same value
/// the tool itself executed with. Accepting it rather than re-parsing
/// `function.arguments` means the nudge can never disagree with what
/// actually ran (the arguments resolver also recovers JSON from
/// natural-language-wrapped input; a second parse could take a
/// different path).
///
/// `work_dir` is the resolved directory the tool actually ran in (not a
/// workspace id) — the caller has no id, which is why the lookup below
/// goes through the resolver. Returns `true` when an event was published
/// (or attempted), which the caller only uses for a trace log.
pub(crate) async fn maybe_nudge_after_shell(
    slots: Option<&GitNudgeSlots>,
    agent_id: &str,
    work_dir: Option<&str>,
    params: &serde_json::Value,
) -> bool {
    let Some(command) = params.get("command").and_then(|c| c.as_str()) else {
        return false;
    };
    // Cheap first: the string check runs before any lock or await, so a
    // non-git command (the overwhelming majority of shell calls) costs
    // one split and nothing else.
    if !crate::security::git_mutate::may_mutate_git(command) {
        return false;
    }
    let Some(slots) = slots else {
        // No MQTT client (CLI mode, or Phase B not finished). Dropping is
        // correct: the Desktop re-reads git state on panel expand and on
        // reconnect, so the user still converges.
        tracing::debug!("git command ran but nudge slots unbound — skipping publish");
        return false;
    };
    let Some(workspace_id) = workspace_id_for(slots, work_dir).await else {
        tracing::debug!(
            work_dir = ?work_dir,
            "git command ran in an unmapped directory — skipping nudge"
        );
        return false;
    };
    crate::workspace::watcher_set::publish_git_status_changed(
        &slots.mqtt_slot,
        agent_id,
        &workspace_id,
    )
    .await;
    tracing::debug!(
        workspace_id = %workspace_id,
        "published git-changed nudge after git-mutating shell command"
    );
    true
}

/// Resolve the workspace **id** owning `work_dir`.
///
/// The agent loop only ever knows the resolved directory
/// ([`SessionCore::current_work_dir`]), while the MQTT topic and the
/// Desktop's store are both keyed by id — so this inverts the usual
/// `id → path` direction.
///
/// Comparison is done on component-normalised paths rather than raw
/// strings: on Windows the same directory can appear as `D:/a/b` or
/// `D:\a\b`, and a plain string compare would silently drop the nudge.
/// The resolver is never canonicalised (it holds paths for workspaces
/// that may not exist yet), so both sides are normalised instead.
async fn workspace_id_for(slots: &GitNudgeSlots, work_dir: Option<&str>) -> Option<String> {
    let work_dir = work_dir?;
    let guard = slots.resolver.read().ok()?;
    // `__agent_home__` is runtime-managed state, never a repo checkout,
    // and the Git Status Bar is hidden for it anyway.
    if same_path(guard.agent_home(), work_dir) {
        return Some("__agent_home__".to_string());
    }
    guard
        .allowed_dirs()
        .iter()
        .find(|d| same_path(&d.path, work_dir))
        .map(|d| d.id.clone())
}

/// Component-normalised, separator-normalised path equality.
fn same_path(a: &str, b: &str) -> bool {
    normalize(a) == normalize(b)
}

/// Normalise a path for comparison purposes only — never for filesystem
/// access, so this deliberately avoids `canonicalize` (which would fail
/// for a workspace that does not exist yet and would follow symlinks out
/// of the tree, making two different workspaces look like one).
fn normalize(path: &str) -> String {
    path.replace('\\', "/")
        .trim_end_matches('/')
        .to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn resolver_with(dirs: Vec<(&str, &str)>) -> SharedResolver {
        use crate::tools::workspace_resolver::{WorkspaceAccess, WorkspaceDir, WorkspaceResolver};
        let allowed = dirs
            .into_iter()
            .map(|(id, path)| WorkspaceDir {
                id: id.to_string(),
                path: path.to_string(),
                access: WorkspaceAccess::ReadWrite,
                last_active: false,
                prompt_file: None,
            })
            .collect();
        Arc::new(std::sync::RwLock::new(WorkspaceResolver::new_for_test(
            allowed,
        )))
    }

    fn slots_for(dirs: Vec<(&str, &str)>) -> GitNudgeSlots {
        GitNudgeSlots {
            mqtt_slot: crate::http::server::SharedMqttClientSlot::default(),
            resolver: resolver_with(dirs),
        }
    }

    #[tokio::test]
    async fn maps_work_dir_back_to_workspace_id() {
        let slots = slots_for(vec![("ws-1", "D:/repo")]);
        assert_eq!(
            workspace_id_for(&slots, Some("D:/repo")).await.as_deref(),
            Some("ws-1")
        );
    }

    /// The Windows case that makes raw string comparison unusable: the
    /// resolver stores forward slashes, `current_work_dir` may carry
    /// backslashes, and drive letters are case-insensitive.
    #[tokio::test]
    async fn normalizes_separators_and_case() {
        let slots = slots_for(vec![("ws-1", "D:/projects/repo")]);
        for variant in [
            "D:\\projects\\repo",
            "d:/projects/repo",
            "D:/projects/repo/",
        ] {
            assert_eq!(
                workspace_id_for(&slots, Some(variant)).await.as_deref(),
                Some("ws-1"),
                "variant {variant} should resolve"
            );
        }
    }

    #[tokio::test]
    async fn unknown_work_dir_yields_none() {
        let slots = slots_for(vec![("ws-1", "D:/repo")]);
        assert_eq!(workspace_id_for(&slots, Some("D:/elsewhere")).await, None);
        assert_eq!(workspace_id_for(&slots, None).await, None);
    }

    /// `__agent_home__` is never a repo, but it must still map to an id
    /// rather than `None` so the caller can tell "unmapped" apart from
    /// "mapped to a non-repo workspace".
    #[tokio::test]
    async fn agent_home_maps_to_its_own_id() {
        let slots = slots_for(vec![]);
        // new_for_test with no dirs still exposes an agent_home; compare
        // against whatever it reports rather than hardcoding a path.
        let home = {
            let guard = slots.resolver.read().unwrap();
            guard.agent_home().to_string()
        };
        assert_eq!(
            workspace_id_for(&slots, Some(&home)).await.as_deref(),
            Some("__agent_home__")
        );
    }

    /// The cheap pre-filter must run before any locking, so a plain
    /// `ls` never touches the resolver. Asserted behaviourally: with no
    /// slots bound at all, a non-git command still returns false rather
    /// than panicking or publishing.
    #[tokio::test]
    async fn non_git_command_returns_false_without_slots() {
        let params = serde_json::json!({"command": "ls -la"});
        assert!(!maybe_nudge_after_shell(None, "agent", Some("D:/repo"), &params).await);
    }

    /// A git command with no slots bound is dropped, not an error — the
    /// Desktop re-reads git state on panel expand, so the user still
    /// converges. This is the CLI-mode path.
    #[tokio::test]
    async fn git_command_without_slots_is_dropped() {
        let params = serde_json::json!({"command": "git commit -m x"});
        assert!(!maybe_nudge_after_shell(None, "agent", Some("D:/repo"), &params).await);
    }

    /// Missing / non-string `command` is not a shell call at all.
    #[tokio::test]
    async fn missing_command_param_returns_false() {
        for params in [
            serde_json::json!({}),
            serde_json::json!({"command": 42}),
            serde_json::json!({"cmd": "git commit"}),
        ] {
            assert!(!maybe_nudge_after_shell(None, "agent", Some("D:/repo"), &params).await);
        }
    }
}
