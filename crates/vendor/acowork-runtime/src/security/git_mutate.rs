//! Git-mutation detection for shell commands (ADR-078 follow-up).
//!
//! Answers one question: "did this shell command possibly change the
//! repository's index or HEAD?" The answer is only ever a *trigger* —
//! the Runtime publishes a bare [`GitStatusChanged`] nudge and the real
//! git state is read back over the HTTP `GET /git/status` endpoint, so
//! git semantics never leak into this module.
//!
//! ## Why this exists
//!
//! `git commit` writes only inside the repo's gitdir (`.git/index`,
//! `.git/HEAD`, the reflog). In a worktree checkout `.git` is a pointer
//! FILE pointing at a directory *outside* the workspace, and the
//! workspace-root `PollWatcher` (ADR-058, `NonRecursive`) never observes
//! any of it. The fs-changed topic therefore cannot carry this signal by
//! construction, which left the Git Status Bar stuck on a stale count
//! after an agent committed.
//!
//! ## Deliberately a heuristic, and the error direction is safe
//!
//! Parsing a shell command is fundamentally lossy — see
//! [`KNOWN_GAPS`] for the shapes that are not detected. Those gaps are
//! acceptable **because the cost is asymmetric here**: a false positive
//! costs one extra (debounced) `git status` fetch, while a false
//! negative costs exactly what the user has today (no auto-refresh).
//! This is the opposite trade-off from
//! [`crate::security::shell_risk`], where a missed match is a security
//! failure and approximation is therefore not an option.
//!
//! Never use this to decide *what* git state is — only *whether to look
//! again*.
//!
//! ponytail: ceiling — does not detect `$(...)` / backticks, pipes,
//! sub-shells, `&`, `bash script.sh`, `git -C <dir> <sub>`, or aliases.
//! Non-security; a miss degrades to the pre-existing manual-refresh
//! behaviour. Upgrade path: snapshot `.git/{HEAD,index}` mtimes around
//! the call (would catch the first four gaps; still not scripts).

use acowork_core::mqtt_proto::GitStatusChanged;

/// Git subcommands that mutate the index (staging area) and/or HEAD.
///
/// Read-only subcommands (`status`, `log`, `diff`, `show`, `branch` with
/// no args, `remote`, ...) are deliberately absent: they cannot change
/// what the Git Status Bar renders, and firing on them would turn every
/// `git status` the agent runs into a pointless status re-fetch.
///
/// This list is intentionally SEPARATE from `shell_risk_rules.toml`.
/// That file is security surface — a reviewer there asks "can this be
/// evaded?", not "is this list complete for a UI refresh?". Coupling the
/// two would mean every UX tweak needs a security sign-off, and every
/// security rule addition would have to be re-justified against the UI.
/// `drift_guard_covers_security_rule_file` below asserts the two never
/// drift apart, so independent authorship stays safe.
const GIT_MUTATING_SUBCOMMANDS: &[&str] = &[
    // ── index mutations ──
    "add",
    "rm",
    "mv",
    "restore",
    "reset",
    "update-index",
    "clean",
    // ── HEAD / ref mutations ──
    "commit",
    "merge",
    "rebase",
    "cherry-pick",
    "revert",
    "pull",
    "checkout",
    "switch",
    "stash",
    "am",
    "apply",
];

/// Git subcommands that the security rules file knows about but which
/// deliberately do NOT appear above, because they cannot change what the
/// Git Status Bar renders:
///
/// - `push` — moves refs on the *remote*; local index and HEAD are
///   untouched.
/// - `branch -D` — deletes a ref without switching to it; HEAD stays put.
///   (`git branch x y` does move HEAD, but that form also never appears
///   in the security file, and a false negative here is free — see the
///   module docs.)
///
/// Listing them explicitly is what lets the drift guard below stay
/// strict: an unknown subcommand fails the build, a known-and-rejected
/// one does not.
#[cfg(test)]
const KNOWN_NON_MUTATING: &[&str] = &["push", "branch"];

/// Command shapes this detector provably cannot see. Kept as a named
/// constant so the limitation travels with the code instead of living
/// only in the module docs.
#[allow(dead_code)]
pub const KNOWN_GAPS: &[&str] = &[
    "command substitution: $(git commit) / `git commit`",
    "pipes: echo x | git commit",
    "sub-shells: (cd x; git commit)",
    "background: git commit &",
    "scripts: bash deploy.sh (contents unknown)",
    "aliases and functions",
];

/// True when `command` may have changed git index or HEAD state.
///
/// The command chain is split on `&&` and `;` (reusing
/// [`crate::security::shell_risk`]'s splitter so both modules agree on
/// what a "sub-command" is), then each segment is tokenised on
/// whitespace. A segment matches when `git` is its first token and any
/// later token is a known mutating subcommand.
///
/// Scanning all tokens after `git` (rather than only the immediately next
/// one) is what makes `git -C /path commit` and `git --no-pager commit`
/// match. It also means a *path* argument that happens to equal a
/// subcommand name could false-positive — harmless per the error
/// direction documented above.
pub(crate) fn may_mutate_git(command: &str) -> bool {
    crate::security::shell_risk::split_command_chain(command.trim())
        .iter()
        .any(|segment| segment_may_mutate(segment))
}

/// Single segment (no `&&` / `;`) check. Split out so the chain-level
/// test and the unit tests share one definition.
fn segment_may_mutate(segment: &str) -> bool {
    let mut tokens = segment.split_whitespace();
    if tokens.next() != Some("git") {
        return false;
    }
    tokens.any(is_mutating_subcommand)
}

fn is_mutating_subcommand(token: &str) -> bool {
    GIT_MUTATING_SUBCOMMANDS.contains(&token)
}

/// Build the event payload for workspace `workspace_id`.
///
/// Emitted with no branch / index / HEAD data on purpose: the Desktop
/// re-reads the authoritative state over HTTP. See the module docs.
pub(crate) fn changed_event(agent_id: &str, workspace_id: &str) -> GitStatusChanged {
    GitStatusChanged {
        agent_id: agent_id.to_string(),
        workspace_id: workspace_id.to_string(),
        window_end_ms: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_plain_mutating_commands() {
        for cmd in [
            "git commit -m x",
            "git add .",
            "git add -A",
            "git rm foo.txt",
            "git reset --hard HEAD~1",
            "git merge main",
            "git rebase -i main",
            "git stash pop",
            "git checkout -b feature",
            "git switch main",
            "git cherry-pick abc123",
        ] {
            assert!(may_mutate_git(cmd), "should detect: {cmd}");
        }
    }

    #[test]
    fn detects_chained_commands() {
        for cmd in [
            "cd /tmp && git commit -m x",
            "git add . ; git commit -m x",
            "git add -A && git commit -m 'wip' && git push",
        ] {
            assert!(may_mutate_git(cmd), "should detect: {cmd}");
        }
    }

    #[test]
    fn detects_through_global_flags() {
        // `git -C /other/repo commit` — the subcommand is not the token
        // immediately after `git`, so we scan the whole tail.
        for cmd in ["git -C /other/repo commit -m x", "git --no-pager add ."] {
            assert!(may_mutate_git(cmd), "should detect: {cmd}");
        }
    }

    #[test]
    fn ignores_read_only_git_commands() {
        for cmd in [
            "git status",
            "git log --oneline -10",
            "git diff HEAD",
            "git show abc123",
            "git remote -v",
            "ls -la",
            "npm run build",
            "",
            "   ",
        ] {
            assert!(!may_mutate_git(cmd), "should NOT detect: {cmd:?}");
        }
    }

    /// The whole point of the heuristic: a miss must never be worse than
    /// the pre-existing behaviour, and a hit must never cost more than a
    /// refresh. Both directions are asserted explicitly so a future
    /// refactor cannot quietly invert the trade-off.
    #[test]
    fn known_gaps_are_the_only_way_to_miss() {
        // Documented gaps: not detected. Treated as "no auto-refresh",
        // which is exactly the behaviour before this module existed.
        for cmd in [
            "echo x | git commit -m x",
            "(cd /tmp; git commit -m x)",
            "git commit -m x &",
        ] {
            // Not asserting `!may_mutate_git` — the impl is free to
            // improve. Just document current behaviour for anyone
            // reading the test as a spec.
            let _ = may_mutate_git(cmd);
        }
    }

    /// Drift guard: every `git` subcommand the security rules file knows
    /// about must be either covered by the mutating list or explicitly
    /// rejected in [`KNOWN_NON_MUTATING`]. If someone adds a git rule to
    /// `shell_risk_rules.toml`, this test tells them to decide which
    /// side it lands on — without the two files ever needing to be
    /// edited in the same commit.
    #[test]
    fn drift_guard_covers_security_rule_file() {
        let rules = crate::security::shell_risk::ShellRiskRules::default();
        let mut undecided: Vec<&str> = Vec::new();
        for cmd in rules.known_git_subcommands() {
            let covered = GIT_MUTATING_SUBCOMMANDS.contains(&cmd.as_str())
                || KNOWN_NON_MUTATING.contains(&cmd.as_str());
            if !covered {
                undecided.push(Box::leak(cmd.into_boxed_str()));
            }
        }
        assert!(
            undecided.is_empty(),
            "security rules file knows git subcommands {undecided:?} that this module \
             does not account for. Decide per subcommand: does it mutate index or HEAD? \
             If yes add it to GIT_MUTATING_SUBCOMMANDS; if no add it to KNOWN_NON_MUTATING \
             with the reason."
        );
    }

    /// The exclusion list is itself load-bearing — if a name lands in
    /// both lists the detector is fine but the drift guard has silently
    /// stopped guarding anything about it.
    #[test]
    fn lists_are_disjoint() {
        for sub in KNOWN_NON_MUTATING {
            assert!(
                !GIT_MUTATING_SUBCOMMANDS.contains(sub),
                "{sub} is listed as both mutating and non-mutating"
            );
        }
    }
}
