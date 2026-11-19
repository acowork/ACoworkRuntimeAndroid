//! LSP server registry schema — the contract between `acowork-lsp-relay`
//! and `acowork-node` (ADR-091).
//!
//! Two JSON files use these types and they have different authority:
//!
//! | file | writer | shape | role |
//! |------|--------|-------|------|
//! | `assets/lsp_servers.json` | nobody at runtime (ships with the suite) | [`LspServersConfig`] | **preset**: read-only server metadata |
//! | `{node_home}/lsp_servers.json` | the Node (single writer) | [`LspRegistryFile`] | **runtime truth**: preset ∪ custom, plus persisted install state |
//!
//! The relay reads the *runtime* file as its server list — that is what makes
//! a user-added custom server reachable — and it reads it with
//! [`LspServersConfig`]. The extra keys a runtime entry carries (`source`, the
//! install-state block) are invisible to it: `LspServerEntry` has no
//! `deny_unknown_fields`, so serde ignores them. That asymmetry is the whole
//! basis for "the Node owns the file, the relay only reads it" (ADR-091 §5.8),
//! and it is enforced by the `run_lsp_registry_redline` check in `dev/ci.sh`
//! (the relay crate must never name `install_state` or write the runtime path).
//!
//! `source` deliberately lives on [`LspRuntimeEntry`] and NOT on
//! [`LspServerEntry`]: the preset file is a shipped artifact whose schema must
//! not grow, while the runtime file is allowed to.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

/// Env var naming the **preset asset directory** — the one holding
/// `lsp_servers.json` and `lsp_install/` (ADR-091 D16).
///
/// It is deliberately not `ACOWORK_LSP_CONFIG_DIR`: that one names the
/// directory the relay loads its server list *from*, which since ADR-091 is
/// `{node_home}` (the runtime file). Install scripts ship with the suite and
/// must keep resolving from the suite's own resources, so the two concerns
/// cannot share one variable.
pub const LSP_ASSET_DIR_ENV: &str = "ACOWORK_LSP_ASSET_DIR";

/// The asset directory from the environment, if it is set and exists.
pub fn lsp_asset_dir_from_env() -> Option<PathBuf> {
    std::env::var_os(LSP_ASSET_DIR_ENV)
        .map(PathBuf::from)
        .filter(|dir| dir.is_dir())
}

/// Candidate asset directories, in priority order, for callers that have to
/// locate the preset without an explicit injection (a bare `acowork-node` or
/// `acowork-lsp-relay` started from a dev shell).
///
/// Mirrors the relay's own config search order — `CARGO_MANIFEST_DIR` for
/// `cargo run`/`cargo test`, the `assets/` of an exe ancestor for a
/// `target/{profile}/` binary, then the working directory — so the Node's
/// registry and the relay's server list agree on where the preset is.
pub fn lsp_asset_dir_candidates() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Some(dir) = lsp_asset_dir_from_env() {
        dirs.push(dir);
    }
    if let Ok(manifest_dir) = std::env::var("CARGO_MANIFEST_DIR") {
        dirs.push(
            PathBuf::from(manifest_dir)
                .join("..")
                .join("..")
                .join("assets"),
        );
    }
    if let Ok(exe_path) = std::env::current_exe() {
        dirs.extend(exe_path.ancestors().skip(1).map(|dir| dir.join("assets")));
    }
    if let Ok(cwd) = std::env::current_dir() {
        dirs.push(cwd.join("assets"));
    }
    dirs
}

/// First candidate directory that actually exists.
pub fn resolve_lsp_asset_dir() -> Option<PathBuf> {
    lsp_asset_dir_candidates().into_iter().find(|dir| dir.is_dir())
}

/// Read the preset registry (`{asset_dir}/lsp_servers.json`), returning
/// `None` when no preset file is found — the caller then starts from an
/// empty registry rather than a hardcoded list, so this shared helper has
/// one opinion about the preset and the relay's own fallback keeps its
/// historical built-in defaults.
pub fn load_preset_servers(asset_dir: Option<&Path>) -> Option<LspServersConfig> {
    // The caller's explicit directory first (what the Node supervisor
    // injects), then the fallback chain for a bare dev/CI run.
    let mut chain = Vec::new();
    if let Some(dir) = asset_dir {
        chain.push(dir.to_path_buf());
    }
    chain.extend(lsp_asset_dir_candidates());
    for dir in chain {
        if dir.join("lsp_servers.json").exists()
            && let Some(cfg) = read_preset_servers(&dir)
        {
            return Some(cfg);
        }
    }
    None
}

fn read_preset_servers(asset_dir: &Path) -> Option<LspServersConfig> {
    let path = asset_dir.join("lsp_servers.json");
    match std::fs::read_to_string(&path) {
        Ok(content) => match serde_json::from_str::<LspServersConfig>(&content) {
            Ok(cfg) => {
                tracing::info!(
                    path = %path.display(),
                    count = cfg.servers.len(),
                    "Loaded LSP preset registry"
                );
                Some(cfg)
            }
            Err(e) => {
                tracing::warn!(path = %path.display(), error = %e, "Failed to parse preset lsp_servers.json");
                None
            }
        },
        Err(e) => {
            tracing::warn!(path = %path.display(), error = %e, "Failed to read preset lsp_servers.json");
            None
        }
    }
}

/// `version` written into the runtime registry file (ADR-091 §5.2).
pub const LSP_REGISTRY_VERSION: u32 = 1;

/// Cap on the persisted install stdout/stderr (ADR-091 §5.4): the file is
/// world-readable-ish on Windows, and an `npm install` log is megabytes.
pub const LSP_INSTALL_OUTPUT_LIMIT: usize = 4096;

/// Per-language LSP server specification.
///
/// `candidate_args` is intentionally kept as `HashMap`: only the entry-point
/// `servers` / `status` maps are user-visible ordering, and there is no
/// stable contract on per-candidate arg overrides.
///
/// `install_hint` / `description` default to empty so a hand-written custom
/// entry (which may only carry `candidates`) still parses; the harness UI
/// falls back to the server name in that case.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LspServerEntry {
    /// Candidate command names (tried in order).
    pub candidates: Vec<String>,
    /// Extra arguments for stdio-mode LSP communication.
    #[serde(default)]
    pub args: Vec<String>,
    /// Per-candidate arg overrides.
    #[serde(default, skip_serializing_if = "empty_candidate_args")]
    pub candidate_args: HashMap<String, Vec<String>>,
    /// One-line install hint shown to the user.
    #[serde(default)]
    pub install_hint: String,
    /// Name of the install script file (e.g. "rust" → lsp_install/rust.sh).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub install_script: Option<String>,
    /// Human-readable description.
    #[serde(default)]
    pub description: String,
    /// Language-specific root marker files (e.g. tsconfig.json, Cargo.toml).
    /// Used by project root discovery to find the nearest project root.
    /// Languages with no markers (rootless) have an empty list.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub root_markers: Vec<String>,
}

fn empty_candidate_args(map: &HashMap<String, Vec<String>>) -> bool {
    map.is_empty()
}

/// Top-level structure of the read-only **preset** file
/// (`assets/lsp_servers.json`).
///
/// `servers` is an `IndexMap` (not `HashMap`) so iteration order matches
/// the order keys appear in the JSON file. `HashMap` would randomize the
/// order per-process (SipHash with a random seed), which made the harness
/// LSP list appear in a different order on every gateway restart.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LspServersConfig {
    pub version: u32,
    pub servers: IndexMap<String, LspServerEntry>,
}

/// Which file a registry entry came from (ADR-091 D5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LspSource {
    /// Shipped with the suite; metadata is refreshed from the preset on merge.
    Preset,
    /// Added by a user through the Node API; never overwritten by a merge.
    Custom,
}

impl Default for LspSource {
    /// A file written before ADR-091 (or hand-written) carries no `source`;
    /// treating it as preset is the conservative reading — a preset entry is
    /// refreshed but never deleted by the merge.
    fn default() -> Self {
        Self::Preset
    }
}

/// Persisted installation state of one LSP server (ADR-091 D9/D10).
///
/// There is deliberately no `installing` variant: an in-flight install is
/// process state, and persisting it would survive a crash as a lie the UI
/// cannot distinguish from a live install. The Node tracks in-flight names in
/// memory instead and exposes them as a separate `installing` flag on the API
/// response.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LspInstallState {
    /// Never probed, or the last probe said the binary is not there. The
    /// default: a record written before ADR-091 has no state to trust.
    #[default]
    Unknown,
    /// A binary was found on PATH, but not installed by our script.
    Detected,
    /// Installed by the registry's own install script.
    Installed,
    /// The last install run exited non-zero or timed out.
    Failed,
}

/// State block of a runtime entry: the state itself plus the evidence that
/// produced it (ADR-091 §5.2).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LspInstallRecord {
    #[serde(default)]
    pub install_state: LspInstallState,
    /// Candidate that resolved last time (shown in the UI when installed).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub installed_command: Option<String>,
    /// Tail of the install script's stdout, truncated to
    /// [`LSP_INSTALL_OUTPUT_LIMIT`] — failure diagnosis without the megabytes.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub install_stdout: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub install_stderr: String,
    /// Wall-clock ms at the end of the last install run (0 epoch = never).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_install_ms: Option<u64>,
    /// Wall-clock ms of the last probe convergence (§5.8) — the UI renders
    /// "checked N ago" from it, because a probe is seconds, not milliseconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_check_ms: Option<u64>,
}

/// One entry of the runtime registry file.
///
/// Both blocks are `#[serde(flatten)]`ed, so the on-disk shape is the flat
/// preset shape plus the state keys — a relay reading this file sees exactly
/// an `LspServerEntry` and ignores the rest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LspRuntimeEntry {
    #[serde(flatten)]
    pub metadata: LspServerEntry,
    #[serde(default)]
    pub source: LspSource,
    #[serde(flatten, default)]
    pub install: LspInstallRecord,
}

impl LspRuntimeEntry {
    /// Fresh entry from a preset definition: state unknown until probed.
    pub fn from_preset(metadata: LspServerEntry) -> Self {
        Self {
            metadata,
            source: LspSource::Preset,
            install: LspInstallRecord::default(),
        }
    }

    pub fn is_custom(&self) -> bool {
        self.source == LspSource::Custom
    }

    /// Truncate install output before persisting it (keeps the tail — that is
    /// where the error is).
    pub fn truncate_output(raw: &str) -> String {
        if raw.len() <= LSP_INSTALL_OUTPUT_LIMIT {
            return raw.to_string();
        }
        let mut start = raw.len() - LSP_INSTALL_OUTPUT_LIMIT;
        // Never split a UTF-8 char (install logs carry npm/pip box drawing).
        while !raw.is_char_boundary(start) {
            start += 1;
        }
        format!("…(head truncated){}", &raw[start..])
    }
}

/// Top-level structure of the runtime registry file
/// (`{node_home}/lsp_servers.json`).
///
/// `IndexMap` for the same reason as [`LspServersConfig`]: the harness list
/// order must be stable across restarts. Ordering invariant (ADR-091 §5.3):
/// preset entries first in preset-file order, then custom entries in
/// creation order.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LspRegistryFile {
    pub version: u32,
    pub servers: IndexMap<String, LspRuntimeEntry>,
}

impl Default for LspRegistryFile {
    fn default() -> Self {
        Self {
            version: LSP_REGISTRY_VERSION,
            servers: IndexMap::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn preset_fixture() -> LspServersConfig {
        serde_json::from_str(
            r#"{
              "version": 1,
              "servers": {
                "rust": {
                  "candidates": ["rust-analyzer"],
                  "args": [],
                  "install_hint": "rustup component add rust-analyzer",
                  "install_script": "rust",
                  "description": "Rust language server",
                  "root_markers": ["Cargo.toml"]
                }
              }
            }"#,
        )
        .expect("preset fixture parses")
    }

    /// A runtime entry must round-trip through the *relay's* view of the
    /// world (`LspServersConfig`), which is how the relay sees a file the
    /// Node wrote: the state keys have to be ignored, not rejected.
    #[test]
    fn runtime_entry_is_readable_as_preset_by_the_relay_view() {
        let preset = preset_fixture();
        let entry = LspRuntimeEntry::from_preset(preset.servers["rust"].clone());
        let file = LspRegistryFile {
            version: LSP_REGISTRY_VERSION,
            servers: IndexMap::from([("rust".to_string(), entry)]),
        };
        let json = serde_json::to_string(&file).unwrap();
        let as_preset: LspServersConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(as_preset.servers["rust"].candidates, ["rust-analyzer"]);
        assert_eq!(as_preset.servers["rust"].install_script.as_deref(), Some("rust"));
    }

    /// Custom entries are written by hand through the API, so the minimal
    /// shape (candidates only) must parse, and `source` must survive.
    #[test]
    fn minimal_custom_entry_parses() {
        let entry: LspRuntimeEntry =
            serde_json::from_str(r#"{"candidates":["my-lsp"],"source":"custom"}"#).unwrap();
        assert_eq!(entry.source, LspSource::Custom);
        assert_eq!(entry.install.install_state, LspInstallState::Unknown);
        assert!(entry.metadata.args.is_empty());
    }

    /// A pre-ADR-091 file (no `source`, no state) must still load — as
    /// preset, the reading that never deletes a shipped server.
    #[test]
    fn missing_source_defaults_to_preset() {
        let entry: LspRuntimeEntry =
            serde_json::from_str(r#"{"candidates":["gopls"],"install_hint":"go install"}"#).unwrap();
        assert_eq!(entry.source, LspSource::Preset);
    }

    #[test]
    fn output_truncation_keeps_the_tail_and_stays_utf8_safe() {
        assert_eq!(LspRuntimeEntry::truncate_output("done"), "done");
        let big = "é".repeat(LSP_INSTALL_OUTPUT_LIMIT);
        let cut = LspRuntimeEntry::truncate_output(&big);
        assert!(cut.len() < big.len());
        assert!(cut.ends_with('é'));
    }
}
