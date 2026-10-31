//! The settings screen's rows, generated from the document the runtime actually reads.
//!
//! ## Why this module exists
//!
//! [`HostConfig`] can be serialised, and a screen could render it by hand — one widget per field,
//! written in Kotlin. That is how the two dead rows in `budgets`/`timing` got shipped once already
//! (see `docs/design/zh/android-runtime-settings.md`): a field was added to the document, a widget
//! was added to the screen, and nothing in between checked that the value reached a process. A
//! screen written by hand can also *miss* a field, in which case the operator cannot set it at all
//! and has no way to know it exists.
//!
//! So the row list lives here, next to the validator, and the two are tied by tests in both
//! directions:
//!
//! - [`catalog`] derives its row ids from the serialised default document, so a field added to
//!   [`HostConfig`] without a row here fails `the_document_and_the_screen_have_the_same_rows`.
//! - Each row carries the same bounds [`HostConfig::validate`] applies, taken from the same
//!   constants — so a slider that would offer a rejected value fails
//!   `a_row_never_offers_a_value_the_validator_would_reject`.
//! - Each row's default is read back out of the live document rather than typed a second time, so
//!   changing a default cannot leave the screen showing the old one.
//!
//! The module deliberately does **not** carry user-facing copy in more than one language: `title`
//! and `help` are English identifiers for developers, and the APK owns the localized strings keyed
//! by [`SettingSpec::id`]. The ids are the contract between the two halves, which is why they are
//! the document's dotted paths and nothing else.

use serde::Serialize;

use crate::host::config::{
    AUDIT_FILE_MAX, AUDIT_FILE_MIN, BUGREPORT_TIMEOUT_MAX, BUGREPORT_TIMEOUT_MIN,
    COMMAND_TIMEOUT_MAX, COMMAND_TIMEOUT_MIN, EVIDENCE_BUDGET_MAX, EVIDENCE_BUDGET_MIN, HostConfig,
    LOCK_TTL_MAX, LOCK_TTL_MIN, LOGCAT_TAIL_MAX, OUTPUT_CAP_MAX, OUTPUT_CAP_MIN,
    SNAPSHOT_STORE_MAX, SNAPSHOT_STORE_MIN,
};

/// Which section of the screen a row belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SettingGroup {
    /// Where the runtime keeps its own bytes.
    Storage,
    /// How much of them it may keep.
    Budgets,
    /// How long it may take.
    Timing,
    /// What it may collect about the device.
    Evidence,
    /// What it may be asked to do.
    Capabilities,
}

/// What control the screen should draw, with the bounds that apply to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SettingKind {
    /// On/off.
    Toggle,
    /// A byte count between two values, inclusive.
    Bytes {
        /// Smallest accepted value.
        min: u64,
        /// Largest accepted value.
        max: u64,
    },
    /// A number of whole seconds, inclusive.
    Seconds {
        /// Smallest accepted value.
        min: u64,
        /// Largest accepted value.
        max: u64,
    },
    /// A number of lines; `0` means "no limit", so only the top is bounded.
    Lines {
        /// Largest accepted value.
        max: u32,
    },
    /// A subdirectory name under the runtime's root. Not a path: the root is the host's.
    Subdirectory,
    /// A list of capability ids, each drawn as its own switch.
    CapabilityList,
}

/// One row of the settings screen.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SettingSpec {
    /// The document path, e.g. `budgets.evidence_budget_bytes`. Also the localization key.
    pub id: String,
    /// The section header it appears under.
    pub group: SettingGroup,
    /// The control and its bounds.
    pub kind: SettingKind,
    /// What the row is, for a developer reading the catalog dump.
    pub title: &'static str,
    /// Why a person would change it — the row's help text, and the reason this field is on the
    /// screen rather than left at its default.
    pub help: &'static str,
    /// The value the runtime starts with when nobody sets one. Read from the live document, so it
    /// cannot disagree with the code.
    pub default: String,
    /// Whether changing it needs the runtime to be restarted.
    ///
    /// Every row is restart-scoped today, and that is a decision rather than an oversight: the
    /// capability claims, the snapshot store's budget and the audit sink are all fixed when a
    /// session's chain is assembled, and changing one of them mid-session would leave approvals
    /// and ledger entries referring to different rules. See `all_rows_are_restart_scoped`.
    pub requires_restart: bool,
}

/// Metadata for one row, keyed by document path.
struct Row {
    id: &'static str,
    group: SettingGroup,
    kind: SettingKind,
    title: &'static str,
    help: &'static str,
}

/// The rows. Kept in document order so a catalog dump reads like the settings file.
const ROWS: &[Row] = &[
    Row {
        id: "storage.snapshot_subdir",
        group: SettingGroup::Storage,
        kind: SettingKind::Subdirectory,
        title: "Snapshot directory",
        help: "Where pre-write backups of files live. Needs room for the store budget below; a \
               device out of space cannot undo its last write.",
    },
    Row {
        id: "storage.audit_subdir",
        group: SettingGroup::Storage,
        kind: SettingKind::Subdirectory,
        title: "Audit directory",
        help: "Where the record of every command that ran is kept. This is the file that answers \
               what the agent did after the fact.",
    },
    Row {
        id: "storage.evidence_subdir",
        group: SettingGroup::Storage,
        kind: SettingKind::Subdirectory,
        title: "Evidence directory",
        help: "Where captured screenshots, logs and bugreports are written before they are \
               collected.",
    },
    Row {
        id: "budgets.snapshot_store_bytes",
        group: SettingGroup::Budgets,
        kind: SettingKind::Bytes {
            min: SNAPSHOT_STORE_MIN,
            max: SNAPSHOT_STORE_MAX,
        },
        title: "Snapshot store budget",
        help: "Total size of the backups kept for one session. Oldest entries are dropped when it \
               fills, and a dropped backup means a write that can no longer be undone.",
    },
    Row {
        id: "budgets.audit_file_bytes",
        group: SettingGroup::Budgets,
        kind: SettingKind::Bytes {
            min: AUDIT_FILE_MIN,
            max: AUDIT_FILE_MAX,
        },
        title: "Audit file size",
        help: "How large the audit file grows before it rotates. Small enough to keep the phone \
               usable, large enough that one day of commands is not lost.",
    },
    Row {
        id: "budgets.evidence_budget_bytes",
        group: SettingGroup::Budgets,
        kind: SettingKind::Bytes {
            min: EVIDENCE_BUDGET_MIN,
            max: EVIDENCE_BUDGET_MAX,
        },
        title: "Evidence size limit",
        help: "The largest single capture. A bugreport is tens of megabytes and leaves the phone; \
               this is the number that decides how much of it is kept.",
    },
    Row {
        id: "budgets.output_cap_bytes",
        group: SettingGroup::Budgets,
        kind: SettingKind::Bytes {
            min: OUTPUT_CAP_MIN,
            max: OUTPUT_CAP_MAX,
        },
        title: "Command output limit",
        help: "How much of one command's output reaches the model. Raising it costs context; \
               lowering it truncates what the agent can see.",
    },
    Row {
        id: "timing.command_timeout_secs",
        group: SettingGroup::Timing,
        kind: SettingKind::Seconds {
            min: COMMAND_TIMEOUT_MIN,
            max: COMMAND_TIMEOUT_MAX,
        },
        title: "Command timeout",
        help: "How long one command may run before the child is killed. Slow devices and long \
               restores need more than the default; the undo at session end obeys this too.",
    },
    Row {
        id: "timing.lock_ttl_secs",
        group: SettingGroup::Timing,
        kind: SettingKind::Seconds {
            min: LOCK_TTL_MIN,
            max: LOCK_TTL_MAX,
        },
        title: "Write lock lifetime",
        help: "How long a write session holds the device exclusive without renewing. Two agents \
               writing at once is the failure this prevents.",
    },
    Row {
        id: "timing.bugreport_timeout_secs",
        group: SettingGroup::Timing,
        kind: SettingKind::Seconds {
            min: BUGREPORT_TIMEOUT_MIN,
            max: BUGREPORT_TIMEOUT_MAX,
        },
        title: "Bugreport timeout",
        help: "How long to wait for a full bugreport. It is measured in minutes on a real phone; \
               below the device's own time the capture always fails.",
    },
    Row {
        id: "evidence.screenshot",
        group: SettingGroup::Evidence,
        kind: SettingKind::Toggle,
        title: "Allow screenshots",
        help: "Capture what is on the display. Whatever is on screen — a message, a code, a \
               face — is in the image.",
    },
    Row {
        id: "evidence.logcat",
        group: SettingGroup::Evidence,
        kind: SettingKind::Toggle,
        title: "Allow logs",
        help: "Capture the system log. Logs routinely contain other apps' data and tokens.",
    },
    Row {
        id: "evidence.logcat_tail_lines",
        group: SettingGroup::Evidence,
        kind: SettingKind::Lines {
            max: LOGCAT_TAIL_MAX,
        },
        title: "Log lines",
        help: "How much log to keep when the caller did not ask for a specific window. `0` means \
               the whole buffer, which is the largest thing on this screen.",
    },
    Row {
        id: "evidence.dumpsys",
        group: SettingGroup::Evidence,
        kind: SettingKind::Toggle,
        title: "Allow service state",
        help: "Capture `dumpsys` output for one system service: window lists, package state, \
               battery history.",
    },
    Row {
        id: "evidence.device_files",
        group: SettingGroup::Evidence,
        kind: SettingKind::Toggle,
        title: "Allow reading device files",
        help: "Bring back a file that already exists on the device. Off by default: those paths \
               are other processes' crash stacks and other tools' scratch, and reading one is a \
               privacy event even when nothing needs to be approved for it.",
    },
    Row {
        id: "evidence.bugreport",
        group: SettingGroup::Evidence,
        kind: SettingKind::Toggle,
        title: "Allow full bugreport",
        help: "Off by default. This is the whole phone in one zip: every log, every dropped \
               notification, the radio state, the account list. It is also the slowest thing on \
               this screen.",
    },
    Row {
        id: "capability_ceiling",
        group: SettingGroup::Capabilities,
        kind: SettingKind::CapabilityList,
        title: "Allowed capabilities",
        help: "What this runtime may be granted. The device decides what is *possible*; this \
               list only ever narrows it, so unchecking a row can refuse work but never permit \
               any more than an unmodified device would.",
    },
];

/// Every row the settings screen should draw, in document order.
///
/// The defaults come from the live [`HostConfig::default`] document, so this function cannot
/// report a value the runtime would not start with.
#[must_use]
pub fn catalog() -> Vec<SettingSpec> {
    let document = serde_json::to_value(HostConfig::default())
        .expect("the default settings document is serialisable by construction");
    ROWS.iter()
        .map(|row| SettingSpec {
            id: row.id.to_string(),
            group: row.group,
            kind: row.kind,
            title: row.title,
            help: row.help,
            default: render(&document, row.id),
            // Nothing on this screen can be applied to a live session; see the field doc.
            requires_restart: true,
        })
        .collect()
}

/// The rows for one section, for a screen that draws them under headers.
#[must_use]
pub fn catalog_in(group: SettingGroup) -> Vec<SettingSpec> {
    catalog().into_iter().filter(|s| s.group == group).collect()
}

/// The document's leaf paths, in serialised order — the ground truth the row list is compared
/// against. Arrays report their own path rather than an indexed element, because the screen edits
/// `capability_ceiling` as one list.
#[cfg(test)]
fn document_leaves(document: &serde_json::Value) -> Vec<String> {
    let mut out = Vec::new();
    walk(document, String::new(), &mut out);
    out.sort();
    out
}

#[cfg(test)]
fn walk(value: &serde_json::Value, path: String, out: &mut Vec<String>) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, child) in map {
                let child_path = if path.is_empty() {
                    key.clone()
                } else {
                    format!("{path}.{key}")
                };
                walk(child, child_path, out);
            }
        }
        serde_json::Value::Array(_) => out.push(path),
        other => {
            let _ = other;
            out.push(path);
        }
    }
}

/// The default value of one path, rendered as text the screen can show.
fn render(document: &serde_json::Value, id: &str) -> String {
    let pointer = format!("/{}", id.replace('.', "/"));
    match document.pointer(&pointer) {
        Some(serde_json::Value::Array(items)) => items
            .iter()
            .filter_map(|i| i.as_str())
            .collect::<Vec<_>>()
            .join(","),
        Some(serde_json::Value::String(s)) => s.clone(),
        Some(serde_json::Value::Bool(b)) => b.to_string(),
        Some(serde_json::Value::Number(n)) => n.to_string(),
        // A row whose path is not in the document is a row that would show the operator a
        // default nobody can set. `debug_assert` catches it in the test run and in development;
        // shipping a wrong string is better than panicking in a UI callback.
        Some(_) | None => {
            debug_assert!(
                false,
                "settings row `{id}` does not name a field of HostConfig"
            );
            String::new()
        }
    }
}

/// The document with one path replaced, so the bounds tests can ask the validator about a value
/// without knowing which Rust field it lives in.
#[cfg(test)]
fn document_with(id: &str, value: serde_json::Value) -> serde_json::Value {
    let mut document =
        serde_json::to_value(HostConfig::default()).expect("default is serialisable");
    let pointer = format!("/{}", id.replace('.', "/"));
    *document
        .pointer_mut(&pointer)
        .unwrap_or_else(|| panic!("`{id}` is not a path in the settings document")) = value;
    document
}

/// Parse a document back into a config, for the bounds tests.
#[cfg(test)]
fn config_from(document: serde_json::Value) -> HostConfig {
    serde_json::from_value(document).expect("the document was built from a valid config")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_document_and_the_screen_have_the_same_rows() {
        // Both directions. A field added to `HostConfig` without a row here would be invisible
        // to the operator; a row here without a field would render a control that saves nothing.
        let document = serde_json::to_value(HostConfig::default()).unwrap();
        let mut fields = document_leaves(&document);
        fields.sort();
        let mut rows: Vec<String> = ROWS.iter().map(|r| r.id.to_string()).collect();
        rows.sort();
        assert_eq!(
            fields, rows,
            "the settings document and the settings screen disagree about what is configurable"
        );
    }

    #[test]
    fn row_ids_are_unique() {
        let mut seen: Vec<&str> = ROWS.iter().map(|r| r.id).collect();
        let total = seen.len();
        seen.sort();
        seen.dedup();
        assert_eq!(seen.len(), total, "a setting appears on the screen twice");
    }

    #[test]
    fn every_row_says_what_it_is_and_why_somebody_would_change_it() {
        // The help text is the only place the reason a knob exists survives; a row that cannot
        // explain itself is a row an operator will leave alone or set wrongly.
        for row in catalog() {
            assert!(!row.title.trim().is_empty(), "{} has no title", row.id);
            assert!(
                row.help.split_whitespace().count() >= 6,
                "{} has no usable help text",
                row.id
            );
            assert!(!row.default.is_empty(), "{} shows an empty default", row.id);
        }
    }

    #[test]
    fn the_default_the_screen_shows_is_the_default_the_runtime_starts_with() {
        let config = HostConfig::defaults();
        let rows = catalog();
        let find = |id: &str| rows.iter().find(|r| r.id == id).expect("row exists");
        assert_eq!(
            find("budgets.evidence_budget_bytes").default,
            config.budgets.evidence_budget_bytes.to_string()
        );
        assert_eq!(
            find("timing.command_timeout_secs").default,
            config.timing.command_timeout_secs.to_string()
        );
        assert_eq!(find("evidence.bugreport").default, "false");
        assert_eq!(find("evidence.screenshot").default, "true");
        assert_eq!(find("storage.snapshot_subdir").default, "snapshots");
        assert_eq!(
            find("capability_ceiling").default,
            config.capability_ceiling.join(",")
        );
    }

    #[test]
    fn a_row_never_offers_a_value_the_validator_would_reject() {
        // The bounds on the control and the bounds in `validate` have to be the same numbers.
        // If they drift, the screen offers a value the save button then refuses, which is worse
        // than not offering it: the operator cannot tell whether the setting is broken or the
        // number is.
        for row in catalog() {
            let (min, max) = match row.kind {
                SettingKind::Bytes { min, max } => (min, max),
                SettingKind::Seconds { min, max } => (min, max),
                SettingKind::Lines { max } => (0, max as u64),
                _ => continue,
            };
            for value in [min, max] {
                let config = config_from(document_with(&row.id, serde_json::json!(value)));
                if let Err(err) = config.validate() {
                    panic!("{} rejects its own bound {value}: {}", row.id, err.reason);
                }
            }
            if min > 0 {
                let config = config_from(document_with(&row.id, serde_json::json!(min - 1)));
                let err = config.validate().expect_err(&format!(
                    "{} accepts a value below its stated floor",
                    row.id
                ));
                assert_eq!(err.field, row.id, "the refusal blames the wrong row");
            }
            let config = config_from(document_with(&row.id, serde_json::json!(max + 1)));
            let err = config.validate().expect_err(&format!(
                "{} accepts a value above its stated ceiling",
                row.id
            ));
            assert_eq!(err.field, row.id, "the refusal blames the wrong row");
        }
    }

    #[test]
    fn a_toggle_row_is_settable_either_way() {
        for id in [
            "evidence.screenshot",
            "evidence.logcat",
            "evidence.dumpsys",
            "evidence.device_files",
            "evidence.bugreport",
        ] {
            for value in [true, false] {
                let config = config_from(document_with(id, serde_json::json!(value)));
                assert!(config.validate().is_ok(), "{id}={value} should be settable");
            }
        }
    }

    #[test]
    fn a_subdirectory_row_refuses_a_path_that_leaves_the_runtime_root() {
        // The screen draws these as a name, not a path, because the root belongs to the host that
        // started the runtime. A row that let somebody type `../..` would move the snapshot store
        // outside the area the port's own write rules cover.
        for id in [
            "storage.snapshot_subdir",
            "storage.audit_subdir",
            "storage.evidence_subdir",
        ] {
            for bad in ["", "..", "../escape", "/absolute", "a/b/../../c"] {
                let config = config_from(document_with(id, serde_json::json!(bad)));
                let err = config
                    .validate()
                    .expect_err(&format!("{id} accepted `{bad}`"));
                assert_eq!(err.field, id);
            }
        }
    }

    #[test]
    fn a_capability_row_refuses_an_id_that_is_not_in_the_vocabulary() {
        let config = config_from(document_with(
            "capability_ceiling",
            serde_json::json!(["android:fs:sytem"]),
        ));
        let err = config
            .validate()
            .expect_err("a misspelled capability id must not be accepted");
        assert_eq!(err.field, "capability_ceiling");
        assert!(
            err.reason.contains("android:fs:sytem"),
            "the refusal should quote what was wrong: {}",
            err.reason
        );
    }

    #[test]
    fn every_capability_the_screen_can_draw_is_a_row_on_the_screen() {
        // The screen draws one switch per capability rather than a free-text list, so it needs
        // the vocabulary from the code. If a capability is added and not listed here, the
        // operator cannot enable it — and the ceiling only ever narrows, so the omission would
        // look like a device fault.
        let options = capability_options();
        assert!(
            options.len() >= 5,
            "expected the full Android vocabulary, got {options:?}"
        );
        for option in &options {
            assert!(!option.id.is_empty() && !option.title.is_empty());
            // Every option is a legal ceiling value on its own.
            let config = config_from(document_with(
                "capability_ceiling",
                serde_json::json!([option.id]),
            ));
            assert!(
                config.validate().is_ok(),
                "the screen offers {} which the validator rejects",
                option.id
            );
        }
    }

    #[test]
    fn all_rows_are_restart_scoped() {
        // Pinned as a test because it is a product decision: a screen that let somebody change
        // the snapshot budget mid-session would leave a session whose approvals were granted
        // under one rule set writing under another. If a future row is genuinely live, this
        // fails and the author has to say why.
        assert!(
            catalog().iter().all(|row| row.requires_restart),
            "a live-applyable setting needs a documented reason for not corrupting a session"
        );
    }

    #[test]
    fn the_catalog_is_serialisable_for_the_apk_to_render() {
        // The Kotlin side gets this JSON over JNI and draws it; a shape change here is a wire
        // change there, so the field names are pinned.
        let json = serde_json::to_string(&catalog()).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        let first = &value[0];
        for key in [
            "id",
            "group",
            "kind",
            "title",
            "help",
            "default",
            "requiresRestart",
        ] {
            assert!(first.get(key).is_some(), "the wire row lost `{key}`");
        }
        assert_eq!(first["id"], "storage.snapshot_subdir");
        assert_eq!(first["group"], "storage");
    }
}

/// One capability the screen can offer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityOption {
    /// The wire id, exactly as the Gateway will see it (`android:fs:system`).
    pub id: String,
    /// What granting it allows.
    pub title: &'static str,
    /// Whether the device this runtime runs on can actually do it — measured, not configured.
    pub supported: bool,
    /// Why not, in the port's own words, when `supported` is false.
    ///
    /// This is the row's whole reason to exist: "this phone cannot do that" and "you told it not
    /// to" look identical to a user otherwise, and only one of them is theirs to change. The text
    /// comes from [`explain_absence`](crate::host::explain_absence), the same function that
    /// answers a refused request at runtime, so the screen and the refusal cannot disagree.
    pub missing_because: Option<String>,
}

/// The capability vocabulary the ceiling list is drawn from, with nothing measured.
///
/// Every row reports `supported: false` because this function has no device to ask. A screen with
/// a profile in hand calls [`capability_options_for`]; this variant exists so the list of *rows*
/// is available before a probe has run.
#[must_use]
pub fn capability_options() -> Vec<CapabilityOption> {
    capability_options_for(&crate::host::HostProfile::assemble(
        &crate::host::ProbeOutput::nothing_ran(),
        "unknown",
    ))
}

/// The same list with each row's `supported` flag answered by a real device's profile.
///
/// The set of supported capabilities is `derive_claims`'s output, not a second derivation: the
/// screen that offered a capability the port would not claim would let an operator enable a row
/// that can never be used.
#[must_use]
pub fn capability_options_for(profile: &crate::host::HostProfile) -> Vec<CapabilityOption> {
    use crate::host::capability::{Capability, explain_absence};
    let earned: std::collections::BTreeSet<Capability> =
        crate::host::capability::derive_claims(profile)
            .into_iter()
            .filter_map(|claim| crate::host::capability::lookup(&claim.capability))
            .collect();
    Capability::all()
        .into_iter()
        .map(|capability| {
            let supported = earned.contains(&capability);
            CapabilityOption {
                id: capability.id().as_str().to_string(),
                title: title_for(capability),
                supported,
                missing_because: (!supported).then(|| explain_absence(profile, capability)),
            }
        })
        .collect()
}

/// One line per capability, for the row label.
///
/// The port's own doc comments on [`Capability`] say more than this, but a row label has to say
/// what a user is agreeing to rather than how it is derived.
fn title_for(capability: crate::host::capability::Capability) -> &'static str {
    use crate::host::capability::Capability;
    match capability {
        Capability::ShellRead => "Read device state",
        Capability::ShellWrite => "Change device settings",
        Capability::FsOutsideApp => "Write files outside this app",
        Capability::FsSystem => "Write the system partition",
        Capability::SelinuxPermissive => "Turn off SELinux enforcement",
    }
}
