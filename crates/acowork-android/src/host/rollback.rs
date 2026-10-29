//! ADR-AND-001 §4.6.4 — the undo that has to happen *after* the write.
//!
//! §4.6.4 promises three things: record a property's old value before changing it, roll it
//! back automatically at session end unless the change was explicitly declared to persist,
//! and back files up into the agent's workspace with a `restore`. None of it existed, and the
//! gate could not have noticed: contract rule R8 demands a stated rollback plan only from
//! capabilities marked `Irreversible`, and on Android exactly one is — `android:fs:system`,
//! where the honest plan is "reflash the stock image" and the point of making a model type
//! that sentence is that no code can undo it for it. `setprop` and `settings put` are marked
//! `Reversible`, which the gate reads as *nothing required*. So a write to a system property
//! sailed through with no plan, no captured value and no restore path, and "reversible" in the
//! capability table was a claim about the existence of this module rather than a fact about
//! the device.
//!
//! The claim was already being *spoken* too: [`crate::host::denial`] offers the model
//! `setenforce 0` with "is restored automatically at session end". Nothing restored anything.
//! A promise in a refusal message is the worst place for an unimplemented feature, because the
//! model reads it as a property of the world and prices the risk accordingly.
//!
//! # Shape
//!
//! Three steps, and the middle one is the reason the other two are in this order:
//!
//! 1. **Capture before.** [`plan`] reads the script's argument vectors — the classifier
//!    discards arguments, since a tier decision does not need to know *which* prop is being
//!    set — and names the read that must run first. Every capture is a §4.4 read (`getprop`,
//!    `settings get`, `getenforce`), so it needs no approval and is auto-passed by the same
//!    rule the rest of the read tier is.
//! 2. **Record after.** Only a write that actually succeeded gets an undo. A failed `setprop`
//!    changed nothing, and recording an inverse for it would add a write to the session's
//!    teardown that has no reason to run.
//! 3. **Restore last, in reverse.** LIFO, because a session that sets the same prop twice has
//!    two true intermediate states and the session ends in the one it reached last.
//!
//! # Why the restore reuses the original approval
//!
//! An inverse is a write, and writes need approval. Asking a human to approve the undo of
//! something they already approved is not safety: it is a prompt that trains them to tap
//! through, and if they are asleep the device stays in the modified state — which is the exact
//! outcome §4.6.4 exists to prevent. So the [`ApprovalToken`] from the original request travels
//! with the [`Undo`], on the reading that the approval covered *moving away from the baseline*,
//! and returning to the baseline is the half of that act nobody objected to. A write that was
//! never approved (an unattended read-tier script cannot reach here, but a caller that skipped
//! the gate can) records no token, and the restore says so rather than running unapproved.
//!
//! # What is not covered, said out loud
//!
//! `am`, `pm`, `input`, `stop`/`start` and any write to a file have no modelled inverse: there
//! is no script that puts a broadcast, an installed package, or a modified file back. Those are
//! returned as [`Unundoable`] and kept per session, because silence here is the failure mode —
//! a ledger that simply has nothing in it looks identical to a session that changed nothing.
//! The file case is §4.6.4's backup-to-workspace half, which is not this module and is not
//! implemented; the planner says so in the text it hands back.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use crate::host::backend::{
    ApprovalToken, BackendError, ExecRecord, ExecRequest, ExecutionBackend,
};
use crate::host::capability::Capability;
use crate::host::commands::{self, Finding};
use crate::host::facts::ShellDialect;
use crate::host::profile::HostProfile;
use crate::host::script::quote_posix;

/// How much file content a snapshot may hold.
///
/// A budget, not a limit: a bigger file is still written, it is simply declared unundoable
/// before the write rather than discovered after it. The number comes from the transport, not
/// from taste — the capture reads the file as base64 through the exec channel, whose stdout is
/// capped at [`crate::host::backend::DEFAULT_OUTPUT_CAP`] (1 MiB), and base64 costs 4 bytes per
/// 3. Leaving room for the envelope and for a device whose `base64` wraps lines differently
/// lands at a quarter of that. Raising it means raising the output cap, not this constant.
pub const SNAPSHOT_BUDGET_BYTES: u64 = 64 * 1024;

/// How much of the Agent workspace the whole snapshot store may occupy.
///
/// Enforced when a backup is *taken*, not when one would be evicted. The difference is the
/// point: an evicted backup voids an undo already written into the ledger, so the ledger would
/// go on promising a restore whose bytes are gone, and the failure would surface at teardown —
/// the worst possible moment to discover it. Refusing at capture time means the promise is
/// simply never made, and the reason appears in the same teardown line as the write that caused
/// it. Sized against the per-file budget: 8 MiB is roughly ninety-four 64 KiB backups, which is
/// far more file edits than a debugging session performs, and the workspace is on the host.
pub const SNAPSHOT_STORE_BUDGET_BYTES: u64 = 8 * 1024 * 1024;

/// Base64 characters handed to one command when a snapshot is put back.
///
/// Measured on a Huawei BLA-AL00 (EMUI, `/system/bin/sh` + toybox): a single argument
/// of 100 KiB reaches `printf` fine, 128 KiB fails with `Argument list too long` — Android's
/// `printf` is a real binary, so the payload goes through `execve` and shares the ~128 KiB
/// budget with the environment. A third of the observed ceiling is the working figure because
/// the ceiling is not the interface: it moves with the environment block, and a restore that
/// fails halfway through leaves a file that is neither the old one nor the new one.
pub const SNAPSHOT_CHUNK_BYTES: usize = 48 * 1024;

/// Where a staged snapshot is reassembled on the device before it is decoded.
///
/// `/data/local/tmp` is the one directory measured writable by the shell on every tier this
/// port runs at; the target path itself is often not writable until the write we are undoing
/// happens to be privileged.
pub const SNAPSHOT_STAGING_DIR: &str = "/data/local/tmp";

/// The host-side half of a file undo: where the old content is kept.
///
/// §4.6.4 says the backup goes to the Agent workspace, which is a directory the node owns and
/// the device does not. Keeping the bytes *out* of the ledger is what makes a session with
/// twelve file edits produce twelve short audit lines instead of twelve copies of the device's
/// data in the log.
#[derive(Debug, Clone)]
pub struct SnapshotStore {
    dir: PathBuf,
    budget: u64,
}

impl SnapshotStore {
    /// Store snapshots under `dir`, created on first use.
    pub fn new(dir: impl Into<PathBuf>) -> SnapshotStore {
        SnapshotStore {
            dir: dir.into(),
            budget: SNAPSHOT_STORE_BUDGET_BYTES,
        }
    }

    /// The same, with a different allowance.
    ///
    /// The budget belongs to the workspace, and the workspace belongs to the node, so a caller
    /// that has decided "4 MiB of backups in this Agent's directory" should say so here rather
    /// than discover the port's default at the wrong moment. It is also what makes the refusal
    /// testable without writing 8 MiB of base64 to a temp directory.
    pub fn with_budget(dir: impl Into<PathBuf>, budget: u64) -> SnapshotStore {
        SnapshotStore {
            dir: dir.into(),
            budget,
        }
    }

    /// The allowance this store enforces.
    pub fn budget(&self) -> u64 {
        self.budget
    }

    /// Where they live.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Write one snapshot, returning its path.
    ///
    /// The session id is a caller-supplied string and it becomes a file name, so it is reduced
    /// to alphanumerics, `-` and `_`. That set has no `.` in it, which is the whole point: a
    /// name built from it can never be `.` or `..`, and a session called `../../escape` cannot
    /// move the backup outside the workspace. A backup outside the workspace is device content
    /// nobody agreed to keep.
    /// `token` makes the name unique within the session — the script layer's nonce does the
    /// job, and reusing it keeps snapshot names in step with the capture that produced them.
    pub fn save(
        &self,
        session: &str,
        token: &str,
        base64_payload: &str,
    ) -> std::io::Result<PathBuf> {
        std::fs::create_dir_all(&self.dir)?;
        let used = self.used_bytes();
        let incoming = base64_payload.len() as u64;
        if used + incoming > self.budget {
            // `StorageFull` is the honest kind: this is not a permissions problem or a missing
            // directory, and a caller that retries would just fail again.
            return Err(std::io::Error::new(
                std::io::ErrorKind::StorageFull,
                format!(
                    "the snapshot store holds {used} bytes against a {}-byte budget, and this \
                     backup needs {incoming} — no older backup is evicted to make room, because \
                     that would void an undo already promised; this one is simply not promised",
                    self.budget
                ),
            ));
        }
        let path = self.dir.join(format!(
            "{}-{}.b64",
            sanitize(session, 40, '_'),
            sanitize(token, 24, '_')
        ));
        let mut file = std::fs::File::create(&path)?;
        file.write_all(base64_payload.as_bytes())?;
        file.flush()?;
        Ok(path)
    }

    /// Bytes currently occupied by stored backups.
    ///
    /// Summed from the directory rather than kept in a counter: the store is `Clone` and handed
    /// around behind an `Arc`, and a counter would be one more piece of state that can disagree
    /// with what is actually on disk. A few dozen `stat` calls per backup is not the cost worth
    /// being wrong about.
    pub fn used_bytes(&self) -> u64 {
        std::fs::read_dir(&self.dir)
            .map(|entries| {
                entries
                    .flatten()
                    .filter_map(|e| e.metadata().ok())
                    .filter(|m| m.is_file())
                    .map(|m| m.len())
                    .sum()
            })
            .unwrap_or_default()
    }

    /// Drop a snapshot. Best effort: a failure here leaves a stale backup in the workspace,
    /// which is untidy, not unsafe — and the alternative (reporting it as a rollback failure)
    /// would say the device was not restored when it was.
    pub fn discard(&self, path: &Path) {
        let _ = std::fs::remove_file(path);
    }
}

/// The value of a long flag in an argument vector: `--pkg com.foo` → `com.foo`.
///
/// A flag whose value is another flag (`--pkg --user 0`) is treated as absent rather than
/// returning `--user`: a package name that starts with `-` is not a package name, and reading
/// it as one would build a capture against a target the command never named.
fn flag_value<'a>(args: &'a [String], flag: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .map(String::as_str)
        .filter(|v| !v.starts_with('-'))
}

/// Whether a string can be trusted as a package name in a generated script.
///
/// The shell-quoting helper makes any of these safe to *embed*, but a name containing a slash
/// or a space is a mis-parse rather than a package, and a capture built on one reads the state
/// of something the write did not touch.
fn is_package_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() < 200
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '+'))
}

fn sanitize(input: &str, max: usize, pad: char) -> String {
    let mut out: String = input
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                pad
            }
        })
        .take(max)
        .collect();
    if out.is_empty() {
        out.push_str("session");
    }
    out
}

/// The piece of device state an [`Undo`] puts back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UndoTarget {
    /// A system property. `getprop`/`setprop`.
    Prop(String),
    /// One row of a `settings` table.
    Setting {
        /// `system` / `secure` / `global`.
        table: String,
        /// The setting key.
        key: String,
    },
    /// The SELinux enforcing mode —整机-wide state, which is why ADR-AND-001 §8 gates it on
    /// `android:selinux:permissive` rather than treating it as one more property.
    SelinuxMode,
    /// A file on the device, addressed by the absolute path the script named.
    ///
    /// Only absolute paths get here. A relative target resolves against the working directory
    /// of the *write*, which is the caller's business and not something a capture issued
    /// separately can reproduce — snapshotting `./hosts` could back up a different file than
    /// the one the script overwrote, and a rollback that restores the wrong file is worse than
    /// no rollback at all.
    File(String),
    /// An installed package, addressed by the name the command itself stated.
    ///
    /// Only `pm install --pkg NAME` reaches this: an install given a path names the package
    /// *inside* the APK, not on the command line, so the capture cannot say which package it
    /// would remove. A capture that cannot name its target must not build an undo for it.
    Package(String),
}

impl UndoTarget {
    /// Short enough to put in a log line, qualified enough that two settings rows in different
    /// tables do not read as the same target.
    pub fn describe(&self) -> String {
        match self {
            UndoTarget::Prop(key) => format!("prop {key}"),
            UndoTarget::Setting { table, key } => format!("settings {table}/{key}"),
            UndoTarget::SelinuxMode => "SELinux enforcing mode".to_string(),
            UndoTarget::File(path) => format!("file {path}"),
            UndoTarget::Package(name) => format!("package {name}"),
        }
    }
}

/// What the write is about to put at the target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Writing {
    /// A literal new value.
    Set(String),
    /// `settings delete` — whose inverse is putting back whatever was there, which is why the
    /// pre-state has to be read for it too.
    Delete,
    /// Something will be written here, and what it is cannot be known before the command runs.
    ///
    /// A redirect is this case: `sha256sum /data > /tmp/sums` writes output the planner has no
    /// business predicting. It does not need to — the inverse is the snapshot, not the value.
    Unknown,
}

/// What a rollback actually does to put one target back.
///
/// Two shapes because the two directions of a file are not the same operation: a property is
/// put back with one short command, while a file is put back by moving bytes that live in the
/// Agent workspace onto the device. Collapsing both into "a script" would mean either
/// embedding a snapshot in a command line — `/system/bin/printf` is a real process on Android,
/// so an argument over ~110 KiB fails with `Argument list too long` — or writing the ledger's
/// inverse out to disk and losing the property that an `Undo` says everything it needs in
/// itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UndoAction {
    /// Run this script through the backend, like any other command.
    Script(String),
    /// Put a file back from a snapshot stored in the Agent workspace.
    Snapshot {
        /// The host-side file holding the bytes.
        snapshot: PathBuf,
        /// How many bytes it held.
        bytes: u64,
        /// `sha256` of the file *as the device reported it*, so a restore can be checked
        /// against the thing it claims to have restored.
        digest: String,
    },
}

/// One read that must happen before the write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capture {
    /// What is about to change.
    pub target: UndoTarget,
    /// The read that yields the current value. Always §4.4 read-tier.
    pub read: String,
    /// What the script is about to write there.
    pub writing: Writing,
    /// `persist.*` — survives a reboot on its own, so leaving it behind is a change to the
    /// device rather than to this session, and §4.6.4 makes keeping it an explicit act.
    pub persists_reboot: bool,
}

impl Capture {
    /// The second read for a file capture: fetch the content itself.
    ///
    /// Split from [`Capture::read`] on purpose. The first read costs one `wc` and answers the
    /// only question that decides whether to continue — is there a file, and is it inside the
    /// snapshot budget? Running `base64` on a 4 GB file to discover it was never going to fit
    /// would put the cost of the decision on the device.
    pub fn content_read(&self) -> Option<String> {
        let UndoTarget::File(path) = &self.target else {
            return None;
        };
        let literal = quote_posix(path);
        Some(format!("sha256sum < {literal} && base64 < {literal}"))
    }
}

impl Capture {
    /// A write whose target is a file the script redirects into.
    ///
    /// Only a *plain absolute path* is modelled. Three cases are refused rather than guessed
    /// at, and each would break the snapshot in a different way:
    ///
    /// - relative paths resolve against the write's working directory, which the capture cannot
    ///   reproduce, so the backup could be of a different file than the one overwritten;
    /// - globs and `$variables` name a set or a value the planner cannot see, and `echo x > /a*`
    ///   may write several files;
    /// - `/dev/…` is a character device: writing it changes nothing readable afterwards, and
    ///   `base64` of it would block or spin.
    fn from_redirect(command: &commands::ParsedCommand) -> Option<Capture> {
        let path = command.redirect.as_deref()?;
        if !is_snapshotable_path(path) {
            return None;
        }
        let literal = quote_posix(path);
        // The envelope is built from ordinary read-tier commands with no subshells and no
        // braces: `$( )` and `{ }` make a script unanalysable to the classifier, and a capture
        // the gate refuses is a capture that reports "nothing was observed" — which is the
        // failure mode this whole module exists to avoid.
        let probe = format!("test -e {literal}");
        let read = format!(
            "{probe} && printf 'PRESENT\n'; {probe} && wc -c < {literal}; {probe} || printf \
             'ABSENT\n'"
        );
        Some(Capture {
            target: UndoTarget::File(path.to_string()),
            read,
            writing: Writing::Unknown,
            // A file is durable in a way a property is not: it is still there after a reboot
            // without anyone declaring it so.
            persists_reboot: true,
        })
    }
}

/// Whether a redirect target can be snapshotted. See [`Capture::from_redirect`].
fn is_snapshotable_path(path: &str) -> bool {
    path.starts_with('/')
        && !path.starts_with("/dev/")
        && !path.contains('~')
        && !path.contains('$')
        && !path.contains('`')
        && !path.chars().any(|c| {
            // Quotation marks included: a target the lexer had to strip quotes to produce
            // could have been assembled from pieces, and a snapshot of the assembled name
            // would not survive re-quoting on the way back.
            "*?[]{}()<>|&;".contains(c) || c == '"' || c == '\''
        })
}

/// A write this port knows how to put back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Undo {
    /// The session whose teardown this belongs to.
    pub session_id: String,
    /// What it puts back.
    pub target: UndoTarget,
    /// How it puts it back. See [`UndoAction`].
    pub action: UndoAction,
    /// The value that was there, verbatim, for whoever has to explain the restore.
    ///
    /// For a file this is a *summary* — size and digest — because the bytes themselves live in
    /// the snapshot store, and a ledger that carried file content would put device data in
    /// every log line the session produces.
    pub old_value: String,
    /// False when the inverse lands near the original state but not on it. Today that is one
    /// case: a property that was *unset* before, which `setprop key ''` restores as
    /// present-and-empty because Android has no unset.
    pub faithful: bool,
    /// See [`Capture::persists_reboot`].
    pub persists_reboot: bool,
    /// The capability the original write carried, so the restore is not a new capability claim.
    pub capability: Capability,
    /// The approval that authorised the write. See the module doc for why this is reused.
    pub token: Option<ApprovalToken>,
}

impl Undo {
    /// The script it runs, when the undo is one.
    ///
    /// `None` for a snapshot restore: that undo is a path and a digest, not a command line, and
    /// a caller that needs to *show* it should say so rather than be handed a truncated script.
    pub fn inverse_script(&self) -> Option<&str> {
        match &self.action {
            UndoAction::Script(script) => Some(script),
            UndoAction::Snapshot { .. } => None,
        }
    }

    /// `prop persist.sys.foo → "" (approximate)` — for a log or a UI, not for parsing.
    pub fn describe(&self) -> String {
        let approx = if self.faithful { "" } else { " (approximate)" };
        format!(
            "{} → {}{approx}",
            self.target.describe(),
            quote_if_empty(&self.old_value)
        )
    }
}

/// Why a write cannot be put back.
///
/// The distinction is the whole point of this enum. "No inverse is modelled" is an admission
/// about this port; "there is nothing to restore" is a fact about the command. Printed as one
/// sentence, the second reads like the first, an operator stops trusting the teardown, and the
/// session ends with the agent claiming it cleaned up something that was never undoable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnundoableKind {
    /// This port has no model for the command *yet*. The only kind that is a gap in the port
    /// rather than a fact about the device, and the only one worth a follow-up issue.
    NotModelled,
    /// The command destroys state the device keeps no copy of. Nothing can put it back; a
    /// backup taken after it ran is a backup of the emptied state.
    DestroysData,
    /// The command removes state that could only be re-created by another write needing its
    /// own approval (uninstall drops the binary; re-installing it is a new action).
    NoRestorableState,
    /// The command is an event, not a state change. There is nothing to restore, and the
    /// opposite gesture is a *new* action, not an undo.
    NotAStateChange,
    /// The write happened, but which object it touched is not derivable from the command text,
    /// so a capture taken before it would not describe the thing the write changed.
    IndeterminateTarget,
    /// The before-state was never observed — the probe failed, was refused, or printed
    /// something this capture cannot interpret. Its own kind because it is the one refusal that
    /// says nothing about whether the change *could* have been undone: the port simply did not
    /// see it, and inventing a value to restore is a new write wearing a rollback's name.
    Unobserved,
    /// The write did not change anything: the device already held the value. Not a failure to
    /// undo, and it must not be labelled like one — a teardown that calls a no-op "unundoable"
    /// teaches the reader to ignore the list.
    NoChange,
}

impl UnundoableKind {
    /// The label the teardown line opens with.
    pub fn label(self) -> &'static str {
        match self {
            UnundoableKind::NotModelled => "no inverse modelled",
            UnundoableKind::DestroysData => "destroys data",
            UnundoableKind::NoRestorableState => "no restorable state",
            UnundoableKind::NotAStateChange => "not a state change",
            UnundoableKind::IndeterminateTarget => "target not identifiable",
            UnundoableKind::Unobserved => "before-state not observed",
            UnundoableKind::NoChange => "no change to undo",
        }
    }
}

/// A mutation with no modelled inverse, kept so the session's teardown can say what it is
/// leaving behind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unundoable {
    /// The command word, as the classifier normalised it.
    pub command: String,
    /// What it does, and why there is no undo. Reaches the node, not the wire.
    pub why: String,
    /// Whether the reason is a fact about the command or a gap in this port.
    pub kind: UnundoableKind,
}

impl Unundoable {
    /// The one line the teardown prints.
    ///
    /// Living on the type rather than at each call site because the category is the part a
    /// reader needs and the part most easily dropped: a consumer that formats `command` and
    /// `why` alone produces a log where "the device cannot put this back" and "this port has
    /// not modelled it" are indistinguishable — which is the exact failure the enum exists to
    /// prevent.
    pub fn summary(&self) -> String {
        format!("[{}] {}: {}", self.kind.label(), self.command, self.why)
    }
}

/// The `pm` / `am` writes that have no inverse, and the reason for each.
///
/// A table rather than a match because the reasons are the deliverable: they are what turns
/// "we did not get to it" into "here is the fact about this command, and here is what you would
/// have to supply to undo it". Every entry was checked against the BLA-AL00 `pm help` output
/// and the device's actual read surface, not against AOSP documentation — which is why, for
/// example, `pm install-existing` is described as "not present on every build" instead of
/// assumed available: it is absent from this build's help text.
/// The enabled-state family shares one reason: the commands pair up, but the read does not
/// distinguish the modes, so no inverse can be named. Kept as one string because four copies of
/// a sentence drift four ways.
const ENABLED_STATE_REASON: &str = "the commands pair up, but no read on this device reports      *which* disabled mode a package is in — `pm list packages -d` folds `disabled`,      `disabled-user` and `disable-until-used` into one list (measured on BLA-AL00: 0 rows      against 300 enabled packages), so restoring the flag can set a different mode than the one      observed. That is a second unapproved change, not a rollback";

const IRREVERSIBLE: &[(&str, &str, UnundoableKind, &str)] = &[
    (
        "pm",
        "enable",
        UnundoableKind::NotModelled,
        ENABLED_STATE_REASON,
    ),
    (
        "pm",
        "disable",
        UnundoableKind::NotModelled,
        ENABLED_STATE_REASON,
    ),
    (
        "pm",
        "disable-user",
        UnundoableKind::NotModelled,
        ENABLED_STATE_REASON,
    ),
    (
        "pm",
        "disable-until-used",
        UnundoableKind::NotModelled,
        ENABLED_STATE_REASON,
    ),
    (
        "pm",
        "default-state",
        UnundoableKind::NotModelled,
        ENABLED_STATE_REASON,
    ),
    (
        "pm",
        "install",
        UnundoableKind::IndeterminateTarget,
        "the package name lives inside the APK, not on the command line, so nothing captured \
         beforehand could name the package this write created. `pm install --pkg NAME` does name \
         it, and then an undo can be planned",
    ),
    (
        "pm",
        "uninstall",
        UnundoableKind::NoRestorableState,
        "the device does not retain an uninstalled package's binary. Putting it back means \
         installing an APK again — a new write with its own approval — and `pm install-existing`, \
         the only primitive that restores a system package without an APK, is not present on \
         every build this port targets (it is absent from this device's `pm help`)",
    ),
    (
        "pm",
        "clear",
        UnundoableKind::DestroysData,
        "deletes everything the app holds: databases, preferences, accounts it configured, files \
         in its private directory. Nothing on the device can bring that back, and a snapshot \
         taken after this command runs captures the empty state",
    ),
    (
        "pm",
        "remove-user",
        UnundoableKind::DestroysData,
        "deletes the user and everything stored under it",
    ),
    (
        "pm",
        "create-user",
        UnundoableKind::IndeterminateTarget,
        "its inverse `remove-user` takes the numeric user id, which `create-user` prints in its \
         output rather than accepting as an argument — the planner plans from the command text, \
         and inventing an id to remove is how a rollback deletes the wrong user",
    ),
    (
        "pm",
        "trim-caches",
        UnundoableKind::DestroysData,
        "deletes cache files. They are regenerable in principle, but not by this port: what gets \
         rebuilt depends on what each app does next",
    ),
    (
        "pm",
        "install-commit",
        UnundoableKind::IndeterminateTarget,
        "a staged session names its payload by session id and the package only becomes known when \
         the commit reads the APK. `install-abandon` cancels a session that has not committed, \
         which is a cancel, not an inverse of one that has",
    ),
    (
        "pm",
        "grant",
        UnundoableKind::NotModelled,
        "the pair is named, but the pre-state is the set of permissions one app holds, and reading \
         it means parsing `dumpsys package`, whose field names are OEM-modified. A parser that \
         guesses here grants or revokes the wrong permission",
    ),
    (
        "am",
        "start",
        UnundoableKind::NoRestorableState,
        "the activity stack that was on screen is not something a command can put back. Forcing \
         the foreground app to stop is a different change, not an inverse, and it destroys state \
         this write never touched",
    ),
    (
        "am",
        "force-stop",
        UnundoableKind::NoRestorableState,
        "the process and everything in its memory are gone. Relaunching the app starts from a \
         different state than the one observed, so the ledger would be recording a change it \
         cannot describe",
    ),
    (
        "am",
        "broadcast",
        UnundoableKind::NotAStateChange,
        "delivers an intent and lets the receivers decide what happens; none of those effects are \
         visible to the planner. There is nothing here to restore, and the opposite action would \
         be another broadcast needing its own approval",
    ),
];

/// Commands where every write is irreversible the same way, whatever the argument is.
const HEAD_IRREVERSIBLE: &[(&str, UnundoableKind, &str)] = &[(
    "input",
    UnundoableKind::NotAStateChange,
    "injects a key, tap or gesture — an event, not a state change. There is no previous value to \
     put back, the app on the other end decides what the event causes, and those downstream \
     effects are not undone either. The opposite gesture is a new action requiring its own \
     approval, not a rollback",
)];

/// Why this write cannot be put back, if the table knows. `None` means the planner has no
/// specific fact to offer, which is reported as [`UnundoableKind::NotModelled`] — the one kind
/// that is an admission about this port rather than about the command.
fn irreversible(head: &str, sub: Option<&str>) -> Option<(UnundoableKind, String)> {
    if let Some(sub) = sub
        && let Some((_, _, kind, why)) = IRREVERSIBLE
            .iter()
            .find(|(h, s, _, _)| *h == head && *s == sub)
    {
        return Some((*kind, why.to_string()));
    }
    // A command whose *every* write is the same kind of irreversible does not need a
    // subcommand to be recognised: `input` has no read-only form at all.
    HEAD_IRREVERSIBLE
        .iter()
        .find(|(h, _, _)| *h == head)
        .map(|(_, kind, why)| (*kind, why.to_string()))
}

/// The subcommand of a dispatcher like `pm`/`am`, skipping any flags that come before it.
fn subcommand(args: &[String]) -> Option<&str> {
    args.get(1..)?
        .iter()
        .find(|a| !a.starts_with('-'))
        .map(String::as_str)
}

/// What a script needs before it runs, and what it will leave unundoable.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Plan {
    /// Reads to perform first, one per undoable write.
    pub captures: Vec<Capture>,
    /// Writes that will not be reversible, with the reason.
    pub unundoable: Vec<Unundoable>,
}

impl Plan {
    /// True when the script changes nothing the planner can see — which, given [`commands::words`]'s
    /// `None` handling, is never a claim that the script is harmless.
    pub fn is_empty(&self) -> bool {
        self.captures.is_empty() && self.unundoable.is_empty()
    }
}

/// Read a script for what it changes and what would have to be remembered to put it back.
///
/// Pure: it does not run anything. The caller decides which captures to issue, because issuing
/// them means talking to the device and that belongs to the backend, not to a planner.
pub fn plan(script: &str) -> Plan {
    let mut out = Plan::default();

    // `None` is the unanalysable case, and it is handled before anything else because it is the
    // one where the planner knows least: a script it cannot split may have changed the whole
    // device, and an empty undo list must not be allowed to imply otherwise.
    let Some(parsed) = commands::parsed(script) else {
        out.unundoable.push(Unundoable {
            command: script.trim().to_string(),
            why: "the script could not be split into commands, so nothing is known about what \
                  it changes — an empty undo list here means the planner was blind, not that \
                  the session is clean"
                .to_string(),
            kind: UnundoableKind::IndeterminateTarget,
        });
        return out;
    };

    // `classify` and `parsed` run the same lexer over the same text, so findings and commands
    // line up index for index. Zipping rather than re-parsing is what keeps the two from
    // disagreeing about what `setprop a 'b c'` is — a disagreement that would show up as a
    // rollback restoring the wrong value.
    let findings = commands::classify(script).findings;
    for (command, finding) in parsed.iter().zip(findings.iter()) {
        if finding.effect.is_read_only() {
            continue;
        }
        let capture =
            Capture::from_args(&command.words, finding).or_else(|| Capture::from_redirect(command));
        match capture {
            Some(capture) => out.captures.push(capture),
            // A redirect the planner *saw* and rejected deserves its own sentence: "no inverse
            // is modelled" reads like a gap in the port's ambition, when the real reason is
            // that the target was not a name the capture could trust.
            None if command.redirect.is_some() => out.unundoable.push(Unundoable {
                command: finding.command.clone(),
                why: format!(
                    "redirects to {:?}, which is not a plain absolute path — a relative name, a                      glob or a `$variable` names a file this capture cannot identify, so no                      snapshot was taken and this change stays after the session ends",
                    command.redirect.as_deref().unwrap_or("")
                ),
                kind: UnundoableKind::IndeterminateTarget,
            }),
            None => {
                // The dispatcher tables answer this before the planner falls back to admitting
                // it has no model. Getting the two apart is the point: `input tap` does not
                // "leave a change behind" that the session failed to clean, and saying so would
                // teach the operator to distrust every line in the teardown.
                let (kind, why) = irreversible(
                    command.words.first().map(String::as_str).unwrap_or(""),
                    subcommand(&command.words),
                )
                .unwrap_or_else(|| {
                    (
                        UnundoableKind::NotModelled,
                        format!(
                            "{} — this port has no inverse modelled for it yet, so the change \
                             stays after the session ends",
                            finding.detail
                        ),
                    )
                });
                out.unundoable.push(Unundoable {
                    command: finding.command.clone(),
                    why,
                    kind,
                })
            }
        }
    }
    out
}

impl Capture {
    /// The known reversible writes, matched on their argument vectors.
    ///
    /// Arity is checked rather than assumed: `setprop` with one argument is a malformed command
    /// the shell will reject, and planning an undo for it would record a value the write never
    /// replaced. `settings` is dispatching on its subcommand, exactly as the classifier does.
    fn from_args(args: &[String], _finding: &Finding) -> Option<Capture> {
        let head = args.first()?.as_str();
        match (head, args.get(1).map(String::as_str)) {
            ("setprop", Some(key)) if args.len() == 3 => Some(Capture {
                target: UndoTarget::Prop(key.to_string()),
                read: format!("getprop {}", quote_posix(key)),
                writing: Writing::Set(args[2].clone()),
                persists_reboot: key.starts_with("persist."),
            }),
            ("settings", Some("put")) if args.len() == 5 => Some(Capture {
                target: UndoTarget::Setting {
                    table: args[2].to_string(),
                    key: args[3].to_string(),
                },
                read: format!(
                    "settings get {} {}",
                    quote_posix(&args[2]),
                    quote_posix(&args[3])
                ),
                writing: Writing::Set(args[4].clone()),
                persists_reboot: true, // `settings` writes are persisted by the provider
            }),
            ("settings", Some("delete")) if args.len() == 4 => Some(Capture {
                target: UndoTarget::Setting {
                    table: args[2].to_string(),
                    key: args[3].to_string(),
                },
                read: format!(
                    "settings get {} {}",
                    quote_posix(&args[2]),
                    quote_posix(&args[3])
                ),
                writing: Writing::Delete,
                persists_reboot: true,
            }),
            ("setenforce", Some(mode)) if args.len() == 2 && matches!(mode, "0" | "1") => {
                Some(Capture {
                    target: UndoTarget::SelinuxMode,
                    read: "getenforce".to_string(),
                    writing: Writing::Set(mode.to_string()),
                    // The mode is not persisted by `setenforce` itself — it is reset by the
                    // next boot from the kernel command line — so leaving it is a live-state
                    // change, not a durable one. Still worth saying in the teardown.
                    persists_reboot: false,
                })
            }
            // `pm set-install-location` is a Settings write wearing a package-manager uniform.
            // The table is not a guess: driving it on BLA-AL00 produced a SecurityException whose
            // stack runs through `SettingsProvider.insertGlobalSetting`, and the row reads back
            // as `global/install_location`. That is also the reason the arm below can be *right*
            // while the command still does nothing on this phone — the shell uid (2000) is
            // refused ("Package android does not belong to 2000"), the write fails, and a failed
            // write records no undo. The row itself round-trips, which is what this mapping is
            // for; inventing a second target type for a Settings row would duplicate a path that
            // already works.
            ("pm", Some("set-install-location"))
                if args.len() == 3
                    && matches!(
                        args[2].as_str(),
                        "0" | "1" | "2" | "auto" | "internal" | "external"
                    ) =>
            {
                Some(Capture {
                    target: UndoTarget::Setting {
                        table: "global".to_string(),
                        key: "install_location".to_string(),
                    },
                    read: "settings get global install_location".to_string(),
                    writing: Writing::Set(args[2].to_string()),
                    persists_reboot: true,
                })
            }
            // An install whose package the command itself names. Without `--pkg` the name is
            // inside the APK, so this arm deliberately does not fire and the write is reported
            // as IndeterminateTarget rather than planned against a guessed package.
            ("pm", Some("install")) => {
                let name = flag_value(args, "--pkg").filter(|n| is_package_name(n))?;
                Some(Capture {
                    target: UndoTarget::Package(name.to_string()),
                    // Absence has to be a *successful* read, not a non-zero exit: `pm path` on a
                    // package that is not installed prints nothing and exits 1, and an
                    // unenveloped read would be treated as "pre-state not observed" — which
                    // means no undo, for the one case where an undo exists.
                    read: format!(
                        "pm path {} 2>/dev/null | grep -q . && printf 'PRESENT\\n' || printf \
                         'ABSENT\\n'",
                        quote_posix(name)
                    ),
                    writing: Writing::Unknown,
                    persists_reboot: true,
                })
            }
            _ => None,
        }
    }
}

/// The pre-state, as observed by the backend.
///
/// An enum rather than a `String` because "what was there before" is not always a printable
/// value, and the difference matters to the decision: a property whose `getprop` came back
/// empty was *unset*, a file that is missing is *absent*, and a file that exists but cannot be
/// read is neither — it is a change the port cannot undo, and it has to be said out loud.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PreState {
    /// The stdout of a value read, verbatim.
    Value(String),
    /// What a file capture found.
    File(FilePreState),
    /// What a package capture found.
    Package(PackagePreState),
}

/// Whether the package was installed when the capture ran.
///
/// Deliberately thinner than [`FilePreState`]: there is no content to snapshot here, so the
/// only thing worth knowing is whether the write created the package or replaced one that
/// already existed. That single bit decides whether an inverse exists at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PackagePreState {
    /// Not installed. The inverse is removing what the install creates.
    Absent,
    /// Already installed — so the write is a reinstall or an update, and the binary it
    /// replaced is not kept anywhere the port can reach.
    Present,
    /// The presence probe did not print the envelope. Treated as "not observed".
    Unknown(String),
}

/// What a file capture found, and what was done about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FilePreState {
    /// Nothing was there. The inverse is removing what the write creates.
    Absent,
    /// Content was read and is now in the snapshot store.
    Present {
        /// Bytes on the device before the write.
        bytes: u64,
        /// `sha256` the device reported for those bytes.
        digest: String,
        /// Where the host copy lives.
        snapshot: PathBuf,
    },
    /// A file exists but is larger than [`SNAPSHOT_BUDGET_BYTES`].
    ///
    /// Deliberately not "snapshot the first 64 KiB": a restore that truncates is a *second*
    /// unapproved change, and the one thing a backup must never be is almost-right.
    TooBig {
        /// What the file actually measured.
        bytes: u64,
    },
    /// A path exists that this shell cannot read — a directory, or someone else's file.
    Unreadable,
    /// The content was readable but the workspace write failed.
    ///
    /// Its own state because the reason reaches the teardown log: "could not read your file"
    /// and "could not keep a copy of it" are different problems for different people.
    NotSaved {
        /// What the filesystem said.
        reason: String,
    },
}

/// What became of one capture once the pre-state was read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UndoResult {
    /// Remember this, and run it at teardown.
    Undo(Undo),
    /// The write would not have changed anything, so there is nothing to undo. Carries the
    /// reason for the teardown log.
    NothingToUndo(String),
    /// A change we cannot put back, discovered only once the pre-state was in hand. The
    /// planner cannot have known: `setenforce 1` is undoable on an enforcing device and not on
    /// one whose SELinux is disabled, and only the device knows which it is.
    CannotUndo {
        /// Whether the reason is a fact about the command or a gap in this port.
        kind: UnundoableKind,
        /// What could not be put back, and why. Reaches the node, not the wire.
        why: String,
    },
}

/// Turn a captured pre-state into the inverse, or explain why there is none.
///
/// `observed` is the capture read's stdout, or `None` when that read failed. Failure is
/// [`UndoResult::CannotUndo`] rather than a guess: an undo built on a value nobody read is a
/// *new* write wearing a rollback's name, and it is the kind of thing that turns a failed
/// experiment into a silent two-command incident.
pub fn undo_for(
    capture: &Capture,
    observed: Option<PreState>,
    request: &ExecRequest,
) -> UndoResult {
    // A file answers a different question from a property: its inverse is bytes, not a value,
    // and the bytes are already in the snapshot store by the time this runs.
    if let UndoTarget::File(path) = &capture.target {
        return undo_for_file(capture, path, observed, request);
    }
    if matches!(capture.target, UndoTarget::Package(_)) {
        return undo_for_package(capture, observed, request);
    }

    let Some(raw) = (match observed {
        Some(PreState::Value(value)) => Some(value),
        // A `File` pre-state against a non-file capture means the backend and the planner
        // disagree about what the target is. Refusing is the only honest reading.
        Some(PreState::File(_) | PreState::Package(_)) | None => None,
    }) else {
        return UndoResult::CannotUndo {
            kind: UnundoableKind::Unobserved,
            why: format!(
                "{}: the pre-state read (`{}`) did not return a value, and restoring to a value \
             that was never observed would be a new change, not a rollback",
                capture.target.describe(),
                capture.read
            ),
        };
    };
    let current = raw.trim();

    match (&capture.target, &capture.writing) {
        (UndoTarget::Prop(key), Writing::Set(next)) => {
            // `getprop` prints an empty line for both an unset prop and a prop set to empty,
            // and Android has no way to distinguish them afterwards either. The undo is real
            // but approximate, and `faithful` is where that is recorded.
            if current == next.as_str() {
                return UndoResult::NothingToUndo(format!(
                    "{} already holds {next:?}; nothing to undo",
                    capture.target.describe()
                ));
            }
            UndoResult::Undo(Undo {
                session_id: request.session_id.clone(),
                target: capture.target.clone(),
                action: UndoAction::Script(format!(
                    "setprop {} {}",
                    quote_posix(key),
                    quote_posix(current)
                )),
                old_value: current.to_string(),
                faithful: !current.is_empty(),
                persists_reboot: capture.persists_reboot,
                capability: request
                    .android_capability()
                    .unwrap_or(Capability::ShellWrite),
                token: request.approval_token.clone(),
            })
        }
        (UndoTarget::Setting { table, key }, writing) => {
            // `settings get` prints the literal string `null` for an absent row — a real value
            // that must not be confused with a row whose value happens to be the word "null".
            let absent = current == "null";
            let next_is_delete = matches!(writing, Writing::Delete);
            if absent && next_is_delete {
                return UndoResult::NothingToUndo(format!(
                    "{} is already unset; nothing to undo",
                    capture.target.describe()
                ));
            }
            if let Writing::Set(next) = writing
                && !absent
                && current == next.as_str()
            {
                return UndoResult::NothingToUndo(format!(
                    "{} already holds {next:?}; nothing to undo",
                    capture.target.describe()
                ));
            }
            let action = UndoAction::Script(if absent {
                format!(
                    "settings delete {} {}",
                    quote_posix(table),
                    quote_posix(key)
                )
            } else {
                format!(
                    "settings put {} {} {}",
                    quote_posix(table),
                    quote_posix(key),
                    quote_posix(current)
                )
            });
            UndoResult::Undo(Undo {
                session_id: request.session_id.clone(),
                target: capture.target.clone(),
                action,
                old_value: current.to_string(),
                // Putting a row back is exact; the delete branch is exact too, since `null`
                // really did mean absent.
                faithful: true,
                persists_reboot: capture.persists_reboot,
                capability: request
                    .android_capability()
                    .unwrap_or(Capability::ShellWrite),
                token: request.approval_token.clone(),
            })
        }
        (UndoTarget::SelinuxMode, Writing::Set(mode)) => {
            let want_permissive = *mode == "0";
            match current {
                // Already in the state the write would produce. Note this is the *only* case
                // where a session ends up permissive without an undo recorded for it, so the
                // teardown can still say which it was: "nothing to undo" or "no undo possible".
                "Permissive" if want_permissive => UndoResult::NothingToUndo(
                    "SELinux is already permissive; this write changes nothing and needs no undo"
                        .to_string(),
                ),
                "Enforcing" if !want_permissive => UndoResult::NothingToUndo(
                    "SELinux is already enforcing; this write changes nothing and needs no undo"
                        .to_string(),
                ),
                // A disabled SELinux is set at boot, from the kernel command line or by a
                // permissive build. `setenforce` cannot re-disable it, and no script on this
                // device can — so the promise to put things back is one this port must not make.
                "Disabled" => UndoResult::CannotUndo {
                    kind: UnundoableKind::NoRestorableState,
                    why:
                        "SELinux is *disabled* on this device, not enforcing; `setenforce` cannot \
                     restore a disabled state (it is set at boot), so this change cannot be \
                     undone from the shell"
                            .to_string(),
                },
                _ => UndoResult::Undo(Undo {
                    session_id: request.session_id.clone(),
                    target: capture.target.clone(),
                    action: UndoAction::Script(format!(
                        "setenforce {}",
                        if want_permissive { "1" } else { "0" }
                    )),
                    old_value: current.to_string(),
                    faithful: true,
                    persists_reboot: capture.persists_reboot,
                    capability: request
                        .android_capability()
                        .unwrap_or(Capability::SelinuxPermissive),
                    token: request.approval_token.clone(),
                }),
            }
        }
        // Unreachable by construction — `undo_for` dispatches on the target before this match.
        // Kept as a refusal rather than an unreachable! because the cost of being wrong about
        // that is a device left in a state nobody can name.
        // Both dispatched above; reaching either here means the backend and the planner
        // disagree about the target, which is refused rather than guessed at.
        (UndoTarget::File(_) | UndoTarget::Package(_), _) => UndoResult::CannotUndo {
            kind: UnundoableKind::IndeterminateTarget,
            why: "a file capture reached the value branch of the undo builder".to_string(),
        },
        (target, Writing::Unknown) => UndoResult::CannotUndo {
            kind: UnundoableKind::NotModelled,
            why: format!(
                "{}: the write's new value is not knowable in advance and no snapshot was taken",
                target.describe()
            ),
        },
        (target, Writing::Delete) => UndoResult::CannotUndo {
            kind: UnundoableKind::NotModelled,
            why: format!(
                "{}: no delete-inverse is modelled for this target",
                target.describe()
            ),
        },
    }
}

/// The file case of [`undo_for`].
///
/// Note what is *not* here: no `NothingToUndo`. A redirect's new content is not knowable
/// before the command runs, so there is no comparison to make and no way to claim the write
/// changed nothing. Every successful file write therefore records something to put back.
fn undo_for_package(
    capture: &Capture,
    observed: Option<PreState>,
    request: &ExecRequest,
) -> UndoResult {
    let UndoTarget::Package(name) = &capture.target else {
        return UndoResult::CannotUndo {
            kind: UnundoableKind::IndeterminateTarget,
            why: "a package undo was requested for a non-package target".to_string(),
        };
    };
    match observed {
        // The package was not there before, so removing it returns the observed state.
        // Not marked faithful: the install may have granted runtime permissions, created
        // directories on shared storage or registered accounts, and none of that is undone
        // by `pm uninstall`. The package entity returns; the surroundings may not.
        Some(PreState::Package(PackagePreState::Absent)) => UndoResult::Undo(Undo {
            session_id: request.session_id.clone(),
            target: capture.target.clone(),
            action: UndoAction::Script(format!("pm uninstall {}", quote_posix(name))),
            old_value: String::new(),
            faithful: false,
            persists_reboot: capture.persists_reboot,
            capability: request
                .android_capability()
                .unwrap_or(Capability::ShellWrite),
            token: request.approval_token.clone(),
        }),
        // Already installed: this write replaced a binary the device does not keep. The
        // inverse would be "install the previous APK again", and the previous APK is not
        // something the port has — offering an undo here would mean inventing one.
        Some(PreState::Package(PackagePreState::Present)) => UndoResult::CannotUndo {
            kind: UnundoableKind::NoRestorableState,
            why: format!(
                "{} was already installed before this write. `pm install` replaced its binary, \
                 and the replaced binary is not retained anywhere this port can reach — the undo \
                 would have to be an APK the session never had",
                capture.target.describe()
            ),
        },
        Some(PreState::Package(PackagePreState::Unknown(text))) => UndoResult::CannotUndo {
            kind: UnundoableKind::Unobserved,
            why: format!(
                "the package presence probe printed {text:?}, which is not the envelope this \
                 capture expects, so nothing is known about what this install replaced"
            ),
        },
        // `None` belongs here: no pre-state observed means the presence probe never
        // answered, and an install with no observed before-state has no defensible inverse.
        other => UndoResult::CannotUndo {
            kind: UnundoableKind::Unobserved,
            why: format!(
                "a package capture was handed a pre-state that is not a package read ({other:?})"
            ),
        },
    }
}

fn undo_for_file(
    capture: &Capture,
    path: &str,
    observed: Option<PreState>,
    request: &ExecRequest,
) -> UndoResult {
    let Some(PreState::File(state)) = observed else {
        return UndoResult::CannotUndo {
            kind: UnundoableKind::Unobserved,
            why: format!(
                "file {path}: the snapshot read did not complete, so nothing is known about what \
             is at that path. Restoring a file to a state nobody observed would be a new \
             change wearing a rollback's name"
            ),
        };
    };
    let undo = |action, old_value: String, faithful: bool| {
        UndoResult::Undo(Undo {
            session_id: request.session_id.clone(),
            target: capture.target.clone(),
            action,
            old_value,
            faithful,
            persists_reboot: capture.persists_reboot,
            capability: request
                .android_capability()
                .unwrap_or(Capability::ShellWrite),
            token: request.approval_token.clone(),
        })
    };
    match state {
        FilePreState::Absent => undo(
            UndoAction::Script(format!("rm -f {}", quote_posix(path))),
            "<absent>".to_string(),
            true,
        ),
        FilePreState::Present {
            bytes,
            digest,
            snapshot,
        } => {
            let summary = format!("{bytes} bytes, sha256 {digest}");
            undo(
                UndoAction::Snapshot {
                    snapshot,
                    bytes,
                    digest,
                },
                summary,
                // The *content* is restored byte for byte and checked against the digest the
                // device itself reported. What does not come back is the modification time, and
                // for a file the write created, the inode: `rm -f` then rewriting is a different
                // file that happens to hold the same bytes. `faithful` is about the state the
                // session was found in, and that includes when it was last written.
                false,
            )
        }
        FilePreState::TooBig { bytes } => UndoResult::CannotUndo {
            kind: UnundoableKind::NoRestorableState,
            why: format!(
                "holds {bytes} bytes, over the {SNAPSHOT_BUDGET_BYTES}-byte snapshot \
             budget; a truncated backup is a second change, so nothing was saved, and this \
             write will still be there when the session ends"
            ),
        },
        FilePreState::Unreadable => UndoResult::CannotUndo {
            kind: UnundoableKind::Unobserved,
            why: format!(
                "file {path} exists but this shell cannot read it; its previous content is \
             unknown, so it cannot be put back"
            ),
        },
        FilePreState::NotSaved { reason } => UndoResult::CannotUndo {
            kind: UnundoableKind::NoRestorableState,
            why: format!("file {path} was readable but no snapshot was kept: {reason}"),
        },
    }
}

fn quote_if_empty(value: &str) -> String {
    if value.is_empty() {
        "(empty)".to_string()
    } else {
        value.to_string()
    }
}

/// The undos a device is holding on behalf of sessions that have not ended yet.
///
/// Deliberately not a `Drop`-based auto-restorer: restoring means awaiting an exec, and no
/// `Drop` implementation can do that. The node calls [`ReversibleBackend::restore`] when a
/// session closes; what this type guarantees is that the *list* survives in the meantime, and
/// that a caller can see it rather than having to trust that it is empty.
#[derive(Debug, Default)]
pub struct RollbackLedger {
    entries: Vec<Undo>,
    unundoable: BTreeMap<String, Vec<Unundoable>>,
}

impl RollbackLedger {
    /// An empty ledger.
    pub fn new() -> RollbackLedger {
        RollbackLedger::default()
    }

    /// Remember one undo.
    pub fn record(&mut self, undo: Undo) {
        self.entries.push(undo);
    }

    /// Record what a session changed that will still be changed after it ends.
    pub fn record_unundoable(&mut self, session: &str, items: &[Unundoable]) {
        if items.is_empty() {
            return;
        }
        self.unundoable
            .entry(session.to_string())
            .or_default()
            .extend(items.iter().cloned());
    }

    /// Every pending undo, in the order they were recorded.
    pub fn pending(&self) -> &[Undo] {
        &self.entries
    }

    /// This session's pending undos, oldest first.
    pub fn pending_for(&self, session: &str) -> Vec<&Undo> {
        self.entries
            .iter()
            .filter(|u| u.session_id == session)
            .collect()
    }

    /// What this session changed that cannot be put back.
    pub fn leaving_behind(&self, session: &str) -> &[Unundoable] {
        self.unundoable
            .get(session)
            .map(Vec::as_slice)
            .unwrap_or_default()
    }

    /// Remove and return one session's pending undos.
    ///
    /// Returned rather than dropped because the caller has to say what happened to them: an
    /// undo that vanishes from the ledger looks exactly like an undo that ran.
    pub(crate) fn take_session(&mut self, session: &str) -> Vec<Undo> {
        let mut taken = Vec::new();
        let mut kept = Vec::with_capacity(self.entries.len());
        for entry in std::mem::take(&mut self.entries) {
            if entry.session_id == session {
                taken.push(entry);
            } else {
                kept.push(entry);
            }
        }
        self.entries = kept;
        taken
    }

    /// Declare a change permanent — §4.6.4's 「`persist.*` 需显式声明才保留」.
    ///
    /// Returns whether anything was dropped. The declaration is an act of *not* rolling back,
    /// so it belongs on this side of the ledger: the write path does not know that the user
    /// decided to keep the value, and the teardown path is the only place that can be told.
    pub fn keep(&mut self, session: &str, target: &UndoTarget) -> bool {
        let before = self.entries.len();
        self.entries
            .retain(|u| !(u.session_id == session && &u.target == target));
        self.entries.len() != before
    }

    /// Take this session's undos out, oldest first, leaving the ledger empty for it.
    ///
    /// Draining rather than popping one at a time is what makes [`ReversibleBackend::restore`]
    /// terminate: a failed inverse is put back, and a loop that re-reads the ledger would take
    /// that same failure again forever.
    fn take_all_for(&mut self, session: &str) -> Vec<Undo> {
        let mut taken = Vec::new();
        let mut kept = Vec::new();
        for entry in std::mem::take(&mut self.entries) {
            if entry.session_id == session {
                taken.push(entry);
            } else {
                kept.push(entry);
            }
        }
        self.entries = kept;
        self.unundoable.remove(session);
        taken
    }

    /// Put a failed undo back.
    fn restore_entry(&mut self, undo: Undo) {
        self.entries.push(undo);
    }
}

/// What a teardown pass did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RestoreReport {
    /// Each target restored, in the order it was run.
    pub restored: Vec<String>,
    /// Each target that did not go back, with the reason. These are *still pending*.
    pub failed: Vec<(String, String)>,
    /// Undos left for other sessions, so a caller can tell "this session was clean" from "the
    /// ledger is not empty".
    pub still_pending_elsewhere: usize,
}

impl RestoreReport {
    /// True when nothing failed. A clean teardown with `leaving_behind` entries is still a
    /// teardown that changed something permanent, and the caller should ask the ledger.
    pub fn clean(&self) -> bool {
        self.failed.is_empty()
    }
}

/// The decorator that makes §4.6.4 true.
///
/// A decorator rather than code inside each backend for the same reason the audit trail is one:
/// three backends that each remember to capture pre-state is three chances to forget, and the
/// one backend that forgets is the one that leaves the device in a modified state after the
/// session ends. It also composes: wrap this *outside* [`crate::host::AuditedBackend`] so the
/// capture reads and the inverse writes are themselves audited records, and so a restore that
/// fails is visible in the log the node keeps.
pub struct ReversibleBackend {
    inner: Arc<dyn ExecutionBackend>,
    ledger: Arc<Mutex<RollbackLedger>>,
    /// Where file snapshots are kept. Required, not optional: a backend that cannot say where
    /// it put a backup is a backend that leaves `UndoAction::Snapshot` holding a path nobody
    /// can find.
    store: Arc<SnapshotStore>,
}

impl ReversibleBackend {
    /// Wrap a backend, keeping snapshots under `snapshot_dir`.
    ///
    /// The ledger is shared so the node can inspect it without the backend; the snapshot
    /// directory is the node's own workspace path, which §4.6.4 names as where a backup goes.
    pub fn new(
        inner: Arc<dyn ExecutionBackend>,
        snapshot_dir: impl Into<PathBuf>,
    ) -> ReversibleBackend {
        ReversibleBackend {
            inner,
            ledger: Arc::new(Mutex::new(RollbackLedger::new())),
            store: Arc::new(SnapshotStore::new(snapshot_dir)),
        }
    }

    /// Wrap a backend with a store the caller configured — a different workspace allowance, or a
    /// directory shared with another backend. `new` is the default-budget case; this is the one
    /// a node reaches for when it has decided how much of the Agent workspace backups may take.
    pub fn with_store(inner: Arc<dyn ExecutionBackend>, store: SnapshotStore) -> ReversibleBackend {
        ReversibleBackend {
            inner,
            ledger: Arc::new(Mutex::new(RollbackLedger::new())),
            store: Arc::new(store),
        }
    }

    /// Wrap a backend with a ledger and a snapshot store the caller already holds.
    pub fn with_ledger(
        inner: Arc<dyn ExecutionBackend>,
        ledger: Arc<Mutex<RollbackLedger>>,
        store: Arc<SnapshotStore>,
    ) -> ReversibleBackend {
        ReversibleBackend {
            inner,
            ledger,
            store,
        }
    }

    /// Where snapshots are kept.
    pub fn snapshots(&self) -> &SnapshotStore {
        &self.store
    }

    /// The shared ledger.
    pub fn ledger(&self) -> Arc<Mutex<RollbackLedger>> {
        Arc::clone(&self.ledger)
    }

    /// Lock the ledger.
    ///
    /// Poison is recovered rather than propagated: a panic in some unrelated command handler
    /// must not make the pending undos unreachable, because the only thing worse than a device
    /// that cannot restore a property is a device that has forgotten it needs to.
    fn ledger_mut(&self) -> std::sync::MutexGuard<'_, RollbackLedger> {
        self.ledger
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Give up on a session without touching the device.
    ///
    /// This is the path for a session that is closing without a rollback — the operator said
    /// keep it, or the node is discarding the session entirely. Two things must happen together
    /// and neither can be left to the caller: the host copies go, and the ledger says out loud
    /// that the device is still changed. An implementation that only cleared the ledger would
    /// produce the one report this module exists to prevent — an empty undo list that reads like
    /// a clean device.
    pub fn abandon(&self, session: &str) -> usize {
        let taken = self
            .ledger
            .lock()
            .map(|mut l| l.take_session(session))
            .unwrap_or_default();
        let count = taken.len();
        let mut left = Vec::with_capacity(count);
        for undo in taken {
            if let UndoAction::Snapshot { snapshot, .. } = &undo.action {
                self.store.discard(snapshot);
            }
            left.push(Unundoable {
                command: undo.target.describe(),
                why: format!(
                    "session {session} was closed without restoring, and this change was left in                      place deliberately; the undo was dropped{}",
                    if undo.persists_reboot {
                        ", and it survives a reboot"
                    } else {
                        ""
                    }
                ),
                kind: UnundoableKind::NoRestorableState,
            });
        }
        if !left.is_empty()
            && let Ok(mut l) = self.ledger.lock()
        {
            l.record_unundoable(session, &left);
        }
        count
    }

    /// Run one capture read.
    ///
    /// `None` means no pre-state was observed, which [`undo_for`] treats as "do not build an
    /// undo", not as "the value was empty".
    async fn read_pre_state(&self, capture: &Capture, session: &str) -> Option<PreState> {
        let record = self.read(&capture.read, session).await?;
        if matches!(capture.target, UndoTarget::Package(_)) {
            return Some(PreState::Package(match record.stdout.trim() {
                "PRESENT" => PackagePreState::Present,
                "ABSENT" => PackagePreState::Absent,
                other => PackagePreState::Unknown(other.to_string()),
            }));
        }
        if !matches!(capture.target, UndoTarget::File(_)) {
            return Some(PreState::Value(record.stdout));
        }

        // A file is read in two steps because the second step's cost is unknown until the
        // first one finishes. The envelope says whether there is a file at all and how big it
        // is; only then is the content fetched, and a file over the budget is refused here
        // rather than base64'd into a pipe that would have to be thrown away.
        let UndoTarget::File(_) = &capture.target else {
            unreachable!("checked above")
        };
        let state = match parse_envelope(&record.stdout) {
            Envelope::Absent => FilePreState::Absent,
            Envelope::Size(None) => FilePreState::Unreadable,
            Envelope::Unparsed(text) => FilePreState::NotSaved {
                reason: format!(
                    "the snapshot read printed {text:?}, which is not the envelope this capture \
                     expects"
                ),
            },
            Envelope::Size(Some(bytes)) if bytes > SNAPSHOT_BUDGET_BYTES => {
                FilePreState::TooBig { bytes }
            }
            Envelope::Size(Some(bytes)) => {
                let payload = self.read(&capture.content_read()?, session).await?;
                match parse_snapshot(&payload.stdout) {
                    None => FilePreState::NotSaved {
                        reason: "the content read did not come back as a digest line followed \
                                 by base64"
                            .to_string(),
                    },
                    Some((_digest, body)) if decoded_len_of_base64(&body) != bytes => {
                        // The payload decodes to a different size than the file measured. That
                        // is the output cap truncating something the budget said would fit, or
                        // transit mangling it — either way the bytes we would put back are not
                        // the bytes that are there, and a partial backup is a second change
                        // waiting to happen.
                        FilePreState::NotSaved {
                            reason: format!(
                                "the base64 read decoded to {} bytes for a {bytes}-byte file",
                                decoded_len_of_base64(&body)
                            ),
                        }
                    }
                    Some((digest, body)) => {
                        match self
                            .store
                            .save(session, &crate::host::script::next_nonce(), &body)
                        {
                            Ok(snapshot) => FilePreState::Present {
                                bytes,
                                digest,
                                snapshot,
                            },
                            Err(e) => FilePreState::NotSaved {
                                reason: format!(
                                    "the snapshot could not be written to {}: {e}",
                                    self.store.dir().display()
                                ),
                            },
                        }
                    }
                }
            }
        };
        Some(PreState::File(state))
    }

    /// One read-tier command through the inner backend. `None` on any failure, including a
    /// refusal: a capture that could not run is not evidence about the device.
    async fn read(&self, script: &str, session: &str) -> Option<ExecRecord> {
        match self
            .inner
            .exec(ExecRequest::read(script.to_string(), session))
            .await
        {
            Ok(record) if record.succeeded() => Some(record),
            _ => None,
        }
    }

    /// Roll one session back to the state it was found in. Called by the node at session end,
    /// and safe to call twice.
    pub async fn restore(&self, session: &str) -> RestoreReport {
        let mut report = RestoreReport::default();
        let taken = { self.ledger_mut().take_all_for(session) };

        // Reverse: the last change made is the first one to take back.
        for undo in taken.into_iter().rev() {
            let outcome = match &undo.action {
                UndoAction::Script(script) => self.run_write(session, &undo, script.clone()).await,
                UndoAction::Snapshot {
                    snapshot,
                    bytes,
                    digest,
                } => {
                    let payload = std::fs::read_to_string(snapshot);
                    match payload {
                        Ok(payload) => {
                            self.restore_snapshot(session, &undo, &payload, *bytes, digest)
                                .await
                        }
                        Err(e) => Err(format!(
                            "the snapshot at {} could not be read ({e}); the bytes this undo \
                             would have written are gone",
                            snapshot.display()
                        )),
                    }
                }
            };
            match outcome {
                Ok(()) => {
                    // The workspace copy has done its job. Keeping device content around after
                    // the device itself is back would leave a second, unexplained copy of it.
                    if let UndoAction::Snapshot { snapshot, .. } = &undo.action {
                        self.store.discard(snapshot);
                    }
                    report.restored.push(undo.describe());
                }
                Err(why) => {
                    // Put it back: a failed restore is still a pending change, and the whole
                    // point of the ledger is that nobody has to guess what is outstanding.
                    report.failed.push((undo.describe(), why));
                    self.ledger_mut().restore_entry(undo);
                }
            }
        }

        report.still_pending_elsewhere = self.ledger_mut().pending().len();
        report
    }

    /// Run one recorded inverse as a write.
    async fn run_write(&self, session: &str, undo: &Undo, script: String) -> Result<(), String> {
        let mut request = ExecRequest::new(undo.capability, script, session);
        request.approval_token = undo.token.clone();
        match self.inner.exec(request).await {
            Ok(record) if record.succeeded() => Ok(()),
            Ok(record) => Err(format!(
                "exit {:?}{}",
                record.exit_code,
                suffix_if_needed(&record.stderr)
            )),
            Err(e) => Err(e.to_string()),
        }
    }

    /// Put a file back from its snapshot, then prove it.
    ///
    /// The payload travels as base64 in chunks, because the device-side `printf` is an
    /// `execve` and an argument list over ~110 KiB is refused (see [`SNAPSHOT_CHUNK_BYTES`]).
    /// Chunking is only tolerable because the last step compares the restored file against the
    /// digest the device reported *before* the write: an assembly that went wrong is reported
    /// as a failure instead of silently leaving a corrupt file where a backup was supposed to
    /// go. That check is the difference between a rollback and a best-efforts write.
    async fn restore_snapshot(
        &self,
        session: &str,
        undo: &Undo,
        payload: &str,
        bytes: u64,
        digest: &str,
    ) -> Result<(), String> {
        let UndoTarget::File(path) = &undo.target else {
            return Err("a snapshot undo pointed at a non-file target".to_string());
        };
        if !is_base64(payload) {
            return Err(format!(
                "the snapshot in {} is not base64 any more; refusing to write it to {path}",
                self.store.dir().display()
            ));
        }
        let literal = quote_posix(path);
        let staged = quote_posix(&format!(
            "{SNAPSHOT_STAGING_DIR}/.acowork-snap-{}.b64",
            crate::host::script::next_nonce()
        ));

        // An empty file has no chunks to stage, and `base64 -d` of a file that was never
        // created would fail on the way to restoring a file that holds nothing. Truncate it
        // directly — the digest check below still has to agree that it is empty.
        if payload.is_empty() {
            self.run_write(session, undo, format!("printf '' > {literal}"))
                .await
                .map_err(|e| format!("restoring the empty {path}: {e}"))?;
            return self
                .verify(session, undo, path, &literal, digest, bytes)
                .await;
        }

        for (index, chunk) in payload.as_bytes().chunks(SNAPSHOT_CHUNK_BYTES).enumerate() {
            let chunk = std::str::from_utf8(chunk).map_err(|_| "snapshot chunk is not utf8")?;
            // `>` for the first chunk, `>>` for the rest: one staging file, one command per
            // chunk. Separate commands rather than a shell loop so the audit log shows how
            // many writes a restore actually made.
            let redirect = if index == 0 { ">" } else { ">>" };
            let script = format!("printf '%s' '{chunk}' {redirect} {staged}");
            if let Err(e) = self.run_write(session, undo, script).await {
                self.cleanup(session, undo, &staged).await;
                return Err(format!("while staging a snapshot chunk for {path}: {e}"));
            }
        }

        let decoded = self
            .run_write(session, undo, format!("base64 -d < {staged} > {literal}"))
            .await;
        // The staging file goes whether the decode worked: base64 of someone's file sitting in
        // /data/local/tmp is a copy nobody asked for, and it outlives this session.
        self.cleanup(session, undo, &staged).await;
        decoded.map_err(|e| format!("restoring {path}: {e}"))?;

        self.verify(session, undo, path, &literal, digest, bytes)
            .await
    }

    /// Check a restored file against the digest the device reported before the write.
    ///
    /// This is the step that makes a chunked restore safe to attempt at all. Without it, a
    /// payload that lost a chunk in transit would leave a file that looks restored, holds the
    /// wrong bytes, and has a rollback ledger claiming otherwise.
    async fn verify(
        &self,
        session: &str,
        _undo: &Undo,
        path: &str,
        literal: &str,
        digest: &str,
        bytes: u64,
    ) -> Result<(), String> {
        // Prove it. `sha256sum` is read-tier, so this costs a read and no approval.
        let record = self
            .read(&format!("sha256sum < {literal}"), session)
            .await
            .ok_or_else(|| {
                format!(
                    "{path} was written but cannot be read back to check it, so the restore is \
                     unverified; the snapshot is kept in {}",
                    self.store.dir().display()
                )
            })?;
        let observed = record
            .stdout
            .split_whitespace()
            .next()
            .unwrap_or("")
            .to_ascii_lowercase();
        if observed != digest.to_ascii_lowercase() {
            return Err(format!(
                "{path} was rewritten but its digest is {observed:?}, not {digest:?}: the file \
                 does *not* hold the {bytes} bytes this session found. The snapshot is kept in {}",
                self.store.dir().display()
            ));
        }
        Ok(())
    }

    /// Remove a staging file, ignoring the outcome. Nothing a caller can do about it, and a
    /// failure must not be reported as "the device was not restored".
    async fn cleanup(&self, session: &str, undo: &Undo, staged: &str) {
        let _ = self
            .run_write(session, undo, format!("rm -f {staged}"))
            .await;
    }
}

/// What a file capture's first read printed.
enum Envelope {
    /// Nothing is at the path.
    Absent,
    /// Something is there and this is its size in bytes. `None` is "there, but this shell
    /// cannot measure it" — a directory, or someone else's file.
    Size(Option<u64>),
    /// The read succeeded and printed something that is not the envelope. A protocol mismatch
    /// is not the same fact as "unreadable", and reporting it as one would send whoever reads
    /// the log looking at file permissions instead of at this code.
    Unparsed(String),
}

/// Parse the envelope [`Capture::read`] prints.
fn parse_envelope(stdout: &str) -> Envelope {
    let mut lines = stdout.lines();
    match lines.next().map(str::trim) {
        Some("ABSENT") => Envelope::Absent,
        Some("PRESENT") => match lines.next().and_then(|l| l.trim().parse().ok()) {
            Some(bytes) => Envelope::Size(Some(bytes)),
            None => Envelope::Size(None),
        },
        Some(other) => Envelope::Unparsed(other.to_string()),
        None => Envelope::Unparsed(String::new()),
    }
}

/// Parse a snapshot read: `<sha256>  -` on the first line, then the base64 body.
///
/// `None` means the text is not what the capture protocol promises. The body comes back owned
/// because it is a whitespace-stripped copy of a capped stdout; borrowing the input instead
/// would mean keeping the whole read alive for a payload that is at most ~88 KiB.
fn parse_snapshot(stdout: &str) -> Option<(String, String)> {
    let (digest_line, rest) = stdout.split_once('\n')?;
    let digest = digest_line.split_whitespace().next()?;
    if digest.len() != 64 || !digest.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let body: String = rest.chars().filter(|c| !c.is_whitespace()).collect();
    if !is_base64(&body) {
        return None;
    }
    Some((digest.to_ascii_lowercase(), body))
}

/// How many file bytes a base64 payload decodes to.
///
/// The exact inverse of the encoder: four characters carry three bytes, less the padding.
/// Compared against the size the *device* reported, this is what catches a payload truncated
/// by the output cap — the one failure mode where a snapshot would otherwise be quietly short
/// and the ledger would still describe it as a backup.
fn decoded_len_of_base64(body: &str) -> u64 {
    body.trim_end_matches('=').len() as u64 * 3 / 4
}

/// True for the base64 alphabet and nothing else, including no whitespace.
///
/// The empty string qualifies: it is what an empty file encodes to, and "the file was there and
/// held nothing" is a state worth putting back.
fn is_base64(text: &str) -> bool {
    text.len().is_multiple_of(4)
        && text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
}

fn suffix_if_needed(stderr: &str) -> String {
    let trimmed = stderr.trim();
    if trimmed.is_empty() {
        String::new()
    } else {
        format!(": {}", trimmed.chars().take(200).collect::<String>())
    }
}

#[async_trait::async_trait]
impl ExecutionBackend for ReversibleBackend {
    fn name(&self) -> &'static str {
        self.inner.name()
    }

    fn dialect(&self) -> Option<ShellDialect> {
        self.inner.dialect()
    }

    fn profile(&self) -> &HostProfile {
        self.inner.profile()
    }

    async fn exec(&self, request: ExecRequest) -> Result<ExecRecord, BackendError> {
        let planned = plan(&request.script);
        if planned.is_empty() {
            return self.inner.exec(request).await;
        }

        let session = request.session_id.clone();

        // Before the write, while nothing has happened yet. Every capture goes through the
        // inner backend as a read-tier request, which is what makes it safe to issue here: the
        // §4.4 rule that auto-passes `getprop` is the same rule that would refuse it if the
        // planner ever invented a capture that was not a read.
        let mut captured: Vec<(Capture, Option<PreState>)> =
            Vec::with_capacity(planned.captures.len());
        for capture in &planned.captures {
            let observed = self.read_pre_state(capture, &session).await;
            captured.push((capture.clone(), observed));
        }

        let record = self.inner.exec(request.clone()).await?;

        // Only a write that happened needs putting back. A refused or failing command is
        // recorded as nothing at all — and the *reasons* the planner could not model are still
        // recorded, because those describe the device as it now is.
        if record.succeeded() {
            let mut ledger = self.ledger_mut();
            ledger.record_unundoable(&session, &planned.unundoable);
            for (capture, observed) in captured {
                match undo_for(&capture, observed, &request) {
                    UndoResult::Undo(undo) => ledger.record(undo),
                    // Both of these are the teardown's business, not the caller's: "nothing to
                    // undo" and "no undo possible" read the same in a log and mean opposite
                    // things to whoever is deciding whether to trust this session's cleanup.
                    UndoResult::NothingToUndo(why) => {
                        ledger.record_unundoable(
                            &session,
                            &[Unundoable {
                                command: capture.target.describe(),
                                why,
                                kind: UnundoableKind::NoChange,
                            }],
                        );
                    }
                    UndoResult::CannotUndo { kind, why } => {
                        ledger.record_unundoable(
                            &session,
                            &[Unundoable {
                                command: capture.target.describe(),
                                why,
                                kind,
                            }],
                        );
                    }
                }
            }
        }

        Ok(record)
    }
}

impl std::fmt::Debug for ReversibleBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let pending = self
            .ledger
            .lock()
            .map(|l| l.pending().len())
            .unwrap_or_else(|poisoned| poisoned.into_inner().pending().len());
        f.debug_struct("ReversibleBackend")
            .field("inner", &self.inner.name())
            .field("pending", &pending)
            .finish()
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    /// A fresh directory per call, so a test that writes a snapshot cannot read another's.
    fn snapshot_dir() -> PathBuf {
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        std::env::temp_dir().join(format!("acowork-snapshot-test-{}-{n}", std::process::id()))
    }
    use crate::host::probe::ProbeOutput;
    use acowork_platform_contract::HostCapability;
    use std::sync::Mutex;

    /// One request as the fake backend saw it.
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct Seen {
        capability: String,
        script: String,
        approved: bool,
    }

    /// A backend that answers by exact script match and remembers the whole sequence.
    ///
    /// The sequence is the point: §4.6.4's guarantee is an *ordering* guarantee (read before
    /// write, restore in reverse), and a fake that only returned canned values could not fail
    /// an ordering test.
    struct Fake {
        profile: HostProfile,
        answers: Vec<(String, String, i32)>,
        seen: Mutex<Vec<Seen>>,
    }

    impl Fake {
        fn answering(answers: &[(&str, &str)]) -> Arc<Fake> {
            Arc::new(Fake {
                profile: HostProfile::assemble(&ProbeOutput::nothing_ran(), "com.example.agent"),
                answers: answers
                    .iter()
                    .map(|(s, o)| (s.to_string(), o.to_string(), 0))
                    .collect(),
                seen: Mutex::new(Vec::new()),
            })
        }

        /// A backend where the script named `fail` exits 1.
        fn with_failing(fail: &str, answers: &[(&str, &str)]) -> Arc<Fake> {
            Arc::new(Fake {
                profile: HostProfile::assemble(&ProbeOutput::nothing_ran(), "com.example.agent"),
                answers: std::iter::once((fail.to_string(), String::new(), 1))
                    .chain(
                        answers
                            .iter()
                            .map(|(s, o)| (s.to_string(), o.to_string(), 0)),
                    )
                    .collect(),
                seen: Mutex::new(Vec::new()),
            })
        }

        fn sequence(&self) -> Vec<Seen> {
            self.seen.lock().unwrap().clone()
        }
    }

    #[async_trait::async_trait]
    impl ExecutionBackend for Fake {
        fn name(&self) -> &'static str {
            "fake(shell)"
        }

        fn dialect(&self) -> Option<ShellDialect> {
            Some(ShellDialect::MkSh)
        }

        fn profile(&self) -> &HostProfile {
            &self.profile
        }

        async fn exec(&self, request: ExecRequest) -> Result<ExecRecord, BackendError> {
            self.seen.lock().unwrap().push(Seen {
                capability: request.capability.as_str().to_string(),
                script: request.script.clone(),
                approved: request.approval_token.is_some(),
            });
            let (stdout, code) = self
                .answers
                .iter()
                .find(|(s, _, _)| *s == request.script)
                .map(|(_, o, c)| (o.clone(), *c))
                .unwrap_or_default();
            Ok(ExecRecord {
                stdout,
                stderr: if code == 0 {
                    String::new()
                } else {
                    "setprop: failed to set property".to_string()
                },
                exit_code: Some(code),
                selinux_denials: Vec::new(),
                uid: Some(2000),
                context: Some("u:r:shell:s0".to_string()),
                duration_ms: 12,
                truncated: false,
                timed_out: false,
            })
        }
    }

    /// The refusal text, for assertions that care about both the category and the sentence.
    fn result_why(result: &UndoResult) -> String {
        match result {
            UndoResult::CannotUndo { why, .. } => why.clone(),
            UndoResult::NothingToUndo(why) => why.clone(),
            other => format!("{other:?}"),
        }
    }

    fn write_request(script: &str, capability: Capability) -> ExecRequest {
        let mut request = ExecRequest::new(capability, script, "session-alpha");
        request.approval_token = Some(ApprovalToken::new("tok-1"));
        request
    }

    fn request_for(script: &str) -> ExecRequest {
        write_request(script, Capability::ShellWrite)
    }

    // ── the planner ──────────────────────────────────────────────────────────

    #[test]
    fn the_planner_names_the_read_each_write_needs_first() {
        let planned = plan("setprop debug.stagefright.ccodec 1");
        assert_eq!(planned.captures.len(), 1);
        let capture = &planned.captures[0];
        assert_eq!(
            capture.target,
            UndoTarget::Prop("debug.stagefright.ccodec".into())
        );
        assert_eq!(capture.read, "getprop 'debug.stagefright.ccodec'");
        assert_eq!(capture.writing, Writing::Set("1".to_string()));
        assert!(!capture.persists_reboot);

        // `settings` dispatches on its subcommand, and so does the planner — but the delete
        // branch needs the pre-state too, because its inverse is putting back what was there.
        let planned = plan("settings put system airplane_mode_on 0");
        assert_eq!(
            planned.captures[0].read,
            "settings get 'system' 'airplane_mode_on'"
        );
        let planned = plan("settings delete system font_scale");
        assert_eq!(planned.captures[0].writing, Writing::Delete);
        assert_eq!(
            planned.captures[0].read,
            "settings get 'system' 'font_scale'"
        );

        let planned = plan("setenforce 0");
        assert_eq!(planned.captures[0].target, UndoTarget::SelinuxMode);
        assert_eq!(planned.captures[0].read, "getenforce");
    }

    #[test]
    fn a_persist_property_is_flagged_because_it_outlives_the_session() {
        // §4.6.4's 「`persist.*` 需显式声明才保留」 only means something if the ledger can tell
        // a persist prop from any other: the change is still there after a reboot whether or
        // not anyone restores it, so "we rolled the session back" is a different claim here.
        let planned = plan("setprop persist.sys.demo 1");
        assert!(planned.captures[0].persists_reboot);
        assert!(!plan("setprop debug.foo 1").captures[0].persists_reboot);
    }

    #[test]
    fn a_write_with_no_inverse_is_reported_rather_than_left_out() {
        let planned = plan("am broadcast -a android.intent.action.BOOT_COMPLETED");
        assert!(planned.captures.is_empty());
        assert_eq!(planned.unundoable.len(), 1);
        assert_eq!(planned.unundoable[0].command, "am broadcast");
        // This one is *not* a gap in the port, and the old message said it was. A broadcast is
        // an event: there is no previous value to put back. Saying "no inverse is modelled, so
        // this change stays after the session ends" describes a change that was never made and
        // admits a gap that does not exist.
        assert_eq!(planned.unundoable[0].kind, UnundoableKind::NotAStateChange);
        assert!(
            planned.unundoable[0]
                .why
                .contains("nothing here to restore"),
            "{:?}",
            planned.unundoable[0]
        );
        assert!(
            !planned.unundoable[0]
                .why
                .contains("stays after the session"),
            "an event must not be reported as a leftover change: {:?}",
            planned.unundoable[0]
        );

        // A file write is §4.6.4's *other* promise — back it up and offer `restore`. It is now
        // kept for a plain absolute path, so this asserts the capture exists rather than that
        // it does not, and pairs it with the two file writes that still cannot be modelled.
        let planned = plan("echo note > /data/local/tmp/note.txt");
        assert_eq!(planned.captures.len(), 1, "{:?}", planned.captures);
        assert_eq!(
            planned.captures[0].target,
            UndoTarget::File("/data/local/tmp/note.txt".to_string())
        );
        assert!(planned.unundoable.is_empty());

        // A relative target names a file only in the context of the write's working directory,
        // which the capture does not share. Refusing is the honest answer; guessing is the one
        // that restores the wrong file.
        let planned = plan("echo note > ./note.txt");
        assert!(planned.captures.is_empty());
        assert_eq!(planned.unundoable.len(), 1);
        assert!(
            planned.unundoable[0]
                .why
                .contains("not a plain absolute path"),
            "{:?}",
            planned.unundoable[0]
        );

        // `rm` deletes a file the script never redirected into: the content is gone by the time
        // the planner looks, and no capture could have run sooner than the command itself.
        let planned = plan("rm -f /data/local/tmp/note.txt");
        assert!(planned.captures.is_empty());
        assert_eq!(planned.unundoable.len(), 1);
        assert_eq!(planned.unundoable[0].command, "rm");
    }

    #[test]
    fn a_script_it_cannot_split_is_called_blind_not_clean() {
        // The distinction this exists to keep: `captures.is_empty()` after a parse failure
        // would tell the node "nothing to restore" about a script that may have reflashed a
        // partition. Backgrounding is the cheapest unanalysable script to write.
        let planned = plan("setprop persist.sys.demo 1 &");
        assert!(planned.captures.is_empty());
        assert_eq!(planned.unundoable.len(), 1);
        assert!(
            planned.unundoable[0].why.contains("could not be split"),
            "{:?}",
            planned.unundoable[0]
        );
        assert!(!planned.is_empty(), "blind is not the same as empty");

        // And a genuine read really is empty, so the two are not conflated in the other
        // direction either.
        assert!(plan("getprop ro.build.type").is_empty());
    }

    // ── building one undo ────────────────────────────────────────────────────

    /// Plan a script, check the read the planner chose, and build the undo from the value the
    /// test says the device reported. The middle check is not decoration: every caller-side
    /// test below is about a *value*, and it only means something if it is the value the
    /// planner's own read would have produced.
    fn undo_of(script: &str, read: &str, observed: Option<&str>) -> UndoResult {
        let planned = plan(script);
        let capture = planned
            .captures
            .first()
            .unwrap_or_else(|| panic!("{} plans no capture", script));
        assert_eq!(
            capture.read, read,
            "the planner's read is not what the test assumed"
        );
        // The request is labelled with the capability the classifier names for the script,
        // which is what a caller that got through the gate must have claimed. `setenforce 0`
        // is the case where that is not `shell:write`, and the undo has to carry whichever it
        // was — a restore asking for the wrong tier is a restore that gets refused.
        let claimed = commands::classify(script)
            .strongest()
            .capability()
            .unwrap_or(Capability::ShellWrite);
        undo_for(
            capture,
            observed.map(|value| PreState::Value(value.to_string())),
            &write_request(script, claimed),
        )
    }

    #[test]
    fn the_undo_restores_the_value_that_was_actually_there() {
        let UndoResult::Undo(undo) = undo_of(
            "setprop debug.stagefright.ccodec 1",
            "getprop 'debug.stagefright.ccodec'",
            Some("0\n"),
        ) else {
            panic!("expected an undo");
        };
        assert_eq!(
            undo.inverse_script().unwrap(),
            "setprop 'debug.stagefright.ccodec' '0'"
        );
        assert_eq!(undo.old_value, "0");
        assert!(undo.faithful);
        assert_eq!(undo.session_id, "session-alpha");
        assert_eq!(undo.capability, Capability::ShellWrite);
        assert!(undo.token.is_some(), "the approval travels with the undo");
    }

    #[test]
    fn an_unreadable_pre_state_refuses_to_become_a_rollback() {
        // The failure this guards: `getprop` fails (SELinux, transport, a killed adb) and the
        // planner invents an empty old value, so the teardown writes `setprop k ''` over a
        // value that was there all along. That is a second, unapproved change.
        let result = undo_of("setprop debug.foo 1", "getprop 'debug.foo'", None);
        assert!(
            matches!(
                &result,
                UndoResult::CannotUndo {
                    kind: UnundoableKind::Unobserved,
                    ..
                } if result_why(&result).contains("never observed")
            ),
            "{result:?}"
        );
    }

    #[test]
    fn a_write_that_changes_nothing_records_nothing() {
        let result = undo_of("setprop debug.foo 1", "getprop 'debug.foo'", Some("1"));
        assert!(
            matches!(
                &result,
                UndoResult::NothingToUndo(why) if why.contains("already holds")
            ),
            "{result:?}"
        );
    }

    #[test]
    fn an_unset_property_comes_back_empty_and_says_it_is_approximate() {
        // Android has no "unset a non-persist prop". The closest inverse leaves the key
        // present with an empty value, which `getprop` prints identically and `/prop` does
        // not. Saying `faithful: false` is what lets a teardown log admit that.
        let UndoResult::Undo(undo) =
            undo_of("setprop debug.foo 1", "getprop 'debug.foo'", Some(""))
        else {
            panic!("expected an undo");
        };
        assert_eq!(undo.inverse_script().unwrap(), "setprop 'debug.foo' ''");
        assert!(!undo.faithful);
        assert!(
            undo.describe().contains("approximate"),
            "{}",
            undo.describe()
        );
    }

    #[test]
    fn a_settings_row_that_was_absent_comes_back_as_a_delete() {
        // `settings get` prints the literal `null` for an absent row. Treating that as a value
        // would restore a row as the four-character string "null" — a setting the platform
        // reads as a parse failure rather than as absent.
        let UndoResult::Undo(undo) = undo_of(
            "settings put system font_scale 1.5",
            "settings get 'system' 'font_scale'",
            Some("null\n"),
        ) else {
            panic!("expected an undo");
        };
        assert_eq!(
            undo.inverse_script().unwrap(),
            "settings delete 'system' 'font_scale'"
        );
        assert!(undo.faithful, "delete is the exact inverse of absent");

        // And a present row comes back with its value quoted, not interpolated.
        let UndoResult::Undo(undo) = undo_of(
            "settings put system font_scale 1.5",
            "settings get 'system' 'font_scale'",
            Some("1.0\n"),
        ) else {
            panic!("expected an undo");
        };
        assert_eq!(
            undo.inverse_script().unwrap(),
            "settings put 'system' 'font_scale' '1.0'"
        );
    }

    #[test]
    fn a_value_that_needs_quoting_is_quoted_rather_than_embedded() {
        // A prop value with a space or an apostrophe is the case where naive interpolation
        // produces a script that runs *something else* at teardown. `quote_posix` is the same
        // function the script builder uses, so the two cannot disagree about quoting.
        let UndoResult::Undo(undo) = undo_of(
            "setprop debug.foo new",
            "getprop 'debug.foo'",
            Some("a b'c\n"),
        ) else {
            panic!("expected an undo");
        };
        assert_eq!(
            undo.inverse_script().unwrap(),
            "setprop 'debug.foo' 'a b'\\''c'"
        );
        // Round-trips through the classifier as one command over two arguments.
        assert_eq!(
            commands::words(undo.inverse_script().unwrap()),
            Some(vec![vec![
                "setprop".to_string(),
                "debug.foo".to_string(),
                "a b'c".to_string()
            ]])
        );
    }

    #[test]
    fn setenforce_records_the_mode_that_was_in_force() {
        let UndoResult::Undo(undo) = undo_of("setenforce 0", "getenforce", Some("Enforcing\n"))
        else {
            panic!("expected an undo");
        };
        assert_eq!(undo.inverse_script().unwrap(), "setenforce 1");
        assert_eq!(undo.capability, Capability::SelinuxPermissive);
        assert_eq!(undo.old_value, "Enforcing");

        // The promise in `denial.rs` — "restored automatically at session end" — is this line.
        // Before this module it was a sentence with no mechanism behind it.
    }

    #[test]
    fn a_disabled_selinux_cannot_be_put_back_and_says_so() {
        // `setenforce` toggles enforcing/permissive. A *disabled* SELinux is a boot-time
        // property, so on such a device the undo this module promises does not exist, and the
        // honest answer is to refuse to record one rather than to run `setenforce 1` and report
        // success while the kernel stays permissive.
        let result = undo_of("setenforce 0", "getenforce", Some("Disabled\n"));
        assert!(
            matches!(
                &result,
                UndoResult::CannotUndo {
                    kind: UnundoableKind::NoRestorableState,
                    ..
                } if result_why(&result).contains("disabled")
            ),
            "{result:?}"
        );
    }

    // ── the decorator ────────────────────────────────────────────────────────

    #[tokio::test]
    async fn the_pre_state_is_read_before_the_device_is_written_to() {
        let fake = Fake::answering(&[("getprop 'debug.foo'", "0")]);
        let backend = ReversibleBackend::new(fake.clone(), snapshot_dir());

        backend
            .exec(request_for("setprop debug.foo 1"))
            .await
            .unwrap();

        let seen = fake.sequence();
        assert_eq!(seen.len(), 2, "one capture read, one write: {seen:?}");
        assert_eq!(seen[0].script, "getprop 'debug.foo'");
        assert_eq!(
            seen[0].capability,
            HostCapability::parse("android:shell:read")
                .unwrap()
                .as_str(),
            "the capture must be a read-tier request, not a write that happens to be harmless"
        );
        assert_eq!(seen[1].script, "setprop debug.foo 1");
        assert!(seen[1].approved);
        assert!(
            !seen[0].approved,
            "a read must not borrow the write's approval to get itself through"
        );
    }

    #[tokio::test]
    async fn a_file_write_is_snapshotted_and_put_back_by_digest() {
        // §4.6.4's other half: the file is copied into the Agent workspace *before* the write,
        // and the restore is checked against the digest the device gave up beforehand. The
        // check is the load-bearing part — chunked transport without it would let a lost chunk
        // be reported as a successful rollback.
        let script = "echo changed > /data/local/tmp/note.txt";
        let digest = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        let planned = plan(script);
        let capture = &planned.captures[0];
        let read = capture.read.clone();
        let content = capture.content_read().unwrap();
        let verify = format!("sha256sum < '{}'", "/data/local/tmp/note.txt");

        let dir = snapshot_dir();
        let fake = Fake::answering(&[
            (&read, "PRESENT\n3\n"),
            (&content, &format!("{digest}  -\nYWJj")),
            (&verify, &format!("{digest}  -")),
            (script, ""),
        ]);
        let backend = ReversibleBackend::new(fake.clone(), dir.clone());

        backend
            .exec(request_for(script))
            .await
            .expect("the write itself succeeds");

        let snapshots: Vec<_> = std::fs::read_dir(&dir)
            .expect("the store was created")
            .flatten()
            .map(|e| e.path())
            .collect();
        assert_eq!(snapshots.len(), 1, "one file, one backup");
        assert_eq!(
            std::fs::read_to_string(&snapshots[0]).unwrap(),
            "YWJj",
            "the backup holds the base64 the device sent"
        );

        let report = backend.restore("session-alpha").await;
        assert!(report.clean(), "{:?}", report.failed);
        assert_eq!(report.restored.len(), 1);
        assert!(
            report.restored[0].contains("/data/local/tmp/note.txt"),
            "{}",
            report.restored[0]
        );

        // The order the whole design rests on: measure, fetch, *then* write.
        let seen = fake.sequence();
        let scripts: Vec<&str> = seen.iter().map(|s| s.script.as_str()).collect();
        assert_eq!(
            &scripts[..3],
            &[read.as_str(), content.as_str(), script],
            "capture before the write, in that order"
        );
        // Verified, so the workspace copy has done its job and is not kept as a second copy of
        // the device's data.
        assert!(
            !snapshots[0].exists(),
            "a restore that checked out discards its snapshot"
        );
    }

    #[tokio::test]
    async fn a_snapshot_larger_than_the_argument_ceiling_is_staged_in_chunks() {
        // The device refuses an argument over ~110 KiB, so a payload of several chunks is the
        // normal case, not the edge case. Two properties matter and both are invisible in the
        // ledger: the first chunk must *create* the staging file and the rest must *append*
        // (`>` twice would silently drop everything before the last chunk), and the digest
        // check must be the thing that decides whether the restore worked.
        let script = "echo changed > /data/local/tmp/many.bin";
        let capture = &plan(script).captures[0];
        let read = capture.read.clone();
        let content = capture.content_read().unwrap();
        let verify = "sha256sum < '/data/local/tmp/many.bin'".to_string();
        let payload = "A".repeat(SNAPSHOT_CHUNK_BYTES + 4);
        let device_bytes = decoded_len_of_base64(&payload);
        let digest = "c".repeat(64);
        let envelope = format!("PRESENT\n{device_bytes}\n");
        let body = format!("{digest}  -\n{payload}");
        let fake = Fake::answering(&[
            (&read, &envelope),
            (&content, &body),
            (&verify, &format!("{digest}  -")),
            (script, ""),
        ]);
        let backend = ReversibleBackend::new(fake.clone(), snapshot_dir());
        backend.exec(request_for(script)).await.unwrap();
        let report = backend.restore("session-alpha").await;
        assert!(report.clean(), "{:?}", report.failed);

        let staged: Vec<String> = fake
            .sequence()
            .iter()
            .map(|s| s.script.clone())
            .filter(|s| s.contains(".acowork-snap-") && s.starts_with("printf"))
            .collect();
        assert_eq!(staged.len(), 2, "{staged:?}");
        assert!(
            staged[0].contains("' > '"),
            "first chunk creates: {}",
            staged[0]
        );
        assert!(
            staged[1].contains("' >> '"),
            "second chunk appends, or the head of the file is lost: {}",
            staged[1]
        );
        // Pull the quoted payload back out of each staging command. `printf '%s' 'X' > 'P'` is
        // the whole shape, so the payload is what sits between the second and third quote.
        let carried = |script: &str| -> String {
            // `printf '%s' 'CHUNK' > 'PATH'` splits on the quotes as
            // ["printf ", "%s", " ", CHUNK, " > ", PATH, ""] — the payload is field 3.
            script.split('\'').nth(3).unwrap_or("").to_string()
        };
        assert_eq!(
            carried(&staged[0]).len(),
            SNAPSHOT_CHUNK_BYTES,
            "the first chunk is a full one"
        );
        assert_eq!(
            carried(&staged[0]).len() + carried(&staged[1]).len(),
            payload.len(),
            "the two chunks carry the whole payload — nothing is dropped between them"
        );
    }

    #[tokio::test]
    async fn a_file_that_was_not_there_is_removed_rather_than_restored() {
        // Creating a file has an inverse too, and it is not a snapshot: it is the absence that
        // was observed. `rm -f` and nothing else.
        let script = "echo new > /data/local/tmp/created.txt";
        let capture = &plan(script).captures[0];
        let read = capture.read.clone();
        let fake = Fake::answering(&[(&read, "ABSENT\n"), (script, "")]);
        let backend = ReversibleBackend::new(fake.clone(), snapshot_dir());
        backend.exec(request_for(script)).await.unwrap();

        // Read the ledger out and let the guard go before the next await: a `MutexGuard` held
        // across an await is how a teardown deadlocks the moment two sessions restore at once.
        let (inverse, old_value, faithful) = {
            let ledger = backend.ledger();
            let guard = ledger.lock().unwrap();
            let pending = guard.pending_for("session-alpha").to_vec();
            assert_eq!(pending.len(), 1);
            (
                pending[0].inverse_script().unwrap().to_string(),
                pending[0].old_value.clone(),
                pending[0].faithful,
            )
        };
        assert_eq!(inverse, "rm -f '/data/local/tmp/created.txt'");
        assert_eq!(old_value, "<absent>");
        assert!(faithful, "absence is restored exactly");

        let report = backend.restore("session-alpha").await;
        assert!(report.clean(), "{:?}", report.failed);
        assert!(
            fake.sequence()
                .iter()
                .any(|s| s.script == "rm -f '/data/local/tmp/created.txt'")
        );
    }

    #[tokio::test]
    async fn a_file_over_budget_is_written_anyway_and_named_at_teardown() {
        // The budget is a promise about *backups*, not about writes: the command still runs, and
        // the session ends by saying out loud that this file is not coming back.
        let script = "echo big > /data/local/tmp/big.txt";
        let read = plan(script).captures[0].read.clone();
        let over = SNAPSHOT_BUDGET_BYTES + 1;
        let envelope = format!("PRESENT\n{over}\n");
        let fake = Fake::answering(&[(&read, &envelope), (script, "")]);
        let backend = ReversibleBackend::new(fake.clone(), snapshot_dir());
        backend.exec(request_for(script)).await.unwrap();

        let ledger = backend.ledger();
        let ledger = ledger.lock().unwrap();
        assert!(
            ledger.pending_for("session-alpha").is_empty(),
            "nothing was saved, so nothing can be restored"
        );
        let left = ledger.leaving_behind("session-alpha");
        assert_eq!(left.len(), 1, "{left:?}");
        assert!(
            left[0].why.contains("snapshot budget") && left[0].why.contains(&over.to_string()),
            "{:?}",
            left[0]
        );
        // The size check happened on the *envelope*: no content read was ever issued, so a
        // 4 GB file costs one `wc` rather than a base64 of the whole thing.
        assert_eq!(
            fake.sequence()
                .iter()
                .filter(|s| s.script.contains("base64"))
                .count(),
            0
        );
    }

    #[tokio::test]
    async fn a_restore_that_does_not_match_the_digest_is_a_failure_not_a_restore() {
        let script = "echo changed > /data/local/tmp/note.txt";
        let digest = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        let capture = &plan(script).captures[0];
        let read = capture.read.clone();
        let content = capture.content_read().unwrap();
        let verify = "sha256sum < '/data/local/tmp/note.txt'".to_string();
        let fake = Fake::answering(&[
            (&read, "PRESENT\n3\n"),
            (&content, &format!("{digest}  -\nYWJj")),
            // The device now reports a different file than the one that was backed up.
            (&verify, &format!("{}  -", "0".repeat(64))),
            (script, ""),
        ]);
        let backend = ReversibleBackend::new(fake.clone(), snapshot_dir());
        backend.exec(request_for(script)).await.unwrap();
        let snapshot = backend
            .ledger()
            .lock()
            .unwrap()
            .pending_for("session-alpha")[0]
            .inverse_script()
            .is_none();
        assert!(snapshot, "the undo is a snapshot, not a script");

        let report = backend.restore("session-alpha").await;
        assert_eq!(report.failed.len(), 1, "{report:?}");
        assert!(
            report.failed[0].1.contains("does *not* hold"),
            "{}",
            report.failed[0].1
        );
        assert_eq!(
            report.still_pending_elsewhere, 1,
            "a failed restore stays pending — the device is not back and the ledger must not \
             pretend otherwise"
        );
    }

    #[test]
    fn a_snapshot_name_cannot_escape_the_store() {
        // The session id is caller-supplied and becomes a file name. Left alone, a session
        // called `../../escape` would put device content outside the workspace.
        let store = SnapshotStore::new(snapshot_dir());
        let path = store
            .save("../../etc/passwd", "nonce", "YWJj")
            .expect("store writes");
        assert_eq!(
            path.parent(),
            Some(store.dir()),
            "the name lands in the store and nowhere else. What carries that is the separator: \
             `/` never survives sanitising, so no session id can reach a parent directory"
        );
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        let prefix = name.strip_suffix("-nonce.b64").expect("{name}");
        assert!(
            !prefix.contains('/') && !prefix.contains('.'),
            "the extension is ours; nothing from the caller may write a dot into the name"
        );
        assert_eq!(prefix, "______etc_passwd");
    }

    #[test]
    fn the_snapshot_protocol_is_checked_before_it_is_believed() {
        assert!(is_base64("YWJj"));
        assert!(
            is_base64(""),
            "an empty file encodes to nothing, which is a real state"
        );
        assert!(!is_base64("YWJj\n"));
        assert!(!is_base64("not base64!"));
        assert_eq!(decoded_len_of_base64("YWJj"), 3);
        assert_eq!(decoded_len_of_base64("YQ=="), 1);
        assert_eq!(decoded_len_of_base64(""), 0);

        assert!(matches!(parse_envelope("ABSENT\n"), Envelope::Absent));
        assert!(matches!(
            parse_envelope("PRESENT\n4096\n"),
            Envelope::Size(Some(4096))
        ));
        assert!(matches!(parse_envelope("PRESENT\n"), Envelope::Size(None)));
        assert!(matches!(parse_envelope(""), Envelope::Unparsed(_)));

        let digest = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        let parsed = parse_snapshot(&format!("{digest}  -\nYW\nJj\n")).unwrap();
        assert_eq!(parsed.0, digest);
        assert_eq!(parsed.1, "YWJj", "wrapped base64 reassembles");
        assert!(parse_snapshot("nope\nYWJj").is_none(), "not a digest line");
        assert!(parse_snapshot(&format!("{digest}  -\nnot base!")).is_none());
    }

    #[tokio::test]
    async fn a_read_only_script_is_passed_through_without_a_second_round_trip() {
        let fake = Fake::answering(&[]);
        let backend = ReversibleBackend::new(fake.clone(), snapshot_dir());
        backend
            .exec(ExecRequest::read("getprop ro.build.type", "session-alpha"))
            .await
            .unwrap();
        assert_eq!(
            fake.sequence().len(),
            1,
            "doubling every read to plan an undo that is never used would make the read tier \
             cost twice as much as §4.4 says it should"
        );
    }

    #[tokio::test]
    async fn a_write_that_failed_records_no_undo() {
        let fake = Fake::with_failing("setprop debug.foo 1", &[("getprop 'debug.foo'", "0")]);
        let backend = ReversibleBackend::new(fake.clone(), snapshot_dir());
        let record = backend
            .exec(request_for("setprop debug.foo 1"))
            .await
            .unwrap();
        assert_eq!(record.exit_code, Some(1));
        assert!(
            backend.ledger().lock().unwrap().pending().is_empty(),
            "an undo for a change that did not happen is a new write at teardown time"
        );
    }

    #[tokio::test]
    async fn restores_run_last_in_first_out() {
        // The same prop twice: the session's intermediate state is real, and restoring in
        // record order would leave the prop at whatever it was between the two writes.
        let fake = Fake::answering(&[
            ("getprop 'debug.foo'", "0"),
            ("setprop debug.foo 1", ""),
            ("setprop debug.foo 2", ""),
        ]);
        let backend = ReversibleBackend::new(fake.clone(), snapshot_dir());
        // The first capture sees 0; after the first write the second capture sees 1, which the
        // fake cannot model from a static table — so the second read is answered explicitly.
        backend
            .exec(request_for("setprop debug.foo 1"))
            .await
            .unwrap();
        let undo_b = {
            let mut plan_b = plan("setprop debug.foo 2");
            let capture = plan_b.captures.remove(0);
            undo_for(
                &capture,
                Some(PreState::Value("1".to_string())),
                &request_for("setprop debug.foo 2"),
            )
        };
        if let UndoResult::Undo(undo) = undo_b {
            backend.ledger().lock().unwrap().record(undo);
        }

        let before: Vec<String> = backend
            .ledger()
            .lock()
            .unwrap()
            .pending()
            .iter()
            .map(|u| u.inverse_script().unwrap().to_string())
            .collect();
        assert_eq!(
            before,
            vec!["setprop 'debug.foo' '0'", "setprop 'debug.foo' '1'"]
        );

        let report = backend.restore("session-alpha").await;
        assert!(report.clean(), "{report:?}");
        assert_eq!(
            report.restored,
            vec!["prop debug.foo → 1", "prop debug.foo → 0"],
            "reverse order, or the session ends in a state it never held"
        );
        assert!(backend.ledger().lock().unwrap().pending().is_empty());
    }

    #[tokio::test]
    async fn a_failing_restore_stays_pending_and_is_reported() {
        let fake = Fake::with_failing("setprop 'debug.foo' '0'", &[("getprop 'debug.foo'", "0")]);
        let backend = ReversibleBackend::new(fake.clone(), snapshot_dir());
        backend
            .exec(request_for("setprop debug.foo 1"))
            .await
            .unwrap();
        assert_eq!(backend.ledger().lock().unwrap().pending().len(), 1);

        let report = backend.restore("session-alpha").await;
        assert!(!report.clean());
        assert_eq!(report.failed.len(), 1);
        assert!(
            report.failed[0].1.contains("failed to set property"),
            "{report:?}"
        );
        assert_eq!(
            backend.ledger().lock().unwrap().pending().len(),
            1,
            "a restore that could not run must not be forgotten — that is the device staying \
             changed with nothing left saying so"
        );

        // Terminates: the re-pending entry is not re-attempted forever by one pass.
        let again = backend.restore("session-alpha").await;
        assert_eq!(again.failed.len(), 1);
    }

    #[tokio::test]
    async fn keeping_a_change_is_an_explicit_act() {
        let fake = Fake::answering(&[("getprop 'persist.sys.demo'", "")]);
        let backend = ReversibleBackend::new(fake.clone(), snapshot_dir());
        backend
            .exec(request_for("setprop persist.sys.demo 1"))
            .await
            .unwrap();

        let ledger = backend.ledger();
        {
            let mut guard = ledger.lock().unwrap();
            assert!(guard.pending()[0].persists_reboot);
            assert!(guard.keep(
                "session-alpha",
                &UndoTarget::Prop("persist.sys.demo".into())
            ));
        }
        let report = backend.restore("session-alpha").await;
        assert!(
            report.restored.is_empty() && report.failed.is_empty(),
            "the user declared this one stays; the teardown must not run it back anyway: {report:?}"
        );
    }

    #[tokio::test]
    async fn what_cannot_be_undone_is_still_known_at_teardown() {
        let fake = Fake::answering(&[]);
        let backend = ReversibleBackend::new(fake.clone(), snapshot_dir());
        backend
            .exec(request_for(
                "am broadcast -a android.intent.action.BOOT_COMPLETED",
            ))
            .await
            .unwrap();

        let ledger = backend.ledger();
        let guard = ledger.lock().unwrap();
        assert!(guard.pending().is_empty());
        let left = guard.leaving_behind("session-alpha");
        assert_eq!(
            left.len(),
            1,
            "the session is not clean, and must not look clean"
        );
        assert_eq!(left[0].command, "am broadcast");
    }

    #[tokio::test]
    async fn one_session_s_teardown_does_not_touch_another_s() {
        let fake = Fake::answering(&[("getprop 'debug.foo'", "0")]);
        let backend = ReversibleBackend::new(fake.clone(), snapshot_dir());
        let mut other = ExecRequest::new(
            Capability::ShellWrite,
            "setprop debug.foo 1",
            "session-beta",
        );
        other.approval_token = Some(ApprovalToken::new("tok-2"));

        backend
            .exec(request_for("setprop debug.foo 1"))
            .await
            .unwrap();
        backend.exec(other).await.unwrap();
        assert_eq!(backend.ledger().lock().unwrap().pending().len(), 2);

        let report = backend.restore("session-alpha").await;
        assert_eq!(report.restored.len(), 1);
        assert_eq!(report.still_pending_elsewhere, 1);
        let ledger = backend.ledger();
        let guard = ledger.lock().unwrap();
        assert_eq!(guard.pending_for("session-beta").len(), 1);
    }

    // ── the `pm` / `am` / `input` surface ────────────────────────────────────
    //
    // These tests exist because the old behaviour was worse than no behaviour: one sentence
    // covered "this port has not modelled it", "nothing on the device can put it back" and
    // "there was never any state to restore". The three read identically in a log and mean
    // opposite things to whoever decides whether the session cleaned up after itself.

    #[test]
    fn a_destructive_pm_write_is_named_as_one() {
        let planned = plan("pm clear com.example.app");
        assert!(planned.captures.is_empty());
        assert_eq!(planned.unundoable[0].kind, UnundoableKind::DestroysData);
        assert!(
            planned.unundoable[0]
                .why
                .contains("a snapshot taken after this command runs"),
            "{:?}",
            planned.unundoable[0]
        );

        // Uninstall is not the same fact: the data is gone *and* the binary is not retained,
        // but the operator's next step differs (re-supply an APK vs restore a backup).
        let planned = plan("pm uninstall com.example.app");
        assert_eq!(
            planned.unundoable[0].kind,
            UnundoableKind::NoRestorableState
        );
    }

    #[test]
    fn an_install_without_a_named_package_has_no_target_to_undo() {
        // The package name is inside the APK. A capture taken here would read the state of
        // nothing in particular, so the planner declines to plan one.
        let planned = plan("pm install /data/local/tmp/x.apk");
        assert!(planned.captures.is_empty());
        assert_eq!(
            planned.unundoable[0].kind,
            UnundoableKind::IndeterminateTarget
        );
    }

    #[test]
    fn an_install_that_names_its_package_is_planned() {
        let planned = plan("pm install --pkg com.example.new /data/local/tmp/x.apk");
        assert_eq!(planned.captures.len(), 1, "{:?}", planned.captures);
        let capture = &planned.captures[0];
        assert_eq!(
            capture.target,
            UndoTarget::Package("com.example.new".to_string())
        );
        // Absence has to come back as a successful read, so the probe is enveloped rather than
        // being `pm path` alone — which exits 1 for exactly the case that has an inverse.
        assert!(
            capture.read.contains("pm path 'com.example.new'"),
            "{}",
            capture.read
        );
        assert!(capture.read.contains("PRESENT"), "{}", capture.read);
        assert!(capture.read.contains("ABSENT"), "{}", capture.read);
    }

    #[test]
    fn a_flag_cannot_become_a_package_name() {
        // `--pkg --user 0` names no package. Reading `--user` as one would build a capture
        // against a target the command never named, and the undo would uninstall something
        // the session did not install.
        let planned = plan("pm install --pkg --user 0 /data/local/tmp/x.apk");
        assert!(planned.captures.is_empty());
        assert_eq!(
            planned.unundoable[0].kind,
            UnundoableKind::IndeterminateTarget
        );

        // A value that is not a package name shape is refused for the same reason, even though
        // shell-quoting would have made it *safe* to embed. Safe to embed is not the test;
        // naming a real package is.
        let planned = plan("pm install --pkg ../etc /data/local/tmp/x.apk");
        assert!(planned.captures.is_empty());
    }

    #[test]
    fn installing_into_an_absent_package_uninstalls_it() {
        let planned = plan("pm install --pkg com.example.new /data/local/tmp/x.apk");
        let result = undo_for(
            &planned.captures[0],
            Some(PreState::Package(PackagePreState::Absent)),
            &request_for("pm install --pkg com.example.new /data/local/tmp/x.apk"),
        );
        let UndoResult::Undo(undo) = result else {
            panic!("an absent package has a real inverse: {result:?}");
        };
        assert_eq!(
            undo.action,
            UndoAction::Script("pm uninstall 'com.example.new'".to_string())
        );
        // Not faithful: the package entity returns, but runtime permissions granted at install
        // time, directories on shared storage and accounts it registered do not.
        assert!(!undo.faithful);
        assert!(undo.persists_reboot);
    }

    #[test]
    fn reinstalling_an_installed_package_offers_no_undo() {
        let planned = plan("pm install --pkg com.example.new /data/local/tmp/x.apk");
        let request = request_for("pm install --pkg com.example.new /data/local/tmp/x.apk");

        let result = undo_for(
            &planned.captures[0],
            Some(PreState::Package(PackagePreState::Present)),
            &request,
        );
        assert!(
            matches!(
                &result,
                UndoResult::CannotUndo {
                    kind: UnundoableKind::NoRestorableState,
                    ..
                }
            ),
            "{result:?}"
        );
        assert!(
            result_why(&result).contains("replaced its binary"),
            "{}",
            result_why(&result)
        );

        // And a probe that never answered is its own category — the port did not see the
        // before-state, which is a different problem from there being nothing to restore.
        let result = undo_for(
            &planned.captures[0],
            Some(PreState::Package(PackagePreState::Unknown(
                "error: package unknown".to_string(),
            ))),
            &request,
        );
        assert!(
            matches!(
                &result,
                UndoResult::CannotUndo {
                    kind: UnundoableKind::Unobserved,
                    ..
                }
            ),
            "{result:?}"
        );

        let result = undo_for(&planned.captures[0], None, &request);
        assert!(
            matches!(
                &result,
                UndoResult::CannotUndo {
                    kind: UnundoableKind::Unobserved,
                    ..
                }
            ),
            "{result:?}"
        );
    }

    #[test]
    fn set_install_location_is_recognised_as_the_settings_write_it_is() {
        // `pm set-install-location` writes Settings.Global.install_location — measured, not
        // assumed: driving it on BLA-AL00 threw a SecurityException whose stack goes through
        // `insertGlobalSetting`. Recognising the row means the undo reuses the settings path,
        // including the `null` means-absent rule, instead of inventing a second model for the
        // same device state.
        let planned = plan("pm set-install-location 1");
        assert_eq!(planned.captures.len(), 1, "{:?}", planned.captures);
        assert_eq!(
            planned.captures[0].target,
            UndoTarget::Setting {
                table: "global".to_string(),
                key: "install_location".to_string(),
            }
        );
        assert_eq!(
            planned.captures[0].read,
            "settings get global install_location"
        );

        // Measured on BLA-AL00: the row reads `null` before anything sets it, so the undo of a
        // first write is a delete, not a put of the string "null".
        let result = undo_for(
            &planned.captures[0],
            Some(PreState::Value("null\n".to_string())),
            &request_for("pm set-install-location 1"),
        );
        let UndoResult::Undo(undo) = result else {
            panic!("an unset row has an exact inverse: {result:?}");
        };
        assert_eq!(
            undo.action,
            UndoAction::Script("settings delete 'global' 'install_location'".to_string())
        );
        assert!(undo.faithful);

        // A value the command would not accept is not planned at all: an undo for a write the
        // device rejects would put a value in the ledger that nothing ever replaced.
        let planned = plan("pm set-install-location 7");
        assert!(planned.captures.is_empty());
        assert_eq!(
            planned.unundoable[0].kind,
            UnundoableKind::NotModelled,
            "{:?}",
            planned.unundoable[0]
        );
    }

    #[test]
    fn an_unmodelled_write_still_admits_it_is_the_ports_gap() {
        // The category that *is* an admission. It has to stay distinguishable from the facts
        // about commands, or the port can quietly reclassify its own gaps as impossibilities.
        let planned = plan("pm set-home-activity com.example.launcher/.MainActivity");
        assert!(planned.captures.is_empty());
        assert_eq!(planned.unundoable[0].kind, UnundoableKind::NotModelled);
        assert!(
            planned.unundoable[0]
                .why
                .contains("no inverse modelled for it yet"),
            "{:?}",
            planned.unundoable[0]
        );

        // `pm enable`/`pm disable` look trivially reversible and are not, on this device: the
        // read cannot tell `disabled` from `disabled-user`, so the "inverse" can set a
        // different mode than the one observed. Recorded as a gap, with the reason.
        let planned = plan("pm disable com.example.app");
        assert_eq!(planned.unundoable[0].kind, UnundoableKind::NotModelled);
        assert!(planned.unundoable[0].why.contains("disabled-user"));
    }

    #[test]
    fn injected_events_are_not_reported_as_leftover_state() {
        for script in ["input tap 540 960", "input keyevent 26", "input text hello"] {
            let planned = plan(script);
            assert!(planned.captures.is_empty(), "{script}");
            assert_eq!(
                planned.unundoable[0].kind,
                UnundoableKind::NotAStateChange,
                "{script}"
            );
            assert!(
                !planned.unundoable[0]
                    .why
                    .contains("stays after the session"),
                "{script}"
            );
        }
    }

    #[test]
    fn every_kind_is_said_in_its_own_words() {
        // The labels reach a human. Two kinds sharing a label would make the list lie.
        let all = [
            UnundoableKind::NotModelled,
            UnundoableKind::DestroysData,
            UnundoableKind::NoRestorableState,
            UnundoableKind::NotAStateChange,
            UnundoableKind::IndeterminateTarget,
            UnundoableKind::Unobserved,
            UnundoableKind::NoChange,
        ];
        let labels: Vec<&str> = all.iter().map(|k| k.label()).collect();
        let unique: std::collections::HashSet<&str> = labels.iter().copied().collect();
        assert_eq!(labels.len(), unique.len(), "{labels:?}");
    }

    // ── the store's own lifetime ─────────────────────────────────────────────

    #[tokio::test]
    async fn a_full_store_refuses_a_new_backup_instead_of_evicting_an_old_one() {
        let digest = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        let first = "echo changed > /data/local/tmp/first.txt";
        let second = "echo changed > /data/local/tmp/second.txt";

        let mut reads = Vec::new();
        for script in [first, second] {
            let capture = &plan(script).captures[0];
            reads.push((capture.read.clone(), capture.content_read().unwrap()));
        }
        let dir = snapshot_dir();
        let fake = Fake::answering(&[
            (&reads[0].0, "PRESENT\n3\n"),
            (&reads[0].1, &format!("{digest}  -\nYWJj")),
            (first, ""),
            (&reads[1].0, "PRESENT\n3\n"),
            (&reads[1].1, &format!("{digest}  -\nYWJj")),
            (second, ""),
        ]);
        // Six bytes: the first 4-byte backup fits, the second does not.
        let backend =
            ReversibleBackend::with_store(fake, SnapshotStore::with_budget(dir.clone(), 6));

        backend.exec(request_for(first)).await.unwrap();
        backend.exec(request_for(second)).await.unwrap();

        let pending = backend
            .ledger()
            .lock()
            .unwrap()
            .pending_for("session-alpha")
            .len();
        assert_eq!(
            pending, 1,
            "the first backup is kept, the second was refused"
        );
        let left = backend
            .ledger()
            .lock()
            .unwrap()
            .leaving_behind("session-alpha")
            .to_vec();
        assert_eq!(left.len(), 1, "{left:?}");
        assert_eq!(left[0].kind, UnundoableKind::NoRestorableState);
        assert!(left[0].why.contains("not promised"), "{}", left[0].why);
        assert!(
            left[0].why.contains("evicted"),
            "the reason has to say why nothing was freed: {}",
            left[0].why
        );

        // The refused write still happened — the store is about the *backup*, not about
        // vetoing the command.
        let kept: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .map(|e| e.path())
            .collect();
        assert_eq!(kept.len(), 1, "the older backup survived the pressure");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn abandoning_a_session_drops_backups_and_says_the_device_is_still_changed() {
        let digest = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        let script = "echo changed > /data/local/tmp/note.txt";
        let capture = &plan(script).captures[0];
        let (read, content) = (capture.read.clone(), capture.content_read().unwrap());
        let dir = snapshot_dir();
        let fake = Fake::answering(&[
            (&read, "PRESENT\n3\n"),
            (&content, &format!("{digest}  -\nYWJj")),
            (script, ""),
        ]);
        let backend = ReversibleBackend::new(fake.clone(), dir.clone());
        backend.exec(request_for(script)).await.unwrap();

        let dropped = backend.abandon("session-alpha");
        assert_eq!(dropped, 1);
        assert!(backend.ledger().lock().unwrap().pending().is_empty());
        assert_eq!(
            std::fs::read_dir(&dir)
                .map(|e| e.flatten().count())
                .unwrap_or(0),
            0,
            "the host copy goes with the undo it belonged to"
        );

        // The point of the whole test: an empty ledger must not read as a clean device.
        let left = backend
            .ledger()
            .lock()
            .unwrap()
            .leaving_behind("session-alpha")
            .to_vec();
        assert_eq!(left.len(), 1, "{left:?}");
        assert_eq!(left[0].kind, UnundoableKind::NoRestorableState);
        assert!(
            left[0].why.contains("closed without restoring"),
            "{}",
            left[0].why
        );

        // And abandoning is not a rollback: nothing was ever sent to the device beyond the
        // capture reads and the write itself.
        let seen = fake.seen.lock().unwrap().clone();
        assert!(
            !seen
                .iter()
                .any(|request| request.script.starts_with("base64 -d")),
            "abandon must not restore: {seen:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn abandoning_a_session_with_nothing_pending_is_quiet() {
        let backend = ReversibleBackend::new(
            Fake::answering(&[("setprop debug.foo 1", "")]),
            snapshot_dir(),
        );
        assert_eq!(backend.abandon("never-here"), 0);
        assert!(
            backend
                .ledger()
                .lock()
                .unwrap()
                .leaving_behind("never-here")
                .is_empty(),
            "a session that changed nothing must not appear in the teardown list"
        );
    }
}
