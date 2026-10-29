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
use std::sync::{Arc, Mutex};

use crate::host::backend::{
    ApprovalToken, BackendError, ExecRecord, ExecRequest, ExecutionBackend,
};
use crate::host::capability::Capability;
use crate::host::commands::{self, Finding};
use crate::host::facts::ShellDialect;
use crate::host::profile::HostProfile;
use crate::host::script::quote_posix;

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
}

impl UndoTarget {
    /// Short enough to put in a log line, qualified enough that two settings rows in different
    /// tables do not read as the same target.
    pub fn describe(&self) -> String {
        match self {
            UndoTarget::Prop(key) => format!("prop {key}"),
            UndoTarget::Setting { table, key } => format!("settings {table}/{key}"),
            UndoTarget::SelinuxMode => "SELinux enforcing mode".to_string(),
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

/// A write this port knows how to put back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Undo {
    /// The session whose teardown this belongs to.
    pub session_id: String,
    /// What it puts back.
    pub target: UndoTarget,
    /// The script that does it.
    pub inverse: String,
    /// The value that was there, verbatim, for whoever has to explain the restore.
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

/// A mutation with no modelled inverse, kept so the session's teardown can say what it is
/// leaving behind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unundoable {
    /// The command word, as the classifier normalised it.
    pub command: String,
    /// What it does, and why there is no undo. Reaches the node, not the wire.
    pub why: String,
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
    let Some(argument_lists) = commands::words(script) else {
        out.unundoable.push(Unundoable {
            command: script.trim().to_string(),
            why: "the script could not be split into commands, so nothing is known about what \
                  it changes — an empty undo list here means the planner was blind, not that \
                  the session is clean"
                .to_string(),
        });
        return out;
    };

    // `classify` and `words` run the same lexer over the same text, so findings and argument
    // vectors line up index for index. Zipping rather than re-parsing is what keeps the two
    // from disagreeing about what `setprop a 'b c'` is — a disagreement that would show up as
    // a rollback restoring the wrong value.
    let findings = commands::classify(script).findings;
    for (args, finding) in argument_lists.iter().zip(findings.iter()) {
        if finding.effect.is_read_only() {
            continue;
        }
        match Capture::from_args(args, finding) {
            Some(capture) => out.captures.push(capture),
            None => out.unundoable.push(Unundoable {
                command: finding.command.clone(),
                why: format!(
                    "{} — and no inverse is modelled for it, so this change stays after the \
                     session ends",
                    finding.detail
                ),
            }),
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
            _ => None,
        }
    }
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
    CannotUndo(String),
}

/// Turn a captured pre-state into the inverse, or explain why there is none.
///
/// `observed` is the capture read's stdout, or `None` when that read failed. Failure is
/// [`UndoResult::CannotUndo`] rather than a guess: an undo built on a value nobody read is a
/// *new* write wearing a rollback's name, and it is the kind of thing that turns a failed
/// experiment into a silent two-command incident.
pub fn undo_for(capture: &Capture, observed: Option<&str>, request: &ExecRequest) -> UndoResult {
    let Some(raw) = observed else {
        return UndoResult::CannotUndo(format!(
            "{}: the pre-state read (`{}`) did not return a value, and restoring to a value \
             that was never observed would be a new change, not a rollback",
            capture.target.describe(),
            capture.read
        ));
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
                inverse: format!("setprop {} {}", quote_posix(key), quote_posix(current)),
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
            let inverse = if absent {
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
            };
            UndoResult::Undo(Undo {
                session_id: request.session_id.clone(),
                target: capture.target.clone(),
                inverse,
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
                "Disabled" => UndoResult::CannotUndo(
                    "SELinux is *disabled* on this device, not enforcing; `setenforce` cannot \
                     restore a disabled state (it is set at boot), so this change cannot be \
                     undone from the shell"
                        .to_string(),
                ),
                _ => UndoResult::Undo(Undo {
                    session_id: request.session_id.clone(),
                    target: capture.target.clone(),
                    inverse: format!("setenforce {}", if want_permissive { "1" } else { "0" }),
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
        (target, Writing::Delete) => UndoResult::CannotUndo(format!(
            "{}: no delete-inverse is modelled for this target",
            target.describe()
        )),
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
}

impl ReversibleBackend {
    /// Wrap a backend. The ledger is shared, so the node can inspect it without the backend.
    pub fn new(inner: Arc<dyn ExecutionBackend>) -> ReversibleBackend {
        ReversibleBackend {
            inner,
            ledger: Arc::new(Mutex::new(RollbackLedger::new())),
        }
    }

    /// Wrap a backend with a ledger the caller already holds.
    pub fn with_ledger(
        inner: Arc<dyn ExecutionBackend>,
        ledger: Arc<Mutex<RollbackLedger>>,
    ) -> ReversibleBackend {
        ReversibleBackend { inner, ledger }
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

    /// Run one capture read. `None` means no value was observed, which [`undo_for`] treats as
    /// "do not build an undo", not as "the value was empty".
    async fn read_pre_state(&self, capture: &Capture, session: &str) -> Option<String> {
        let request = ExecRequest::read(capture.read.clone(), session);
        match self.inner.exec(request).await {
            Ok(record) if record.succeeded() => Some(record.stdout),
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
            let mut request = ExecRequest::new(undo.capability, undo.inverse.clone(), session);
            request.approval_token = undo.token.clone();
            match self.inner.exec(request).await {
                Ok(record) if record.succeeded() => report.restored.push(undo.describe()),
                Ok(record) => {
                    report.failed.push((
                        undo.describe(),
                        format!(
                            "exit {:?}{}",
                            record.exit_code,
                            suffix_if_needed(&record.stderr)
                        ),
                    ));
                    self.ledger_mut().restore_entry(undo);
                }
                Err(e) => {
                    report.failed.push((undo.describe(), e.to_string()));
                    self.ledger_mut().restore_entry(undo);
                }
            }
        }

        report.still_pending_elsewhere = self.ledger_mut().pending().len();
        report
    }
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
        let mut captured: Vec<(Capture, Option<String>)> =
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
                match undo_for(&capture, observed.as_deref(), &request) {
                    UndoResult::Undo(undo) => ledger.record(undo),
                    // Both of these are the teardown's business, not the caller's: "nothing to
                    // undo" and "no undo possible" read the same in a log and mean opposite
                    // things to whoever is deciding whether to trust this session's cleanup.
                    UndoResult::NothingToUndo(why) | UndoResult::CannotUndo(why) => {
                        ledger.record_unundoable(
                            &session,
                            &[Unundoable {
                                command: capture.target.describe(),
                                why,
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
        assert!(
            planned.unundoable[0].why.contains("no inverse is modelled"),
            "{:?}",
            planned.unundoable[0]
        );

        // A file write is §4.6.4's *other* promise — back it up and offer `restore` — which is
        // not implemented. The plan must not read as though nothing happened.
        let planned = plan("echo note > /data/local/tmp/note.txt");
        assert!(planned.captures.is_empty());
        assert_eq!(planned.unundoable.len(), 1, "{:?}", planned.unundoable);
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
        undo_for(capture, observed, &write_request(script, claimed))
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
        assert_eq!(undo.inverse, "setprop 'debug.stagefright.ccodec' '0'");
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
            matches!(&result, UndoResult::CannotUndo(why) if why.contains("never observed")),
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
        assert_eq!(undo.inverse, "setprop 'debug.foo' ''");
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
        assert_eq!(undo.inverse, "settings delete 'system' 'font_scale'");
        assert!(undo.faithful, "delete is the exact inverse of absent");

        // And a present row comes back with its value quoted, not interpolated.
        let UndoResult::Undo(undo) = undo_of(
            "settings put system font_scale 1.5",
            "settings get 'system' 'font_scale'",
            Some("1.0\n"),
        ) else {
            panic!("expected an undo");
        };
        assert_eq!(undo.inverse, "settings put 'system' 'font_scale' '1.0'");
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
        assert_eq!(undo.inverse, "setprop 'debug.foo' 'a b'\\''c'");
        // Round-trips through the classifier as one command over two arguments.
        assert_eq!(
            commands::words(&undo.inverse),
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
        assert_eq!(undo.inverse, "setenforce 1");
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
            matches!(&result, UndoResult::CannotUndo(why) if why.contains("disabled")),
            "{result:?}"
        );
    }

    // ── the decorator ────────────────────────────────────────────────────────

    #[tokio::test]
    async fn the_pre_state_is_read_before_the_device_is_written_to() {
        let fake = Fake::answering(&[("getprop 'debug.foo'", "0")]);
        let backend = ReversibleBackend::new(fake.clone());

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
    async fn a_read_only_script_is_passed_through_without_a_second_round_trip() {
        let fake = Fake::answering(&[]);
        let backend = ReversibleBackend::new(fake.clone());
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
        let backend = ReversibleBackend::new(fake.clone());
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
        let backend = ReversibleBackend::new(fake.clone());
        // The first capture sees 0; after the first write the second capture sees 1, which the
        // fake cannot model from a static table — so the second read is answered explicitly.
        backend
            .exec(request_for("setprop debug.foo 1"))
            .await
            .unwrap();
        let undo_b = {
            let mut plan_b = plan("setprop debug.foo 2");
            let capture = plan_b.captures.remove(0);
            undo_for(&capture, Some("1"), &request_for("setprop debug.foo 2"))
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
            .map(|u| u.inverse.clone())
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
        let backend = ReversibleBackend::new(fake.clone());
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
        let backend = ReversibleBackend::new(fake.clone());
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
        let backend = ReversibleBackend::new(fake.clone());
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
        let backend = ReversibleBackend::new(fake.clone());
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
}
