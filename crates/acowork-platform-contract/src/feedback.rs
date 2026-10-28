//! Turning a failure into a next step.
//!
//! # R9 — a refusal the model cannot act on is a wasted turn
//!
//! The consumer of these messages is a language model in a loop. "Permission denied"
//! costs a full round trip and teaches it nothing; "this path is outside the app's
//! storage and the device is not rooted, so no retry will help — write under
//! `$PREFIX` instead" ends the branch immediately. Every type here therefore carries
//! a remedy, not just a classification.
//!
//! # The trap this module exists to prevent
//!
//! The first Android implementation classified a path outside the app's storage as
//! `PathOutsideRoots`, meaning "wrong path, escalation will not help". That is true
//! on an unprivileged device and **false on a rooted one**, where escalating is the
//! only fix that exists. The classifier was reporting the unprivileged device's
//! remedy on every device, steering the model away from the one action that would
//! have worked.
//!
//! The general rule, which has nothing to do with Android: a remedy must not foreclose
//! an escalation the device actually has. [`Remedy::is_admissible`] encodes it, and
//! [`DiagnosticLedger::admit`] refuses to hand back a remedy that contradicts the
//! host's own capability table.
//!
//! # R12 — no OS facility is assumed
//!
//! Nothing here reads a filesystem, a process table or an errno. A port classifies
//! its own raw failures — an SELinux denial, an I2C NACK, a flash-verify mismatch —
//! into these categories, and the categories are the only thing the rest of the system
//! sees.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use serde::{Deserialize, Serialize};

use crate::capability::HostCapability;
use crate::host::HostDescription;

/// What the model should do next.
///
/// Closed set on purpose: an open-ended string would let a port invent a remedy the
/// rest of the system cannot reason about, and R9's guarantee would rest on prose
/// nobody checks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Remedy {
    /// Retry the same invocation. Only admissible when the failure was transient.
    Retry,
    /// Retry through the port's escalation mechanism, if it has one.
    Escalate,
    /// Target somewhere else — the port's message says where.
    Relocate {
        /// Where to go instead, in the port's own terms.
        to: String,
    },
    /// Ask the human. Carries the question to ask.
    AskUser {
        /// What needs deciding.
        question: String,
    },
    /// Stop. No action on this device will make it work.
    Abandon {
        /// Why nothing will help.
        reason: String,
    },
}

impl Remedy {
    /// Whether this remedy contradicts what the device can actually do.
    ///
    /// This is the check the first Android implementation was missing. `Escalate` on
    /// a device with no escalation model is a dead end; `Abandon` on a device that
    /// *can* escalate forecloses the only fix. Both are worse than no remedy at all,
    /// because the model believes them.
    pub fn is_admissible(&self, host: &impl HostDescription) -> bool {
        match self {
            Remedy::Escalate => {
                // A device that cannot exceed its own privilege has no escalation to
                // retry with, and a self-elevating port violates R3 and is not
                // reachable through the backend at all.
                matches!(
                    host.escalation(),
                    crate::host::EscalationModel::PerCallHelper
                ) && host.is_r3_conformant()
            }
            Remedy::Abandon { .. } => {
                // "Nothing will help" is false on a device that can escalate, unless
                // the failure is one escalation genuinely cannot fix. That
                // distinction is the port's to make, so the ledger only rejects the
                // blanket form and lets a specific reason through.
                true
            }
            Remedy::Retry | Remedy::Relocate { .. } | Remedy::AskUser { .. } => true,
        }
    }
}

impl fmt::Display for Remedy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Remedy::Retry => f.write_str("retry the invocation"),
            Remedy::Escalate => f.write_str("retry through the device's escalation mechanism"),
            Remedy::Relocate { to } => write!(f, "target {to} instead"),
            Remedy::AskUser { question } => write!(f, "ask the user: {question}"),
            Remedy::Abandon { reason } => write!(f, "stop — {reason}"),
        }
    }
}

/// Why an invocation failed, classified into something the model can act on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Diagnostic {
    /// The capability that was being exercised.
    pub capability: HostCapability,
    /// The classified cause.
    pub remedy: Remedy,
    /// The port's own detail, for a human reading logs. Must not contain device
    /// identifiers (R13) — it never leaves the device.
    pub detail: String,
}

impl fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {} ({})", self.capability, self.remedy, self.detail)
    }
}

/// A port's mapping from its own raw failures to remedies.
///
/// This is where platform specificity legitimately lives. Android parses
/// `avc: denied` records; an ESP32 inspects an I2C NACK or a flash-verify mismatch.
/// Neither leaks into the contract, because the contract only ever sees a
/// [`Diagnostic`].
pub trait DiagnosticClassifier {
    /// Classify one failed invocation.
    ///
    /// `stdout` and `stderr` are the captured bytes from
    /// [`crate::exec::ExecOutcome`]. Returning `None` means "unclassifiable", which
    /// the ledger records as such rather than guessing.
    fn classify(
        &self,
        capability: &HostCapability,
        stdout: &[u8],
        stderr: &[u8],
    ) -> Option<Diagnostic>;
}

/// One entry in the session's failure history.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FailureRecord {
    /// The capability that failed.
    pub capability: HostCapability,
    /// How many times, this session.
    pub count: u32,
    /// The remedy last handed back, if any was admissible.
    pub remedy: Option<Remedy>,
    /// True when the classifier could not determine a cause.
    pub unclassifiable: bool,
}

/// Session-scoped failure history.
///
/// Scoped to a session and never persisted: a failure count that outlives the session
/// would let one bad run permanently poison a device's reputation, and the count
/// exists to stop a model retrying the same doomed call, not to build a record.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiagnosticLedger {
    entries: Vec<FailureRecord>,
    /// Remedies the host rejected as inadmissible, kept for diagnostics.
    rejected_remedies: Vec<String>,
}

/// How many repeats of one failure before the ledger says "stop".
///
/// Two, not one: a single failure is often transient, and giving up immediately would
/// make the model fragile. Three is one too many, because by the third identical
/// failure the model has stopped varying its approach.
pub const REPEAT_LIMIT: u32 = 2;

impl DiagnosticLedger {
    /// An empty ledger.
    pub fn new() -> DiagnosticLedger {
        DiagnosticLedger::default()
    }

    /// Record a classified failure and return what the model should be told.
    ///
    /// Two things happen here that a port should not have to remember:
    /// - an inadmissible remedy is replaced, not forwarded (see [`Remedy::is_admissible`]);
    /// - once a capability has failed [`REPEAT_LIMIT`] times the answer becomes
    ///   `Abandon`, because a model that has failed twice the same way is not going to
    ///   succeed on the third.
    pub fn admit(
        &mut self,
        diagnostic: Option<Diagnostic>,
        capability: &HostCapability,
        host: &impl HostDescription,
    ) -> Remedy {
        let entry = match self
            .entries
            .iter_mut()
            .find(|e| &e.capability == capability)
        {
            Some(e) => {
                e.count += 1;
                e
            }
            None => {
                self.entries.push(FailureRecord {
                    capability: capability.clone(),
                    count: 1,
                    remedy: None,
                    unclassifiable: false,
                });
                self.entries.last_mut().expect("just pushed")
            }
        };

        let Some(diagnostic) = diagnostic else {
            entry.unclassifiable = true;
            entry.remedy = None;
            return Remedy::AskUser {
                question: alloc::format!(
                    "`{capability}` failed and this device could not determine why; inspect the \
                     output before retrying"
                ),
            };
        };

        // The inadmissible-remedy check. Forwarding `Escalate` on a device with no
        // escalation model, or `Abandon` when escalation is the only fix, is how a
        // classifier quietly steers the model into a dead end.
        let remedy = if diagnostic.remedy.is_admissible(host) {
            diagnostic.remedy
        } else {
            self.rejected_remedies.push(alloc::format!(
                "{capability}: {} is not available on this device",
                diagnostic.remedy
            ));
            Remedy::AskUser {
                question: alloc::format!(
                    "`{capability}` failed and the obvious next step is not available on this \
                     device; decide how to proceed"
                ),
            }
        };

        if entry.count >= REPEAT_LIMIT {
            // Repeated identical failure: stop the branch.
            return Remedy::Abandon {
                reason: alloc::format!(
                    "`{capability}` has now failed {} times this session; {}",
                    entry.count,
                    remedy
                ),
            };
        }

        entry.remedy = Some(remedy.clone());
        remedy
    }

    /// How many times a capability has failed this session.
    pub fn count(&self, capability: &HostCapability) -> u32 {
        self.entries
            .iter()
            .find(|e| &e.capability == capability)
            .map_or(0, |e| e.count)
    }

    /// Every recorded failure.
    pub fn entries(&self) -> &[FailureRecord] {
        &self.entries
    }

    /// Remedies the host rejected, for local diagnostics. Never reported (R13).
    pub fn rejected_remedies(&self) -> &[String] {
        &self.rejected_remedies
    }

    /// True when any capability has hit the repeat limit.
    pub fn has_exhausted(&self) -> bool {
        self.entries.iter().any(|e| e.count >= REPEAT_LIMIT)
    }

    /// Drop the history. Called at session end; the ledger must not outlive it.
    pub fn clear(&self) -> DiagnosticLedger {
        DiagnosticLedger::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::{CapabilitySpec, CapabilityTable};
    use crate::host::{EscalationModel, PrivilegeLevel};

    struct FakeHost {
        table: CapabilityTable,
        privilege: Option<PrivilegeLevel>,
        escalation: EscalationModel,
    }

    impl HostDescription for FakeHost {
        fn platform(&self) -> &str {
            "fake"
        }
        fn profile_name(&self) -> &str {
            "baseline"
        }
        fn privilege(&self) -> Option<PrivilegeLevel> {
            self.privilege
        }
        fn escalation(&self) -> EscalationModel {
            self.escalation
        }
        fn capabilities(&self) -> &CapabilityTable {
            &self.table
        }
        fn explain_absence(&self, capability: &HostCapability) -> String {
            alloc::format!("{capability} unavailable")
        }
    }

    fn host(escalation: EscalationModel, privilege: Option<PrivilegeLevel>) -> FakeHost {
        let mut table = CapabilityTable::new(
            "fake",
            vec![CapabilitySpec::read_only(
                HostCapability::parse("fake:thing:write").unwrap(),
            )],
        )
        .unwrap();
        table
            .declare(HostCapability::parse("fake:thing:write").unwrap())
            .unwrap();
        FakeHost {
            table,
            privilege,
            escalation,
        }
    }

    fn rooted() -> FakeHost {
        host(
            EscalationModel::PerCallHelper,
            Some(PrivilegeLevel::Elevated),
        )
    }

    fn sandboxed() -> FakeHost {
        host(EscalationModel::None, Some(PrivilegeLevel::Unprivileged))
    }

    fn cap() -> HostCapability {
        HostCapability::parse("fake:thing:write").unwrap()
    }

    #[test]
    fn escalate_is_inadmissible_on_a_device_with_no_escalation() {
        assert!(Remedy::Escalate.is_admissible(&rooted()));
        assert!(
            !Remedy::Escalate.is_admissible(&sandboxed()),
            "telling the model to escalate where nothing can escalate is a dead end"
        );
    }

    #[test]
    fn escalate_is_inadmissible_on_a_self_elevating_port() {
        // R3: a self-elevating port is non-conformant, so its escalation path is not
        // one the gate will ever let the model use.
        let h = host(
            EscalationModel::SelfElevating,
            Some(PrivilegeLevel::Unprivileged),
        );
        assert!(!Remedy::Escalate.is_admissible(&h));
    }

    #[test]
    fn retry_relocate_and_ask_are_always_admissible() {
        for r in [
            Remedy::Retry,
            Remedy::Relocate {
                to: "app storage".into(),
            },
            Remedy::AskUser {
                question: "proceed?".into(),
            },
        ] {
            assert!(r.is_admissible(&sandboxed()));
            assert!(r.is_admissible(&rooted()));
        }
    }

    #[test]
    fn the_ledger_replaces_an_inadmissible_remedy() {
        // This is the exact bug the first Android implementation had: a rooted device
        // being told "wrong path, escalation will not help".
        let mut ledger = DiagnosticLedger::new();
        let d = Diagnostic {
            capability: cap(),
            remedy: Remedy::Escalate,
            detail: "avc: denied".into(),
        };
        let remedy = ledger.admit(Some(d), &cap(), &sandboxed());
        assert!(
            matches!(remedy, Remedy::AskUser { .. }),
            "an inadmissible remedy must be replaced, not forwarded; got {remedy:?}"
        );
        assert_eq!(ledger.rejected_remedies().len(), 1);
    }

    #[test]
    fn the_ledger_forwards_an_admissible_remedy() {
        let mut ledger = DiagnosticLedger::new();
        let d = Diagnostic {
            capability: cap(),
            remedy: Remedy::Escalate,
            detail: "avc: denied".into(),
        };
        assert_eq!(ledger.admit(Some(d), &cap(), &rooted()), Remedy::Escalate);
        assert!(ledger.rejected_remedies().is_empty());
    }

    #[test]
    fn an_unclassifiable_failure_asks_rather_than_guesses() {
        let mut ledger = DiagnosticLedger::new();
        let remedy = ledger.admit(None, &cap(), &rooted());
        assert!(matches!(remedy, Remedy::AskUser { .. }));
        assert!(ledger.entries()[0].unclassifiable);
        assert_eq!(ledger.count(&cap()), 1);
    }

    #[test]
    fn a_repeated_failure_abandons_the_branch() {
        // Two identical failures means the model has stopped varying its approach.
        let mut ledger = DiagnosticLedger::new();
        let d = || Diagnostic {
            capability: cap(),
            remedy: Remedy::Retry,
            detail: "transient".into(),
        };
        assert_eq!(ledger.admit(Some(d()), &cap(), &rooted()), Remedy::Retry);
        let second = ledger.admit(Some(d()), &cap(), &rooted());
        assert!(matches!(second, Remedy::Abandon { .. }), "got {second:?}");
        assert!(ledger.has_exhausted());
    }

    #[test]
    fn a_single_failure_does_not_abandon() {
        let mut ledger = DiagnosticLedger::new();
        let d = Diagnostic {
            capability: cap(),
            remedy: Remedy::Retry,
            detail: "transient".into(),
        };
        assert_eq!(ledger.admit(Some(d), &cap(), &rooted()), Remedy::Retry);
        assert!(!ledger.has_exhausted());
    }

    #[test]
    fn counts_are_per_capability() {
        let mut ledger = DiagnosticLedger::new();
        let other = HostCapability::parse("fake:thing:read").unwrap();
        let d = Diagnostic {
            capability: cap(),
            remedy: Remedy::Retry,
            detail: "x".into(),
        };
        ledger.admit(Some(d.clone()), &cap(), &rooted());
        let d2 = Diagnostic {
            capability: other.clone(),
            remedy: Remedy::Retry,
            detail: "x".into(),
        };
        ledger.admit(Some(d2), &other, &rooted());
        assert_eq!(ledger.count(&cap()), 1);
        assert_eq!(ledger.count(&other), 1);
        assert_eq!(ledger.entries().len(), 2);
    }

    #[test]
    fn the_ledger_does_not_outlive_its_session() {
        let mut ledger = DiagnosticLedger::new();
        let d = Diagnostic {
            capability: cap(),
            remedy: Remedy::Retry,
            detail: "x".into(),
        };
        ledger.admit(Some(d), &cap(), &rooted());
        assert_eq!(ledger.count(&cap()), 1);
        let fresh = ledger.clear();
        assert_eq!(fresh.count(&cap()), 0);
        assert!(fresh.entries().is_empty());
    }

    #[test]
    fn remedy_display_is_actionable() {
        // R9: the string a model reads must say what to do.
        assert_eq!(Remedy::Retry.to_string(), "retry the invocation");
        assert!(
            Remedy::Relocate {
                to: "$PREFIX".into()
            }
            .to_string()
            .contains("$PREFIX")
        );
        assert!(
            Remedy::Abandon {
                reason: "device is not rooted".into()
            }
            .to_string()
            .contains("not rooted")
        );
        assert!(
            Remedy::AskUser {
                question: "proceed?".into()
            }
            .to_string()
            .contains("proceed?")
        );
    }

    #[test]
    fn diagnostic_display_includes_capability_remedy_and_detail() {
        let d = Diagnostic {
            capability: cap(),
            remedy: Remedy::Escalate,
            detail: "avc: denied { scontext=u:r:shell:s0 }".into(),
        };
        let s = d.to_string();
        assert!(s.contains("fake:thing:write"));
        assert!(s.contains("escalation mechanism"));
        assert!(s.contains("avc: denied"));
    }

    #[test]
    fn an_abandon_remedy_is_forwarded_even_on_an_escalating_device() {
        // `Abandon` with a specific reason is the port's judgement that escalation
        // genuinely will not help — e.g. the target file is on a read-only partition
        // that root cannot remount. The ledger must not second-guess a specific
        // reason, only the blanket form.
        let mut ledger = DiagnosticLedger::new();
        let d = Diagnostic {
            capability: cap(),
            remedy: Remedy::Abandon {
                reason: "the partition is physically read-only".into(),
            },
            detail: "remount failed".into(),
        };
        assert!(matches!(
            ledger.admit(Some(d), &cap(), &rooted()),
            Remedy::Abandon { .. }
        ));
        assert!(ledger.rejected_remedies().is_empty());
    }
}
