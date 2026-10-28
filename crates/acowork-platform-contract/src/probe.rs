//! Probe discipline: what a capability claim must be backed by.
//!
//! # R4 — demonstrated, not assumed
//!
//! A capability may be declared only if the port actually observed it. This module
//! turns that from a good intention into a checkable record: every claim carries the
//! evidence that produced it, and evidence has a lifetime.
//!
//! Two consequences a port has to live with:
//!
//! - **A failed probe is not a failed capability.** Android's `getenforce` is absent
//!   on some images; that says nothing about whether the shell works. Evidence for
//!   one capability must not be inferred from the success of an unrelated probe.
//! - **Evidence goes stale.** A device can be rooted, unrooted, rebooted into a
//!   different SELinux mode, or have its storage remounted. [`Evidence::is_fresh`]
//!   exists so a long-lived node re-probes instead of trusting a boot-time answer
//!   forever.
//!
//! # Why evidence is recorded at all
//!
//! Because R9 requires a gap to be explained, and an explanation without evidence is
//! a guess. "Not rooted" is only a useful thing to tell the model if the port
//! actually tried to escalate and saw what happened.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;
use core::time::Duration;

use serde::{Deserialize, Serialize};

/// What the port observed when it probed for a capability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvidenceKind {
    /// A command ran and its exit status / output demonstrated the capability.
    Observed {
        /// A short, identifier-free description of what was run, e.g.
        /// `su -c id`. Kept short on purpose: this is not a place to stash raw
        /// output, which R13 keeps off the wire.
        what: String,
        /// The exit status, if the platform has one.
        status: Option<i32>,
    },
    /// A static fact about the device implies the capability, e.g. a build-type
    /// field or a filesystem type. Weaker than `Observed`: it says what the device
    /// *is*, not what it *did*.
    Inferred {
        /// The fact relied on, e.g. `ro.build.type=userdebug`.
        fact: String,
    },
    /// The port tried and was refused. This is the evidence that powers a useful
    /// [`crate::feedback`] message — a denial is more informative than an absence.
    Denied {
        /// Why it was refused, in the platform's own terms, e.g.
        /// `selinux:enforcing` or `su:not-found`.
        reason: String,
    },
    /// The probe could not run at all: no such command, timed out, unreadable.
    /// Distinct from `Denied` because it carries no information about permission.
    Inconclusive {
        /// What went wrong, e.g. `timeout` or `enoent`.
        reason: String,
    },
}

impl EvidenceKind {
    /// True when this evidence can support a positive capability claim.
    ///
    /// `Denied` and `Inconclusive` cannot: they explain an absence, they do not
    /// demonstrate a presence. A port that declared a capability on the strength of
    /// a denial would be claiming exactly the thing it failed to do.
    pub fn supports_claim(&self) -> bool {
        matches!(
            self,
            EvidenceKind::Observed { .. } | EvidenceKind::Inferred { .. }
        )
    }

    /// True when this evidence explains why a capability is absent.
    pub fn explains_absence(&self) -> bool {
        matches!(
            self,
            EvidenceKind::Denied { .. } | EvidenceKind::Inconclusive { .. }
        )
    }
}

/// One probe result, with the time it was taken.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence {
    /// What was observed.
    pub kind: EvidenceKind,
    /// How long ago, relative to the node's own clock. A port that cannot tell time
    /// (many embedded targets) uses `None`, which means "never expires" — and then
    /// the port is responsible for re-probing on whatever event invalidates it.
    pub age: Option<Duration>,
}

impl Evidence {
    /// Evidence taken just now.
    pub fn now(kind: EvidenceKind) -> Evidence {
        Evidence {
            kind,
            age: Some(Duration::ZERO),
        }
    }

    /// Evidence with no meaningful timestamp.
    pub fn undated(kind: EvidenceKind) -> Evidence {
        Evidence { kind, age: None }
    }

    /// Whether this evidence is still young enough to trust.
    ///
    /// `max_age` comes from the port's own policy; the contract does not pick a
    /// number, because "how long until a rooted device might not be" is a platform
    /// question. Undated evidence never expires by this rule.
    pub fn is_fresh(&self, max_age: Duration) -> bool {
        match self.age {
            None => true,
            Some(age) => age <= max_age,
        }
    }

    /// Whether this evidence can support a positive claim right now.
    pub fn can_support_claim(&self, max_age: Duration) -> bool {
        self.kind.supports_claim() && self.is_fresh(max_age)
    }
}

/// One capability claim and the evidence behind it.
///
/// This is the unit a port hands to [`crate::capability::CapabilityTable::declare`].
/// Keeping claim and evidence together is what makes R4 auditable: you can always
/// ask *why* a device says it has something.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityClaim {
    /// The capability being claimed.
    pub capability: crate::capability::HostCapability,
    /// The evidence for it.
    pub evidence: Evidence,
}

/// The outcome of validating a set of claims against a vocabulary.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ClaimAudit {
    /// Claims accepted: registered, supported by evidence, and fresh.
    pub accepted: Vec<String>,
    /// Claims rejected because the ID is not in the vocabulary (R5).
    pub unregistered: Vec<String>,
    /// Claims rejected because the evidence was a denial or inconclusive (R4).
    pub unsupported: Vec<String>,
    /// Claims rejected because the evidence had gone stale (R4).
    pub stale: Vec<String>,
}

impl ClaimAudit {
    /// True when nothing was rejected.
    pub fn is_clean(&self) -> bool {
        self.unregistered.is_empty() && self.unsupported.is_empty() && self.stale.is_empty()
    }

    /// Every rejection, as a human-readable line (R9).
    pub fn rejections(&self) -> Vec<String> {
        let mut out = Vec::new();
        for id in &self.unregistered {
            out.push(alloc::format!("{id}: not in this platform's vocabulary"));
        }
        for id in &self.unsupported {
            out.push(alloc::format!("{id}: probe did not demonstrate it"));
        }
        for id in &self.stale {
            out.push(alloc::format!(
                "{id}: evidence is older than the re-probe interval"
            ));
        }
        out
    }
}

impl fmt::Display for ClaimAudit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} accepted, {} rejected",
            self.accepted.len(),
            self.unregistered.len() + self.unsupported.len() + self.stale.len()
        )
    }
}

/// Validate claims against a vocabulary and fold the survivors into a table.
///
/// This is the single place R4 and R5 are enforced together, so a port cannot
/// satisfy one and forget the other. It returns the audit rather than panicking:
/// a rejected claim is a normal outcome (the device simply lacks something), and the
/// audit is what makes it explainable.
pub fn audit_claims(
    table: &mut crate::capability::CapabilityTable,
    claims: &[CapabilityClaim],
    max_age: Duration,
) -> ClaimAudit {
    let mut audit = ClaimAudit::default();
    for claim in claims {
        let id = claim.capability.as_str().to_string();
        if table.spec(&claim.capability).is_none() {
            audit.unregistered.push(id);
            continue;
        }
        if !claim.evidence.kind.supports_claim() {
            audit.unsupported.push(id);
            continue;
        }
        if !claim.evidence.is_fresh(max_age) {
            audit.stale.push(id);
            continue;
        }
        // Registered and supported: the declare call cannot fail here, because the
        // spec lookup above already established membership.
        let _ = table.declare(claim.capability.clone());
        audit.accepted.push(id);
    }
    audit.accepted.sort();
    audit.unregistered.sort();
    audit.unsupported.sort();
    audit.stale.sort();
    audit
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::{CapabilitySpec, CapabilityTable, HostCapability};

    fn cap(name: &str) -> HostCapability {
        HostCapability::parse(&alloc::format!("fake:{name}")).unwrap()
    }

    fn table() -> CapabilityTable {
        CapabilityTable::new(
            "fake",
            vec![
                CapabilitySpec::read_only(cap("thing:read")),
                CapabilitySpec::read_only(cap("thing:write")),
            ],
        )
        .unwrap()
    }

    #[test]
    fn observed_and_inferred_evidence_supports_a_claim() {
        assert!(
            EvidenceKind::Observed {
                what: "id".into(),
                status: Some(0)
            }
            .supports_claim()
        );
        assert!(
            EvidenceKind::Inferred {
                fact: "ro.build.type=userdebug".into()
            }
            .supports_claim()
        );
    }

    #[test]
    fn a_denial_never_supports_a_claim() {
        // R4: claiming a capability because you were refused it would be claiming
        // exactly what you failed to do.
        let denied = EvidenceKind::Denied {
            reason: "selinux:enforcing".into(),
        };
        assert!(!denied.supports_claim());
        assert!(denied.explains_absence());
    }

    #[test]
    fn an_inconclusive_probe_never_supports_a_claim() {
        // A missing `getenforce` says nothing about whether the shell works.
        let inc = EvidenceKind::Inconclusive {
            reason: "enoent".into(),
        };
        assert!(!inc.supports_claim());
        assert!(inc.explains_absence());
    }

    #[test]
    fn evidence_goes_stale() {
        let e = Evidence {
            kind: EvidenceKind::Observed {
                what: "id".into(),
                status: Some(0),
            },
            age: Some(Duration::from_secs(3600)),
        };
        assert!(e.is_fresh(Duration::from_secs(7200)));
        assert!(!e.is_fresh(Duration::from_secs(1800)));
        assert!(!e.can_support_claim(Duration::from_secs(1800)));
    }

    #[test]
    fn undated_evidence_never_expires_by_age() {
        // A target with no clock opts out of the age rule and takes responsibility
        // for re-probing on invalidating events instead.
        let e = Evidence::undated(EvidenceKind::Inferred {
            fact: "efuse:blank".into(),
        });
        assert!(e.is_fresh(Duration::from_secs(1)));
        assert!(e.can_support_claim(Duration::from_secs(1)));
    }

    #[test]
    fn audit_accepts_supported_registered_claims() {
        let mut t = table();
        let audit = audit_claims(
            &mut t,
            &[CapabilityClaim {
                capability: cap("thing:read"),
                evidence: Evidence::now(EvidenceKind::Observed {
                    what: "ls".into(),
                    status: Some(0),
                }),
            }],
            Duration::from_secs(3600),
        );
        assert!(audit.is_clean());
        assert_eq!(audit.accepted, vec!["fake:thing:read"]);
        assert!(t.is_declared(&cap("thing:read")));
    }

    #[test]
    fn audit_rejects_an_unregistered_claim() {
        let mut t = table();
        let audit = audit_claims(
            &mut t,
            &[CapabilityClaim {
                capability: cap("thing:delete"),
                evidence: Evidence::now(EvidenceKind::Observed {
                    what: "rm".into(),
                    status: Some(0),
                }),
            }],
            Duration::from_secs(3600),
        );
        assert_eq!(audit.unregistered, vec!["fake:thing:delete"]);
        assert!(!audit.is_clean());
        assert!(t.declared().is_empty());
    }

    #[test]
    fn audit_rejects_a_claim_backed_by_a_denial() {
        let mut t = table();
        let audit = audit_claims(
            &mut t,
            &[CapabilityClaim {
                capability: cap("thing:write"),
                evidence: Evidence::now(EvidenceKind::Denied {
                    reason: "ro-filesystem".into(),
                }),
            }],
            Duration::from_secs(3600),
        );
        assert_eq!(audit.unsupported, vec!["fake:thing:write"]);
        assert!(t.declared().is_empty());
    }

    #[test]
    fn audit_rejects_stale_evidence() {
        let mut t = table();
        let audit = audit_claims(
            &mut t,
            &[CapabilityClaim {
                capability: cap("thing:read"),
                evidence: Evidence {
                    kind: EvidenceKind::Observed {
                        what: "ls".into(),
                        status: Some(0),
                    },
                    age: Some(Duration::from_secs(86_400)),
                },
            }],
            Duration::from_secs(3600),
        );
        assert_eq!(audit.stale, vec!["fake:thing:read"]);
        assert!(t.declared().is_empty());
    }

    #[test]
    fn audit_separates_the_three_rejection_reasons() {
        let mut t = table();
        let audit = audit_claims(
            &mut t,
            &[
                CapabilityClaim {
                    capability: cap("thing:read"),
                    evidence: Evidence::now(EvidenceKind::Observed {
                        what: "ls".into(),
                        status: Some(0),
                    }),
                },
                CapabilityClaim {
                    capability: cap("thing:delete"),
                    evidence: Evidence::now(EvidenceKind::Observed {
                        what: "rm".into(),
                        status: Some(0),
                    }),
                },
                CapabilityClaim {
                    capability: cap("thing:write"),
                    evidence: Evidence::now(EvidenceKind::Inconclusive {
                        reason: "timeout".into(),
                    }),
                },
            ],
            Duration::from_secs(3600),
        );
        assert_eq!(audit.accepted, vec!["fake:thing:read"]);
        assert_eq!(audit.unregistered, vec!["fake:thing:delete"]);
        assert_eq!(audit.unsupported, vec!["fake:thing:write"]);
        assert_eq!(audit.to_string(), "1 accepted, 2 rejected");
    }

    #[test]
    fn rejection_lines_are_actionable() {
        // R9: each line says what to do about it, not just that it failed.
        let mut t = table();
        let audit = audit_claims(
            &mut t,
            &[CapabilityClaim {
                capability: cap("thing:write"),
                evidence: Evidence::now(EvidenceKind::Denied {
                    reason: "ro".into(),
                }),
            }],
            Duration::from_secs(3600),
        );
        let lines = audit.rejections();
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("fake:thing:write"));
        assert!(lines[0].contains("did not demonstrate"));
    }

    #[test]
    fn audit_is_deterministic_regardless_of_claim_order() {
        let a = {
            let mut t = table();
            audit_claims(
                &mut t,
                &[
                    CapabilityClaim {
                        capability: cap("thing:read"),
                        evidence: Evidence::now(EvidenceKind::Observed {
                            what: "ls".into(),
                            status: Some(0),
                        }),
                    },
                    CapabilityClaim {
                        capability: cap("thing:write"),
                        evidence: Evidence::now(EvidenceKind::Observed {
                            what: "touch".into(),
                            status: Some(0),
                        }),
                    },
                ],
                Duration::from_secs(3600),
            )
        };
        let b = {
            let mut t = table();
            audit_claims(
                &mut t,
                &[
                    CapabilityClaim {
                        capability: cap("thing:write"),
                        evidence: Evidence::now(EvidenceKind::Observed {
                            what: "touch".into(),
                            status: Some(0),
                        }),
                    },
                    CapabilityClaim {
                        capability: cap("thing:read"),
                        evidence: Evidence::now(EvidenceKind::Observed {
                            what: "ls".into(),
                            status: Some(0),
                        }),
                    },
                ],
                Duration::from_secs(3600),
            )
        };
        assert_eq!(a, b);
    }
}
