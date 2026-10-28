//! The gate: one place where the two authorities are composed.
//!
//! # R7 — two authorities, one composition point
//!
//! Upstream ADR-087 puts ownership truth in the control plane's `node_owners.json`
//! and forbids the runtime from learning who anyone is. ADR-AND-001 §7.4 puts the
//! final decision on the device, and §7.1 forbids the control plane from making it.
//! Read literally, those two documents close every path.
//!
//! They stop conflicting once the question is split:
//!
//! - **Attribution** — *is this session allowed to touch this device at all?* That is
//!   an ownership question, the control plane owns the data, and the device cannot
//!   answer it. It sends an [`AttributionVerdict`]: a boolean plus a tier, and
//!   nothing else.
//! - **Readiness** — *can this device do it right now?* That is a local question:
//!   is the capability declared, is the dangerous-mode switch on, is the resource
//!   lock free. The control plane cannot answer it, because it does not have the
//!   probe facts.
//!
//! Neither authority can produce a decision alone, and the conjunction happens here,
//! on the device. That satisfies §7.4 — the device makes the call — without
//! violating ADR-087, because a boolean verdict is not an identity. The node never
//! learns *who* was authorised, only *that* it was.
//!
//! # R6 — no platform branch appears below this line
//!
//! Every rule reads the [`CapabilitySpec`] the port registered. There is no
//! `if platform == "android"` anywhere in this file, and adding one would be the bug:
//! it would mean a new platform can change how authorization works, which is exactly
//! what "uniform rules" forbids.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;

use serde::{Deserialize, Serialize};

use crate::capability::{AttributionTier, CapabilitySpec, HostCapability};
use crate::exec::GateView;
use crate::host::{HostDescription, PrivilegeLevel};

/// The control plane's answer to "may this session touch this device?".
///
/// Deliberately information-poor. There is no user id, no owner name, no role string
/// — a verdict, and the tier it was issued for. Anything richer would make the node
/// aware of users, which ADR-087 D1/D5 forbids and which would also give a compromised
/// device something worth exfiltrating.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttributionVerdict {
    /// Whether the control plane authorised this session for the requested tier.
    pub granted: bool,
    /// The tier the verdict was issued against, so a verdict cannot be replayed
    /// against a higher one.
    pub tier: AttributionTier,
}

impl AttributionVerdict {
    /// A granted verdict for `tier`.
    pub fn granted_for(tier: AttributionTier) -> AttributionVerdict {
        AttributionVerdict {
            granted: true,
            tier,
        }
    }

    /// A denied verdict for `tier`.
    pub fn denied_for(tier: AttributionTier) -> AttributionVerdict {
        AttributionVerdict {
            granted: false,
            tier,
        }
    }

    /// Whether this verdict covers `required`.
    ///
    /// A verdict is scoped to the tier it was issued for. Requiring a match stops a
    /// `use`-tier verdict from being presented for a `manage`-tier capability, which
    /// is the replay the opaque-boolean design would otherwise allow.
    pub fn covers(&self, required: AttributionTier) -> bool {
        self.granted && self.tier == required
    }
}

/// The device-side half of the decision: everything the control plane cannot know.
///
/// R3 is deliberately *not* a field here. The host description is the sole authority
/// on its own privilege, and letting a caller assert conformance would allow it to
/// contradict the host — which is precisely the kind of second source of truth the
/// two-authority split exists to avoid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalReadiness {
    /// The session was started with the platform's dangerous-mode switch. Never
    /// persisted — a restart must re-earn it.
    pub dangerous_session: bool,
    /// A human approved *this specific action*, and the port can prove it.
    ///
    /// The contract checks presence and nothing else. What an approval is — a token,
    /// a signed nonce, a tap on a dialog — belongs to the port, because a target with
    /// no UI may have no approval mechanism at all and would then register no
    /// `PerUse` capabilities. Keeping the payload out of the contract is also what
    /// stops a backend from inventing its own approval semantics.
    pub approval_presented: bool,
    /// Whether the device resource lock is available to this caller (R11).
    pub lock: LockState,
}

/// The lock fact the gate needs, without the gate touching the lock.
///
/// The gate is a pure decision function: it reads this and never acquires anything.
/// Acquisition belongs to the caller, for two reasons. First, only the caller knows
/// *who* is asking — ADR-AND-001 §7.2 requires a lock refusal to name the holding
/// session, and "session" is a port concept the contract has no business carrying.
/// Second, a decision function with a side effect can wedge a device on a path nobody
/// tested; a pure one cannot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LockState {
    /// Free, or already held by this caller.
    Available,
    /// Held by another caller. Carries how long until the TTL frees it, so the
    /// refusal can tell the model when to come back.
    Busy {
        /// How long to wait before retrying.
        retry_after: core::time::Duration,
    },
}

impl LockState {
    /// True when this caller may proceed.
    pub fn is_available(&self) -> bool {
        matches!(self, LockState::Available)
    }
}

impl LocalReadiness {
    /// Readiness for a read-only invocation: nothing to switch on, nothing to lock.
    ///
    /// The read tier is `ApprovalRequirement::None` on every platform, so no approval
    /// is needed either.
    pub fn for_read() -> LocalReadiness {
        LocalReadiness {
            dangerous_session: false,
            approval_presented: false,
            lock: LockState::Available,
        }
    }
}

/// Why the gate refused. One variant per rule, so the message can name the rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Refusal {
    /// The capability is not in this platform's vocabulary (R5).
    Unregistered(HostCapability),
    /// The device never demonstrated it (R4).
    NotDeclared(HostCapability),
    /// The node process holds too much privilege to be trusted with it (R3).
    PrivilegeViolation {
        /// What the node runs at.
        found: PrivilegeLevel,
    },
    /// The capability needs a per-use human approval and none was presented.
    ApprovalMissing(HostCapability),
    /// The capability needs the dangerous-mode switch and the session lacks it.
    DangerousSessionRequired(HostCapability),
    /// The control plane did not authorise this session for the required tier (R7).
    AttributionDenied {
        /// The tier that was needed.
        required: AttributionTier,
    },
    /// Another invocation is mutating the device (R11).
    DeviceBusy {
        /// How long until the TTL frees it.
        retry_after: core::time::Duration,
    },
    /// The capability is irreversible and no rollback plan was given (R8).
    RollbackPlanRequired(HostCapability),
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Refusal::Unregistered(cap) => write!(
                f,
                "`{cap}` is not a capability this platform registers, so it cannot be authorized"
            ),
            Refusal::NotDeclared(cap) => write!(
                f,
                "`{cap}` is registered for this platform but this device did not demonstrate it"
            ),
            Refusal::PrivilegeViolation { found } => write!(
                f,
                "the node process runs at `{found}` privilege; it must not hold unrestricted \
                 privilege itself (escalation belongs in the backend, per call)"
            ),
            Refusal::ApprovalMissing(cap) => write!(
                f,
                "`{cap}` changes this device and needs a human approval for each use; none was \
                 presented, so ask before retrying"
            ),
            Refusal::DangerousSessionRequired(cap) => write!(
                f,
                "`{cap}` needs the session to have been started in dangerous mode; restart the \
                 session with that switch enabled"
            ),
            Refusal::AttributionDenied { required } => write!(
                f,
                "the control plane did not authorize this session for the `{required:?}` tier; \
                 this device cannot widen that verdict locally, so the session must be \
                 re-authorized before retrying"
            ),
            Refusal::DeviceBusy { retry_after } => write!(
                f,
                "another invocation is changing this device; retry in {}s (requests are not \
                 queued, because an unattended node must not accumulate a backlog)",
                retry_after.as_secs()
            ),
            Refusal::RollbackPlanRequired(cap) => write!(
                f,
                "`{cap}` cannot be undone; state how to roll it back before requesting it"
            ),
        }
    }
}

/// The gate's answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GateDecision {
    /// Run it. Carries the spec so the caller does not have to look it up again.
    Allow {
        /// The capability being exercised.
        capability: HostCapability,
        /// Whether the caller must hold the resource lock for the duration.
        hold_lock: bool,
    },
    /// Do not run it, and here is the rule that said so.
    Deny {
        /// The capability that was requested.
        capability: HostCapability,
        /// Why.
        refusal: Refusal,
    },
}

impl GateDecision {
    /// True when the invocation may proceed.
    pub fn is_allowed(&self) -> bool {
        matches!(self, GateDecision::Allow { .. })
    }

    /// The refusal, if there was one.
    pub fn refusal(&self) -> Option<&Refusal> {
        match self {
            GateDecision::Deny { refusal, .. } => Some(refusal),
            GateDecision::Allow { .. } => None,
        }
    }

    /// The human-readable reason, for the model (R9).
    pub fn explanation(&self) -> String {
        match self {
            GateDecision::Allow { capability, .. } => {
                alloc::format!("{capability} authorized")
            }
            GateDecision::Deny { refusal, .. } => refusal.to_string(),
        }
    }
}

/// The gate: a pure function from (request, verdict, readiness) to a decision.
///
/// It holds only a borrow of the port's [`HostDescription`], and it performs no side
/// effects — no lock acquisition, no clock read, no I/O. Everything it needs to know
/// arrives as an argument, which is what makes it testable without a device and safe
/// to call on any path.
pub struct Gate<'h, H: HostDescription> {
    host: &'h H,
}

impl<'h, H: HostDescription> Gate<'h, H> {
    /// A gate over a port's description.
    pub fn new(host: &'h H) -> Gate<'h, H> {
        Gate { host }
    }

    /// Decide whether `request` may run.
    ///
    /// `verdict` is the control plane's answer and may be `None` when the control
    /// plane was unreachable — which is treated as a denial for anything needing
    /// attribution, never as a pass. Failing closed on an absent authority is the
    /// only safe reading: "we could not ask" is not "yes".
    pub fn decide<R: GateView>(
        &self,
        request: &R,
        verdict: Option<AttributionVerdict>,
        readiness: LocalReadiness,
    ) -> GateDecision {
        let capability = request.capability().clone();
        let table = self.host.capabilities();

        // R5: an unregistered ID has no spec, so there are no axes to evaluate and
        // nothing to authorize against.
        let Some(spec) = table.spec(&capability) else {
            return GateDecision::Deny {
                capability: capability.clone(),
                refusal: Refusal::Unregistered(capability),
            };
        };

        // R3 first: a non-conformant node must not exercise anything mutating,
        // because the rule exists to keep the long-lived process unprivileged. The
        // host description is the only source for this — see `LocalReadiness`.
        if spec.effect.needs_lock() && !self.host.is_r3_conformant() {
            let found = self
                .host
                .privilege()
                .unwrap_or(PrivilegeLevel::Unrestricted);
            return GateDecision::Deny {
                capability,
                refusal: Refusal::PrivilegeViolation { found },
            };
        }

        // R4: registered but not demonstrated on this device.
        if !table.is_declared(&capability) {
            return GateDecision::Deny {
                capability: capability.clone(),
                refusal: Refusal::NotDeclared(capability),
            };
        }

        // R8: irreversible without a rollback plan. Checked before the lock so a
        // request that could never run does not contend for the device.
        if spec.reversibility.needs_rollback_plan() && request.rollback_plan().is_none() {
            return GateDecision::Deny {
                capability: capability.clone(),
                refusal: Refusal::RollbackPlanRequired(capability),
            };
        }

        // Axis 2: human involvement. Two independent checks, because they fail for
        // different reasons and the model fixes them differently — an approval is
        // per-action, the dangerous-mode switch is per-session.
        if spec.approval.needs_token() && !readiness.approval_presented {
            return GateDecision::Deny {
                capability: capability.clone(),
                refusal: Refusal::ApprovalMissing(capability),
            };
        }
        if spec.approval.needs_dangerous_session() && !readiness.dangerous_session {
            return GateDecision::Deny {
                capability: capability.clone(),
                refusal: Refusal::DangerousSessionRequired(capability),
            };
        }

        // Axis 3 / R7: the control plane's half.
        if spec.attribution.needs_attribution() {
            let covered = verdict.is_some_and(|v| v.covers(spec.attribution));
            if !covered {
                return GateDecision::Deny {
                    capability,
                    refusal: Refusal::AttributionDenied {
                        required: spec.attribution,
                    },
                };
            }
        }

        // Axis 1 / R11: mutating actions serialize. The gate reads the caller's
        // report; taking the lock is the caller's job, because only the caller knows
        // which session it is acting for.
        let hold_lock = spec.effect.needs_lock();
        if hold_lock && let LockState::Busy { retry_after } = readiness.lock {
            return GateDecision::Deny {
                capability,
                refusal: Refusal::DeviceBusy { retry_after },
            };
        }

        GateDecision::Allow {
            capability,
            hold_lock,
        }
    }

    /// Every capability this device could not demonstrate, with the port's own
    /// explanation (R9). This is what the model receives instead of a silent absence.
    pub fn gaps(&self) -> Vec<Gap> {
        let table = self.host.capabilities();
        table
            .specs()
            .iter()
            .filter(|spec| !table.is_declared(&spec.id))
            .map(|spec: &CapabilitySpec| Gap {
                capability: spec.id.clone(),
                reason: self.host.explain_absence(&spec.id),
            })
            .collect()
    }
}

/// A capability in the vocabulary that this device lacks, and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Gap {
    /// The capability.
    pub capability: HostCapability,
    /// The port's explanation, in terms the model can act on.
    pub reason: String,
}

impl fmt::Display for Gap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.capability, self.reason)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::{
        ApprovalRequirement, CapabilitySpec, CapabilityTable, Effect, Reversibility,
    };
    use crate::exec::{Budget, ExecOutcome, ExecutionBackend};
    use crate::host::{EscalationModel, HostDescription};

    struct TestHost {
        table: CapabilityTable,
        privilege: Option<PrivilegeLevel>,
        escalation: EscalationModel,
    }

    impl HostDescription for TestHost {
        fn platform(&self) -> &str {
            "test"
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
            alloc::format!("{capability} was not demonstrated here")
        }
    }

    fn cap(name: &str) -> HostCapability {
        HostCapability::parse(&alloc::format!("test:{name}")).unwrap()
    }

    fn vocab() -> Vec<CapabilitySpec> {
        vec![
            CapabilitySpec::read_only(cap("read")),
            CapabilitySpec {
                id: cap("write"),
                effect: Effect::Mutating,
                approval: ApprovalRequirement::PerUse,
                attribution: AttributionTier::None,
                reversibility: Reversibility::Reversible,
            },
            CapabilitySpec {
                id: cap("system"),
                effect: Effect::Mutating,
                approval: ApprovalRequirement::DangerousSession,
                attribution: AttributionTier::Manage,
                reversibility: Reversibility::Irreversible,
            },
        ]
    }

    fn host(privilege: Option<PrivilegeLevel>) -> TestHost {
        let mut table = CapabilityTable::new("test", vocab()).unwrap();
        for name in ["read", "write", "system"] {
            table.declare(cap(name)).unwrap();
        }
        TestHost {
            table,
            privilege,
            escalation: EscalationModel::PerCallHelper,
        }
    }

    struct Req {
        capability: HostCapability,
        budget: Budget,
        rollback: Option<String>,
    }

    impl GateView for Req {
        fn capability(&self) -> &HostCapability {
            &self.capability
        }
        fn budget(&self) -> &Budget {
            &self.budget
        }
        fn rollback_plan(&self) -> Option<&str> {
            self.rollback.as_deref()
        }
    }

    fn req(name: &str) -> Req {
        Req {
            capability: cap(name),
            budget: Budget::unbounded(),
            rollback: None,
        }
    }

    fn ready() -> LocalReadiness {
        LocalReadiness {
            dangerous_session: true,
            approval_presented: true,
            lock: LockState::Available,
        }
    }

    fn gate(h: &TestHost) -> Gate<'_, TestHost> {
        Gate::new(h)
    }

    #[test]
    fn a_read_only_capability_needs_nothing() {
        let h = host(Some(PrivilegeLevel::Elevated));
        let g = gate(&h);
        let d = g.decide(&req("read"), None, LocalReadiness::for_read());
        assert_eq!(
            d,
            GateDecision::Allow {
                capability: cap("read"),
                hold_lock: false
            },
            "reads must stay available while another session holds the write lock"
        );
    }

    #[test]
    fn a_mutating_capability_requires_the_caller_to_hold_the_lock() {
        let h = host(Some(PrivilegeLevel::Elevated));
        let g = gate(&h);
        let d = g.decide(&req("write"), None, ready());
        assert_eq!(
            d,
            GateDecision::Allow {
                capability: cap("write"),
                hold_lock: true
            }
        );
    }

    #[test]
    fn a_second_mutating_call_is_refused_not_queued() {
        // R11: no queueing. An unattended node must not accumulate a backlog of
        // state changes against a device nobody is watching. The caller reports the
        // lock as busy; the gate's job is only to refuse and say when to come back.
        let h = host(Some(PrivilegeLevel::Elevated));
        let g = gate(&h);
        assert!(g.decide(&req("write"), None, ready()).is_allowed());

        let busy = LocalReadiness {
            lock: LockState::Busy {
                retry_after: core::time::Duration::from_secs(595),
            },
            ..ready()
        };
        let d = g.decide(&req("write"), None, busy);
        match d.refusal() {
            Some(Refusal::DeviceBusy { retry_after }) => {
                assert_eq!(*retry_after, core::time::Duration::from_secs(595))
            }
            other => panic!("expected DeviceBusy, got {other:?}"),
        }
    }

    #[test]
    fn an_unregistered_capability_is_denied() {
        let h = host(Some(PrivilegeLevel::Elevated));
        let g = gate(&h);
        let r = Req {
            capability: cap("nuke"),
            budget: Budget::unbounded(),
            rollback: None,
        };
        assert!(matches!(
            g.decide(&r, None, ready()).refusal(),
            Some(Refusal::Unregistered(_))
        ));
    }

    #[test]
    fn a_registered_but_undeclared_capability_is_denied() {
        // R4: in the vocabulary, not demonstrated on this device.
        let mut table = CapabilityTable::new("test", vocab()).unwrap();
        table.declare(cap("read")).unwrap();
        let h = TestHost {
            table,
            privilege: Some(PrivilegeLevel::Elevated),
            escalation: EscalationModel::PerCallHelper,
        };
        let g = gate(&h);
        assert!(matches!(
            g.decide(&req("write"), None, ready()).refusal(),
            Some(Refusal::NotDeclared(_))
        ));
    }

    #[test]
    fn r3_blocks_mutating_work_on_a_privileged_node() {
        // The node process must not itself be unrestricted.
        let h = host(Some(PrivilegeLevel::Unrestricted));
        let g = gate(&h);
        assert!(matches!(
            g.decide(&req("write"), None, ready()).refusal(),
            Some(Refusal::PrivilegeViolation {
                found: PrivilegeLevel::Unrestricted
            })
        ));
        // Reads still work: R3 is about not *holding* privilege, not about being useless.
        assert!(
            g.decide(&req("read"), None, LocalReadiness::for_read())
                .is_allowed()
        );
    }

    #[test]
    fn r3_blocks_self_elevating_ports() {
        let mut h = host(Some(PrivilegeLevel::Unprivileged));
        h.escalation = EscalationModel::SelfElevating;
        let g = gate(&h);
        assert!(matches!(
            g.decide(&req("write"), None, ready()).refusal(),
            Some(Refusal::PrivilegeViolation { .. })
        ));
    }

    #[test]
    fn dangerous_mode_is_required_for_the_system_tier() {
        let h = host(Some(PrivilegeLevel::Elevated));
        let g = gate(&h);
        let r = LocalReadiness {
            dangerous_session: false,
            approval_presented: true,
            lock: LockState::Available,
        };
        let sys = Req {
            capability: cap("system"),
            budget: Budget::unbounded(),
            rollback: Some("restore image".into()),
        };
        assert!(matches!(
            g.decide(
                &sys,
                Some(AttributionVerdict::granted_for(AttributionTier::Manage)),
                r
            )
            .refusal(),
            Some(Refusal::DangerousSessionRequired(_))
        ));
    }

    #[test]
    fn a_per_use_capability_needs_an_approval() {
        // Axis 2 was declared but not enforced until this check existed: a capability
        // can be `PerUse` and still run with no human in the loop, which is the whole
        // thing `PerUse` is supposed to prevent.
        let h = host(Some(PrivilegeLevel::Elevated));
        let g = gate(&h);
        let mut r = ready();
        r.approval_presented = false;
        assert!(matches!(
            g.decide(&req("write"), None, r).refusal(),
            Some(Refusal::ApprovalMissing(_))
        ));
    }

    #[test]
    fn the_read_tier_needs_no_approval() {
        let h = host(Some(PrivilegeLevel::Elevated));
        let g = gate(&h);
        // `for_read` presents no approval and no dangerous-mode switch, and must
        // still pass: the read tier is `ApprovalRequirement::None` everywhere.
        assert!(
            g.decide(&req("read"), None, LocalReadiness::for_read())
                .is_allowed()
        );
    }

    #[test]
    fn a_missing_approval_is_named_before_a_missing_switch() {
        // Both are absent; the approval is the cheaper fix, so it is the one reported.
        let h = host(Some(PrivilegeLevel::Elevated));
        let g = gate(&h);
        let r = LocalReadiness {
            dangerous_session: false,
            approval_presented: false,
            lock: LockState::Available,
        };
        let sys = Req {
            capability: cap("system"),
            budget: Budget::unbounded(),
            rollback: Some("reflash".to_string()),
        };
        assert!(matches!(
            g.decide(&sys, None, r).refusal(),
            Some(Refusal::ApprovalMissing(_))
        ));
    }

    #[test]
    fn attribution_is_required_for_the_manage_tier() {
        // R7: the control plane's half. No verdict means no pass.
        let h = host(Some(PrivilegeLevel::Elevated));
        let g = gate(&h);
        let sys = Req {
            capability: cap("system"),
            budget: Budget::unbounded(),
            rollback: Some("restore image".into()),
        };
        assert!(matches!(
            g.decide(&sys, None, ready()).refusal(),
            Some(Refusal::AttributionDenied {
                required: AttributionTier::Manage
            })
        ));
        assert!(matches!(
            g.decide(
                &sys,
                Some(AttributionVerdict::denied_for(AttributionTier::Manage)),
                ready()
            )
            .refusal(),
            Some(Refusal::AttributionDenied { .. })
        ));
    }

    #[test]
    fn a_lower_tier_verdict_does_not_satisfy_a_higher_tier_capability() {
        // The replay the opaque-boolean design would otherwise allow.
        let h = host(Some(PrivilegeLevel::Elevated));
        let g = gate(&h);
        let sys = Req {
            capability: cap("system"),
            budget: Budget::unbounded(),
            rollback: Some("restore image".into()),
        };
        assert!(matches!(
            g.decide(
                &sys,
                Some(AttributionVerdict::granted_for(AttributionTier::Use)),
                ready()
            )
            .refusal(),
            Some(Refusal::AttributionDenied {
                required: AttributionTier::Manage
            })
        ));
    }

    #[test]
    fn a_matching_verdict_satisfies_attribution() {
        let h = host(Some(PrivilegeLevel::Elevated));
        let g = gate(&h);
        let sys = Req {
            capability: cap("system"),
            budget: Budget::unbounded(),
            rollback: Some("restore image".into()),
        };
        assert!(
            g.decide(
                &sys,
                Some(AttributionVerdict::granted_for(AttributionTier::Manage)),
                ready()
            )
            .is_allowed()
        );
    }

    #[test]
    fn an_irreversible_capability_needs_a_rollback_plan() {
        // R8. Checked before the lock, so a doomed request does not contend.
        let h = host(Some(PrivilegeLevel::Elevated));
        let g = gate(&h);
        let sys = Req {
            capability: cap("system"),
            budget: Budget::unbounded(),
            rollback: None,
        };
        assert!(matches!(
            g.decide(
                &sys,
                Some(AttributionVerdict::granted_for(AttributionTier::Manage)),
                ready()
            )
            .refusal(),
            Some(Refusal::RollbackPlanRequired(_))
        ));
    }

    #[test]
    fn a_reversible_capability_needs_no_rollback_plan() {
        let h = host(Some(PrivilegeLevel::Elevated));
        let g = gate(&h);
        assert!(g.decide(&req("write"), None, ready()).is_allowed());
    }

    #[test]
    fn the_gate_is_pure_so_a_denial_cannot_wedge_the_device() {
        // Deciding twice with the same inputs gives the same answer and changes
        // nothing. This is the property that makes a refusal safe: an earlier draft
        // had the gate acquire the lock itself, so a denial on a later rule left the
        // device wedged for a full TTL.
        let h = host(Some(PrivilegeLevel::Elevated));
        let g = gate(&h);
        let sys = Req {
            capability: cap("system"),
            budget: Budget::unbounded(),
            rollback: None,
        };
        let v = Some(AttributionVerdict::granted_for(AttributionTier::Manage));
        let first = g.decide(&sys, v, ready());
        let second = g.decide(&sys, v, ready());
        assert_eq!(first, second);
        assert!(!first.is_allowed());
        assert!(matches!(
            first.refusal(),
            Some(Refusal::RollbackPlanRequired(_))
        ));
    }

    #[test]
    fn gaps_list_undeclared_capabilities_with_the_port_explanation() {
        // R9: the model is told what is missing and why, not left to guess.
        let mut table = CapabilityTable::new("test", vocab()).unwrap();
        table.declare(cap("read")).unwrap();
        let h = TestHost {
            table,
            privilege: Some(PrivilegeLevel::Elevated),
            escalation: EscalationModel::PerCallHelper,
        };
        let g = gate(&h);
        let gaps = g.gaps();
        assert_eq!(gaps.len(), 2);
        assert!(gaps.iter().any(|x| x.capability == cap("write")));
        assert!(gaps.iter().any(|x| x.capability == cap("system")));
        assert!(gaps[0].to_string().contains("was not demonstrated here"));
    }

    #[test]
    fn refusal_messages_name_the_rule_and_the_remedy() {
        // R9: every refusal says what to do next.
        let messages = vec![
            Refusal::Unregistered(cap("nuke")).to_string(),
            Refusal::NotDeclared(cap("write")).to_string(),
            Refusal::PrivilegeViolation {
                found: PrivilegeLevel::Unrestricted,
            }
            .to_string(),
            Refusal::ApprovalMissing(cap("write")).to_string(),
            Refusal::DangerousSessionRequired(cap("system")).to_string(),
            Refusal::AttributionDenied {
                required: AttributionTier::Manage,
            }
            .to_string(),
            Refusal::DeviceBusy {
                retry_after: core::time::Duration::from_secs(30),
            }
            .to_string(),
            Refusal::RollbackPlanRequired(cap("system")).to_string(),
        ];
        for m in &messages {
            assert!(m.len() > 20, "message too terse to be actionable: {m}");
        }
        assert!(messages[3].contains("ask before retrying"));
        assert!(messages[4].contains("restart the session"));
        // Index 5 was the one refusal that named a condition but no next step: the
        // device genuinely cannot fix an attribution verdict, and a message that does
        // not say so sends the model re-probing a device that was never the problem.
        assert!(messages[5].contains("re-authorized before retrying"));
        assert!(messages[6].contains("retry in 30s"));
        assert!(messages[7].contains("roll it back"));
    }

    #[test]
    fn the_gate_has_no_platform_branch() {
        // R6, asserted rather than merely intended: the same table shape drives a
        // different platform's decisions with no change to gate code. A port that
        // needed a gate edit to behave differently would fail this test by
        // construction, because nothing here mentions a platform.
        let mut table = CapabilityTable::new(
            "esp32",
            vec![
                CapabilitySpec::read_only(HostCapability::parse("esp32:sensor:read").unwrap()),
                CapabilitySpec {
                    id: HostCapability::parse("esp32:efuse:burn").unwrap(),
                    effect: Effect::Mutating,
                    approval: ApprovalRequirement::DangerousSession,
                    attribution: AttributionTier::Manage,
                    reversibility: Reversibility::Irreversible,
                },
            ],
        )
        .unwrap();
        table
            .declare(HostCapability::parse("esp32:sensor:read").unwrap())
            .unwrap();
        table
            .declare(HostCapability::parse("esp32:efuse:burn").unwrap())
            .unwrap();

        // A privilege-less target: `None` privilege, no escalation model.
        let h = TestHost {
            table,
            privilege: None,
            escalation: EscalationModel::None,
        };
        let g = gate(&h);

        let read = Req {
            capability: HostCapability::parse("esp32:sensor:read").unwrap(),
            budget: Budget::unbounded(),
            rollback: None,
        };
        assert!(
            g.decide(&read, None, LocalReadiness::for_read())
                .is_allowed()
        );

        let burn = Req {
            capability: HostCapability::parse("esp32:efuse:burn").unwrap(),
            budget: Budget::unbounded(),
            rollback: Some("device is not field-recoverable; replace the unit".to_string()),
        };
        // Same rules, same code path, different platform.
        assert!(matches!(
            g.decide(&burn, None, ready()).refusal(),
            Some(Refusal::AttributionDenied {
                required: AttributionTier::Manage
            })
        ));
        assert!(
            g.decide(
                &burn,
                Some(AttributionVerdict::granted_for(AttributionTier::Manage)),
                ready()
            )
            .is_allowed()
        );
    }

    #[test]
    fn a_backend_can_be_driven_through_the_gate() {
        // Smoke test that the trait shapes compose: gate decides, backend executes.
        struct Echo;
        impl ExecutionBackend for Echo {
            type Request = Req;
            type ExecuteFuture<'a> = core::future::Ready<ExecOutcome>;
            fn execute(&self, _request: Self::Request) -> Self::ExecuteFuture<'_> {
                core::future::ready(ExecOutcome {
                    result: Ok(crate::exec::ExitStatus::Code(0)),
                    stdout: Default::default(),
                    stderr: Default::default(),
                })
            }
        }
        let h = host(Some(PrivilegeLevel::Elevated));
        let g = gate(&h);
        let backend = Echo;
        let r = req("read");
        let d = g.decide(&r, None, LocalReadiness::for_read());
        assert!(d.is_allowed());
        let res = block_on(backend.execute(r));
        assert!(res.succeeded());
    }

    /// Minimal driver, so the crate's tests need no executor. `Ready` futures
    /// complete on the first poll, which is all these tests use.
    fn block_on<F: core::future::Future>(fut: F) -> F::Output {
        use alloc::boxed::Box;
        use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

        fn clone(_: *const ()) -> RawWaker {
            RawWaker::new(core::ptr::null(), &VTABLE)
        }
        fn noop(_: *const ()) {}
        static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, noop, noop, noop);

        let waker = unsafe { Waker::from_raw(RawWaker::new(core::ptr::null(), &VTABLE)) };
        let mut cx = Context::from_waker(&waker);
        let mut fut = Box::pin(fut);
        // No loop: both arms diverge, so a second poll is unreachable. `Ready`
        // futures complete on the first poll, which is all these tests use.
        match fut.as_mut().poll(&mut cx) {
            Poll::Ready(v) => v,
            Poll::Pending => panic!("test future returned Pending; use a real executor"),
        }
    }
}
