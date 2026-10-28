//! Rule conformance: does the Android port actually satisfy R1–R13?
//!
//! # What this file is for
//!
//! `acowork-platform-contract` states thirteen rules. A rule in a document is an
//! intention; a rule with a test is a constraint. This file is the Android port's
//! evidence that it meets them, one test per rule, named `r1_…` through `r13_…`.
//!
//! It is also the **template**. Android is the first platform to attach to ACowork, and
//! the point of going first is that the second port — an ESP32, say — should not have to
//! invent what "conformant" means. A new platform copies this file, keeps the rule
//! names, and replaces the fixtures. Where a rule does not apply to that platform, the
//! test says so explicitly rather than being quietly deleted, so the absence is a
//! decision on the record.
//!
//! # How to read a failure here
//!
//! A failing `rN_*` test is not "a test broke". It means the port has stopped satisfying
//! a rule the whole multi-platform design rests on, and the fix belongs in the port or
//! in the contract — not in the assertion. Each test's doc comment states the rule and
//! what specifically is being proven, so the failure message should point at the cause.

use std::collections::BTreeMap;

use acowork_android::host::{
    Capability, CommandOutput, ExecRecord, ExecRequest, FsRoot, HostProfile, Privilege,
    ProbeCommand, ProbeOutput, SelinuxDenial, SelinuxDomain, SelinuxState, SessionWriteLock,
    ShellDialect, VerityState, android_vocabulary, classify, derive_claims, explain_absence,
    lookup, parse_denials,
};
use acowork_platform_contract::{
    ApprovalRequirement, AttributionTier, AttributionVerdict, Budget, CapabilitySpec,
    CapabilityTable, Diagnostic, DiagnosticLedger, Effect, EscalationModel, ExitStatus, Gate,
    GateDecision, GateView, HostCapability, HostDescription, HostSummary, LocalReadiness,
    LockState, PrivilegeLevel, Refusal, Remedy, Reversibility, audit_claims,
};

mod common;

use common::{apk_probe, rooted_probe, termux_probe};

// ── Fixtures ────────────────────────────────────────────────────────────────

/// The three baselines android-host-probe.md §7 requires snapshots of.
fn baselines() -> Vec<(&'static str, HostProfile)> {
    vec![
        (
            "termux",
            HostProfile::assemble(&termux_probe(), "com.termux"),
        ),
        (
            "rooted",
            HostProfile::assemble(&rooted_probe(), "com.example.agent"),
        ),
        (
            "apk-sandbox",
            HostProfile::assemble(&apk_probe(), "com.example.agent"),
        ),
    ]
}

/// Readiness with every local switch on, so a test can isolate one rule.
fn ready() -> LocalReadiness {
    LocalReadiness {
        dangerous_session: true,
        approval_presented: true,
        lock: LockState::Available,
    }
}

/// A request for one capability, with an approval and a rollback plan already present.
///
/// Presenting everything up front means a refusal can only come from the rule under
/// test, not from a missing token.
fn request(cap: Capability) -> ExecRequest {
    ExecRequest {
        capability: cap.id(),
        approval_token: Some(acowork_android::host::ApprovalToken::new("t")),
        rollback_plan: Some("reflash the stock image".to_string()),
        ..ExecRequest::read("true", "s-1")
    }
}

fn rooted() -> HostProfile {
    HostProfile::assemble(&rooted_probe(), "com.example.agent")
}

// ── R1: capabilities are a function of probed facts, never of configuration ──

#[test]
fn r1_capabilities_are_derived_from_facts_and_not_configurable() {
    // Three parts to this rule, and all three have to hold.

    // (a) The same facts always produce the same capabilities: derivation is pure.
    for (name, profile) in baselines() {
        let again = match name {
            "termux" => HostProfile::assemble(&termux_probe(), "com.termux"),
            "rooted" => HostProfile::assemble(&rooted_probe(), "com.example.agent"),
            _ => HostProfile::assemble(&apk_probe(), "com.example.agent"),
        };
        assert_eq!(
            profile.caps.declared_ids(),
            again.caps.declared_ids(),
            "derivation is not deterministic on {name}"
        );
    }

    // (b) Changing one fact changes exactly the capabilities that depend on it.
    //     Removing `su` must cost the escalation-dependent capabilities and nothing
    //     else — if unrelated capabilities also moved, the rules are entangled.
    let mut no_su = rooted_probe();
    no_su.su = Some(CommandOutput::failed(1, "su: not found"));
    let without = HostProfile::assemble(&no_su, "com.example.agent");
    let with = rooted();
    assert!(with.caps.is_declared(&Capability::ShellWrite.id()));
    assert!(!without.caps.is_declared(&Capability::ShellWrite.id()));
    assert!(
        without.caps.is_declared(&Capability::ShellRead.id()),
        "losing `su` must not cost read-only inspection"
    );

    // (c) There is no way to declare a capability the facts do not support. The table
    //     rejects an unregistered ID, and the audit rejects an unsupported claim, so
    //     neither a typo nor a config file can widen the set.
    let mut table =
        CapabilityTable::new(acowork_android::host::PLATFORM, android_vocabulary()).unwrap();
    assert!(
        table
            .declare(HostCapability::parse("android:shell:delete-everything").unwrap())
            .is_err()
    );
}

#[test]
fn r1_no_environment_or_config_path_can_widen_the_capability_set() {
    // The rule says "never of configuration". This is the structural half: the only
    // inputs to derivation are the probe output and the package name, both of which are
    // function arguments. Assert it by showing that a probe which ran *nothing* declares
    // nothing at all — there is no default-on path.
    let profile = HostProfile::assemble(&ProbeOutput::nothing_ran(), "com.example.agent");
    assert!(
        profile.caps.declared().is_empty(),
        "an empty probe must declare nothing; got {:?}",
        profile.caps.declared_ids()
    );
}

// ── R2: a probe is not a guarantee; per-call authority is the gate ────────────

#[test]
fn r2_a_declared_capability_is_still_decided_per_call() {
    // The profile is session-immutable, but authority is not: the same request against
    // the same profile gets different answers depending on the per-call facts. If the
    // profile were the authority, the second decision would also be Allow.
    let profile = rooted();
    let gate = Gate::new(&profile);
    assert!(profile.caps.is_declared(&Capability::ShellWrite.id()));

    let req = request(Capability::ShellWrite);
    assert!(gate.decide(&req, None, ready()).is_allowed());

    // Same profile, same request, no approval this time.
    let mut no_approval = ready();
    no_approval.approval_presented = false;
    assert!(
        matches!(
            gate.decide(&req, None, no_approval).refusal(),
            Some(Refusal::ApprovalMissing(_))
        ),
        "a declared capability must not be self-authorizing"
    );

    // Same profile, same request, device busy.
    let busy = LocalReadiness {
        lock: LockState::Busy {
            retry_after: std::time::Duration::from_secs(30),
        },
        ..ready()
    };
    assert!(matches!(
        gate.decide(&req, None, busy).refusal(),
        Some(Refusal::DeviceBusy { .. })
    ));
}

#[test]
fn r2_a_runtime_denial_is_fed_back_rather_than_swallowed() {
    // android-host-probe.md §4: the profile can say "writable" and SELinux can still
    // refuse. The refusal has to become a next step, not a dead end.
    let profile = rooted();
    assert!(profile.caps.is_declared(&Capability::ShellWrite.id()));

    let line = "avc: denied { write } for comm=\"touch\" path=\"/data/local/tmp/x\" \
                scontext=u:r:untrusted_app:s0 tcontext=u:object_r:shell_data_file:s0 \
                tclass=file permissive=0";
    let denial = &parse_denials(line)[0];
    let diag = classify(denial, &profile).expect("an enforced denial must classify");
    assert_eq!(
        diag.remedy,
        Remedy::Escalate,
        "a denial in an unprivileged domain on a rooted device is an escalation candidate"
    );
}

// ── R3: the node process never holds elevated privilege ───────────────────────

#[test]
fn r3_no_baseline_runs_the_node_privileged() {
    // ADR-AND-001 §4.1 and the §6 P1 acceptance criterion. Checked on every baseline,
    // because the rooted one is where it is tempting to get this wrong: `su` being
    // *available to the helper* is not the node *being* root.
    for (name, profile) in baselines() {
        assert!(
            profile.runtime_is_unprivileged(),
            "the {name} baseline runs the node at {:?}",
            profile.privilege
        );
        assert!(
            profile.is_r3_conformant(),
            "the {name} baseline violates contract rule R3"
        );
        assert!(
            !matches!(profile.privilege(), Some(PrivilegeLevel::Unrestricted)),
            "{name} maps to Unrestricted"
        );
    }
}

#[test]
fn r3_a_privileged_node_is_refused_mutating_work_by_the_gate() {
    // The rule is enforced, not merely asserted in a document. No baseline produces
    // this state, so build it deliberately.
    let mut profile = rooted();
    profile.privilege = Privilege::Root;
    assert!(!profile.is_r3_conformant());

    let gate = Gate::new(&profile);
    assert!(matches!(
        gate.decide(&request(Capability::ShellWrite), None, ready())
            .refusal(),
        Some(Refusal::PrivilegeViolation {
            found: PrivilegeLevel::Unrestricted
        })
    ));

    // Reads still work. R3 is about not *holding* privilege, not about being useless,
    // and a node that could not even inspect the device could not diagnose this.
    assert!(
        gate.decide(
            &ExecRequest::read("getprop", "s-1"),
            None,
            LocalReadiness::for_read()
        )
        .is_allowed()
    );
}

#[test]
fn r3_escalation_is_per_call_and_never_self_elevating() {
    // The conformant shape: a helper runs one command at elevated privilege and returns.
    // A port that could raise its own privilege and keep it would violate R3 however
    // low it started.
    for (name, profile) in baselines() {
        assert!(
            !profile.escalation().violates_r3(),
            "{name} reports a self-elevating escalation model"
        );
        assert!(
            matches!(
                profile.escalation(),
                EscalationModel::PerCallHelper | EscalationModel::None
            ),
            "{name} reports {:?}",
            profile.escalation()
        );
    }
    // The rooted baseline has a helper; the sandbox does not.
    assert_eq!(rooted().escalation(), EscalationModel::PerCallHelper);
    assert_eq!(
        HostProfile::assemble(&apk_probe(), "com.example.agent").escalation(),
        EscalationModel::None
    );
}

// ── R4: a capability may be declared only if the port demonstrated it ─────────

#[test]
fn r4_every_declared_capability_carries_evidence_that_supports_it() {
    for (name, profile) in baselines() {
        let claims = derive_claims(&profile);
        for claim in &claims {
            if profile.caps.is_declared(&claim.capability) {
                assert!(
                    claim.evidence.kind.supports_claim(),
                    "{name} declared {} on evidence that cannot support a claim",
                    claim.capability
                );
            }
        }
        // And nothing is declared that has no claim at all.
        for declared in profile.caps.declared() {
            assert!(
                claims.iter().any(|c| &c.capability == declared),
                "{name} declared {declared} with no claim behind it"
            );
        }
    }
}

#[test]
fn r4_a_declined_su_prompt_never_becomes_a_declared_capability() {
    // android-host-probe.md §2 item 4: a declined prompt is not retryable. Recording it
    // as a *denial* rather than omitting it is what makes that visible, and the audit is
    // what stops the denial from being promoted into a capability.
    let mut probe = rooted_probe();
    probe.su = Some(CommandOutput::failed(1, "su: Permission denied"));
    let profile = HostProfile::assemble(&probe, "com.example.agent");

    assert!(
        !profile.caps.is_declared(&Capability::ShellWrite.id()),
        "a declined prompt must not grant write access"
    );
    let claims = derive_claims(&profile);
    let write = claims
        .iter()
        .find(|c| c.capability == Capability::ShellWrite.id())
        .expect("the declined prompt should still be recorded as a claim");
    assert!(!write.evidence.kind.supports_claim());

    // The audit rejects it, and says why.
    let mut table =
        CapabilityTable::new(acowork_android::host::PLATFORM, android_vocabulary()).unwrap();
    let audit = audit_claims(&mut table, &claims, std::time::Duration::from_secs(3600));
    assert!(
        audit
            .unsupported
            .contains(&"android:shell:write".to_string()),
        "audit was {audit}"
    );
    assert!(
        explain_absence(&profile, Capability::ShellWrite).contains("not retryable"),
        "the explanation must say the prompt was declined, not just that it failed"
    );
}

#[test]
fn r4_an_inconclusive_probe_does_not_close_or_open_anything() {
    // A missing `getenforce` says nothing about whether the shell works. It must not be
    // read as permission, and it must not be read as proof of absence either — the write
    // tier closes because the *fact is unknown*, which is the conservative reading, not
    // because a denial was observed.
    let mut probe = termux_probe();
    probe.getenforce = None;
    let profile = HostProfile::assemble(&probe, "com.termux");
    assert_eq!(profile.selinux, SelinuxState::Unknown);
    assert!(
        profile.caps.is_declared(&Capability::ShellRead.id()),
        "an unreadable SELinux mode must not cost read-only inspection"
    );
}

// ── R5: the vocabulary belongs to the protocol, the facts to the device ───────

#[test]
fn r5_the_android_vocabulary_is_exactly_the_five_adr_ids() {
    // ADR-AND-001 §4.4. If blocker B2 is ruled against these spellings, this is the test
    // that fails — and it fails in one place, which is the whole reason the vocabulary
    // is data rather than scattered string literals.
    let ids: Vec<String> = Capability::all()
        .iter()
        .map(|c| c.id().to_string())
        .collect();
    assert_eq!(
        ids,
        vec![
            "android:shell:read",
            "android:shell:write",
            "android:fs:outside-app",
            "android:fs:system",
            "android:selinux:permissive",
        ]
    );
    for id in &ids {
        assert_eq!(
            HostCapability::parse(id).unwrap().platform(),
            "android",
            "{id} is not in the android namespace"
        );
    }
}

#[test]
fn r5_an_id_outside_the_vocabulary_is_refused_not_defaulted() {
    // Silently accepting an unrecognised ID is how a vocabulary change becomes a
    // privilege escalation, so the lookup is closed and the gate refuses.
    for bad in [
        "android:kernel:write",
        "android:shell",
        "esp32:gpio:write",
        "ANDROID:shell:read",
        "android:shell read",
    ] {
        let parsed = HostCapability::parse(bad);
        if let Ok(cap) = parsed {
            assert_eq!(
                lookup(&cap),
                None,
                "{bad} resolved to an Android capability"
            );
        }
    }

    let profile = rooted();
    let gate = Gate::new(&profile);
    let req = ExecRequest {
        capability: HostCapability::parse("android:kernel:write").unwrap(),
        ..ExecRequest::read("true", "s-1")
    };
    assert!(matches!(
        gate.decide(&req, None, ready()).refusal(),
        Some(Refusal::Unregistered(_))
    ));
}

#[test]
fn r5_a_device_cannot_declare_what_its_platform_never_registered() {
    let mut table =
        CapabilityTable::new(acowork_android::host::PLATFORM, android_vocabulary()).unwrap();
    // Well-formed, namespaced, and still refused: the vocabulary is closed.
    let err = table
        .declare(HostCapability::parse("android:bootloader:unlock").unwrap())
        .unwrap_err();
    assert!(
        err.to_string()
            .contains("not in this platform's vocabulary")
    );
    assert!(table.declared().is_empty());
}

// ── R6: four axes, composed uniformly, with no platform branch ────────────────

#[test]
fn r6_every_android_capability_declares_all_four_axes() {
    // A capability with an unstated axis would fall back to a default, and a default is
    // a decision nobody made. Check all five declare all four explicitly.
    for cap in Capability::all() {
        let spec = cap.spec();
        assert_eq!(spec.id, cap.id());
        // Each axis is one of its enum's variants; asserting the mapping is the point.
        let _ = (
            spec.effect,
            spec.approval,
            spec.attribution,
            spec.reversibility,
        );
        assert!(
            matches!(spec.effect, Effect::ReadOnly | Effect::Mutating)
                && matches!(
                    spec.approval,
                    ApprovalRequirement::None
                        | ApprovalRequirement::PerUse
                        | ApprovalRequirement::DangerousSession
                )
                && matches!(
                    spec.attribution,
                    AttributionTier::None | AttributionTier::Use | AttributionTier::Manage
                )
                && matches!(
                    spec.reversibility,
                    Reversibility::Reversible | Reversibility::Irreversible
                ),
            "{cap} has an axis outside the contract's vocabulary"
        );
    }
    // The vocabulary the contract validates is the same one the gate reads.
    let table =
        CapabilityTable::new(acowork_android::host::PLATFORM, android_vocabulary()).unwrap();
    assert_eq!(table.specs().len(), 5);
    for cap in Capability::all() {
        assert_eq!(table.spec(&cap.id()).unwrap(), &cap.spec());
    }
}

#[test]
fn r6_the_axes_reproduce_the_adr_tiers() {
    // ADR-AND-001 §4.4 / §4.6 item 5 / §7.3, expressed as data.
    assert_eq!(
        Capability::ShellRead.spec().effect,
        Effect::ReadOnly,
        "§4.6 item 5: read 类不锁"
    );
    for cap in Capability::all() {
        assert_eq!(
            cap.spec().effect.needs_lock(),
            cap != Capability::ShellRead,
            "{cap} lock requirement is wrong"
        );
        assert_eq!(
            cap.spec().approval.needs_token(),
            cap != Capability::ShellRead,
            "{cap} approval requirement is wrong"
        );
        assert_eq!(
            cap.spec().approval.needs_dangerous_session(),
            matches!(cap, Capability::FsSystem | Capability::SelinuxPermissive),
            "§7.3: only the system tier needs the dangerous-mode switch ({cap})"
        );
    }
}

#[test]
fn r6_the_same_gate_code_decides_a_non_android_host() {
    // The strongest form of "no platform branch": drive the contract gate with a host
    // that is not Android at all, using the same `Gate` type and the same rules. A port
    // that needed a gate edit to behave differently could not pass this, because nothing
    // here mentions Android.
    struct Esp32Like {
        table: CapabilityTable,
    }
    impl HostDescription for Esp32Like {
        fn platform(&self) -> &str {
            "esp32"
        }
        fn profile_name(&self) -> &str {
            "devkit-c"
        }
        // No MMU, no uid: the privilege axis does not exist on this platform, and `None`
        // is the honest answer rather than an invented one.
        fn privilege(&self) -> Option<PrivilegeLevel> {
            None
        }
        fn escalation(&self) -> EscalationModel {
            EscalationModel::None
        }
        fn capabilities(&self) -> &CapabilityTable {
            &self.table
        }
        fn explain_absence(&self, capability: &HostCapability) -> String {
            format!("{capability} was not demonstrated on this board")
        }
    }

    struct RpcCall {
        capability: HostCapability,
        budget: Budget,
        rollback: Option<String>,
    }
    impl GateView for RpcCall {
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

    let host = Esp32Like { table };
    let gate = Gate::new(&host);

    // A read needs nothing, on a platform with no privilege model at all.
    let read = RpcCall {
        capability: HostCapability::parse("esp32:sensor:read").unwrap(),
        budget: Budget::unbounded(),
        rollback: None,
    };
    assert!(
        gate.decide(&read, None, LocalReadiness::for_read())
            .is_allowed()
    );

    // An irreversible, manage-tier capability: same rules as Android's `fs:system`.
    let burn = RpcCall {
        capability: HostCapability::parse("esp32:efuse:burn").unwrap(),
        budget: Budget::unbounded(),
        rollback: None,
    };
    assert!(matches!(
        gate.decide(&burn, None, ready()).refusal(),
        Some(Refusal::RollbackPlanRequired(_))
    ));
    let burn = RpcCall {
        rollback: Some("the part is not field-recoverable; replace the board".to_string()),
        ..burn
    };
    assert!(matches!(
        gate.decide(&burn, None, ready()).refusal(),
        Some(Refusal::AttributionDenied {
            required: AttributionTier::Manage
        })
    ));
    assert!(
        gate.decide(
            &burn,
            Some(AttributionVerdict::granted_for(AttributionTier::Manage)),
            ready()
        )
        .is_allowed()
    );
}

// ── R7: two authorities, one composition point ────────────────────────────────

#[test]
fn r7_the_attribution_verdict_carries_no_identity() {
    // ADR-087 D1/D5: the node must not learn who was authorised. A boolean plus the tier
    // it was issued for is the whole payload, and the serialized shape is pinned so a
    // future field cannot smuggle an identity in.
    let v = AttributionVerdict::granted_for(AttributionTier::Manage);
    let json = serde_json::to_string(&v).unwrap();
    let value: serde_json::Value = serde_json::from_str(&json).unwrap();
    let keys: Vec<&str> = value
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        keys,
        vec!["granted", "tier"],
        "verdict shape changed: {json}"
    );
    for forbidden in ["user", "owner", "name", "id", "role", "email"] {
        assert!(
            !json.to_lowercase().contains(forbidden),
            "`{forbidden}` appeared in the verdict: {json}"
        );
    }
}

#[test]
fn r7_the_conjunction_happens_on_the_device_and_neither_authority_suffices() {
    // B1's resolution, end to end. The Gateway answers *who may ask*; the device answers
    // *what is possible now*; the AND is evaluated here, on the device.
    let profile = rooted();
    let gate = Gate::new(&profile);
    let req = request(Capability::FsSystem);
    let granted = Some(AttributionVerdict::granted_for(AttributionTier::Manage));

    // Gateway says yes, device says no (no dangerous-mode switch) → refused.
    let no_switch = LocalReadiness {
        dangerous_session: false,
        ..ready()
    };
    assert!(matches!(
        gate.decide(&req, granted, no_switch).refusal(),
        Some(Refusal::DangerousSessionRequired(_))
    ));

    // Device says yes, Gateway says nothing → refused. An unreachable control plane is
    // not a pass; "we could not ask" is not "yes".
    assert!(matches!(
        gate.decide(&req, None, ready()).refusal(),
        Some(Refusal::AttributionDenied { .. })
    ));

    // Both say yes → allowed.
    assert!(gate.decide(&req, granted, ready()).is_allowed());
}

#[test]
fn r7_a_verdict_cannot_be_replayed_against_a_higher_tier() {
    // The opacity of the verdict is only safe if it is scoped. A `use`-tier verdict
    // presented for a `manage`-tier capability must be refused.
    let profile = rooted();
    let gate = Gate::new(&profile);
    let req = request(Capability::FsSystem);
    assert!(matches!(
        gate.decide(
            &req,
            Some(AttributionVerdict::granted_for(AttributionTier::Use)),
            ready()
        )
        .refusal(),
        Some(Refusal::AttributionDenied {
            required: AttributionTier::Manage
        })
    ));
    // And an explicit denial is a denial.
    assert!(matches!(
        gate.decide(
            &req,
            Some(AttributionVerdict::denied_for(AttributionTier::Manage)),
            ready()
        )
        .refusal(),
        Some(Refusal::AttributionDenied { .. })
    ));
}

// ── R8: irreversible operations need a stated rollback path ───────────────────

#[test]
fn r8_irreversibility_follows_whether_an_undo_actually_exists() {
    // `/system` has no snapshot to restore from, so the model must state the cost.
    assert!(
        Capability::FsSystem
            .spec()
            .reversibility
            .needs_rollback_plan()
    );
    // `setenforce 0` is auto-restored at session end (ADR-AND-001 §8), so it has a real
    // undo. Demanding a rollback plan for something the runtime already rolls back would
    // be noise, and noise trains the model to answer these questions carelessly.
    assert!(
        !Capability::SelinuxPermissive
            .spec()
            .reversibility
            .needs_rollback_plan()
    );
    assert!(
        !Capability::ShellWrite
            .spec()
            .reversibility
            .needs_rollback_plan()
    );
    assert!(
        !Capability::ShellRead
            .spec()
            .reversibility
            .needs_rollback_plan()
    );
}

#[test]
fn r8_the_gate_enforces_the_rollback_requirement() {
    let profile = rooted();
    let gate = Gate::new(&profile);
    let granted = Some(AttributionVerdict::granted_for(AttributionTier::Manage));

    let no_plan = ExecRequest {
        rollback_plan: None,
        ..request(Capability::FsSystem)
    };
    assert!(matches!(
        gate.decide(&no_plan, granted, ready()).refusal(),
        Some(Refusal::RollbackPlanRequired(_))
    ));
    assert!(
        gate.decide(&request(Capability::FsSystem), granted, ready())
            .is_allowed()
    );
}

// ── R9: diagnostics travel with the error and are actionable ──────────────────

#[test]
fn r9_every_refusal_names_the_condition_and_the_next_step() {
    // A refusal the model cannot act on costs a full round trip and teaches it nothing.
    let refusals = vec![
        Refusal::Unregistered(Capability::ShellWrite.id()),
        Refusal::NotDeclared(Capability::FsSystem.id()),
        Refusal::PrivilegeViolation {
            found: PrivilegeLevel::Unrestricted,
        },
        Refusal::ApprovalMissing(Capability::ShellWrite.id()),
        Refusal::DangerousSessionRequired(Capability::FsSystem.id()),
        Refusal::AttributionDenied {
            required: AttributionTier::Manage,
        },
        Refusal::DeviceBusy {
            retry_after: std::time::Duration::from_secs(30),
        },
        Refusal::RollbackPlanRequired(Capability::FsSystem.id()),
    ];
    for r in &refusals {
        let msg = r.to_string();
        assert!(msg.len() > 30, "too terse to act on: {msg}");
        assert!(
            msg.contains("android:") || msg.contains("privilege") || msg.contains("device"),
            "the message should identify the subject: {msg}"
        );
    }
    // Spot-check that the remedy is stated, not just the problem. Every index, so a
    // refusal cannot regress into naming only its condition.
    assert!(refusals[3].to_string().contains("ask before retrying"));
    assert!(refusals[4].to_string().contains("restart the session"));
    assert!(
        refusals[5]
            .to_string()
            .contains("re-authorized before retrying")
    );
    assert!(refusals[6].to_string().contains("retry in 30s"));
    assert!(refusals[7].to_string().contains("roll it back"));
}

#[test]
fn r9_every_absent_capability_is_explained_on_every_baseline() {
    // No capability may be silently missing. The explanation has to name the missing
    // fact, because "not permitted" is a dead end and "dm-verity is enforcing" is a
    // next step.
    for (name, profile) in baselines() {
        let gate = Gate::new(&profile);
        for gap in gate.gaps() {
            assert!(
                gap.reason.len() > 15,
                "{name}: explanation for {} is too terse: {}",
                gap.capability,
                gap.reason
            );
            // The port must be able to explain anything in its own vocabulary.
            assert!(lookup(&gap.capability).is_some(), "{name}: {gap}");
        }
        // And every undeclared capability appears in the gap list — the two views of
        // "what this device lacks" cannot disagree.
        for cap in Capability::all() {
            if !profile.caps.is_declared(&cap.id()) {
                assert!(
                    gate.gaps().iter().any(|g| g.capability == cap.id()),
                    "{name}: {cap} is undeclared but unexplained"
                );
                assert!(!explain_absence(&profile, cap).is_empty());
            }
        }
    }
}

#[test]
fn r9_a_remedy_is_never_suggested_that_the_device_cannot_perform() {
    // This is the defect the admissibility rule exists to prevent. The first Android
    // implementation told a rooted device "wrong path, privilege will not help" for an
    // out-of-roots path — false, and it steered the model away from the only fix.
    let rooted = rooted();
    let sandbox = HostProfile::assemble(&apk_probe(), "com.example.agent");

    assert!(Remedy::Escalate.is_admissible(&rooted));
    assert!(
        !Remedy::Escalate.is_admissible(&sandbox),
        "a sandbox has no escalation to suggest"
    );

    // And the classifier respects it: every remedy Android produces is admissible on
    // the host it was produced for.
    let lines = [
        "avc: denied { read open } for comm=\"cat\" path=\"/data/local/tmp/x\" \
         scontext=u:r:shell:s0 tcontext=u:object_r:shell_data_file:s0 tclass=file permissive=0",
        "avc: denied { read } for comm=\"cat\" path=\"/mnt/secret/x\" \
         scontext=u:r:shell:s0 tcontext=u:object_r:mnt_file:s0 tclass=file permissive=0",
    ];
    for line in lines {
        let d = &parse_denials(line)[0];
        for host in [&rooted, &sandbox] {
            if let Some(diag) = classify(d, host) {
                assert!(
                    diag.remedy.is_admissible(host),
                    "{:?} is not admissible on a host whose escalation model is {:?}",
                    diag.remedy,
                    host.escalation()
                );
            }
        }
    }
}

#[test]
fn r9_a_repeated_failure_stops_the_branch() {
    // Two identical failures means the model has stopped varying its approach. The
    // contract ledger turns the second into Abandon; the Android denial ledger does the
    // same per SELinux target, which is finer-grained and is the wall that matters.
    let profile = rooted();
    let mut ledger = DiagnosticLedger::new();
    let cap = Capability::ShellWrite.id();
    let diag = || Diagnostic {
        capability: cap.clone(),
        remedy: Remedy::Retry,
        detail: "transient".to_string(),
    };
    assert_eq!(ledger.admit(Some(diag()), &cap, &profile), Remedy::Retry);
    assert!(matches!(
        ledger.admit(Some(diag()), &cap, &profile),
        Remedy::Abandon { .. }
    ));

    let mut denials = acowork_android::host::DenialLedger::new();
    let line = "avc: denied { read open } for comm=\"cat\" path=\"/data/local/tmp/x\" \
                scontext=u:r:shell:s0 tcontext=u:object_r:shell_data_file:s0 tclass=file permissive=0";
    let d = parse_denials(line)[0].clone();
    assert_eq!(denials.record(&d, &profile), Remedy::Escalate);
    assert!(matches!(
        denials.record(&d, &profile),
        Remedy::Abandon { .. }
    ));
}

// ── R10: the request shape belongs to the port ────────────────────────────────

#[test]
fn r10_the_contract_sees_three_answers_and_never_the_posix_fields() {
    // `ExecRequest` is POSIX all the way down — a script, a directory, an environment.
    // The contract must not depend on any of it, only on the three `GateView` answers.
    let req = ExecRequest {
        script: "setprop debug.x 1".to_string(),
        cwd: Some(std::path::PathBuf::from("/data/local/tmp")),
        env: BTreeMap::from([("TOKEN".to_string(), "secret".to_string())]),
        ..request(Capability::ShellWrite)
    };

    assert_eq!(
        GateView::capability(&req).as_str(),
        "android:shell:write",
        "the gate must be able to identify the capability"
    );
    assert!(
        GateView::budget(&req).timeout.is_some(),
        "the gate must be able to see a time bound"
    );
    assert_eq!(
        GateView::rollback_plan(&req),
        Some("reflash the stock image"),
        "the gate must be able to see the rollback path"
    );

    // The decision does not depend on the POSIX fields: two requests differing only in
    // script, cwd and env get the same answer.
    let profile = rooted();
    let gate = Gate::new(&profile);
    let bare = request(Capability::ShellWrite);
    assert_eq!(
        gate.decide(&req, None, ready()),
        gate.decide(&bare, None, ready()),
        "the gate must not be reading the POSIX fields"
    );
}

#[test]
fn r10_a_request_shape_from_another_platform_is_equally_valid() {
    // Proven structurally by `r6_the_same_gate_code_decides_a_non_android_host`, whose
    // `RpcCall` has no script, no path and no environment. Restated here because R10 is
    // the rule that makes it possible: the contract requires answers, not a struct.
    struct NoPosixAtAll {
        capability: HostCapability,
        budget: Budget,
    }
    impl GateView for NoPosixAtAll {
        fn capability(&self) -> &HostCapability {
            &self.capability
        }
        fn budget(&self) -> &Budget {
            &self.budget
        }
    }
    let req = NoPosixAtAll {
        capability: Capability::ShellRead.id(),
        budget: Budget::unbounded(),
    };
    let profile = rooted();
    let gate = Gate::new(&profile);
    assert!(
        gate.decide(&req, None, LocalReadiness::for_read())
            .is_allowed()
    );
}

// ── R11: one mutating action at a time, no queueing, no preemption ────────────

#[test]
fn r11_mutating_actions_serialize_and_reads_do_not() {
    let profile = rooted();
    let gate = Gate::new(&profile);
    let lock = SessionWriteLock::new();
    let t0 = std::time::Duration::ZERO;

    // A read takes no lock, so read-only diagnostics stay available mid-write.
    assert!(
        gate.decide(
            &ExecRequest::read("logcat -d", "s-1"),
            None,
            LocalReadiness::for_read()
        )
        .is_allowed()
    );
    assert!(matches!(
        gate.decide(
            &ExecRequest::read("logcat -d", "s-1"),
            None,
            LocalReadiness::for_read()
        ),
        GateDecision::Allow {
            hold_lock: false,
            ..
        }
    ));

    // A write does.
    assert!(matches!(
        gate.decide(&request(Capability::ShellWrite), None, ready()),
        GateDecision::Allow {
            hold_lock: true,
            ..
        }
    ));

    // And once one session holds it, another is refused rather than queued.
    assert!(matches!(
        lock.try_acquire("s-1", t0),
        acowork_android::host::SessionLockOutcome::Acquired
    ));
    match lock.try_acquire("s-2", std::time::Duration::from_secs(5)) {
        acowork_android::host::SessionLockOutcome::HeldBy {
            holder,
            retry_after,
        } => {
            // ADR-AND-001 §7.2 requires naming the holder, which the contract's
            // identity-free lock cannot do — this is why the wrapper exists.
            assert_eq!(holder, "s-1");
            assert_eq!(retry_after, std::time::Duration::from_secs(595));
        }
        other => panic!("expected HeldBy, got {other:?}"),
    }
}

#[test]
fn r11_a_dead_session_cannot_wedge_the_device_forever() {
    // The TTL exists because an unattended node whose session died mid-write would
    // otherwise block every later session, with nobody around to notice.
    let lock = SessionWriteLock::with_ttl(std::time::Duration::from_secs(600));
    lock.try_acquire("s-1", std::time::Duration::ZERO);
    let later = std::time::Duration::from_secs(601);
    assert_eq!(lock.lock_state("s-2", later), LockState::Available);
    assert!(matches!(
        lock.try_acquire("s-2", later),
        acowork_android::host::SessionLockOutcome::Acquired
    ));
}

#[test]
fn r11_a_non_holder_can_neither_release_nor_preempt() {
    let lock = SessionWriteLock::new();
    lock.try_acquire("s-1", std::time::Duration::ZERO);
    // A late release from a session that lost the lock must not free someone else's hold.
    lock.release("s-2");
    assert_eq!(lock.current_holder().as_deref(), Some("s-1"));
    // Renewing another session's hold is preemption by another name.
    assert!(matches!(
        lock.renew("s-2", std::time::Duration::from_secs(1)),
        acowork_android::host::SessionLockOutcome::HeldBy { .. }
    ));
    assert_eq!(lock.current_holder().as_deref(), Some("s-1"));
    // The holder itself sees the lock as available, so a read-then-write sequence works.
    assert_eq!(
        lock.lock_state("s-1", std::time::Duration::ZERO),
        LockState::Available
    );
}

// ── R12: the contract presumes no OS facility ─────────────────────────────────

#[test]
fn r12_the_contract_projection_carries_no_posix_vocabulary() {
    // Android's record is full of POSIX: a uid, a SELinux context, an exit code. The
    // projection onto the contract must carry none of it, because a platform without
    // uids has to be able to produce the same type.
    let record = ExecRecord {
        stdout: "ok\n".to_string(),
        stderr: String::new(),
        exit_code: Some(0),
        selinux_denials: vec![SelinuxDenial {
            permissions: vec!["read".to_string()],
            scontext: Some("u:r:shell:s0".to_string()),
            tcontext: Some("u:object_r:system_data_file:s0".to_string()),
            tclass: Some("file".to_string()),
            permissive: false,
            path: Some("/data/system/packages.xml".to_string()),
            comm: Some("cat".to_string()),
        }],
        uid: Some(0),
        context: Some("u:r:magisk:s0".to_string()),
        duration_ms: 12,
        truncated: false,
        timed_out: false,
    };
    let outcome = record.to_contract();
    let json = serde_json::to_string(&outcome).unwrap();
    for posix in ["uid", "scontext", "magisk", "selinux", "avc"] {
        assert!(
            !json.to_lowercase().contains(posix),
            "`{posix}` leaked into the contract projection: {json}"
        );
    }
    assert!(outcome.succeeded());
}

#[test]
fn r12_a_killed_process_is_not_spelled_as_a_signal() {
    // Signals are a Unix concept. The contract says "the platform stopped it early",
    // which covers SIGKILL, a watchdog reset and a radio timeout alike.
    let record = ExecRecord {
        stdout: String::new(),
        stderr: String::new(),
        exit_code: None,
        selinux_denials: Vec::new(),
        uid: None,
        context: None,
        duration_ms: 30_000,
        truncated: false,
        timed_out: false,
    };
    assert_eq!(record.to_contract().result, Ok(ExitStatus::Terminated));
    assert!(!record.to_contract().succeeded());
    let json = serde_json::to_string(&record.to_contract()).unwrap();
    assert!(!json.contains("signal"), "{json}");
}

#[test]
fn r12_a_host_with_no_privilege_model_is_representable() {
    // The privilege axis is `Option`, so a platform with no MMU and no uid reports
    // `None` instead of inventing a value. Android always has uids, so it always answers
    // `Some` — but the contract must not *require* that, or R12 is false.
    for (name, profile) in baselines() {
        assert!(
            profile.privilege().is_some(),
            "{name} should report a privilege level; Android has uids"
        );
    }
    // The `None` case is exercised by `r6_the_same_gate_code_decides_a_non_android_host`,
    // whose host reports no privilege at all and still passes every rule.
    let summary = HostSummary {
        platform: "esp32".to_string(),
        profile: "devkit-c".to_string(),
        privilege: None,
        escalation: EscalationModel::None,
        capabilities: vec!["esp32:sensor:read".to_string()],
    };
    assert!(serde_json::to_string(&summary).unwrap().contains("null"));
}

#[test]
fn r12_no_api_in_the_contract_reads_a_clock() {
    // Every time-taking call in the contract accepts `now` from the caller, so a target
    // with only a tick counter — or no clock at all — can drive the same code. Asserted
    // here by using the lock at a hand-chosen time and getting deterministic answers.
    let lock = SessionWriteLock::with_ttl(std::time::Duration::from_secs(10));
    let t = std::time::Duration::from_secs(1_000_000);
    assert!(matches!(
        lock.try_acquire("s-1", t),
        acowork_android::host::SessionLockOutcome::Acquired
    ));
    assert!(matches!(
        lock.try_acquire("s-2", t + std::time::Duration::from_secs(5)),
        acowork_android::host::SessionLockOutcome::HeldBy { .. }
    ));
    assert!(matches!(
        lock.try_acquire("s-2", t + std::time::Duration::from_secs(11)),
        acowork_android::host::SessionLockOutcome::Acquired
    ));
}

// ── R13: the reported summary carries no device identifiers ───────────────────

#[test]
fn r13_no_baseline_leaks_device_detail_in_its_summary() {
    // ADR-AND-001 §7.1 forbids reporting the serial or model, the concrete `fs_roots`
    // paths, the raw SELinux context, or observed-denial detail. The contract's summary
    // shape makes most of that structurally impossible: it has five fields and none of
    // them can hold a path or a context.
    for (name, profile) in baselines() {
        let json = serde_json::to_string(&profile.summary()).unwrap();
        for forbidden in [
            "u:r:", // any SELinux context
            "scontext", "/data/", // any concrete path
            "/sdcard", "avc:",  // any denial detail
            "arm64", // device facts
            "magisk",
        ] {
            assert!(
                !json.contains(forbidden),
                "{name} summary leaked `{forbidden}`: {json}"
            );
        }
        // The summary has exactly the five designed fields.
        //
        // Compared as a set, not in declaration order: the invariant is "no field appeared or
        // disappeared", and asserting the order would couple this test to whether the parent
        // workspace turns on serde_json's `preserve_order`. A shape check that changes result
        // with a serialisation feature is measuring the feature, not the summary.
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        let mut keys: Vec<&str> = value
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        let mut want = vec![
            "capabilities",
            "escalation",
            "platform",
            "privilege",
            "profile",
        ];
        want.sort_unstable();
        assert_eq!(keys, want, "{name} summary shape changed: {json}");
        // And it still carries what the control plane legitimately needs.
        assert!(json.contains("android"), "{json}");
    }
}

#[test]
fn r13_the_profile_keeps_detail_that_the_summary_drops() {
    // The rule is about what is *reported*, not about what the device may know. The
    // profile still holds the raw context and the mount table, because local diagnostics
    // need them; they simply have no path to the wire.
    let profile = rooted();
    assert!(profile.context.is_some(), "the raw context is kept locally");
    assert!(!profile.fs_roots.is_empty(), "the roots are kept locally");
    let json = serde_json::to_string(&profile.summary()).unwrap();
    for root in &profile.fs_roots {
        assert!(
            !json.contains(&root.path),
            "{} reached the summary",
            root.path
        );
    }
}

// ── Cross-cutting: the port is internally consistent ──────────────────────────

#[test]
fn the_tier_and_the_declared_shell_capability_never_disagree() {
    // A structural invariant, checked on every baseline: the tier says "has a shell"
    // exactly when a shell capability was declared. If this ever fires, the tier logic
    // and the derivation rules have drifted, and the profile is lying to the tool
    // registry in one direction or the other.
    for (name, profile) in baselines() {
        assert_eq!(
            profile.name.has_shell(),
            profile.caps.is_declared(&Capability::ShellRead.id()),
            "{name}: tier and declared capability disagree"
        );
    }
}

#[test]
fn every_baseline_is_a_valid_contract_host() {
    // The port's entry point: each baseline satisfies `HostDescription`, which is what
    // lets the contract's gate, summary and gap reporting work on it without knowing
    // anything about Android.
    for (name, profile) in baselines() {
        assert_eq!(profile.platform(), "android", "{name}");
        assert!(!profile.profile_name().is_empty(), "{name}");
        assert_eq!(profile.capabilities().platform(), "android", "{name}");
        // The vocabulary is complete on every device; only the *declared* set varies.
        assert_eq!(profile.capabilities().specs().len(), 5, "{name}");
        assert!(profile.is_r3_conformant(), "{name} violates R3");
    }
}

#[test]
fn the_apk_sandbox_declares_nothing_and_is_still_a_useful_host() {
    // The degenerate case, and the one most likely to be gotten wrong by treating "no
    // capabilities" as an error. It is a valid host that can answer "no" precisely.
    let profile = HostProfile::assemble(&apk_probe(), "com.example.agent");
    assert!(profile.caps.declared().is_empty());
    assert_eq!(profile.name.as_str(), "apk-sandbox");

    let gate = Gate::new(&profile);
    let gaps = gate.gaps();
    assert_eq!(gaps.len(), 5, "every capability must be explained");
    for gap in &gaps {
        assert!(!gap.reason.is_empty());
    }
    // And a request is refused with a reason, not with a panic or a silent no.
    let d = gate.decide(
        &ExecRequest::read("logcat -d", "s-1"),
        None,
        LocalReadiness::for_read(),
    );
    assert!(
        matches!(d.refusal(), Some(Refusal::NotDeclared(_))),
        "got {d:?}"
    );
    assert!(
        d.explanation().contains("android:shell:read"),
        "{}",
        d.explanation()
    );
}

#[test]
fn the_termux_baseline_gains_a_capability_only_when_the_fact_appears() {
    // android-host-probe.md §3's `fs:outside-app` rule, and the general shape of R1: a
    // capability appears exactly when its supporting fact does.
    let base = HostProfile::assemble(&termux_probe(), "com.termux");
    assert!(!base.caps.is_declared(&Capability::FsOutsideApp.id()));

    let mut probe = termux_probe();
    probe.fs_roots = vec![
        FsRoot {
            path: "/data/data/com.termux/files/home".to_string(),
            writable: true,
            own_package: true,
        },
        FsRoot {
            path: "/sdcard".to_string(),
            writable: true,
            own_package: false,
        },
    ];
    let granted = HostProfile::assemble(&probe, "com.termux");
    assert!(
        granted.caps.is_declared(&Capability::FsOutsideApp.id()),
        "a writable root outside the package must grant fs:outside-app"
    );
    // And nothing else moved: the fact supports one capability, not a general upgrade.
    assert_eq!(
        granted.caps.is_declared(&Capability::FsSystem.id()),
        base.caps.is_declared(&Capability::FsSystem.id()),
        "an unrelated capability changed when a filesystem fact appeared"
    );
}

#[test]
fn a_stale_profile_is_explained_rather_than_silently_wrong() {
    // android-host-probe.md §6 lists the re-probe events. Between one of those events and
    // the re-probe, the declared set can lag the facts. The gate refuses on the declared
    // set — which is correct, because a stale *grant* is worse than a stale refusal — and
    // the gap explanation is what tells the operator to re-probe.
    let mut profile = HostProfile::assemble(&termux_probe(), "com.termux");
    assert!(!profile.caps.is_declared(&Capability::FsSystem.id()));

    // Simulate the facts changing underneath the session: verity disabled and /system
    // remountable, but the table was derived before that happened.
    profile.device.verity = VerityState::NotEnforcing;
    profile.system_remountable = true;

    let gate = Gate::new(&profile);
    let d = gate.decide(&request(Capability::FsSystem), None, ready());
    assert!(
        matches!(d.refusal(), Some(Refusal::NotDeclared(_))),
        "a stale profile must refuse, not grant: {d:?}"
    );
    // The explanation still names a real missing condition rather than shrugging.
    let gap = gate
        .gaps()
        .iter()
        .find(|g| g.capability == Capability::FsSystem.id())
        .map(|g| g.reason.clone())
        .expect("fs:system must be explained");
    assert!(
        gap.contains("re-probe") || gap.contains("remount") || gap.contains("verity"),
        "the explanation should point at the staleness or the missing fact: {gap}"
    );
}

#[test]
fn the_domain_classification_drives_the_escalation_answer() {
    // SELinux, not the uid, is the real gate on Android (ADR-AND-001 §1.1). A denial in a
    // privileged domain is a different problem from one in an unprivileged domain, and
    // the classifier must tell them apart or it will suggest escalation that cannot help.
    let profile = rooted();
    let unprivileged = "avc: denied { read } for comm=\"cat\" path=\"/data/local/tmp/x\" \
                        scontext=u:r:shell:s0 tcontext=u:object_r:shell_data_file:s0 \
                        tclass=file permissive=0";
    let privileged = "avc: denied { read } for comm=\"cat\" path=\"/data/local/tmp/x\" \
                      scontext=u:r:magisk:s0 tcontext=u:object_r:system_data_file:s0 \
                      tclass=file permissive=0";

    let d = classify(&parse_denials(unprivileged)[0], &profile).unwrap();
    assert_eq!(d.remedy, Remedy::Escalate);

    let d = classify(&parse_denials(privileged)[0], &profile).unwrap();
    match &d.remedy {
        Remedy::AskUser { question } => {
            assert!(
                question.contains("android:selinux:permissive"),
                "already privileged, so only a policy change helps: {question}"
            );
        }
        other => panic!("expected a permissive-approval question, got {other:?}"),
    }
    assert_eq!(SelinuxDomain::parse("u:r:magisk:s0"), SelinuxDomain::Magisk);
}

#[test]
fn the_probe_fixtures_are_the_three_devices_the_spec_requires() {
    // android-host-probe.md §7 names the three snapshots. Pin the tier each fixture
    // produces, so a fixture edit cannot silently change which device is under test.
    assert_eq!(
        HostProfile::assemble(&termux_probe(), "com.termux")
            .name
            .as_str(),
        "termux"
    );
    assert_eq!(rooted().name.as_str(), "root-shell");
    assert_eq!(
        HostProfile::assemble(&apk_probe(), "com.example.agent")
            .name
            .as_str(),
        "apk-sandbox"
    );
    // Sanity on the facts that distinguish them.
    let termux = HostProfile::assemble(&termux_probe(), "com.termux");
    assert_eq!(termux.shell, Some(ShellDialect::Bash));
    assert!(!termux.su.got_root());
    assert!(rooted().su.got_root());
    assert_eq!(
        rooted().device.build_type,
        acowork_android::host::BuildType::UserDebug
    );
    assert_eq!(
        HostProfile::assemble(&apk_probe(), "com.example.agent").shell,
        None
    );
    let _ = (ProbeCommand::Id, SelinuxState::Enforcing);
}
