//! Contract-level tests for the three host profiles.
//!
//! These are the executable form of two acceptance criteria:
//!
//! - **android-host-probe.md §7, 契约层**: "三档 profile 各产出一份 `HostProfile`
//!   快照，作为回归基线（真机：user 版 + Termux；userdebug + Magisk root；APK
//!   沙箱）". The fixtures below stand in for the three real devices; the
//!   assertions pin the *shape* each tier must have, so a parser regression shows
//!   up here rather than on a phone.
//! - **android-host-probe.md §7, 故障注入**: "su 弹窗被拒、`getenforce` 不存在、
//!   toybox/busybox 双缺失、`/system` remount 失败 —— 均须降级而非 panic，且错误
//!   信息可执行".
//!
//! Plus the P1 invariant from ADR-AND-001 §6: on the root-shell tier there is no
//! resident root process, i.e. the Runtime's own privilege stays below root.

use acowork_android::host::{
    BackendError, Capability, CommandOutput, ExecRecord, ExecRequest, FsRoot, HostProfile,
    Privilege, ProbeOutput, RefusalKind, SelinuxDomain, SelinuxState, SessionWriteLock,
    ShellDialect, VerityState, parse_denials,
};
use acowork_platform_contract::{
    AttributionTier, AttributionVerdict, Gate, GateDecision, HostDescription, LocalReadiness,
    LockState, Refusal,
};

mod common;

use common::{apk_probe, rooted_probe, termux_probe};

#[test]
fn baseline_termux_user_build() {
    let profile = HostProfile::assemble(&termux_probe(), "com.termux");

    assert_eq!(profile.privilege, Privilege::AppUid);
    assert_eq!(profile.selinux, SelinuxState::Enforcing);
    assert_eq!(profile.domain, SelinuxDomain::UntrustedApp);
    assert_eq!(profile.shell, Some(ShellDialect::Bash));
    assert_eq!(
        profile.device.build_type,
        acowork_android::host::BuildType::User
    );
    assert_eq!(profile.device.verity, VerityState::Enforcing);

    // Both dialects are visible so ADR-AND-001 §4.5 can register two tools.
    assert!(profile.dialects.contains(&ShellDialect::Bash));
    assert!(profile.dialects.contains(&ShellDialect::MkSh));

    // Read tier yes, write tier no: no su on a user build.
    assert!(profile.caps.is_declared(&Capability::ShellRead.id()));
    assert!(!profile.caps.is_declared(&Capability::ShellWrite.id()));
    assert!(!profile.caps.is_declared(&Capability::FsSystem.id()));
    assert!(
        !profile
            .caps
            .is_declared(&Capability::SelinuxPermissive.id())
    );

    // `$PREFIX` is Termux's *own* storage, and the CLI deliverable runs inside
    // the Termux package — so writing there is writing to our own space, not
    // "outside the app". `android:fs:outside-app` must therefore be absent until
    // the user grants SAF access to somewhere else. This matches the README
    // capability matrix ("文件可达范围: `$PREFIX` + 用户授权的 SAF").
    assert!(
        !profile.caps.is_declared(&Capability::FsOutsideApp.id()),
        "$PREFIX is own storage, not outside-app"
    );
    assert!(profile.fs_roots.iter().all(|r| r.own_package));

    assert!(profile.runtime_is_unprivileged());
}

#[test]
fn termux_with_a_saf_grant_gains_outside_app_and_nothing_else() {
    // The one thing that changes the Termux file story: the user grants access to
    // shared storage. That is a new writable root which is *not* our own package,
    // so `android:fs:outside-app` becomes a fact. Nothing else should move — in
    // particular no shell-write tier, because there is still no su.
    let mut probe = termux_probe();
    probe.fs_roots.push(FsRoot {
        path: "/storage/emulated/0/Documents".to_string(),
        writable: true,
        own_package: false,
    });

    let profile = HostProfile::assemble(&probe, "com.termux");

    assert!(profile.caps.is_declared(&Capability::FsOutsideApp.id()));
    assert!(profile.caps.is_declared(&Capability::ShellRead.id()));
    assert!(!profile.caps.is_declared(&Capability::ShellWrite.id()));
    assert!(!profile.caps.is_declared(&Capability::FsSystem.id()));
    assert!(
        !profile
            .caps
            .is_declared(&Capability::SelinuxPermissive.id())
    );
}

#[test]
fn baseline_userdebug_magisk_root() {
    let profile = HostProfile::assemble(&rooted_probe(), "com.example.agent");

    assert!(profile.su.got_root());
    assert_eq!(profile.selinux, SelinuxState::Enforcing);
    assert_eq!(profile.device.verity, VerityState::NotEnforcing);
    assert!(profile.system_remountable);

    // The full capability set, because every fact supports it.
    for cap in Capability::all() {
        assert!(profile.caps.is_declared(&cap.id()), "missing {cap}");
    }

    // Applets come from both list sources plus the spot checks.
    assert!(profile.applets.contains("logcat"));
    assert!(profile.applets.contains("ash"));
    assert!(profile.applets.contains("screencap"));
    assert!(!profile.applets.list_source_missing);

    // ADR-AND-001 §6 P1: no resident root process. The Runtime itself stays
    // unprivileged even though `su` is available to the helper.
    assert!(
        profile.runtime_is_unprivileged(),
        "the Runtime must never itself be root (ADR-AND-001 §4.1)"
    );
    assert_eq!(profile.privilege, Privilege::AppUid);
    assert_eq!(profile.domain, SelinuxDomain::UntrustedApp);
}

#[test]
fn baseline_apk_sandbox() {
    let probe = apk_probe();
    let profile = HostProfile::assemble(&probe, "com.example.agent");

    assert!(!profile.name.has_shell());
    assert_eq!(profile.selinux, SelinuxState::Unknown);
    assert_eq!(profile.domain, SelinuxDomain::Unreadable);
    assert_eq!(profile.device.verity, VerityState::Unknown);
    assert!(
        profile.caps.declared().is_empty(),
        "an APK sandbox must declare nothing, got {:?}",
        profile.caps.declared_ids()
    );
    assert!(profile.runtime_is_unprivileged());
}

// ── Fault injection (android-host-probe.md §7) ──────────────────────────────

#[test]
fn fault_denied_su_prompt_degrades_without_panic() {
    let mut probe = rooted_probe();
    probe.su = Some(CommandOutput::failed(1, "su: Permission denied"));

    let profile = HostProfile::assemble(&probe, "com.example.agent");

    assert!(profile.su.prompt_denied);
    assert!(!profile.su.got_root());
    // The write tier and the SELinux toggle must both disappear.
    assert!(!profile.caps.is_declared(&Capability::ShellWrite.id()));
    assert!(
        !profile
            .caps
            .is_declared(&Capability::SelinuxPermissive.id())
    );
    // Read tier survives: the shell is still there.
    assert!(profile.caps.is_declared(&Capability::ShellRead.id()));
}

#[test]
fn fault_missing_getenforce_closes_the_write_tier() {
    let mut probe = rooted_probe();
    // `getenforce` absent: the runner reports a failed spawn.
    probe.getenforce = Some(CommandOutput::failed(127, "getenforce: not found"));

    let profile = HostProfile::assemble(&probe, "com.example.agent");

    assert_eq!(profile.selinux, SelinuxState::Unknown);
    assert!(
        !profile
            .caps
            .is_declared(&Capability::SelinuxPermissive.id()),
        "android-host-probe.md §2 item 2: unknown SELinux never opens the write tier"
    );
}

#[test]
fn fault_getenforce_entirely_absent_is_still_unknown() {
    let mut probe = rooted_probe();
    probe.getenforce = None;
    let profile = HostProfile::assemble(&probe, "com.example.agent");
    assert_eq!(profile.selinux, SelinuxState::Unknown);
    assert!(
        !profile
            .caps
            .is_declared(&Capability::SelinuxPermissive.id())
    );
}

#[test]
fn fault_both_applet_sources_missing_degrades_to_builtins_only() {
    let mut probe = rooted_probe();
    probe.toybox_list = Some(CommandOutput::failed(127, "toybox: not found"));
    probe.busybox_list = None;
    probe.applet_spot_checks.clear();

    let profile = HostProfile::assemble(&probe, "com.example.agent");

    assert!(profile.applets.is_empty());
    assert!(
        profile.applets.list_source_missing,
        "the tool description has to say the shell has builtins only (§2 item 6)"
    );
    // A missing applet list is not a missing shell: mksh was still detected.
    assert_eq!(profile.shell, Some(ShellDialect::MkSh));
    assert!(profile.caps.is_declared(&Capability::ShellRead.id()));
}

#[test]
fn fault_system_remount_failure_closes_fs_system() {
    let mut probe = rooted_probe();
    probe.system_remount = Some(CommandOutput::failed(
        32,
        "mount: '/system' not in /proc/mounts",
    ));

    let profile = HostProfile::assemble(&probe, "com.example.agent");

    assert!(!profile.system_remountable);
    assert!(!profile.caps.is_declared(&Capability::FsSystem.id()));
    // Everything else on the root tier is unaffected.
    assert!(profile.caps.is_declared(&Capability::ShellWrite.id()));
}

#[test]
fn fault_malformed_mount_table_does_not_panic() {
    let mut probe = rooted_probe();
    probe.mount_table = Some(CommandOutput::ok(
        "mount: garbage \x00 line\nnot a mount line at all\n\n",
    ));
    // Must not panic; the profile still assembles from the other facts.
    let profile = HostProfile::assemble(&probe, "com.example.agent");
    assert!(profile.caps.is_declared(&Capability::ShellRead.id()));
}

#[test]
fn fault_garbage_property_values_degrade_to_unknown() {
    let mut probe = rooted_probe();
    probe.prop_build_type = Some(CommandOutput::ok("not-a-build-type\n"));
    probe.prop_sdk = Some(CommandOutput::ok("NaN\n"));
    probe.prop_veritymode = Some(CommandOutput::ok("wat\n"));

    let profile = HostProfile::assemble(&probe, "com.example.agent");

    assert_eq!(
        profile.device.build_type,
        acowork_android::host::BuildType::Unknown
    );
    assert_eq!(profile.device.api_level, None);
    assert_eq!(profile.device.verity, VerityState::Unknown);
    // Unknown verity is treated as enforcing, so fs:system stays closed.
    assert!(!profile.caps.is_declared(&Capability::FsSystem.id()));
}

// ── The tier invariant, across every baseline ───────────────────────────────

#[test]
fn tier_and_declared_shell_capability_never_disagree() {
    // The structural invariant the debug_assert in `assemble` checks, verified
    // here in release mode across all three baselines plus the fault variants.
    let cases = [
        HostProfile::assemble(&termux_probe(), "com.termux"),
        HostProfile::assemble(&rooted_probe(), "com.example.agent"),
        HostProfile::assemble(&ProbeOutput::nothing_ran(), "com.example.agent"),
    ];
    for profile in cases {
        assert_eq!(
            profile.name.has_shell(),
            profile.caps.is_declared(&Capability::ShellRead.id()),
            "{:?} disagrees with its own capability set",
            profile.name
        );
    }
}

#[test]
fn no_baseline_ever_reports_a_privileged_runtime() {
    // ADR-AND-001 §4.1's non-negotiable: the Runtime holds the Gateway
    // credential and the LLM key, so it is never the thing that runs as root.
    for probe in [termux_probe(), rooted_probe(), ProbeOutput::nothing_ran()] {
        let profile = HostProfile::assemble(&probe, "com.example.agent");
        assert!(profile.runtime_is_unprivileged());
        assert!(profile.privilege < Privilege::Root);
    }
}

// ── The gateway summary red line (ADR-AND-001 §7.1) ─────────────────────────

#[test]
fn gateway_summary_never_leaks_device_detail_on_any_tier() {
    for probe in [termux_probe(), rooted_probe()] {
        let profile = HostProfile::assemble(&probe, "com.example.agent");
        let json = serde_json::to_string(&profile.gateway_summary()).unwrap();

        for forbidden in [
            "u:r:",        // raw SELinux context
            "/data/data/", // concrete fs_roots paths
            "/data/local/tmp",
            "arm64-v8a", // device detail
            "userdebug",
            "com.termux",
        ] {
            assert!(
                !json.contains(forbidden),
                "summary leaked `{forbidden}`: {json}"
            );
        }
        // But it does carry the four things §7.1 says to report.
        assert!(json.contains("profile"));
        assert!(json.contains("privilege"));
        assert!(json.contains("caps"));
    }
}

#[test]
fn the_exec_error_path_never_leaks_device_detail_either() {
    // §7.1 has two halves. The summary is the one everyone remembers; the other is the
    // error string, which is *also* built on the device and shipped to the Gateway, and
    // which is far more likely to be written as free text because "just put the reason in
    // the message" feels helpful. Every way the host layer can fail, projected onto the
    // contract, must clear the same forbidden vocabulary.
    let context = "u:r:untrusted_app:s0:c166,c232";
    let denial = "avc: denied { read } for scontext=u:r:untrusted_app:s0:c166,c232 \
                  tcontext=u:object_r:shell_data_file:s0";
    let cases: Vec<(BackendError, &str)> = vec![
        (
            BackendError::PrivilegeNotGranted {
                observed_uid: Some(10166),
                observed_context: Some(context.into()),
            },
            "silent privilege drop",
        ),
        (
            BackendError::PrivilegeNotGranted {
                observed_uid: None,
                observed_context: None,
            },
            "identity probe produced nothing",
        ),
        (
            BackendError::EscalationUnavailable("su: prompt denied".into()),
            "no su",
        ),
        (
            BackendError::Backend("spawn failed".into()),
            "backend broke",
        ),
        (
            BackendError::Refused {
                reason: "`setprop` needs android:shell:write".into(),
                kind: RefusalKind::Mismatch,
            },
            "content refusal",
        ),
    ];

    for (err, label) in cases {
        let projected = err.to_contract().to_string();
        for forbidden in [
            "u:r:",
            "s0:c",
            "c166",
            "c232",
            "untrusted_app",
            "shell_data_file",
        ] {
            assert!(
                !projected.contains(forbidden),
                "{label}: projection leaked `{forbidden}`: {projected}"
            );
        }
        // R9 still holds on the far side of the seam: a refusal must say something usable.
        assert!(
            projected.split_whitespace().count() > 4,
            "{label}: projection is not actionable: {projected}"
        );
    }

    // The record is the local channel, and it keeps what the projection dropped — otherwise
    // the audit trail could not answer "who actually ran this".
    let record = ExecRecord {
        stdout: String::new(),
        stderr: denial.into(),
        exit_code: Some(1),
        selinux_denials: parse_denials(denial),
        uid: Some(10166),
        context: Some(context.into()),
        duration_ms: 12,
        truncated: false,
        timed_out: false,
    };
    assert_eq!(record.context.as_deref(), Some(context));
    assert!(!record.selinux_denials.is_empty());
    let wire = serde_json::to_string(&record.to_contract()).unwrap();
    for forbidden in ["u:r:", "c166", "s0:c"] {
        assert!(
            !wire.contains(forbidden),
            "ExecOutcome leaked `{forbidden}`: {wire}"
        );
    }
}

// ── The §7.4 conjunction, end to end ────────────────────────────────────────
//
// These drive the *contract* gate, not an Android-local one. That is the point of the
// rewiring: the rules that decide a request live in `acowork-platform-contract`, so a
// second platform inherits them by depending on the crate. What Android contributes here
// is the request shape (`ExecRequest`), the host description (`HostProfile`) and the
// session-identity lock.

/// Readiness with every local switch on, so a test isolates one rule at a time.
fn ready() -> LocalReadiness {
    LocalReadiness {
        dangerous_session: true,
        approval_presented: true,
        lock: LockState::Available,
    }
}

#[test]
fn read_tier_flows_without_approval_lock_or_attribution() {
    // The P1 deliverable: read-only system inspection works with no approval, no lock
    // and no attribution verdict — the whole point of "先只读、后可写".
    //
    // It flows on the two baselines that *have a shell*. It does not flow on the APK
    // sandbox, and that is not an exception to the rule: with no shell there is nothing
    // to read with, so `android:shell:read` was never declared. Declaring it anyway would
    // be the "capability lie" upstream design doc 30 §11.1 warns is worse than no
    // capability at all, and which B12's shell conjunct exists to prevent.
    let request = ExecRequest::read("logcat -d", "s-1");

    for probe in [rooted_probe(), termux_probe()] {
        let profile = HostProfile::assemble(&probe, "com.example.agent");
        let gate = Gate::new(&profile);
        // `for_read` presents no approval, no dangerous-mode switch and no verdict.
        let d = gate.decide(&request, None, LocalReadiness::for_read());
        assert_eq!(
            d,
            GateDecision::Allow {
                capability: Capability::ShellRead.id(),
                hold_lock: false
            },
            "read tier must flow on {:?} with nothing presented",
            profile.name
        );
    }
}

#[test]
fn read_tier_is_refused_on_the_apk_sandbox_because_there_is_no_shell() {
    // The other direction, pinned so the two cannot drift: a host with no shell must not
    // be handed a shell capability, however harmless read-only access sounds.
    let profile = HostProfile::assemble(&apk_probe(), "com.example.agent");
    let gate = Gate::new(&profile);
    assert!(
        profile.caps.declared().is_empty(),
        "the APK sandbox declares nothing; got {:?}",
        profile.caps.declared_ids()
    );

    let d = gate.decide(
        &ExecRequest::read("logcat -d", "s-1"),
        None,
        LocalReadiness::for_read(),
    );
    assert!(
        matches!(d.refusal(), Some(Refusal::NotDeclared(_))),
        "got {d:?}"
    );

    // And the gap is explained, not silently absent (R9).
    let gap = gate
        .gaps()
        .iter()
        .find(|g| g.capability == Capability::ShellRead.id())
        .expect("shell:read must be reported as a gap on the APK sandbox")
        .reason
        .clone();
    // The wording names the *evidence* that is missing — a shell that ran the probe — rather
    // than "no usable shell", which a reader could mistake for "a shell exists but we do not
    // trust it". The two have different remedies.
    assert!(gap.contains("no shell"), "{gap}");
}

#[test]
fn system_tier_is_refused_on_the_termux_baseline_because_the_fact_is_missing() {
    let profile = HostProfile::assemble(&termux_probe(), "com.termux");
    let gate = Gate::new(&profile);
    let request = ExecRequest {
        capability: Capability::FsSystem.id(),
        approval_token: Some(acowork_android::host::ApprovalToken::new("t")),
        rollback_plan: Some("reflash the stock image".to_string()),
        ..ExecRequest::read("mount -o remount,rw /system", "s-1")
    };

    // Even with dangerous-mode on, an approval presented and attribution granted, the
    // device simply cannot do this — and the refusal names the missing fact (R9).
    let d = gate.decide(
        &request,
        Some(AttributionVerdict::granted_for(AttributionTier::Manage)),
        ready(),
    );
    assert!(
        matches!(d.refusal(), Some(Refusal::NotDeclared(_))),
        "got {d:?}"
    );

    // The explanation comes from the port, through the contract's gap reporting.
    let gaps = gate.gaps();
    let fs_system = gaps
        .iter()
        .find(|g| g.capability == Capability::FsSystem.id())
        .expect("fs:system must be reported as a gap on Termux");
    assert!(
        fs_system.reason.contains("verity") || fs_system.reason.contains("remount"),
        "the gap must name the missing fact: {}",
        fs_system.reason
    );
}

#[test]
fn the_manage_tier_needs_a_gateway_verdict_even_on_a_capable_device() {
    // B1, end to end: the rooted device *can* do this, dangerous-mode is on, an approval
    // is presented — and it is still refused, because the control plane has not said this
    // session may touch this device. No verdict means no pass.
    let profile = HostProfile::assemble(&rooted_probe(), "com.example.agent");
    let gate = Gate::new(&profile);
    assert!(
        profile.caps.is_declared(&Capability::FsSystem.id()),
        "the rooted baseline must actually declare fs:system for this test to mean anything"
    );

    let request = ExecRequest {
        capability: Capability::FsSystem.id(),
        approval_token: Some(acowork_android::host::ApprovalToken::new("t")),
        rollback_plan: Some("reflash the stock image".to_string()),
        ..ExecRequest::read("mount -o remount,rw /system", "s-1")
    };

    let d = gate.decide(&request, None, ready());
    assert!(
        matches!(
            d.refusal(),
            Some(Refusal::AttributionDenied {
                required: AttributionTier::Manage
            })
        ),
        "got {d:?}"
    );

    // A `use`-tier verdict does not satisfy a `manage`-tier capability.
    let d = gate.decide(
        &request,
        Some(AttributionVerdict::granted_for(AttributionTier::Use)),
        ready(),
    );
    assert!(
        matches!(d.refusal(), Some(Refusal::AttributionDenied { .. })),
        "got {d:?}"
    );

    // The matching verdict does.
    let d = gate.decide(
        &request,
        Some(AttributionVerdict::granted_for(AttributionTier::Manage)),
        ready(),
    );
    assert!(d.is_allowed(), "got {d:?}");
    assert!(
        matches!(
            d,
            GateDecision::Allow {
                hold_lock: true,
                ..
            }
        ),
        "a mutating capability must tell the caller to hold the lock"
    );
}

#[test]
fn the_verdict_carries_no_identity() {
    // ADR-087 D1/D5: the node must not learn who was authorised. The verdict is a
    // boolean plus the tier it was issued for, and serializing it must not grow a field.
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
}

#[test]
fn a_busy_device_refuses_a_second_mutating_call_and_names_the_holder() {
    // ADR-AND-001 §7.2: no queueing, no preemption, and the refusal names the holder —
    // which is information the contract's identity-free lock cannot carry, so the
    // Android session lock supplies it.
    let profile = HostProfile::assemble(&rooted_probe(), "com.example.agent");
    let lock = SessionWriteLock::new();
    let t0 = std::time::Duration::ZERO;

    assert!(matches!(
        lock.try_acquire("s-1", t0),
        acowork_android::host::SessionLockOutcome::Acquired
    ));
    match lock.try_acquire("s-2", std::time::Duration::from_secs(5)) {
        acowork_android::host::SessionLockOutcome::HeldBy {
            holder,
            retry_after,
        } => {
            assert_eq!(holder, "s-1");
            assert_eq!(retry_after, std::time::Duration::from_secs(595));
        }
        other => panic!("expected HeldBy, got {other:?}"),
    }

    // The gate sees the same fact and refuses.
    let gate = Gate::new(&profile);
    let request = ExecRequest {
        capability: Capability::ShellWrite.id(),
        approval_token: Some(acowork_android::host::ApprovalToken::new("t")),
        ..ExecRequest::read("setprop debug.x 1", "s-2")
    };
    let busy = LocalReadiness {
        lock: lock.lock_state("s-2", std::time::Duration::from_secs(5)),
        ..ready()
    };
    assert!(matches!(
        gate.decide(&request, None, busy).refusal(),
        Some(Refusal::DeviceBusy { .. })
    ));

    // The holder itself is not blocked by its own lock.
    let own = LocalReadiness {
        lock: lock.lock_state("s-1", std::time::Duration::from_secs(5)),
        ..ready()
    };
    assert!(gate.decide(&request, None, own).is_allowed());
}

#[test]
fn a_root_runtime_is_refused_mutating_work_by_r3() {
    // ADR-AND-001 §4.1 as an enforced rule rather than a sentence in a document. The
    // baselines never produce this, so build it deliberately.
    let mut profile = HostProfile::assemble(&rooted_probe(), "com.example.agent");
    profile.privilege = Privilege::Root;
    assert!(!profile.is_r3_conformant());

    let gate = Gate::new(&profile);
    let request = ExecRequest {
        capability: Capability::ShellWrite.id(),
        approval_token: Some(acowork_android::host::ApprovalToken::new("t")),
        ..ExecRequest::read("setprop debug.x 1", "s-1")
    };
    assert!(
        matches!(
            gate.decide(&request, None, ready()).refusal(),
            Some(Refusal::PrivilegeViolation { .. })
        ),
        "a root node must not be handed mutating capabilities"
    );
    // Reads still work: R3 is about not *holding* privilege, not about being useless.
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
fn an_irreversible_capability_needs_a_stated_rollback_path() {
    // Contract rule R8. `/system` has no snapshot to restore from, so the model must
    // acknowledge the cost — in practice "reflash the stock image".
    let profile = HostProfile::assemble(&rooted_probe(), "com.example.agent");
    let gate = Gate::new(&profile);
    let v = Some(AttributionVerdict::granted_for(AttributionTier::Manage));

    let no_plan = ExecRequest {
        capability: Capability::FsSystem.id(),
        approval_token: Some(acowork_android::host::ApprovalToken::new("t")),
        rollback_plan: None,
        ..ExecRequest::read("mount -o remount,rw /system", "s-1")
    };
    assert!(matches!(
        gate.decide(&no_plan, v, ready()).refusal(),
        Some(Refusal::RollbackPlanRequired(_))
    ));

    // `setenforce 0` is auto-restored at session end (ADR-AND-001 §8), so it has a real
    // undo and must not be made to state one.
    let permissive = ExecRequest {
        capability: Capability::SelinuxPermissive.id(),
        approval_token: Some(acowork_android::host::ApprovalToken::new("t")),
        rollback_plan: None,
        ..ExecRequest::read("setenforce 0", "s-1")
    };
    assert!(gate.decide(&permissive, v, ready()).is_allowed());
}

#[test]
fn device_facts_and_applets_reach_the_tool_description_inputs() {
    // ADR-AND-001 §4.5: tool descriptions are generated from what the probe
    // found, not hardcoded. These are the inputs that generation reads.
    let profile = HostProfile::assemble(&rooted_probe(), "com.example.agent");
    assert_eq!(profile.device.api_level, Some(34));
    assert_eq!(profile.device.abi.as_deref(), Some("arm64-v8a"));
    assert!(profile.device.debuggable);
    assert!(profile.applets.contains("dumpsys"));
    // A command that was never reported must be absent, so the generated
    // description cannot advertise something the device does not have.
    assert!(!profile.applets.contains("bugreportz"));
    assert!(!profile.applets.contains("definitely-not-an-applet"));
}
