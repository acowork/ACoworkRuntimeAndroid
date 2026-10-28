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

use std::collections::BTreeMap;

use acowork_android::host::{AttributionVerdict, AuthorizationContext, LocalReadiness};
use acowork_android::host::{
    Capability, CommandOutput, Denial, FsRoot, HostProfile, LockOutcome, Privilege, ProbeCommand,
    ProbeOutput, SelinuxDomain, SelinuxState, ShellDialect, VerityState, authorize,
};

/// Build a probe output from `(command, stdout)` pairs, leaving everything else
/// unrun. Mirrors how a real runner reports a device where most applets exist.
fn probe_of(pairs: &[(ProbeCommand, &str)]) -> ProbeOutput {
    let mut out = ProbeOutput::default();
    for (cmd, stdout) in pairs {
        let value = CommandOutput::ok(stdout);
        match cmd {
            ProbeCommand::Id => out.id = Some(value),
            ProbeCommand::GetEnforce => out.getenforce = Some(value),
            ProbeCommand::AttrCurrent => out.attr_current = Some(value),
            ProbeCommand::Su => out.su = Some(value),
            ProbeCommand::BashPath => out.bash_path = Some(value),
            ProbeCommand::SystemShVersion => out.system_sh_version = Some(value),
            ProbeCommand::ToyboxList => out.toybox_list = Some(value),
            ProbeCommand::BusyboxList => out.busybox_list = Some(value),
            ProbeCommand::MountTable => out.mount_table = Some(value),
            ProbeCommand::SystemRemount => out.system_remount = Some(value),
            ProbeCommand::PropBuildType => out.prop_build_type = Some(value),
            ProbeCommand::PropDebuggable => out.prop_debuggable = Some(value),
            ProbeCommand::PropSecure => out.prop_secure = Some(value),
            ProbeCommand::PropAdbSecure => out.prop_adb_secure = Some(value),
            ProbeCommand::PropVerityMode => out.prop_veritymode = Some(value),
            ProbeCommand::PropSdk => out.prop_sdk = Some(value),
            ProbeCommand::PropAbi => out.prop_abi = Some(value),
        }
    }
    out
}

const TOYBOX_LIST: &str =
    "basename\ncat\nchmod\ndf\ndumpsys\ngetprop\nlogcat\nmount\nps\nsetprop\ntoybox\n";

// ── Baseline 1: user build + Termux ─────────────────────────────────────────

fn termux_probe() -> ProbeOutput {
    let mut probe = probe_of(&[
        (ProbeCommand::Id, "10233\n"),
        (ProbeCommand::GetEnforce, "Enforcing\n"),
        (
            ProbeCommand::AttrCurrent,
            "u:r:untrusted_app:s0:c123,c456\n",
        ),
        (
            ProbeCommand::BashPath,
            "/data/data/com.termux/files/usr/bin/bash\n",
        ),
        (
            ProbeCommand::SystemShVersion,
            "@(#)MIRBSD KSH R59 2020/10/31\n",
        ),
        (ProbeCommand::ToyboxList, TOYBOX_LIST),
        (
            ProbeCommand::MountTable,
            "/dev/block/sda1 /data f2fs rw,seclabel 0 0\n\
             /dev/block/dm-0 /system ext4 ro,seclabel 0 0\n",
        ),
        (ProbeCommand::PropBuildType, "user\n"),
        (ProbeCommand::PropDebuggable, "0\n"),
        (ProbeCommand::PropSecure, "1\n"),
        (ProbeCommand::PropAdbSecure, "1\n"),
        (ProbeCommand::PropVerityMode, "enforcing\n"),
        (ProbeCommand::PropSdk, "34\n"),
        (ProbeCommand::PropAbi, "arm64-v8a\n"),
    ]);
    probe.termux_prefix = Some("/data/data/com.termux/files/usr".to_string());
    probe.fs_roots = vec![
        FsRoot {
            path: "/data/data/com.termux/files/usr".to_string(),
            writable: true,
            own_package: false,
        },
        FsRoot {
            path: "/data/data/com.termux/files/home".to_string(),
            writable: true,
            own_package: false,
        },
    ];
    probe
}

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
    assert!(profile.caps.contains(Capability::ShellRead));
    assert!(!profile.caps.contains(Capability::ShellWrite));
    assert!(!profile.caps.contains(Capability::FsSystem));
    assert!(!profile.caps.contains(Capability::SelinuxPermissive));

    // `$PREFIX` is Termux's *own* storage, and the CLI deliverable runs inside
    // the Termux package — so writing there is writing to our own space, not
    // "outside the app". `android:fs:outside-app` must therefore be absent until
    // the user grants SAF access to somewhere else. This matches the README
    // capability matrix ("文件可达范围: `$PREFIX` + 用户授权的 SAF").
    assert!(
        !profile.caps.contains(Capability::FsOutsideApp),
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

    assert!(profile.caps.contains(Capability::FsOutsideApp));
    assert!(profile.caps.contains(Capability::ShellRead));
    assert!(!profile.caps.contains(Capability::ShellWrite));
    assert!(!profile.caps.contains(Capability::FsSystem));
    assert!(!profile.caps.contains(Capability::SelinuxPermissive));
}

// ── Baseline 2: userdebug + Magisk root ─────────────────────────────────────

fn rooted_probe() -> ProbeOutput {
    let mut probe = probe_of(&[
        (ProbeCommand::Id, "10233\n"),
        (ProbeCommand::GetEnforce, "Enforcing\n"),
        (
            ProbeCommand::AttrCurrent,
            "u:r:untrusted_app:s0:c123,c456\n",
        ),
        (ProbeCommand::Su, "0\nu:r:magisk:s0\n"),
        (
            ProbeCommand::SystemShVersion,
            "@(#)MIRBSD KSH R59 2020/10/31\n",
        ),
        (ProbeCommand::ToyboxList, TOYBOX_LIST),
        (
            ProbeCommand::BusyboxList,
            "BusyBox v1.34.1 multi-call binary.\nash\nsed\ngrep\n",
        ),
        (
            ProbeCommand::MountTable,
            "/dev/block/sda1 /data f2fs rw,seclabel 0 0\n\
             /dev/block/dm-0 /system ext4 ro,seclabel 0 0\n",
        ),
        (ProbeCommand::SystemRemount, ""),
        (ProbeCommand::PropBuildType, "userdebug\n"),
        (ProbeCommand::PropDebuggable, "1\n"),
        (ProbeCommand::PropVerityMode, "disabled\n"),
        (ProbeCommand::PropSdk, "34\n"),
        (ProbeCommand::PropAbi, "arm64-v8a\n"),
    ]);
    let mut spot = BTreeMap::new();
    for applet in acowork_android::host::SPOT_CHECK_APPLETS {
        spot.insert(
            applet.to_string(),
            CommandOutput::ok(&format!("/system/bin/{applet}\n")),
        );
    }
    probe.applet_spot_checks = spot;
    probe.fs_roots = vec![
        FsRoot {
            path: "/data/data/com.example.agent".to_string(),
            writable: true,
            own_package: true,
        },
        FsRoot {
            path: "/data/local/tmp".to_string(),
            writable: true,
            own_package: false,
        },
    ];
    probe
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
        assert!(profile.caps.contains(cap), "missing {cap}");
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

// ── Baseline 3: APK sandbox ─────────────────────────────────────────────────

#[test]
fn baseline_apk_sandbox() {
    // Nothing could be spawned: every command probe is absent, and only the
    // syscall-based item 12 produced an answer.
    let mut probe = ProbeOutput::nothing_ran();
    probe.fs_roots = vec![FsRoot {
        path: "/data/data/com.example.agent/files".to_string(),
        writable: true,
        own_package: true,
    }];

    let profile = HostProfile::assemble(&probe, "com.example.agent");

    assert!(!profile.name.has_shell());
    assert_eq!(profile.selinux, SelinuxState::Unknown);
    assert_eq!(profile.domain, SelinuxDomain::Unreadable);
    assert_eq!(profile.device.verity, VerityState::Unknown);
    assert!(
        profile.caps.is_empty(),
        "an APK sandbox must declare nothing, got {:?}",
        profile.caps.ids()
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
    assert!(!profile.caps.contains(Capability::ShellWrite));
    assert!(!profile.caps.contains(Capability::SelinuxPermissive));
    // Read tier survives: the shell is still there.
    assert!(profile.caps.contains(Capability::ShellRead));
}

#[test]
fn fault_missing_getenforce_closes_the_write_tier() {
    let mut probe = rooted_probe();
    // `getenforce` absent: the runner reports a failed spawn.
    probe.getenforce = Some(CommandOutput::failed(127, "getenforce: not found"));

    let profile = HostProfile::assemble(&probe, "com.example.agent");

    assert_eq!(profile.selinux, SelinuxState::Unknown);
    assert!(
        !profile.caps.contains(Capability::SelinuxPermissive),
        "android-host-probe.md §2 item 2: unknown SELinux never opens the write tier"
    );
}

#[test]
fn fault_getenforce_entirely_absent_is_still_unknown() {
    let mut probe = rooted_probe();
    probe.getenforce = None;
    let profile = HostProfile::assemble(&probe, "com.example.agent");
    assert_eq!(profile.selinux, SelinuxState::Unknown);
    assert!(!profile.caps.contains(Capability::SelinuxPermissive));
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
    assert!(profile.caps.contains(Capability::ShellRead));
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
    assert!(!profile.caps.contains(Capability::FsSystem));
    // Everything else on the root tier is unaffected.
    assert!(profile.caps.contains(Capability::ShellWrite));
}

#[test]
fn fault_malformed_mount_table_does_not_panic() {
    let mut probe = rooted_probe();
    probe.mount_table = Some(CommandOutput::ok(
        "mount: garbage \x00 line\nnot a mount line at all\n\n",
    ));
    // Must not panic; the profile still assembles from the other facts.
    let profile = HostProfile::assemble(&probe, "com.example.agent");
    assert!(profile.caps.contains(Capability::ShellRead));
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
    assert!(!profile.caps.contains(Capability::FsSystem));
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
            profile.caps.contains(Capability::ShellRead),
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

// ── The §7.4 conjunction, end to end ────────────────────────────────────────

fn ctx(dangerous: bool, attribution: AttributionVerdict) -> AuthorizationContext {
    AuthorizationContext {
        attribution,
        local: LocalReadiness {
            dangerous_mode: dangerous,
            lock: LockOutcome::Acquired,
        },
    }
}

#[test]
fn read_tier_flows_on_every_baseline_without_any_gate() {
    // The P1 deliverable: read-only system inspection works on a rooted device
    // with no approval, no lock and no attribution — that is the whole point of
    // "先只读、后可写".
    let profile = HostProfile::assemble(&rooted_probe(), "com.example.agent");
    let request = acowork_android::host::ExecRequest::read("logcat -d", "s-1");
    let grant = authorize(&request, &profile, &ctx(false, AttributionVerdict::Absent)).unwrap();
    assert!(!grant.holds_write_lock);
    assert!(!grant.attribution_checked);
}

#[test]
fn system_tier_is_refused_on_the_termux_baseline_because_the_fact_is_missing() {
    let profile = HostProfile::assemble(&termux_probe(), "com.termux");
    let request = acowork_android::host::ExecRequest {
        capability: Capability::FsSystem,
        approval_token: Some(acowork_android::host::ApprovalToken::new("t")),
        ..acowork_android::host::ExecRequest::read("mount -o remount,rw /system", "s-1")
    };
    // Even with dangerous-mode on and attribution granted, the device simply
    // cannot do this — and the refusal names the missing fact.
    let err = authorize(&request, &profile, &ctx(true, AttributionVerdict::Granted)).unwrap_err();
    match err {
        Denial::NotDeclared { reason, .. } => {
            assert!(
                reason.contains("verity") || reason.contains("remount"),
                "{reason}"
            );
        }
        other => panic!("expected NotDeclared, got {other:?}"),
    }
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
