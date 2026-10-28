//! Shared probe fixtures for the Android integration tests.
//!
//! These stand in for the three real devices android-host-probe.md §7 requires
//! snapshots of: a `user` build under Termux, a `userdebug` build with Magisk root,
//! and a stock APK sandbox. Keeping them in one module means the baseline tests and
//! the rule-conformance tests probe *the same* three devices, so a fixture cannot
//! drift between the two suites.

#![allow(dead_code)] // Not every fixture is used by every test binary.

use std::collections::BTreeMap;

use acowork_android::host::{CommandOutput, FsRoot, ProbeCommand, ProbeOutput};

/// Build a probe output from `(command, stdout)` pairs, leaving everything else
/// unrun. Mirrors how a real runner reports a device where most applets exist.
pub fn probe_of(pairs: &[(ProbeCommand, &str)]) -> ProbeOutput {
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

pub const TOYBOX_LIST: &str =
    "basename\ncat\nchmod\ndf\ndumpsys\ngetprop\nlogcat\nmount\nps\nsetprop\ntoybox\n";

// ── Baseline 1: user build + Termux ─────────────────────────────────────────

pub fn termux_probe() -> ProbeOutput {
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

// ── Baseline 2: userdebug + Magisk root ─────────────────────────────────────

pub fn rooted_probe() -> ProbeOutput {
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

// ── Baseline 3: APK sandbox ─────────────────────────────────────────────────

/// The APK-sandbox baseline: nothing could be spawned, every command probe absent,
/// and only the syscall-based item 12 produced an answer.
pub fn apk_probe() -> ProbeOutput {
    let mut probe = ProbeOutput::nothing_ran();
    probe.fs_roots = vec![FsRoot {
        path: "/data/data/com.example.agent/files".to_string(),
        writable: true,
        own_package: true,
    }];
    probe
}
