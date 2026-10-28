//! Ground-truth reconciliation: a real device's probe output, captured once and committed,
//! run through the same parsers and derivation the shipped node uses.
//!
//! The other test suites in this crate are built on fixtures written by the same person who
//! wrote the parsers. That is a closed loop: a fixture can assert whatever the author believed,
//! and nothing in it can say "actually, Android's mksh is built without `--version`". This file
//! is the open end of that loop.
//!
//! # Provenance
//!
//! `fixtures/devices/huawei-bla-al00-api29.json` was captured on 2026-10-28 from a Huawei
//! BLA-AL00, API 29, EMUI 10, arm64-v8a, bootloader locked, `ro.build.type=user`, no root, no
//! Termux, reached over adb by `cargo run -p acowork-android --example device_probe`. It is the
//! verbatim `ProbeOutput` — every string in it is what the device printed, including the NUL
//! that `/proc/self/attr/current` ends with and the empty `BASH=` line.
//!
//! # What it is for
//!
//! Four findings, each a bug, each invisible to the hand-written fixtures:
//!
//! 1. probe item 5b ran `/system/bin/sh --version`, which **errors** on a real device, so the
//!    dialect was never detected and a working shell host was classified as an APK sandbox;
//! 2. `/proc/*/attr/current` is NUL-terminated, and `str::trim` does not remove NUL, so the
//!    terminator was stored in the profile and echoed into audit records;
//! 3. a host with no Termux was handed a fabricated `$PREFIX`, forging the very marker the
//!    profile exists to record;
//! 4. the applet listings were the only source of command presence, and they cannot see
//!    `/system/bin` binaries — see [`the_read_surface_exists_on_the_device_only_item_6c_can_see`].

use std::path::PathBuf;

use acowork_android::host::capability::Capability;
use acowork_android::host::facts::{SelinuxDomain, SelinuxState, ShellDialect, VerityState};
use acowork_android::host::facts::{
    parse_bool_prop, parse_prop, su_helper_missing, su_prompt_denied,
};
use acowork_android::host::probe::ProbeOutput;
use acowork_android::host::spawn::ScriptedSpawnRunner;
use acowork_android::host::{
    AppletSet, ExecutionBackend, HostProfile, HostProfileName, Privilege, ShellBackend,
};
use acowork_platform_contract::HostDescription;

/// The device this fixture came from, as far as the profile is concerned.
const OWN_PACKAGE: &str = "com.acowork.node";

fn ground_truth() -> ProbeOutput {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/devices/huawei-bla-al00-api29.json");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "{}: the ground-truth fixture is part of the test suite, not a generated artifact",
            e
        )
    });
    serde_json::from_str(&text).expect("fixture must deserialize into ProbeOutput")
}

#[test]
fn the_device_that_started_this_file_is_not_an_apk_sandbox() {
    // The regression that motivated the harness. Every command in this fixture was executed by
    // a shell on the device, yet the port concluded "no usable shell" and refused
    // `android:shell:read` — on a host that had just answered `id -u` with `2000`.
    let profile = HostProfile::assemble(&ground_truth(), OWN_PACKAGE);
    assert!(profile.shell_executed, "a shell ran every probe command");
    assert_eq!(profile.name, HostProfileName::SystemShell);
    assert_eq!(profile.shell, Some(ShellDialect::MkSh));
    assert!(profile.caps.is_declared(&Capability::ShellRead.id()));

    // And it is not Termux, for the specific reasons Termux would be: this device has no
    // bash and never reported a `$PREFIX`. A tier name is a claim about the environment, so
    // the absence of both markers is what puts it in the fourth tier rather than the second.
    let paths = &profile.paths;
    assert_eq!(paths.bash, None, "no bash on this device");
    assert_eq!(paths.termux_prefix, None, "no Termux prefix on this device");
}

#[test]
fn the_backend_built_on_this_profile_does_not_call_itself_termux() {
    // The same fabrication, one layer down. `ShellBackend` serves both unprivileged-shell
    // tiers, and its `name()` — which is what the exec record carries — used to return the
    // literal `"termux"` regardless of what the probe found.
    let profile = HostProfile::assemble(&ground_truth(), OWN_PACKAGE);
    let backend = ShellBackend::with_runner(profile, ScriptedSpawnRunner::default())
        .expect("a profile with a shell must yield a backend");
    assert_eq!(backend.name(), "system-shell");
    assert_ne!(backend.name(), "termux");
}

#[test]
fn the_identity_the_device_reported_is_the_identity_the_profile_records() {
    let profile = HostProfile::assemble(&ground_truth(), OWN_PACKAGE);
    assert_eq!(profile.privilege, Privilege::ShellUid);
    assert_eq!(profile.selinux, SelinuxState::Enforcing);
    assert_eq!(profile.domain, SelinuxDomain::Shell);

    // `/proc/self/attr/current` ends with a NUL, not a newline. The stored context must not
    // carry it: it goes into the profile, into the audit trail, and into any comparison a
    // caller makes against a context read through `$(cat …)`, which does drop it.
    let ctx = profile
        .context
        .clone()
        .expect("the device reported a context");
    assert_eq!(ctx, "u:r:shell:s0");
    assert!(
        !ctx.contains('\0'),
        "the terminator leaked into the profile: {ctx:?}"
    );

    // The raw fixture still has it, which is the point: the harness does not pre-clean output
    // on the way in, so the parser is what has to be right.
    let raw_probe = ground_truth();
    let raw = &raw_probe.attr_current.as_ref().unwrap().stdout;
    assert!(
        raw.ends_with('\0'),
        "fixture must keep the real bytes: {raw:?}"
    );
}

#[test]
fn an_absent_su_is_read_as_absent_rather_than_as_a_declined_prompt() {
    // The wording list in `su_prompt_denied` was written from memory about Magisk and
    // KernelSU. This is what a device with *no* superuser at all actually says, and the two
    // have opposite retry semantics: "not found" is worth re-probing after an install, a
    // declined prompt is not retryable at all.
    let su = ground_truth().su.clone().expect("the su probe ran");
    assert_eq!(su.exit_code, Some(127));
    assert!(
        su_helper_missing(&su.stderr),
        "real wording not recognised: {:?}",
        su.stderr
    );
    assert!(
        !su_prompt_denied(&su.stderr),
        "a missing binary must not be recorded as the user saying no: {:?}",
        su.stderr
    );

    let profile = HostProfile::assemble(&ground_truth(), OWN_PACKAGE);
    assert!(profile.su.unavailable);
    assert!(!profile.su.prompt_denied);
    assert!(!profile.su.got_root());

    // Item 4a, the one added because `paths.su` was never a probed fact. On this device the
    // shell's own lookup agrees with the fixed-path attempt: no `su` anywhere on `PATH`
    // (`/sbin`, `/system/bin`, `/system/xbin`, `/vendor/bin`, `/vendor/xbin` and three apex
    // dirs were all on it), so exit 1 with empty stdout and no path in the profile.
    let su_path = ground_truth()
        .su_path
        .clone()
        .expect("item 4a runs on the device");
    assert_eq!(su_path.exit_code, Some(1));
    assert_eq!(su_path.stdout.trim(), "");
    assert_eq!(
        profile.paths.su, None,
        "an empty `command -v` answer must not become a path"
    );
}

#[test]
fn the_applet_listing_survives_the_real_typography() {
    // `toybox` with no arguments prints a *space-separated, line-wrapped* list, not one name
    // per line as the hand-written fixture had it.
    let toybox = ground_truth().toybox_list.clone().unwrap();
    let set = AppletSet::parse_list(&toybox.stdout);
    assert!(!set.list_source_missing);
    // `env` is in the list, and the adb transport depends on it: `env -i` is how a cleared
    // environment is reproduced on the device instead of the host.
    assert!(
        set.contains("env"),
        "the harness's `env -i` needs this applet"
    );
    assert!(set.contains("base64"));
    assert!(set.contains("cat"));
    assert!(
        set.len() > 150,
        "a real Android 10 toybox lists ~194: {}",
        set.len()
    );

    // `logcat` and `getprop` are standalone `/system/bin` binaries on this device, not toybox
    // applets, so the bulk listing does not contain them. The hand-written fixture claimed it
    // did. Nothing here proves those commands are *absent* — only that `toybox --list` is not
    // where their presence comes from; that is item 6c's `command -v` spot-check, which the
    // listing alone cannot substitute for (android-host-probe.md §7.5 item 1).
    assert!(
        !set.contains("logcat"),
        "logcat is /system/bin/logcat here, not a toybox applet"
    );
    assert!(!set.contains("getprop"));
}

#[test]
fn the_read_surface_exists_on_the_device_where_only_item_6c_can_see_it() {
    // ADR-AND-001 §4.4 defines the read allow-list as getprop / dumpsys / logcat / ps / df /
    // mount / getenforce. On this device seven of those tools are standalone `/system/bin`
    // binaries that appear in none of the 194 listed applets. Before item 6c the listings
    // were the *only* source of command presence, so a profile assembled from this device
    // declared absent the exact surface this port exists to offer — and the hand-written
    // fixtures, which listed `logcat` as an applet, kept the two sources from being told
    // apart.
    let probe = ground_truth();
    let listed = AppletSet::parse_list(&probe.toybox_list.as_ref().unwrap().stdout);
    let profile = HostProfile::assemble(&probe, OWN_PACKAGE);

    assert!(
        probe.applet_spot_checks.values().all(|o| o.succeeded()),
        "the device answered for every name it was asked about"
    );

    for name in [
        "logcat",
        "dumpsys",
        "getprop",
        "am",
        "pm",
        "input",
        "screencap",
    ] {
        assert!(
            !listed.contains(name),
            "{name} is not a toybox applet on this device; if the fixture changed, this \
             test is describing the wrong device"
        );
        assert!(
            profile.applets.contains(name),
            "{name} is at /system/bin/{name} and the profile must know it"
        );
    }

    // The ones that genuinely are applets are present through both sources, which is the
    // expected overlap rather than a contradiction.
    assert!(listed.contains("mount") && profile.applets.contains("mount"));
    assert!(listed.contains("ps") && profile.applets.contains("ps"));
}

#[test]
fn su_presence_has_exactly_one_source() {
    // `su` is decided by item 4a (`command -v su`), whose answer feeds `ShellPaths::su`.
    // Keeping it out of item 6c's list matters: two independent "is su present" claims on
    // one device is how a root tier gets built on evidence the other probe contradicts.
    assert!(
        !acowork_android::host::SPOT_CHECK_APPLETS.contains(&"su"),
        "su presence must come from item 4a only"
    );
    let probe = ground_truth();
    assert!(
        !probe.applet_spot_checks.contains_key("su"),
        "the spot-check set must not have grown an su answer"
    );
}

#[test]
fn the_device_facts_are_the_device_that_is() {
    use acowork_android::host::facts::BuildType;
    let probe = ground_truth();
    let profile = HostProfile::assemble(&probe, OWN_PACKAGE);
    let d = &profile.device;
    assert_eq!(d.build_type, BuildType::User);
    assert!(!d.debuggable, "ro.debuggable=0");
    assert!(d.secure, "ro.secure=1");
    assert!(d.adb_secure, "ro.adb.secure=1");
    assert_eq!(d.api_level, Some(29));
    assert_eq!(d.abi.as_deref(), Some("arm64-v8a"));
    assert_eq!(d.verity, VerityState::Enforcing);

    // A production build with a locked bootloader and enforcing verity is the case the whole
    // privilege model was designed for: the node must not assume it can write.
    assert!(!profile.system_remountable);
    assert!(!profile.caps.is_declared(&Capability::FsSystem.id()));
    assert!(
        !profile
            .caps
            .is_declared(&Capability::SelinuxPermissive.id())
    );
    assert!(!profile.caps.is_declared(&Capability::ShellWrite.id()));
}

#[test]
fn the_only_writable_roots_are_the_ones_the_touch_succeeded_on() {
    let profile = HostProfile::assemble(&ground_truth(), OWN_PACKAGE);
    let writable: Vec<&str> = profile
        .fs_roots
        .iter()
        .filter(|r| r.writable)
        .map(|r| r.path.as_str())
        .collect();
    assert_eq!(
        writable,
        vec!["/data/local/tmp", "/sdcard", "/storage/self/primary"],
        "the probe wrote to these and only these"
    );
    // `/data` and the partitions are present but not writable by uid 2000.
    for path in ["/data", "/system", "/vendor", "/product", "/"] {
        let root = profile
            .fs_roots
            .iter()
            .find(|r| r.path == path)
            .unwrap_or_else(|| panic!("{path} should have been reported as reachable"));
        assert!(!root.writable, "{path} is not writable by the shell uid");
    }
    // Which is exactly why `android:fs:outside-app` is declared and needs per-use approval.
    assert!(profile.caps.is_declared(&Capability::FsOutsideApp.id()));
}

#[test]
fn a_backend_built_on_the_real_profile_does_not_invent_a_termux_prefix() {
    let profile = HostProfile::assemble(&ground_truth(), OWN_PACKAGE);
    assert!(
        profile.paths.termux_prefix.is_none(),
        "no Termux on this device"
    );
    assert!(profile.paths.bash.is_none(), "no bash on this device");

    let backend = ShellBackend::new(profile).expect("a shell exists, so a backend can be built");
    assert_eq!(backend.shell_path().to_str(), Some("/system/bin/sh"));
    let env = backend.base_env();
    assert!(
        env.get("PREFIX").is_none(),
        "PREFIX is the Termux marker; setting it here would forge the tier: {env:?}"
    );
    assert!(
        !env.values().any(|v| v.contains("com.termux")),
        "no path may point into an install that was never probed: {env:?}"
    );
    // The scratch directory is the root the probe actually wrote to.
    assert_eq!(env.get("HOME").map(String::as_str), Some("/data/local/tmp"));
}

#[test]
fn the_props_the_device_printed_are_the_props_the_parsers_read() {
    // Run the property parsers over the raw captured text rather than over the assembled
    // profile, so a change in either the parser or the device output is attributable.
    let probe = ground_truth();
    let text = |o: &Option<acowork_android::host::probe::CommandOutput>| {
        o.as_ref().map(|c| c.stdout.clone()).unwrap_or_default()
    };
    assert_eq!(
        parse_prop(&text(&probe.prop_build_type)).as_deref(),
        Some("user")
    );
    assert!(!parse_bool_prop(&text(&probe.prop_debuggable)));
    assert!(parse_bool_prop(&text(&probe.prop_secure)));
    assert!(parse_bool_prop(&text(&probe.prop_adb_secure)));
}

#[test]
fn the_summary_reported_upward_names_the_tier_the_device_actually_is() {
    let profile = HostProfile::assemble(&ground_truth(), OWN_PACKAGE);
    let summary = HostDescription::summary(&profile);
    assert_eq!(summary.platform, "android");
    // R13: no serial, no model, no build fingerprint.
    let blob = format!("{summary:?}");
    for secret in ["BLA", "emulator-5554", "HUAWEI", "harmony"] {
        assert!(!blob.contains(secret), "summary leaks {secret}: {blob}");
    }
    assert!(HostDescription::is_r3_conformant(&profile));
}

#[test]
fn the_probe_budget_was_met_on_real_hardware() {
    // android-host-probe.md §3 bounds the whole probe. A real device over a real adb link is
    // the only way to know whether that number is fiction; measured here at ~2 s for 16
    // commands, which is why the budget is a budget and not an aspiration.
    let probe = ground_truth();
    let ran = [
        probe.id.as_ref(),
        probe.getenforce.as_ref(),
        probe.attr_current.as_ref(),
        probe.su.as_ref(),
        probe.bash_path.as_ref(),
        probe.system_sh_version.as_ref(),
        probe.toybox_list.as_ref(),
        probe.busybox_list.as_ref(),
        probe.mount_table.as_ref(),
    ]
    .into_iter()
    .flatten()
    .filter(|o| !o.timed_out)
    .count();
    assert_eq!(
        ran, 9,
        "no probe command may have hit its deadline on this device"
    );
}
