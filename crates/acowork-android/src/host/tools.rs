//! ADR-AND-001 §4.5 — the shell tools a host registers, described from what was measured.
//!
//! Upstream registers Git Bash and PowerShell as two separate tools on Windows, each with its
//! own description, so that the model picks between them instead of guessing. Android copies
//! the shape: `bash` where a bash was resolved, `ash` for `/system/bin/sh`. The naming
//! divergence (upstream registers a single `shell` tool on Unix) is readiness item B5 and is
//! still awaiting an upstream ruling; nothing here depends on the answer, only on the text.
//!
//! # Two rules this module exists to enforce
//!
//! 1. **Register a tool only when its interpreter is known.** A tool whose path was never
//!    resolved is a promise the backend cannot keep: [`super::backends`] clears the child
//!    environment, so a bare command name has nothing to resolve against.
//! 2. **Say only what the probe saw.** Every sentence in a generated description traces to a
//!    field of [`HostProfile`]. The tempting failure mode is a description that reads like
//!    Android folklore — "mksh has no arrays", "`/system` is read-only" — which is wrong on
//!    some device and the model then refuses a command that would have worked, or relies on a
//!    restriction that was never there. Where the probe has no answer, the description says
//!    it does not know.
//!
//! The description is also the only place the *presence* of a command becomes visible to the
//! model. Probe item 6c went and asked `command -v` for each name in §4.4's vocabulary; this
//! module reports those answers, and reports the gaps as gaps.

use std::path::{Path, PathBuf};

use crate::host::commands::{self, READ_TIER_COMMANDS, WRITE_TIER_COMMANDS};
use crate::host::facts::{Privilege, SelinuxState, ShellDialect};
use crate::host::profile::HostProfile;

/// One shell tool, in the shape a node would register it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShellTool {
    /// The name the model calls. `bash` or `ash` (ADR-AND-001 §4.5).
    pub name: &'static str,
    /// The interpreter this tool binds to. Always absolute, for the reason in the module doc.
    pub path: PathBuf,
    /// The dialect the probe identified for *this* interpreter, when it identified one.
    ///
    /// `None` means the platform shell ran the probe successfully but named nothing we
    /// recognise — busybox ash sets neither `KSH_VERSION` nor `BASH_VERSION`, and a device
    /// in that state gets a tool, not a guess.
    pub dialect: Option<ShellDialect>,
    /// The description text handed to the model.
    pub description: String,
}

/// The shell tools this profile justifies, in registration order (`bash` first when present).
pub fn shell_tools(profile: &HostProfile) -> Vec<ShellTool> {
    let mut tools = Vec::new();
    if let Some(bash) = profile.paths.bash.clone() {
        let dialect = Some(ShellDialect::Bash);
        tools.push(ShellTool {
            name: "bash",
            description: describe(profile, "bash", &bash, dialect),
            path: bash,
            dialect,
        });
    }
    if profile.shell_executed {
        let dialect = ash_dialect(profile);
        let path = profile.paths.system_sh.clone();
        tools.push(ShellTool {
            name: "ash",
            description: describe(profile, "ash", &path, dialect),
            path,
            dialect,
        });
    }
    tools
}

/// The dialect of `/system/bin/sh` specifically.
///
/// `ShellDialect::Bash` in [`HostProfile::dialects`] came from `command -v bash` resolving a
/// different binary, so it must not be attributed to the platform shell; and when both are
/// known, mksh/busybox is the answer for `/system/bin/sh` because probe item 5b asked that
/// binary to name itself.
fn ash_dialect(profile: &HostProfile) -> Option<ShellDialect> {
    if profile.dialects.contains(&ShellDialect::MkSh) {
        Some(ShellDialect::MkSh)
    } else if profile.dialects.contains(&ShellDialect::BusyBoxSh) {
        Some(ShellDialect::BusyBoxSh)
    } else {
        None
    }
}

fn dialect_line(dialect: Option<ShellDialect>) -> String {
    match dialect {
        Some(ShellDialect::Bash) => "This is GNU bash.".to_string(),
        Some(ShellDialect::MkSh) => {
            "This is MIRBSD ksh (mksh): not bash, so do not assume bash-specific syntax."
                .to_string()
        }
        Some(ShellDialect::BusyBoxSh) => {
            "This is BusyBox ash: not bash, so do not assume bash-specific syntax.".to_string()
        }
        None => "The probe could not identify the dialect; do not assume bash or mksh syntax."
            .to_string(),
    }
}

/// Build the description for one tool.
///
/// Six lines, in this order: what the tool binds to; which dialect that is; which §4.4
/// commands exist; where writing is possible; what can be collected as evidence; and the
/// trust boundary the model is inside. Each is stated from a measured field, and each says
/// "not measured" rather than inheriting a default.
fn describe(
    profile: &HostProfile,
    name: &'static str,
    path: &Path,
    dialect: Option<ShellDialect>,
) -> String {
    let mut blocks = vec![
        format!("{name} — {}", path.display()),
        dialect_line(dialect),
    ];
    blocks.push(commands_block(profile));
    blocks.push(writes_block(profile));
    blocks.push(writable_block(profile));
    blocks.push(evidence_block(profile));
    blocks.push(boundary_block(profile));
    blocks.join("\n")
}

fn commands_block(profile: &HostProfile) -> String {
    if profile.applets.list_source_missing {
        return "Commands: neither `toybox` nor `busybox` returned a list on this device, so \
                the command set is unknown — check that a command exists before relying on it."
            .to_string();
    }
    let present: Vec<&str> = READ_TIER_COMMANDS
        .iter()
        .copied()
        .filter(|c| profile.applets.contains(c))
        .collect();
    let missing: Vec<&str> = READ_TIER_COMMANDS
        .iter()
        .copied()
        .filter(|c| !profile.applets.contains(c))
        .collect();
    let mut line = format!(
        "Read commands present: {}.",
        if present.is_empty() {
            "none of them".to_string()
        } else {
            present.join(", ")
        }
    );
    if !missing.is_empty() {
        line.push_str(&format!(" Not on this device: {}.", missing.join(", ")));
    }
    line
}

fn writes_block(profile: &HostProfile) -> String {
    if profile.applets.list_source_missing {
        return String::new();
    }
    let present: Vec<&str> = WRITE_TIER_COMMANDS
        .iter()
        .copied()
        .filter(|c| profile.applets.contains(c))
        .collect();
    if present.is_empty() {
        return "No state-changing system-service command was found on this device.".to_string();
    }
    format!(
        "Present but not unattended — each needs `android:shell:write` and an approval: {}.",
        present.join(", ")
    )
}

fn writable_block(profile: &HostProfile) -> String {
    let writable: Vec<&str> = profile
        .fs_roots
        .iter()
        .filter(|root| root.writable)
        .map(|root| root.path.as_str())
        .collect();
    if writable.is_empty() {
        return "Writable locations: none was confirmed by a write probe.".to_string();
    }
    format!("Writable locations: {}.", writable.join(", "))
}

/// What `getEvidence` can actually collect here, stated per source.
///
/// The ADR's evidence list (§4.6 item 6) reads as six available sources. On a `user` build
/// they are six permission questions, and the answers differ per path: the BLA-AL00 this
/// was verified against lists three filenames under `/data/anr` and refuses to open every
/// one of them, while `/data/tombstones` cannot even be stat'd. So each source is named
/// with the access class that was measured, and a source the probe never answered for says
/// so rather than dropping off the list — an agent that reads a silent omission as
/// "unavailable" will decline to ask for root on a device where the answer was never asked.
fn evidence_block(profile: &HostProfile) -> String {
    use crate::host::facts::EvidencePath;
    if profile.evidence.is_unknown() {
        // The command's state is reported even here: it comes from the spot check, which is a
        // different probe from the path walk, and an unanswered `/data/anr` says nothing about
        // whether `bugreportz` is installed.
        return format!(
            "Evidence: no evidence source was probed, so availability is unknown.{}",
            bugreportz_note(profile)
        );
    }
    let mut parts = Vec::new();
    for path in EvidencePath::ALL {
        let access = profile.evidence.access(path);
        if access == crate::host::facts::EvidenceAccess::NotProbed {
            parts.push(format!("{} not probed", path.path()));
        } else {
            parts.push(format!("{} {}", path.path(), access.describe()));
        }
    }
    let inventory = match profile.evidence.dumpsys_services {
        Some(count) => format!(
            " `dumpsys` has {count} running services to dump from (each needs its own `android:shell:read` approval)."
        ),
        None => " The `dumpsys` service inventory was not answered.".to_string(),
    };
    format!(
        "Evidence: {}.{}{}",
        parts.join("; "),
        inventory,
        bugreportz_note(profile)
    )
}

/// The sixth source in ADR-AND-001 §4.6 item 6, which is a command rather than a path.
///
/// `bugreportz` is the one evidence source no applet listing can see: on the BLA-AL00 it is a
/// standalone `/system/bin` binary, absent from the 194 names `toybox` reports, so the only
/// thing that knows about it is probe item 6c's `command -v` spot check. It is therefore also
/// the source a description built from a listing would most confidently get wrong — not by
/// misdescribing it but by never mentioning it, and an agent that is never told a command
/// exists does not ask for the approval it needs.
///
/// The tier is read back from the classifier rather than written down here, because the two
/// have different owners: an agent told one thing by a tool description and refused in some
/// other wording by the gate has been lied to by us twice over, and the second time is the one
/// that costs it a retry.
fn bugreportz_note(profile: &HostProfile) -> String {
    const NAME: &str = "bugreportz";
    // The invocation §4.6 item 6 means: a partial report. Whether `-p` exists on *this* build
    // is not something the probe measured, and nothing here claims that it was.
    const SCRIPT: &str = "bugreportz -p";

    if !profile.applets.was_spot_checked(NAME) {
        // Not "not installed": nobody asked. Item 6c is the only source that can answer for
        // this name, and a profile assembled without it has not.
        return format!(" `{NAME}` was not asked about, so whether this device has it is unknown.");
    }
    if !profile.applets.contains(NAME) {
        return format!(" `{NAME}` is not installed on this device.");
    }
    let claimed = Some(crate::host::capability::Capability::ShellWrite);
    match commands::check(SCRIPT, claimed) {
        Ok(verdict) => {
            let effect = verdict.strongest();
            match effect.capability() {
                Some(cap) => format!(
                    " `{NAME}` is installed; it is not an unattended read — the classifier puts it in the `{cap}` tier, approval required."
                ),
                // Opaque or banned: no capability to name. Say which, in the classifier's own
                // words, because "needs approval" would send the agent to ask for an approval
                // that does not exist.
                None => format!(
                    " `{NAME}` is installed but `{SCRIPT}` is {} under any capability, so asking for approval will not unblock it.",
                    effect_word(effect)
                ),
            }
        }
        Err(refusal) => format!(" `{NAME}` is installed and this port will not run it: {refusal}"),
    }
}

/// [`Effect`](commands::Effect) in the few words a model needs, derived from the enum rather
/// than restated as prose that can drift from it.
fn effect_word(effect: commands::Effect) -> &'static str {
    match effect {
        commands::Effect::Banned => "hard-banned by §4.6.3 item 3",
        commands::Effect::Opaque => "unanalysable",
        // Only the two effects with no capability reach this function. Naming the rest instead
        // of `unreachable!()` is deliberate: this runs while building a tool description, and
        // a panic there would take the Runtime's own registration down with it. A new effect
        // added to the enum lands here as text that is merely imprecise.
        commands::Effect::ReadOnly => "readable without approval",
        commands::Effect::ShellWrite => "a write",
        commands::Effect::FileWrite => "a file write",
        commands::Effect::SystemWrite => "a system write",
        commands::Effect::SelinuxChange => "an SELinux change",
    }
}

fn boundary_block(profile: &HostProfile) -> String {
    // Stated from the enum, not from `Privilege::uid()`: that returns a placeholder for app
    // uids (the real one is `u0_aNNN`, which the probe does not measure), and a description
    // printing "uid 10000" would be inventing a fact about the device.
    let who = match profile.privilege {
        Privilege::Root => "uid 0 (root)",
        Privilege::ShellUid => "uid 2000 (shell)",
        Privilege::AppUid => "the app's own uid",
    };
    let selinux = match profile.selinux {
        SelinuxState::Enforcing => "SELinux is enforcing",
        SelinuxState::Permissive => "SELinux is permissive",
        SelinuxState::Unknown => "SELinux mode is unknown",
    };
    format!("Runs as {who}; {selinux}.")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::capability::{PLATFORM, android_vocabulary};
    use crate::host::facts::{
        AppletSet, BuildType, DeviceFacts, FsRoot, Privilege, SelinuxDomain, SelinuxState, SuProbe,
        VerityState,
    };
    use crate::host::profile::{HostProfileName, ShellPaths};
    use acowork_platform_contract::CapabilityTable;

    fn profile(
        name: HostProfileName,
        privilege: Privilege,
        shell_executed: bool,
        dialects: &[ShellDialect],
        applets: &str,
        paths: ShellPaths,
    ) -> HostProfile {
        HostProfile {
            name,
            privilege,
            selinux: SelinuxState::Enforcing,
            context: Some("u:r:shell:s0".to_string()),
            domain: SelinuxDomain::Shell,
            shell: dialects.first().copied(),
            shell_executed,
            dialects: dialects.iter().copied().collect(),
            applets: AppletSet::parse_list(applets),
            fs_roots: vec![
                FsRoot {
                    path: "/data/local/tmp".to_string(),
                    writable: true,
                    own_package: false,
                },
                FsRoot {
                    path: "/system".to_string(),
                    writable: false,
                    own_package: false,
                },
            ],
            evidence: crate::host::facts::EvidenceSurface::default(),
            su: SuProbe {
                uid: None,
                context: None,
                prompt_denied: false,
                unavailable: true,
            },
            system_remountable: false,
            caps: CapabilityTable::new(PLATFORM, android_vocabulary()).unwrap(),
            device: DeviceFacts {
                build_type: BuildType::User,
                debuggable: false,
                secure: true,
                adb_secure: true,
                api_level: Some(29),
                abi: Some("arm64-v8a".to_string()),
                verity: VerityState::Enforcing,
            },
            paths,
        }
    }

    /// The BLA-AL00 as measured: mksh, no bash, no su, the seven §4.4 reads plus `settings`.
    fn system_shell() -> HostProfile {
        profile(
            HostProfileName::SystemShell,
            Privilege::ShellUid,
            true,
            &[ShellDialect::MkSh],
            "getprop dumpsys logcat ps df mount getenforce setprop am pm settings input",
            ShellPaths::default(),
        )
    }

    fn termux() -> HostProfile {
        let paths = ShellPaths {
            bash: Some("/data/data/com.termux/files/usr/bin/bash".into()),
            termux_prefix: Some("/data/data/com.termux/files/usr".to_string()),
            ..ShellPaths::default()
        };
        profile(
            HostProfileName::Termux,
            Privilege::AppUid,
            true,
            &[ShellDialect::Bash, ShellDialect::MkSh],
            "getprop dumpsys logcat ps df mount getenforce",
            paths,
        )
    }

    fn apk_sandbox() -> HostProfile {
        profile(
            HostProfileName::ApkSandbox,
            Privilege::AppUid,
            false,
            &[],
            "",
            ShellPaths::default(),
        )
    }

    #[test]
    fn a_host_with_no_executing_shell_registers_no_shell_tool() {
        let tools = shell_tools(&apk_sandbox());
        assert!(
            tools.is_empty(),
            "registering `ash` on a device where no shell ran offers a tool that cannot work"
        );
    }

    #[test]
    fn the_system_shell_device_gets_exactly_one_tool_bound_to_the_platform_shell() {
        let tools = shell_tools(&system_shell());
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].name, "ash");
        assert_eq!(tools[0].path, PathBuf::from("/system/bin/sh"));
        assert_eq!(tools[0].dialect, Some(ShellDialect::MkSh));
    }

    #[test]
    fn bash_is_registered_only_where_it_was_resolved_and_carries_its_own_path() {
        let tools = shell_tools(&termux());
        assert_eq!(tools.len(), 2, "§4.5 registers both dialects");
        let bash = &tools[0];
        assert_eq!(bash.name, "bash");
        assert_eq!(
            bash.path,
            PathBuf::from("/data/data/com.termux/files/usr/bin/bash")
        );
        assert!(
            bash.path.is_absolute(),
            "the backend clears the environment, so a relative or bare name cannot resolve"
        );
    }

    #[test]
    fn a_resolved_bash_is_never_attributed_to_the_platform_shell() {
        // `dialects` contains Bash on Termux because `command -v bash` resolved it; that says
        // nothing about /system/bin/sh, which item 5b asked to name itself.
        let tools = shell_tools(&termux());
        let ash = tools.iter().find(|t| t.name == "ash").unwrap();
        assert_eq!(ash.dialect, Some(ShellDialect::MkSh));
        assert!(ash.description.contains("not bash"));
        assert!(!tools[0].description.contains("not bash"));
    }

    #[test]
    fn the_description_lists_the_read_commands_this_device_has() {
        let text = shell_tools(&system_shell())[0].description.clone();
        for name in READ_TIER_COMMANDS {
            assert!(text.contains(name), "{name} missing from {text}");
        }
        assert!(text.contains("Read commands present"));
    }

    #[test]
    fn a_read_command_the_device_lacks_is_reported_as_absent_not_omitted() {
        let p = profile(
            HostProfileName::SystemShell,
            Privilege::ShellUid,
            true,
            &[ShellDialect::MkSh],
            "getprop ps mount",
            ShellPaths::default(),
        );
        let text = shell_tools(&p)[0].description.clone();
        assert!(text.contains("Not on this device"));
        assert!(text.contains("logcat") && text.contains("dumpsys"));
        assert!(
            !text.contains("Read commands present: getprop, dumpsys"),
            "logcat is absent here and must not be listed as present"
        );
    }

    #[test]
    fn an_unlistable_command_set_is_said_to_be_unknown() {
        // Probe item 6 found neither listing. The honest answer is "unknown", not an empty
        // list the model reads as "this device has no commands".
        let mut p = system_shell();
        p.applets = AppletSet::parse_list("");
        let text = shell_tools(&p)[0].description.clone();
        assert!(text.contains("command set is unknown"));
        assert!(!text.contains("Read commands present"));
    }

    #[test]
    fn write_capable_commands_are_named_with_the_approval_they_need() {
        let text = shell_tools(&system_shell())[0].description.clone();
        assert!(text.contains("settings"));
        assert!(text.contains("android:shell:write"));
        assert!(
            text.find("Read commands present") < text.find("not unattended"),
            "the read surface should be stated before the approval boundary"
        );
    }

    #[test]
    fn writable_locations_are_the_ones_a_write_probe_confirmed() {
        let text = shell_tools(&system_shell())[0].description.clone();
        assert!(text.contains("/data/local/tmp"));
        assert!(
            !text.contains("/system,"),
            "/system was not writable and must not appear in the list: {text}"
        );
    }

    #[test]
    fn evidence_is_stated_per_source_with_the_access_that_was_measured() {
        let mut p = system_shell();
        use crate::host::facts::{EvidenceAccess, EvidencePath};
        p.evidence
            .sources
            .insert(EvidencePath::Anr, EvidenceAccess::Listable);
        p.evidence
            .sources
            .insert(EvidencePath::Tombstones, EvidenceAccess::Absent);
        p.evidence
            .sources
            .insert(EvidencePath::Dropbox, EvidenceAccess::Readable);
        p.evidence.dumpsys_services = Some(246);
        let text = shell_tools(&p)[0].description.clone();
        assert!(text.contains("/data/anr names only"), "{text}");
        assert!(text.contains("/data/tombstones not reachable"), "{text}");
        assert!(text.contains("/data/system/dropbox readable"), "{text}");
        assert!(text.contains("246 running services"), "{text}");
    }

    #[test]
    fn a_listable_evidence_source_is_never_described_as_available() {
        // The failure this guards against is the specific one the BLA-AL00 measured: names
        // without contents. A description that called that "available" would send an agent
        // off to read traces it cannot open, and a description that called it "not
        // reachable" would hide the one fact it could have used.
        let mut p = system_shell();
        p.evidence.sources.insert(
            crate::host::facts::EvidencePath::Anr,
            crate::host::facts::EvidenceAccess::Listable,
        );
        let text = shell_tools(&p)[0].description.clone();
        assert!(text.contains("names only"), "{text}");
        for claim in ["available", "readable"] {
            let anr_line = text
                .lines()
                .find(|l| l.contains("/data/anr"))
                .unwrap_or_default();
            assert!(
                !anr_line.contains(claim),
                "{claim} claimed for a locked source"
            );
        }
    }

    #[test]
    fn an_unprobed_evidence_source_says_so_instead_of_disappearing() {
        // Only one of three sources was answered. The other two must still be named, because
        // a list that silently shortens reads as "this device has no dropbox".
        let mut p = system_shell();
        p.evidence.sources.insert(
            crate::host::facts::EvidencePath::Anr,
            crate::host::facts::EvidenceAccess::Empty,
        );
        let text = shell_tools(&p)[0].description.clone();
        assert!(text.contains("/data/anr empty"), "{text}");
        assert!(text.contains("/data/tombstones not probed"), "{text}");
        assert!(text.contains("/data/system/dropbox not probed"), "{text}");
    }

    #[test]
    fn an_unanswered_dumpsys_inventory_is_not_reported_as_zero_services() {
        // `Some(0)` is not a fact any Android device produces; `None` is "we did not get an
        // answer". Printing "0 services" would be the same fabrication in the other
        // direction.
        let mut p = system_shell();
        p.evidence.sources.insert(
            crate::host::facts::EvidencePath::Anr,
            crate::host::facts::EvidenceAccess::Empty,
        );
        p.evidence.dumpsys_services = None;
        let text = shell_tools(&p)[0].description.clone();
        assert!(
            text.contains("service inventory was not answered"),
            "{text}"
        );
        assert!(!text.contains("0 running services"), "{text}");
    }

    #[test]
    fn a_device_with_no_evidence_probe_says_availability_is_unknown() {
        let text = shell_tools(&system_shell())[0].description.clone();
        assert!(text.contains("no evidence source was probed"), "{text}");
        assert!(!text.contains("/data/anr"), "{text}");
    }

    #[test]
    fn bugreportz_is_reported_in_the_state_the_probe_left_it_in() {
        // Three states, not two: installed, absent, never asked. Folding the third into the
        // second is how a description tells an agent to stop looking for something this device
        // may well have — and `bugreportz` is exactly the command where that mistake is
        // available, because no applet listing reports it either way.
        let mut p = system_shell();
        let text = shell_tools(&p)[0].description.clone();
        assert!(text.contains("was not asked about"), "{text}");
        assert!(
            !text.contains("not installed"),
            "an unanswered spot check must not be described as an absent command"
        );

        p.applets.record_spot_check("bugreportz");
        let text = shell_tools(&p)[0].description.clone();
        assert!(text.contains("not installed on this device"), "{text}");

        p.applets.insert_confirmed("bugreportz");
        let text = shell_tools(&p)[0].description.clone();
        assert!(text.contains("`bugreportz` is installed"), "{text}");

        // What the description says about the tier is what the gate will say, read from the
        // same call rather than restated: the two have different owners, and only one of them
        // is allowed to be wrong.
        let gate = commands::check(
            "bugreportz -p",
            Some(crate::host::capability::Capability::ShellWrite),
        );
        match gate {
            Ok(v) => match v.strongest().capability() {
                Some(cap) => assert!(
                    text.contains(&cap.to_string()) || text.contains("approval"),
                    "{text}"
                ),
                None => assert!(
                    text.contains("asking for approval will not unblock it"),
                    "{text}"
                ),
            },
            Err(r) => assert!(text.contains(&r.to_string()), "{text}"),
        }
    }

    #[test]
    fn the_boundary_names_uid_and_selinux_mode_and_nothing_else_about_identity() {
        let text = shell_tools(&system_shell())[0].description.clone();
        assert!(text.contains("uid 2000 (shell)"));
        assert!(text.contains("SELinux is enforcing"));
        // R13 / ADR-AND-001 §7.1: the raw context never leaves the device. A tool description
        // is handed to a model over the wire, so it must not carry it either.
        assert!(
            !text.contains("u:r:"),
            "the SELinux context string must not reach a generated description: {text}"
        );
    }

    #[test]
    fn an_unrecognised_banner_still_gets_a_tool_and_says_it_does_not_know() {
        // busybox ash sets neither KSH_VERSION nor BASH_VERSION: the shell ran (item 5b exits
        // 0) but named nothing. Losing the tool would repeat the misclassification this port
        // already made once on a real device.
        let mut p = system_shell();
        p.dialects = Default::default();
        p.shell = None;
        let tools = shell_tools(&p);
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].dialect, None);
        assert!(
            tools[0]
                .description
                .contains("could not identify the dialect")
        );
    }

    #[test]
    fn descriptions_are_deterministic() {
        let a = shell_tools(&termux());
        let b = shell_tools(&termux());
        assert_eq!(
            a, b,
            "the same profile must not produce different tool text"
        );
    }
}
