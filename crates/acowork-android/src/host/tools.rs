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

use crate::host::commands::{READ_TIER_COMMANDS, WRITE_TIER_COMMANDS};
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
/// Five lines, in this order: what the tool binds to; which dialect that is; which §4.4
/// commands exist; where writing is possible; and the trust boundary the model is inside.
/// Each is stated from a measured field, and each says "not measured" rather than inheriting
/// a default.
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
