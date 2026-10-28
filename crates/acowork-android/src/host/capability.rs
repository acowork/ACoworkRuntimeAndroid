//! Capability model and its derivation from probed facts.
//!
//! # Why this type is local and not upstream `Permission`
//!
//! ADR-AND-001 §4.4 introduces five `android:*` capabilities and says it follows
//! the upstream `filesystem:read:<path>` granularity style. Upstream, however,
//! models permissions as a **closed enum** (`acowork-core/src/permission.rs`)
//! with a proto tag mapping, `from_str`, `implies`, `category`, `type_name`,
//! `type_value` and a WASI mapper — seven match sites. Adding a variant there is
//! an upstream core + proto change, not something this repository can do locally.
//!
//! Upstream design doc 30 §6.2 goes further and rules that "新增能力的唯一路径是
//! 注册表 PR", that engines may not mint capability IDs, and that "能力是布尔
//! 开关，不带参数". Two of the five capabilities below are inherently
//! parameterised (`android:fs:outside-app` is a path scope, `android:shell:read`
//! carries a command whitelist), so they collide with that ruling.
//!
//! This is recorded as blocker **B2** in
//! `docs/review/zh/readiness-assessment.md`. Until it is ruled on, this module
//! deliberately defines its **own** capability type and does **not** depend on
//! `acowork_core::Permission`. The mapping layer to whatever the registry ends
//! up being is a separate, later, thin adapter — so a ruling against the current
//! IDs costs one file, not a rewrite of the probe.
//!
//! # Derivation is a function of facts, never of configuration
//!
//! android-host-probe.md §3: "capability 是探测事实的函数，不是配置项". Every
//! rule below reads only from [`super::facts`] and [`super::profile`] values.
//! There is no config file, no environment override and no way to declare a
//! capability the device did not demonstrate.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::host::facts::{Privilege, SelinuxState, VerityState};
use crate::host::profile::HostProfile;

/// The five Android capabilities from ADR-AND-001 §4.4.
///
/// The string IDs are the ones the ADR specifies. They are **provisional**
/// pending the B2 ruling — see the module docs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Capability {
    /// Read-only system inspection: `getprop`, `dumpsys`, `logcat`, `ps`, `df`,
    /// `mount`, `getenforce`. Whitelist auto-approved per ADR-AND-001 §4.4.
    ShellRead,
    /// Mutating shell: `setprop`, `am start`, `pm install`, `settings put`,
    /// `input`. **Requires approval.**
    ShellWrite,
    /// Writing under `/data` outside this package's own directory.
    /// Requires approval plus an automatic backup.
    FsOutsideApp,
    /// Remounting and writing the system partition. Requires a
    /// `dangerous-mode` session switch **and** per-command approval, and per
    /// ADR-AND-001 §7.4 also the node-owner gate.
    FsSystem,
    /// `setenforce 0`. Approved per command, auto-restored at session end
    /// (ADR-AND-001 §8).
    SelinuxPermissive,
}

impl Capability {
    /// The wire/audit identifier.
    ///
    /// Provisional — see the module-level note on blocker B2.
    pub fn as_str(&self) -> &'static str {
        match self {
            Capability::ShellRead => "android:shell:read",
            Capability::ShellWrite => "android:shell:write",
            Capability::FsOutsideApp => "android:fs:outside-app",
            Capability::FsSystem => "android:fs:system",
            Capability::SelinuxPermissive => "android:selinux:permissive",
        }
    }

    /// True when exercising this capability mutates device-global state and
    /// therefore has to be serialised behind the DeviceWriteLock
    /// (ADR-AND-001 §4.6 item 5: "read 类不锁").
    pub fn is_mutating(&self) -> bool {
        !matches!(self, Capability::ShellRead)
    }

    /// True when the capability requires an explicit human approval per use,
    /// as opposed to whitelist auto-approval.
    pub fn requires_approval(&self) -> bool {
        match self {
            // ADR-AND-001 §4.4: read-tier is whitelist auto-approved.
            Capability::ShellRead => false,
            Capability::ShellWrite
            | Capability::FsOutsideApp
            | Capability::FsSystem
            | Capability::SelinuxPermissive => true,
        }
    }

    /// True when the capability additionally requires the `dangerous-mode`
    /// session switch (ADR-AND-001 §4.4 / §7.3).
    pub fn requires_dangerous_mode(&self) -> bool {
        matches!(self, Capability::FsSystem | Capability::SelinuxPermissive)
    }

    /// All five, in declaration order. Useful for tests and for building the
    /// capability summary reported to the Gateway (ADR-AND-001 §7.1).
    pub fn all() -> [Capability; 5] {
        [
            Capability::ShellRead,
            Capability::ShellWrite,
            Capability::FsOutsideApp,
            Capability::FsSystem,
            Capability::SelinuxPermissive,
        ]
    }
}

impl std::fmt::Display for Capability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Parse a capability ID back into a [`Capability`].
///
/// The inverse of [`Capability::as_str`]. Unknown IDs are rejected rather than
/// mapped to a default: silently accepting an unrecognised capability is how a
/// vocabulary change turns into a privilege escalation.
pub fn parse_capability(id: &str) -> Option<Capability> {
    Capability::all().into_iter().find(|c| c.as_str() == id)
}

// Serialization goes through the contract ID, not the Rust variant name. Both
// the snapshot baselines (android-host-probe.md §7) and the Gateway capability
// summary (ADR-AND-001 §7.1) are expressed in IDs, so a variant rename must not
// be able to change the wire form.
impl Serialize for Capability {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Capability {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Capability, D::Error> {
        let raw = String::deserialize(deserializer)?;
        parse_capability(&raw).ok_or_else(|| {
            serde::de::Error::custom(format!(
                "unknown capability id `{raw}`; the vocabulary is closed"
            ))
        })
    }
}

/// An ordered, de-duplicated capability set.
///
/// `BTreeSet` rather than `HashSet` so that serialization is deterministic —
/// android-host-probe.md §7 makes the serialized `HostProfile` a regression
/// baseline, and a randomly ordered set would produce spurious snapshot diffs.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilitySet(BTreeSet<Capability>);

impl CapabilitySet {
    /// An empty set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether this capability was derived from the probed facts.
    pub fn contains(&self, cap: Capability) -> bool {
        self.0.contains(&cap)
    }

    /// Add a capability. Used by tests and by the derivation itself.
    pub fn insert(&mut self, cap: Capability) {
        self.0.insert(cap);
    }

    /// Number of declared capabilities.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether nothing at all was derived.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Iterate in stable (declaration) order.
    pub fn iter(&self) -> impl Iterator<Item = Capability> + '_ {
        self.0.iter().copied()
    }

    /// The IDs, for the Gateway capability summary (ADR-AND-001 §7.1).
    pub fn ids(&self) -> Vec<&'static str> {
        self.0.iter().map(Capability::as_str).collect()
    }
}

impl FromIterator<Capability> for CapabilitySet {
    fn from_iter<I: IntoIterator<Item = Capability>>(iter: I) -> Self {
        CapabilitySet(iter.into_iter().collect())
    }
}

/// Derive the capability set from probed facts.
///
/// Implements the five rules in android-host-probe.md §3 verbatim:
///
/// ```text
/// android:shell:read         ← shell != None
/// android:shell:write        ← caps 含 read 且 privilege >= Root（或 su 探测成功）
/// android:fs:outside-app     ← fs_roots 存在 writable 且不属于自身包目录
/// android:fs:system          ← verity != Enforcing 且 /system 实测可 remount
/// android:selinux:permissive ← privilege >= Root 且 selinux == Enforcing
/// ```
///
/// Both of the last two rules additionally require a shell, because `mount` and
/// `setenforce` are commands: a host that cannot spawn a process cannot exercise
/// them whatever the other facts say. See the `FsSystem` arm below and blocker
/// B12 in the readiness assessment.
///
/// Two deliberate readings, both documented because they are judgement calls
/// rather than transcriptions:
///
/// 1. **`shell:write` needs demonstrated escalation, not just a root uid.** The
///    rule says `privilege >= Root` *or* a successful `su` probe. On the Termux
///    profile the Runtime itself is `AppUid` and only the helper escalates, so
///    the `su`-probe arm is the one that fires. Requiring `su_ok` in that arm is
///    what keeps "no root-shell profile" from silently granting write.
/// 2. **`selinux:permissive` is only meaningful while enforcing.** If the device
///    is already permissive there is nothing to toggle, so the capability is not
///    declared. `SelinuxState::Unknown` also yields nothing: you cannot justify
///    `setenforce` on a device whose mode you could not read.
pub fn derive_capabilities(profile: &HostProfile) -> CapabilitySet {
    let mut caps = CapabilitySet::new();

    // android:shell:read ← shell != None
    let has_shell = profile.shell.is_some();
    if has_shell {
        caps.insert(Capability::ShellRead);
    }

    // android:shell:write ← read ∧ (privilege >= Root ∨ su probe succeeded)
    let can_escalate = profile.privilege >= Privilege::Root || profile.su.got_root();
    if has_shell && can_escalate {
        caps.insert(Capability::ShellWrite);
    }

    // android:fs:outside-app ← some writable root that is not our own package dir
    if profile
        .fs_roots
        .iter()
        .any(|root| root.writable && !root.own_package)
    {
        caps.insert(Capability::FsOutsideApp);
    }

    // android:fs:system ← shell ∧ verity not enforcing ∧ /system remountable.
    //
    // The `shell` conjunct is not in android-host-probe.md §3's rule as written,
    // and adding it is deliberate: remounting means *running* `mount`, so a host
    // with no shell cannot do it however permissive its verity state is. This is
    // what ADR-AND-001 §7.3 states as fact ("APK 档根本没有 shell，也没有 su，
    // android:fs:system 在 APK 上不可达"). Without the conjunct an APK profile can
    // declare a capability it has no way to exercise, which is precisely the
    // "capability lie" upstream design doc 30 §11.1 warns is worse than no
    // capability at all. Recorded as B12 in the readiness assessment.
    if has_shell && !profile.device.verity.blocks_system_write() && profile.system_remountable {
        caps.insert(Capability::FsSystem);
    }

    // android:selinux:permissive ← shell ∧ privilege >= Root ∧ selinux == Enforcing
    if has_shell && can_escalate && profile.selinux == SelinuxState::Enforcing {
        caps.insert(Capability::SelinuxPermissive);
    }

    caps
}

/// Why a capability was *not* derived.
///
/// Diagnostics are a non-goal-turned-requirement in ADR-AND-001 N3 ("诊断信息随
/// 错误一并返回"). When the model or the user asks "why can't I setprop", the
/// answer has to name the missing fact, not just say "denied".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityGap {
    /// The capability that could not be derived.
    pub capability: Capability,
    /// Which probed fact is missing, in words a model can act on.
    pub reason: String,
}

/// Explain every capability the facts did not yield.
///
/// Pure function over the same inputs as [`derive_capabilities`], so the two can
/// never disagree: the explanation is computed from the facts, not from a
/// second copy of the rules.
pub fn explain_gaps(profile: &HostProfile) -> Vec<CapabilityGap> {
    let derived = derive_capabilities(profile);
    let mut gaps = Vec::new();

    for cap in Capability::all() {
        if derived.contains(cap) {
            continue;
        }
        let reason = match cap {
            Capability::ShellRead => "no usable shell was detected on this host".to_string(),
            Capability::ShellWrite => {
                if profile.shell.is_none() {
                    "no usable shell was detected".to_string()
                } else {
                    format!(
                        "privilege is {:?} and the su probe did not return uid 0",
                        profile.privilege
                    )
                }
            }
            Capability::FsOutsideApp => {
                "no writable filesystem root outside this package's own directory".to_string()
            }
            Capability::FsSystem if profile.shell.is_none() => {
                "this host has no shell, so it cannot run `mount` at all".to_string()
            }
            Capability::FsSystem => match profile.device.verity {
                VerityState::Enforcing => {
                    "dm-verity is enforcing; writing /system needs disable-verity plus a reboot"
                        .to_string()
                }
                VerityState::Unknown => {
                    "dm-verity state could not be read, so it is treated as enforcing".to_string()
                }
                VerityState::NotEnforcing if !profile.system_remountable => {
                    "/system did not survive the remount probe".to_string()
                }
                VerityState::NotEnforcing => unreachable!("cap would have been derived"),
            },
            Capability::SelinuxPermissive => {
                if profile.selinux != SelinuxState::Enforcing {
                    format!(
                        "SELinux mode is {:?}, not Enforcing — nothing to toggle",
                        profile.selinux
                    )
                } else {
                    "privilege is below Root and the su probe did not return uid 0".to_string()
                }
            }
        };
        gaps.push(CapabilityGap {
            capability: cap,
            reason,
        });
    }

    gaps
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::facts::{
        AppletSet, BuildType, DeviceFacts, FsRoot, SelinuxDomain, ShellDialect, SuProbe,
        VerityState,
    };
    use crate::host::profile::{HostProfile, HostProfileName};

    /// A rooted debugging device: `su` works, SELinux enforcing, verity off,
    /// `/system` remountable, and a writable root outside our own package.
    /// Every capability should be derivable from this shape.
    fn root_profile() -> HostProfile {
        let mut profile = HostProfile {
            name: HostProfileName::RootShell,
            privilege: Privilege::AppUid,
            selinux: SelinuxState::Enforcing,
            context: Some("u:r:untrusted_app:s0".to_string()),
            domain: SelinuxDomain::UntrustedApp,
            shell: Some(ShellDialect::MkSh),
            dialects: [ShellDialect::MkSh].into_iter().collect(),
            applets: AppletSet::parse_list("cat\nlogcat\nsetprop\n"),
            fs_roots: vec![
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
            ],
            su: SuProbe {
                uid: Some(0),
                context: Some("u:r:magisk:s0".to_string()),
                prompt_denied: false,
                unavailable: false,
            },
            system_remountable: true,
            caps: CapabilitySet::new(),
            device: DeviceFacts {
                build_type: BuildType::UserDebug,
                debuggable: true,
                secure: false,
                adb_secure: false,
                api_level: Some(34),
                abi: Some("arm64-v8a".to_string()),
                verity: VerityState::NotEnforcing,
            },
        };
        profile.caps = derive_capabilities(&profile);
        profile
    }

    /// Re-derive caps after mutating a fact, so a test can never observe a
    /// stale capability set.
    fn with(mut profile: HostProfile, f: impl FnOnce(&mut HostProfile)) -> HostProfile {
        f(&mut profile);
        profile.caps = derive_capabilities(&profile);
        profile
    }

    #[test]
    fn capability_ids_match_the_adr() {
        assert_eq!(Capability::ShellRead.as_str(), "android:shell:read");
        assert_eq!(Capability::ShellWrite.as_str(), "android:shell:write");
        assert_eq!(Capability::FsOutsideApp.as_str(), "android:fs:outside-app");
        assert_eq!(Capability::FsSystem.as_str(), "android:fs:system");
        assert_eq!(
            Capability::SelinuxPermissive.as_str(),
            "android:selinux:permissive"
        );
    }

    #[test]
    fn read_tier_is_the_only_non_mutating_capability() {
        assert!(!Capability::ShellRead.is_mutating());
        for cap in Capability::all() {
            if cap != Capability::ShellRead {
                assert!(
                    cap.is_mutating(),
                    "{cap} must serialise behind the write lock"
                );
            }
        }
    }

    #[test]
    fn approval_and_dangerous_mode_tiers() {
        assert!(!Capability::ShellRead.requires_approval());
        assert!(Capability::ShellWrite.requires_approval());
        assert!(!Capability::ShellWrite.requires_dangerous_mode());
        assert!(Capability::FsSystem.requires_dangerous_mode());
        assert!(Capability::SelinuxPermissive.requires_dangerous_mode());
        assert!(!Capability::FsOutsideApp.requires_dangerous_mode());
    }

    #[test]
    fn fully_capable_root_device_derives_all_five() {
        let profile = root_profile();
        assert_eq!(profile.caps.len(), 5);
        for cap in Capability::all() {
            assert!(profile.caps.contains(cap), "missing {cap}");
        }
    }

    #[test]
    fn no_shell_means_no_shell_capabilities() {
        let profile = with(root_profile(), |p| {
            p.shell = None;
            p.dialects.clear();
        });
        assert!(!profile.caps.contains(Capability::ShellRead));
        assert!(!profile.caps.contains(Capability::ShellWrite));
        // Filesystem capabilities are independent of the shell.
        assert!(profile.caps.contains(Capability::FsOutsideApp));
    }

    #[test]
    fn shell_without_escalation_gets_read_only() {
        let profile = with(root_profile(), |p| {
            p.su.unavailable = true;
            p.su.uid = None;
            p.privilege = Privilege::AppUid;
        });
        assert!(profile.caps.contains(Capability::ShellRead));
        assert!(
            !profile.caps.contains(Capability::ShellWrite),
            "Termux without su must not gain the write tier"
        );
        assert!(!profile.caps.contains(Capability::SelinuxPermissive));
    }

    #[test]
    fn shell_uid_privilege_alone_does_not_grant_write() {
        // `adb shell` is uid 2000, not root: the rule is `privilege >= Root`.
        let profile = with(root_profile(), |p| {
            p.privilege = Privilege::ShellUid;
            p.su.uid = None;
            p.su.unavailable = true;
        });
        assert!(!profile.caps.contains(Capability::ShellWrite));
    }

    #[test]
    fn root_privilege_without_su_still_grants_write() {
        // The `privilege >= Root` arm of the rule. ADR-AND-001 §4.1 forbids the
        // Runtime itself running as root, but the derivation must still be
        // correct if that shape ever appears (e.g. a probe run from adb).
        let profile = with(root_profile(), |p| {
            p.privilege = Privilege::Root;
            p.su.uid = None;
            p.su.unavailable = true;
        });
        assert!(profile.caps.contains(Capability::ShellWrite));
    }

    #[test]
    fn verity_enforcing_blocks_fs_system_even_when_remountable() {
        let profile = with(root_profile(), |p| {
            p.device.verity = VerityState::Enforcing;
            p.system_remountable = true;
        });
        assert!(!profile.caps.contains(Capability::FsSystem));
    }

    #[test]
    fn verity_unknown_blocks_fs_system() {
        let profile = with(root_profile(), |p| p.device.verity = VerityState::Unknown);
        assert!(!profile.caps.contains(Capability::FsSystem));
    }

    #[test]
    fn remount_probe_failure_blocks_fs_system() {
        let profile = with(root_profile(), |p| {
            p.device.verity = VerityState::NotEnforcing;
            p.system_remountable = false;
        });
        assert!(!profile.caps.contains(Capability::FsSystem));
    }

    #[test]
    fn only_own_package_writable_does_not_grant_outside_app() {
        let profile = with(root_profile(), |p| {
            p.fs_roots = vec![FsRoot {
                path: "/data/data/com.example.agent".to_string(),
                writable: true,
                own_package: true,
            }];
        });
        assert!(!profile.caps.contains(Capability::FsOutsideApp));
    }

    #[test]
    fn outside_root_must_be_writable_to_count() {
        let profile = with(root_profile(), |p| {
            p.fs_roots = vec![FsRoot {
                path: "/sdcard".to_string(),
                writable: false,
                own_package: false,
            }];
        });
        assert!(!profile.caps.contains(Capability::FsOutsideApp));
    }

    #[test]
    fn already_permissive_device_does_not_declare_the_toggle_capability() {
        let profile = with(root_profile(), |p| p.selinux = SelinuxState::Permissive);
        assert!(
            !profile.caps.contains(Capability::SelinuxPermissive),
            "nothing to toggle when already permissive"
        );
    }

    #[test]
    fn unknown_selinux_never_opens_the_permissive_toggle() {
        // android-host-probe.md §2 item 2: getenforce missing => the write-tier
        // capabilities are never opened.
        let profile = with(root_profile(), |p| p.selinux = SelinuxState::Unknown);
        assert!(!profile.caps.contains(Capability::SelinuxPermissive));
        // shell:write is gated on demonstrated escalation, not on knowing the
        // SELinux mode, so it survives; the dangerous toggle does not.
        assert!(profile.caps.contains(Capability::ShellWrite));
    }

    #[test]
    fn apk_sandbox_shape_derives_nothing_at_all() {
        let profile = with(root_profile(), |p| {
            p.name = HostProfileName::ApkSandbox;
            p.privilege = Privilege::AppUid;
            p.shell = None;
            p.dialects.clear();
            p.su = SuProbe {
                uid: None,
                context: None,
                prompt_denied: false,
                unavailable: true,
            };
            p.device.verity = VerityState::Unknown;
            p.system_remountable = false;
            p.fs_roots = vec![FsRoot {
                path: "/data/data/com.example.agent".to_string(),
                writable: true,
                own_package: true,
            }];
        });
        assert!(
            profile.caps.is_empty(),
            "an APK sandbox must declare no capability, got {:?}",
            profile.caps.ids()
        );
    }

    #[test]
    fn gaps_cover_exactly_the_underived_capabilities() {
        let profile = with(root_profile(), |p| {
            p.selinux = SelinuxState::Permissive;
            p.device.verity = VerityState::Enforcing;
        });
        let gaps = explain_gaps(&profile);

        assert_eq!(profile.caps.len() + gaps.len(), Capability::all().len());
        for gap in &gaps {
            assert!(!profile.caps.contains(gap.capability));
            assert!(!gap.reason.is_empty(), "every gap needs a stated reason");
        }
        assert!(
            gaps.iter()
                .any(|g| g.capability == Capability::FsSystem && g.reason.contains("dm-verity"))
        );
        assert!(
            gaps.iter()
                .any(|g| g.capability == Capability::SelinuxPermissive
                    && g.reason.contains("Permissive"))
        );
    }

    #[test]
    fn no_gaps_when_everything_is_derived() {
        assert!(explain_gaps(&root_profile()).is_empty());
    }

    #[test]
    fn capability_set_serializes_deterministically() {
        let caps = root_profile().caps;
        let a = serde_json::to_string(&caps).unwrap();
        let b = serde_json::to_string(&caps).unwrap();
        assert_eq!(a, b, "snapshot baselines require stable ordering");
        assert!(a.contains("android:shell:read"));
    }
}
