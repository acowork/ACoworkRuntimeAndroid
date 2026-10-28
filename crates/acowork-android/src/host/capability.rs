//! The Android capability vocabulary, and its derivation from probed facts.
//!
//! # What lives here versus in the contract
//!
//! The **rules** — what the four axes mean, how they compose, who may declare what —
//! live in `acowork-platform-contract` and are not repeated here. This module holds
//! only the two things that are genuinely Android:
//!
//! 1. the **vocabulary**: which five capabilities this platform registers, and what
//!    each one's four axes are ([`Capability::spec`]);
//! 2. the **derivation**: how probed facts turn into claims with evidence
//!    ([`derive_claims`]), and how an absent capability is explained
//!    ([`explain_absence`]).
//!
//! A third platform writes its own version of this file and nothing else. That is the
//! point of the split: the gate never changes, so a new port cannot alter how
//! authorization works (contract rule R6).
//!
//! # Why a local enum on top of a contract type
//!
//! [`Capability`] is a handle, not a vocabulary. The authoritative ID is the contract's
//! [`HostCapability`], and [`Capability::id`] produces it. Keeping a local enum buys
//! exhaustive matching — the compiler rejects a `match` that forgets a capability,
//! which a string-keyed map cannot. It costs one `id()` call.
//!
//! # B2 — the IDs are provisional, and that is now cheap
//!
//! ADR-AND-001 §4.4 specifies these five `android:*` IDs. Upstream design doc 30 §6.2
//! rules that new capabilities enter only by registry PR, that engines may not mint
//! IDs, and that "能力是布尔开关，不带参数" — and two of the five are inherently
//! parameterised (`fs:outside-app` is a path scope, `shell:read` carries a command
//! whitelist). Doc 30 also uses dot-separated names where the ADR uses colons.
//!
//! Because the vocabulary is now data in one function ([`android_vocabulary`]) and the
//! rules are elsewhere, a ruling against these IDs costs this file alone. That is the
//! whole reason the contract layer exists; see the readiness assessment's B2.
//!
//! # B11 — `shell:write` and the attribution tier
//!
//! ADR-087 D4 puts "安装/卸载" under `manage = owner ∨ admin`, and `android:shell:write`
//! covers `pm install`. ADR-AND-001 §7.4 gates only the two system-tier capabilities on
//! ownership. The two documents disagree, so this module declares
//! [`AttributionTier::None`] for `shell:write` — the ADR's reading — and says so in the
//! spec table where a test can see it. Changing the answer is one line here and no line
//! anywhere else.

use acowork_platform_contract::{
    ApprovalRequirement, AttributionTier, CapabilitySpec, Effect, HostCapability, Reversibility,
};

use crate::host::facts::{Privilege, SelinuxState, VerityState};
use crate::host::profile::HostProfile;

/// The platform namespace this port registers under.
pub const PLATFORM: &str = "android";

/// The five Android capabilities from ADR-AND-001 §4.4.
///
/// A handle for exhaustive matching; the wire identity is [`Capability::id`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Capability {
    /// Read-only system inspection: `getprop`, `dumpsys`, `logcat`, `ps`, `df`,
    /// `mount`, `getenforce`. Whitelist auto-approved per ADR-AND-001 §4.4.
    ShellRead,
    /// Mutating shell: `setprop`, `am start`, `pm install`, `settings put`, `input`.
    /// Requires per-use approval.
    ShellWrite,
    /// Writing under `/data` outside this package's own directory. Requires approval.
    FsOutsideApp,
    /// Remounting and writing the system partition. Requires a `dangerous-mode`
    /// session switch, per-command approval, and — per ADR-AND-001 §7.4 — the
    /// node-owner gate.
    FsSystem,
    /// `setenforce 0`. Approved per command, auto-restored at session end
    /// (ADR-AND-001 §8).
    SelinuxPermissive,
}

impl Capability {
    /// All five, in declaration order.
    pub fn all() -> [Capability; 5] {
        [
            Capability::ShellRead,
            Capability::ShellWrite,
            Capability::FsOutsideApp,
            Capability::FsSystem,
            Capability::SelinuxPermissive,
        ]
    }

    /// The contract-level identifier.
    ///
    /// Infallible: the five IDs are literals this module controls, and each is
    /// asserted well-formed by [`tests::every_vocabulary_id_parses`].
    pub fn id(&self) -> HostCapability {
        let name = match self {
            Capability::ShellRead => "shell:read",
            Capability::ShellWrite => "shell:write",
            Capability::FsOutsideApp => "fs:outside-app",
            Capability::FsSystem => "fs:system",
            Capability::SelinuxPermissive => "selinux:permissive",
        };
        HostCapability::new(PLATFORM, name).expect("android vocabulary ids are well-formed")
    }

    /// This capability's four axes (contract rule R6).
    ///
    /// This is the only place Android states what its capabilities *mean* to the
    /// gate. The gate reads these values and nothing else.
    pub fn spec(&self) -> CapabilitySpec {
        let id = self.id();
        match self {
            // Observation tier: no lock, no approval, no attribution, nothing to undo.
            Capability::ShellRead => CapabilitySpec::read_only(id),

            // B11: `AttributionTier::None` follows ADR-AND-001 §7.4, which gates only
            // the two system-tier capabilities on ownership. ADR-087 D4 would put
            // `pm install` under `manage`. Provisional, and provisional visibly.
            Capability::ShellWrite => CapabilitySpec {
                id,
                effect: Effect::Mutating,
                approval: ApprovalRequirement::PerUse,
                attribution: AttributionTier::None,
                reversibility: Reversibility::Reversible,
            },

            Capability::FsOutsideApp => CapabilitySpec {
                id,
                effect: Effect::Mutating,
                approval: ApprovalRequirement::PerUse,
                attribution: AttributionTier::None,
                reversibility: Reversibility::Reversible,
            },

            // Irreversible: there is no snapshot of `/system` to restore from, so the
            // agent cannot undo its own write. Contract rule R8 therefore requires a
            // stated rollback path — in practice "reflash the stock image", which is
            // exactly the cost the model should have to acknowledge.
            Capability::FsSystem => CapabilitySpec {
                id,
                effect: Effect::Mutating,
                approval: ApprovalRequirement::DangerousSession,
                attribution: AttributionTier::Manage,
                reversibility: Reversibility::Irreversible,
            },

            // Reversible, and deliberately so: ADR-AND-001 §8 auto-restores enforcing
            // at session end, so `setenforce 0` has a real undo. Marking it
            // irreversible would demand a rollback plan for something the runtime
            // already rolls back.
            Capability::SelinuxPermissive => CapabilitySpec {
                id,
                effect: Effect::Mutating,
                approval: ApprovalRequirement::DangerousSession,
                attribution: AttributionTier::Manage,
                reversibility: Reversibility::Reversible,
            },
        }
    }
}

impl std::fmt::Display for Capability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Delegate to the contract type so there is exactly one spelling of each ID.
        write!(f, "{}", self.id())
    }
}

/// The Android vocabulary, as contract specs.
///
/// Hand this to [`acowork_platform_contract::CapabilityTable::new`] to build the table
/// a [`acowork_platform_contract::HostDescription`] returns.
pub fn android_vocabulary() -> Vec<CapabilitySpec> {
    Capability::all().iter().map(Capability::spec).collect()
}

/// Look a capability up by its contract ID.
///
/// Returns `None` for anything outside the five, which is how contract rule R5 stays
/// closed: an unrecognised ID has no spec, so the gate has no axes to evaluate and
/// refuses.
pub fn lookup(id: &HostCapability) -> Option<Capability> {
    Capability::all().into_iter().find(|c| &c.id() == id)
}

/// Derive capability claims from probed facts.
///
/// Implements the five rules in android-host-probe.md §3, and — unlike a bare set of
/// booleans — attaches the **evidence** each claim rests on, which is what contract
/// rule R4 requires and what makes a claim auditable after the fact.
///
/// Only positive claims are returned. An absent capability is not a claim with weak
/// evidence; it is explained by [`explain_absence`], and the two functions read the
/// same fields so they cannot disagree.
pub fn derive_claims(profile: &HostProfile) -> Vec<acowork_platform_contract::CapabilityClaim> {
    use acowork_platform_contract::{CapabilityClaim, Evidence, EvidenceKind};

    let mut claims = Vec::new();
    let mut claim = |cap: Capability, kind: EvidenceKind| {
        claims.push(CapabilityClaim {
            capability: cap.id(),
            evidence: Evidence::now(kind),
        });
    };

    // android:shell:read ← a shell actually executed.
    //
    // The dialect belongs in the evidence text, not in the condition. A shell we cannot name
    // is still a shell: refusing a read-tier command on a device that has just run `id -u`
    // for us would be the port contradicting the device.
    let has_shell = profile.shell_executed;
    if has_shell {
        let what = match profile.shell {
            Some(dialect) => format!("/system/bin/sh -c ran as {dialect:?}"),
            None => "/system/bin/sh -c ran, dialect not recognised".to_string(),
        };
        claim(
            Capability::ShellRead,
            EvidenceKind::Observed {
                what,
                status: Some(0),
            },
        );
    }

    // android:shell:write ← read ∧ (privilege >= Root ∨ su probe returned uid 0)
    let can_escalate = profile.privilege >= Privilege::Root || profile.su.got_root();
    if has_shell && can_escalate {
        // Prefer the stronger evidence: an observed `su -c id` beats an inference from
        // the process's own uid, because it demonstrates the escalation path rather
        // than assuming one.
        let kind = if profile.su.got_root() {
            EvidenceKind::Observed {
                what: "su -c id".to_string(),
                status: Some(0),
            }
        } else {
            EvidenceKind::Inferred {
                fact: format!("id -u = {}", profile.privilege.uid()),
            }
        };
        claim(Capability::ShellWrite, kind);
    } else if has_shell && profile.su.prompt_denied {
        // The user rejected the Magisk prompt. Record it as a denial rather than
        // silently omitting the claim: android-host-probe.md §2 item 4 rules this
        // **not retryable**, and an audit trail is what stops a later session
        // re-prompting for a decision already made.
        claim(
            Capability::ShellWrite,
            EvidenceKind::Denied {
                reason: "su:prompt-denied".to_string(),
            },
        );
    }

    // android:fs:outside-app ← some writable root that is not our own package dir
    if let Some(root) = profile
        .fs_roots
        .iter()
        .find(|root| root.writable && !root.own_package)
    {
        claim(
            Capability::FsOutsideApp,
            EvidenceKind::Observed {
                what: format!("test -w {}", root.path),
                status: Some(0),
            },
        );
    }

    // android:fs:system ← shell ∧ verity not enforcing ∧ /system remountable.
    //
    // The `shell` conjunct is not in android-host-probe.md §3 as written, and adding
    // it is deliberate: remounting means *running* `mount`, so a host with no shell
    // cannot do it however permissive its verity state is. This is what ADR-AND-001
    // §7.3 states as fact ("APK 档根本没有 shell，也没有 su，android:fs:system 在
    // APK 上不可达"). Without the conjunct an APK profile declares a capability it
    // has no way to exercise — the "capability lie" upstream design doc 30 §11.1
    // warns is worse than no capability at all. Recorded as B12.
    if has_shell && !profile.device.verity.blocks_system_write() && profile.system_remountable {
        claim(
            Capability::FsSystem,
            EvidenceKind::Observed {
                what: "mount -o remount,rw /system".to_string(),
                status: Some(0),
            },
        );
    }

    // android:selinux:permissive ← shell ∧ can escalate ∧ selinux == Enforcing
    if has_shell && can_escalate && profile.selinux == SelinuxState::Enforcing {
        claim(
            Capability::SelinuxPermissive,
            EvidenceKind::Inferred {
                fact: "selinux=enforcing ∧ escalation demonstrated".to_string(),
            },
        );
    }

    claims
}

/// Why a capability was not derived, in terms the model can act on.
///
/// ADR-AND-001 N3 requires diagnostics to travel with the error. When the model asks
/// "why can't I setprop", the answer must name the missing fact and the next step —
/// "denied" costs a round trip and teaches nothing (contract rule R9).
///
/// Pure over the same fields [`derive_claims`] reads, so the two cannot disagree.
pub fn explain_absence(profile: &HostProfile, cap: Capability) -> String {
    match cap {
        Capability::ShellRead => {
            "no shell executed the probe, so this host cannot run a command at all".to_string()
        }

        Capability::ShellWrite => {
            if !profile.shell_executed {
                "no shell executed the probe, so no command can run".to_string()
            } else if profile.su.prompt_denied {
                // Not retryable: the user already answered this prompt.
                "the superuser prompt was declined, so this is not retryable — ask the user to \
                 grant superuser access in the Magisk/KernelSU manager"
                    .to_string()
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

        Capability::FsSystem if !profile.shell_executed => {
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
            VerityState::NotEnforcing => {
                // Unreachable when called through the gate, which only asks about
                // undeclared capabilities. Kept honest rather than `unreachable!()`
                // so a caller that asks directly gets an answer, not a panic.
                "all conditions for /system access appear to hold; re-probe to confirm".to_string()
            }
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::facts::{
        AppletSet, BuildType, DeviceFacts, FsRoot, SelinuxDomain, ShellDialect, SuProbe,
        VerityState,
    };
    use crate::host::profile::{HostProfileName, ShellPaths};
    use acowork_platform_contract::{CapabilityTable, EvidenceKind};

    /// An empty table over the Android vocabulary, for fixtures that fill `caps` in
    /// later or do not exercise it at all.
    fn empty_table_for_test() -> CapabilityTable {
        CapabilityTable::new(PLATFORM, android_vocabulary()).unwrap()
    }

    /// A rooted debugging device: `su` works, SELinux enforcing, verity off,
    /// `/system` remountable, and a writable root outside our own package.
    fn root_profile() -> HostProfile {
        HostProfile {
            name: HostProfileName::RootShell,
            privilege: Privilege::AppUid,
            selinux: SelinuxState::Enforcing,
            context: Some("u:r:untrusted_app:s0".to_string()),
            domain: SelinuxDomain::UntrustedApp,
            shell: Some(ShellDialect::MkSh),
            shell_executed: true,
            dialects: [ShellDialect::MkSh].into_iter().collect(),
            applets: AppletSet::parse_list("cat\nsetprop\nmount\n"),
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
            evidence: crate::host::facts::EvidenceSurface::default(),
            su: SuProbe {
                uid: Some(0),
                context: Some("u:r:magisk:s0".to_string()),
                prompt_denied: false,
                unavailable: false,
            },
            system_remountable: true,
            caps: empty_table_for_test(),
            device: DeviceFacts {
                build_type: BuildType::UserDebug,
                debuggable: true,
                secure: false,
                adb_secure: false,
                api_level: Some(34),
                abi: Some("arm64-v8a".to_string()),
                verity: VerityState::NotEnforcing,
            },
            paths: ShellPaths::default(),
        }
    }

    #[test]
    fn every_vocabulary_id_parses() {
        // The `expect` in `id()` is only safe because this holds.
        for cap in Capability::all() {
            let id = cap.id();
            assert_eq!(id.platform(), PLATFORM);
            assert_eq!(HostCapability::parse(id.as_str()).unwrap(), id);
        }
    }

    #[test]
    fn ids_match_the_adr_spelling() {
        // ADR-AND-001 §4.4. If B2 is ruled against these, this test is what fails,
        // and it fails in exactly one file.
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
    }

    #[test]
    fn the_vocabulary_builds_a_contract_table() {
        // R5/R6: the Android vocabulary is accepted by the contract's own validator,
        // which is the check that this port has not invented gate logic.
        let table = CapabilityTable::new(PLATFORM, android_vocabulary())
            .expect("android vocabulary must satisfy the contract");
        assert_eq!(table.specs().len(), 5);
        for cap in Capability::all() {
            assert_eq!(table.spec(&cap.id()).unwrap(), &cap.spec());
        }
    }

    #[test]
    fn axes_match_the_adr_tiers() {
        assert!(!Capability::ShellRead.spec().effect.needs_lock());
        assert!(!Capability::ShellRead.spec().approval.needs_token());

        for cap in [
            Capability::ShellWrite,
            Capability::FsOutsideApp,
            Capability::FsSystem,
            Capability::SelinuxPermissive,
        ] {
            assert!(
                cap.spec().effect.needs_lock(),
                "{cap} mutates and must serialise"
            );
            assert!(cap.spec().approval.needs_token(), "{cap} needs approval");
        }

        // ADR-AND-001 §4.4 / §7.3: only the two system-tier capabilities need the
        // dangerous-mode switch.
        for cap in Capability::all() {
            assert_eq!(
                cap.spec().approval.needs_dangerous_session(),
                matches!(cap, Capability::FsSystem | Capability::SelinuxPermissive),
                "{cap} dangerous-mode requirement is wrong"
            );
        }
    }

    #[test]
    fn attribution_mapping_is_the_provisional_b11_one() {
        // Pinned so a change is deliberate. ADR-AND-001 §7.4 gates only the system
        // tier; ADR-087 D4 would also gate `pm install` under `shell:write`.
        assert!(!Capability::ShellRead.spec().attribution.needs_attribution());
        assert!(
            !Capability::ShellWrite
                .spec()
                .attribution
                .needs_attribution()
        );
        assert!(
            !Capability::FsOutsideApp
                .spec()
                .attribution
                .needs_attribution()
        );
        assert_eq!(
            Capability::FsSystem.spec().attribution,
            AttributionTier::Manage,
            "ADR-AND-001 §7.4 gates fs:system on node ownership"
        );
        assert_eq!(
            Capability::SelinuxPermissive.spec().attribution,
            AttributionTier::Manage
        );
    }

    #[test]
    fn reversibility_follows_whether_an_undo_actually_exists() {
        // `/system` has no snapshot to restore, so R8 demands a rollback plan.
        assert!(
            Capability::FsSystem
                .spec()
                .reversibility
                .needs_rollback_plan()
        );
        // `setenforce 0` is auto-restored at session end (ADR-AND-001 §8), so it has
        // a real undo and must not demand a plan for it.
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
    }

    #[test]
    fn lookup_is_closed_over_the_five() {
        // R5: an ID outside the vocabulary has no spec, so the gate refuses it.
        for cap in Capability::all() {
            assert_eq!(lookup(&cap.id()), Some(cap));
        }
        assert_eq!(
            lookup(&HostCapability::parse("android:kernel:write").unwrap()),
            None
        );
        assert_eq!(
            lookup(&HostCapability::parse("esp32:gpio:write").unwrap()),
            None
        );
    }

    #[test]
    fn a_rooted_device_claims_all_five_with_evidence() {
        let p = root_profile();
        let claims = derive_claims(&p);
        assert_eq!(
            claims.len(),
            5,
            "a fully capable device should claim all five"
        );
        // R4: every claim carries evidence that can actually support it.
        for c in &claims {
            assert!(
                c.evidence.kind.supports_claim(),
                "{} was claimed on evidence that cannot support a claim",
                c.capability
            );
        }
    }

    #[test]
    fn a_declined_su_prompt_is_recorded_as_a_denial_not_omitted() {
        // android-host-probe.md §2 item 4: not retryable. Recording it as a denial is
        // what makes that visible in the audit trail, and the contract's audit then
        // refuses to turn it into a claim.
        let mut p = root_profile();
        p.su = SuProbe {
            uid: None,
            context: None,
            prompt_denied: true,
            unavailable: false,
        };
        let claims = derive_claims(&p);
        let write = claims
            .iter()
            .find(|c| c.capability == Capability::ShellWrite.id());
        assert!(
            write.is_some(),
            "the declined prompt should still be recorded"
        );
        assert!(!write.unwrap().evidence.kind.supports_claim());

        let mut table = CapabilityTable::new(PLATFORM, android_vocabulary()).unwrap();
        let audit = acowork_platform_contract::audit_claims(
            &mut table,
            &claims,
            std::time::Duration::from_secs(3600),
        );
        assert!(
            audit
                .unsupported
                .contains(&"android:shell:write".to_string()),
            "a denial must not become a declared capability; audit was {audit}"
        );
        assert!(!table.is_declared(&Capability::ShellWrite.id()));
    }

    #[test]
    fn a_host_with_no_shell_claims_nothing() {
        let mut p = root_profile();
        p.shell_executed = false;
        p.shell = None;
        p.dialects.clear();
        let claims = derive_claims(&p);
        // fs:outside-app does not depend on a shell, so it survives; the other four
        // all need one.
        assert_eq!(claims.len(), 1);
        assert_eq!(claims[0].capability, Capability::FsOutsideApp.id());
    }

    /// The device that motivated this test is a Huawei BLA-AL00 on API 29: `/system/bin/sh`
    /// runs as mksh R57, and the probe command that asks it which dialect it is returns a
    /// zero exit with an answer the dialect parser can read. Substitute the shell that sets
    /// neither `$KSH_VERSION` nor `$BASH_VERSION` — busybox ash, a real option on custom
    /// ROMs — and the dialect is unknown while the shell is unquestionably there.
    ///
    /// Deriving existence from vocabulary classified that device as an APK sandbox with no
    /// shell, and it then refused `android:shell:read` on a host that had just executed
    /// `id -u` and printed `2000`.
    #[test]
    fn an_unnameable_shell_is_still_a_shell() {
        let mut p = root_profile();
        p.shell = None;
        p.dialects.clear();
        // shell_executed stays true: the probe command exited 0, it simply said nothing we
        // could classify.
        let claims = derive_claims(&p);
        assert!(
            claims
                .iter()
                .any(|c| c.capability == Capability::ShellRead.id()),
            "a shell that ran but could not be named must still earn android:shell:read"
        );
        let read = claims
            .iter()
            .find(|c| c.capability == Capability::ShellRead.id())
            .unwrap();
        let EvidenceKind::Observed { what, .. } = &read.evidence.kind else {
            panic!("shell presence must be recorded as observed evidence, not inferred");
        };
        assert!(
            what.contains("not recognised"),
            "the evidence must admit the dialect is unknown rather than imply one: {what}"
        );
    }

    #[test]
    fn fs_system_requires_a_shell_even_when_verity_is_off() {
        // B12: without the shell conjunct an APK profile would declare a capability
        // it has no way to exercise.
        let mut p = root_profile();
        p.shell_executed = false;
        p.shell = None;
        p.system_remountable = true;
        p.device.verity = VerityState::NotEnforcing;
        let claims = derive_claims(&p);
        assert!(
            !claims
                .iter()
                .any(|c| c.capability == Capability::FsSystem.id()),
            "no shell means no `mount`, so fs:system must not be claimed"
        );
        assert!(explain_absence(&p, Capability::FsSystem).contains("no shell"));
    }

    #[test]
    fn every_absent_capability_has_an_explanation() {
        // R9: no capability may be silently missing.
        let mut p = root_profile();
        p.shell_executed = false;
        p.shell = None;
        p.fs_roots.retain(|r| r.own_package);
        p.device.verity = VerityState::Enforcing;
        for cap in Capability::all() {
            let reason = explain_absence(&p, cap);
            assert!(
                reason.len() > 15,
                "{cap} explanation is too terse: {reason}"
            );
        }
        // With no shell, "cannot run `mount` at all" is the more fundamental blocker and
        // correctly takes precedence over the verity state.
        assert!(explain_absence(&p, Capability::FsSystem).contains("no shell"));

        // The verity explanation is reachable only when a shell exists to run `mount`.
        let mut with_shell = p.clone();
        with_shell.shell_executed = true;
        with_shell.shell = Some(crate::host::facts::ShellDialect::MkSh);
        assert!(explain_absence(&with_shell, Capability::FsSystem).contains("dm-verity"));
    }

    #[test]
    fn a_declined_prompt_explains_that_it_is_not_retryable() {
        let mut p = root_profile();
        p.su = SuProbe {
            uid: None,
            context: None,
            prompt_denied: true,
            unavailable: false,
        };
        let reason = explain_absence(&p, Capability::ShellWrite);
        assert!(reason.contains("not retryable"), "{reason}");
        assert!(
            reason.contains("Magisk"),
            "must name where to fix it: {reason}"
        );
    }

    #[test]
    fn explanation_and_derivation_cannot_disagree() {
        // The two read the same fields; this pins the invariant across every
        // combination of the three facts that drive the rules.
        for shell in [true, false] {
            for rooted in [true, false] {
                for remountable in [true, false] {
                    let mut p = root_profile();
                    p.shell = shell.then_some(ShellDialect::MkSh);
                    p.su.uid = rooted.then_some(0);
                    p.system_remountable = remountable;
                    p.device.verity = VerityState::NotEnforcing;

                    let claims = derive_claims(&p);
                    for cap in Capability::all() {
                        let claimed = claims
                            .iter()
                            .any(|c| c.capability == cap.id() && c.evidence.kind.supports_claim());
                        if !claimed {
                            assert!(
                                !explain_absence(&p, cap).is_empty(),
                                "{cap} is absent but unexplained (shell={shell} rooted={rooted} \
                                 remountable={remountable})"
                            );
                        }
                    }
                }
            }
        }
    }
}
