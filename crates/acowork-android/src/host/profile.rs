//! The `HostProfile` aggregate: what this device actually is.
//!
//! android-host-probe.md §3 defines the contract; this module implements it and
//! adds the assembly step that turns raw probe output into the typed profile.
//!
//! # Lifecycle
//!
//! A profile is produced **once at startup** and is read-only for the rest of the
//! session (android-host-probe.md §3: "一次生成，会话期内只读"). It is
//! re-derived only on the events listed in §6 — a Magisk policy change, a
//! `setenforce`, a `remount`, or a process restart after reboot. There is
//! deliberately no polling: probing spawns subprocesses, and on a battery-powered
//! device that costs power for information nobody asked for.
//!
//! # Probe is not a guarantee
//!
//! android-host-probe.md §4 is the load-bearing rule of this whole subsystem:
//! the profile decides **which tools get registered and which capabilities get
//! declared**. It never decides whether a concrete command is allowed to run.
//! SELinux judges per `(scontext, tcontext, tclass)` at execution time, so a
//! profile that says "writable" can still collect `avc: denied`. Real authority
//! is the actual exit code plus stderr, and denials are fed back through
//! [`super::denial`].
//!
//! Treating the profile as a guarantee produces the failure mode §4 warns about:
//! the model probes, gets denied, retries, and fills the context window with
//! garbage. Everything in this module is designed to be *informative*, never
//! *permissive*.

use std::collections::BTreeSet;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use acowork_platform_contract::{
    CapabilityTable, EscalationModel, HostDescription, PrivilegeLevel,
};

use crate::host::capability::{
    Capability, PLATFORM, android_vocabulary, derive_claims, explain_absence,
};
use crate::host::facts::{
    AppletSet, DeviceFacts, FsRoot, Privilege, SelinuxDomain, SelinuxState, ShellDialect, SuProbe,
    normalize_context,
};
use crate::host::probe::{CommandOutput, ProbeOutput};

/// Which of the three host profiles this device turned out to be.
///
/// ADR-AND-001 §4.1: these are three capability tiers of **one** engine, not
/// three products. The tier is probed, never configured — the same binary behaves
/// differently on a stock phone and on a rooted engineering device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum HostProfileName {
    /// No shell, scoped storage only. The fallback, and the answer whenever the
    /// probe itself could not run (android-host-probe.md §2 item 1).
    ApkSandbox,
    /// Termux: app uid, bash, `$PREFIX`.
    Termux,
    /// An unprivileged shell that is not Termux: `adb shell` on a stock device — uid 2000,
    /// `/system/bin/sh` (mksh), no bash, no `$PREFIX`, no `su`.
    ///
    /// This tier exists because the alternative was a lie in the audit record. Classifying
    /// this host as `Termux` reported `"profile": "termux"` for a device with no Termux
    /// installed, and a control plane reading that would conclude a bash-capable,
    /// `$PREFIX`-having environment was available when neither probe item had found one.
    SystemShell,
    /// A rooted debugging device: `su -c` escalation is available.
    RootShell,
}

impl HostProfileName {
    /// True when this profile can spawn processes at all.
    ///
    /// `ApkSandbox` cannot, which is why ADR-AND-001 §7.3 rules that
    /// `dangerous-mode` has no APK UI switch: there is no shell and no `su` on
    /// that profile, so `android:fs:system` is simply unreachable there.
    pub fn has_shell(&self) -> bool {
        !matches!(self, HostProfileName::ApkSandbox)
    }

    /// The stable wire spelling of this tier.
    ///
    /// This is the value the contract's [`HostSummary::profile`] carries. It is the
    /// port's own name for its configuration and is opaque to the contract — used for
    /// scheduling and for humans, never in a gate decision, because a rule keyed on a
    /// profile *name* would be a platform branch in disguise (contract rule R6).
    pub fn as_str(&self) -> &'static str {
        match self {
            HostProfileName::ApkSandbox => "apk-sandbox",
            HostProfileName::Termux => "termux",
            HostProfileName::SystemShell => "system-shell",
            HostProfileName::RootShell => "root-shell",
        }
    }
}

/// Where the executables needed to start a shell actually are.
///
/// Split out from the rest of [`HostProfile`] because these are the only probed facts whose
/// sole consumer is process construction: capability derivation and the gate never read
/// them. Grouping them also makes the one gap in this set impossible to miss — see
/// [`ShellPaths::su`].
///
/// They matter because [`spawn`](super::spawn) clears the child's environment. A cleared
/// environment means a bare command name resolves only if `PATH` was supplied, so "run
/// `bash`" has to become "run `/data/user/0/com.termux/files/usr/bin/bash`". Every path a
/// backend uses is therefore either probed or a fixed platform fact, never a guess.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShellPaths {
    /// Probe item 5a — the resolved `bash`, when `command -v bash` found one.
    ///
    /// `None` is a real answer: a stock Android shell has no bash, which is why the Termux
    /// tier is decided by *this* and not by whether `$PREFIX` happens to be set.
    pub bash: Option<PathBuf>,
    /// Probe item 12 — Termux's `$PREFIX`, when set and reachable.
    pub termux_prefix: Option<String>,
    /// The platform's own shell. Not probed: `/system/bin/sh` is what Android *is*, on
    /// every tier, and it is what a privileged helper is asked to exec.
    pub system_sh: PathBuf,
    /// The privileged helper, as probe item 4a resolved it.
    ///
    /// Item 4 invokes `su` by bare name, so it records *whether* escalation worked and throws
    /// away *where* the binary was — and under a cleared environment a bare name does not
    /// resolve at all. Item 4a (`command -v su`) is what fills this. The two answers are
    /// independent and both are needed: a helper that exists but refuses is not the same
    /// situation as one that is not on `PATH`, and `RootShellBackend` distinguishes them.
    ///
    /// Left as `None` when the lookup found nothing rather than defaulted to a guess: a wrong
    /// path fails loudly as `EscalationUnavailable`, whereas a plausible-but-wrong default
    /// fails as a root shell that silently is not one.
    pub su: Option<PathBuf>,
}

impl ShellPaths {
    /// The locations a `su` binary is found at in practice, in the order a harness should
    /// test them. Magisk installs into a tmpfs early in boot, so `/sbin` precedes
    /// `/system/bin`; a SuperSU or KSU install may differ.
    pub const SU_CANDIDATES: &'static [&'static str] = &[
        "/sbin/su",
        "/system/bin/su",
        "/system/xbin/su",
        "/data/adb/magisk/su",
        "/debug_ramdisk/su",
    ];

    /// The Android default: system shell present, nothing else resolved yet.
    pub fn android_default() -> ShellPaths {
        ShellPaths {
            bash: None,
            termux_prefix: None,
            system_sh: PathBuf::from("/system/bin/sh"),
            su: None,
        }
    }

    /// First candidate in [`ShellPaths::SU_CANDIDATES`] that exists on this filesystem.
    ///
    /// A cheap `stat`, not a probe: it answers "is there a binary here", which is not the
    /// same question as "will it grant root" — that stays probe item 4's job.
    pub fn resolve_su() -> Option<PathBuf> {
        ShellPaths::SU_CANDIDATES
            .iter()
            .map(PathBuf::from)
            .find(|p| p.exists())
    }
}

impl Default for ShellPaths {
    fn default() -> ShellPaths {
        ShellPaths::android_default()
    }
}

/// The probed host, in full.
///
/// Field-for-field this is the android-host-probe.md §3 contract, plus five
/// additions. Each addition is a measured fact that the contract's own derivation
/// rules or audit requirements already presuppose, so leaving it out would force
/// callers to re-derive it:
///
/// | Field | Why it is here |
/// |---|---|
/// | `domain` | §2 item 3 classifies the context; `context` alone keeps only the raw string |
/// | `su` | §2 item 4 requires the uid **and** domain after `su`, and §7 needs the denial/absent distinction because a denied prompt is not retryable |
/// | `system_remountable` | §2 item 7's `touch`/remount probe result; the `android:fs:system` rule reads it directly |
/// | `dialects` | ADR-AND-001 §4.5 registers `bash` **and** `ash` as separate tools, which a single-valued `shell` field cannot express |
/// | `paths` | an execution backend cannot start a shell from a bare name once the child's environment is cleared, so the resolved paths have to be part of the profile rather than guessed at call time |
///
/// The `dialects` addition is recorded as **B8** in the readiness assessment: the
/// §3 contract needs updating upstream-side, because dual tool registration is
/// already decided in the ADR but not representable in the contract as written.

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostProfile {
    /// Which tier this device is.
    pub name: HostProfileName,
    /// Privilege of the process that ran the probe. The Runtime itself is
    /// **always** `AppUid` or `ShellUid` — ADR-AND-001 §4.1 forbids running the
    /// Runtime as root, so a `Root` value here means the probe was run from a
    /// privileged context and is a bug worth surfacing, not a feature.
    pub privilege: Privilege,
    /// SELinux enforcement mode.
    pub selinux: SelinuxState,
    /// Raw `/proc/self/attr/current`, kept verbatim for diagnostics.
    /// Never reported to the Gateway (ADR-AND-001 §7.1).
    pub context: Option<String>,
    /// Classified form of `context`.
    pub domain: SelinuxDomain,
    /// Primary shell dialect — the one a bare `shell` tool binds to.
    ///
    /// `None` means "we could not name the dialect", **not** "there is no shell". Read
    /// [`Self::shell_executed`] for that. Conflating the two is not a theoretical hazard: a
    /// real Huawei BLA-AL00 runs `/system/bin/sh` perfectly well as mksh R57 while setting
    /// neither of the variables a dialect probe can read, and a profile that derived
    /// shell-presence from dialect-presence classified it as an APK sandbox with no shell at
    /// all — which then refused `android:shell:read` on a device that had just answered
    /// `id -u`.
    pub shell: Option<ShellDialect>,
    /// Whether a shell actually executed something for us.
    ///
    /// This is the fact the host tier and the shell capabilities are keyed on, per
    /// android-host-probe.md §2: the dividing line between the shell tier and the APK
    /// sandbox is *execution*, not vocabulary. Established by the platform shell running
    /// probe item 5b to a successful exit, or by `command -v bash` resolving a bash — two
    /// independent pieces of evidence, either of which is enough.
    pub shell_executed: bool,
    /// Every dialect detected, for ADR-AND-001 §4.5 dual registration.
    pub dialects: BTreeSet<ShellDialect>,
    /// Commands actually present (toybox ∪ busybox ∪ spot checks).
    pub applets: AppletSet,
    /// Reachable filesystem roots with measured writability.
    pub fs_roots: Vec<FsRoot>,
    /// Result of the `su` probe.
    pub su: SuProbe,
    /// Whether `/system` survived an actual remount probe.
    pub system_remountable: bool,
    /// The contract capability table: the Android vocabulary plus what this device
    /// actually demonstrated. A pure function of the fields above — never configured.
    ///
    /// This replaced a local `CapabilitySet`. Holding the contract type directly is
    /// what stops two capability models from drifting apart: there is now one set of
    /// declared capabilities in the whole crate, and it is the one the gate reads.
    pub caps: CapabilityTable,
    /// Immutable device facts.
    pub device: DeviceFacts,
    /// Where the executables an execution backend needs are, resolved from the probe.
    ///
    /// Carried here rather than passed to each backend separately because these are probed
    /// facts, and the profile is the only place probed facts live. A backend that had to be
    /// handed a `bash` path by its caller would be a backend whose shell may disagree with
    /// the shell the capabilities were derived from.
    pub paths: ShellPaths,
}

impl HostProfile {
    /// Assemble a profile from raw probe output.
    ///
    /// `own_package` is the Agent's package name (or install directory), used to
    /// tell "our own writable directory" apart from "somewhere else writable" —
    /// the distinction the `android:fs:outside-app` rule turns on.
    ///
    /// This function performs no I/O. Everything it knows came from `probe`.
    pub fn assemble(probe: &ProbeOutput, own_package: &str) -> HostProfile {
        // ── Item 1: uid ────────────────────────────────────────────────────
        // A failed id probe is the documented signal to fall all the way back
        // to apk-sandbox (§2 item 1).
        let privilege = probe
            .id
            .as_ref()
            .and_then(|out| Privilege::parse_uid(&out.stdout))
            .unwrap_or(Privilege::AppUid);
        let probe_ran = probe.id.is_some();

        // ── Items 2 + 3: SELinux mode and domain ───────────────────────────
        let selinux = probe
            .getenforce
            .as_ref()
            .map(|out| SelinuxState::parse(&out.stdout))
            .unwrap_or(SelinuxState::Unknown);
        let context = probe.attr_current.as_ref().and_then(|out| {
            // The kernel terminates this read with NUL, not a newline — see
            // `facts::normalize_context`. Storing the raw text would put a NUL in the
            // profile and in every audit record that quotes it.
            normalize_context(&out.stdout).map(str::to_string)
        });
        let domain = context
            .as_deref()
            .map(SelinuxDomain::parse)
            .unwrap_or(SelinuxDomain::Unreadable);

        // ── Item 4: su ─────────────────────────────────────────────────────
        let su = match probe.su.as_ref() {
            Some(out) => {
                crate::host::facts::parse_su_probe(&out.stdout, &out.stderr, out.timed_out)
            }
            // Not run at all (e.g. no su binary on PATH per a cheap pre-check).
            None => SuProbe {
                uid: None,
                context: None,
                prompt_denied: false,
                unavailable: true,
            },
        };

        // ── Items 5: shell dialects ────────────────────────────────────────
        let mut dialects = BTreeSet::new();
        if let Some(out) = probe.bash_path.as_ref()
            && out.succeeded()
            && !out.stdout.trim().is_empty()
        {
            dialects.insert(ShellDialect::Bash);
        }
        let system_sh_dialect = probe
            .system_sh_version
            .as_ref()
            .and_then(|out| ShellDialect::parse_version_banner(&out.stdout));
        if let Some(d) = system_sh_dialect {
            dialects.insert(d);
        }

        // ── Did a shell execute at all? ────────────────────────────────────
        // Two independent witnesses, either sufficient:
        //
        //   - `/system/bin/sh -c '…'` exited 0. The command *is* the shell being asked to run
        //     a script, so a zero exit is the shell attesting to itself; an unrecognised
        //     banner (busybox ash sets neither variable) still counts.
        //   - `command -v bash` resolved a path. `command` is a shell builtin, so a successful
        //     lookup could not have happened without a shell parsing it.
        //
        // Deliberately not `system_sh_dialect.is_some()`: that is the dialect question, and
        // answering the existence question with it is what misclassified a working device.
        let platform_shell_ran = probe
            .system_sh_version
            .as_ref()
            .is_some_and(|out| out.succeeded());
        let shell_executed = platform_shell_ran || !dialects.is_empty();

        // Primary dialect: prefer the one the host is actually known for. On
        // Termux that is bash; on a rooted device driving /system/bin/sh it is
        // whatever that binary turned out to be.
        let shell = if dialects.contains(&ShellDialect::Bash) && probe.termux_prefix.is_some() {
            Some(ShellDialect::Bash)
        } else {
            system_sh_dialect.or_else(|| dialects.iter().next().copied())
        };

        // ── Items 4a and 5a: where `su` and `bash` actually are ────────────
        // `command -v X` prints the resolved path and exits non-zero when there is none, so
        // both conditions are needed — a non-zero exit whose stdout happens to be a leftover
        // from a wrapper script is not the binary we asked for.
        let bash = resolved_path(probe.bash_path.as_ref());
        // The gap this closes is functional, not cosmetic: `RootShellBackend` refuses to be
        // built without `paths.su`, and nothing used to fill that field, so the root tier was
        // unreachable from an assembled profile — reachable only from a hand-written one.
        let su_path = resolved_path(probe.su_path.as_ref());

        let paths = ShellPaths {
            bash,
            su: su_path,
            termux_prefix: probe.termux_prefix.clone(),
            ..ShellPaths::android_default()
        };

        // ── Item 6: applets ────────────────────────────────────────────────
        let mut applets = AppletSet::new();
        let mut saw_list_source = false;
        for out in probe.toybox_list.iter().chain(probe.busybox_list.iter()) {
            let parsed = AppletSet::parse_list(&out.stdout);
            saw_list_source |= !parsed.list_source_missing;
            applets.merge(&parsed);
        }
        applets.list_source_missing = !saw_list_source;
        for (name, out) in &probe.applet_spot_checks {
            // `command -v <name>` echoes the resolved path and exits non-zero
            // when the applet is absent, so exit code plus non-empty stdout is
            // the presence test. The name comes from the map key, which the
            // runner recorded when it issued the check.
            if out.succeeded() && !out.stdout.trim().is_empty() {
                applets.insert_confirmed(name);
            }
        }

        // ── Items 7 + 12: mounts, remount probe, fs roots ──────────────────
        let system_remountable = probe
            .system_remount
            .as_ref()
            .is_some_and(|out| out.exit_code == Some(0));
        let fs_roots = probe.fs_roots.clone();

        // ── Items 8-11: device facts ───────────────────────────────────────
        let device = DeviceFacts {
            build_type: probe
                .prop_build_type
                .as_ref()
                .and_then(|out| crate::host::facts::parse_prop(&out.stdout))
                .as_deref()
                .map(crate::host::facts::BuildType::parse)
                .unwrap_or(crate::host::facts::BuildType::Unknown),
            debuggable: probe
                .prop_debuggable
                .as_ref()
                .is_some_and(|out| crate::host::facts::parse_bool_prop(&out.stdout)),
            secure: probe
                .prop_secure
                .as_ref()
                .is_some_and(|out| crate::host::facts::parse_bool_prop(&out.stdout)),
            adb_secure: probe
                .prop_adb_secure
                .as_ref()
                .is_some_and(|out| crate::host::facts::parse_bool_prop(&out.stdout)),
            api_level: probe
                .prop_sdk
                .as_ref()
                .and_then(|out| out.stdout.trim().parse::<u32>().ok()),
            abi: probe
                .prop_abi
                .as_ref()
                .and_then(|out| crate::host::facts::parse_prop(&out.stdout)),
            verity: probe
                .prop_veritymode
                .as_ref()
                .map(|out| crate::host::facts::VerityState::parse(&out.stdout))
                .unwrap_or(crate::host::facts::VerityState::Unknown),
        };

        // ── Profile tier ───────────────────────────────────────────────────
        // Precedence RootShell > Termux > SystemShell > ApkSandbox, where the
        // dividing line between the shell tiers and ApkSandbox is **whether a shell
        // actually executed**.
        //
        // Making that the criterion rather than "is $PREFIX set" is what turns the
        // invariant into a structural one: ApkSandbox holds if and only if no
        // shell was detected, so an ApkSandbox profile can never declare a shell
        // capability.
        //
        // `$PREFIX` and the resolved `bash` then split the shell tiers, which is where
        // those markers actually belong: they say *which* shell environment the device
        // offered, not whether it offered one. Using "a shell ran" alone for that split
        // called this crate's own test device Termux — a Huawei with no Termux anywhere
        // on it — and put `"profile": "termux"` in the audit record, which is a claim
        // about installed software that nothing in the probe had observed. The tier a
        // device is *not* in is as much a fabrication as a path it invented.
        //
        // The precedence itself is an inference: neither the ADR nor the probe
        // spec states it. Recorded as B9 in the readiness assessment.
        let name = if !probe_ran {
            // §2 item 1: the probe itself failed => apk-sandbox.
            HostProfileName::ApkSandbox
        } else if su.got_root() {
            HostProfileName::RootShell
        } else if !shell_executed {
            HostProfileName::ApkSandbox
        } else if paths.bash.is_some() || paths.termux_prefix.is_some() {
            HostProfileName::Termux
        } else {
            HostProfileName::SystemShell
        };

        let mut profile = HostProfile {
            name,
            privilege,
            selinux,
            context,
            domain,
            shell,
            shell_executed,
            dialects,
            applets,
            fs_roots,
            su,
            system_remountable,
            caps: empty_table(),
            device,
            paths,
        };
        profile.caps = derive_table(&profile);

        // Structural invariant: the tier says "has a shell" exactly when the
        // derivation produced a shell capability. This is a self-check, not a
        // second source of truth — if it ever fires, the tier logic above and the
        // capability rules have drifted apart, and the profile would be lying to
        // the tool registry in one direction or the other.
        debug_assert_eq!(
            profile.name.has_shell(),
            profile.caps.is_declared(&Capability::ShellRead.id()),
            "host tier and declared shell capability disagree"
        );

        // `own_package` is used by the runner when it builds `fs_roots` (it is
        // the runner that knows which root is the app's own). Accepting it here
        // keeps the signature honest about what assembly depends on, and lets a
        // caller re-tag roots if the package name was not known at probe time.
        if !own_package.is_empty() {
            for root in &mut profile.fs_roots {
                if root.path.contains(own_package) {
                    root.own_package = true;
                }
            }
            profile.caps = derive_table(&profile);
        }

        profile
    }

    /// The coarse summary that may be reported to the Gateway.
    ///
    /// ADR-AND-001 §7.1 is explicit about both halves of this: report the
    /// profile name, capability set, shell dialect and privilege level; do
    /// **not** report the device serial or model, the concrete `fs_roots` paths,
    /// the raw SELinux context string, or observed-denial detail.
    ///
    /// Note that §7.1 also rules the Gateway uses this only for display and
    /// filtering and never for an allow decision. That ruling currently
    /// contradicts upstream ADR-087 D5 and design doc 30 §6.2 — see blocker
    /// **B1**/**B2** in the readiness assessment. The summary type is kept
    /// minimal so that whichever way the ruling goes, the wire shape does not
    /// have to leak more than this.
    pub fn gateway_summary(&self) -> HostCapabilitySummary {
        HostCapabilitySummary {
            profile: self.name,
            privilege: self.privilege,
            caps: self
                .caps
                .declared_ids()
                .into_iter()
                .map(str::to_string)
                .collect(),
            shell_dialect: self.shell.map(|d| match d {
                ShellDialect::Bash => "bash",
                ShellDialect::MkSh => "mksh",
                ShellDialect::BusyBoxSh => "busybox-sh",
            }),
        }
    }

    /// True when the Runtime process itself is running privileged.
    ///
    /// ADR-AND-001 §4.1 makes "the Runtime is never root" a non-negotiable
    /// invariant, and §6 P1 makes asserting it an acceptance criterion. This is
    /// the predicate that assertion checks.
    ///
    /// It is the Android spelling of contract rule R3; [`HostDescription::is_r3_conformant`]
    /// is the platform-neutral one, and the two agree by construction because
    /// [`Privilege::to_contract`] maps `Root` to `Unrestricted`.
    pub fn runtime_is_unprivileged(&self) -> bool {
        self.privilege < Privilege::Root
    }
}

/// An empty table over the Android vocabulary.
///
/// Exists because [`HostProfile::assemble`] builds the struct before it has the facts
/// to derive from; the real table is filled in on the next line.
/// Read a `command -v` answer: the path it echoed, if and only if the lookup succeeded.
///
/// Shared by items 4a and 5a because both ask the same question of the same kind of answer,
/// and because the failure mode is easy to get wrong in one place and not the other: treating
/// "exit 1, empty stdout" as "present but unnamed" would hand a backend a `Some("")` path.
fn resolved_path(out: Option<&CommandOutput>) -> Option<PathBuf> {
    out.filter(|o| o.succeeded())
        .map(|o| o.stdout.trim().to_string())
        .filter(|text| !text.is_empty())
        .map(PathBuf::from)
}

fn empty_table() -> CapabilityTable {
    CapabilityTable::new(PLATFORM, android_vocabulary())
        .expect("the Android vocabulary satisfies the contract")
}

/// Derive the declared-capability table from probed facts.
///
/// Two steps, and the split is the contract's, not Android's: [`derive_claims`] turns
/// facts into claims with evidence, then [`acowork_platform_contract::audit_claims`]
/// validates them against the vocabulary and folds in the survivors. Going through the
/// audit rather than declaring directly is what enforces rules R4 and R5 on this port —
/// a claim backed by a denial, or an ID outside the vocabulary, cannot become a
/// declared capability even if the derivation logic says it should.
fn derive_table(profile: &HostProfile) -> CapabilityTable {
    let mut table = empty_table();
    let claims = derive_claims(profile);
    // Evidence is taken at probe time and the profile is session-immutable, so the
    // re-probe interval is the session lifetime: nothing here expires by age. The
    // invalidation events in android-host-probe.md §6 rebuild the profile instead.
    let audit = acowork_platform_contract::audit_claims(
        &mut table,
        &claims,
        std::time::Duration::from_secs(u64::MAX / 2),
    );
    debug_assert!(
        audit.unregistered.is_empty(),
        "derivation produced an ID outside the Android vocabulary: {:?}",
        audit.unregistered
    );
    table
}

impl HostDescription for HostProfile {
    fn platform(&self) -> &str {
        PLATFORM
    }

    fn profile_name(&self) -> &str {
        self.name.as_str()
    }

    fn privilege(&self) -> Option<PrivilegeLevel> {
        // Android always has uids, so this is never `None`. The `Option` exists for
        // platforms with no privilege separation at all — an ESP32 has no MMU and no
        // uid, and inventing a value there would make the field mean nothing.
        Some(self.privilege.to_contract())
    }

    fn escalation(&self) -> EscalationModel {
        // `su -c` is a per-call helper: it runs one command at elevated privilege and
        // returns. That is the conformant shape under R3. A device with no working
        // `su` has no escalation at all.
        if self.su.got_root() || self.privilege >= Privilege::Root {
            EscalationModel::PerCallHelper
        } else {
            EscalationModel::None
        }
    }

    fn capabilities(&self) -> &CapabilityTable {
        &self.caps
    }

    fn explain_absence(&self, capability: &acowork_platform_contract::HostCapability) -> String {
        // An ID outside the Android five has no Android-specific explanation, and
        // inventing one would be a guess. Say so plainly: the gate refuses such an ID
        // on rule R5 before it ever asks why.
        match crate::host::capability::lookup(capability) {
            Some(cap) => explain_absence(self, cap),
            None => format!(
                "`{capability}` is not a capability the Android port registers, so this device \
                 has no evidence about it either way"
            ),
        }
    }

    // `summary` is deliberately *not* overridden. The contract's default builds the
    // reported shape from `platform`/`profile_name`/`privilege`/`escalation`/`capabilities`,
    // and that shape is the one whose fields were designed so no device identifier can be
    // put in them (rule R13). Overriding it here would both duplicate that guarantee and
    // — as an earlier revision did — recurse infinitely, because `HostDescription::summary`
    // resolves statically to this impl rather than to the default.
    //
    // `gateway_summary` remains for the Android-specific extras ADR-AND-001 §7.1 asks for,
    // notably the shell dialect, which the contract has no opinion about.
}

/// The Gateway-facing capability summary (ADR-AND-001 §7.1).
///
/// Deliberately contains no device identifiers and no paths.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostCapabilitySummary {
    /// Which tier this device is.
    pub profile: HostProfileName,
    /// Privilege level of the Runtime process itself.
    pub privilege: Privilege,
    /// Declared capability IDs.
    pub caps: Vec<String>,
    /// Primary shell dialect, for tool registration.
    pub shell_dialect: Option<&'static str>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::capability::Capability;
    use crate::host::facts::VerityState;
    use crate::host::probe::{CommandOutput, ProbeOutput};

    fn out(stdout: &str) -> CommandOutput {
        CommandOutput::ok(stdout)
    }

    /// Item 6c answers for the commands no applet listing can see. On the measured device
    /// these are standalone `/system/bin` binaries; a fixture that lists them as applets is
    /// describing a device that does not exist.
    fn spot_checks(names: &[&str]) -> std::collections::BTreeMap<String, CommandOutput> {
        names
            .iter()
            .map(|n| (n.to_string(), out(&format!("/system/bin/{n}"))))
            .collect()
    }

    fn rooted_probe() -> ProbeOutput {
        ProbeOutput {
            id: Some(out("10233\n")),
            getenforce: Some(out("Enforcing\n")),
            attr_current: Some(out("u:r:untrusted_app:s0:c512,c768\n")),
            su: Some(out("0\nu:r:magisk:s0\n")),
            su_path: Some(out("/sbin/su\n")),
            bash_path: Some(out("")),
            system_sh_version: Some(out("KSH=@(#)MIRBSD KSH R57 2019-03-01 Android\\nBASH=\\n")),
            toybox_list: Some(out("cat\nchmod\nmount\nps\nsetprop\n")),
            busybox_list: None,
            applet_spot_checks: spot_checks(&["logcat", "dumpsys", "getprop", "am", "pm"]),
            mount_table: Some(out("/dev/block/sda1 on /data type f2fs (rw,seclabel)\n")),
            system_remount: Some(out("")),
            prop_build_type: Some(out("userdebug\n")),
            prop_debuggable: Some(out("1\n")),
            prop_secure: Some(out("0\n")),
            prop_adb_secure: Some(out("0\n")),
            prop_sdk: Some(out("34\n")),
            prop_abi: Some(out("arm64-v8a\n")),
            prop_veritymode: Some(out("disabled\n")),
            termux_prefix: None,
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
        }
    }

    #[test]
    fn rooted_device_assembles_the_root_shell_tier() {
        let p = HostProfile::assemble(&rooted_probe(), "com.example.agent");
        assert_eq!(p.name, HostProfileName::RootShell);
        // The Runtime itself stays unprivileged even though su works.
        assert_eq!(p.privilege, Privilege::AppUid);
        assert!(p.runtime_is_unprivileged());
        assert_eq!(p.selinux, SelinuxState::Enforcing);
        assert_eq!(p.domain, SelinuxDomain::UntrustedApp);
        assert_eq!(p.shell, Some(ShellDialect::MkSh));
        assert!(p.su.got_root());
        assert_eq!(
            p.device.build_type,
            crate::host::facts::BuildType::UserDebug
        );
        assert!(p.device.debuggable);
        assert_eq!(p.device.api_level, Some(34));
        assert_eq!(p.device.abi.as_deref(), Some("arm64-v8a"));
        assert_eq!(p.device.verity, VerityState::NotEnforcing);
    }

    #[test]
    fn rooted_device_derives_the_full_capability_set() {
        let p = HostProfile::assemble(&rooted_probe(), "com.example.agent");
        for cap in Capability::all() {
            assert!(p.caps.is_declared(&cap.id()), "missing {cap}");
        }
    }

    #[test]
    fn applets_come_from_the_bulk_list() {
        let p = HostProfile::assemble(&rooted_probe(), "com.example.agent");
        assert!(p.applets.contains("setprop"));
        assert!(p.applets.contains("mount"));
        assert!(!p.applets.list_source_missing);
    }

    #[test]
    fn the_bulk_listing_alone_cannot_see_a_system_bin_binary() {
        // The two sources of command presence are not interchangeable, and this is the
        // defect item 6c exists for: on the measured device `logcat`, `dumpsys` and `getprop`
        // are `/system/bin` binaries that appear in no applet listing, so a profile built
        // from `toybox` alone declares ADR-AND-001 §4.4's whole read surface absent.
        let mut probe = rooted_probe();
        assert!(
            !probe
                .toybox_list
                .as_ref()
                .unwrap()
                .stdout
                .contains("logcat"),
            "the fixture's listing must not contain what the real device's does not"
        );
        assert!(
            HostProfile::assemble(&probe, "com.example.agent")
                .applets
                .contains("logcat"),
            "confirmed by spot-check, therefore present"
        );

        // Remove the spot-check answers and the command becomes unknown — which is not the
        // same as the device saying it is absent, and must not be reported as a capability.
        probe.applet_spot_checks.clear();
        assert!(
            !HostProfile::assemble(&probe, "com.example.agent")
                .applets
                .contains("logcat"),
            "presence may not be inferred from a listing that never mentioned it"
        );
    }

    #[test]
    fn termux_probe_yields_the_termux_tier_with_bash() {
        let probe = ProbeOutput {
            su: None,
            su_path: None,
            bash_path: Some(out("/data/data/com.termux/files/usr/bin/bash\n")),
            system_sh_version: Some(out("KSH=@(#)MIRBSD KSH R57 2019-03-01 Android\nBASH=\n")),
            termux_prefix: Some("/data/data/com.termux/files/usr".to_string()),
            prop_veritymode: Some(out("enforcing\n")),
            system_remount: None,
            fs_roots: vec![FsRoot {
                path: "/data/data/com.termux/files/usr".to_string(),
                writable: true,
                own_package: false,
            }],
            ..rooted_probe()
        };
        let p = HostProfile::assemble(&probe, "com.termux");
        assert_eq!(p.name, HostProfileName::Termux);
        assert_eq!(p.shell, Some(ShellDialect::Bash));
        // Both dialects are visible so §4.5 can register two tools.
        assert!(p.dialects.contains(&ShellDialect::Bash));
        assert!(p.dialects.contains(&ShellDialect::MkSh));
        assert!(p.caps.is_declared(&Capability::ShellRead.id()));
        assert!(
            !p.caps.is_declared(&Capability::ShellWrite.id()),
            "Termux without su must stay read-only"
        );
        assert!(!p.caps.is_declared(&Capability::FsSystem.id()));
    }

    /// The device this port was first run against: uid 2000, `/system/bin/sh` answering to
    /// mksh, no bash, no `$PREFIX`, no su.
    ///
    /// Until this tier existed that host was reported as `Termux`, which is a claim about
    /// installed software that neither probe item 5a (`command -v bash`) nor item 13 (`$PREFIX`)
    /// had observed. The name lands in `HostSummary.profile` and in every exec record, so the
    /// fabrication was reported upstream on every call.
    /// The root tier used to be unreachable from a probe.
    ///
    /// `RootShellBackend` refuses to be built without `paths.su`, and `assemble()` never
    /// filled that field, so a rooted device that had answered every probe correctly still
    /// could not get a backend — only a hand-written profile could. That is the shape of bug
    /// a fixture hides: every fixture that needed a `su` path had set it by hand.
    #[test]
    fn the_root_tier_carries_a_su_path_a_backend_can_actually_use() {
        let probe = rooted_probe();
        let p = HostProfile::assemble(&probe, "com.example.agent");
        assert_eq!(p.name, HostProfileName::RootShell);
        assert_eq!(
            p.paths.su,
            Some(PathBuf::from("/sbin/su")),
            "the resolved su must reach the profile, or the tier it names is not buildable"
        );
    }

    #[test]
    fn a_su_lookup_that_found_nothing_leaves_no_path() {
        // `command -v su` exits 1 and prints nothing on a device with no su. Neither half of
        // that may become a path: `Some("")` would satisfy the backend's presence check and
        // then fail to exec.
        let probe = ProbeOutput {
            su: Some(out("127\n")),
            su_path: Some(out("")),
            ..rooted_probe()
        };
        let p = HostProfile::assemble(&probe, "com.example.agent");
        assert_eq!(p.paths.su, None);
    }

    #[test]
    fn a_shell_without_termux_markers_is_the_system_shell_tier() {
        let probe = ProbeOutput {
            su: None,
            su_path: None,
            bash_path: None,
            termux_prefix: None,
            system_sh_version: Some(out("KSH=@(#)MIRBSD KSH R57 2019-03-01 Android\nBASH=\n")),
            prop_veritymode: Some(out("enforcing\n")),
            system_remount: None,
            fs_roots: vec![FsRoot {
                path: "/data/local/tmp".to_string(),
                writable: true,
                own_package: false,
            }],
            ..rooted_probe()
        };
        let p = HostProfile::assemble(&probe, "com.acowork.node");
        assert_eq!(p.name, HostProfileName::SystemShell);
        assert_eq!(p.name.as_str(), "system-shell");
        assert!(p.shell_executed);
        assert_eq!(p.shell, Some(ShellDialect::MkSh));
        assert_eq!(p.paths.bash, None);
        assert_eq!(p.paths.termux_prefix, None);

        // Same capability consequences as Termux: for `shell:read` a shell is a shell, and
        // the absence of root still means no write. The new tier changes what the host *is*,
        // not what it may do.
        assert!(p.caps.is_declared(&Capability::ShellRead.id()));
        assert!(!p.caps.is_declared(&Capability::ShellWrite.id()));
        assert!(!p.caps.is_declared(&Capability::FsSystem.id()));

        // And it is not the sandbox tier, whose defining property is that nothing ran.
        assert!(p.name.has_shell());
    }

    #[test]
    fn failed_probe_falls_back_to_apk_sandbox() {
        // §2 item 1: the probe itself failing means apk-sandbox.
        let p = HostProfile::assemble(&ProbeOutput::nothing_ran(), "com.example.agent");
        assert_eq!(p.name, HostProfileName::ApkSandbox);
        assert!(p.caps.declared().is_empty());
        assert_eq!(p.selinux, SelinuxState::Unknown);
        assert_eq!(p.domain, SelinuxDomain::Unreadable);
        assert!(!p.name.has_shell());
    }

    #[test]
    fn apk_without_shell_or_prefix_is_apk_sandbox() {
        let probe = ProbeOutput {
            id: Some(out("10233\n")),
            su: None,
            su_path: None,
            bash_path: Some(out("")),
            system_sh_version: None,
            termux_prefix: None,
            fs_roots: vec![FsRoot {
                path: "/data/data/com.example.agent".to_string(),
                writable: true,
                own_package: true,
            }],
            ..rooted_probe()
        };
        let p = HostProfile::assemble(&probe, "com.example.agent");
        assert_eq!(p.name, HostProfileName::ApkSandbox);
        assert!(p.caps.declared().is_empty());
    }

    #[test]
    fn denied_su_prompt_does_not_yield_the_root_tier() {
        let probe = ProbeOutput {
            su: Some(CommandOutput::failed(1, "su: Permission denied")),
            ..rooted_probe()
        };
        let p = HostProfile::assemble(&probe, "com.example.agent");
        assert_ne!(p.name, HostProfileName::RootShell);
        assert!(p.su.prompt_denied);
        assert!(!p.caps.is_declared(&Capability::ShellWrite.id()));
    }

    #[test]
    fn own_package_root_is_retagged_from_the_package_name() {
        let probe = ProbeOutput {
            fs_roots: vec![FsRoot {
                path: "/data/data/com.example.agent/files".to_string(),
                writable: true,
                // Runner did not know the package at probe time.
                own_package: false,
            }],
            ..rooted_probe()
        };
        let p = HostProfile::assemble(&probe, "com.example.agent");
        assert!(p.fs_roots[0].own_package);
        // With only our own directory writable, outside-app must not be granted.
        assert!(!p.caps.is_declared(&Capability::FsOutsideApp.id()));
    }

    #[test]
    fn gateway_summary_carries_no_device_identifiers_or_paths() {
        let p = HostProfile::assemble(&rooted_probe(), "com.example.agent");
        let summary = p.gateway_summary();
        let json = serde_json::to_string(&summary).unwrap();

        assert_eq!(summary.profile, HostProfileName::RootShell);
        assert!(summary.caps.iter().any(|c| c == "android:shell:read"));
        assert_eq!(summary.shell_dialect, Some("mksh"));

        // ADR-AND-001 §7.1: none of these may cross the wire.
        for forbidden in [
            "u:r:untrusted_app",
            "/data/local/tmp",
            "/data/data/com.example.agent",
            "arm64-v8a",
            "userdebug",
        ] {
            assert!(
                !json.contains(forbidden),
                "gateway summary leaked {forbidden}: {json}"
            );
        }
    }

    #[test]
    fn profile_serializes_stably_for_snapshot_baselines() {
        let p = HostProfile::assemble(&rooted_probe(), "com.example.agent");
        let a = serde_json::to_string(&p).unwrap();
        let b = serde_json::to_string(&p).unwrap();
        assert_eq!(
            a, b,
            "android-host-probe.md §7 needs deterministic snapshots"
        );
    }
}
