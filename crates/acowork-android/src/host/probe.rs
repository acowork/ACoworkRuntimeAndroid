//! The probe contract: which commands run, what they cost, and how the raw
//! output is carried to the parsers.
//!
//! # Separation of concerns
//!
//! This module owns **what to ask** and **what came back**. It does not own
//! spawning (that is the platform runner, `ProbeRunner`) and it does not own
//! interpretation (that is [`super::facts`] and [`super::profile`]). Keeping the
//! three apart is what lets the whole probe be unit-tested from fabricated
//! output — the P0 acceptance criterion in ADR-AND-001 §6.
//!
//! # Budget
//!
//! android-host-probe.md §2: the full probe must finish in under two seconds
//! serially, with a 500 ms per-item timeout, and a single timeout must degrade to
//! `Unknown` rather than block the rest. These are not advisory numbers — the
//! probe runs at startup on a phone, and a startup that hangs is indistinguishable
//! from a crash to the user.

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::time::Duration;
use std::time::Instant;

use serde::{Deserialize, Serialize};

use crate::host::facts::FsRoot;

/// Per-item probe timeout (android-host-probe.md §2).
pub const PROBE_ITEM_TIMEOUT: Duration = Duration::from_millis(500);

/// Whole-probe budget. Exceeding it is a bug, not a degradation.
pub const PROBE_TOTAL_BUDGET: Duration = Duration::from_secs(2);

/// The high-value commands spot-checked with `command -v` (item 6c).
///
/// android-host-probe.md §7.5 item 1 caps this at ten. The cap was originally justified by
/// spawn cost — one process per name — and item 6c now runs them all in a single shell
/// invocation, so the budget is no longer what the number protects. It still earns its
/// place for a different reason: every name here is a claim the port makes about devices
/// in general, so the list has to stay short enough that each entry is defensible. These ten
/// are the ones the Android debugging toolset (ADR-AND-001 §4.6 item 6) and the write tier
/// actually invoke.
///
/// Within that, a name earns its slot by being one no other probe item **already proves**.
/// `logcat`, `dumpsys`, `getprop`, `am`, `pm`, `input`, `screencap` and `settings` are
/// standalone `/system/bin` binaries on the one real device this has been run against, and
/// none appears in `toybox --list`. `mount` was the only name here that another item
/// executes for its own reasons — item 7 runs `mount` and parses the table — so its slot was
/// buying a second answer to a question item 7 has already answered by running the thing.
/// `settings` took it: named outright by §4.4's write row, invisible to every listing.
///
/// `ps` and `setprop` stay even though the listing shows them here. A listing is a claim
/// about a dispatcher's own table; `command -v` is a claim about the filesystem the shell
/// will actually resolve against, and whether the two agree is a device-dependent accident.
pub const SPOT_CHECK_APPLETS: [&str; 11] = [
    "logcat",
    "dumpsys",
    "getprop",
    "setprop",
    "am",
    "pm",
    "input",
    "screencap",
    "settings",
    "ps",
    // ADR-AND-001 §4.6 item 6 names `bugreportz` as an evidence source, and — measured on
    // the BLA-AL00 — no applet listing can see it: `/system/bin/bugreportz` is a standalone
    // binary, absent from the 194 names `toybox` reports. It is therefore exactly the case
    // this list exists for. Presence is all this asks: a bug report takes the better part of
    // a minute to generate and is not something a startup probe should trigger.
    "bugreportz",
];

/// The evidence locations ADR-AND-001 §4.6 item 6 names as paths, probed by
/// [`ProbeCommand::EvidenceSurface`].
///
/// Spelled out here rather than derived from [`EvidencePath`](super::facts::EvidencePath)
/// because the probe script is a shell string that needs the words; a test pins the two
/// lists against each other, so they cannot drift.
pub const EVIDENCE_PATHS: [&str; 3] = ["/data/anr", "/data/tombstones", "/data/system/dropbox"];

/// One probe command, identified so results can be routed without stringly-typed
/// keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ProbeCommand {
    /// Item 1 — `id -u`.
    Id,
    /// Item 2 — `getenforce`.
    GetEnforce,
    /// Item 3 — `cat /proc/self/attr/current`.
    AttrCurrent,
    /// Item 4 — `su -c 'id -u; cat /proc/self/attr/current'`.
    Su,
    /// Item 4a — where `su` is, if the shell can find one at all.
    SuPath,
    /// Item 5a — `command -v bash`.
    BashPath,
    /// Item 5b — ask `/system/bin/sh` which dialect it is, by having it run a script.
    SystemShVersion,
    /// Item 6a — the `toybox` applet listing.
    ToyboxList,
    /// Item 6b — `busybox --list`.
    BusyboxList,
    /// Item 6c — `command -v` spot-check over [`SPOT_CHECK_APPLETS`].
    ///
    /// The bulk listings in 6a/6b answer "which applets does this toybox/busybox build
    /// provide". They do **not** answer "which commands can this shell run": on a real
    /// device the high-value debug commands are standalone binaries that no applet listing
    /// mentions — measured on a Huawei BLA-AL00, `toybox` listed 194 applets and `logcat`,
    /// `getprop`, `dumpsys`, `am`, `pm`, `input` and `screencap` were none of them, while
    /// all of them exist under `/system/bin`. A profile assembled from the listing alone
    /// therefore reports the whole read surface of ADR-AND-001 §4.4 as absent on a device
    /// that has it.
    ///
    /// This is android-host-probe.md §7.5 item 1's second half: take the bulk list once,
    /// then `command -v` a capped set of high-value names.
    SpotChecks,
    /// Item 7a — the mount table.
    MountTable,
    /// Item 7b — the `/system` remount attempt.
    SystemRemount,
    /// Item 8 — `getprop ro.build.type`.
    PropBuildType,
    /// Item 9 — `getprop ro.debuggable`.
    PropDebuggable,
    /// Item 9 — `getprop ro.secure`.
    PropSecure,
    /// Item 9 — `getprop ro.adb.secure`.
    PropAdbSecure,
    /// Item 10 — `getprop ro.boot.veritymode`.
    PropVerityMode,
    /// Item 11 — `getprop ro.build.version.sdk`.
    PropSdk,
    /// Item 11 — `getprop ro.product.cpu.abi`.
    PropAbi,
    /// Item 13 — what this uid can actually collect from the evidence locations
    /// ADR-AND-001 §4.6 item 6 names.
    ///
    /// The ADR lists `/data/anr`, `/data/tombstones` and `/data/system/dropbox` as the
    /// debugging payload and calls them root-tier value. Measured on a `user` build at uid
    /// 2000 they are not one thing: the ANR directory lists its traces by name and refuses
    /// every byte of them, while the other two cannot even be statted. A yes/no probe would
    /// have reported all three as unavailable and thrown away the index of a hang, which is
    /// the part an agent can act on.
    ///
    /// Batched into one invocation for the same reason as [`Self::SpotChecks`]: three paths
    /// at four commands each is twelve round trips on a battery.
    EvidenceSurface,
    /// Item 13b — how many services `dumpsys` will dump here.
    ///
    /// `dumpsys <service>` is the single highest-volume read surface on Android, and the ADR
    /// treats it as one command. It is not one: it is a dispatcher over a per-device list.
    /// The readiness assessment's own open item says exactly this — `dumpsys -l` had been
    /// checked, no individual service had. The inventory is the honest scope: the port can
    /// say how many services this device exposes, and cannot promise that any one of them
    /// will not answer with a permission error.
    DumpsysInventory,
}

impl ProbeCommand {
    /// The command line to run.
    ///
    /// Two details matter here and are easy to get wrong:
    ///
    /// - The `su` probe passes its script through **`su -c`**, and the inner
    ///   script is quoted so it survives one level of shell parsing. Per
    ///   ADR-AND-001 §4.7, sensitive material goes through stdin rather than
    ///   argv, because argv is world-readable via `ps`. Nothing in the probe is
    ///   sensitive, but the habit is enforced by the exec contract anyway.
    /// - `getenforce` and the applet listings are run **without** a shell wrapper
    ///   where possible, so a missing applet produces a spawn error rather than a
    ///   shell error message that a parser might mistake for data.
    pub fn command_line(&self) -> Cow<'static, str> {
        match self {
            ProbeCommand::Id => Cow::Borrowed("id -u"),
            ProbeCommand::GetEnforce => Cow::Borrowed("getenforce"),
            ProbeCommand::AttrCurrent => Cow::Borrowed("cat /proc/self/attr/current"),
            ProbeCommand::Su => Cow::Borrowed("su -c 'id -u; cat /proc/self/attr/current'"),
            // Item 4a. `command -v` rather than a `stat` over a candidate list, for two
            // reasons. A helper can live anywhere on `PATH` — the device measured here has
            // `/sbin`, `/system/xbin`, `/vendor/bin`, `/vendor/xbin` and three apex dirs on
            // it — and a fixed list that misses it reports "no su" on a rooted phone. And a
            // `stat` is only honest when this process is on the target: the adb harness runs
            // on the machine *next to* the phone, where `Path::exists()` would be asking
            // about the wrong filesystem.
            //
            // Verified on that device: `command -v cat` echoes `/system/bin/cat` and exits 0,
            // `command -v su` prints nothing and exits 1, so exit code plus non-empty stdout
            // is a sound presence test — the same shape item 5a already relies on.
            ProbeCommand::SuPath => Cow::Borrowed("command -v su"),
            ProbeCommand::BashPath => Cow::Borrowed("command -v bash"),
            // NOT `/system/bin/sh --version`. Android's mksh is built without the version
            // option, and on a real device the attempt is an error rather than a banner —
            // measured on a Huawei BLA-AL00 (API 29): `/system/bin/sh: --: unknown option`,
            // exit 1. `$KSH_VERSION` is set unconditionally, and asking the platform shell
            // to echo it (rather than reading our own shell's variable) keeps the probe
            // about `/system/bin/sh` even when the runner is Termux's bash.
            //
            // Both dialects are echoed because exactly one will be non-empty, and an empty
            // answer is itself the evidence that the shell is neither mksh nor bash.
            ProbeCommand::SystemShVersion => Cow::Borrowed(
                "/system/bin/sh -c 'echo \"KSH=$KSH_VERSION\"; echo \"BASH=$BASH_VERSION\"'",
            ),
            ProbeCommand::ToyboxList => Cow::Borrowed("toybox"),
            ProbeCommand::BusyboxList => Cow::Borrowed("busybox --list"),
            // Item 6c. One spawn for the whole set, because the cost this probe is designed
            // around is process creation (android-host-probe.md §7.5 item 1: probing every
            // applet individually is "上百次子进程派生", unacceptable on a battery), and
            // over the adb harness each spawn is also a round trip. `command -v` is a shell
            // builtin, so the loop itself costs nothing.
            //
            // The marker prefix is not decoration: a login shell on the device can print
            // banner prose, and a parser that takes any line as data would read the banner
            // as a resolved path.
            ProbeCommand::SpotChecks => Cow::Owned(format!(
                "for n in {} ; do p=$(command -v \"$n\") ; rc=$? ; echo \"SPOT $n rc=$rc path=$p\" \
                 ; done",
                SPOT_CHECK_APPLETS.join(" ")
            )),
            ProbeCommand::MountTable => Cow::Borrowed("cat /proc/mounts"),
            ProbeCommand::SystemRemount => Cow::Borrowed("mount -o remount,rw /system"),
            ProbeCommand::PropBuildType => Cow::Borrowed("getprop ro.build.type"),
            ProbeCommand::PropDebuggable => Cow::Borrowed("getprop ro.debuggable"),
            ProbeCommand::PropSecure => Cow::Borrowed("getprop ro.secure"),
            ProbeCommand::PropAdbSecure => Cow::Borrowed("getprop ro.adb.secure"),
            ProbeCommand::PropVerityMode => Cow::Borrowed("getprop ro.boot.veritymode"),
            ProbeCommand::PropSdk => Cow::Borrowed("getprop ro.build.version.sdk"),
            ProbeCommand::PropAbi => Cow::Borrowed("getprop ro.product.cpu.abi"),
            // Four exit codes per path, and none of them depends on the wording of an error:
            // `ls` on a directory whose traverse is denied prints a message that varies by
            // toybox build, while its exit status does not. The same lesson `parse_su_probe`
            // had to learn the hard way, applied before the fact instead of after.
            ProbeCommand::EvidenceSurface => Cow::Owned(format!(
                "for p in {} ; do ls -d \"$p\" >/dev/null 2>&1 ; x=$? ; ls \"$p\" >/dev/null 2>&1 ; \
                 l=$? ; n=$(ls \"$p\" 2>/dev/null | wc -l) ; r=2 ; f=$(ls \"$p\" 2>/dev/null | head -n 1) ; \
                 if [ -n \"$f\" ] ; then head -n 1 \"$p/$f\" >/dev/null 2>&1 ; r=$? ; fi ; \
                 echo \"EVID $p exists=$x list=$l count=$n read=$r\" ; done",
                EVIDENCE_PATHS.join(" ")
            )),
            ProbeCommand::DumpsysInventory => Cow::Borrowed("dumpsys -l 2>/dev/null"),
        }
    }

    /// Commands that mutate device state and therefore must **not** run during a
    /// read-only probe.
    ///
    /// `mount -o remount,rw /system` is the only one, and it is the reason this
    /// predicate exists: android-host-probe.md §2 item 7 asks for a remount probe,
    /// but ADR-AND-001 §6 puts all write-tier behaviour in P3 behind approval and
    /// the DeviceWriteLock. Running a remount at startup on a P1 read-only build
    /// would violate the "先只读、后可写" ordering, so the runner is expected to
    /// skip it unless the write tier is enabled.
    pub fn is_mutating(&self) -> bool {
        matches!(self, ProbeCommand::SystemRemount)
    }

    /// The read-only probe set: everything except the mutating commands.
    ///
    /// This is the set a P1 read-only build runs.
    pub fn read_only_set() -> Vec<ProbeCommand> {
        all_commands()
            .into_iter()
            .filter(|c| !c.is_mutating())
            .collect()
    }
}

/// Every probe command, in the order android-host-probe.md §2 lists them.
pub fn all_commands() -> Vec<ProbeCommand> {
    vec![
        ProbeCommand::Id,
        ProbeCommand::GetEnforce,
        ProbeCommand::AttrCurrent,
        ProbeCommand::Su,
        ProbeCommand::SuPath,
        ProbeCommand::BashPath,
        ProbeCommand::SystemShVersion,
        ProbeCommand::ToyboxList,
        ProbeCommand::BusyboxList,
        ProbeCommand::SpotChecks,
        ProbeCommand::MountTable,
        ProbeCommand::SystemRemount,
        ProbeCommand::PropBuildType,
        ProbeCommand::PropDebuggable,
        ProbeCommand::PropSecure,
        ProbeCommand::PropAdbSecure,
        ProbeCommand::PropVerityMode,
        ProbeCommand::PropSdk,
        ProbeCommand::PropAbi,
        ProbeCommand::EvidenceSurface,
        ProbeCommand::DumpsysInventory,
    ]
}

/// The captured result of one probe command.
///
/// `exit_code` is `None` when the process was killed rather than exiting, which
/// is how a timeout is distinguished from a command that ran and failed. That
/// distinction matters: a failed `getenforce` means "unknown SELinux state",
/// while a timed-out one might mean "the device is slow", and the two should not
/// be conflated in diagnostics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandOutput {
    /// Captured standard output.
    pub stdout: String,
    /// Captured standard error.
    pub stderr: String,
    /// Exit status, or `None` when the process was killed rather than exiting.
    pub exit_code: Option<i32>,
    /// Whether the per-item timeout fired.
    pub timed_out: bool,
    /// Wall time the device took to answer, measured by the probe loop around the runner
    /// call. `None` means "not measured", which is a different fact from `Some(0)`.
    ///
    /// It exists because §3 states a budget ("< 2s for the whole probe") that nothing could
    /// otherwise check: the fixture recorded exit codes and timeouts but no durations, so
    /// "the budget was met" was an inference from "no item hit its deadline". Absence of a
    /// timeout is not evidence about total time — twenty items at 49 ms each never trip a
    /// 500 ms guard and still cost a second.
    #[serde(default)]
    pub duration_ms: Option<u64>,
}

impl CommandOutput {
    /// A command that ran and exited 0.
    pub fn ok(stdout: &str) -> CommandOutput {
        CommandOutput {
            stdout: stdout.to_string(),
            stderr: String::new(),
            exit_code: Some(0),
            timed_out: false,
            duration_ms: None,
        }
    }

    /// A command that ran and failed with the given stderr.
    pub fn failed(exit_code: i32, stderr: &str) -> CommandOutput {
        CommandOutput {
            stdout: String::new(),
            stderr: stderr.to_string(),
            exit_code: Some(exit_code),
            timed_out: false,
            duration_ms: None,
        }
    }

    /// A command that never produced a result: spawn failure or timeout.
    ///
    /// Per android-host-probe.md §2, a single item failing must not block the
    /// rest of the probe — it degrades to `Unknown`.
    pub fn unavailable(timed_out: bool) -> CommandOutput {
        CommandOutput {
            stdout: String::new(),
            stderr: String::new(),
            exit_code: None,
            timed_out,
            duration_ms: None,
        }
    }

    /// True when the command produced usable stdout.
    pub fn succeeded(&self) -> bool {
        self.exit_code == Some(0)
    }
}

/// Everything the probe measured, before interpretation.
///
/// A `None` field means "this command was not run or produced nothing", which the
/// parsers treat as `Unknown` — never as a negative answer. That asymmetry is
/// deliberate: concluding "no root" from "the su probe timed out" would be a
/// guess, and android-host-probe.md §4 forbids guessing.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeOutput {
    /// Item 1 — `id -u`.
    pub id: Option<CommandOutput>,
    /// Item 2 — `getenforce`.
    pub getenforce: Option<CommandOutput>,
    /// Item 3 — `/proc/self/attr/current`.
    pub attr_current: Option<CommandOutput>,
    /// Item 4 — the `su -c` escalation probe.
    pub su: Option<CommandOutput>,
    /// Item 4a — the resolved `su`, when the shell's `PATH` has one.
    pub su_path: Option<CommandOutput>,
    /// Item 5a — `command -v bash`.
    pub bash_path: Option<CommandOutput>,
    /// Item 5b — the dialect variables read out of `/system/bin/sh`.
    ///
    /// Not `--version`: on the device this was verified against, that is an error
    /// (`sh: --: unknown option`), so the version has to be read from mksh's own
    /// `$KSH_VERSION`. See `ProbeCommand::command()` for the exact script.
    pub system_sh_version: Option<CommandOutput>,
    /// Item 6a — the `toybox` applet listing.
    pub toybox_list: Option<CommandOutput>,
    /// Item 6b — `busybox --list`.
    pub busybox_list: Option<CommandOutput>,
    /// Spot-check results keyed by applet name.
    pub applet_spot_checks: BTreeMap<String, CommandOutput>,
    /// Item 7a — the mount table.
    pub mount_table: Option<CommandOutput>,
    /// Item 7b — the `/system` remount attempt (mutating; skipped on read-only builds).
    pub system_remount: Option<CommandOutput>,
    /// Item 8 — `ro.build.type`.
    pub prop_build_type: Option<CommandOutput>,
    /// Item 9 — `ro.debuggable`.
    pub prop_debuggable: Option<CommandOutput>,
    /// Item 9 — `ro.secure`.
    pub prop_secure: Option<CommandOutput>,
    /// Item 9 — `ro.adb.secure`.
    pub prop_adb_secure: Option<CommandOutput>,
    /// Item 10 — `ro.boot.veritymode`.
    pub prop_veritymode: Option<CommandOutput>,
    /// Item 11 — `ro.build.version.sdk`.
    pub prop_sdk: Option<CommandOutput>,
    /// Item 11 — `ro.product.cpu.abi`.
    pub prop_abi: Option<CommandOutput>,
    /// Item 13 — the `EVID` lines describing what this uid can collect from each evidence
    /// location: listed by name, readable, empty, or unreachable.
    pub evidence_surface: Option<CommandOutput>,
    /// Item 13b — `dumpsys -l`, the service inventory.
    pub dumpsys_inventory: Option<CommandOutput>,
    /// What each invocation cost, in the order the loop ran them.
    ///
    /// Kept beside the answers rather than inside them, because the two have different
    /// lifetimes: the spot-check batch is parsed into ten per-applet entries and the original
    /// `CommandOutput` is dropped, so a duration carried only on the output would vanish with
    /// it. A budget total that silently omits one of twenty round trips is not the number it
    /// says it is.
    #[serde(default)]
    pub costs: Vec<(ProbeCommand, u64)>,

    /// `$PREFIX`, when set and reachable — the Termux marker.
    pub termux_prefix: Option<String>,
    /// Item 12. Produced by the runner rather than parsed from text, because
    /// reachability and writability are established by syscalls (`touch`), not by
    /// reading a listing.
    pub fs_roots: Vec<FsRoot>,
}

impl ProbeOutput {
    /// An empty result set: nothing ran. Assembles to `ApkSandbox`.
    pub fn nothing_ran() -> ProbeOutput {
        ProbeOutput::default()
    }

    /// Total device time the probe's command loop waited.
    ///
    /// `None` when nothing was timed — which is what a fixture captured before durations
    /// existed reports. The field is `Option` for that reason: "0 ms" and "we did not measure"
    /// are different claims, and only one of them can be checked.
    ///
    /// Deliberately narrower than "how long the probe took": it covers the serial command
    /// loop, not the up-front `$PREFIX` read or the `fs_roots` write probes, which are
    /// separate runner calls that never pass through this loop.
    pub fn total_duration_ms(&self) -> Option<u64> {
        (!self.costs.is_empty()).then(|| self.costs.iter().map(|(_, ms)| *ms).sum())
    }

    /// The slowest single invocation, in milliseconds.
    ///
    /// Kept separate from the total because the two answer different questions and §3's
    /// budget conflates them: a per-item deadline catches a device that hangs on one command
    /// and says nothing about twenty commands that are each fine and together slow.
    pub fn slowest_item_ms(&self) -> Option<u64> {
        self.costs.iter().map(|(_, ms)| *ms).max()
    }

    /// True when not a single probe command produced output.
    pub fn is_empty(&self) -> bool {
        self.id.is_none()
            && self.getenforce.is_none()
            && self.attr_current.is_none()
            && self.su.is_none()
            && self.bash_path.is_none()
            && self.system_sh_version.is_none()
            && self.toybox_list.is_none()
            && self.busybox_list.is_none()
            && self.mount_table.is_none()
            && self.prop_build_type.is_none()
            && self.evidence_surface.is_none()
            && self.dumpsys_inventory.is_none()
    }
}

/// The platform-specific executor.
///
/// Two implementations are expected (ADR-AND-001 §4.2): one that spawns through
/// the Termux environment, and one for the APK sandbox where process spawning is
/// unavailable and every call returns [`CommandOutput::unavailable`]. The latter
/// is not a degenerate stub — it is how the APK profile honestly reports "I could
/// not measure this", which is what makes the fallback to `ApkSandbox` a
/// conclusion rather than an assumption.
///
/// Implementations must honour [`PROBE_ITEM_TIMEOUT`] per command. The total
/// budget is the caller's concern, since only the caller knows how many commands
/// it asked for.
#[async_trait::async_trait]
pub trait ProbeRunner: Send + Sync {
    /// Run one probe command and capture its output.
    ///
    /// Must not return `Err` for a command that simply failed or was missing —
    /// that is a normal, expected outcome and belongs in the returned
    /// [`CommandOutput`]. `Err` is reserved for the runner itself being unable to
    /// operate at all.
    async fn run(&self, command: ProbeCommand) -> Result<CommandOutput, ProbeError>;

    /// Discover reachable filesystem roots (probe item 12).
    ///
    /// Separate from [`ProbeRunner::run`] because it is syscall-based rather than
    /// command-based, and because on the APK profile it is the *only* probe that
    /// can produce a real answer.
    async fn discover_fs_roots(&self, own_package: &str) -> Result<Vec<FsRoot>, ProbeError>;

    /// The value of `$PREFIX`, when this environment has one.
    fn termux_prefix(&self) -> Option<String>;
}

/// A runner-level failure, as opposed to a command that ran and failed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProbeError {
    /// The runner cannot spawn processes at all (the APK sandbox case).
    SpawningUnsupported,
    /// The runner itself broke (I/O error, interrupted, ...).
    Runner(String),
}

impl std::fmt::Display for ProbeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProbeError::SpawningUnsupported => {
                write!(
                    f,
                    "this host cannot spawn processes; probing is unavailable"
                )
            }
            ProbeError::Runner(detail) => write!(f, "probe runner failed: {detail}"),
        }
    }
}

impl std::error::Error for ProbeError {}

/// Drive a runner across a command set and collect the results.
///
/// This is the reusable middleware between the platform runner and the parsers:
/// it owns routing (which output lands in which `ProbeOutput` field) and the
/// degradation rule (a failed or missing command becomes `None`, never a panic
/// and never a guessed value).
///
/// Commands are issued serially, matching the budget model in
/// android-host-probe.md §2. Parallelising would shorten wall-clock time but
/// would also spike CPU on a phone at startup, and the two-second budget is
/// already met serially.
pub async fn run_probe(
    runner: &dyn ProbeRunner,
    commands: &[ProbeCommand],
    own_package: &str,
) -> ProbeOutput {
    let mut output = ProbeOutput::default();

    for command in commands {
        // A runner that cannot operate yields `None` for every command, which the
        // parsers read as Unknown. That is the honest outcome, so the error is
        // deliberately dropped rather than propagated.
        //
        // Timed around the runner rather than inside it, so the number means the same thing
        // for adb, for a device-side runner, and for the in-memory test double: how long the
        // probe loop waited.
        let started = Instant::now();
        let result = runner.run(*command).await.ok();
        // One measurement, recorded twice: on the answer, for a caller displaying a single
        // item, and in the ledger, which is what the budget is computed from. The ledger has
        // to exist because `route` parses the spot-check batch into per-applet entries and
        // drops the original answer — and it records the call even when there is no answer
        // at all, since a command that hung and was killed still spent the time it spent. A
        // budget that counted only successes would be flattered by the device's failures.
        let ms = started.elapsed().as_millis() as u64;
        let result = result.map(|mut out| {
            out.duration_ms = Some(ms);
            out
        });
        output.costs.push((*command, ms));
        route(&mut output, *command, result);
    }

    output.termux_prefix = runner.termux_prefix();
    output.fs_roots = runner
        .discover_fs_roots(own_package)
        .await
        .unwrap_or_default();
    output
}

/// Parse item 6c's `SPOT <name> rc=<n> path=<p>` lines into per-command results.
///
/// Three rules keep this from inventing facts:
///
/// - Only names in [`SPOT_CHECK_APPLETS`] are accepted. Banner prose, a shell warning, or a
///   device that echoes the loop back would otherwise become evidence about a command nobody
///   asked about.
/// - A name that never appears gets **no** entry. Missing from the output means the answer
///   was lost — truncated buffer, a shell that broke out of the loop — which is *unknown*,
///   not *absent*. Collapsing those two is how a device with `logcat` ends up reported as a
///   device without it.
/// - The recorded exit code is the one the device reported for that `command -v`, not a
///   synthesised one, so [`CommandOutput::succeeded`] means the same thing here as it does
///   for every other probe item.
pub fn parse_spot_checks(stdout: &str) -> BTreeMap<String, CommandOutput> {
    let mut checks = BTreeMap::new();
    for line in stdout.lines() {
        let Some(body) = line.trim().strip_prefix("SPOT ") else {
            continue;
        };
        let Some((name, rest)) = body.split_once(" rc=") else {
            continue;
        };
        if !SPOT_CHECK_APPLETS.contains(&name) {
            continue;
        }
        let Some((rc_text, path)) = rest.split_once(" path=") else {
            continue;
        };
        let Ok(exit_code) = rc_text.trim().parse::<i32>() else {
            // Shaped like our own output but carrying something that is not an exit status.
            // Record "no evidence" rather than choosing which way to guess.
            checks.insert(name.to_string(), CommandOutput::unavailable(false));
            continue;
        };
        let output = if exit_code == 0 {
            CommandOutput::ok(path.trim())
        } else {
            CommandOutput::failed(exit_code, "")
        };
        checks.insert(name.to_string(), output);
    }
    checks
}

/// Place one command's output into the right `ProbeOutput` field.
fn route(output: &mut ProbeOutput, command: ProbeCommand, result: Option<CommandOutput>) {
    match command {
        ProbeCommand::Id => output.id = result,
        ProbeCommand::GetEnforce => output.getenforce = result,
        ProbeCommand::AttrCurrent => output.attr_current = result,
        ProbeCommand::Su => output.su = result,
        ProbeCommand::SuPath => output.su_path = result,
        ProbeCommand::BashPath => output.bash_path = result,
        ProbeCommand::SystemShVersion => output.system_sh_version = result,
        ProbeCommand::ToyboxList => output.toybox_list = result,
        ProbeCommand::BusyboxList => output.busybox_list = result,
        ProbeCommand::SpotChecks => {
            output.applet_spot_checks = match result {
                Some(out) if out.succeeded() => parse_spot_checks(&out.stdout),
                // No shell, a failed loop, a timeout: no evidence either way. Leaving the map
                // empty is the honest outcome — an entry claiming "absent" would be a claim
                // about the device that nothing observed.
                _ => BTreeMap::new(),
            };
        }
        ProbeCommand::MountTable => output.mount_table = result,
        ProbeCommand::SystemRemount => output.system_remount = result,
        ProbeCommand::PropBuildType => output.prop_build_type = result,
        ProbeCommand::PropDebuggable => output.prop_debuggable = result,
        ProbeCommand::PropSecure => output.prop_secure = result,
        ProbeCommand::PropAdbSecure => output.prop_adb_secure = result,
        ProbeCommand::PropVerityMode => output.prop_veritymode = result,
        ProbeCommand::PropSdk => output.prop_sdk = result,
        ProbeCommand::PropAbi => output.prop_abi = result,
        ProbeCommand::EvidenceSurface => output.evidence_surface = result,
        ProbeCommand::DumpsysInventory => output.dumpsys_inventory = result,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_command_has_a_non_empty_command_line() {
        for command in all_commands() {
            assert!(
                !command.command_line().trim().is_empty(),
                "{command:?} has no command line"
            );
        }
    }

    #[test]
    fn command_lines_are_unique() {
        let mut seen = std::collections::BTreeSet::new();
        for command in all_commands() {
            assert!(
                seen.insert(command.command_line()),
                "duplicate command line for {command:?}"
            );
        }
    }

    #[test]
    fn read_only_set_excludes_every_mutating_command() {
        let set = ProbeCommand::read_only_set();
        assert!(!set.contains(&ProbeCommand::SystemRemount));
        assert!(set.contains(&ProbeCommand::MountTable));
        assert_eq!(set.len(), all_commands().len() - 1);
        for command in &set {
            assert!(!command.is_mutating());
        }
    }

    #[test]
    fn su_probe_uses_su_dash_c_per_the_magisk_only_ruling() {
        // ADR-AND-001 §7.5 item 3: first version supports MagiskSU syntax only.
        assert!(ProbeCommand::Su.command_line().starts_with("su -c "));
    }

    #[test]
    fn mount_probe_reads_procfs_so_a_missing_applet_degrades_cleanly() {
        // `mount` is an applet and can be absent; /proc/mounts always exists.
        assert_eq!(ProbeCommand::MountTable.command_line(), "cat /proc/mounts");
    }

    #[test]
    fn spot_check_list_is_capped_and_justified() {
        // android-host-probe.md §7.5 item 1 caps this list — originally at 10, raised to 12
        // when `bugreportz` was added. The cap bounds how many claims the port makes about
        // devices in general, not the spawn cost: item 6c runs every name in one shell
        // invocation, and `command -v` is a builtin.
        //
        // Raising a cap is the kind of change that should cost its author an argument, so
        // the rule is stated here rather than in a comment somewhere else: a name belongs on
        // this list if (a) the §4.4 vocabulary or the §4.6 item 6 evidence list uses it, and
        // (b) no other probe item already proves it. `mount` failed (b) and left; `ps` and
        // `setprop` pass (a) and stay even though the listing does name them, because the
        // listing is a dispatcher's self-report while `command -v` asks the filesystem.
        assert!(
            SPOT_CHECK_APPLETS.len() <= 12,
            "grown past what the ruling bounds; justify it in android-host-probe.md §8 first"
        );
        assert!(SPOT_CHECK_APPLETS.contains(&"logcat"));
        assert!(SPOT_CHECK_APPLETS.contains(&"screencap"));
        assert!(SPOT_CHECK_APPLETS.contains(&"bugreportz"));
    }

    #[test]
    fn the_evidence_probe_walks_every_source_the_adr_names_in_one_invocation() {
        // One spawn, three sources, four exit codes each. The batching is the same argument
        // as the spot checks: twelve round trips at startup on a phone battery, for a
        // question a single `for` loop answers.
        let line = ProbeCommand::EvidenceSurface.command_line();
        assert_eq!(line.matches("for p in ").count(), 1);
        for path in EVIDENCE_PATHS {
            assert!(line.contains(path), "{path} is not probed: {line}");
        }
        assert_eq!(
            line.matches("EVID $p exists=").count(),
            1,
            "each source must be reported once, in one echo"
        );
        // The classification reads exit codes only. If the script ever starts depending on
        // the text of an `ls` error, this probe becomes device-version dependent.
        assert!(
            !line.contains("Permission") && !line.contains("denied"),
            "the evidence probe must not classify on error wording: {line}"
        );
    }

    #[test]
    fn the_evidence_path_list_and_the_typed_source_list_agree() {
        // The probe script asks with strings and the parser answers with an enum. Those two
        // drift independently, and when they do, a source silently stops being reported —
        // the profile says `NotProbed` for a directory the device was in fact asked about.
        use crate::host::facts::EvidencePath;
        let typed: Vec<&str> = EvidencePath::ALL.iter().map(|p| p.path()).collect();
        assert_eq!(typed, EVIDENCE_PATHS.to_vec());
    }

    #[test]
    fn the_dumpsys_inventory_probe_asks_for_the_list_not_a_dump() {
        // `dumpsys` with no service argument dumps *everything*, which on this device is
        // megabytes and seconds. The inventory probe must be the `-l` form only.
        let line = ProbeCommand::DumpsysInventory.command_line();
        assert_eq!(line, "dumpsys -l 2>/dev/null");
    }

    #[test]
    fn the_spot_check_asks_for_every_name_in_one_invocation() {
        // The whole point of batching: probing each name as its own command would be one
        // spawn per name, and over the adb harness that is a dozen round trips at startup on
        // a battery. `command -v` is a builtin, so the loop itself is free.
        let line = ProbeCommand::SpotChecks.command_line();
        assert_eq!(line.matches("command -v").count(), 1);
        assert_eq!(line.matches("for n in ").count(), 1);
        for name in SPOT_CHECK_APPLETS {
            assert!(
                line.contains(&format!(" {name} "))
                    || line.starts_with(&format!("for n in {name} ")),
                "{name} is not in the spot-check list: {line}"
            );
        }
    }

    #[test]
    fn spot_checks_confirm_the_commands_an_applet_listing_cannot_see() {
        // Verbatim from a Huawei BLA-AL00 (API 29) through `adb shell`. Nine of these eleven
        // names do not appear anywhere in that device's 194-name `toybox` listing, because
        // they are standalone `/system/bin` binaries rather than applets. A profile built
        // from the listing alone reports the entire read surface as absent.
        let device_output = "\
SPOT logcat rc=0 path=/system/bin/logcat
SPOT dumpsys rc=0 path=/system/bin/dumpsys
SPOT getprop rc=0 path=/system/bin/getprop
SPOT setprop rc=0 path=/system/bin/setprop
SPOT am rc=0 path=/system/bin/am
SPOT pm rc=0 path=/system/bin/pm
SPOT input rc=0 path=/system/bin/input
SPOT screencap rc=0 path=/system/bin/screencap
SPOT settings rc=0 path=/system/bin/settings
SPOT ps rc=0 path=/system/bin/ps
SPOT bugreportz rc=0 path=/system/bin/bugreportz
";
        let checks = parse_spot_checks(device_output);
        assert_eq!(checks.len(), SPOT_CHECK_APPLETS.len());
        for (name, out) in &checks {
            assert!(
                out.succeeded(),
                "{name} reported present but not successful"
            );
            assert_eq!(out.stdout, format!("/system/bin/{name}"));
        }
    }

    #[test]
    fn a_measured_absence_is_recorded_and_is_not_the_same_as_no_answer() {
        // `command -v` exits non-zero and prints nothing when the name is not on the PATH:
        // that is an observed fact about the device, so it gets an entry whose `succeeded()`
        // is false. A name with no line at all gets no entry (next test).
        let checks =
            parse_spot_checks("SPOT am rc=1 path=\nSPOT logcat rc=0 path=/system/bin/logcat\n");
        let am = &checks["am"];
        assert_eq!(am.exit_code, Some(1), "the device's own status is recorded");
        assert!(am.stdout.is_empty());
        assert!(!am.succeeded());
        assert!(checks["logcat"].succeeded());
    }

    #[test]
    fn answers_about_commands_nobody_asked_about_are_dropped() {
        // `su` is not on the capped list. Accepting its line would let a device's output
        // populate a claim the probe never made, and the claim would look measured.
        let checks = parse_spot_checks("SPOT su rc=0 path=/system/xbin/su\n");
        assert!(
            checks.is_empty(),
            "the parser must not accept answers about commands it did not ask about"
        );
    }

    #[test]
    fn a_name_that_never_answered_is_unknown_rather_than_absent() {
        // Truncated output, or a shell that broke out of the loop, loses answers. Reading
        // that as "this device does not have dumpsys" is the failure mode that made the
        // fabricated fixtures more confident than the real device ever was.
        let checks = parse_spot_checks("SPOT logcat rc=0 path=/system/bin/logcat\n");
        assert!(checks.contains_key("logcat"));
        assert!(
            !checks.contains_key("dumpsys"),
            "no line means no evidence — not a claim of absence"
        );
    }

    #[test]
    fn shell_noise_is_not_evidence_about_a_command() {
        // A login shell can print prose. Lines that are not ours are dropped, and a line
        // that looks like ours but carries a non-numeric status is recorded as no evidence
        // rather than guessed at.
        let checks = parse_spot_checks(
            "WARNING: shell noise\n\
             logcat: something\n\
             SPOT logcat rc=ok path=/system/bin/logcat\n\
             SPOT settings rc=0 path=/system/bin/settings\n",
        );
        assert_eq!(checks.len(), 2);
        assert!(!checks["logcat"].succeeded());
        assert!(
            checks["logcat"].exit_code.is_none(),
            "unparseable status = no result"
        );
        assert!(checks["settings"].succeeded());
    }

    #[test]
    fn budgets_match_the_spec() {
        assert_eq!(PROBE_ITEM_TIMEOUT, Duration::from_millis(500));
        assert_eq!(PROBE_TOTAL_BUDGET, Duration::from_secs(2));
        assert!(PROBE_ITEM_TIMEOUT < PROBE_TOTAL_BUDGET);
    }

    #[test]
    fn timeout_is_distinguishable_from_a_nonzero_exit() {
        let timed_out = CommandOutput::unavailable(true);
        assert!(timed_out.timed_out);
        assert_eq!(timed_out.exit_code, None);

        let failed = CommandOutput::failed(1, "getenforce: not found");
        assert!(!failed.timed_out);
        assert_eq!(failed.exit_code, Some(1));
        assert!(!failed.succeeded());
    }

    #[test]
    fn empty_probe_output_reports_itself_empty() {
        assert!(ProbeOutput::nothing_ran().is_empty());
        let ran = ProbeOutput {
            id: Some(CommandOutput::ok("0")),
            ..ProbeOutput::default()
        };
        assert!(!ran.is_empty());
    }

    /// A runner that cannot spawn at all — the APK sandbox shape.
    struct NoSpawnRunner;

    #[async_trait::async_trait]
    impl ProbeRunner for NoSpawnRunner {
        async fn run(&self, _command: ProbeCommand) -> Result<CommandOutput, ProbeError> {
            Err(ProbeError::SpawningUnsupported)
        }

        async fn discover_fs_roots(&self, own_package: &str) -> Result<Vec<FsRoot>, ProbeError> {
            Ok(vec![FsRoot {
                path: format!("/data/data/{own_package}"),
                writable: true,
                own_package: true,
            }])
        }

        fn termux_prefix(&self) -> Option<String> {
            None
        }
    }

    #[tokio::test]
    async fn a_runner_that_cannot_spawn_yields_an_empty_probe_not_an_error() {
        let output = run_probe(
            &NoSpawnRunner,
            &ProbeCommand::read_only_set(),
            "com.example.agent",
        )
        .await;

        assert!(output.id.is_none());
        assert!(output.getenforce.is_none());
        // Item 12 still answers, because it is syscall-based rather than
        // command-based — this is the one thing an APK can genuinely measure.
        assert_eq!(output.fs_roots.len(), 1);
        assert!(output.fs_roots[0].own_package);
        assert!(output.termux_prefix.is_none());
    }

    /// A runner driven by a fixed table, for exercising the routing logic.
    struct TableRunner {
        table: BTreeMap<ProbeCommand, CommandOutput>,
    }
    #[async_trait::async_trait]
    impl ProbeRunner for TableRunner {
        async fn run(&self, command: ProbeCommand) -> Result<CommandOutput, ProbeError> {
            self.table
                .get(&command)
                .cloned()
                .ok_or(ProbeError::Runner("not in table".to_string()))
        }

        async fn discover_fs_roots(&self, _own_package: &str) -> Result<Vec<FsRoot>, ProbeError> {
            Ok(vec![])
        }

        fn termux_prefix(&self) -> Option<String> {
            Some("/data/data/com.termux/files/usr".to_string())
        }
    }

    #[tokio::test]
    async fn routing_lands_each_output_in_its_own_field() {
        let mut table = BTreeMap::new();
        table.insert(ProbeCommand::Id, CommandOutput::ok("10233"));
        table.insert(ProbeCommand::GetEnforce, CommandOutput::ok("Enforcing"));
        table.insert(ProbeCommand::PropSdk, CommandOutput::ok("34"));

        let output = run_probe(
            &TableRunner { table },
            &[
                ProbeCommand::Id,
                ProbeCommand::GetEnforce,
                ProbeCommand::PropSdk,
                // Not in the table: the runner errors, and routing must record
                // that as None rather than propagating the failure.
                ProbeCommand::PropAbi,
            ],
            "com.example.agent",
        )
        .await;

        assert_eq!(output.id.unwrap().stdout, "10233");
        assert_eq!(output.getenforce.unwrap().stdout, "Enforcing");
        assert_eq!(output.prop_sdk.unwrap().stdout, "34");
        assert!(output.prop_abi.is_none());
        assert_eq!(
            output.termux_prefix.as_deref(),
            Some("/data/data/com.termux/files/usr")
        );
    }

    #[tokio::test]
    async fn every_invocation_is_costed_including_the_ones_that_never_answered() {
        // The ledger is what the §3 budget is computed from, so it has to count the calls the
        // device failed to answer. A total over successes only would be flattered by a bad
        // link: the hung and killed commands are precisely the expensive ones.
        let table = [(ProbeCommand::Id, CommandOutput::ok("2000"))]
            .into_iter()
            .collect();
        let runner = TableRunner { table };
        let commands = [ProbeCommand::Id, ProbeCommand::GetEnforce, ProbeCommand::Su];
        let output = run_probe(&runner, &commands, "com.example.agent").await;

        assert_eq!(output.costs.len(), 3, "one entry per invocation attempted");
        assert!(output.getenforce.is_none() && output.su.is_none());
        // `None`, not `Some(0)`, when nothing was timed — and here something was.
        assert!(output.total_duration_ms().is_some());
        assert!(output.slowest_item_ms().is_some());
    }

    #[test]
    fn a_probe_with_no_ledger_reports_no_duration_rather_than_zero() {
        // A fixture captured before durations existed must read as "not measured". Calling
        // that "0 ms" would turn an absence of evidence into evidence of speed, which is the
        // exact mistake §3's budget line used to make.
        let probe = ProbeOutput::nothing_ran();
        assert_eq!(probe.total_duration_ms(), None);
        assert_eq!(probe.slowest_item_ms(), None);

        let probe = ProbeOutput {
            costs: vec![(ProbeCommand::Id, 0), (ProbeCommand::Su, 7)],
            ..ProbeOutput::nothing_ran()
        };
        assert_eq!(probe.total_duration_ms(), Some(7));
        assert_eq!(probe.slowest_item_ms(), Some(7));
    }

    #[test]
    fn an_empty_cost_is_still_a_measurement() {
        // The distinction the `Option` exists for: `Some(0)` means we timed it and it was
        // instant, `None` means nobody looked. Both must be expressible.
        let probe = ProbeOutput {
            costs: vec![(ProbeCommand::Id, 0)],
            ..ProbeOutput::nothing_ran()
        };
        assert_eq!(probe.total_duration_ms(), Some(0));
    }
}
