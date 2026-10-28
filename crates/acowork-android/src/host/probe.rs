//! The probe contract: which commands run, what they cost, and how the raw
//! output is carried to the parsers.
//!
//! # Separation of concerns
//!
//! This module owns **what to ask** and **what came back**. It does not own
//! spawning (that is the platform runner, [`ProbeRunner`]) and it does not own
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

use std::collections::BTreeMap;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::host::facts::FsRoot;

/// Per-item probe timeout (android-host-probe.md §2).
pub const PROBE_ITEM_TIMEOUT: Duration = Duration::from_millis(500);

/// Whole-probe budget. Exceeding it is a bug, not a degradation.
pub const PROBE_TOTAL_BUDGET: Duration = Duration::from_secs(2);

/// The high-value commands spot-checked with `command -v`.
///
/// android-host-probe.md §7.5 item 1 caps this at ten, because each check is a
/// process spawn and hundreds of spawns at startup is not acceptable on a mobile
/// device. These ten are the ones the Android debugging toolset
/// (ADR-AND-001 §4.6 item 6) and the write tier actually invoke.
pub const SPOT_CHECK_APPLETS: [&str; 10] = [
    "logcat",
    "dumpsys",
    "getprop",
    "setprop",
    "am",
    "pm",
    "input",
    "screencap",
    "mount",
    "ps",
];

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
    /// Item 5a — `command -v bash`.
    BashPath,
    /// Item 5b — ask `/system/bin/sh` which dialect it is, by having it run a script.
    SystemShVersion,
    /// Item 6a — the `toybox` applet listing.
    ToyboxList,
    /// Item 6b — `busybox --list`.
    BusyboxList,
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
    pub fn command_line(&self) -> &'static str {
        match self {
            ProbeCommand::Id => "id -u",
            ProbeCommand::GetEnforce => "getenforce",
            ProbeCommand::AttrCurrent => "cat /proc/self/attr/current",
            ProbeCommand::Su => "su -c 'id -u; cat /proc/self/attr/current'",
            ProbeCommand::BashPath => "command -v bash",
            // NOT `/system/bin/sh --version`. Android's mksh is built without the version
            // option, and on a real device the attempt is an error rather than a banner —
            // measured on a Huawei BLA-AL00 (API 29): `/system/bin/sh: --: unknown option`,
            // exit 1. `$KSH_VERSION` is set unconditionally, and asking the platform shell
            // to echo it (rather than reading our own shell's variable) keeps the probe
            // about `/system/bin/sh` even when the runner is Termux's bash.
            //
            // Both dialects are echoed because exactly one will be non-empty, and an empty
            // answer is itself the evidence that the shell is neither mksh nor bash.
            ProbeCommand::SystemShVersion => {
                "/system/bin/sh -c 'echo \"KSH=$KSH_VERSION\"; echo \"BASH=$BASH_VERSION\"'"
            }
            ProbeCommand::ToyboxList => "toybox",
            ProbeCommand::BusyboxList => "busybox --list",
            ProbeCommand::MountTable => "cat /proc/mounts",
            ProbeCommand::SystemRemount => "mount -o remount,rw /system",
            ProbeCommand::PropBuildType => "getprop ro.build.type",
            ProbeCommand::PropDebuggable => "getprop ro.debuggable",
            ProbeCommand::PropSecure => "getprop ro.secure",
            ProbeCommand::PropAdbSecure => "getprop ro.adb.secure",
            ProbeCommand::PropVerityMode => "getprop ro.boot.veritymode",
            ProbeCommand::PropSdk => "getprop ro.build.version.sdk",
            ProbeCommand::PropAbi => "getprop ro.product.cpu.abi",
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
        ProbeCommand::BashPath,
        ProbeCommand::SystemShVersion,
        ProbeCommand::ToyboxList,
        ProbeCommand::BusyboxList,
        ProbeCommand::MountTable,
        ProbeCommand::SystemRemount,
        ProbeCommand::PropBuildType,
        ProbeCommand::PropDebuggable,
        ProbeCommand::PropSecure,
        ProbeCommand::PropAdbSecure,
        ProbeCommand::PropVerityMode,
        ProbeCommand::PropSdk,
        ProbeCommand::PropAbi,
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
}

impl CommandOutput {
    /// A command that ran and exited 0.
    pub fn ok(stdout: &str) -> CommandOutput {
        CommandOutput {
            stdout: stdout.to_string(),
            stderr: String::new(),
            exit_code: Some(0),
            timed_out: false,
        }
    }

    /// A command that ran and failed with the given stderr.
    pub fn failed(exit_code: i32, stderr: &str) -> CommandOutput {
        CommandOutput {
            stdout: String::new(),
            stderr: stderr.to_string(),
            exit_code: Some(exit_code),
            timed_out: false,
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
    /// Item 5a — `command -v bash`.
    pub bash_path: Option<CommandOutput>,
    /// Item 5b — `/system/bin/sh --version`.
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
        let result = runner.run(*command).await.ok();
        route(&mut output, *command, result);
    }

    output.termux_prefix = runner.termux_prefix();
    output.fs_roots = runner
        .discover_fs_roots(own_package)
        .await
        .unwrap_or_default();
    output
}

/// Place one command's output into the right `ProbeOutput` field.
fn route(output: &mut ProbeOutput, command: ProbeCommand, result: Option<CommandOutput>) {
    match command {
        ProbeCommand::Id => output.id = result,
        ProbeCommand::GetEnforce => output.getenforce = result,
        ProbeCommand::AttrCurrent => output.attr_current = result,
        ProbeCommand::Su => output.su = result,
        ProbeCommand::BashPath => output.bash_path = result,
        ProbeCommand::SystemShVersion => output.system_sh_version = result,
        ProbeCommand::ToyboxList => output.toybox_list = result,
        ProbeCommand::BusyboxList => output.busybox_list = result,
        ProbeCommand::MountTable => output.mount_table = result,
        ProbeCommand::SystemRemount => output.system_remount = result,
        ProbeCommand::PropBuildType => output.prop_build_type = result,
        ProbeCommand::PropDebuggable => output.prop_debuggable = result,
        ProbeCommand::PropSecure => output.prop_secure = result,
        ProbeCommand::PropAdbSecure => output.prop_adb_secure = result,
        ProbeCommand::PropVerityMode => output.prop_veritymode = result,
        ProbeCommand::PropSdk => output.prop_sdk = result,
        ProbeCommand::PropAbi => output.prop_abi = result,
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
    fn spot_check_list_is_capped_at_ten() {
        // android-host-probe.md §7.5 item 1: at most ten, because each is a spawn.
        assert!(SPOT_CHECK_APPLETS.len() <= 10);
        assert!(SPOT_CHECK_APPLETS.contains(&"logcat"));
        assert!(SPOT_CHECK_APPLETS.contains(&"screencap"));
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
}
