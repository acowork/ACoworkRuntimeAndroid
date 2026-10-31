//! The backends that start a process.
//!
//! [`super::backend`] defines the contract and the gate that guards it; this module holds the
//! implementations that turn an [`ExecRequest`] into a running shell. The three profile tiers
//! of ADR-AND-001 §4.2 each get one: [`ShellBackend`] (app uid, no escalation),
//! [`RootShellBackend`] (uid 0 behind `su`), and [`AppSandboxBackend`] — a backend whose only
//! honest answer is that there is no shell here.
//!
//! # What a backend is allowed to decide
//!
//! Nothing about **authorisation**. By the time [`ExecutionBackend::exec`] is called the gate
//! has already run, and a backend that re-decided registration, approval, reversibility or
//! attribution would be a second copy of a rule — two copies drift, which is how a port ends
//! up with a check that passes on one path and fails on the other.
//!
//! There is one thing a backend decides that looks like permission from the outside, and it
//! is not a second copy because the gate cannot evaluate it at all: whether the script's
//! *content* matches the capability the caller labelled it with. Contract rule R12 keeps
//! script text out of the envelope the gate sees, so the gate is handed `android:shell:read`
//! as an assertion about the commands and has no way to test it. ADR-AND-001 §4.4 auto-passes
//! that tier precisely because those commands cannot change the device, so the assertion is
//! the whole of the safety argument, and [`check`](super::commands) is where
//! it stops being taken on trust. It runs in `run_script`, the one path every shell backend
//! takes, before anything is assembled or spawned.
//!
//! What a backend *also* decides is everything else the gate cannot know:
//!
//! - which binary to exec, and with what arguments;
//! - what environment a cleared process starts with;
//! - how to ask for privilege, and **whether the privilege asked for was actually granted**;
//! - how to turn raw bytes into an [`ExecRecord`].
//!
//! The third item is the only place in the crate where a privilege claim is verified rather
//! than assumed, and it is why [`RootShellBackend`] refuses a run whose observed uid is not 0
//! instead of returning a record that would let the caller infer success from an exit code.
//!
//! # Why the base environment is the backend's, not the request's
//!
//! [`super::spawn`] clears the child's environment, so *something* has to supply `PATH` or the
//! shell cannot find `id` and the identity probe reports nothing. That cannot be the caller's
//! job: a request that supplied its own `PATH` could point `id` at a script that prints `0`,
//! which would forge the very proof this module exists to obtain. So the base environment is
//! owned by the backend, and [`ExecRequest::env`] is layered on top of it *inside the script*
//! as `export` lines — which reach the body, and never the prologue.
//!
//! # Unverified about this module
//!
//! The `su` command-line (`-c` versus `su 0`, and whether `su` forwards stdin to the shell it
//! spawns) and the denial-wording list in `super::facts::su_prompt_denied` are both taken
//! from documentation and memory, not from a device. Neither is confirmed by anything here:
//! every test in this module uses a scripted runner, which cannot tell a correct guess from a
//! wrong one. They are the first two things the device harness has to settle.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use acowork_platform_contract::Budget;
use async_trait::async_trait;

use super::backend::{BackendError, ExecRecord, ExecRequest, ExecutionBackend};
use super::commands;
use super::denial::parse_denials;
use super::facts::{ShellDialect, su_helper_missing, su_prompt_denied};
use super::profile::HostProfile;
use super::script::{self, extract_identity};
use super::spawn::{ProcessSpawnRunner, RawOutput, SpawnError, SpawnInvocation, SpawnRunner};

/// The directory a privileged shell starts in.
///
/// Conventional because it is writable by both `shell` and root on every Android version.
/// Whether it is writable *on this device* is a probed fact ([`HostProfile::fs_roots`]) that
/// nothing here consults yet — a backend that could not write its `HOME` would fail in ways
/// that look like a broken command rather than a broken assumption. Recorded as a
/// device-harness item.
const ROOT_HOME: &str = "/data/local/tmp";

/// Build a [`BTreeMap`] from literal pairs, because a map has no literal and the alternative
/// — six `insert` calls per environment — hides what is being set.
fn env_map(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect()
}

/// Scratch directories, in preference order, for a shell that has no Termux prefix.
///
/// `HOME` and `TMPDIR` have to come from somewhere once the child's environment is cleared,
/// and the only honest source is the list of roots the probe *measured* writable by an actual
/// `touch` (item 12). `/data/local/tmp` leads because it is the one directory the adb-shell
/// tier reliably owns; `/sdcard` is FUSE and will not hold a socket or an executable, so it is
/// deliberately absent.
const SCRATCH_PREFERENCE: &[&str] = &["/data/local/tmp"];

/// Pick the scratch directory from measured facts, or `None` when nothing was proven writable.
fn scratch_dir(profile: &HostProfile) -> Option<&'static str> {
    SCRATCH_PREFERENCE
        .iter()
        .find(|want| {
            profile
                .fs_roots
                .iter()
                .any(|r| r.writable && !r.own_package && r.path == **want)
        })
        .copied()
}

/// The environment for an unprivileged shell.
///
/// # Nothing here is guessed
///
/// `PREFIX` is set **only when the device reported one**. It used to fall back to the stock
/// Termux path, which is a fabrication with consequences: `$PREFIX` is the marker that
/// distinguishes a Termux host from any other shell host, so inventing it makes a script that
/// checks `$PREFIX` — Termux's own scripts do — conclude it is inside Termux on a device that
/// has never had it installed, and then look for data under a directory that does not exist.
/// The backend was forging the very fact the profile was built to record.
///
/// `HOME` and `TMPDIR` come from [`scratch_dir`], i.e. from a root the probe wrote to. When
/// nothing was proven writable they are left unset rather than pointed at a plausible path:
/// `mktemp` will then fail naming `/tmp`, which is a true error, instead of writing into a
/// directory nobody verified.
fn shell_base_env(prefix: Option<&str>, scratch: Option<&str>) -> BTreeMap<String, String> {
    let mut pairs: Vec<(&str, String)> = Vec::new();
    match prefix {
        Some(p) => {
            // Termux's own bin first, then its `system-bin` symlinks (toybox applets under
            // Termux names), then the platform directories for anything neither provides.
            pairs.push((
                "PATH",
                format!("{p}/bin:{p}/bin/system-bin:/system/bin:/system/xbin"),
            ));
            pairs.push(("PREFIX", p.to_string()));
            pairs.push(("HOME", format!("{p}/home")));
            pairs.push(("TMPDIR", format!("{p}/tmp")));
        }
        None => {
            // No Termux: platform directories only, and no `PREFIX` at all.
            pairs.push(("PATH", "/system/bin:/system/xbin:/product/bin".to_string()));
            if let Some(dir) = scratch {
                pairs.push(("HOME", dir.to_string()));
                pairs.push(("TMPDIR", dir.to_string()));
            }
        }
    }
    pairs.push(("ANDROID_ROOT", "/system".to_string()));
    pairs.push(("ANDROID_DATA", "/data".to_string()));

    let refs: Vec<(&str, &str)> = pairs.iter().map(|(k, v)| (*k, v.as_str())).collect();
    env_map(&refs)
}

/// The environment for a root shell.
///
/// Deliberately *not* the Termux environment. Termux's `bin` is writable by the app uid, and
/// a privileged helper that picked up `$PREFIX/bin` first would run attacker-writable binaries
/// as root — which is the one path by which an ordinary app reaches uid 0. So the privileged
/// `PATH` contains platform directories only, plus `/sbin`, where a Magisk install puts its own
/// helpers.
///
/// `LANG=C` makes tool output byte-stable: `sort`, `date` and toybox itself all change
/// behaviour under a UTF-8 locale, and the parsers in [`super::facts`] are written against C.
fn root_base_env() -> BTreeMap<String, String> {
    env_map(&[
        ("PATH", "/system/bin:/system/xbin:/product/bin:/sbin"),
        ("HOME", ROOT_HOME),
        ("TMPDIR", ROOT_HOME),
        ("ANDROID_ROOT", "/system"),
        ("ANDROID_DATA", "/data"),
        ("LANG", "C"),
    ])
}

/// Turn raw process output into the record the caller sees.
///
/// The identity marker is stripped before the caller's stdout is exposed, so a script never
/// sees its own output carrying a line it did not write; the uid and domain go into
/// [`ExecRecord::uid`] and [`ExecRecord::context`] instead, which is the whole mechanism for
/// proving who ran the command.
fn to_record(raw: RawOutput, nonce: &str) -> ExecRecord {
    let (identity, stdout_bytes) = extract_identity(&raw.stdout, nonce);
    let stderr = String::from_utf8_lossy(&raw.stderr).into_owned();
    // Denials are extracted here, once, so no caller has to know the `avc: denied` grammar.
    // In the record builder rather than in each backend, because two backends disagreeing
    // about what counts as a block is worse than one that is slightly wrong.
    let selinux_denials = parse_denials(&stderr);

    ExecRecord {
        stdout: String::from_utf8_lossy(&stdout_bytes).into_owned(),
        stderr,
        exit_code: raw.exit_code,
        selinux_denials,
        uid: identity.uid,
        context: identity.context,
        duration_ms: raw.duration.as_millis() as u64,
        truncated: raw.truncated,
        timed_out: raw.timed_out,
    }
}

/// Refuse a capability this device never demonstrated, before anything is spawned.
///
/// The gate refuses it too, as `NotDeclared`, and this repeats the check one layer down on
/// purpose. [`Gate::decide`](acowork_platform_contract::Gate::decide) is a pure function a
/// caller chooses to call, and a control nobody is compelled to walk through is advice. The
/// device harness found the difference by driving `ShellBackend` directly on a BLA-AL00 whose
/// profile declares only `android:shell:read` and `android:fs:outside-app`: the phone ran the
/// `setprop` as though that tier had been granted, because the content check below compares a
/// script with the label it carries and never asks whether this device can hold that label.
///
/// The floor is not the ceiling. Approval, the write lock and attribution stay with the gate —
/// a request that reaches here has usually passed them, and this refuses only what the probe
/// never demonstrated. It is deliberately not a second copy of the tier rules either: the
/// probe output is the single source, so a device that gains root declares more on the next
/// boot because the probe said so, not because this function was updated.
fn check_declared(profile: &HostProfile, request: &ExecRequest) -> Result<(), BackendError> {
    if profile.caps.is_declared(&request.capability) {
        return Ok(());
    }
    let declared = profile.caps.declared_ids();
    Err(BackendError::Refused {
        reason: format!(
            "`{}` was never demonstrated on this device, which declares {} — the backend does \
             not run a command the profile cannot account for. The gate refuses the same \
             request as `NotDeclared` and names the missing condition; where that condition is \
             a superuser grant, the next step is a device that has one, not a retry.",
            request.capability.as_str(),
            if declared.is_empty() {
                "nothing".to_string()
            } else {
                declared.join(", ")
            }
        ),
        kind: commands::RefusalKind::Undeclared,
    })
}

/// Everything about the *backend* that running one script needs.
///
/// These were positional arguments until the operator's budget joined them, at which point
/// `run_script` took eight and clippy was right that the list had stopped describing a call and
/// started describing a struct. The split is not cosmetic: every field here is fixed by the
/// backend for the life of the call, and the one thing that varies per command is the
/// [`ExecRequest`]. Naming that pair is what makes the choke point readable.
struct DeviceRun<'a, R: SpawnRunner> {
    runner: &'a R,
    profile: &'a HostProfile,
    base_env: &'a BTreeMap<String, String>,
    /// The budget a request gets when its author did not name one — the operator's, once a
    /// settings document is in play. See [`effective_budget`].
    default_budget: Budget,
    /// The program to exec. Always an absolute path: the child's environment is cleared, so a
    /// bare name may not resolve at all.
    file: PathBuf,
    /// argv. Never contains the script, which goes to stdin.
    args: Vec<String>,
    /// Names the privileged program when the invocation goes through one (`Some("su")`), which
    /// changes only how a failure to *start* is classified: "no `su` here" is a fact about the
    /// device's privilege model, while "no `bash` here" is this backend being broken. The caller
    /// must be able to tell them apart, because the first is answered by installing a superuser
    /// app and the second by fixing the profile.
    helper: Option<&'a str>,
}

impl<R: SpawnRunner> DeviceRun<'_, R> {
    /// Assemble, run, and record.
    async fn exec(&self, request: &ExecRequest) -> Result<ExecRecord, BackendError> {
        // Content before mechanism: the script is checked against the capability it claims
        // *before* anything is assembled or spawned, so a mislabelled request never reaches the
        // device. This is the one choke point every shell backend goes through.
        if let Err(refusal) = commands::check(&request.script, request.android_capability()) {
            return Err(BackendError::Refused {
                reason: refusal.to_string(),
                kind: refusal.kind(),
            });
        }

        // Then the device. Order matters for the log rather than for safety: a hard-banned script
        // stays classified as banned even on a tier that would never have run it, because
        // "someone reached for a partition-destroying command" and "someone reached for a write
        // tier this phone does not have" are different things to be counting.
        check_declared(self.profile, request)?;

        let prepared = script::prepare(&request.script, request.cwd.as_deref(), &request.env)
            .map_err(|e| BackendError::Backend(e.to_string()))?;

        let mut invocation = SpawnInvocation::new(self.file.clone(), prepared.text);
        invocation.args = self.args.clone();
        invocation.env = self.base_env.clone();
        // The budget the *device* sees. A request that still carries the port's default means its
        // author did not choose — which is the case for every command the port builds for itself,
        // including a snapshot capture and a restore — and those are exactly the ones an
        // operator's settings have to reach. A caller that named numbers keeps them:
        // `evidence::capture` asks for 300 s for a measured reason, and quietly capping it back
        // to the screen's 30 s would be a setting overriding an intention.
        let budget = effective_budget(&request.budget, &self.default_budget);
        invocation.output_cap = budget.output_cap;
        invocation.timeout = budget.timeout;

        let raw = self
            .runner
            .spawn(invocation)
            .await
            .map_err(|e| classify_spawn_failure(e, self.helper))?;

        Ok(to_record(raw, &prepared.nonce))
    }
}

/// Which budget actually runs: the caller's, or the operator's when the caller took the default.
///
/// Equality against [`default_budget`] is the test for "nobody chose", and the collision it
/// allows is deliberate and harmless: a caller who explicitly asks for exactly the port default
/// on a device whose operator changed it gets the operator's number. The reverse — a request
/// carrying a chosen budget being overwritten — is the failure mode that would silently truncate
/// an evidence dump, so it is the direction this refuses.
fn effective_budget(requested: &Budget, default_budget: &Budget) -> Budget {
    if requested == &crate::host::backend::default_budget() {
        *default_budget
    } else {
        *requested
    }
}

fn classify_spawn_failure(error: SpawnError, helper: Option<&str>) -> BackendError {
    match (&error, helper) {
        (SpawnError::Unavailable { file, reason }, Some(h)) => BackendError::EscalationUnavailable(
            format!("`{h}` at `{file}` could not be started: {reason}"),
        ),
        (SpawnError::Unavailable { file, reason }, None) => {
            BackendError::Backend(format!("`{file}` could not be started: {reason}"))
        }
        (SpawnError::Backend(why), _) => BackendError::Backend(why.clone()),
    }
}

/// Which shell a backend drives, and what it speaks.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ShellChoice {
    path: PathBuf,
    dialect: ShellDialect,
}

/// Resolve the shell an unprivileged-shell tier host should get.
///
/// Prefers the probed `bash`, because the Termux tier is *defined* by having it and the tool
/// registered for it promises bash semantics. Falls back to the platform shell for a host with
/// a shell but no bash — the [`HostProfileName::SystemShell`] case: uid 2000, mksh, no Termux
/// install, and still a legitimate place to run commands.
fn choose_shell(profile: &HostProfile) -> Option<ShellChoice> {
    if let Some(bash) = profile.paths.bash.as_ref() {
        return Some(ShellChoice {
            path: bash.clone(),
            dialect: ShellDialect::Bash,
        });
    }
    let dialect = profile.shell?;
    Some(ShellChoice {
        path: profile.paths.system_sh.clone(),
        dialect,
    })
}

/// Executes commands as the app uid, with no escalation of any kind.
///
/// One type serves two tiers, because the difference between them is a probed fact it reads
/// rather than a mechanism it implements: with a `bash` and a `$PREFIX` it is the Termux
/// environment, without them it is `/system/bin/sh` on a stock device. What it may *not* be
/// called is what the profile says it is not — see [`ShellBackend::name`], which reports the
/// tier rather than the type.
///
/// Everything this backend can do, the Runtime process could already do: it is a
/// *convenience*, not a privilege, and the gate's privilege axis never moves because of it.
#[derive(Debug)]
pub struct ShellBackend<R = ProcessSpawnRunner> {
    profile: HostProfile,
    runner: R,
    shell: ShellChoice,
    base_env: BTreeMap<String, String>,
    default_budget: Budget,
}

impl ShellBackend<ProcessSpawnRunner> {
    /// Build a shell backend that starts real processes.
    pub fn new(profile: HostProfile) -> Result<ShellBackend<ProcessSpawnRunner>, BackendError> {
        ShellBackend::with_runner(profile, ProcessSpawnRunner::new())
    }
}

impl<R: SpawnRunner> ShellBackend<R> {
    /// Build a shell backend over an arbitrary runner.
    ///
    /// Fails when the profile has no shell at all. Refusing at construction rather than at the
    /// first `exec` matters: the caller decides which tools to register from the profile, and a
    /// backend that exists but cannot run anything would advertise a capability the device did
    /// not earn.
    pub fn with_runner(profile: HostProfile, runner: R) -> Result<ShellBackend<R>, BackendError> {
        let shell = choose_shell(&profile).ok_or_else(|| {
            BackendError::Backend(
                "this host profile has no shell, so a shell backend cannot be built on it; \
                 use `AppSandboxBackend` and `std::fs` instead"
                    .to_string(),
            )
        })?;
        let base_env = shell_base_env(
            profile.paths.termux_prefix.as_deref(),
            scratch_dir(&profile),
        );
        Ok(ShellBackend {
            profile,
            runner,
            shell,
            base_env,
            default_budget: crate::host::backend::default_budget(),
        })
    }

    /// The budget a request gets when it did not name one.
    ///
    /// Set this from the operator's settings
    /// ([`HostConfig::budget`](crate::host::config::HostConfig::budget)) rather than leaving the
    /// port default: a screen that offers "command timeout" and is not wired to the value the
    /// child is killed by is a screen with a dead control on it.
    pub fn with_default_budget(mut self, budget: Budget) -> Self {
        self.default_budget = budget;
        self
    }

    /// The absolute path this backend execs.
    pub fn shell_path(&self) -> &Path {
        &self.shell.path
    }

    /// The environment this backend hands the child, before the request's own exports.
    pub fn base_env(&self) -> &BTreeMap<String, String> {
        &self.base_env
    }
}

#[async_trait]
impl<R: SpawnRunner> ExecutionBackend for ShellBackend<R> {
    fn name(&self) -> &'static str {
        // The tier, not the type. This backend is one implementation serving two tiers, and
        // hard-coding "termux" here reported a Termux environment on a device whose probe
        // found no bash and no `$PREFIX` — the same fabrication one tier up, in a second
        // place that reads it: this name is what the exec record carries.
        self.profile.name.as_str()
    }

    fn dialect(&self) -> Option<ShellDialect> {
        Some(self.shell.dialect)
    }

    fn profile(&self) -> &HostProfile {
        &self.profile
    }

    async fn exec(&self, request: ExecRequest) -> Result<ExecRecord, BackendError> {
        // `-s`: read the script from stdin. It also makes the body unambiguous — without it a
        // script whose first line begins with `-` would be parsed as an option.
        DeviceRun {
            runner: &self.runner,
            profile: &self.profile,
            base_env: &self.base_env,
            default_budget: self.default_budget,
            file: self.shell.path.clone(),
            args: vec!["-s".to_string()],
            helper: None,
        }
        .exec(&request)
        .await
    }
}

/// Executes commands through `su`, as uid 0.
///
/// # The claim this backend makes, and how it checks it
///
/// `su` exiting with status 0 does **not** mean the script ran as root. Superuser
/// implementations differ in what they grant — Magisk can be configured to hand back the shell
/// uid rather than 0 — and ADR-AND-001 §1.1 is explicit that uid 0 and a usable SELinux domain
/// are separate facts that can disagree. So this backend never infers privilege from an exit
/// code. It reads the uid and domain that `script` observed *inside* the running script, and
/// refuses the result unless they say root.
///
/// A run whose identity could not be established is refused too. "Cannot prove it was root" and
/// "was not root" get the same answer here on purpose: for an unattended node, treating an
/// unproven privileged execution as successful is precisely the failure mode that writes to
/// `/system` from a shell that was never privileged.
#[derive(Debug)]
pub struct RootShellBackend<R = ProcessSpawnRunner> {
    profile: HostProfile,
    runner: R,
    su: PathBuf,
    /// The platform shell `su` is told to exec. Always the system shell, never the probed
    /// bash: an escalated command must not depend on app-writable storage. See
    /// [`root_base_env`].
    shell: PathBuf,
    /// Override for the `su` argument vector. Empty means "use [`RootShellBackend::su_argv`]".
    ///
    /// `su -c` is the Magisk and KernelSU spelling; SuperSU and the `su 0 <cmd>` variants
    /// differ, and no probe currently records which dialect a device speaks. Which is why this
    /// is overridable rather than hardcoded, and why confirming it is a device-harness item.
    su_args: Vec<String>,
    base_env: BTreeMap<String, String>,
    default_budget: Budget,
}

impl RootShellBackend<ProcessSpawnRunner> {
    /// Build a root backend that starts real processes.
    pub fn new(profile: HostProfile) -> Result<RootShellBackend<ProcessSpawnRunner>, BackendError> {
        RootShellBackend::with_runner(profile, ProcessSpawnRunner::new())
    }
}

impl<R: SpawnRunner> RootShellBackend<R> {
    /// Build a root backend over an arbitrary runner.
    ///
    /// Refuses a profile that did not actually get root from `su`. The check is on
    /// [`HostProfile::su`] rather than on the presence of a `su` binary, because a binary that
    /// denies is a different device than one that grants, and the two need different next steps.
    pub fn with_runner(
        profile: HostProfile,
        runner: R,
    ) -> Result<RootShellBackend<R>, BackendError> {
        if profile.su.prompt_denied {
            return Err(BackendError::EscalationUnavailable(
                "the superuser prompt was declined during the probe. This is not retryable: \
                 re-asking presents the user a dialog for a decision they already made. The \
                 grant has to be restored in the superuser app first"
                    .to_string(),
            ));
        }
        if profile.su.unavailable || !profile.su.got_root() {
            return Err(BackendError::EscalationUnavailable(
                "this device's `su` probe did not produce uid 0, so a privileged backend cannot \
                 be built from its profile"
                    .to_string(),
            ));
        }
        let su = profile.paths.su.clone().ok_or_else(|| {
            BackendError::EscalationUnavailable(
                "probe item 4 says the helper works but item 4a (`command -v` for it) did not \
                 return a path, and a backend that clears the child's environment cannot exec a \
                 bare command name. Re-run the probe with item 4a included, or supply \
                 `HostProfile::paths.su` — `ShellPaths::resolve_su()` finds it by stat, but only \
                 when this process is running on the device itself"
                    .to_string(),
            )
        })?;

        Ok(RootShellBackend {
            shell: profile.paths.system_sh.clone(),
            default_budget: crate::host::backend::default_budget(),
            profile,
            runner,
            su,
            su_args: Vec::new(),
            base_env: root_base_env(),
        })
    }

    /// The budget a request gets when it did not name one.
    ///
    /// Same contract as [`ShellBackend::with_default_budget`], and the same reason: a restore
    /// that runs as root is the command least able to fail for a reason nobody configured.
    pub fn with_default_budget(mut self, budget: Budget) -> Self {
        self.default_budget = budget;
        self
    }

    /// Override the `su` argument vector, for an implementation that does not speak `-c`.
    pub fn with_su_args(mut self, args: &[&str]) -> RootShellBackend<R> {
        self.su_args = args.iter().map(|a| (*a).to_string()).collect();
        self
    }

    /// The argv handed to `su`, with the default applied.
    ///
    /// The command is `"<shell> -s"` as one argument: `su -c` takes a single string and gives
    /// it to a shell, and the script body arrives separately on stdin, which that shell then
    /// reads. Nothing caller-supplied appears here, so `ps` reveals nothing (ADR-AND-001 §4.7).
    fn su_argv(&self) -> Vec<String> {
        if !self.su_args.is_empty() {
            return self.su_args.clone();
        }
        vec!["-c".to_string(), format!("{} -s", self.shell.display())]
    }

    /// The privileged helper this backend execs.
    pub fn su_path(&self) -> &Path {
        &self.su
    }

    /// The platform shell it is told to exec.
    pub fn shell_path(&self) -> &Path {
        &self.shell
    }

    /// The environment this backend hands the child.
    pub fn base_env(&self) -> &BTreeMap<String, String> {
        &self.base_env
    }
}

#[async_trait]
impl<R: SpawnRunner> ExecutionBackend for RootShellBackend<R> {
    fn name(&self) -> &'static str {
        "root-shell"
    }

    fn dialect(&self) -> Option<ShellDialect> {
        // The escalated shell is the platform shell whatever the unprivileged probe found, so
        // promising bash semantics here would misdescribe the shell the body actually reaches.
        // bash is excluded from the choice for exactly that reason.
        self.profile
            .dialects
            .iter()
            .find(|d| !matches!(d, ShellDialect::Bash))
            .copied()
            .or(self.profile.shell)
    }

    fn profile(&self) -> &HostProfile {
        &self.profile
    }

    async fn exec(&self, request: ExecRequest) -> Result<ExecRecord, BackendError> {
        let argv = self.su_argv();
        let args: Vec<&str> = argv.iter().map(String::as_str).collect();

        let record = DeviceRun {
            runner: &self.runner,
            profile: &self.profile,
            base_env: &self.base_env,
            default_budget: self.default_budget,
            file: self.su.clone(),
            args: args.iter().map(|a| (*a).to_string()).collect(),
            helper: Some("su"),
        }
        .exec(&request)
        .await?;

        if record.uid == Some(0) {
            return Ok(record);
        }

        // Escalation did not happen, or cannot be proved. Which of those it was changes what
        // the caller should do next, so the cases are separated rather than collapsed into one
        // "privilege failed" error.
        if record.timed_out {
            // An unanswered superuser dialog is indistinguishable from a slow command at this
            // layer, and it is by far the common cause — so the likely reason is stated rather
            // than left for the caller to guess.
            return Err(BackendError::EscalationUnavailable(
                "`su` produced no result within its budget and the identity that ran it is \
                 unknown. The usual cause is a superuser prompt nobody answered; check for an \
                 open dialog before retrying"
                    .to_string(),
            ));
        }
        if su_prompt_denied(&record.stderr) {
            return Err(BackendError::EscalationUnavailable(
                "the superuser prompt was declined for this call. Not retryable — the user has \
                 to grant access in the superuser app first"
                    .to_string(),
            ));
        }
        if su_helper_missing(&record.stderr) {
            return Err(BackendError::EscalationUnavailable(format!(
                "`su` at `{}` is not reachable from this context",
                self.su.display()
            )));
        }

        Err(BackendError::PrivilegeNotGranted {
            observed_uid: record.uid,
            observed_context: record.context.clone(),
        })
    }
}

/// Answers "there is no shell on this host" without pretending there is one.
///
/// ADR-AND-001 §7.5 item 2: on the APK profile, file operations stay on `std::fs` and are *not*
/// routed through a backend. This type exists so that a caller asking for a shell gets a refusal
/// naming the missing fact and the alternative, rather than an `ENOENT` from a `sh` that is not
/// there. It is not a file API and must not grow into one.
#[derive(Debug)]
pub struct AppSandboxBackend {
    profile: HostProfile,
}

impl AppSandboxBackend {
    /// Wrap an APK-sandbox profile.
    pub fn new(profile: HostProfile) -> AppSandboxBackend {
        AppSandboxBackend { profile }
    }
}

#[async_trait]
impl ExecutionBackend for AppSandboxBackend {
    fn name(&self) -> &'static str {
        "app-sandbox"
    }

    fn dialect(&self) -> Option<ShellDialect> {
        None
    }

    fn profile(&self) -> &HostProfile {
        &self.profile
    }

    async fn exec(&self, request: ExecRequest) -> Result<ExecRecord, BackendError> {
        Err(BackendError::Backend(format!(
            "this host has no shell (apk-sandbox profile), so `{}` cannot be executed here; \
             use `std::fs` within the app's own storage instead",
            request.capability.as_str()
        )))
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::host::capability::Capability;
    use crate::host::facts::{FsRoot, Privilege};
    use crate::host::probe::{CommandOutput, ProbeCommand, ProbeOutput};
    use crate::host::spawn::{DynamicSpawnRunner, ScriptedSpawnRunner};

    const PREFIX: &str = "/data/data/com.termux/files/usr";

    // ── profiles, assembled rather than typed out ────────────────────────────

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
                other => unreachable!("the fixture set does not route {other:?}"),
            }
        }
        out
    }

    /// Built through [`HostProfile::assemble`] rather than as a struct literal on purpose: a
    /// fixture typed out by hand can assert things no probe would ever produce, and the
    /// backends would then pass tests against a device that does not exist.
    fn termux_profile() -> HostProfile {
        let bash = format!("{PREFIX}/bin/bash\n");
        let mut probe = probe_of(&[
            (ProbeCommand::Id, "10233\n"),
            (ProbeCommand::GetEnforce, "Enforcing\n"),
            (
                ProbeCommand::AttrCurrent,
                "u:r:untrusted_app:s0:c123,c456\n",
            ),
            (ProbeCommand::BashPath, &bash),
            (
                ProbeCommand::SystemShVersion,
                "KSH=@(#)MIRBSD KSH R57 2019-03-01 Android\nBASH=\n",
            ),
            (ProbeCommand::ToyboxList, "cat\nid\nlogcat\n"),
        ]);
        probe.termux_prefix = Some(PREFIX.to_string());
        probe.fs_roots = vec![FsRoot {
            path: PREFIX.to_string(),
            writable: true,
            own_package: true,
        }];
        HostProfile::assemble(&probe, "com.termux")
    }

    /// A rooted device, plus the one fact the probe does not yet record, filled in by hand.
    fn rooted_profile() -> HostProfile {
        let mut probe = probe_of(&[
            (ProbeCommand::Id, "2000\n"),
            (ProbeCommand::GetEnforce, "Enforcing\n"),
            (ProbeCommand::AttrCurrent, "u:r:shell:s0\n"),
            (ProbeCommand::Su, "0\nu:r:magisk:s0\n"),
            (
                ProbeCommand::SystemShVersion,
                "KSH=@(#)MIRBSD KSH R57 2019-03-01 Android\nBASH=\n",
            ),
            (ProbeCommand::ToyboxList, "cat\nid\nmount\nsetprop\n"),
        ]);
        probe.fs_roots = vec![FsRoot {
            path: "/data/local/tmp".to_string(),
            writable: true,
            own_package: false,
        }];
        let mut profile = HostProfile::assemble(&probe, "com.acowork.node");
        assert!(
            profile.su.got_root(),
            "the fixture is supposed to be rooted"
        );
        // Not probed — see `ShellPaths::su`. A caller resolves it; the device harness will too.
        profile.paths.su = Some(PathBuf::from("/system/bin/su"));
        profile
    }

    /// A host with a shell but no bash and no Termux: the `adb shell` deliverable.
    fn shell_only_profile() -> HostProfile {
        let probe = probe_of(&[
            (ProbeCommand::Id, "2000\n"),
            (ProbeCommand::GetEnforce, "Enforcing\n"),
            (ProbeCommand::AttrCurrent, "u:r:shell:s0\n"),
            (
                ProbeCommand::SystemShVersion,
                "KSH=@(#)MIRBSD KSH R57 2019-03-01 Android\nBASH=\n",
            ),
        ]);
        HostProfile::assemble(&probe, "")
    }

    /// A stock APK sandbox: no shell was detected at all.
    fn apk_profile() -> HostProfile {
        HostProfile::assemble(&ProbeOutput::default(), "com.acowork.node")
    }

    // ── the fake shell ───────────────────────────────────────────────────────

    /// A runner that behaves like a shell about the identity prologue.
    ///
    /// A canned stdout cannot work here: `run_script` generates a **fresh nonce per call**, and
    /// a real shell echoes back the one it was handed inside the script. So the reply is
    /// computed from the invocation. That also makes the fake fail loudly if the prologue ever
    /// stops being the first thing the generated script does — which is the property that lets
    /// a timed-out command be attributed at all.
    #[derive(Debug, Clone)]
    struct FakeShell {
        uid: Option<u32>,
        context: Option<String>,
        body_stdout: String,
        stderr: String,
        exit_code: Option<i32>,
        timed_out: bool,
        truncated: bool,
    }

    impl FakeShell {
        /// A shell that ran as `uid` in `context` and produced nothing.
        fn ran_as(uid: u32, context: &str) -> FakeShell {
            FakeShell {
                uid: Some(uid),
                context: Some(context.to_string()),
                body_stdout: String::new(),
                stderr: String::new(),
                exit_code: Some(0),
                timed_out: false,
                truncated: false,
            }
        }

        fn root() -> FakeShell {
            FakeShell::ran_as(0, "u:r:magisk:s0")
        }

        fn app() -> FakeShell {
            FakeShell::ran_as(10233, "u:r:untrusted_app:s0:c123,c456")
        }

        fn shell_uid() -> FakeShell {
            FakeShell::ran_as(2000, "u:r:shell:s0")
        }

        /// A shell where `id` is missing: the prologue runs, the marker is malformed, and
        /// nothing about who ran the command can be established.
        fn identity_unknown() -> FakeShell {
            FakeShell {
                uid: None,
                context: None,
                body_stdout: String::new(),
                stderr: String::new(),
                exit_code: Some(0),
                timed_out: false,
                truncated: false,
            }
        }

        fn body(mut self, text: &str) -> FakeShell {
            self.body_stdout = text.to_string();
            self
        }

        fn stderr(mut self, text: &str) -> FakeShell {
            self.stderr = text.to_string();
            self
        }

        fn exit(mut self, code: Option<i32>) -> FakeShell {
            self.exit_code = code;
            self
        }

        /// The cap was hit: the shell produced more than the budget allowed.
        fn truncated(mut self) -> FakeShell {
            self.truncated = true;
            self
        }

        fn timed_out(mut self) -> FakeShell {
            self.timed_out = true;
            self.exit_code = None;
            self
        }

        fn into_runner(self) -> impl SpawnRunner + Recorded {
            ScriptedSpawnRunner::dynamic(move |inv| {
                let nonce = script::nonce_of(&inv.script).unwrap_or_else(|| {
                    panic!(
                        "the fake shell was handed a script with no identity prologue, so it \
                         cannot echo a marker. If this fires, `run_script` stopped putting the \
                         probe first — which is the property that makes a killed command \
                         attributable. Script was:\n{}",
                        inv.script
                    )
                });
                let marker = match self.uid {
                    Some(uid) => format!(
                        "{nonce}\t{uid}\t{}\t{nonce}\n",
                        self.context.clone().unwrap_or_default()
                    ),
                    // No marker at all: what a device without toybox `id` produces.
                    None => String::new(),
                };
                RawOutput {
                    exit_code: self.exit_code,
                    stdout: format!("{marker}{}", self.body_stdout).into_bytes(),
                    stderr: self.stderr.clone().into_bytes(),
                    truncated: self.truncated,
                    timed_out: self.timed_out,
                    duration: Duration::from_millis(7),
                }
            })
        }
    }

    /// Runner types that remember what they were handed.
    ///
    /// A local trait rather than an `Any` downcast, because the backends are generic over the
    /// runner and the concrete type is known at every call site in here.
    trait Recorded {
        fn invocations(&self) -> Vec<SpawnInvocation>;

        fn only(&self) -> SpawnInvocation {
            let all = self.invocations();
            assert_eq!(
                all.len(),
                1,
                "expected exactly one invocation, got {}",
                all.len()
            );
            all.into_iter().next().unwrap()
        }
    }

    impl<F> Recorded for DynamicSpawnRunner<F>
    where
        F: Fn(&SpawnInvocation) -> RawOutput + Send + Sync,
    {
        fn invocations(&self) -> Vec<SpawnInvocation> {
            DynamicSpawnRunner::invocations(self)
        }
    }

    fn read_request() -> ExecRequest {
        ExecRequest::read("logcat -d", "session-1")
    }

    fn write_request() -> ExecRequest {
        ExecRequest::new(
            Capability::ShellWrite,
            "setprop persist.acowork.on 1",
            "session-1",
        )
    }

    // ── construction ─────────────────────────────────────────────────────────

    #[test]
    fn a_termux_backend_drives_the_probed_bash() {
        let backend = ShellBackend::new(termux_profile()).unwrap();
        assert_eq!(backend.name(), "termux");
        assert_eq!(backend.dialect(), Some(ShellDialect::Bash));
        assert_eq!(
            backend.shell_path(),
            Path::new(&format!("{PREFIX}/bin/bash"))
        );
    }

    #[test]
    fn a_host_with_a_shell_but_no_bash_falls_back_to_the_platform_shell() {
        // The `adb shell` deliverable: uid 2000, mksh, no Termux. A backend that refused here
        // would leave the CLI build with no way to run anything.
        let backend = ShellBackend::new(shell_only_profile()).unwrap();
        assert_eq!(backend.shell_path(), Path::new("/system/bin/sh"));
        assert_eq!(backend.dialect(), Some(ShellDialect::MkSh));
    }

    #[test]
    fn no_backend_is_built_on_a_profile_with_no_shell() {
        let err = ShellBackend::new(apk_profile()).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("no shell"), "{msg}");
        assert!(msg.contains("AppSandboxBackend"), "{msg}");
        assert!(msg.contains("std::fs"), "{msg}");
    }

    #[test]
    fn a_root_backend_needs_to_know_where_su_is() {
        // Item 4 proves the helper works; item 4a proves where it is. A profile with the first
        // and not the second cannot be turned into a backend, and has to say which is missing.
        let mut profile = rooted_profile();
        profile.paths.su = None;
        let err = RootShellBackend::with_runner(profile, ProcessSpawnRunner::new()).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("item 4a"), "{msg}");
        assert!(msg.contains("command -v"), "{msg}");
        assert!(msg.contains("ShellPaths::resolve_su"), "{msg}");
    }

    #[test]
    fn a_root_backend_is_not_built_on_a_device_without_root() {
        let err = RootShellBackend::new(shell_only_profile()).unwrap_err();
        assert!(err.to_string().contains("did not produce uid 0"), "{err}");
    }

    #[test]
    fn a_declined_prompt_at_probe_time_is_not_retryable_and_says_so() {
        let mut probe = probe_of(&[
            (ProbeCommand::Id, "2000\n"),
            (ProbeCommand::AttrCurrent, "u:r:shell:s0\n"),
            (
                ProbeCommand::SystemShVersion,
                "KSH=@(#)MIRBSD KSH R57 2019-03-01 Android\nBASH=\n",
            ),
        ]);
        let mut denied = CommandOutput::ok("");
        denied.stderr = "su: Permission denied".to_string();
        probe.su = Some(denied);
        let profile = HostProfile::assemble(&probe, "");
        assert!(
            profile.su.prompt_denied,
            "fixture must reach the denial path"
        );

        let err = RootShellBackend::new(profile).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("declined"), "{msg}");
        assert!(msg.contains("not retryable"), "{msg}");
    }

    #[test]
    fn the_root_backend_promises_the_platform_dialect_not_bash() {
        // A device with both bash and su: escalating still lands in mksh, so registering the
        // tool as bash would describe a shell the body never reaches.
        let mut profile = rooted_profile();
        profile.dialects.insert(ShellDialect::Bash);
        let backend = RootShellBackend::new(profile).unwrap();
        assert_eq!(backend.dialect(), Some(ShellDialect::MkSh));
    }

    // ── the base environment is made of probed facts only ────────────────────

    /// The bug this test pins: a host with no Termux was handed a fabricated `$PREFIX`
    /// pointing at the stock Termux directory.
    ///
    /// `$PREFIX` is the marker the profile uses to decide whether this *is* a Termux host, so
    /// inventing one makes a script that checks it — Termux's own scripts do — conclude it is
    /// inside Termux on a device that has never had it installed, and then go looking for data
    /// under a directory that does not exist. A Huawei BLA-AL00 with no Termux produced exactly
    /// this environment from the harness.
    #[test]
    fn a_device_without_termux_is_not_given_a_fake_prefix() {
        let backend = ShellBackend::new(shell_only_profile()).unwrap();
        let env = backend.base_env();
        assert!(
            env.get("PREFIX").is_none(),
            "PREFIX must be absent, not defaulted: {env:?}"
        );
        assert!(
            !env.values().any(|v| v.contains("com.termux")),
            "no path may point inside a Termux install that was never probed: {env:?}"
        );
        assert_eq!(
            env.get("PATH").map(String::as_str),
            Some("/system/bin:/system/xbin:/product/bin"),
            "without a prefix the search path is the platform's own"
        );
    }

    /// `HOME` and `TMPDIR` have to be supplied once the environment is cleared, and the only
    /// acceptable source is a root the probe actually wrote a file into.
    #[test]
    fn home_and_tmpdir_come_from_a_root_the_probe_wrote_to() {
        let mut profile = shell_only_profile();
        profile.fs_roots = vec![FsRoot {
            path: "/data/local/tmp".to_string(),
            writable: true,
            own_package: false,
        }];
        let backend = ShellBackend::new(profile).unwrap();
        let env = backend.base_env();
        assert_eq!(env.get("HOME").map(String::as_str), Some("/data/local/tmp"));
        assert_eq!(
            env.get("TMPDIR").map(String::as_str),
            Some("/data/local/tmp")
        );
    }

    #[test]
    fn nothing_measured_writable_leaves_home_unset_rather_than_guessed() {
        let mut profile = shell_only_profile();
        // Present but read-only: the probe looked, and the `touch` failed.
        profile.fs_roots = vec![FsRoot {
            path: "/data/local/tmp".to_string(),
            writable: false,
            own_package: false,
        }];
        let backend = ShellBackend::new(profile).unwrap();
        let env = backend.base_env();
        assert!(
            env.get("HOME").is_none() && env.get("TMPDIR").is_none(),
            "a directory nobody proved writable must not be asserted: {env:?}"
        );
    }

    #[test]
    fn a_writable_own_package_root_is_not_used_as_the_scratch_directory() {
        // On Termux the app directory is writable, and on an APK sandbox it is the *only*
        // writable root. Neither is the right `HOME` for a shell that has no prefix: the
        // scratch preference is an explicit list, not "whatever was writable first".
        let mut profile = shell_only_profile();
        profile.fs_roots = vec![FsRoot {
            path: "/data/data/com.acowork.node".to_string(),
            writable: true,
            own_package: true,
        }];
        let backend = ShellBackend::new(profile).unwrap();
        assert!(backend.base_env().get("HOME").is_none());
    }

    /// The other side of the same rule: when the device *did* report a prefix, its canonical
    /// Termux layout is used, and `PREFIX` is set.
    #[test]
    fn a_probed_prefix_is_used_and_reexported() {
        let backend = ShellBackend::new(termux_profile()).unwrap();
        let env = backend.base_env();
        assert_eq!(env.get("PREFIX").map(String::as_str), Some(PREFIX));
        let want_home = format!("{PREFIX}/home");
        let want_tmp = format!("{PREFIX}/tmp");
        assert_eq!(
            env.get("HOME").map(String::as_str),
            Some(want_home.as_str())
        );
        assert_eq!(
            env.get("TMPDIR").map(String::as_str),
            Some(want_tmp.as_str())
        );
        assert!(
            env.get("PATH")
                .unwrap()
                .starts_with(&format!("{PREFIX}/bin:")),
            "Termux's own bin leads when it exists"
        );
    }

    // ── what reaches the runner ──────────────────────────────────────────────

    #[tokio::test]
    async fn termux_execs_the_shell_with_s_and_keeps_the_script_out_of_argv() {
        let runner = FakeShell::app().into_runner();
        let backend = ShellBackend::with_runner(termux_profile(), runner).unwrap();
        let shell = backend.shell_path().to_path_buf();

        backend.exec(read_request()).await.unwrap();

        let inv = backend.runner.only();
        assert_eq!(inv.file, shell);
        assert_eq!(inv.args, vec!["-s".to_string()]);
        assert!(
            !inv.args.iter().any(|a| a.contains("logcat")),
            "the script body must not be in argv: {:?}",
            inv.args
        );
        assert!(
            inv.script.contains("logcat -d"),
            "the body belongs on stdin"
        );
    }

    #[tokio::test]
    async fn root_execs_su_with_the_platform_shell_and_a_fixed_argv() {
        let backend =
            RootShellBackend::with_runner(rooted_profile(), FakeShell::root().into_runner())
                .unwrap();

        backend.exec(read_request()).await.unwrap();

        let inv = backend.runner.only();
        assert_eq!(inv.file, PathBuf::from("/system/bin/su"));
        assert_eq!(
            inv.args,
            vec!["-c".to_string(), "/system/bin/sh -s".to_string()],
            "the escalation argv must be fixed, never caller-influenced"
        );
        assert!(!inv.args.iter().any(|a| a.contains("logcat")));
    }

    #[tokio::test]
    async fn su_args_can_be_overridden_for_a_helper_that_does_not_speak_dash_c() {
        let backend =
            RootShellBackend::with_runner(rooted_profile(), FakeShell::root().into_runner())
                .unwrap()
                .with_su_args(&["0", "/system/bin/sh", "-s"]);

        backend.exec(read_request()).await.unwrap();

        assert_eq!(
            backend.runner.only().args,
            vec!["0", "/system/bin/sh", "-s"]
        );
    }

    #[tokio::test]
    async fn the_request_cannot_redirect_the_shell_the_identity_probe_runs() {
        // The security property behind `base_env` being the backend's: a request that set PATH
        // could otherwise point `id` at a script that prints 0, forging the proof this crate
        // exists to obtain.
        let backend =
            ShellBackend::with_runner(termux_profile(), FakeShell::app().into_runner()).unwrap();

        let mut request = read_request();
        request.env = env_map(&[("PATH", "/evil")]);
        backend.exec(request).await.unwrap();

        let inv = backend.runner.only();
        let want = format!("{PREFIX}/bin:{PREFIX}/bin/system-bin:/system/bin:/system/xbin");
        assert_eq!(inv.env.get("PATH").map(String::as_str), Some(&*want));
        // The request's variable still reaches the body, as an export inside the script.
        assert!(inv.script.contains("export PATH='/evil'"));
    }

    #[tokio::test]
    async fn a_privileged_path_never_contains_termux_bin() {
        // Termux's bin is app-writable; root executing from it is an app's route to uid 0 —
        // even on a device that has both Termux and su.
        let backend = RootShellBackend::new(rooted_profile()).unwrap();
        let path = backend
            .base_env()
            .get("PATH")
            .cloned()
            .expect("root env sets PATH");
        assert!(
            !path.contains("com.termux"),
            "root PATH leaked Termux: {path}"
        );
        assert!(path.starts_with("/system/bin"), "{path}");
        assert_eq!(
            backend.base_env().get("LANG").map(String::as_str),
            Some("C")
        );
    }

    #[tokio::test]
    async fn the_request_budget_reaches_the_runner() {
        let backend =
            ShellBackend::with_runner(termux_profile(), FakeShell::app().into_runner()).unwrap();

        let mut request = read_request();
        request.budget.output_cap = 1234;
        request.budget.timeout = Some(Duration::from_secs(3));
        backend.exec(request).await.unwrap();

        let inv = backend.runner.only();
        assert_eq!(inv.output_cap, 1234);
        assert_eq!(inv.timeout, Some(Duration::from_secs(3)));
    }

    #[tokio::test]
    async fn the_working_directory_and_env_reach_the_generated_script() {
        let backend =
            ShellBackend::with_runner(termux_profile(), FakeShell::app().into_runner()).unwrap();
        let mut request = read_request();
        request.cwd = Some(PathBuf::from("/data/local/tmp"));
        request.env = env_map(&[("TARGET", "u:object_r:system_file:s0")]);

        backend.exec(request).await.unwrap();

        let script = backend.runner.only().script;
        assert!(script.contains("cd -- '/data/local/tmp' ||"), "{script}");
        assert!(
            script.contains("export TARGET='u:object_r:system_file:s0'"),
            "{script}"
        );
    }

    // ── the record ───────────────────────────────────────────────────────────

    #[tokio::test]
    async fn the_identity_that_ran_is_reported_and_the_marker_is_stripped() {
        let body = "total 0\n";
        let runner = FakeShell::app().body(body).into_runner();
        let backend = ShellBackend::with_runner(termux_profile(), runner).unwrap();

        let record = backend.exec(read_request()).await.unwrap();

        assert_eq!(record.uid, Some(10233));
        assert_eq!(
            record.context.as_deref(),
            Some("u:r:untrusted_app:s0:c123,c456")
        );
        assert_eq!(record.stdout, body, "the marker must not reach the caller");
        assert!(record.succeeded());
        assert_eq!(record.duration_ms, 7);
    }

    #[tokio::test]
    async fn denials_are_extracted_once_so_no_caller_reparses_them() {
        let stderr = "avc: denied { read } for pid=1234 comm=\"cat\" \
                      name=u:object_r:system_file:s0 tclass=file permissive=0\n";
        let runner = FakeShell::app().stderr(stderr).exit(Some(1)).into_runner();
        let backend = ShellBackend::with_runner(termux_profile(), runner).unwrap();

        let record = backend.exec(read_request()).await.unwrap();

        assert_eq!(record.selinux_denials.len(), 1);
        assert_eq!(record.selinux_denials[0].tclass.as_deref(), Some("file"));
        assert!(record.was_blocked_by_selinux());
        assert!(!record.succeeded(), "a blocked command is not a success");
    }

    #[tokio::test]
    async fn a_timeout_is_a_record_with_evidence_not_an_error_without_any() {
        let runner = FakeShell::app().body("partial").timed_out().into_runner();
        let backend = ShellBackend::with_runner(termux_profile(), runner).unwrap();

        let record = backend.exec(read_request()).await.unwrap();

        assert!(record.timed_out);
        assert_eq!(record.exit_code, None);
        assert_eq!(record.stdout, "partial");
        assert_eq!(
            record.uid,
            Some(10233),
            "a killed command still says who ran it"
        );
        assert!(!record.succeeded());
        assert_eq!(
            record.to_contract().result,
            Err(acowork_platform_contract::ExecutionError::TimedOut),
            "and the contract still learns it timed out"
        );
    }

    #[tokio::test]
    async fn a_script_error_is_refused_before_anything_is_spawned() {
        // An invalid env key is rejected by `script::prepare`. The runner must never be called,
        // because a half-built script is not something to hand to a shell.
        let runner = FakeShell::app().into_runner();
        let backend = ShellBackend::with_runner(termux_profile(), runner).unwrap();

        let mut request = read_request();
        request.env = env_map(&[("1BAD", "x")]);
        let err = backend.exec(request).await.unwrap_err();

        assert!(matches!(err, BackendError::Backend(_)), "{err:?}");
        assert!(err.to_string().contains("1BAD"), "{err}");
        assert!(
            backend.runner.invocations().is_empty(),
            "nothing should have run"
        );
    }

    // ── content versus claim (ADR-AND-001 §4.4) ──────────────────────────────

    #[tokio::test]
    async fn a_write_labelled_as_read_never_reaches_the_device() {
        // The hole §4.4 was supposed to close and didn't: `read()` is a self-declaration, so
        // without a content check the auto-pass tier is one careless label away from running
        // `setprop` unattended. The refusal has to happen before the spawn, not after.
        let runner = FakeShell::app().into_runner();
        let backend = ShellBackend::with_runner(termux_profile(), runner).unwrap();

        let request = ExecRequest::read("setprop persist.acowork.on 1", "session-1");
        let err = backend.exec(request).await.unwrap_err();

        assert!(matches!(err, BackendError::Refused { .. }), "{err:?}");
        let text = err.to_string();
        assert!(text.contains("setprop"), "{text}");
        assert!(
            text.contains(&Capability::ShellWrite.id().to_string()),
            "the refusal must name the capability that would authorise it: {text}"
        );
        assert!(
            backend.runner.invocations().is_empty(),
            "a refused request must not touch the device"
        );
    }

    #[tokio::test]
    async fn a_remount_labelled_as_read_is_refused_by_the_privileged_backend_too() {
        let runner = FakeShell::root().into_runner();
        let backend = RootShellBackend::with_runner(rooted_profile(), runner).unwrap();

        let request = ExecRequest::read("mount -o remount,rw /system", "session-1");
        let err = backend.exec(request).await.unwrap_err();
        assert!(matches!(err, BackendError::Refused { .. }), "{err:?}");
        assert!(
            err.to_string()
                .contains(&Capability::FsSystem.id().to_string()),
            "{err}"
        );
        assert!(backend.runner.invocations().is_empty());
    }

    #[tokio::test]
    async fn a_hard_banned_command_is_refused_under_a_label_that_would_otherwise_pass() {
        // §4.6.3 item 3. The write label is the one an agent with approval would carry, so
        // this is where the ban has to bite — raising the tier must not be the answer.
        let runner = FakeShell::root().into_runner();
        let backend = RootShellBackend::with_runner(rooted_profile(), runner).unwrap();

        let request = ExecRequest::new(Capability::ShellWrite, "rm -rf /data", "session-1");
        let err = backend.exec(request).await.unwrap_err();
        assert!(matches!(err, BackendError::Refused { .. }), "{err:?}");
        assert!(err.to_string().contains("human"), "{err}");
        assert!(backend.runner.invocations().is_empty());
    }

    #[tokio::test]
    async fn a_capability_the_device_never_declared_is_refused_by_the_backend() {
        // The gate refuses this as `NotDeclared` — but `decide` is a pure function a caller
        // chooses to call, and a control nobody is compelled to walk through is advice. The
        // device harness found the hole while proving §4.6.4: it drove `ShellBackend` directly
        // on a BLA-AL00 whose profile declares only `android:shell:read` and
        // `android:fs:outside-app`, and the phone ran the `setprop`. The content check could
        // not have caught it: that check compares a script with the label it carries, and this
        // label was carried honestly. What is missing is not the right words in the request,
        // it is a device that demonstrated it.
        let profile = shell_only_profile();
        assert!(
            !profile.caps.is_declared(&Capability::ShellWrite.id()),
            "the fixture must be a host that never demonstrated the write tier"
        );
        let runner = FakeShell::shell_uid().into_runner();
        let backend = ShellBackend::with_runner(profile, runner).unwrap();

        let mut request = ExecRequest::new(
            Capability::ShellWrite,
            "setprop debug.acowork.on 1",
            "session-1",
        );
        // Approved by a caller that then skipped the gate. An approval is not evidence the
        // device can do the thing: it is evidence a human agreed to try.
        request.approval_token = Some(crate::host::ApprovalToken::new("gate was never consulted"));
        let err = backend.exec(request).await.unwrap_err();

        assert!(
            matches!(&err, BackendError::Refused { kind, .. }
                if *kind == commands::RefusalKind::Undeclared),
            "{err:?}"
        );
        let text = err.to_string();
        assert!(text.contains("android:shell:write"), "{text}");
        assert!(
            text.contains("android:shell:read"),
            "the refusal has to say what this device *does* allow, or the caller retries harder instead of elsewhere: {text}"
        );
        assert!(
            backend.runner.invocations().is_empty(),
            "a tier the device never demonstrated must not touch the device"
        );
    }

    #[tokio::test]
    async fn a_banned_script_stays_banned_on_a_tier_that_could_not_have_run_it() {
        // Which of the two checks fires first is a logging decision, not a safety one — both
        // refuse. But if the declaration check ran first, every hard-banned attempt on a
        // low-tier device would be counted as `undeclared`, and the one number anyone actually
        // wants to watch ("how often is something reaching for a partition-destroying
        // command?") would go quiet exactly when the fleet gets less capable.
        let runner = FakeShell::shell_uid().into_runner();
        let backend = ShellBackend::with_runner(shell_only_profile(), runner).unwrap();

        let err = backend
            .exec(ExecRequest::new(
                Capability::ShellWrite,
                "toybox rm -rf /data",
                "session-1",
            ))
            .await
            .unwrap_err();
        assert!(
            matches!(&err, BackendError::Refused { kind, .. }
                if *kind == commands::RefusalKind::Banned),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn the_declaration_check_refuses_a_capability_that_is_not_even_in_the_vocabulary() {
        // A request labelled with something Android never defined. `is_declared` answers
        // false, which is the right refusal — the alternative is a backend that runs whatever
        // carries an unrecognised string.
        let runner = FakeShell::shell_uid().into_runner();
        let backend = ShellBackend::with_runner(shell_only_profile(), runner).unwrap();
        let mut request = ExecRequest::read("getprop ro.build.type", "session-1");
        request.capability =
            acowork_platform_contract::HostCapability::new("symbian", "shell:read")
                .expect("well-formed id");

        let err = backend.exec(request).await.unwrap_err();
        assert!(
            matches!(&err, BackendError::Refused { kind, .. }
                if *kind == commands::RefusalKind::Undeclared),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn the_tiers_that_match_their_content_still_run() {
        // The check must not become a tax on correct requests: the read tier keeps its
        // approval-free path, and a write under its own label still gets to the device.
        let runner = FakeShell::app().into_runner();
        let backend = ShellBackend::with_runner(termux_profile(), runner).unwrap();
        let record = backend.exec(read_request()).await.unwrap();
        assert_eq!(record.exit_code, Some(0));
        assert_eq!(backend.runner.invocations().len(), 1);

        let runner = FakeShell::root().into_runner();
        let backend = RootShellBackend::with_runner(rooted_profile(), runner).unwrap();
        let record = backend.exec(write_request()).await.unwrap();
        assert_eq!(record.uid, Some(0));
    }

    #[tokio::test]
    async fn a_refusal_keeps_its_reason_through_the_contract_projection() {
        // The caller on the other side of the port sees `ExecutionError`, so the named
        // capability and the next step have to survive the trip.
        let runner = FakeShell::app().into_runner();
        let backend = ShellBackend::with_runner(termux_profile(), runner).unwrap();
        let err = backend
            .exec(ExecRequest::read("setprop a b", "session-1"))
            .await
            .unwrap_err();
        let contract = err.to_contract();
        assert!(
            matches!(
                contract,
                acowork_platform_contract::ExecutionError::Rejected(_)
            ),
            "{contract:?}"
        );
        assert!(
            contract.to_string().contains("setprop"),
            "projected text must still name the command: {contract}"
        );
    }

    #[tokio::test]
    async fn hitting_the_output_cap_is_recorded_not_silently_truncated() {
        // The caller cannot tell a cut-off answer from a complete one unless the record says
        // so, and an audit trail that reads "the command printed 512 bytes" when it printed
        // 500 KB is worse than no audit trail.
        let runner = FakeShell::app()
            .body("x".repeat(512).as_str())
            .truncated()
            .into_runner();
        let backend = ShellBackend::with_runner(termux_profile(), runner).unwrap();

        let record = backend.exec(read_request()).await.unwrap();
        assert!(record.truncated);
        assert!(
            record.to_contract().stdout.truncated,
            "and the contract projection keeps the flag"
        );
    }

    // ── the privilege claim ──────────────────────────────────────────────────

    #[tokio::test]
    async fn a_root_run_that_observed_uid_zero_is_accepted() {
        let runner = FakeShell::root().body("Enforcing\n").into_runner();
        let backend = RootShellBackend::with_runner(rooted_profile(), runner).unwrap();

        let record = backend.exec(write_request()).await.unwrap();
        assert_eq!(record.uid, Some(0));
        assert_eq!(record.context.as_deref(), Some("u:r:magisk:s0"));
    }

    #[tokio::test]
    async fn a_silent_privilege_drop_is_refused_with_what_was_actually_observed() {
        // The case ADR-AND-001 §7.4 is about: `su` exited 0, the body ran, and it was not root.
        let runner = FakeShell::shell_uid().body("uid=2000").into_runner();
        let backend = RootShellBackend::with_runner(rooted_profile(), runner).unwrap();

        let err = backend.exec(write_request()).await.unwrap_err();
        match &err {
            BackendError::PrivilegeNotGranted {
                observed_uid,
                observed_context,
            } => {
                assert_eq!(*observed_uid, Some(2000));
                assert_eq!(observed_context.as_deref(), Some("u:r:shell:s0"));
            }
            other => panic!("expected PrivilegeNotGranted, got {other:?}"),
        }
        assert!(err.to_string().contains("asked to run as root"), "{err}");
    }

    #[tokio::test]
    async fn uid_zero_in_an_unprivileged_domain_is_accepted_and_recorded_for_the_caller() {
        // ADR-AND-001 §1.1: uid 0 and a usable domain are separate facts. This backend proves
        // the uid; the domain is handed to the caller for judgement, because refusing here
        // would make the mechanism second-guess the gate's privilege axis.
        let runner = FakeShell::ran_as(0, "u:r:untrusted_app:s0").into_runner();
        let backend = RootShellBackend::with_runner(rooted_profile(), runner).unwrap();

        let record = backend.exec(write_request()).await.unwrap();
        assert_eq!(record.uid, Some(0));
        assert_eq!(record.context.as_deref(), Some("u:r:untrusted_app:s0"));
    }

    #[tokio::test]
    async fn an_unprovable_identity_is_refused_not_assumed_privileged() {
        let runner = FakeShell::identity_unknown()
            .body("no marker here")
            .into_runner();
        let backend = RootShellBackend::with_runner(rooted_profile(), runner).unwrap();

        let err = backend.exec(write_request()).await.unwrap_err();
        assert!(
            matches!(
                err,
                BackendError::PrivilegeNotGranted {
                    observed_uid: None,
                    ..
                }
            ),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn an_unanswered_su_prompt_is_escalation_not_a_wrong_uid() {
        let runner = FakeShell::identity_unknown().timed_out().into_runner();
        let backend = RootShellBackend::with_runner(rooted_profile(), runner).unwrap();

        let err = backend.exec(write_request()).await.unwrap_err();
        assert!(
            matches!(err, BackendError::EscalationUnavailable(_)),
            "{err:?}"
        );
        assert!(err.to_string().contains("prompt nobody answered"), "{err}");
    }

    #[tokio::test]
    async fn a_declined_prompt_at_exec_time_is_marked_not_retryable() {
        let runner = FakeShell::shell_uid()
            .stderr("su: Permission denied")
            .into_runner();
        let backend = RootShellBackend::with_runner(rooted_profile(), runner).unwrap();

        let err = backend.exec(write_request()).await.unwrap_err();
        assert!(
            matches!(err, BackendError::EscalationUnavailable(_)),
            "{err:?}"
        );
        assert!(err.to_string().contains("Not retryable"), "{err}");
    }

    #[tokio::test]
    async fn a_missing_su_binary_is_escalation_unavailable_not_a_broken_backend() {
        let backend = RootShellBackend::with_runner(rooted_profile(), UnavailableRunner).unwrap();
        let err = backend.exec(write_request()).await.unwrap_err();
        match err {
            BackendError::EscalationUnavailable(why) => {
                assert!(why.contains("`su`"), "{why}");
                assert!(why.contains("/system/bin/su"), "{why}");
            }
            other => panic!("expected EscalationUnavailable, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_missing_shell_binary_is_a_broken_backend_not_a_missing_privilege() {
        // The same failure at the seam, classified by whether a privileged helper was involved.
        let backend = ShellBackend::with_runner(termux_profile(), UnavailableRunner).unwrap();
        let err = backend.exec(read_request()).await.unwrap_err();
        match err {
            BackendError::Backend(why) => {
                assert!(why.contains("bash"), "{why}");
                assert!(!why.contains("`su`"), "{why}");
            }
            other => panic!("expected Backend, got {other:?}"),
        }
    }

    /// A runner whose program is not there, the way a device reports it.
    struct UnavailableRunner;

    #[async_trait]
    impl SpawnRunner for UnavailableRunner {
        async fn spawn(&self, inv: SpawnInvocation) -> Result<RawOutput, SpawnError> {
            Err(SpawnError::Unavailable {
                file: inv.file.display().to_string(),
                reason: "No such file or directory".to_string(),
            })
        }
    }

    // ── the sandbox tier ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn the_apk_sandbox_refuses_by_name_and_points_at_the_alternative() {
        let backend = AppSandboxBackend::new(apk_profile());
        assert_eq!(backend.dialect(), None);
        assert_eq!(backend.name(), "app-sandbox");

        let err = backend.exec(read_request()).await.unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("no shell"), "{msg}");
        assert!(msg.contains("android:shell:read"), "{msg}");
        assert!(msg.contains("std::fs"), "{msg}");
    }

    #[tokio::test]
    async fn every_backend_refusal_keeps_its_reason_after_contract_projection() {
        // R9 across the seam: a contract-level caller must still get something actionable, not
        // an enum discriminant.
        let cases: Vec<BackendError> = vec![
            AppSandboxBackend::new(apk_profile())
                .exec(read_request())
                .await
                .unwrap_err(),
            RootShellBackend::new(shell_only_profile()).unwrap_err(),
            BackendError::PrivilegeNotGranted {
                observed_uid: Some(2000),
                observed_context: Some("u:r:shell:s0".into()),
            },
        ];
        for err in cases {
            let projected = err.to_contract().to_string();
            assert!(
                projected.split_whitespace().count() > 4,
                "projection is not actionable: {projected}"
            );
        }
    }

    #[test]
    fn the_runtime_process_is_never_the_privileged_one() {
        // ADR-AND-001 §4.1 as a structural check on the fixtures: the *probe* ran as app or
        // shell uid on every tier. A profile whose probe ran as root means someone started the
        // Runtime under `su`, which is the thing the whole design forbids.
        for profile in [termux_profile(), rooted_profile(), shell_only_profile()] {
            assert_ne!(
                profile.privilege,
                Privilege::Root,
                "{} profile was probed from a root process",
                profile.name.as_str()
            );
        }
    }
}
