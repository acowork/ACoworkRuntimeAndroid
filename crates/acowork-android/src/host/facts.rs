//! Probed host facts and their text parsers.
//!
//! Layering: this module is the **data model** of the probe subsystem. Every
//! parser here is a pure function from a command's captured text to a typed
//! fact — no I/O, no process spawning, no global state. That is what makes the
//! probe testable with fabricated command output, which is the P0 acceptance
//! criterion in ADR-AND-001 §6 ("单元测试用伪造 probe 输出").
//!
//! Robustness contract (android-host-probe.md §7): every parser must tolerate
//! "command not found", empty output, and malformed text by degrading to an
//! explicit `Unknown`/`None` value. **A parser never panics and never guesses.**
//! Guessing is how a probe turns into a false capability declaration, and
//! android-host-probe.md §4 forbids exactly that.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

/// Privilege level of the process that will actually run a command.
///
/// Ordered: `AppUid < ShellUid < Root`. The ordering is what the capability
/// derivation rules in android-host-probe.md §3 mean by `privilege >= Root`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Privilege {
    /// Ordinary application uid (`u0_aNNN`). No process spawning on a stock APK.
    AppUid,
    /// The `shell` uid (2000), as reached via `adb shell`.
    ShellUid,
    /// uid 0. Still constrained by the SELinux domain — see [`SelinuxState`].
    Root,
}

impl Privilege {
    /// Parse the output of `id -u`.
    ///
    /// Returns `None` when the probe itself failed, which per
    /// android-host-probe.md §2 item 1 means the host degrades to `apk-sandbox`.
    pub fn parse_uid(raw: &str) -> Option<Privilege> {
        let uid: u32 = raw.trim().parse().ok()?;
        Some(match uid {
            0 => Privilege::Root,
            2000 => Privilege::ShellUid,
            _ => Privilege::AppUid,
        })
    }

    /// The canonical uid for this level, for diagnostics and evidence strings.
    ///
    /// `AppUid` has no single uid — it is `u0_aNNN`, per-app — so this returns the
    /// base of that range. It is used only in human-readable evidence, never in a
    /// comparison; the ordering on [`Privilege`] is what rules read.
    pub fn uid(&self) -> u32 {
        match self {
            Privilege::AppUid => 10_000,
            Privilege::ShellUid => 2_000,
            Privilege::Root => 0,
        }
    }

    /// Map onto the contract's platform-neutral level.
    ///
    /// This is the bridge between an Android fact and a rule that must also hold on
    /// a device with no uids at all. The mapping is the port's to make and the
    /// contract's to consume; nothing else in the system needs to know that
    /// `ShellUid` exists.
    ///
    /// `Root` maps to `Unrestricted`, which is what makes contract rule R3 bite: a
    /// node process probing as root is non-conformant, and the gate will refuse its
    /// mutating capabilities. That is ADR-AND-001 §4.1 expressed as a rule the
    /// compiler and the gate both enforce, rather than as a sentence in a document.
    pub fn to_contract(&self) -> acowork_platform_contract::PrivilegeLevel {
        use acowork_platform_contract::PrivilegeLevel;
        match self {
            Privilege::AppUid => PrivilegeLevel::Unprivileged,
            Privilege::ShellUid => PrivilegeLevel::Elevated,
            Privilege::Root => PrivilegeLevel::Unrestricted,
        }
    }
}

/// SELinux enforcement state, as reported by `getenforce`.
///
/// This — not the uid — is the real gate on Android (ADR-AND-001 §1.1). A root
/// process in a restricted domain still collects `avc: denied`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SelinuxState {
    /// Denials are enforced. The normal state on a production device.
    Enforcing,
    /// Denials are logged but allowed.
    Permissive,
    /// `getenforce` is missing or unreadable. Per android-host-probe.md §2
    /// item 2, **write-tier capabilities are never opened in this state.**
    Unknown,
}

impl SelinuxState {
    /// Parse the output of `getenforce`.
    ///
    /// Accepts the canonical capitalized spelling and the lowercase form some
    /// toybox builds emit. Anything else — including an empty string from a
    /// missing applet — is `Unknown`, never a silent default.
    pub fn parse(raw: &str) -> SelinuxState {
        match raw.trim().to_ascii_lowercase().as_str() {
            "enforcing" => SelinuxState::Enforcing,
            "permissive" => SelinuxState::Permissive,
            _ => SelinuxState::Unknown,
        }
    }

    /// True when this state can ever justify opening a write-tier capability.
    pub fn known(&self) -> bool {
        !matches!(self, SelinuxState::Unknown)
    }
}

/// dm-verity / AVB state of the system partition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum VerityState {
    /// Verity is enforcing: `/system` cannot be remounted read-write without
    /// `disable-verity` **plus a reboot** (ADR-AND-001 §1.1).
    Enforcing,
    /// Verity is logging or disabled, so a remount is at least conceivable.
    NotEnforcing,
    /// `ro.boot.veritymode` is absent or unrecognised. Treated as `Enforcing`
    /// by the derivation rules — android-host-probe.md §2 item 10:
    /// "未知 → 保守按 enforcing".
    Unknown,
}

impl VerityState {
    /// Parse `getprop ro.boot.veritymode`.
    ///
    /// Real devices report `enforcing` / `logging` / `disabled`; some bootloaders
    /// emit the single-letter abbreviations, which is what
    /// android-host-probe.md §2 item 10 refers to by "`e`（enforcing）".
    pub fn parse(raw: &str) -> VerityState {
        match raw.trim().to_ascii_lowercase().as_str() {
            "enforcing" | "e" => VerityState::Enforcing,
            "logging" | "l" | "disabled" | "off" | "d" => VerityState::NotEnforcing,
            _ => VerityState::Unknown,
        }
    }

    /// Conservative view used by capability derivation: unknown counts as
    /// enforcing, so `android:fs:system` stays closed.
    pub fn blocks_system_write(&self) -> bool {
        !matches!(self, VerityState::NotEnforcing)
    }
}

/// Android build flavour from `getprop ro.build.type`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BuildType {
    /// Production build. `/system` is verity-protected and read-only.
    User,
    /// Debug build with root available via `adb root`.
    UserDebug,
    /// Engineering build. The most permissive flavour.
    Eng,
    /// Property missing or unrecognised.
    Unknown,
}

impl BuildType {
    /// Parse `getprop ro.build.type`.
    pub fn parse(raw: &str) -> BuildType {
        match raw.trim().to_ascii_lowercase().as_str() {
            "user" => BuildType::User,
            "userdebug" => BuildType::UserDebug,
            "eng" => BuildType::Eng,
            _ => BuildType::Unknown,
        }
    }
}

/// Shell dialect behind a `sh`-compatible binary.
///
/// ADR-AND-001 §1.1: `/system/bin/sh` is **mksh**, not bash, and the difference
/// is observable by the model (no arrays, different `[[` semantics). The dialect
/// therefore has to reach the tool description, not stay an internal detail.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ShellDialect {
    /// GNU bash — the Termux case.
    Bash,
    /// MIRBSD Korn Shell, i.e. `/system/bin/sh` on every stock Android.
    MkSh,
    /// BusyBox `ash`.
    BusyBoxSh,
}

impl ShellDialect {
    /// Tool name this dialect is registered under.
    ///
    /// Follows the upstream dual-registration pattern in
    /// `core/acowork-runtime/src/tools/builtin/shell.rs` (bash / powershell are
    /// separate tools so the model can pick). Note the open naming question
    /// recorded as B5 in the readiness assessment: upstream registers a single
    /// tool called `shell` on Unix, so `bash` here is a divergence that still
    /// needs an upstream ruling.
    pub fn tool_name(&self) -> &'static str {
        match self {
            ShellDialect::Bash => "bash",
            ShellDialect::MkSh => "ash",
            ShellDialect::BusyBoxSh => "ash",
        }
    }

    /// Classify the answer to probe item 5b.
    ///
    /// Two shapes are accepted, because the probe asks the platform shell to name itself:
    ///
    /// - the labelled form `KSH=@(#)MIRBSD KSH R57 …` / `BASH=`, which is what
    ///   [`ProbeCommand::SystemShVersion`](super::probe::ProbeCommand::SystemShVersion)
    ///   emits;
    /// - a bare version banner, which is what a shell that supports `--version` prints.
    ///
    /// Returns `None` for an empty or unrecognised answer rather than defaulting to a
    /// dialect: a wrong dialect in the tool description teaches the model syntax that will
    /// not run. `None` does **not** mean "no shell" — that is a separate fact, decided by
    /// whether the probe command exited successfully, and recorded as
    /// [`HostProfile::shell_executed`](super::profile::HostProfile::shell_executed). Busybox
    /// ash is the everyday case where the two disagree: it runs the script and sets neither
    /// variable.
    pub fn parse_version_banner(raw: &str) -> Option<ShellDialect> {
        let text = raw.trim();
        if text.is_empty() {
            return None;
        }

        // Labelled form. Only a *non-empty* value counts: `BASH=` on a device whose platform
        // shell is mksh is evidence against bash, not for it.
        for line in text.lines() {
            let (label, value) = match line.split_once('=') {
                Some(pair) => pair,
                None => continue,
            };
            let value = value.trim();
            if value.is_empty() {
                continue;
            }
            match label.trim().to_ascii_uppercase().as_str() {
                "KSH" | "KSH_VERSION" => return Some(ShellDialect::MkSh),
                "BASH" | "BASH_VERSION" => return Some(ShellDialect::Bash),
                _ => {}
            }
        }

        let lower = text.to_ascii_lowercase();
        if lower.contains("mirbsd ksh") || lower.contains("mksh") {
            Some(ShellDialect::MkSh)
        } else if lower.contains("gnu bash") {
            Some(ShellDialect::Bash)
        } else if lower.contains("busybox") {
            Some(ShellDialect::BusyBoxSh)
        } else {
            None
        }
    }
}

/// The set of command names actually present on the device.
///
/// android-host-probe.md §7.5 item 1: take the bulk list from `toybox` and
/// `busybox --list` in one shot, then spot-check at most ten high-value commands
/// with `command -v`. Probing each applet individually would mean hundreds of
/// process spawns, which is not acceptable on a battery-powered device.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppletSet {
    names: BTreeSet<String>,
    /// True when neither `toybox` nor `busybox` reported a list. The shell then
    /// has builtins only, and the tool description must say so
    /// (android-host-probe.md §2 item 6).
    pub list_source_missing: bool,
}

impl AppletSet {
    /// An empty set with no list source.
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether this command name was reported present.
    pub fn contains(&self, name: &str) -> bool {
        self.names.contains(name)
    }

    /// Number of known command names.
    pub fn len(&self) -> usize {
        self.names.len()
    }

    /// Whether no command name is known.
    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }

    /// Iterate names in stable order.
    pub fn iter(&self) -> impl Iterator<Item = &String> {
        self.names.iter()
    }

    /// Parse a bulk applet listing.
    ///
    /// Handles all three real-world shapes: `toybox` bare (one name per line),
    /// `busybox --list` (one name per line), and `busybox` bare (which prints a
    /// multi-column "functions:" block). Columns are split on whitespace so the
    /// busybox banner does not need a special case.
    pub fn parse_list(raw: &str) -> AppletSet {
        let mut set = AppletSet::new();
        for line in raw.lines() {
            let line = line.trim();
            // Skip the busybox banner lines, which are prose rather than names.
            if line.is_empty()
                || line.starts_with("BusyBox v")
                || line.ends_with("multi-call binary.")
                || line == "Currently defined functions:"
            {
                continue;
            }
            // Split on whitespace *and* commas: `busybox --list` and `toybox`
            // print one name per line, but bare `busybox` prints a
            // comma-separated "Currently defined functions:" block.
            for token in line.split(|c: char| c.is_whitespace() || c == ',') {
                if is_applet_name(token) {
                    set.names.insert(token.to_string());
                }
            }
        }
        set.list_source_missing = set.names.is_empty();
        set
    }

    /// Merge another listing into this one (toybox ∪ busybox ∪ spot checks).
    pub fn merge(&mut self, other: &AppletSet) {
        self.names.extend(other.names.iter().cloned());
        // A union is only "no list source" when *both* sides had none.
        self.list_source_missing &= other.list_source_missing;
    }

    /// Record a single `command -v` spot check as present.
    pub fn insert_confirmed(&mut self, name: &str) {
        if is_applet_name(name) {
            self.names.insert(name.to_string());
        }
    }
}

/// An applet name is a bare lowercase-ish token with no path or punctuation.
/// This filter is what keeps `mount` prose and busybox banner text out of the set.
fn is_applet_name(token: &str) -> bool {
    // `[` and `[[` are genuine busybox applets (the test builtin) and would
    // otherwise be filtered out by the alphabetic-first-character rule below.
    if token == "[" || token == "[[" {
        return true;
    }
    !token.is_empty()
        && token.len() <= 32
        && !token.contains('/')
        && !token.contains('(')
        && token
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
        && token
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic())
}

/// One row of the mount table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MountEntry {
    /// The backing device or pseudo-fs identifier.
    pub device: String,
    /// Where it is mounted, with procfs octal escapes resolved.
    pub mount_point: String,
    /// Filesystem type (`ext4`, `f2fs`, `tmpfs`, ...).
    pub fs_type: String,
    /// Whether the *first* mount option is `rw`.
    pub read_write: bool,
}

/// Parse a mount table.
///
/// Accepts both shapes found on Android:
/// - `mount` output: `<dev> on <point> type <fstype> (<opts>)`
/// - `/proc/mounts`:  `<dev> <point> <fstype> <opts> 0 0`
///
/// Supporting both is not speculative generality: `mount` is an applet, so it is
/// exactly the kind of command that can be missing (android-host-probe.md §2
/// item 6), and `/proc/mounts` is the fallback that always exists.
pub fn parse_mount_table(raw: &str) -> Vec<MountEntry> {
    let mut out = Vec::new();
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(entry) = parse_mount_line_human(line) {
            out.push(entry);
            continue;
        }
        if let Some(entry) = parse_mount_line_procfs(line) {
            out.push(entry);
        }
    }
    out
}

fn parse_mount_line_human(line: &str) -> Option<MountEntry> {
    // <dev> on <point> type <fstype> (<opts>)
    let on = line.find(" on ")?;
    let rest = &line[on + 4..];
    let type_idx = rest.find(" type ")?;
    let mount_point = unescape_mount_point(rest[..type_idx].trim());
    let after_type = &rest[type_idx + 6..];
    let (fs_type, opts) = match after_type.find('(') {
        Some(paren) => (
            after_type[..paren].trim().to_string(),
            after_type[paren..].trim().to_string(),
        ),
        None => (after_type.trim().to_string(), String::new()),
    };
    Some(MountEntry {
        device: line[..on].trim().to_string(),
        mount_point,
        fs_type,
        read_write: opts_are_rw(&opts),
    })
}

fn parse_mount_line_procfs(line: &str) -> Option<MountEntry> {
    // <dev> <point> <fstype> <opts> <dump> <pass>
    let mut fields = line.split_whitespace();
    let device = fields.next()?.to_string();
    let mount_point = unescape_mount_point(fields.next()?);
    let fs_type = fields.next()?.to_string();
    let opts = fields.next().unwrap_or("").to_string();
    // Fewer than five fields: not a procfs mount line.
    fields.next()?;
    Some(MountEntry {
        device,
        mount_point,
        fs_type,
        read_write: opts_are_rw(&opts),
    })
}

/// `ro`/`rw` is the *first* option in both formats; a later `remount` or a
/// `ro` inside a `user_xattr`-style token must not flip the verdict.
fn opts_are_rw(opts: &str) -> bool {
    let trimmed = opts.trim_start_matches('(').trim_end_matches(')');
    match trimmed.split(',').next() {
        Some(first) => first.trim() == "rw",
        None => false,
    }
}

/// procfs escapes spaces, tabs and newlines in mount points as octal.
fn unescape_mount_point(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let bytes = raw.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 3 < bytes.len() {
            let oct = &raw[i + 1..i + 4];
            if let Ok(code) = u8::from_str_radix(oct, 8) {
                out.push(code as char);
                i += 4;
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

/// A `key=value` system property.
pub fn parse_prop(raw: &str) -> Option<String> {
    let value = raw.trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

/// Parse `ro.debuggable` / `ro.secure` / `ro.adb.secure` style boolean props.
///
/// Android booleans are `1`/`0` or `true`/`false` depending on the property, so
/// both are accepted. Missing means `false` — these are all "is the device
/// locked down" signals, and android-host-probe.md §2 item 9 treats
/// `ro.debuggable=1` as the positive signal.
pub fn parse_bool_prop(raw: &str) -> bool {
    matches!(
        raw.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "y" | "on"
    )
}

/// Parse the combined output of `su -c 'id -u; cat /proc/self/attr/current'`.
///
/// android-host-probe.md §2 item 4 requires recording the uid **and** the domain
/// after `su`, because they can disagree: Magisk can hand back uid 0 while the
/// process stays in a domain the policy restricts. Treating "su worked" as
/// "root is omnipotent" is the exact mistake ADR-AND-001 §1.1 corrects.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SuProbe {
    /// uid after `su`. `Some(0)` is the only value that counts as root.
    pub uid: Option<u32>,
    /// SELinux context after `su` — recorded separately because it can disagree with the uid.
    pub context: Option<String>,
    /// The `su` binary exists but the user rejected the Magisk prompt. Per
    /// android-host-probe.md §2 item 4 this is **not retryable** — retrying
    /// re-prompts the user for a decision they already made.
    pub prompt_denied: bool,
    /// `su` is absent, or the probe timed out.
    pub unavailable: bool,
}

impl SuProbe {
    /// Did `su` actually deliver uid 0?
    pub fn got_root(&self) -> bool {
        self.uid == Some(0)
    }
}

/// Does this stderr say the superuser prompt was **refused by the user**?
///
/// Split out of [`parse_su_probe`] because an execution backend has to make the same
/// distinction at the same time as the probe does — a declined prompt is not retryable
/// (android-host-probe.md §2 item 4), while "no su here" is a reason to re-probe after
/// installing a manager. Two copies of the wording list would drift apart, and the drift
/// would show up as a node that retries a prompt the user already said no to.
///
/// Substring matching, not exact comparison: the wording varies by Magisk/KernelSU/SuperSU
/// version and by whether a manager app is installed at all.
pub fn su_prompt_denied(stderr: &str) -> bool {
    let err = stderr.to_ascii_lowercase();
    [
        "denied",
        "permission denied",
        "not allowed",
        "rejected",
        "cancelled",
    ]
    .iter()
    .any(|needle| err.contains(needle))
}

/// Does this stderr say the privileged helper is **absent or unreachable**?
///
/// See [`su_prompt_denied`] for why this is a shared predicate rather than a local one.
pub fn su_helper_missing(stderr: &str) -> bool {
    let err = stderr.to_ascii_lowercase();
    ["not found", "no such file", "inaccessible", "not available"]
        .iter()
        .any(|needle| err.contains(needle))
}

/// Parse the stdout/stderr pair of the `su` probe.
///
/// `stderr` is inspected first because the denial messages are what
/// distinguishes "user said no" from "no su here" — and those two have different
/// retry semantics.
pub fn parse_su_probe(stdout: &str, stderr: &str, timed_out: bool) -> SuProbe {
    if timed_out {
        return SuProbe {
            uid: None,
            context: None,
            prompt_denied: false,
            unavailable: true,
        };
    }

    let denied = su_prompt_denied(stderr);
    let missing = su_helper_missing(stderr);

    if denied {
        return SuProbe {
            uid: None,
            context: None,
            prompt_denied: true,
            unavailable: false,
        };
    }
    if missing {
        return SuProbe {
            uid: None,
            context: None,
            prompt_denied: false,
            unavailable: true,
        };
    }

    // Expected stdout: "<uid>\n<context>" — but tolerate a missing context line,
    // since reading /proc/self/attr/current can itself be denied.
    let mut lines = stdout.lines().map(str::trim).filter(|l| !l.is_empty());
    let uid = lines.next().and_then(|l| l.parse::<u32>().ok());
    let context = lines.next().map(|l| l.to_string()).or_else(|| {
        // Some `su` builds print only the context when `id` is unavailable.
        stdout
            .lines()
            .map(str::trim)
            .find(|l| l.starts_with("u:r:"))
            .map(|l| l.to_string())
    });

    if uid.is_none() && context.is_none() {
        return SuProbe {
            uid: None,
            context: None,
            prompt_denied: false,
            unavailable: true,
        };
    }

    SuProbe {
        uid,
        context,
        prompt_denied: false,
        unavailable: false,
    }
}

/// Classify `/proc/self/attr/current`.
///
/// android-host-probe.md §2 item 3: an unreadable context means "treat as a
/// restricted domain", which is what `None` represents here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SelinuxDomain {
    /// `u:r:untrusted_app:*` — a normal APK.
    UntrustedApp,
    /// `u:r:shell:*` — adb shell or Termux's login shell on some ROMs.
    Shell,
    /// `u:r:magisk:*` / `u:r:su:*` — a Magisk-injected privileged domain.
    Magisk,
    /// A domain we did not recognise. Still a real domain, so it is *not* the
    /// same as unreadable; it just earns no assumptions.
    Other(String),
    /// Could not be read. Treated as restricted.
    Unreadable,
}

/// Strip the terminator the kernel puts on a security-context read.
///
/// `/proc/*/attr/current` is **NUL-terminated, not newline-terminated**. Measured on a
/// Huawei BLA-AL00 (API 29): `cat /proc/self/attr/current` yields the 14 bytes
/// `u:r:shell:s0\0`. `str::trim` and `is_ascii_whitespace` both leave `\0` in place, so
/// without this the terminator is carried into [`HostProfile`](super::profile), echoed in
/// every audit record that cites the context, and compared unequal to the same context
/// read through a shell — `$(cat …)` *does* drop it, which is why the exec path never
/// showed the problem while the probe path did.
///
/// Returns `None` for an empty or terminator-only read, which is the same "unreadable"
/// answer [`SelinuxDomain::Unreadable`] encodes.
pub fn normalize_context(raw: &str) -> Option<&str> {
    let ctx = raw.trim().trim_end_matches('\0').trim();
    (!ctx.is_empty()).then_some(ctx)
}

impl SelinuxDomain {
    /// Classify a raw `/proc/self/attr/current` value.
    ///
    /// Tolerates the NUL terminator (see [`normalize_context`]) so a caller that hands it
    /// the unparsed file read still gets `Shell` rather than `Other("shell")` with a
    /// trailing NUL in its payload.
    pub fn parse(raw: &str) -> SelinuxDomain {
        let Some(ctx) = normalize_context(raw) else {
            return SelinuxDomain::Unreadable;
        };
        // The context is `user:role:type[:level]`; the type is the third field.
        let domain = ctx.split(':').nth(2).unwrap_or(ctx);
        match domain {
            "untrusted_app" | "untrusted_app_25" | "untrusted_app_27" | "untrusted_app_29"
            | "untrusted_app_32" | "untrusted_app_all" => SelinuxDomain::UntrustedApp,
            "shell" => SelinuxDomain::Shell,
            "magisk" | "su" | "su_daemon" => SelinuxDomain::Magisk,
            _ => SelinuxDomain::Other(domain.to_string()),
        }
    }

    /// True when this domain is one a privileged helper is expected to run in.
    pub fn is_privileged(&self) -> bool {
        matches!(self, SelinuxDomain::Magisk)
    }
}

/// Immutable device facts (android-host-probe.md §3, `DeviceFacts`).
///
/// These are reported to the Gateway only as the coarse summary decided in
/// ADR-AND-001 §7.1 — never as raw device identifiers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceFacts {
    /// `ro.build.type`.
    pub build_type: BuildType,
    /// `ro.debuggable` — the strongest single signal for a debugging device.
    pub debuggable: bool,
    /// `ro.secure`.
    pub secure: bool,
    /// `ro.adb.secure`.
    pub adb_secure: bool,
    /// `ro.build.version.sdk`.
    pub api_level: Option<u32>,
    /// `ro.product.cpu.abi`.
    pub abi: Option<String>,
    /// `ro.boot.veritymode`.
    pub verity: VerityState,
}

impl DeviceFacts {
    /// All-unknown facts, used when every property probe failed.
    pub fn unknown() -> Self {
        DeviceFacts {
            build_type: BuildType::Unknown,
            debuggable: false,
            secure: false,
            adb_secure: false,
            api_level: None,
            abi: None,
            // Conservative per android-host-probe.md §2 item 10.
            verity: VerityState::Unknown,
        }
    }
}

/// A filesystem root the Agent may reach.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FsRoot {
    /// Absolute path of the root.
    pub path: String,
    /// Confirmed writable by an actual `touch` probe, not inferred from the
    /// mount options. android-host-probe.md §2 item 7 requires both: the mount
    /// table says what *should* be writable, the touch says what *is*.
    pub writable: bool,
    /// True when this root is the Agent's own package directory. Deriving
    /// `android:fs:outside-app` depends on telling these apart.
    pub own_package: bool,
}

/// One of the evidence sources ADR-AND-001 §4.6 item 6 names.
///
/// A closed vocabulary rather than a `String` because these are the paths the ADR commits
/// to collecting, and a profile that reported an arbitrary path would be reporting something
/// no consumer asked for. The list is deliberately short: `/data/local/tmp` is already
/// covered by [`FsRoot`], and `logcat` / `dumpsys` are commands, not paths, so they are
/// probed as commands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum EvidencePath {
    /// `/data/anr` — ANR traces.
    Anr,
    /// `/data/tombstones` — native crash dumps.
    Tombstones,
    /// `/data/system/dropbox` — the system event log.
    Dropbox,
}

impl EvidencePath {
    /// Every source the probe asks about, in the order the probe script walks them.
    pub const ALL: [EvidencePath; 3] = [
        EvidencePath::Anr,
        EvidencePath::Tombstones,
        EvidencePath::Dropbox,
    ];

    /// The on-device path, as probed and as it appears in a record.
    pub fn path(&self) -> &'static str {
        match self {
            EvidencePath::Anr => "/data/anr",
            EvidencePath::Tombstones => "/data/tombstones",
            EvidencePath::Dropbox => "/data/system/dropbox",
        }
    }
}

/// How much of an evidence source this uid can actually get — measured, not assumed.
///
/// The ladder exists because the ADR's evidence list is written as though each source is
/// either available or not, and on a real device it is neither. Measured on a Huawei
/// BLA-AL00 (`user` build, uid 2000, enforcing, no root): `/data/anr` answered
/// [`Listable`](Self::Listable) — three trace files by name, every one of them `-rw-------
/// system system`, so the *index* of a hang is readable and the *trace* is not — while
/// `/data/tombstones` and `/data/system/dropbox` answered
/// [`Absent`](Self::Absent): the shell could not even stat them, which is what a SELinux
/// domain denial looks like from the inside (the kernel will not distinguish "no such file"
/// from "no such access" when the traverse is refused).
///
/// Reporting all three as "unavailable" would lose the one thing an agent can act on: an ANR
/// happened at 21:37 on 2026-07-28 is a fact worth having even when the bytes are locked,
/// and it changes what "go look at the traces" should be answered with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvidenceAccess {
    /// Not there, or not reachable enough to tell. On a enforcing device the two are the
    /// same observation, and root is the only way to tell them apart.
    Absent,
    /// The directory can be listed but its files cannot be read: names and timestamps are
    /// evidence, contents are not.
    Listable,
    /// At least one file's contents were read.
    Readable,
    /// Listable, and empty right now. Says nothing about permissions — a device with no
    /// crashes yet looks exactly like a device whose crash dir is locked from the inside.
    Empty,
    /// The probe did not run, or ran and produced nothing to go on.
    NotProbed,
}

impl EvidenceAccess {
    /// True when contents — not just names — can be collected from this source.
    pub fn has_contents(&self) -> bool {
        *self == EvidenceAccess::Readable
    }

    /// How this source reads in a tool description or a log line.
    pub fn describe(&self) -> &'static str {
        match self {
            EvidenceAccess::Absent => "not reachable",
            EvidenceAccess::Listable => "names only",
            EvidenceAccess::Readable => "readable",
            EvidenceAccess::Empty => "empty",
            EvidenceAccess::NotProbed => "not probed",
        }
    }
}

/// What the device said about its evidence sources, all of it measured at the uid the
/// probe ran as.
///
/// Two fields because the ADR's evidence list mixes two kinds of claim: "this path holds
/// the payload" and "this command dumps it". Neither is a capability and neither is a
/// command presence check — `dumpsys` is in the read vocabulary already, and knowing it
/// exists says nothing about whether the service an agent wants is running.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceSurface {
    /// One entry per [`EvidencePath::ALL`], so a source the probe never answered for is
    /// present with [`EvidenceAccess::NotProbed`] rather than missing. Absent-from-the-map
    /// and present-but-unknown are the same to a reader that forgets to check, and they are
    /// not the same fact.
    pub sources: BTreeMap<EvidencePath, EvidenceAccess>,
    /// How many services `dumpsys -l` listed. `None` when the probe did not run or the
    /// answer was not a listing.
    pub dumpsys_services: Option<usize>,
}

impl Default for EvidenceSurface {
    fn default() -> EvidenceSurface {
        EvidenceSurface {
            sources: EvidencePath::ALL
                .iter()
                .map(|p| (*p, EvidenceAccess::NotProbed))
                .collect(),
            dumpsys_services: None,
        }
    }
}

impl EvidenceSurface {
    /// The access class for one source, `NotProbed` when the map has no answer.
    pub fn access(&self, path: EvidencePath) -> EvidenceAccess {
        self.sources
            .get(&path)
            .copied()
            .unwrap_or(EvidenceAccess::NotProbed)
    }

    /// Sources whose *contents* can be collected, in the fixed path order.
    ///
    /// A method rather than a stored field: it is a filter over the map, and storing it
    /// would create a second answer that can disagree with the first.
    pub fn readable(&self) -> Vec<EvidencePath> {
        EvidencePath::ALL
            .iter()
            .filter(|p| self.access(**p).has_contents())
            .copied()
            .collect()
    }

    /// True when the probe got no answer about any evidence source.
    pub fn is_unknown(&self) -> bool {
        self.sources
            .values()
            .all(|a| *a == EvidenceAccess::NotProbed)
            && self.dumpsys_services.is_none()
    }
}

/// Parse the `EVID` lines from [`ProbeCommand::EvidenceSurface`](super::probe::ProbeCommand).
///
/// Unparsable lines are skipped rather than guessed at, and a source the device did not
/// mention comes back [`EvidenceAccess::NotProbed`] — the three states a caller can act on
/// are "we asked and this is the answer", and "we never got an answer", and they must not
/// collapse into each other.
///
/// The field order is not trusted: a probe script is text, and a future revision that
/// reorders it should not silently mis-key every value into the wrong field.
pub fn parse_evidence_surface(stdout: &str) -> Vec<(EvidencePath, EvidenceAccess)> {
    let mut found: Vec<(EvidencePath, EvidenceAccess)> = Vec::new();
    for line in stdout.lines() {
        let Some(rest) = line.strip_prefix("EVID ") else {
            continue;
        };
        let mut words = rest.split_whitespace();
        let Some(path) = words.next() else { continue };
        let Some(source) = EvidencePath::ALL.iter().find(|p| p.path() == path) else {
            continue;
        };
        // Key=value in any order; a missing key means we cannot place the source on the
        // ladder, which is NotProbed rather than a guess at the bottom rung.
        let pairs: Vec<(&str, &str)> = words.filter_map(|kv| kv.split_once('=')).collect();
        let get = |key: &str| {
            pairs
                .iter()
                .find(|(k, _)| *k == key)
                .and_then(|(_, v)| v.parse::<i32>().ok())
        };
        let (Some(exists), Some(list), Some(count), Some(read)) =
            (get("exists"), get("list"), get("count"), get("read"))
        else {
            continue;
        };
        found.push((*source, classify_evidence(exists, list, count, read)));
    }
    found
}

/// The one place the exit-code ladder becomes a fact.
///
/// Split out so the ordering is testable without reconstructing probe text.
pub fn classify_evidence(exists: i32, list: i32, count: i32, read: i32) -> EvidenceAccess {
    if exists != 0 || list != 0 {
        EvidenceAccess::Absent
    } else if count == 0 {
        EvidenceAccess::Empty
    } else if read == 0 {
        EvidenceAccess::Readable
    } else {
        EvidenceAccess::Listable
    }
}

/// Count the indented service names in a `dumpsys -l` listing.
///
/// `None`, not `Some(0)`, when the header is missing or nothing matched: a `dumpsys` that
/// refused to answer and a device with zero running services are different facts, and the
/// second one does not exist on Android.
pub fn parse_dumpsys_inventory(stdout: &str) -> Option<usize> {
    let mut lines = stdout.lines().peekable();
    if !lines.peek()?.starts_with("Currently running services") {
        return None;
    }
    let count = lines.filter(|l| l.starts_with("  ")).count();
    // A header with no services under it is not a device with no services — no Android
    // device has those — it is a truncated or unexpected listing, which is "no answer".
    (count > 0).then_some(count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_evidence_ladder_separates_names_from_contents() {
        // Verbatim shape from a Huawei BLA-AL00 (API 29, user build, uid 2000, enforcing,
        // no root). `/data/anr` lists three traces and refuses every one of their bytes;
        // the other two sources cannot even be statted, because a refused directory
        // traverse looks identical to a missing path from outside the domain.
        let device = "\
EVID /data/anr exists=0 list=0 count=3 read=1
EVID /data/tombstones exists=1 list=1 count=0 read=2
EVID /data/system/dropbox exists=1 list=1 count=0 read=2
";
        let parsed = parse_evidence_surface(device);
        assert_eq!(
            parsed,
            vec![
                (EvidencePath::Anr, EvidenceAccess::Listable),
                (EvidencePath::Tombstones, EvidenceAccess::Absent),
                (EvidencePath::Dropbox, EvidenceAccess::Absent),
            ]
        );
        // The distinction the whole type exists for: names are evidence, and a flat
        // "available / not available" would have thrown the ANR index away.
        assert!(!parsed[0].1.has_contents());
        assert!(parsed[0].1 != EvidenceAccess::Absent);
    }

    #[test]
    fn root_reads_what_shell_only_lists() {
        let root = "EVID /data/anr exists=0 list=0 count=3 read=0\n";
        assert_eq!(
            parse_evidence_surface(root),
            vec![(EvidencePath::Anr, EvidenceAccess::Readable)]
        );
    }

    #[test]
    fn an_empty_crash_directory_is_not_a_denial() {
        // A healthy device and a locked one both answer `count=0`, and collapsing them would
        // tell an agent "you cannot read traces here" when the truth is "there are none yet".
        // The difference only shows up once a crash happens, which is exactly when it matters.
        let empty = "EVID /data/anr exists=0 list=0 count=0 read=2\n";
        assert_eq!(
            parse_evidence_surface(empty),
            vec![(EvidencePath::Anr, EvidenceAccess::Empty)]
        );
        assert_eq!(classify_evidence(0, 0, 0, 2), EvidenceAccess::Empty);
        assert_eq!(classify_evidence(1, 1, 0, 2), EvidenceAccess::Absent);
    }

    #[test]
    fn evidence_lines_that_do_not_parse_are_dropped_not_guessed() {
        // A source the device never mentioned must come back `NotProbed` from the assembler,
        // not `Absent` — `Absent` is a claim about the filesystem that nothing observed.
        let junk = "\
ls: /data/anr: Permission denied
EVID /data/unknown exists=0 list=0 count=1 read=0
EVID /data/anr exists=0 list=0
EVID /data/tombstones exists=abc list=0 count=1 read=0
EVID /data/system/dropbox exists=0 list=0 count=2 read=1
";
        assert_eq!(
            parse_evidence_surface(junk),
            vec![(EvidencePath::Dropbox, EvidenceAccess::Listable)],
            "only the one complete, known line may survive"
        );
        assert!(parse_evidence_surface("").is_empty());
    }

    #[test]
    fn evidence_fields_are_matched_by_name_not_position() {
        // The probe script is text and its field order is not a contract. Reading these
        // positionally would put a `read` rc into the `exists` slot and report a readable
        // directory as absent.
        let reordered = "EVID /data/anr read=1 count=3 list=0 exists=0\n";
        assert_eq!(
            parse_evidence_surface(reordered),
            vec![(EvidencePath::Anr, EvidenceAccess::Listable)]
        );
    }

    #[test]
    fn an_unanswered_source_is_present_as_not_probed() {
        // The map is keyed by the fixed vocabulary, so "we never got an answer" is a value
        // rather than an absent key. A caller that wrote `.get()` and treated `None` as
        // "unavailable" would tell an agent the device has no ANR directory when the truth
        // is that the port never managed to ask.
        let surface = EvidenceSurface::default();
        assert_eq!(surface.access(EvidencePath::Anr), EvidenceAccess::NotProbed);
        assert!(surface.is_unknown());
        assert!(surface.readable().is_empty());

        let mut surface = EvidenceSurface::default();
        surface
            .sources
            .insert(EvidencePath::Anr, EvidenceAccess::Readable);
        surface.dumpsys_services = Some(246);
        assert!(!surface.is_unknown());
        assert_eq!(surface.readable(), vec![EvidencePath::Anr]);
        // Order comes from the fixed vocabulary, not from insertion, so a description built
        // from it is deterministic across devices.
        surface
            .sources
            .insert(EvidencePath::Tombstones, EvidenceAccess::Readable);
        assert_eq!(
            surface.readable(),
            vec![EvidencePath::Anr, EvidencePath::Tombstones]
        );
    }

    #[test]
    fn dumpsys_inventory_requires_its_header() {
        let device = "Currently running services:\n  SurfaceFlinger\n  activity\n  window\n";
        assert_eq!(parse_dumpsys_inventory(device), Some(3));
        // No header: `dumpsys` refused, printed a usage line, or is not on this device.
        assert_eq!(parse_dumpsys_inventory(""), None);
        assert_eq!(parse_dumpsys_inventory("Can't find service: -l\n"), None);
        // Header with nothing under it is not "zero services" — no Android device has those,
        // so the honest answer is that the listing is not trustworthy.
        assert_eq!(
            parse_dumpsys_inventory("Currently running services:\n"),
            None
        );
    }

    #[test]
    fn uid_mapping_covers_the_three_privilege_levels() {
        assert_eq!(Privilege::parse_uid("0\n"), Some(Privilege::Root));
        assert_eq!(Privilege::parse_uid("2000"), Some(Privilege::ShellUid));
        assert_eq!(Privilege::parse_uid("10233"), Some(Privilege::AppUid));
    }

    #[test]
    fn uid_parse_degrades_to_none_on_garbage() {
        assert_eq!(Privilege::parse_uid(""), None);
        assert_eq!(Privilege::parse_uid("id: not found"), None);
    }

    #[test]
    fn privilege_ordering_matches_the_derivation_rules() {
        assert!(Privilege::Root > Privilege::ShellUid);
        assert!(Privilege::ShellUid > Privilege::AppUid);
    }

    #[test]
    fn getenforce_missing_command_is_unknown_not_permissive() {
        assert_eq!(SelinuxState::parse("Enforcing"), SelinuxState::Enforcing);
        assert_eq!(
            SelinuxState::parse("permissive\n"),
            SelinuxState::Permissive
        );
        assert_eq!(SelinuxState::parse(""), SelinuxState::Unknown);
        assert_eq!(
            SelinuxState::parse("getenforce: not found"),
            SelinuxState::Unknown
        );
        assert!(!SelinuxState::Unknown.known());
    }

    #[test]
    fn verity_accepts_both_spellings_and_defaults_conservatively() {
        assert_eq!(VerityState::parse("enforcing"), VerityState::Enforcing);
        assert_eq!(VerityState::parse("e"), VerityState::Enforcing);
        assert_eq!(VerityState::parse("logging"), VerityState::NotEnforcing);
        assert_eq!(VerityState::parse("disabled"), VerityState::NotEnforcing);
        assert_eq!(VerityState::parse(""), VerityState::Unknown);
        // Unknown must block a system write, exactly like Enforcing.
        assert!(VerityState::Unknown.blocks_system_write());
        assert!(VerityState::Enforcing.blocks_system_write());
        assert!(!VerityState::NotEnforcing.blocks_system_write());
    }

    #[test]
    fn build_type_parse() {
        assert_eq!(BuildType::parse("userdebug"), BuildType::UserDebug);
        assert_eq!(BuildType::parse("user\n"), BuildType::User);
        assert_eq!(BuildType::parse("eng"), BuildType::Eng);
        assert_eq!(BuildType::parse(""), BuildType::Unknown);
    }

    #[test]
    fn shell_banner_classification() {
        assert_eq!(
            ShellDialect::parse_version_banner("@(#)MIRBSD KSH R59 2020/10/31"),
            Some(ShellDialect::MkSh)
        );
        assert_eq!(
            ShellDialect::parse_version_banner(
                "GNU bash, version 5.2.15(1)-release (aarch64-linux-android)"
            ),
            Some(ShellDialect::Bash)
        );
        assert_eq!(
            ShellDialect::parse_version_banner(
                "BusyBox v1.34.1 (2022-01-01 00:00:00 UTC) multi-call binary."
            ),
            Some(ShellDialect::BusyBoxSh)
        );
        // Unrecognised => None, never a guessed dialect.
        assert_eq!(ShellDialect::parse_version_banner(""), None);
        assert_eq!(ShellDialect::parse_version_banner("sh: unknown flag"), None);
    }

    /// The labelled form is what probe item 5b now returns, because `/system/bin/sh
    /// --version` is not an option on a real device. Captured from a Huawei BLA-AL00 (API 29).
    #[test]
    fn labelled_shell_identity_is_read_from_the_variable_that_is_set() {
        let real = "KSH=@(#)MIRBSD KSH R57 2019-03-01 Android\nBASH=\n";
        assert_eq!(
            ShellDialect::parse_version_banner(real),
            Some(ShellDialect::MkSh)
        );

        // A Termux install whose platform shell is still mksh but whose *runner* is bash.
        assert_eq!(
            ShellDialect::parse_version_banner(
                "KSH=\nBASH=GNU bash, version 5.1.16(1)-release (aarch64-linux-android)\n"
            ),
            Some(ShellDialect::Bash)
        );

        // An empty value is evidence of absence, not a match on the label's own text.
        assert_eq!(ShellDialect::parse_version_banner("KSH=\nBASH=\n"), None);
        assert_eq!(ShellDialect::parse_version_banner("KSH=\n"), None);
        // Busybox ash sets neither, so the probe says nothing and the dialect stays unknown.
        assert_eq!(
            ShellDialect::parse_version_banner("KSH=\nBASH=\n"),
            None,
            "an unnameable shell must be reported as unknown, not defaulted"
        );
    }

    #[test]
    fn applet_list_parses_toybox_one_per_line() {
        let set = AppletSet::parse_list("acpi\nbasename\ncat\nchmod\n");
        assert!(set.contains("cat"));
        assert!(set.contains("chmod"));
        assert_eq!(set.len(), 4);
        assert!(!set.list_source_missing);
    }

    #[test]
    fn applet_list_parses_busybox_multicolumn_with_banner() {
        let raw = "BusyBox v1.34.1 (2022) multi-call binary.\n\
                   Currently defined functions:\n\
                   [, [[, acpi, adjtimex, arp, ash, awk, basename, cat, chgrp\n";
        let set = AppletSet::parse_list(raw);
        assert!(set.contains("ash"));
        assert!(set.contains("basename"));
        assert!(
            !set.contains("BusyBox"),
            "banner prose must not become applets"
        );
        assert!(!set.list_source_missing);
    }

    #[test]
    fn applet_list_empty_output_flags_missing_source() {
        let set = AppletSet::parse_list("");
        assert!(set.list_source_missing);
        assert!(set.is_empty());
    }

    #[test]
    fn applet_merge_only_loses_source_when_both_sides_lack_one() {
        let mut a = AppletSet::parse_list("cat\nls\n");
        let b = AppletSet::parse_list("");
        a.merge(&b);
        assert!(a.contains("cat"));
        assert!(!a.list_source_missing);

        let mut c = AppletSet::parse_list("");
        c.merge(&AppletSet::parse_list(""));
        assert!(c.list_source_missing);
    }

    #[test]
    fn mount_parse_human_format() {
        let raw = "/dev/block/dm-0 on / type ext4 (ro,seclabel,relatime)\n\
                   tmpfs on /dev type tmpfs (rw,seclabel,nosuid)\n\
                   /dev/block/sda1 on /data type f2fs (rw,seclabel,lazytime)\n";
        let table = parse_mount_table(raw);
        assert_eq!(table.len(), 3);
        assert_eq!(table[0].mount_point, "/");
        assert!(!table[0].read_write);
        assert!(table[1].read_write);
        assert_eq!(table[2].mount_point, "/data");
        assert_eq!(table[2].fs_type, "f2fs");
        assert!(table[2].read_write);
    }

    #[test]
    fn mount_parse_procfs_format() {
        let raw = "/dev/block/sda1 /data f2fs rw,seclabel 0 0\n\
                   /dev/block/dm-0 /system ext4 ro,seclabel 0 0\n";
        let table = parse_mount_table(raw);
        assert_eq!(table.len(), 2);
        assert!(table[0].read_write);
        assert!(!table[1].read_write);
        assert_eq!(table[1].mount_point, "/system");
    }

    #[test]
    fn mount_parse_unescapes_octal_spaces() {
        let table = parse_mount_table("tmpfs on /mnt/my\\040dir type tmpfs (rw)\n");
        assert_eq!(table[0].mount_point, "/mnt/my dir");
    }

    #[test]
    fn mount_parse_ignores_a_lone_ro_substring_option() {
        // `user_xattr,ro_thing` style tokens must not flip the verdict; only the
        // first option decides.
        let table = parse_mount_table("dev on /mnt type vfat (ro,user_xattr)\n");
        assert!(!table[0].read_write);
        let table = parse_mount_table("dev on /mnt type vfat (rw,relatime)\n");
        assert!(table[0].read_write);
    }

    #[test]
    fn mount_parse_survives_garbage_lines() {
        assert!(parse_mount_table("mount: not found\n\n").is_empty());
    }

    #[test]
    fn bool_prop_accepts_both_conventions() {
        assert!(parse_bool_prop("1"));
        assert!(parse_bool_prop("true\n"));
        assert!(!parse_bool_prop("0"));
        assert!(!parse_bool_prop(""));
        assert!(!parse_bool_prop("false"));
    }

    #[test]
    fn prop_parse_treats_empty_as_absent() {
        assert_eq!(parse_prop("28\n").as_deref(), Some("28"));
        assert_eq!(parse_prop(""), None);
        assert_eq!(parse_prop("   "), None);
    }

    #[test]
    fn su_probe_records_uid_and_domain_separately() {
        let p = parse_su_probe("0\nu:r:magisk:s0\n", "", false);
        assert!(p.got_root());
        assert_eq!(p.context.as_deref(), Some("u:r:magisk:s0"));
        assert!(!p.prompt_denied);
    }

    #[test]
    fn su_probe_prompt_denial_is_not_retryable() {
        let p = parse_su_probe("", "/system/bin/sh: su: Permission denied", false);
        assert!(p.prompt_denied);
        assert!(!p.got_root());
        assert!(!p.unavailable, "denied != absent: the binary is there");
    }

    #[test]
    fn su_probe_absent_binary() {
        let p = parse_su_probe("", "su: not found", false);
        assert!(p.unavailable);
        assert!(!p.prompt_denied);
    }

    #[test]
    fn su_probe_timeout_is_unavailable() {
        let p = parse_su_probe("", "", true);
        assert!(p.unavailable);
        assert!(!p.prompt_denied);
    }

    #[test]
    fn su_probe_tolerates_missing_context_line() {
        let p = parse_su_probe("0\n", "", false);
        assert!(p.got_root());
        assert_eq!(p.context, None);
    }

    #[test]
    fn su_probe_empty_output_is_unavailable_not_root() {
        let p = parse_su_probe("", "", false);
        assert!(p.unavailable);
        assert!(!p.got_root());
    }

    #[test]
    fn domain_classification() {
        assert_eq!(
            SelinuxDomain::parse("u:r:untrusted_app:s0:c123,c456"),
            SelinuxDomain::UntrustedApp
        );
        assert_eq!(
            SelinuxDomain::parse("u:r:untrusted_app_32:s0:c123"),
            SelinuxDomain::UntrustedApp
        );
        assert_eq!(SelinuxDomain::parse("u:r:shell:s0"), SelinuxDomain::Shell);
        assert_eq!(SelinuxDomain::parse("u:r:magisk:s0"), SelinuxDomain::Magisk);
        assert!(SelinuxDomain::Magisk.is_privileged());
        assert!(!SelinuxDomain::Shell.is_privileged());
        assert_eq!(
            SelinuxDomain::parse("u:r:platform_app:s0"),
            SelinuxDomain::Other("platform_app".to_string())
        );
        assert_eq!(SelinuxDomain::parse(""), SelinuxDomain::Unreadable);
        assert!(!SelinuxDomain::Unreadable.is_privileged());
    }

    /// The kernel terminates a security-context read with NUL rather than a newline. This
    /// is a captured byte-for-byte result, not a guess: on a Huawei BLA-AL00 (API 29),
    /// `cat /proc/self/attr/current` emits `u:r:shell:s0\0` and nothing else.
    #[test]
    fn context_normalization_strips_the_kernels_nul_terminator() {
        let real = "u:r:shell:s0\0";
        assert_eq!(normalize_context(real), Some("u:r:shell:s0"));
        // The shapes a shell or a second read can add around it.
        assert_eq!(normalize_context("u:r:su:s0\0\n"), Some("u:r:su:s0"));
        assert_eq!(normalize_context("\n"), None);
        assert_eq!(normalize_context("\0"), None);
        assert_eq!(normalize_context("   \0  "), None);
        // Classification survives the terminator too. Before this, the trailing NUL sat in
        // the fourth field and happened not to matter — a fact pinned so that a future
        // context shape with fewer fields cannot quietly start reporting `Other`.
        assert_eq!(SelinuxDomain::parse(real), SelinuxDomain::Shell);
        assert_eq!(
            SelinuxDomain::parse("u:r:magisk\0"),
            SelinuxDomain::Magisk,
            "a context without a level field must not lose its NUL to the domain name"
        );
    }
}
