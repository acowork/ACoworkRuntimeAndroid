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

use std::collections::BTreeSet;

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

    /// Classify a `sh --version` banner.
    ///
    /// Returns `None` for an empty or unrecognised banner rather than defaulting
    /// to a dialect: a wrong dialect in the tool description teaches the model
    /// syntax that will not run.
    pub fn parse_version_banner(raw: &str) -> Option<ShellDialect> {
        let text = raw.trim();
        if text.is_empty() {
            return None;
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

    let err = stderr.to_ascii_lowercase();
    // Magisk / KernelSU denial wordings. Kept as a substring match because the
    // exact text varies by version and by whether a manager app is installed.
    let denied = [
        "denied",
        "permission denied",
        "not allowed",
        "rejected",
        "cancelled",
    ]
    .iter()
    .any(|needle| err.contains(needle));
    let missing = ["not found", "no such file", "inaccessible", "not available"]
        .iter()
        .any(|needle| err.contains(needle));

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

impl SelinuxDomain {
    /// Classify a raw `/proc/self/attr/current` value.
    pub fn parse(raw: &str) -> SelinuxDomain {
        let ctx = raw.trim();
        if ctx.is_empty() {
            return SelinuxDomain::Unreadable;
        }
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
