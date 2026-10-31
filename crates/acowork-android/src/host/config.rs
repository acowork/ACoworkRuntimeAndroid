//! The operator's knobs, in one place, with their bounds written down.
//!
//! # The two columns
//!
//! Two kinds of value reach an Android runtime, and only one of them is a person's decision:
//!
//! | question | who answers it | type |
//! |---|---|---|
//! | What **is** this device — rooted? enforcing? which applets, which writable roots? | the device, by being probed | [`HostProfile`] |
//! | What is this runtime **allowed** to do, how long may it take, how much space may it keep? | a person, on a screen | [`HostConfig`] |
//!
//! The whole design of this module follows from keeping the columns apart. A settings screen
//! that could set the left one would be a screen with a text box labelled "rooted", and typing
//! `true` into it would get you root: [`derive_claims`]
//! reads the profile, so a hand-written profile is a hand-written capability claim. That is
//! precisely the 能力谎报 the readiness assessment calls worse than having no capability at all.
//! So nothing here is an input to the probe, to the classification of a command, or to the gate's
//! reading of what a script does.
//!
//! # The three rules
//!
//! 1. **Settings narrow; they never widen.** [`HostConfig::claims`] intersects the ceiling the
//!    operator chose with what the probe earned. Turning `android:fs:system` *on* on a device
//!    that has no root changes nothing, because the intersection has the profile as one of its
//!    two operands and that operand is not editable. This is a structural property, not a
//!    validation rule, and it is asserted by a test rather than by a comment.
//! 2. **Paths are subdirectories of a host-supplied root.** The settings file carries names
//!    (`"snapshots"`), never absolute paths. The node passes the root it owns — the app's
//!    private data directory on the device, the Agent workspace when the node runs on a desktop
//!    driving a phone over adb. A screen that accepted `/data/system/x.conf` would be an
//!    arbitrary-write primitive living inside the most privileged component of the product, and
//!    it would be *the* CVE of this port.
//! 3. **`dangerous-mode` is not in here.** It is a per-session switch, never persisted
//!    ([`LocalReadiness`](acowork_platform_contract::LocalReadiness) says so; ADR-AND-001 §7.3
//!    decided the APK gets no UI for it). A "remember this choice" checkbox next to the switch
//!    that unlocks writing the system partition is the most attractive way to break the port's
//!    own rule, so the rule is enforced by the type having no such field — and by a test that
//!    refuses a settings file which tries to set one.
//!
//! # What the bounds are for
//!
//! Every tunable has a minimum and a maximum. The maximum exists because a settings screen is
//! how somebody accidentally asks for a 4 GB snapshot store on a phone with 11 GB free, and the
//! failure surfaces as an `ENOSPC` in the middle of a restore. The minimum exists because the
//! numbers in this crate are measurements, not tastes: a command timeout below a second will
//! fire on a device that is merely busy, and an audit cap below 32 KiB cannot hold the ~130
//! records that make a session reconstructable. Bounds are where the measurements are kept
//! honest about being configurable at all.
//!
//! # Assembly
//!
//! [`HostConfig::prepare`] is the point where the settings stop being data and start being
//! objects: it creates the directories and builds the audit sink and the snapshot store.
//! [`HostConfig::assemble`] then puts them into the decorator chain. Creating the directories
//! eagerly, at startup rather than at the first write, is deliberate: a snapshot directory that
//! does not exist is a fact best learned while there is still nothing to undo.

use std::collections::BTreeSet;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::host::{
    AuditSink, BackendError, Capability, DEFAULT_EVIDENCE_BUDGET, DEFAULT_MAX_FILE_BYTES,
    DEFAULT_OUTPUT_CAP, DEFAULT_READ_TIMEOUT, EvidenceSource, ExecutionBackend, FileAuditSink,
    HostProfile, SNAPSHOT_STORE_BUDGET_BYTES, SnapshotStore, WRITE_LOCK_TTL, chain, derive_claims,
    evidence, lookup,
};
use acowork_platform_contract::{Budget, CapabilityClaim, HostCapability};

/// Where a bounded number stops being a preference.
///
/// The units below are named, not written as `1048576`, because the reader of a settings screen
/// and the reader of this file need to be able to check the same claim: "eight megabytes", not
/// "some number that worked in a test".
const KIB: u64 = 1024;
const MIB: u64 = 1024 * KIB;
const GIB: u64 = 1024 * MIB;

/// Smallest snapshot store worth configuring.
///
/// One snapshot of one file is up to [`SNAPSHOT_BUDGET_BYTES`](crate::host::SNAPSHOT_BUDGET_BYTES)
/// of base64; below 64 KiB the store can hold fewer than two backups and every third edit of
/// any file refuses itself.
pub const SNAPSHOT_STORE_MIN: u64 = 64 * KIB;
/// Largest snapshot store that is a decision rather than a disk-usage incident.
pub const SNAPSHOT_STORE_MAX: u64 = GIB;

/// Smallest audit file that can still reconstruct a session (~130 records at ~250 bytes).
pub const AUDIT_FILE_MIN: u64 = 32 * KIB;
/// Largest audit file worth keeping on a phone indefinitely.
pub const AUDIT_FILE_MAX: u64 = 256 * MIB;

/// Smallest evidence budget that can hold a screenshot plus a logcat tail.
pub const EVIDENCE_BUDGET_MIN: u64 = 256 * KIB;
/// Largest evidence budget before "capture" means "copy the device".
pub const EVIDENCE_BUDGET_MAX: u64 = 512 * MIB;

/// Smallest per-command output cap.
pub const OUTPUT_CAP_MIN: u64 = 4 * KIB;
/// Largest per-command output cap. Above this, a `dumpsys` answer is being kept for a reason
/// the audit trail should not carry.
pub const OUTPUT_CAP_MAX: u64 = 64 * MIB;

/// Shortest command timeout. Below a second, a busy device times out commands that succeeded.
pub const COMMAND_TIMEOUT_MIN: u64 = 1;
/// Longest command timeout. Anything longer is an evidence capture and has its own budget.
pub const COMMAND_TIMEOUT_MAX: u64 = 600;

/// Shortest write-lock TTL. The lock is a *dead-man* switch: it must outlive one slow command
/// and be reclaimable soon after a process that stopped answering.
pub const LOCK_TTL_MIN: u64 = 30;
/// Longest write-lock TTL. A lock held longer than an hour without renewal is a bug, not a session.
pub const LOCK_TTL_MAX: u64 = 3600;

/// Shortest bugreport timeout. Measured at 1 m 44 s on a Huawei BLA-AL00; below 30 s the
/// capture cannot finish on the device this number came from.
pub const BUGREPORT_TIMEOUT_MIN: u64 = 30;
/// Longest bugreport timeout. Past fifteen minutes the report is not being waited for.
pub const BUGREPORT_TIMEOUT_MAX: u64 = 900;

/// Largest `logcat -t` the settings may ask for. `0` means "the whole buffer" and is allowed.
pub const LOGCAT_TAIL_MAX: u32 = 100_000;

/// Longest storage subdirectory name.
pub const SUBDIR_MAX: usize = 64;

/// The name of the audit file inside [`StorageConfig::audit_subdir`].
pub const AUDIT_FILE_NAME: &str = "audit.jsonl";

/// Everything a person may set about this runtime.
///
/// Serialised as JSON so the settings screen and the CLI edit the same document; `deny_unknown_fields`
/// everywhere because a settings file that silently ignores `snapshort_store_bytes` is a screen
/// that shows a value which is not in force.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HostConfig {
    /// Where the runtime keeps its own bytes.
    pub storage: StorageConfig,
    /// How much of them it may keep.
    pub budgets: BudgetConfig,
    /// How long it may take.
    pub timing: TimingConfig,
    /// Which evidence sources it may collect.
    pub evidence: EvidenceConfig,
    /// The capability ceiling: capability ids this runtime is willing to be asked for.
    ///
    /// Wire ids (`android:fs:system`), so the screen shows exactly what the Gateway will see.
    pub capability_ceiling: Vec<String>,
}

/// Where the runtime's own files go, relative to a root the host supplies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct StorageConfig {
    /// Subdirectory holding pre-write snapshots.
    pub snapshot_subdir: String,
    /// Subdirectory holding the audit trail.
    pub audit_subdir: String,
    /// Subdirectory holding captured evidence.
    pub evidence_subdir: String,
}

/// Size ceilings, in bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BudgetConfig {
    /// Total bytes of pre-write backups one session set may keep.
    pub snapshot_store_bytes: u64,
    /// Ceiling for the audit file before it rotates.
    pub audit_file_bytes: u64,
    /// Ceiling for one evidence capture.
    pub evidence_budget_bytes: u64,
    /// Ceiling for one command's captured output.
    pub output_cap_bytes: u64,
}

/// Time ceilings, in whole seconds.
///
/// Seconds rather than a duration type: a settings screen shows a number of seconds, and the
/// port's measured defaults are whole seconds too. Read the typed value through the accessors.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TimingConfig {
    /// Budget for one command.
    pub command_timeout_secs: u64,
    /// How long a write lock survives without renewal.
    pub lock_ttl_secs: u64,
    /// Budget for a `bugreportz` capture, which exceeds every other budget in the crate.
    pub bugreport_timeout_secs: u64,
}

/// Which evidence sources may be collected, and how much of them.
///
/// This is the one section that is a privacy decision rather than a capacity decision, so it is
/// the one section whose defaults are all *narrow*: a runtime that volunteers to pull the phone's
/// logs and the phone's screen to a desktop is a runtime nobody would install.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct EvidenceConfig {
    /// `screencap -p` — what is on the display right now.
    pub screenshot: bool,
    /// `logcat -d`.
    pub logcat: bool,
    /// Lines of logcat to keep when the caller did not say. `0` means the whole buffer.
    pub logcat_tail_lines: u32,
    /// `dumpsys <service>`.
    pub dumpsys: bool,
    /// A file already on the device, read directly. Off by default: the paths this means
    /// (`/data/anr/*`, `/data/local/tmp/*`) are other processes' stacks and other tools'
    /// scratch, and reading one is a privacy event even when no approval is needed for it.
    pub device_files: bool,
    /// `bugreportz` — the whole device in one zip. Off by default: it is the largest, slowest
    /// and most personal artifact the port can ask for.
    pub bugreport: bool,
}

impl Default for HostConfig {
    fn default() -> Self {
        HostConfig {
            storage: StorageConfig::default(),
            budgets: BudgetConfig::default(),
            timing: TimingConfig::default(),
            evidence: EvidenceConfig::default(),
            // The three tiers that need nothing beyond the session's own approval. The two
            // system-tier capabilities are absent, which is §7.4's "默认拒绝" expressed as a
            // default value rather than as a runtime check.
            capability_ceiling: vec![
                Capability::ShellRead.id().as_str().to_string(),
                Capability::ShellWrite.id().as_str().to_string(),
                Capability::FsOutsideApp.id().as_str().to_string(),
            ],
        }
    }
}

impl Default for StorageConfig {
    fn default() -> Self {
        StorageConfig {
            snapshot_subdir: "snapshots".to_string(),
            audit_subdir: "audit".to_string(),
            evidence_subdir: "evidence".to_string(),
        }
    }
}

impl Default for BudgetConfig {
    fn default() -> Self {
        BudgetConfig {
            snapshot_store_bytes: SNAPSHOT_STORE_BUDGET_BYTES,
            audit_file_bytes: DEFAULT_MAX_FILE_BYTES,
            evidence_budget_bytes: DEFAULT_EVIDENCE_BUDGET,
            output_cap_bytes: DEFAULT_OUTPUT_CAP as u64,
        }
    }
}

impl Default for TimingConfig {
    fn default() -> Self {
        TimingConfig {
            command_timeout_secs: DEFAULT_READ_TIMEOUT.as_secs(),
            lock_ttl_secs: WRITE_LOCK_TTL.as_secs(),
            bugreport_timeout_secs: evidence::BUGREPORT_TIMEOUT.as_secs(),
        }
    }
}

impl Default for EvidenceConfig {
    fn default() -> Self {
        EvidenceConfig {
            screenshot: true,
            logcat: true,
            logcat_tail_lines: 200,
            dumpsys: true,
            device_files: false,
            bugreport: false,
        }
    }
}

/// One rejected setting: which knob, and why.
///
/// `field` is a dotted path (`"budgets.snapshot_store_bytes"`) rather than a parse position,
/// because its consumer is a settings screen that has to highlight a row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError {
    /// The setting this error is about, as a dotted path. `""` when the document itself is the
    /// problem (unparseable JSON).
    pub field: String,
    /// What is wrong, in terms a screen can show next to the field.
    pub reason: String,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.field.is_empty() {
            write!(f, "the settings document is invalid: {}", self.reason)
        } else {
            write!(f, "{}: {}", self.field, self.reason)
        }
    }
}

impl std::error::Error for ConfigError {}

impl ConfigError {
    fn new(field: impl Into<String>, reason: impl Into<String>) -> ConfigError {
        ConfigError {
            field: field.into(),
            reason: reason.into(),
        }
    }
}

/// Why a runtime could not be assembled from a settings document.
#[derive(Debug)]
pub enum AssemblyError {
    /// A setting was out of bounds, or the ceiling named a capability the port does not know.
    Config(ConfigError),
    /// The directories could not be created.
    Storage(std::io::Error),
    /// The profile cannot host this chain — no shell on a device asked for a shell backend.
    Backend(BackendError),
}

impl fmt::Display for AssemblyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AssemblyError::Config(err) => write!(f, "{err}"),
            AssemblyError::Storage(err) => {
                write!(
                    f,
                    "the runtime's own directories could not be created: {err}"
                )
            }
            AssemblyError::Backend(err) => write!(f, "the chain could not be built: {err}"),
        }
    }
}

impl std::error::Error for AssemblyError {}

impl From<ConfigError> for AssemblyError {
    fn from(err: ConfigError) -> Self {
        AssemblyError::Config(err)
    }
}

impl From<std::io::Error> for AssemblyError {
    fn from(err: std::io::Error) -> Self {
        AssemblyError::Storage(err)
    }
}

impl From<BackendError> for AssemblyError {
    fn from(err: BackendError) -> Self {
        AssemblyError::Backend(err)
    }
}

/// Check that a number sits inside the range that is a decision rather than a mistake.
fn check_range(field: &str, value: u64, min: u64, max: u64, unit: &str) -> Result<(), ConfigError> {
    if value < min || value > max {
        return Err(ConfigError::new(
            field,
            format!("{value} {unit} is outside the supported range {min}..={max} {unit}"),
        ));
    }
    Ok(())
}

/// Check one storage subdirectory name.
///
/// Absolute paths, separators, `.` and `..` are all refused, and the refusal says why: the root
/// is the host's, and a name that can contain a separator is a name that can leave it.
fn check_subdir(field: &str, name: &str) -> Result<(), ConfigError> {
    if name.is_empty() {
        return Err(ConfigError::new(
            field,
            "a directory name is required; the runtime's files cannot live in the root itself",
        ));
    }
    if name.len() > SUBDIR_MAX {
        return Err(ConfigError::new(
            field,
            format!("a directory name longer than {SUBDIR_MAX} characters is not a name"),
        ));
    }
    if name.starts_with('/') || name.contains('/') || name.contains('\\') {
        return Err(ConfigError::new(
            field,
            format!(
                "`{name}` is a path, not a directory name. This document holds names only: the \
                 root is supplied by the host (the app's private data directory on the device, \
                 the Agent workspace when driving a phone over adb), so a setting cannot point \
                 the runtime's own files somewhere nobody agreed to give it."
            ),
        ));
    }
    if name == "." || name == ".." {
        return Err(ConfigError::new(
            field,
            format!("`{name}` would place the runtime's files outside the host's root"),
        ));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        return Err(ConfigError::new(
            field,
            format!(
                "`{name}` uses characters outside ASCII letters, digits, `-`, `_`, `.`; these \
                 names are joined into paths and into file names by other components"
            ),
        ));
    }
    Ok(())
}

impl HostConfig {
    /// Parse and validate a settings document.
    ///
    /// Validation is not a separate courtesy: a document that parses but carries a
    /// zero-byte audit cap is constructible only if `from_json` checks, and the alternative is
    /// a runtime that discovers its settings are impossible while it is writing the record that
    /// would explain the failure.
    pub fn from_json(text: &str) -> Result<HostConfig, ConfigError> {
        let config: HostConfig = serde_json::from_str(text).map_err(|err| ConfigError {
            field: String::new(),
            reason: err.to_string(),
        })?;
        config.validate()?;
        Ok(config)
    }

    /// Render back to a settings document.
    pub fn to_json(&self) -> Result<String, ConfigError> {
        serde_json::to_string_pretty(self).map_err(|err| {
            ConfigError::new("", format!("the settings could not be written: {err}"))
        })
    }

    /// The default document, validated.
    pub fn defaults() -> HostConfig {
        HostConfig::default()
    }

    /// Reject out-of-bounds settings, path-shaped directory names and unknown capability ids.
    pub fn validate(&self) -> Result<(), ConfigError> {
        check_subdir("storage.snapshot_subdir", &self.storage.snapshot_subdir)?;
        check_subdir("storage.audit_subdir", &self.storage.audit_subdir)?;
        check_subdir("storage.evidence_subdir", &self.storage.evidence_subdir)?;

        check_range(
            "budgets.snapshot_store_bytes",
            self.budgets.snapshot_store_bytes,
            SNAPSHOT_STORE_MIN,
            SNAPSHOT_STORE_MAX,
            "bytes",
        )?;
        check_range(
            "budgets.audit_file_bytes",
            self.budgets.audit_file_bytes,
            AUDIT_FILE_MIN,
            AUDIT_FILE_MAX,
            "bytes",
        )?;
        check_range(
            "budgets.evidence_budget_bytes",
            self.budgets.evidence_budget_bytes,
            EVIDENCE_BUDGET_MIN,
            EVIDENCE_BUDGET_MAX,
            "bytes",
        )?;
        check_range(
            "budgets.output_cap_bytes",
            self.budgets.output_cap_bytes,
            OUTPUT_CAP_MIN,
            OUTPUT_CAP_MAX,
            "bytes",
        )?;

        check_range(
            "timing.command_timeout_secs",
            self.timing.command_timeout_secs,
            COMMAND_TIMEOUT_MIN,
            COMMAND_TIMEOUT_MAX,
            "seconds",
        )?;
        check_range(
            "timing.lock_ttl_secs",
            self.timing.lock_ttl_secs,
            LOCK_TTL_MIN,
            LOCK_TTL_MAX,
            "seconds",
        )?;
        check_range(
            "timing.bugreport_timeout_secs",
            self.timing.bugreport_timeout_secs,
            BUGREPORT_TIMEOUT_MIN,
            BUGREPORT_TIMEOUT_MAX,
            "seconds",
        )?;

        if self.evidence.logcat_tail_lines > LOGCAT_TAIL_MAX {
            return Err(ConfigError::new(
                "evidence.logcat_tail_lines",
                format!(
                    "{} lines is more than the {} this screen may ask for; `0` means the whole \
                     buffer and is the honest way to ask for everything",
                    self.evidence.logcat_tail_lines, LOGCAT_TAIL_MAX
                ),
            ));
        }

        // The ceiling is checked by resolving it, not by pattern-matching it: an id that parses
        // but is not in the Android vocabulary would silently claim nothing forever.
        self.ceiling()?;
        Ok(())
    }

    /// The capability ceiling as resolved capabilities.
    ///
    /// Unknown ids are an error rather than a skip: a ceiling naming `android:fs:sytem` (one
    /// letter short) reads as "system writes are allowed" to whoever set it and does nothing.
    pub fn ceiling(&self) -> Result<BTreeSet<Capability>, ConfigError> {
        let mut set = BTreeSet::new();
        for id in &self.capability_ceiling {
            let parsed = HostCapability::parse(id).map_err(|err| {
                ConfigError::new(
                    "capability_ceiling",
                    format!("`{id}` is not a `<platform>:<name>` capability id ({err})"),
                )
            })?;
            let Some(cap) = lookup(&parsed) else {
                return Err(ConfigError::new(
                    "capability_ceiling",
                    format!(
                        "`{id}` is not in the Android vocabulary; this port knows {}",
                        Capability::all()
                            .iter()
                            .map(|c| c.id().to_string())
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                ));
            };
            set.insert(cap);
        }
        Ok(set)
    }

    /// What this runtime may claim: the device's earned claims, intersected with the ceiling.
    ///
    /// The intersection is the whole point of the method. A ceiling that contains
    /// `android:fs:system` does not put it in the output when the probe did not earn it, and a
    /// ceiling that omits `android:shell:write` takes it out even on a rooted device. Neither
    /// direction is a convention: change the order of the operands and the settings screen
    /// becomes a privilege escalation path.
    pub fn claims(&self, profile: &HostProfile) -> Result<Vec<CapabilityClaim>, ConfigError> {
        let ceiling = self.ceiling()?;
        Ok(derive_claims(profile)
            .into_iter()
            .filter(|claim| lookup(&claim.capability).is_some_and(|cap| ceiling.contains(&cap)))
            .collect())
    }

    /// Capabilities the device earned that the settings screen has turned off.
    ///
    /// For the screen's explanatory text: "this device could do that, you said no" is a
    /// different row from "this device cannot do that", and only the first is the operator's
    /// to change.
    ///
    /// In vocabulary order ([`Capability::all`]), which is the order the Gateway lists them in.
    pub fn blocked_by_settings(&self, profile: &HostProfile) -> Vec<Capability> {
        let Ok(ceiling) = self.ceiling() else {
            return Vec::new();
        };
        derive_claims(profile)
            .into_iter()
            .filter_map(|claim| lookup(&claim.capability))
            .filter(|cap| !ceiling.contains(cap))
            .collect()
    }

    /// The command budget to put on every request.
    pub fn command_timeout(&self) -> Duration {
        self.timing.command_timeout()
    }

    /// How long a write lock survives without renewal.
    pub fn lock_ttl(&self) -> Duration {
        self.timing.lock_ttl()
    }

    /// How long to wait for a bugreport.
    pub fn bugreport_timeout(&self) -> Duration {
        self.timing.bugreport_timeout()
    }

    /// Bytes of output one command may produce.
    pub fn output_cap(&self) -> usize {
        self.budgets.output_cap_bytes as usize
    }

    /// The budget to hand a backend as its default.
    ///
    /// This is what makes the two rows above real rather than decorative. A backend applies it
    /// to any request whose author did not name a budget — which includes every command the port
    /// builds for itself, the snapshot capture and the restore among them — so the operator's
    /// number reaches the process that gets killed by it.
    pub fn budget(&self) -> Budget {
        Budget {
            timeout: Some(self.command_timeout()),
            output_cap: self.output_cap(),
        }
    }

    /// Create the runtime's own directories and build the objects the settings name.
    ///
    /// Directories are created now rather than lazily. A snapshot store whose directory is
    /// missing fails at the moment a file is being overwritten — the one moment a runtime is
    /// not allowed to discover it has nowhere to put the old bytes.
    pub fn prepare(&self, root: &Path) -> Result<PreparedHost, AssemblyError> {
        self.validate()?;
        let snapshot_dir = self.storage.snapshot_dir(root);
        let audit_dir = self.storage.audit_dir(root);
        let evidence_dir = self.storage.evidence_dir(root);
        for dir in [&snapshot_dir, &audit_dir, &evidence_dir] {
            std::fs::create_dir_all(dir)?;
        }
        let audit = Arc::new(FileAuditSink::with_max_bytes(
            self.storage.audit_log(root),
            self.budgets.audit_file_bytes,
        ));
        let snapshots = SnapshotStore::with_budget(snapshot_dir, self.budgets.snapshot_store_bytes);
        Ok(PreparedHost {
            audit,
            snapshots,
            evidence_dir,
            default_budget: self.budget(),
        })
    }

    /// The shipped chain for a device this port runs on directly: audit and rollback over the
    /// **shell** backend.
    ///
    /// `root` is the host's own directory (see [`StorageConfig`]). The result is the decorator
    /// order [`chain`] states.
    ///
    /// Not over the privileged backend, and the omission is the design rather than an unfinished
    /// branch. Which tier the Runtime executes at is decided by ADR-AND-001 §4.1 (never as root)
    /// plus the escalation *evidence* a probe gathered; a config module that picked the tier
    /// would be a settings file widening what the device earned, which is rule 1. A node that
    /// has decided it is on a rooted device builds the privileged backend and hands it to
    /// [`PreparedHost::chain`], and gets the same chain from the same settings:
    ///
    /// ```ignore
    /// let prepared = config.prepare(&root)?;
    /// let backend = RootShellBackend::new(profile)?
    ///     .with_default_budget(prepared.default_budget);
    /// let chain = prepared.chain(Arc::new(backend));
    /// ```
    pub fn assemble(&self, profile: HostProfile, root: &Path) -> Result<Assembly, AssemblyError> {
        let prepared = self.prepare(root)?;
        let backend: Arc<dyn ExecutionBackend> = Arc::new(
            crate::host::backends::ShellBackend::new(profile)?
                .with_default_budget(prepared.default_budget),
        );
        let reversible = prepared.chain(backend);
        Ok(Assembly {
            reversible,
            prepared,
        })
    }
}

impl StorageConfig {
    /// Where pre-write backups live under `root`.
    pub fn snapshot_dir(&self, root: &Path) -> PathBuf {
        root.join(&self.snapshot_subdir)
    }

    /// Where the audit trail lives under `root`.
    pub fn audit_dir(&self, root: &Path) -> PathBuf {
        root.join(&self.audit_subdir)
    }

    /// The audit file itself.
    pub fn audit_log(&self, root: &Path) -> PathBuf {
        self.audit_dir(root).join(AUDIT_FILE_NAME)
    }

    /// Where captured evidence lands under `root`.
    pub fn evidence_dir(&self, root: &Path) -> PathBuf {
        root.join(&self.evidence_subdir)
    }
}

impl EvidenceConfig {
    /// Filter and narrow one requested source against this policy.
    ///
    /// `None` means "not collected", and the caller says so in its own output rather than
    /// capturing something the operator never agreed to. A policy nobody consults is a settings
    /// row that lies, which is why this is a function on the policy instead of a field someone
    /// may or may not read.
    pub fn apply(&self, source: &EvidenceSource) -> Option<EvidenceSource> {
        match source {
            EvidenceSource::Screenshot if self.screenshot => Some(source.clone()),
            EvidenceSource::Logcat {
                buffer,
                filter,
                tail,
            } if self.logcat => {
                // The screen's tail applies when the caller did not name one. A caller that
                // asked for the whole buffer asked on purpose, and `0` is how the settings say
                // the same thing.
                let tail = match tail {
                    Some(n) => Some(*n),
                    None if self.logcat_tail_lines == 0 => None,
                    None => Some(self.logcat_tail_lines),
                };
                Some(EvidenceSource::Logcat {
                    buffer: buffer.clone(),
                    filter: filter.clone(),
                    tail,
                })
            }
            EvidenceSource::Dumpsys { .. } if self.dumpsys => Some(source.clone()),
            EvidenceSource::DeviceFile { .. } if self.device_files => Some(source.clone()),
            EvidenceSource::Bugreport if self.bugreport => Some(source.clone()),
            _ => None,
        }
    }
}

impl TimingConfig {
    /// The command budget to put on every request.
    ///
    /// The typed accessor lives on the section, so a screen that renders one row can read the
    /// value back in the unit it will display.
    pub fn command_timeout(&self) -> Duration {
        Duration::from_secs(self.command_timeout_secs)
    }

    /// How long a write lock survives without renewal.
    pub fn lock_ttl(&self) -> Duration {
        Duration::from_secs(self.lock_ttl_secs)
    }

    /// How long to wait for a `bugreportz` capture.
    pub fn bugreport_timeout(&self) -> Duration {
        Duration::from_secs(self.bugreport_timeout_secs)
    }
}

/// The runtime's own objects, built from a validated settings document.
#[derive(Debug)]
pub struct PreparedHost {
    /// The audit sink that is in the chain.
    pub audit: Arc<FileAuditSink>,
    /// The snapshot store that is in the chain.
    pub snapshots: SnapshotStore,
    /// Where evidence captures land.
    pub evidence_dir: PathBuf,
    /// The default command budget, for the backend the caller builds.
    ///
    /// Carried here rather than read off the config at the call site so that a node which
    /// chooses its own inner backend — the privileged tier, or an adb-driven harness — cannot
    /// assemble a chain that ignores the operator's timeout.
    pub default_budget: Budget,
}

impl PreparedHost {
    /// Put an inner backend into the chain this host was configured for.
    ///
    /// Takes the inner backend rather than building one, so a node driving a phone over adb, a
    /// node running on the device, and a test with a scripted device all get the *same* decorator
    /// order from the same settings.
    pub fn chain(&self, inner: Arc<dyn ExecutionBackend>) -> Arc<ReversibleBackendHandle> {
        let store =
            SnapshotStore::with_budget(self.snapshots.dir().to_path_buf(), self.snapshots.budget());
        chain::wrap_with_store(inner, Arc::clone(&self.audit) as Arc<dyn AuditSink>, store)
    }
}

/// A assembled runtime: the chain plus the directories it writes into.
pub struct Assembly {
    /// Audit → rollback over the profile's shell backend.
    pub reversible: Arc<ReversibleBackendHandle>,
    /// The objects it was built from, for whoever has to report where the files are.
    pub prepared: PreparedHost,
}

impl fmt::Debug for Assembly {
    /// The directories and the caps, not the decorators.
    ///
    /// A derived `Debug` is impossible here — the chain holds an `Arc<dyn ExecutionBackend>`,
    /// and a device backend cannot print itself. What a reader of this value actually needs is
    /// "where do this runtime's files live and how big may they get", which is exactly what
    /// `PreparedHost` can say.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Assembly")
            .field("snapshots", &self.prepared.snapshots.dir())
            .field("budget", &self.prepared.snapshots.budget())
            .field("audit", &self.prepared.audit.path())
            .field("audit_cap", &self.prepared.audit.max_bytes())
            .field("evidence", &self.prepared.evidence_dir)
            .field("command_timeout", &self.prepared.default_budget.timeout)
            .field("output_cap", &self.prepared.default_budget.output_cap)
            .finish()
    }
}

/// The name the rest of the crate uses for the outermost decorator.
///
/// An alias rather than a re-import by design: [`chain`]'s constructors return this type, and a
/// settings module that named it differently would be the third place to update when the
/// outermost decorator changes.
type ReversibleBackendHandle = crate::host::rollback::ReversibleBackend;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::facts::{FsRoot, SelinuxState, SuProbe, VerityState};
    use crate::host::probe::ProbeOutput;
    use crate::host::{
        ApprovalToken, Capability, ExecRecord, ExecRequest, HostProfile, HostProfileName,
        ShellDialect,
    };
    use crate::host::{PLATFORM, android_vocabulary};
    use acowork_platform_contract::CapabilityTable;
    use acowork_platform_contract::HostCapability;

    /// A directory per test, removed first: `prepare` creates, and a leftover file from a
    /// previous run would make a green test mean nothing.
    fn tempdir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "acowork-hostconfig-{tag}-{}-{}",
            std::process::id(),
            tag_counter(tag)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn tag_counter(tag: &str) -> u64 {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let _ = tag;
        SEQ.fetch_add(1, Ordering::Relaxed)
    }

    /// Re-derive the declared table after mutating the facts.
    ///
    /// `HostProfile::assemble` does this itself; a fixture that changes the facts afterwards has
    /// to, or the profile would declare nothing and every backend built from it would refuse at
    /// `check_declared` — which is the behaviour, not a quirk to design around.
    fn declare_from_facts(profile: &mut HostProfile) {
        let mut table = CapabilityTable::new(PLATFORM, android_vocabulary()).unwrap();
        let claims = derive_claims(profile);
        let _ = acowork_platform_contract::audit_claims(
            &mut table,
            &claims,
            Duration::from_secs(u64::MAX / 2),
        );
        profile.caps = table;
    }

    /// A device with a working shell and one writable root that is not our own package.
    ///
    /// Built by mutating the empty probe rather than writing a twenty-field literal: the point
    /// of these tests is the *intersection* with the ceiling, and the fields that earn
    /// `android:shell:read` are the four that matter.
    fn shell_profile() -> HostProfile {
        let mut profile = HostProfile::assemble(&ProbeOutput::nothing_ran(), "com.example.agent");
        profile.name = HostProfileName::SystemShell;
        profile.shell = Some(ShellDialect::MkSh);
        profile.shell_executed = true;
        profile.dialects.insert(ShellDialect::MkSh);
        profile.fs_roots.push(FsRoot {
            path: "/data/local/tmp".to_string(),
            writable: true,
            own_package: false,
        });
        declare_from_facts(&mut profile);
        profile
    }

    /// The same device, plus a `su` that answered `uid 0`.
    fn rooted_profile() -> HostProfile {
        let mut profile = shell_profile();
        profile.name = HostProfileName::RootShell;
        profile.su = SuProbe {
            uid: Some(0),
            context: Some("u:r:magisk:s0".to_string()),
            prompt_denied: false,
            unavailable: false,
        };
        profile.system_remountable = true;
        // The two facts `fs:system` is keyed on beyond escalation: verity must not be
        // enforcing, and an unknown verity state counts as enforcing (§2 item 10).
        profile.device.verity = VerityState::NotEnforcing;
        profile.selinux = SelinuxState::Enforcing;
        declare_from_facts(&mut profile);
        profile
    }

    fn ids(caps: &[Capability]) -> Vec<String> {
        caps.iter().map(|c| c.id().as_str().to_string()).collect()
    }

    /// Every capability id, for a ceiling that turns nothing off.
    fn all_ids() -> Vec<String> {
        ids(Capability::all().as_ref())
    }

    fn claim_ids(claims: &[CapabilityClaim]) -> Vec<String> {
        claims
            .iter()
            .map(|c| c.capability.as_str().to_string())
            .collect()
    }

    /// A device that answers everything with success and remembers what it was asked.
    struct Always {
        profile: HostProfile,
        seen: std::sync::Mutex<Vec<String>>,
    }

    impl Always {
        fn new(profile: HostProfile) -> Arc<Always> {
            Arc::new(Always {
                profile,
                seen: std::sync::Mutex::new(Vec::new()),
            })
        }
    }

    #[async_trait::async_trait]
    impl ExecutionBackend for Always {
        fn name(&self) -> &'static str {
            "fake(shell)"
        }
        fn dialect(&self) -> Option<ShellDialect> {
            Some(ShellDialect::MkSh)
        }
        fn profile(&self) -> &HostProfile {
            &self.profile
        }
        async fn exec(&self, request: ExecRequest) -> Result<ExecRecord, BackendError> {
            self.seen.lock().unwrap().push(request.script.clone());
            Ok(ExecRecord {
                stdout: String::new(),
                stderr: String::new(),
                exit_code: Some(0),
                selinux_denials: Vec::new(),
                uid: Some(2000),
                context: Some("u:r:shell:s0".to_string()),
                duration_ms: 1,
                truncated: false,
                timed_out: false,
            })
        }
    }

    // ── the defaults are measurements, not tastes ─────────────────────────────

    #[test]
    fn the_defaults_are_the_numbers_the_crate_measured() {
        // Not "8 MiB is a nice round number" — if `SNAPSHOT_STORE_BUDGET_BYTES` changes because
        // a device said so, the settings screen follows without anyone editing a second copy.
        let config = HostConfig::defaults();
        assert_eq!(
            config.budgets.snapshot_store_bytes,
            SNAPSHOT_STORE_BUDGET_BYTES
        );
        assert_eq!(config.budgets.audit_file_bytes, DEFAULT_MAX_FILE_BYTES);
        assert_eq!(
            config.budgets.evidence_budget_bytes,
            DEFAULT_EVIDENCE_BUDGET
        );
        assert_eq!(config.budgets.output_cap_bytes, DEFAULT_OUTPUT_CAP as u64);
        assert_eq!(
            config.timing.command_timeout(),
            crate::host::DEFAULT_READ_TIMEOUT
        );
        assert_eq!(config.timing.lock_ttl(), crate::host::WRITE_LOCK_TTL);
        assert_eq!(
            config.bugreport_timeout(),
            crate::host::evidence::BUGREPORT_TIMEOUT
        );
        assert_eq!(config.command_timeout(), DEFAULT_READ_TIMEOUT);
        assert_eq!(config.output_cap(), DEFAULT_OUTPUT_CAP);
    }

    #[test]
    fn the_default_ceiling_is_the_three_tiers_that_need_no_owner() {
        // §7.4's "默认拒绝" as a default value: the two system-tier capabilities are off until
        // somebody turns them on, and turning them on still needs the session switch and the
        // owner verdict.
        let config = HostConfig::defaults();
        let expected: BTreeSet<Capability> = [
            Capability::ShellRead,
            Capability::ShellWrite,
            Capability::FsOutsideApp,
        ]
        .into_iter()
        .collect();
        assert_eq!(config.ceiling().unwrap(), expected);
    }

    #[test]
    fn the_default_evidence_policy_is_the_narrow_one() {
        let config = HostConfig::defaults();
        assert!(
            !config.evidence.bugreport,
            "a bugreport is never volunteered"
        );
        assert!(
            !config.evidence.device_files,
            "reading another process's stack is not a default"
        );
        assert_eq!(config.evidence.logcat_tail_lines, 200);
    }

    // ── the document ─────────────────────────────────────────────────────────

    #[test]
    fn a_settings_document_round_trips() {
        let mut config = HostConfig::defaults();
        config.budgets.snapshot_store_bytes = 1024 * 1024;
        config.evidence.bugreport = true;
        config
            .capability_ceiling
            .push("android:fs:system".to_string());
        let text = config.to_json().unwrap();
        assert_eq!(HostConfig::from_json(&text).unwrap(), config);
    }

    #[test]
    fn an_unknown_key_is_refused_rather_than_ignored() {
        // A screen that shows a value the runtime is not using is worse than a screen that
        // refuses to start.
        let err = HostConfig::from_json(r#"{ "budgets": { "snapshot_store_byte": 1048576 } }"#)
            .unwrap_err();
        assert!(
            err.reason.contains("snapshot_store_byte"),
            "the message must name the key that is not a setting: {}",
            err.reason
        );
    }

    #[test]
    fn a_missing_section_keeps_its_defaults() {
        // A hand-edited file with one line in it is a normal thing; it must not zero the rest.
        let config =
            HostConfig::from_json(r#"{ "timing": { "command_timeout_secs": 45 } }"#).unwrap();
        assert_eq!(config.timing.command_timeout_secs, 45);
        assert_eq!(
            config.budgets.snapshot_store_bytes,
            SNAPSHOT_STORE_BUDGET_BYTES
        );
        assert_eq!(config.storage.snapshot_subdir, "snapshots");
    }

    #[test]
    fn the_document_has_no_way_to_persist_dangerous_mode() {
        // ADR-AND-001 §7.3 and the contract's own comment ("Never persisted") enforced by the
        // type: there is no field to set, and a file that tries to set one does not parse.
        let text = HostConfig::defaults().to_json().unwrap();
        for forbidden in ["dangerous", "owner", "root", "bypass"] {
            assert!(
                !text.to_lowercase().contains(forbidden),
                "the settings document must not mention `{forbidden}`: {text}"
            );
        }
        let err = HostConfig::from_json(r#"{ "dangerous_mode": true }"#).unwrap_err();
        assert!(err.reason.contains("dangerous_mode"), "{}", err.reason);
    }

    // ── bounds ───────────────────────────────────────────────────────────────

    #[test]
    fn a_budget_below_its_floor_names_the_setting() {
        // The dotted path is the contract with the screen: it highlights a row, not a byte offset.
        let err = HostConfig::from_json(r#"{ "budgets": { "snapshot_store_bytes": 1024 } }"#)
            .unwrap_err();
        assert_eq!(err.field, "budgets.snapshot_store_bytes");
        assert!(err.reason.contains(&SNAPSHOT_STORE_MIN.to_string()));

        let err =
            HostConfig::from_json(r#"{ "budgets": { "snapshot_store_bytes": 9999999999999 } }"#)
                .unwrap_err();
        assert_eq!(err.field, "budgets.snapshot_store_bytes");
        assert!(err.reason.contains(&SNAPSHOT_STORE_MAX.to_string()));
    }

    #[test]
    fn every_timing_knob_has_its_own_bounds() {
        for (json, field) in [
            (
                r#"{ "timing": { "command_timeout_secs": 0 } }"#,
                "timing.command_timeout_secs",
            ),
            (
                r#"{ "timing": { "command_timeout_secs": 99999 } }"#,
                "timing.command_timeout_secs",
            ),
            (
                r#"{ "timing": { "lock_ttl_secs": 5 } }"#,
                "timing.lock_ttl_secs",
            ),
            (
                r#"{ "timing": { "bugreport_timeout_secs": 1 } }"#,
                "timing.bugreport_timeout_secs",
            ),
        ] {
            let err = HostConfig::from_json(json).unwrap_err();
            assert_eq!(err.field, field, "wrong field named for {json}");
        }
    }

    // ── rule 2: names, not paths ─────────────────────────────────────────────

    #[test]
    fn an_absolute_directory_name_is_refused() {
        let err = HostConfig::from_json(
            r#"{ "storage": { "snapshot_subdir": "/data/local/tmp/backups" } }"#,
        )
        .unwrap_err();
        assert_eq!(err.field, "storage.snapshot_subdir");
        assert!(
            err.reason.contains("not a directory name"),
            "{}",
            err.reason
        );
    }

    #[test]
    fn a_traversing_directory_name_is_refused() {
        for name in ["..", "../shared", "a/b", "a\\b", ".", ""] {
            let json = format!(r#"{{ "storage": {{ "audit_subdir": "{name}" }} }}"#);
            let err = HostConfig::from_json(&json).unwrap_err();
            assert_eq!(
                err.field, "storage.audit_subdir",
                "`{name}` must not be accepted as a directory name"
            );
        }
    }

    #[test]
    fn a_name_is_joined_onto_the_root_the_host_supplied() {
        let config = HostConfig::defaults();
        let root = Path::new("/data/user/0/com.acowork.node/files");
        assert_eq!(
            config.storage.snapshot_dir(root),
            PathBuf::from("/data/user/0/com.acowork.node/files/snapshots")
        );
        assert_eq!(
            config.storage.audit_log(root),
            PathBuf::from("/data/user/0/com.acowork.node/files/audit/audit.jsonl")
        );
    }

    // ── rule 1: settings narrow, never widen ─────────────────────────────────

    #[test]
    fn a_ceiling_cannot_claim_what_the_device_never_earned() {
        // The escalation test. Every capability switched on, on a device with no shell at all:
        // the output is empty, because the profile is the other operand and it is not editable.
        let config = HostConfig {
            capability_ceiling: all_ids(),
            ..HostConfig::defaults()
        };
        let sandbox = HostProfile::assemble(&ProbeOutput::nothing_ran(), "com.example.agent");
        assert!(
            config.claims(&sandbox).unwrap().is_empty(),
            "a settings screen must not be able to mint a capability: {:?}",
            config.claims(&sandbox).unwrap()
        );
    }

    #[test]
    fn a_ceiling_turns_off_what_the_device_could_do() {
        let rooted = rooted_profile();
        let open = HostConfig {
            capability_ceiling: all_ids(),
            ..HostConfig::defaults()
        };
        let earned = open.claims(&rooted).unwrap();
        assert!(
            claim_ids(&earned).contains(&"android:fs:system".to_string()),
            "a rooted, remountable device with the ceiling open earns the system tier: {:?}",
            claim_ids(&earned)
        );

        let read_only = HostConfig {
            capability_ceiling: vec!["android:shell:read".to_string()],
            ..HostConfig::defaults()
        };
        let kept = read_only.claims(&rooted).unwrap();
        assert_eq!(claim_ids(&kept), vec!["android:shell:read".to_string()]);
        let blocked: BTreeSet<Capability> =
            read_only.blocked_by_settings(&rooted).into_iter().collect();
        let expected: BTreeSet<Capability> = [
            Capability::ShellWrite,
            Capability::FsOutsideApp,
            Capability::FsSystem,
            Capability::SelinuxPermissive,
        ]
        .into_iter()
        .collect();
        assert_eq!(
            blocked, expected,
            "the screen must be able to say which rows are the operator's to change"
        );
    }

    #[test]
    fn the_default_ceiling_holds_the_system_tier_back_on_a_rooted_phone() {
        // The device says yes, the settings say not by default. The settings win, and this is
        // the row that makes §7.4's conjunction visible without a second mechanism.
        let earned = HostConfig::defaults().claims(&rooted_profile()).unwrap();
        let kept = claim_ids(&earned);
        assert!(kept.contains(&"android:shell:read".to_string()));
        assert!(kept.contains(&"android:shell:write".to_string()));
        assert!(
            !kept.contains(&"android:fs:system".to_string()),
            "fs:system must not be claimable without the operator turning it on: {kept:?}"
        );
        assert!(!kept.contains(&"android:selinux:permissive".to_string()));
    }

    #[test]
    fn an_unknown_capability_id_is_refused() {
        // `fs:sytem` parses as an id and resolves to nothing: accepted silently, it would read
        // as "system writes are allowed" to the person who typed it and do nothing.
        let config = HostConfig {
            capability_ceiling: vec!["android:fs:sytem".to_string()],
            ..HostConfig::defaults()
        };
        let err = config.validate().unwrap_err();
        assert_eq!(err.field, "capability_ceiling");
        assert!(err.reason.contains("android:fs:sytem"));

        let err = HostConfig {
            capability_ceiling: vec!["fs-system".to_string()],
            ..HostConfig::defaults()
        }
        .validate()
        .unwrap_err();
        assert_eq!(err.field, "capability_ceiling");
    }

    #[test]
    fn a_foreign_namespace_is_not_an_android_capability() {
        let config = HostConfig {
            capability_ceiling: vec!["linux:fs:system".to_string()],
            ..HostConfig::defaults()
        };
        assert!(config.validate().is_err());
    }

    // ── evidence policy ──────────────────────────────────────────────────────

    #[test]
    fn the_policy_narrows_a_logcat_that_did_not_say_how_much() {
        let policy = EvidenceConfig::default();
        let source = EvidenceSource::Logcat {
            buffer: None,
            filter: vec!["ActivityManager:V".to_string()],
            tail: None,
        };
        match policy.apply(&source) {
            Some(EvidenceSource::Logcat { tail, filter, .. }) => {
                assert_eq!(tail, Some(200));
                assert_eq!(filter, vec!["ActivityManager:V".to_string()]);
            }
            other => {
                panic!("a logcat under a default policy must survive and be narrowed: {other:?}")
            }
        }
    }

    #[test]
    fn a_caller_that_asked_for_the_whole_buffer_is_not_overruled_by_a_tail() {
        // The setting is a default for callers who did not choose, not a cap on callers who did.
        let policy = EvidenceConfig::default();
        let source = EvidenceSource::Logcat {
            buffer: Some("crash".to_string()),
            filter: Vec::new(),
            tail: Some(50_000),
        };
        match policy.apply(&source) {
            Some(EvidenceSource::Logcat { tail, .. }) => assert_eq!(tail, Some(50_000)),
            other => panic!("expected the narrowed source, got {other:?}"),
        }
    }

    #[test]
    fn the_two_expensive_sources_are_off_until_asked_for() {
        let policy = EvidenceConfig::default();
        assert!(policy.apply(&EvidenceSource::Bugreport).is_none());
        assert!(
            policy
                .apply(&EvidenceSource::DeviceFile {
                    path: "/data/anr/dumptrace".to_string()
                })
                .is_none()
        );
        assert!(policy.apply(&EvidenceSource::Screenshot).is_some());
        assert!(
            policy
                .apply(&EvidenceSource::Dumpsys {
                    service: "batteryinfo".to_string()
                })
                .is_some()
        );

        let open = EvidenceConfig {
            bugreport: true,
            device_files: true,
            ..EvidenceConfig::default()
        };
        assert!(open.apply(&EvidenceSource::Bugreport).is_some());
        assert!(
            open.apply(&EvidenceSource::DeviceFile {
                path: "/data/anr/dumptrace".to_string()
            })
            .is_some()
        );

        let off = EvidenceConfig {
            screenshot: false,
            dumpsys: false,
            ..EvidenceConfig::default()
        };
        assert!(off.apply(&EvidenceSource::Screenshot).is_none());
        assert!(
            off.apply(&EvidenceSource::Dumpsys {
                service: "batteryinfo".to_string()
            })
            .is_none()
        );
    }

    #[test]
    fn a_logcat_tail_beyond_the_screen_is_refused() {
        let err = HostConfig::from_json(&format!(
            r#"{{ "evidence": {{ "logcat_tail_lines": {} }} }}"#,
            LOGCAT_TAIL_MAX + 1
        ))
        .unwrap_err();
        assert_eq!(err.field, "evidence.logcat_tail_lines");
        // `0` is the documented way to ask for everything, and it must stay legal.
        assert!(HostConfig::from_json(r#"{ "evidence": { "logcat_tail_lines": 0 } }"#).is_ok());
    }

    /// A runner that answers like a shell and keeps every invocation it was handed.
    #[derive(Clone)]
    struct Recorder(Arc<std::sync::Mutex<Vec<crate::host::SpawnInvocation>>>);

    impl Recorder {
        fn new() -> Recorder {
            Recorder(Arc::new(std::sync::Mutex::new(Vec::new())))
        }
        fn last(&self) -> crate::host::SpawnInvocation {
            self.0
                .lock()
                .unwrap()
                .last()
                .cloned()
                .expect("one invocation")
        }
    }

    #[async_trait::async_trait]
    impl crate::host::SpawnRunner for Recorder {
        async fn spawn(
            &self,
            invocation: crate::host::SpawnInvocation,
        ) -> Result<crate::host::RawOutput, crate::host::SpawnError> {
            let nonce = crate::host::script::nonce_of(&invocation.script)
                .unwrap_or_default()
                .to_string();
            self.0.lock().unwrap().push(invocation);
            Ok(crate::host::RawOutput {
                exit_code: Some(0),
                stdout: format!("{nonce}\t2000\tu:r:shell:s0\t{nonce}\n").into_bytes(),
                stderr: Vec::new(),
                truncated: false,
                timed_out: false,
                duration: Duration::from_millis(1),
            })
        }
    }

    // ── assembly ─────────────────────────────────────────────────────────────

    #[test]
    fn prepare_creates_the_three_directories() {
        let root = tempdir("prepare");
        let prepared = HostConfig::defaults().prepare(&root).unwrap();
        for dir in ["snapshots", "audit", "evidence"] {
            assert!(root.join(dir).is_dir(), "{dir} was not created");
        }
        assert_eq!(prepared.evidence_dir, root.join("evidence"));
        assert_eq!(prepared.audit.path(), root.join("audit/audit.jsonl"));
        assert_eq!(prepared.snapshots.dir(), root.join("snapshots"));
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn prepare_refuses_an_impossible_document_before_touching_the_disk() {
        let root = tempdir("prepare-invalid");
        let config = HostConfig {
            budgets: BudgetConfig {
                audit_file_bytes: 1,
                ..BudgetConfig::default()
            },
            ..HostConfig::defaults()
        };
        match config.prepare(&root) {
            Err(AssemblyError::Config(err)) => assert_eq!(err.field, "budgets.audit_file_bytes"),
            other => panic!("an out-of-range cap must be refused, not created: {other:?}"),
        }
        assert!(
            !root.exists(),
            "a refused document must not have made directories"
        );
    }

    #[test]
    fn the_snapshot_budget_in_the_settings_is_the_budget_in_force() {
        // The number on the screen is the number the store enforces — checked by making the
        // store refuse, which is the only way to see the budget from outside.
        let root = tempdir("budget");
        let config = HostConfig {
            budgets: BudgetConfig {
                snapshot_store_bytes: SNAPSHOT_STORE_MIN,
                ..BudgetConfig::default()
            },
            ..HostConfig::defaults()
        };
        let prepared = config.prepare(&root).unwrap();
        assert_eq!(prepared.snapshots.budget(), SNAPSHOT_STORE_MIN);

        let payload = "A".repeat(SNAPSHOT_STORE_MIN as usize + 1);
        let err = prepared
            .snapshots
            .save("session", "nonce", &payload)
            .unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::StorageFull);
        assert!(err.to_string().contains(&SNAPSHOT_STORE_MIN.to_string()));

        // And it is not a permissions problem wearing a budget's clothes: a payload that fits
        // lands in the directory the settings named.
        let path = prepared
            .snapshots
            .save("session", "nonce", "YWJj")
            .expect("a 4-byte backup fits in 64 KiB");
        assert_eq!(path.parent(), Some(root.join("snapshots").as_path()));
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn the_audit_cap_in_the_settings_reaches_the_sink() {
        let root = tempdir("audit-cap");
        let config = HostConfig {
            budgets: BudgetConfig {
                audit_file_bytes: AUDIT_FILE_MIN,
                ..BudgetConfig::default()
            },
            ..HostConfig::defaults()
        };
        let prepared = config.prepare(&root).unwrap();
        assert_eq!(prepared.audit.max_bytes(), AUDIT_FILE_MIN);
        assert_eq!(
            prepared.audit.used_bytes(),
            0,
            "a log nobody has written to reads as empty, not as an error"
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn a_chain_built_from_the_settings_writes_its_log_where_the_settings_said() {
        let root = tempdir("chain");
        let config = HostConfig::defaults();
        let prepared = config.prepare(&root).unwrap();
        let device = Always::new(shell_profile());
        let chain = prepared.chain(Arc::clone(&device) as Arc<dyn ExecutionBackend>);

        let mut request = ExecRequest::new(Capability::ShellRead, "getprop ro.build.type", "s-1");
        request.approval_token = Some(ApprovalToken::new("test"));
        chain.exec(request).await.unwrap();

        let log = std::fs::read_to_string(prepared.audit.path()).expect("the audit file exists");
        assert_eq!(log.lines().count(), 2, "an attempt and its outcome: {log}");
        assert!(log.contains("getprop ro.build.type"));
        assert_eq!(prepared.audit.failures(), 0);
        // The screen's "已用 X / 上限 Y" reading is the file itself. A counter would be a second
        // answer, and rotation is the first thing that makes the two disagree.
        assert_eq!(prepared.audit.used_bytes() as usize, log.len());
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn assembling_a_rooted_phone_does_not_pick_the_privileged_backend() {
        // The tier is not the settings' decision. `RootShellBackend` demands `paths.su`, which a
        // profile built without item 4a does not carry, so a successful assembly here can only
        // have gone through the shell backend — the privileged path is reachable, but through
        // `PreparedHost::chain` and a caller that chose it knowingly.
        let root = tempdir("assemble-tier");
        let assembly = HostConfig::defaults()
            .assemble(rooted_profile(), &root)
            .expect("a rooted device still assembles the shell chain");
        assert_eq!(
            assembly.reversible.dialect(),
            Some(ShellDialect::MkSh),
            "the chain was built over the profile's shell, not over a helper"
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn a_sandbox_profile_cannot_be_asked_for_a_shell_chain() {
        // Settings do not conjure a shell: `assemble` fails on a profile where nothing executed,
        // and it fails as a construction error rather than as a first command that mysteriously
        // cannot run.
        let root = tempdir("assemble-sandbox");
        let sandbox = HostProfile::assemble(&ProbeOutput::nothing_ran(), "com.example.agent");
        match HostConfig::defaults().assemble(sandbox, &root) {
            Err(AssemblyError::Backend(err)) => {
                assert!(err.to_string().contains("no shell"), "{err}")
            }
            other => panic!("expected a backend refusal, got {other:?}"),
        }
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn the_ceiling_is_rechecked_at_assembly_not_only_at_parse() {
        // A caller that builds the struct by hand (a CLI, a test, a future config source) gets
        // the same refusal as the JSON path.
        let root = tempdir("assemble-invalid");
        let config = HostConfig {
            capability_ceiling: vec!["android:not-a-thing".to_string()],
            ..HostConfig::defaults()
        };
        assert!(matches!(
            config.assemble(shell_profile(), &root),
            Err(AssemblyError::Config(_))
        ));
        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn the_command_timeout_in_the_settings_is_the_one_that_kills_the_child() {
        // Without this, "命令超时 30 s" is a row on a screen and nothing else. The value has to
        // reach the process that gets killed — including for the commands the port builds for
        // itself, which is why the substitution happens in the backend and not at a call site.
        let mut config = HostConfig::defaults();
        config.timing.command_timeout_secs = 120;
        config.budgets.output_cap_bytes = 3 * MIB;

        let seen = Recorder::new();
        let backend =
            crate::host::backends::ShellBackend::with_runner(shell_profile(), seen.clone())
                .unwrap()
                .with_default_budget(config.budget());
        backend
            .exec(ExecRequest::read("getprop ro.build.type", "s-1"))
            .await
            .unwrap();

        let invocation = seen.last();
        assert_eq!(invocation.timeout, Some(Duration::from_secs(120)));
        assert_eq!(invocation.output_cap, 3 * MIB as usize);
    }

    #[tokio::test]
    async fn a_caller_that_named_a_budget_is_not_overruled_by_the_screen() {
        // `evidence::capture` asks for 300 s for a measured reason. Capping it back to the
        // operator's default would turn a settings value into a silent refusal to collect the
        // thing the settings were opened to allow.
        let mut config = HostConfig::defaults();
        config.timing.command_timeout_secs = 5;
        config.budgets.output_cap_bytes = 4 * KIB;

        let seen = Recorder::new();
        let backend =
            crate::host::backends::ShellBackend::with_runner(shell_profile(), seen.clone())
                .unwrap()
                .with_default_budget(config.budget());
        let mut request = ExecRequest::read("logcat -d", "s-1");
        request.budget = Budget {
            timeout: Some(Duration::from_secs(300)),
            output_cap: 4 * MIB as usize,
        };
        backend.exec(request).await.unwrap();

        let invocation = seen.last();
        assert_eq!(invocation.timeout, Some(Duration::from_secs(300)));
        assert_eq!(invocation.output_cap, 4 * MIB as usize);
    }

    #[test]
    fn prepare_carries_the_budget_for_a_backend_the_caller_builds() {
        // The privileged tier is not assembled here (rule 1), so the number has to travel with
        // the prepared host — otherwise the documented root path quietly runs on the port default.
        let root = tempdir("budget-prepare");
        let mut config = HostConfig::defaults();
        config.timing.lock_ttl_secs = 90;
        let prepared = config.prepare(&root).unwrap();
        assert_eq!(
            prepared.default_budget.timeout,
            Some(DEFAULT_READ_TIMEOUT),
            "the command timeout, not the lock TTL, is what bounds a command"
        );
        assert_eq!(prepared.default_budget.output_cap, DEFAULT_OUTPUT_CAP);
        assert_eq!(config.lock_ttl(), Duration::from_secs(90));
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn a_configured_id_resolves_through_the_port_vocabulary() {
        // Guards the id strings the defaults use against a rename in capability.rs.
        for id in HostConfig::defaults().capability_ceiling.clone() {
            let parsed = HostCapability::parse(&id).unwrap();
            assert!(lookup(&parsed).is_some(), "{id} does not resolve");
        }
    }
}
