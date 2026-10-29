//! Android host subsystem: probe, capability model, execution backends.
//!
//! # Layering
//!
//! The modules here form a strict pipeline, and the dependency arrows only point
//! one way:
//!
//! ```mermaid
//! graph LR
//!     R["ProbeRunner<br/>(platform I/O)"] --> P["probe<br/>what to ask, what came back"]
//!     P --> F["facts<br/>text → typed fact"]
//!     F --> PR["profile<br/>HostProfile aggregate"]
//!     PR --> C["capability<br/>facts → capabilities"]
//!     C --> PR
//!     PR --> B["backend<br/>ExecutionBackend + gate"]
//!     B --> D["denial<br/>stderr → next step"]
//! ```
//!
//! | Layer | Module | Responsibility | Purity |
//! |---|---|---|---|
//! | Data model | [`facts`] | One type per probed fact, plus its text parser | Pure — no I/O |
//! | Collection | [`probe`] | Which commands to run, the budget, routing results | Contract + routing |
//! | Aggregate | [`profile`] | Assemble facts into the session-immutable `HostProfile` | Pure |
//! | Derivation | [`capability`] | Capabilities as a function of facts, never of config | Pure |
//! | Content check | [`commands`] | What a script actually does, independent of the label claiming it | Pure |
//! | Presentation | [`tools`] | ADR-AND-001 §4.5 tool registration text, from measured facts | Pure |
//! | Assembly | [`script`] | Render a request into the script a shell runs, with the identity probe | Pure |
//! | Process | [`spawn`] | The one seam that touches an OS: `SpawnRunner`, plus the tokio impl | I/O |
//! | Contract | [`backend`] | `ExecutionBackend`, and the gate that composes both authorities | Pure gate + async trait |
//! | Backends | [`backends`] | The tier-specific `ExecutionBackend` implementations | Composes script + spawn + commands |
//! | Transport | [`adb`] | Drive a device from the host over `adb` (feature `device`) | I/O |
//! | Feedback | [`denial`] | `avc: denied` → an actionable next step | Pure, plus a session ledger |
//! | Accountability | [`audit`] | §4.6.1: one record per attempt, written before and after | I/O on the way in, pure mapping |
//! | Reversibility | [`rollback`] | §4.6.4: capture a write's pre-state, restore it at session end | Pure planner, plus a backend decorator |
//!
//! Keeping the parsers pure is not tidiness for its own sake: it is what makes the
//! P0 acceptance criterion in ADR-AND-001 §6 ("单元测试用伪造 probe 输出")
//! achievable at all. A parser that also spawns a process cannot be tested without
//! a device, and a probe that cannot be tested without a device will not be tested.
//!
//! # What this subsystem deliberately does not contain
//!
//! - **No engine dependency.** Nothing here imports `acowork-runtime` or
//!   `acowork-core`. See [`backend`]'s module docs for why that keeps the module
//!   valid under either resolution of blocker B3.
//! - **No upstream `Permission` coupling.** [`capability::Capability`] is a local
//!   type; the adapter to whatever wire vocabulary wins is a separate later file.
//!   See blocker B2.
//! - **No authorization *decisions* about who a user is.** The gate consumes an
//!   opaque [`backend::AttributionVerdict`]. Owner truth stays in the Gateway per
//!   upstream ADR-087 D1/D5. See blocker B1.
//! - **No polling.** The profile is built once and re-derived only on the events
//!   listed in android-host-probe.md §6.

pub mod audit;
pub mod backend;
pub mod backends;
pub mod capability;
pub mod commands;
pub mod denial;
pub mod facts;
pub mod probe;
pub mod profile;
pub mod rollback;
pub mod script;
pub mod spawn;
pub mod tools;

#[cfg(feature = "device")]
pub mod adb;

#[cfg(feature = "device")]
pub use adb::{AdbTransport, CANDIDATE_ROOTS, RemoteArg};
pub use audit::{
    AuditError, AuditEvent, AuditOutcome, AuditSink, AuditedBackend, DEFAULT_MAX_FILE_BYTES,
    FileAuditSink, MAX_COMMAND_BYTES, MemoryAuditSink,
};
pub use backend::{
    ApprovalToken, BackendError, ContractBackend, DEFAULT_OUTPUT_CAP, DEFAULT_READ_TIMEOUT,
    ExecRecord, ExecRequest, ExecutionBackend, SessionLockOutcome, SessionWriteLock,
    WRITE_LOCK_TTL,
};
pub use backends::{AppSandboxBackend, RootShellBackend, ShellBackend};
pub use capability::{
    Capability, PLATFORM, android_vocabulary, derive_claims, explain_absence, lookup,
};
pub use commands::{
    Effect, Finding, Refusal, RefusalKind, Verdict, check as check_script,
    classify as classify_script,
};
pub use denial::{
    DenialLedger, SelinuxClassifier, SelinuxDenial, classify, parse_denials, redact_denials,
};
pub use facts::{
    AppletSet, BuildType, DeviceFacts, FsRoot, MountEntry, Privilege, SelinuxDomain, SelinuxState,
    ShellDialect, SuProbe, VerityState, parse_bool_prop, parse_mount_table, parse_prop,
    parse_su_probe, su_helper_missing, su_prompt_denied,
};
pub use probe::{
    CommandOutput, PROBE_ITEM_TIMEOUT, PROBE_TOTAL_BUDGET, ProbeCommand, ProbeError, ProbeOutput,
    ProbeRunner, SPOT_CHECK_APPLETS, all_commands, parse_spot_checks, run_probe,
};
pub use profile::{HostCapabilitySummary, HostProfile, HostProfileName, ShellPaths};
pub use rollback::{
    Capture, FilePreState, Plan, PreState, RestoreReport, ReversibleBackend, RollbackLedger,
    SNAPSHOT_BUDGET_BYTES, SNAPSHOT_CHUNK_BYTES, SNAPSHOT_STAGING_DIR, SnapshotStore, Undo,
    UndoAction, UndoResult, UndoTarget, Unundoable, Writing, plan as plan_rollback, undo_for,
};
pub use script::{
    Identity, PreparedScript, ScriptError, extract_identity, is_valid_env_key, next_nonce,
    nonce_of, prepare, quote_posix,
};
pub use spawn::{
    DynamicSpawnRunner, ProcessSpawnRunner, RawOutput, ScriptedSpawnRunner, SpawnError,
    SpawnInvocation, SpawnRunner, scripted_output,
};
pub use tools::{ShellTool, shell_tools};
