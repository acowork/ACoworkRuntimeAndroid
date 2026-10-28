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
//! | Contract | [`backend`] | `ExecutionBackend`, and the gate that composes both authorities | Pure gate + async trait |
//! | Feedback | [`denial`] | `avc: denied` → an actionable next step | Pure, plus a session ledger |
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

pub mod backend;
pub mod backends;
pub mod capability;
pub mod denial;
pub mod facts;
pub mod probe;
pub mod profile;
pub mod script;
pub mod spawn;

#[cfg(feature = "device")]
pub mod adb;

#[cfg(feature = "device")]
pub use adb::{AdbTransport, CANDIDATE_ROOTS, RemoteArg};
pub use backend::{
    ApprovalToken, BackendError, ContractBackend, DEFAULT_OUTPUT_CAP, DEFAULT_READ_TIMEOUT,
    ExecRecord, ExecRequest, ExecutionBackend, SessionLockOutcome, SessionWriteLock,
    WRITE_LOCK_TTL,
};
pub use backends::{AppSandboxBackend, RootShellBackend, ShellBackend};
pub use capability::{
    Capability, PLATFORM, android_vocabulary, derive_claims, explain_absence, lookup,
};
pub use denial::{DenialLedger, SelinuxClassifier, SelinuxDenial, classify, parse_denials};
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
pub use script::{
    Identity, PreparedScript, ScriptError, extract_identity, is_valid_env_key, next_nonce,
    nonce_of, prepare, quote_posix,
};
pub use spawn::{
    DynamicSpawnRunner, ProcessSpawnRunner, RawOutput, ScriptedSpawnRunner, SpawnError,
    SpawnInvocation, SpawnRunner, scripted_output,
};
