//! # ACowork Platform Contract
//!
//! The platform-neutral rules any device must satisfy to join an ACowork cluster as
//! a node. Android is the first implementation; ESP32-class firmware, and any later
//! platform, implement the same contract.
//!
//! ## Why a contract and not a shared implementation
//!
//! ACowork's goal is that devices running different platforms can all attach as
//! nodes over one protocol. Those platforms do not share an execution model: Android
//! has processes, a POSIX-ish filesystem, an MMU and SELinux; an ESP32 has none of
//! these. There is therefore **no unified solution** — but there can be **unified
//! rules**, and that is what this crate is. It fixes the invariants a port must
//! uphold and the shapes it must fill in, and leaves everything platform-specific to
//! the port.
//!
//! Concretely this crate owns: the capability model and its four declaration axes,
//! the evidence discipline behind a capability claim, the execution envelope, the
//! authorization gate, and the feedback primitives. It does **not** own: which
//! capabilities exist, which facts are probed, how a command is run, or what a
//! refusal looks like in a port's own terms.
//!
//! ## Dependency discipline
//!
//! This crate depends on **`serde` and nothing else**. No `acowork-core`, no
//! `acowork-runtime`, no `async-trait`, no `tokio`. Async is spelled with
//! `core::future::Future` and an associated future type, which is why the crate
//! compiles under `no_std + alloc` — R12 makes that a requirement, not a nicety.
//!
//! Keeping the monorepo out of the dependency graph is deliberate: a port should be
//! able to depend on this contract alone, without pulling a workspace that has no
//! published tags. See the readiness assessment's B3.
//!
//! ## The rules
//!
//! These are normative. Each is enforced somewhere in this crate, and the unit tests
//! next to the enforcement restate it as an executable assertion, so a port can be
//! *checked* rather than trusted.
//!
//! | # | Rule | Enforced by |
//! |---|---|---|
//! | **R1** | Capabilities are a function of probed facts, never of configuration. There is no config file and no environment override. | [`probe::audit_claims`] is the only path into [`CapabilityTable::declare`]; nothing in this crate parses config |
//! | **R2** | A probe is not a guarantee. It decides what is *declared*; per-call authority is the gate's actual decision. | [`gate::Gate::decide`] runs on every request, not once at boot |
//! | **R3** | The node process never holds elevated privilege. Escalation exists only inside a single call, behind [`exec::ExecutionBackend`]. | [`host::HostDescription::is_r3_conformant`], [`gate::Refusal::PrivilegeViolation`] |
//! | **R4** | A capability may be declared only if the port actually demonstrated it. A denial or an inconclusive probe never supports a claim. | [`probe::EvidenceKind::supports_claim`], [`probe::audit_claims`] |
//! | **R5** | The vocabulary belongs to the protocol, the facts belong to the device. IDs are closed and namespaced; a port may not mint one at runtime. | [`HostCapability::parse`] rejects malformed IDs; [`CapabilityTable::spec`] returns `None` for unregistered ones |
//! | **R6** | Every capability declares the same four axes and the gate composes them uniformly. A port may not invent gate logic. | [`CapabilitySpec`]; [`gate::Gate::decide`] contains no platform branch |
//! | **R7** | Two authorities, one composition point. *Who may ask* is the control plane's, delivered as an opaque verdict; *what is possible now* is the device's; the conjunction is evaluated on the device. | `gate::AttributionVerdict` carries no identity; [`gate::Gate::decide`] conjoins it with [`gate::LocalReadiness`] |
//! | **R8** | An irreversible operation is refused unless the caller states a rollback path. | [`Reversibility`], [`gate::Refusal::RollbackPlanRequired`] |
//! | **R9** | Diagnostics travel with the error and are actionable: every refusal names the missing condition and the next step. | [`gate::Refusal`] implements `Display`; [`feedback::Remedy`]; [`host::HostDescription::explain_absence`] |
//! | **R10** | The request shape belongs to the port. The contract requires three answers, not one struct. | [`exec::GateView`]; [`exec::ExecutionBackend::Request`] is an associated type |
//! | **R11** | One mutating action at a time, with no queueing and no preemption. | [`exec::ResourceLock`], [`gate::Refusal::DeviceBusy`] |
//! | **R12** | The contract presumes no OS facility: no shell, no filesystem path, no process model, no MMU, no `std`, no wall clock, no atomics. | `#![cfg_attr(not(feature = "std"), no_std)]`; [`exec::ExitStatus`] has no signal variant; [`exec::ExecOutput`] is bytes, not text; every time-taking API takes `now` from the caller; compiles for `riscv32imc-unknown-none-elf`, which has neither an OS nor an `a` extension |
//! | **R13** | The reported summary carries no device identifiers and no raw probe detail. | [`host::HostSummary`] has five fields, none of which can hold one |
//!
//! ## One conditional item
//!
//! [`exec::ResourceLock`] is gated on `target_has_atomic = "ptr"`. Its compare-exchange
//! is what stops two racing callers from both believing they won, and a target with no
//! atomics — `riscv32imc-unknown-none-elf`, for instance — has nothing to build that
//! from. R11 is *not* thereby optional: such a target is in practice single-core and
//! cooperatively scheduled, where the port supplies exclusion from a critical section it
//! already has. The rule is the contract's; that particular lock-free encoding is only
//! the reference mechanism. Everything else in this crate is unconditional.
//!
//! ## What this crate is *not*
//!
//! It is not the ACowork wire protocol. Capability IDs here are host-side facts about
//! a device; upstream design doc 30's engine capabilities are a per-agent registry
//! with a different consumer (scheduling versus UI feature gating) and a different
//! owner. A node hosts zero or many agents, so folding host capabilities into the
//! engine registry would attach a node property to an agent record. See the readiness
//! assessment's B2 for the counter-proposal this distinction supports.
//!
//! It is also not a HAL. It does not abstract a shell, a radio or a flash
//! controller; it constrains how a port that already has one may claim, gate and
//! explain its use.

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(missing_docs)]
#![warn(clippy::all)]

extern crate alloc;

pub mod capability;
pub mod exec;
pub mod feedback;
pub mod gate;
pub mod host;
pub mod probe;

pub use capability::{
    ApprovalRequirement, AttributionTier, CapabilityIdError, CapabilitySpec, CapabilityTable,
    CapabilityTableError, Effect, HostCapability, HostCapabilityId, Reversibility,
};
pub use exec::{
    Budget, ExecOutcome, ExecOutput, ExecutionBackend, ExecutionError, ExitStatus, GateView,
    LockOutcome,
};
// See `exec::ResourceLock` for why this one is conditional: it needs a compare-exchange,
// and a target with no atomics has nothing to build it from. R11 still applies there —
// the port supplies the mechanism.
#[cfg(target_has_atomic = "ptr")]
pub use exec::ResourceLock;
pub use feedback::{
    Diagnostic, DiagnosticClassifier, DiagnosticLedger, FailureRecord, REPEAT_LIMIT, Remedy,
};
pub use gate::{AttributionVerdict, Gap, Gate, GateDecision, LocalReadiness, LockState, Refusal};
pub use host::{EscalationModel, HostDescription, HostSummary, PrivilegeLevel};
pub use probe::{CapabilityClaim, ClaimAudit, Evidence, EvidenceKind, audit_claims};
