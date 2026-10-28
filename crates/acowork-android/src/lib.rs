//! `acowork-android` — the Android host subsystem of the ACowork Node/Runtime port.
//!
//! # Scope of this crate today
//!
//! This crate currently contains **one** subsystem: [`host`], the Android host
//! profile probe, capability model and execution-backend contract. That is the P0
//! slice of ADR-AND-001 §6.
//!
//! The scope is deliberately this narrow. README.zh.md sketches a broader
//! `crates/acowork-android` shared engine, but upstream design doc 30 has not
//! settled whether the Android engine is a crate compiled into `acowork-runtime`
//! (§5, option A) or a consumer of a published Host crate (§9). Building the host
//! subsystem first is the choice that stays correct under either answer: doc 30 §9
//! itself places `ExecutionBackend` "在引擎内部" and orthogonal to the engine
//! interface, so nothing here has to be unwound when that question is resolved.
//!
//! # Reading order
//!
//! 1. [`host::facts`] — the data model. One type per probed fact, one pure parser
//!    per command's text output.
//! 2. [`host::probe`] — which commands run, what they cost, and how results are
//!    routed. The [`host::probe::ProbeRunner`] trait is the only I/O boundary.
//! 3. [`host::profile`] — assembly into the session-immutable `HostProfile`.
//! 4. [`host::capability`] — capabilities derived from facts, never configured.
//! 5. [`host::backend`] — the `ExecutionBackend` contract and the authorization
//!    gate that composes the Gateway's attribution verdict with the device's local
//!    readiness.
//! 6. [`host::denial`] — turning `avc: denied` into a next step, which is what
//!    stops the retry loop android-host-probe.md §4 warns about.
//!
//! # The invariant behind all of it
//!
//! **Probe is not a guarantee.** A `HostProfile` decides which tools get registered
//! and which capabilities get declared. It never decides whether a concrete command
//! may run — SELinux judges that per `(scontext, tcontext, tclass)` at execution
//! time, and the real authority is the actual exit code plus stderr. Everything in
//! this crate is built to be informative and never permissive.
//!
//! The second invariant, from ADR-AND-001 §4.1, is that **the Runtime itself never
//! runs as root**. It holds the Gateway enrollment credential and the LLM API key,
//! serves HTTP on loopback, and executes instructions arriving from the network;
//! making that process privileged turns one prompt injection into the whole device.
//! Privilege exists only inside a single tool call, behind the narrow
//! [`host::ExecutionBackend`] interface. [`host::HostProfile::runtime_is_unprivileged`]
//! is the predicate the P1 acceptance assertion checks.

#![deny(missing_docs)]
#![warn(clippy::all)]

pub mod host;
