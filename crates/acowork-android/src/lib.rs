//! `acowork-android` — the Android host subsystem of the ACowork Node/Runtime port.
//!
//! # Scope of this crate today
//!
//! Two subsystems:
//!
//! - [`host`] — Android host profile probe, capability model and
//!   `ExecutionBackend` contract (ADR-AND-001 §6 P0).
//! - [`node`] — independent Android Node pieces: configurable Runtime engine
//!   (`EngineSpec`), process table, capability tags, enroll payload shape
//!   (ADR-AND-003). Speaks the Gateway **protocol** only; does not depend on
//!   upstream `acowork-node` / `acowork-runtime` crates or binaries.
//! - [`runtime`] — Runtime-role package load (vendored from upstream loader);
//!   LLM main loop is a later slice.
//!
//! B3 (engine ownership) is closed: this repo is an independent engine. B6
//! (sibling `acowork-runtime` path) is closed: the engine is configured, never
//! hardcoded by binary name.
//!
//! # Reading order
//!
//! 1. [`host::facts`] — the data model. One type per probed fact, one pure parser
//!    per command's text output.
//! 2. [`host::probe`] — which commands run, what they cost, and how results are
//!    routed. The `host::probe::ProbeRunner` trait is the only I/O boundary.
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
pub mod node;
pub mod runtime;
