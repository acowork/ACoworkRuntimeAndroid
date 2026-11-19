//! Cancellation handle — per-request cancellation signal (single source of truth).
//!
//! See ADR-044 §4 for design rationale and §4.5 for phased rollout.
//!
//! Phase 1 introduces only the building blocks:
//! - [`CancelHandle`] — clonable handle to a shared cancellation state
//! - [`CancellationReason`] / [`StopSource`] — structured cancellation metadata
//! - [`select_on_cancel`] — race a future against a cancellation handle (drop-future semantics)
//!
//! Wiring into AgentLoop / SessionManager / MQTT dispatcher happens in
//! Phase 2 (additive) and Phase 3 (fixes the TTFT stop bug). Phase 4 cleans
//! up the legacy `urgent_stop` / `pending_interrupt` fields. This module
//! must remain pure and dependency-light so future phases can build on it.
//!
//! # Naming note
//!
//! The handle type is called `CancelHandle` (not `CancellationToken`) because
//! the word `token` is reserved inside this project for LLM data units
//! (`input_tokens`, `output_tokens`, `total_tokens`). Using both creates
//! ambiguity when reading code. The semantic pattern is identical to
//! `tokio_util::sync::CancellationToken` / .NET `CancellationToken` — we
//! simply expose it under a project-local name.

mod reason;
mod token;
mod wrapper;

#[cfg(test)]
mod integration_tests;

pub use reason::{CancellationReason, StopSource};
pub use token::CancelHandle;
pub use wrapper::select_on_cancel;
