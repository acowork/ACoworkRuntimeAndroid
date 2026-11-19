//! RAG tool integration module (Phase 4, S4)
//!
//! Implements the enterprise RAG retrieval channel as defined in
//! docs/00-prd.md §1.13 and docs/plan/plan-p4.md S4.
//!
//! Key design decisions:
//! - RAG is opt-in: only active when manifest declares `[[tools]] type = "rag"`
//! - Dual-channel: Grafeo (local) + RAG (enterprise) are independent channels
//! - Standard query protocol: ACowork defines the protocol, enterprises adapt
//! - Timeout/degradation: RAG unavailability never blocks Agent execution

pub mod client;
pub mod types;
