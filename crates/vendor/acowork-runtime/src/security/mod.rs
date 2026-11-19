//! Security module — Shell safety, FileProvenance, Approval Gate
//!
//! Implements the Phase 3 application-layer security as defined in
//! `docs/08-security.md` §11: FileProvenance + ShellRisk + Approval Gate.

pub mod approval_gate;
pub mod audit_log;
pub mod file_provenance;
pub mod fs_watcher;
pub mod git_mutate;
pub mod shell_risk;
