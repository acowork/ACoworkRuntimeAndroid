//! Approval Gate — user confirmation for risky tool executions
//!
//! Implements the Approval Gate pattern from `docs/08-security.md` §11.3.
//! Medium/High risk commands are paused for user confirmation.
//!
//! S5.1: Interactive CLI mode uses `dialoguer` crate for terminal prompts.
//! Enable with `--features interactive-cli`. Without the feature,
//! the gate auto-approves Medium/High and auto-rejects Blocked (Phase 3 behavior).

use crate::security::shell_risk::ShellRisk;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// User's response to an approval request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ApprovalResponse {
    /// User approved the execution.
    Approved,
    /// User rejected the execution.
    Rejected,
    /// User approved and chose to always allow this pattern.
    AlwaysAllow { pattern: String },
}

/// An approval request presented to the user.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRequest {
    /// The tool being executed.
    pub tool_name: String,
    /// The command or action being performed.
    pub action: String,
    /// Risk level of the action.
    pub risk_level: ShellRisk,
    /// Human-readable reason for the risk classification.
    pub reason: String,
    /// Executable paths involved (if any).
    pub executable_paths: Vec<PathBuf>,
    /// Whether the risk was elevated due to file provenance.
    pub provenance_elevated: bool,
    /// LLM tool_call_id for frontend matching
    pub tool_call_id: String,
}

/// Trait for approval gate implementations.
///
/// The CLI provides a terminal-based implementation.
/// The Desktop App (Phase 5) will provide a GUI implementation.
#[async_trait]
pub trait ApprovalGate: Send + Sync {
    /// Request approval for a potentially risky action.
    /// Returns the user's decision.
    async fn request_approval(&self, request: &ApprovalRequest) -> ApprovalResponse;
}

/// CLI-based approval gate that prompts the user on the terminal.
pub struct CliApprovalGate {
    /// Whether to auto-approve all requests (for testing/automation).
    auto_approve: bool,
}

impl CliApprovalGate {
    /// Create a new CLI approval gate.
    pub fn new() -> Self {
        Self {
            auto_approve: false,
        }
    }

    /// Create with auto-approve mode (for testing).
    pub fn new_auto_approve() -> Self {
        Self { auto_approve: true }
    }
}

impl Default for CliApprovalGate {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ApprovalGate for CliApprovalGate {
    async fn request_approval(&self, request: &ApprovalRequest) -> ApprovalResponse {
        if self.auto_approve {
            return ApprovalResponse::Approved;
        }

        #[cfg(feature = "interactive-cli")]
        {
            self.interactive_approval(request)
        }

        #[cfg(not(feature = "interactive-cli"))]
        {
            self.noninteractive_approval(request)
        }
    }
}

// --- Non-interactive fallback (no dialoguer) ---

#[cfg(not(feature = "interactive-cli"))]
impl CliApprovalGate {
    /// Non-interactive approval: log the request and auto-approve
    /// Medium/High, auto-reject Blocked.
    fn noninteractive_approval(&self, request: &ApprovalRequest) -> ApprovalResponse {
        tracing::warn!(
            "[ApprovalGate] {} risk: {} — {} (action: {}) [non-interactive]",
            request.risk_level.label(),
            request.tool_name,
            request.reason,
            request.action
        );

        match request.risk_level {
            ShellRisk::Blocked => ApprovalResponse::Rejected,
            _ => ApprovalResponse::Approved,
        }
    }
}

// --- Interactive CLI mode (dialoguer) ---

#[cfg(feature = "interactive-cli")]
impl CliApprovalGate {
    /// Interactive approval using dialoguer::Confirm.
    ///
    /// This is a blocking call (reads from stdin). It is designed to be
    /// called from `tokio::task::spawn_blocking()` in the Gateway's gRPC
    /// handler to avoid blocking the async runtime.
    fn interactive_approval(&self, request: &ApprovalRequest) -> ApprovalResponse {
        use dialoguer::Confirm;

        let prompt = format!(
            "\n\n  [ApprovalGate] {} risk: {}\n  Reason: {}\n  Action: {}\n\n  Allow?",
            request.risk_level.label(),
            request.tool_name,
            request.reason,
            request.action
        );

        // Blocked actions cannot be approved interactively
        if request.risk_level == ShellRisk::Blocked {
            tracing::error!(
                "[ApprovalGate] Blocked action cannot be approved: {}",
                request.action
            );
            return ApprovalResponse::Rejected;
        }

        let confirmed = Confirm::new()
            .with_prompt(prompt)
            .default(false) // Default to reject for safety
            .interact()
            .unwrap_or(false); // If stdin unavailable, default to reject

        if confirmed {
            tracing::info!(
                "[ApprovalGate] User approved: {} — {}",
                request.tool_name,
                request.action
            );
            ApprovalResponse::Approved
        } else {
            tracing::info!(
                "[ApprovalGate] User rejected: {} — {}",
                request.tool_name,
                request.action
            );
            ApprovalResponse::Rejected
        }
    }
}

/// A no-op approval gate that auto-approves everything (for testing).
pub struct AutoApproveGate;

#[async_trait]
impl ApprovalGate for AutoApproveGate {
    async fn request_approval(&self, _request: &ApprovalRequest) -> ApprovalResponse {
        ApprovalResponse::Approved
    }
}

/// An approval gate that auto-rejects everything (for testing).
pub struct AutoRejectGate;

#[async_trait]
impl ApprovalGate for AutoRejectGate {
    async fn request_approval(&self, _request: &ApprovalRequest) -> ApprovalResponse {
        ApprovalResponse::Rejected
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_approval_request_serialization() {
        let request = ApprovalRequest {
            tool_name: "shell".to_string(),
            action: "./payload.sh".to_string(),
            risk_level: ShellRisk::High,
            reason: "Executing Downloaded file".to_string(),
            executable_paths: vec![PathBuf::from("./payload.sh")],
            provenance_elevated: true,
            tool_call_id: "call_test".to_string(),
        };

        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("shell"));
        assert!(json.contains("High"));
    }

    #[tokio::test]
    async fn test_auto_approve_gate() {
        let gate = AutoApproveGate;
        let request = ApprovalRequest {
            tool_name: "shell".to_string(),
            action: "rm -rf /tmp/test".to_string(),
            risk_level: ShellRisk::High,
            reason: "Dangerous command".to_string(),
            executable_paths: vec![],
            provenance_elevated: false,
            tool_call_id: "call_test".to_string(),
        };
        let response = gate.request_approval(&request).await;
        assert_eq!(response, ApprovalResponse::Approved);
    }

    #[tokio::test]
    async fn test_auto_reject_gate() {
        let gate = AutoRejectGate;
        let request = ApprovalRequest {
            tool_name: "shell".to_string(),
            action: "rm -rf /".to_string(),
            risk_level: ShellRisk::Blocked,
            reason: "Destructive".to_string(),
            executable_paths: vec![],
            provenance_elevated: false,
            tool_call_id: "call_test".to_string(),
        };
        let response = gate.request_approval(&request).await;
        assert_eq!(response, ApprovalResponse::Rejected);
    }

    #[tokio::test]
    async fn test_cli_gate_auto_approve_mode() {
        let gate = CliApprovalGate::new_auto_approve();
        let request = ApprovalRequest {
            tool_name: "shell".to_string(),
            action: "curl example.com".to_string(),
            risk_level: ShellRisk::Medium,
            reason: "Can download content".to_string(),
            executable_paths: vec![],
            provenance_elevated: false,
            tool_call_id: "call_test".to_string(),
        };
        let response = gate.request_approval(&request).await;
        assert_eq!(response, ApprovalResponse::Approved);
    }

    #[test]
    fn test_approval_response_equality() {
        assert_eq!(ApprovalResponse::Approved, ApprovalResponse::Approved);
        assert_ne!(ApprovalResponse::Approved, ApprovalResponse::Rejected);
    }
}
