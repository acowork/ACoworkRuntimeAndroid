//! Audit log — structured JSON logging for shell executions
//!
//! Records every shell command execution with full security context
//! as defined in `docs/08-security.md` §11.5.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::security::shell_risk::ShellRisk;

/// A single audit log entry for a shell execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShellAuditEntry {
    /// Tool that triggered the execution.
    pub tool: String,
    /// The command that was executed.
    pub command: String,
    /// Risk level assigned to the command.
    pub risk_level: ShellRisk,
    /// Reason for the risk classification.
    pub reason: String,
    /// How the execution was approved (user_confirmation / auto / always_allow).
    pub approved_by: String,
    /// Process exit code (if available).
    pub exit_code: Option<i32>,
    /// Files created during execution (detected by FsWatcher).
    pub files_created: Vec<String>,
    /// Files modified during execution.
    pub files_modified: Vec<String>,
    /// Whether the risk was elevated due to file provenance.
    pub provenance_elevated: bool,
    /// Timestamp of execution.
    pub timestamp: DateTime<Utc>,
}

impl ShellAuditEntry {
    /// Create a new audit entry builder.
    pub fn new(tool: &str, command: &str) -> Self {
        Self {
            tool: tool.to_string(),
            command: command.to_string(),
            risk_level: ShellRisk::Low,
            reason: String::new(),
            approved_by: "auto".to_string(),
            exit_code: None,
            files_created: Vec::new(),
            files_modified: Vec::new(),
            provenance_elevated: false,
            timestamp: Utc::now(),
        }
    }

    /// Set the risk level and reason.
    pub fn with_risk(mut self, risk: ShellRisk, reason: &str) -> Self {
        self.risk_level = risk;
        self.reason = reason.to_string();
        self
    }

    /// Set who approved the execution.
    pub fn with_approval(mut self, approved_by: &str) -> Self {
        self.approved_by = approved_by.to_string();
        self
    }

    /// Set the exit code.
    pub fn with_exit_code(mut self, code: i32) -> Self {
        self.exit_code = Some(code);
        self
    }

    /// Set files created/modified.
    pub fn with_file_changes(mut self, created: Vec<String>, modified: Vec<String>) -> Self {
        self.files_created = created;
        self.files_modified = modified;
        self
    }

    /// Set provenance elevated flag.
    pub fn with_provenance_elevated(mut self, elevated: bool) -> Self {
        self.provenance_elevated = elevated;
        self
    }

    /// Serialize to JSON string.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }

    /// Serialize to pretty-printed JSON string.
    pub fn to_json_pretty(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_default()
    }
}

/// Audit logger that writes entries to a file.
pub struct AuditLogger {
    log_dir: PathBuf,
}

impl AuditLogger {
    /// Create a new audit logger that writes to the given directory.
    pub fn new(log_dir: &Path) -> Self {
        Self {
            log_dir: log_dir.to_path_buf(),
        }
    }

    /// Log an audit entry to a file.
    /// Creates one file per day: shell_audit_YYYY-MM-DD.jsonl
    pub fn log(&self, entry: &ShellAuditEntry) -> std::io::Result<()> {
        // Ensure log directory exists
        std::fs::create_dir_all(&self.log_dir)?;

        let date = entry.timestamp.format("%Y-%m-%d").to_string();
        let filename = format!("shell_audit_{}.jsonl", date);
        let path = self.log_dir.join(&filename);

        // Append JSON line
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        use std::io::Write;
        writeln!(file, "{}", entry.to_json())?;

        Ok(())
    }

    /// Read all audit entries from a specific date.
    pub fn read_entries(&self, date: &str) -> std::io::Result<Vec<ShellAuditEntry>> {
        let filename = format!("shell_audit_{}.jsonl", date);
        let path = self.log_dir.join(&filename);

        if !path.exists() {
            return Ok(Vec::new());
        }

        let content = std::fs::read_to_string(&path)?;
        let mut entries = Vec::new();
        for line in content.lines() {
            if let Ok(entry) = serde_json::from_str::<ShellAuditEntry>(line) {
                entries.push(entry);
            }
        }
        Ok(entries)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_audit_entry_creation() {
        let entry = ShellAuditEntry::new("shell", "ls -la")
            .with_risk(ShellRisk::Low, "Low-risk command")
            .with_approval("auto");

        assert_eq!(entry.tool, "shell");
        assert_eq!(entry.command, "ls -la");
        assert_eq!(entry.risk_level, ShellRisk::Low);
        assert_eq!(entry.approved_by, "auto");
    }

    #[test]
    fn test_audit_entry_json() {
        let entry = ShellAuditEntry::new("shell", "./payload.sh")
            .with_risk(ShellRisk::High, "Executing Downloaded file")
            .with_approval("user_confirmation")
            .with_exit_code(0)
            .with_file_changes(vec!["output.dat".to_string()], vec![]);

        let json = entry.to_json();
        assert!(json.contains("shell"));
        assert!(json.contains("High"));
        assert!(json.contains("output.dat"));
        assert!(json.contains("user_confirmation"));
    }

    #[test]
    fn test_audit_entry_pretty_json() {
        let entry =
            ShellAuditEntry::new("shell", "cat file.txt").with_risk(ShellRisk::Low, "Low-risk");

        let pretty = entry.to_json_pretty();
        assert!(pretty.contains('\n'));
    }

    #[test]
    fn test_audit_logger_write_and_read() {
        let dir = std::env::temp_dir().join("acowork-test-audit");
        let _ = fs::remove_dir_all(&dir);

        let logger = AuditLogger::new(&dir);
        let entry =
            ShellAuditEntry::new("shell", "echo hello").with_risk(ShellRisk::Low, "Low-risk");

        logger.log(&entry).unwrap();

        let date = entry.timestamp.format("%Y-%m-%d").to_string();
        let entries = logger.read_entries(&date).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].command, "echo hello");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_audit_logger_read_nonexistent() {
        let dir = std::env::temp_dir().join("acowork-test-audit-nonexistent");
        let logger = AuditLogger::new(&dir);
        let entries = logger.read_entries("2099-01-01").unwrap();
        assert!(entries.is_empty());
    }
}
