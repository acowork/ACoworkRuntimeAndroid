//! The order of the host decorators, written down once.
//!
//! §4.6.1 puts an audit record around every command; §4.6.4 puts a capture before every write
//! and a restore at session end. Both are decorators over [`ExecutionBackend`], and the order
//! they are nested in is a correctness property, not a style choice — so it is stated here
//! rather than re-derived by every consumer that assembles a backend. A consumer that guesses
//! wrong gets a chain that passes every functional test and quietly loses half the evidence.
//!
//! ```text
//!   caller
//!     └─ ReversibleBackend   plan → capture → run → ledger → restore
//!          └─ AuditedBackend one record for each command that reaches the device
//!               └─ ShellBackend / RootShellBackend / AppSandboxBackend
//! ```
//!
//! Rollback sits **outside** audit, because a capture and a restore are themselves commands:
//!
//! - A capture is the runtime reading the device (`getprop persist.sys.acowork.probe`). If it
//!   is not in the log, "what did you see before you decided to change that" has no answer for
//!   exactly the class of command where the answer is the point.
//! - A restore is the most sensitive command in the lifecycle: it mutates the device after the
//!   session is over, when nobody is watching, on an approval token issued earlier. Nesting the
//!   other way — `Audit(Rollback(Shell))` — puts the audit layer above the layer that sees only
//!   the original request, so the restores go straight to the shell and the log describes a
//!   session that wrote two properties and restored nothing.
//!
//! The innermost backend is whichever one the tier earned; [`wrap`] does not know or care which,
//! which is why it takes the inner backend as an argument. Tier differences belong to the
//! [`HostProfile`](crate::host::HostProfile), not to the shape of the chain: a read-only profile
//! produces empty plans and unremarkable records, so there is no second, simpler chain worth
//! maintaining — and two shapes would mean two chances to pick the one that loses the rollback.

use std::path::PathBuf;
use std::sync::Arc;

use crate::host::{
    AuditSink, AuditedBackend, BackendError, ExecutionBackend, HostProfile, ReversibleBackend,
    RootShellBackend, ShellBackend, SpawnRunner,
};

/// Log every command and make every write undoable.
///
/// `snapshot_dir` is where the bytes of an overwritten file are kept until they are restored —
/// §4.6.4 names the Agent workspace, which is a directory the node owns and the device does
/// not. It is a plain path rather than a injected trait because the only implementation that
/// would differ is one that keeps snapshots somewhere the Agent cannot guarantee exists.
pub fn wrap(
    backend: Arc<dyn ExecutionBackend>,
    sink: Arc<dyn AuditSink>,
    snapshot_dir: impl Into<PathBuf>,
) -> Arc<ReversibleBackend> {
    let audited: Arc<dyn ExecutionBackend> = Arc::new(AuditedBackend::new(backend, sink));
    Arc::new(ReversibleBackend::new(audited, snapshot_dir))
}

/// The chain over a shell backend that starts real processes.
///
/// Fails when the profile has no shell at all — see
/// [`ShellBackend::with_runner`](crate::host::ShellBackend::with_runner) for why that is a
/// construction error rather than a runtime one.
pub fn shell(
    profile: HostProfile,
    sink: Arc<dyn AuditSink>,
    snapshot_dir: impl Into<PathBuf>,
) -> Result<Arc<ReversibleBackend>, BackendError> {
    let backend = ShellBackend::new(profile)?;
    Ok(wrap(Arc::new(backend), sink, snapshot_dir))
}

/// The chain over the root shell backend.
///
/// Constructing this is not an escalation: the profile handed in must already carry the
/// `android:shell:root` capability, which only a probe that saw a working `su` can put there.
pub fn root_shell(
    profile: HostProfile,
    sink: Arc<dyn AuditSink>,
    snapshot_dir: impl Into<PathBuf>,
) -> Result<Arc<ReversibleBackend>, BackendError> {
    let backend = RootShellBackend::new(profile)?;
    Ok(wrap(Arc::new(backend), sink, snapshot_dir))
}

/// The shell chain over an arbitrary runner — for a node that drives the device through
/// something other than a local `adb`, and for tests that want the real decorators around a
/// fake device.
pub fn shell_with_runner<R: SpawnRunner + 'static>(
    profile: HostProfile,
    runner: R,
    sink: Arc<dyn AuditSink>,
    snapshot_dir: impl Into<PathBuf>,
) -> Result<Arc<ReversibleBackend>, BackendError> {
    let backend = ShellBackend::with_runner(profile, runner)?;
    Ok(wrap(Arc::new(backend), sink, snapshot_dir))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::{
        ApprovalToken, Capability, ExecRecord, ExecRequest, HostProfile, MemoryAuditSink,
        ShellDialect, probe::ProbeOutput,
    };

    /// A device with one property and a memory of every script it was asked to run.
    struct Echo {
        profile: HostProfile,
        value: std::sync::Mutex<String>,
        seen: std::sync::Mutex<Vec<String>>,
    }

    impl Echo {
        fn new() -> Arc<Echo> {
            Arc::new(Echo {
                profile: HostProfile::assemble(&ProbeOutput::nothing_ran(), "com.example.agent"),
                value: std::sync::Mutex::new(String::new()),
                seen: std::sync::Mutex::new(Vec::new()),
            })
        }

        fn seen(&self) -> Vec<String> {
            self.seen.lock().unwrap().clone()
        }

        fn value(&self) -> String {
            self.value.lock().unwrap().clone()
        }
    }

    #[async_trait::async_trait]
    impl ExecutionBackend for Echo {
        fn name(&self) -> &'static str {
            "fake(shell)"
        }

        fn dialect(&self) -> Option<ShellDialect> {
            Some(ShellDialect::MkSh)
        }

        fn profile(&self) -> &HostProfile {
            &self.profile
        }

        async fn exec(&self, request: ExecRequest) -> Result<ExecRecord, BackendError> {
            self.seen.lock().unwrap().push(request.script.clone());
            let mut value = self.value.lock().unwrap();
            let (stdout, code) = if request.script.starts_with("getprop ") {
                // Whatever key the capture asks for, this device has exactly one property.
                (value.clone(), 0)
            } else if let Some(rest) = request.script.strip_prefix("setprop ") {
                // `setprop 'debug.acowork.probe' 'one'`
                let mut parts = rest.split_whitespace();
                let key = parts.next().unwrap_or("").trim_matches('\'');
                let val = parts.next().unwrap_or("").trim_matches('\'');
                if key != "debug.acowork.probe" {
                    (String::new(), 1)
                } else {
                    *value = val.to_string();
                    (String::new(), 0)
                }
            } else {
                (String::new(), 0)
            };
            Ok(ExecRecord {
                stdout,
                stderr: String::new(),
                exit_code: Some(code),
                selinux_denials: Vec::new(),
                uid: Some(2000),
                context: Some("u:r:shell:s0".to_string()),
                duration_ms: 1,
                truncated: false,
                timed_out: false,
            })
        }
    }

    async fn write(chain: &ReversibleBackend, script: &str, session: &str) -> i32 {
        let mut request = ExecRequest::new(Capability::ShellWrite, script, session);
        request.approval_token = Some(ApprovalToken::new("test"));
        match chain.exec(request).await {
            Ok(record) => record.exit_code.unwrap_or(-1),
            Err(_) => -1,
        }
    }

    fn tempdir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("acowork-chain-{tag}"));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    /// The reason this module exists. If somebody flips the decorators, the chain still writes,
    /// still restores, and still passes every other test — the only thing lost is the record
    /// that the restore happened.
    #[tokio::test]
    async fn a_restore_is_a_command_the_audit_log_sees() {
        let device = Echo::new();
        let sink = Arc::new(MemoryAuditSink::new());
        let chain = wrap(
            Arc::clone(&device) as Arc<dyn ExecutionBackend>,
            Arc::clone(&sink) as Arc<dyn AuditSink>,
            tempdir("restore"),
        );

        write(&chain, "setprop debug.acowork.probe one", "s-1").await;
        write(&chain, "setprop debug.acowork.probe two", "s-1").await;
        assert_eq!(device.value(), "two");

        let report = chain.restore("s-1").await;
        assert_eq!(report.restored.len(), 2, "{report:?}");
        assert_eq!(device.value(), "", "LIFO takes both changes back");

        let logged: Vec<String> = sink
            .events()
            .into_iter()
            .filter(|e| e.command.contains("setprop"))
            .map(|e| e.command)
            .collect();
        assert!(
            logged.iter().any(|c| c.contains("''")),
            "the restore is in the audit log, not only on the device: {logged:?}"
        );
        assert!(
            device
                .seen()
                .iter()
                .any(|s| s.contains("setprop ") && s.contains("''")),
            "and it really reached the device"
        );
    }

    /// A capture is a read of the device, and §4.6.1 says every command is recorded.
    #[tokio::test]
    async fn a_capture_is_a_command_the_audit_log_sees() {
        let device = Echo::new();
        let sink = Arc::new(MemoryAuditSink::new());
        let chain = wrap(
            Arc::clone(&device) as Arc<dyn ExecutionBackend>,
            Arc::clone(&sink) as Arc<dyn AuditSink>,
            tempdir("capture"),
        );

        write(&chain, "setprop debug.acowork.probe one", "s-2").await;

        let reads = sink
            .events()
            .into_iter()
            .filter(|e| e.command.contains("getprop"))
            .count();
        assert!(
            reads >= 1,
            "the pre-state read went through the audit layer: {:?}",
            sink.events()
                .into_iter()
                .map(|e| e.command)
                .collect::<Vec<_>>()
        );
    }

    /// A failed write must not leave an undo behind — the chain is where that is decided, so it
    /// is asserted here rather than only in the decorator's own tests.
    #[tokio::test]
    async fn a_write_that_did_not_succeed_is_not_promised_back() {
        let device = Echo::new();
        let sink = Arc::new(MemoryAuditSink::new());
        let chain = wrap(
            Arc::clone(&device) as Arc<dyn ExecutionBackend>,
            Arc::clone(&sink) as Arc<dyn AuditSink>,
            tempdir("failed"),
        );

        // A key the fake device refuses.
        write(&chain, "setprop persist.sys.refused 1", "s-3").await;
        let report = chain.restore("s-3").await;
        assert!(report.restored.is_empty(), "{report:?}");
        assert!(report.failed.is_empty(), "{report:?}");
        assert!(
            chain.ledger().lock().unwrap().pending_for("s-3").is_empty(),
            "a write the device refused must not promise a restore"
        );
    }
}
