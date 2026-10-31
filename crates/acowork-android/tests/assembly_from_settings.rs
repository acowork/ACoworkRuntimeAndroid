//! From a settings document on disk to a chain that runs a command and undoes it.
//!
//! Everything in `host/config.rs` was verified by unit tests that build a `HostConfig` in code.
//! That leaves the one question a caller actually asks unanswered: does a document an operator
//! saved reach the process? This file answers it through **the public API only** — no `#[cfg(test)]`
//! helpers, no crate-internal types — because a caller that cannot assemble a runtime out of
//! `acowork_android::host::*` is a caller that will not exist inside an APK either.
//!
//! The three things pinned here are the three the review round found unproven:
//!
//! 1. the directories, budgets and limits named in the document are the ones the assembled host
//!    uses, not the crate's constants;
//! 2. a command run through the assembled chain is audited into the file the document names, under
//!    the cap the document sets;
//! 3. a document that does not parse leaves no half-assembled runtime behind.
//!
//! No device is involved: the inner backend is a fake that behaves like a shell with a property
//! store, so the decorators, the ledger, the sink and the filesystem are all real.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use acowork_android::host::{
    AUDIT_FILE_NAME, ApprovalToken, BackendError, Capability, ExecRecord, ExecRequest,
    ExecutionBackend, HostConfig, HostProfile, LoadSource, ShellDialect,
};

mod common;
use common::rooted_probe;

/// A device with a property store and a memory of what it was asked to run.
struct Device {
    profile: HostProfile,
    state: Mutex<BTreeMap<String, String>>,
    seen: Mutex<Vec<String>>,
}

impl Device {
    fn new(profile: HostProfile) -> Arc<Device> {
        Arc::new(Device {
            profile,
            state: Mutex::new(BTreeMap::new()),
            seen: Mutex::new(Vec::new()),
        })
    }

    fn scripts(&self) -> Vec<String> {
        self.seen.lock().unwrap().clone()
    }

    fn value(&self, key: &str) -> Option<String> {
        self.state.lock().unwrap().get(key).cloned()
    }
}

#[async_trait::async_trait]
impl ExecutionBackend for Device {
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
        let script = request.script.clone();
        self.seen.lock().unwrap().push(script.clone());
        let out;
        let mut code = 0;
        if let Some(key) = script.strip_prefix("getprop ") {
            let key = key.trim_matches('\'');
            let value = self
                .state
                .lock()
                .unwrap()
                .get(key)
                .cloned()
                .unwrap_or_default();
            // What a real `getprop` prints: the value and a newline, and nothing else. The
            // SELinux context a real backend also learns comes back on `ExecRecord::context`,
            // not inside stdout — putting it here would make the pre-state capture record an
            // undo that sets the property to a two-line string.
            out = format!("{value}\n");
        } else if let Some(rest) = script.strip_prefix("setprop ") {
            let mut parts = rest.split_whitespace();
            let key = parts.next().unwrap_or("").trim_matches('\'');
            let value = parts.next().unwrap_or("").trim_matches('\'');
            self.state
                .lock()
                .unwrap()
                .insert(key.to_string(), value.to_string());
            out = String::new();
        } else {
            code = 127;
            out = format!("this fake device does not run: {script}");
        }
        Ok(ExecRecord {
            stdout: out,
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

/// A root the caller owns, removed at the end of the test.
struct Root(PathBuf);

impl Root {
    fn new(name: &str) -> Root {
        let dir = std::env::temp_dir().join(format!("acowork-assembly-{name}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("a temp root for the runtime's own files");
        Root(dir)
    }
}

impl Drop for Root {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A document that changes every number the screen can change, so a value left at the crate's
/// constant cannot pass for one that was read.
const EDITED: &str = r#"{
  "storage": {
    "snapshot_subdir": "snap-v1",
    "audit_subdir": "trail-v1",
    "evidence_subdir": "shots-v1"
  },
  "budgets": {
    "snapshot_store_bytes": 131072,
    "audit_file_bytes": 65536,
    "evidence_budget_bytes": 524288,
    "output_cap_bytes": 16384
  },
  "timing": {
    "command_timeout_secs": 11,
    "lock_ttl_secs": 44,
    "bugreport_timeout_secs": 77
  },
  "evidence": {
    "screenshot": true,
    "logcat": false,
    "logcat_tail_lines": 25,
    "dumpsys": true,
    "device_files": false,
    "bugreport": false
  },
  "capability_ceiling": ["android:shell:read", "android:shell:write", "android:fs:outside-app"]
}"#;

#[tokio::test]
async fn every_number_in_a_saved_document_is_the_number_the_chain_runs_with() {
    let root = Root::new("numbers");
    std::fs::write(root.0.join("settings.json"), EDITED).unwrap();

    let loaded = HostConfig::load(&root.0).expect("the document is valid");
    assert_eq!(
        loaded.source,
        LoadSource::File(root.0.join("settings.json")),
        "a document that exists must be reported as read, not as defaulted"
    );

    let prepared = loaded.config.prepare(&root.0).unwrap();

    // Paths: the subdirectory names from the document, not the defaults.
    assert_eq!(prepared.snapshots.dir(), root.0.join("snap-v1"));
    assert_eq!(
        prepared.audit.path(),
        root.0.join("trail-v1").join(AUDIT_FILE_NAME)
    );
    assert_eq!(prepared.evidence_dir, root.0.join("shots-v1"));
    for dir in ["snap-v1", "trail-v1", "shots-v1"] {
        assert!(root.0.join(dir).is_dir(), "{dir} was not created");
    }

    // Budgets and waits. Each of these was a decoration row at some point during this port's
    // development; the assertion is that the assembled host carries the operator's number.
    assert_eq!(prepared.snapshots.budget(), 131_072);
    assert_eq!(prepared.audit.max_bytes(), 65_536);
    assert_eq!(prepared.default_budget.output_cap, 16_384);
    assert_eq!(
        prepared.default_budget.timeout,
        Some(std::time::Duration::from_secs(11))
    );
    assert_eq!(prepared.limits.budget, 524_288);
    assert_eq!(
        prepared.limits.bugreport,
        std::time::Duration::from_secs(77)
    );
}

#[tokio::test]
async fn a_write_through_the_assembled_chain_is_audited_and_then_undone() {
    let root = Root::new("write");
    std::fs::write(root.0.join("settings.json"), EDITED).unwrap();
    let config = HostConfig::load(&root.0).unwrap().config;

    let profile = HostProfile::assemble(&rooted_probe(), "com.example.agent");
    // The device starts with a value, so the undo has an exact inverse to run rather than a
    // snapshot to restore — which keeps this test about the assembly rather than about bytes.
    let device = Device::new(profile.clone());
    device
        .state
        .lock()
        .unwrap()
        .insert("debug.acowork.demo".to_string(), "before".to_string());

    let prepared = config.prepare(&root.0).unwrap();
    let inner: Arc<dyn ExecutionBackend> = device.clone();
    let chain = prepared.chain(inner);

    let mut request = ExecRequest::new(
        Capability::ShellWrite,
        "setprop 'debug.acowork.demo' 'after'",
        "s-1",
    );
    request.approval_token = Some(ApprovalToken::new("test-operator"));
    let record = chain.exec(request).await.expect("the chain runs it");
    assert_eq!(record.exit_code, Some(0));
    assert_eq!(
        device.value("debug.acowork.demo").as_deref(),
        Some("after"),
        "the write should have happened before any undo"
    );

    let report = chain.restore("s-1").await;
    assert_eq!(
        report.restored.len(),
        1,
        "one write, one undo: {:?}",
        report.failed
    );
    assert_eq!(
        device.value("debug.acowork.demo").as_deref(),
        Some("before"),
        "the device is back the way it was found"
    );

    // The audit file is the operator's answer, and it has to be in the place the document named.
    let text = std::fs::read_to_string(root.0.join("trail-v1").join(AUDIT_FILE_NAME))
        .expect("the configured audit file");
    let lines: Vec<&str> = text.lines().collect();
    assert!(
        lines.len() >= 6,
        "attempt+result for the capture, the write and the undo, got {}",
        lines.len()
    );
    assert!(
        text.contains("\"session_id\":\"s-1\""),
        "the audit trail must attribute the run to the session that asked for it"
    );
    assert!(
        text.contains("setprop 'debug.acowork.demo' 'before'"),
        "the undo has to be in the record, or the trail says the device was changed and never \
         says it was put back"
    );
}

#[tokio::test]
async fn a_document_that_does_not_parse_leaves_no_half_assembled_runtime() {
    // The failure an operator actually causes: they edit the file by hand, get one key wrong, and
    // start the runtime. If `load` fell back to defaults the runtime would come up with a policy
    // nobody chose while the screen showed theirs; if `prepare` ran first it would come up with
    // directories and an audit file for a session that must not exist.
    let root = Root::new("broken");
    std::fs::write(
        root.0.join("settings.json"),
        EDITED.replace("output_cap_bytes", "output_kap_bytes"),
    )
    .unwrap();

    let err = HostConfig::load(&root.0).expect_err("an unknown field is an error, not a default");
    assert!(
        err.to_string().contains("output_kap_bytes"),
        "the refusal should name what it could not read: {err}"
    );
    assert!(
        !root.0.join("snap-v1").exists() && !root.0.join("trail-v1").exists(),
        "a rejected document must not have created the runtime's directories"
    );
    assert_eq!(
        std::fs::read_dir(&root.0)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name() != "settings.json")
            .count(),
        0,
        "nothing but the document itself was left behind"
    );
}

#[tokio::test]
async fn a_source_the_screen_switched_off_is_refused_without_touching_the_device() {
    // `evidence.logcat` is false in the document. The capture entry point has to consult it,
    // because a runtime that collects the log anyway has broken the one promise the evidence
    // section exists to make.
    let root = Root::new("policy");
    std::fs::write(root.0.join("settings.json"), EDITED).unwrap();
    let config = HostConfig::load(&root.0).unwrap().config;
    let prepared = config.prepare(&root.0).unwrap();

    let device = Device::new(HostProfile::assemble(&rooted_probe(), "com.example.agent"));
    let inner: Arc<dyn ExecutionBackend> = device.clone();
    let err = prepared
        .capture(
            &inner,
            &acowork_android::host::EvidenceSource::Logcat {
                buffer: None,
                filter: Vec::new(),
                tail: None,
            },
            "s-1",
            None,
        )
        .await
        .expect_err("logcat is switched off in the document");
    match err {
        acowork_android::host::CaptureError::NotAllowed { setting, .. } => {
            assert_eq!(setting, "evidence.logcat");
        }
        other => panic!("expected a policy refusal, got {other:?}"),
    }
    assert!(
        device.scripts().is_empty(),
        "a refused capture must not have sent anything to the device"
    );
}

#[tokio::test]
async fn the_ceiling_in_the_document_is_a_ceiling_rather_than_a_request() {
    // The rooted fixture earns all five capabilities. The document lists three, so the claims the
    // node reports must be those three — and the two it left out must be reported as *the
    // operator's* decision, not as a device limitation. That distinction is the difference between
    // a user being told to get a different phone and being told to change a setting.
    let root = Root::new("ceiling");
    std::fs::write(root.0.join("settings.json"), EDITED).unwrap();
    let config = HostConfig::load(&root.0).unwrap().config;
    let profile = HostProfile::assemble(&rooted_probe(), "com.example.agent");

    let claimed: Vec<String> = config
        .claims(&profile)
        .unwrap()
        .into_iter()
        .map(|c| c.capability.as_str().to_string())
        .collect();
    assert_eq!(
        claimed,
        vec![
            "android:shell:read",
            "android:shell:write",
            "android:fs:outside-app",
        ],
        "the ceiling narrows; it never adds"
    );
    let blocked = config.blocked_by_settings(&profile);
    let blocked_ids: Vec<String> = blocked
        .iter()
        .map(|c| c.id().as_str().to_string())
        .collect();
    assert_eq!(
        blocked_ids,
        vec!["android:fs:system", "android:selinux:permissive"],
        "the device could do both; the document said no, and the screen has to be able to say so"
    );
}

/// The document is written under a root the caller owns; this checks that a root that cannot be
/// created is a reported failure rather than a runtime that silently has no audit trail.
#[tokio::test]
async fn a_root_that_cannot_be_created_is_a_refusal_rather_than_an_unaudited_runtime() {
    let impossible = Path::new("/proc/acowork-cannot-be-here");
    let err = HostConfig::defaults()
        .prepare(impossible)
        .expect_err("no directories, no runtime");
    assert!(
        !err.to_string().is_empty(),
        "the assembly failure has to say why"
    );
}
