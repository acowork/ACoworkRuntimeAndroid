//! In-process Runtime table (ADR-AND-003 §2.3).
//!
//! Children are tracked by **instance id**, never by argv0 basename. That is the B6 unlock:
//! an external engine named anything is still the same row.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Stdio;

use tokio::process::{Child, Command};

use super::engine::{EngineError, EngineSpec, RuntimeLaunch};

/// One live (or recently exited) Runtime.
#[derive(Debug)]
pub struct RuntimeHandle {
    /// Package / agent id.
    pub agent_id: String,
    /// Instance id (primary key).
    pub instance_id: String,
    /// Loopback port it was started with.
    pub http_port: u16,
    /// OS pid while running.
    pub pid: Option<u32>,
    /// Program that was exec'd (for diagnostics only).
    pub program: PathBuf,
    /// Child process, while we still own it.
    child: Option<Child>,
}

/// Coarse status for listing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeStatus {
    /// Child is still held and has not been waited.
    Running,
    /// `try_wait` saw an exit (or the child was taken).
    Exited,
}

impl RuntimeHandle {
    /// Refresh and return whether the child is still running.
    pub fn status(&mut self) -> RuntimeStatus {
        match self.child.as_mut() {
            None => RuntimeStatus::Exited,
            Some(child) => match child.try_wait() {
                Ok(Some(_)) => {
                    self.pid = None;
                    RuntimeStatus::Exited
                }
                Ok(None) => RuntimeStatus::Running,
                Err(_) => RuntimeStatus::Exited,
            },
        }
    }
}

/// The Node's process table: one device, one table (ADR-AND-001 §7.2 spirit).
#[derive(Debug, Default)]
pub struct ProcessTable {
    entries: BTreeMap<String, RuntimeHandle>,
    next_port: u16,
}

impl ProcessTable {
    /// Start empty; first allocated HTTP port is `base` (default 19901).
    pub fn new(base_http_port: u16) -> ProcessTable {
        ProcessTable {
            entries: BTreeMap::new(),
            next_port: base_http_port.max(19901),
        }
    }

    /// How many rows are still Running.
    pub fn running_count(&mut self) -> usize {
        self.entries
            .values_mut()
            .filter_map(|h| {
                if h.status() == RuntimeStatus::Running {
                    Some(())
                } else {
                    None
                }
            })
            .count()
    }

    /// Allocate the next loopback HTTP port.
    pub fn allocate_http_port(&mut self) -> u16 {
        let port = self.next_port;
        self.next_port = self.next_port.saturating_add(1);
        port
    }

    /// Spawn a Runtime via `spec` + `launch`.
    pub async fn start(
        &mut self,
        spec: &EngineSpec,
        launch: RuntimeLaunch,
    ) -> Result<&RuntimeHandle, ProcessError> {
        if self.entries.contains_key(&launch.instance_id) {
            return Err(ProcessError::AlreadyRunning(launch.instance_id.clone()));
        }
        let program = spec.program_path().map_err(ProcessError::Engine)?;
        let mut cmd = Command::new(&program);
        for a in &spec.prefix_args {
            cmd.arg(a);
        }
        for a in launch.args() {
            cmd.arg(a);
        }
        // Capture engine stderr under the instance work dir when possible so
        // Android logcat is not the only place a failed cold-start shows up.
        let log_path = launch.work_dir.join("engine.stderr.log");
        let stderr = std::fs::File::create(&log_path)
            .map(Stdio::from)
            .unwrap_or_else(|_| Stdio::null());

        // Point the child at the APK-packaged ash (SELinux-executable).
        if let Some(dir) = program.parent() {
            let ash = dir.join("libacowork_ash.so");
            if ash.is_file() {
                cmd.env("ACOWORK_ASH", &ash);
            }
        }
        // Device tools (camera, audio, BLE, USB HID) call back into the app
        // process. The token file is written when the bridge starts; engines
        // spawned before that simply do not see the tools.
        if let Some(home) = std::env::var_os("HOME") {
            // Do not rely on inherit: tokio Command may snapshot env without
            // later set_var mutations. Pass the node home explicitly.
            cmd.env("HOME", &home);
            cmd.env("ACOWORK_NODE_HOME", &home);
            if let Some(value) = crate::device::endpoint_from_home(std::path::Path::new(&home)) {
                cmd.env(crate::device::ENV_BRIDGE, value);
            } else {
                eprintln!(
                    "acowork-android control: device bridge token missing under {}",
                    std::path::Path::new(&home).display()
                );
            }
        } else {
            eprintln!(
                "acowork-android control: HOME unset — cannot inject {}",
                crate::device::ENV_BRIDGE
            );
        }
        cmd.stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(stderr)
            .current_dir(&launch.work_dir)
            .kill_on_drop(true);

        // process_group(0) is useful on Linux desktops so stop() can kill the
        // whole tree. On Android it has been observed to make spawn flaky /
        // slow under the app sandbox — skip it there.
        #[cfg(all(unix, not(target_os = "android")))]
        cmd.process_group(0);

        let child = cmd.spawn().map_err(|e| ProcessError::Spawn {
            program: program.display().to_string(),
            reason: e.to_string(),
        })?;
        let pid = child.id();
        let key = launch.instance_id.clone();
        self.entries.insert(
            key.clone(),
            RuntimeHandle {
                agent_id: launch.agent_id,
                instance_id: launch.instance_id,
                http_port: launch.http_port,
                pid,
                program,
                child: Some(child),
            },
        );
        Ok(self.entries.get(&key).expect("just inserted"))
    }

    /// Stop by instance id. Missing → error.
    pub async fn stop(&mut self, instance_id: &str) -> Result<(), ProcessError> {
        let Some(mut handle) = self.entries.remove(instance_id) else {
            return Err(ProcessError::NotFound(instance_id.to_string()));
        };
        if let Some(mut child) = handle.child.take() {
            let _ = child.start_kill();
            let _ = child.wait().await;
        }
        Ok(())
    }

    /// Snapshot for listing (refreshes exit status).
    pub fn list(&mut self) -> Vec<(String, String, u16, RuntimeStatus, Option<u32>)> {
        let mut out = Vec::new();
        for h in self.entries.values_mut() {
            let status = h.status();
            out.push((
                h.agent_id.clone(),
                h.instance_id.clone(),
                h.http_port,
                status,
                h.pid,
            ));
        }
        out
    }
}

/// Process-table failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcessError {
    /// Engine path could not be resolved.
    Engine(EngineError),
    /// Spawn failed.
    Spawn {
        /// Program that was attempted.
        program: String,
        /// OS reason.
        reason: String,
    },
    /// Instance already in the table.
    AlreadyRunning(String),
    /// Unknown instance id.
    NotFound(String),
}

impl std::fmt::Display for ProcessError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProcessError::Engine(e) => write!(f, "{e}"),
            ProcessError::Spawn { program, reason } => {
                write!(f, "cannot spawn {program}: {reason}")
            }
            ProcessError::AlreadyRunning(id) => {
                write!(f, "instance `{id}` is already in the process table")
            }
            ProcessError::NotFound(id) => write!(f, "instance `{id}` is not in the process table"),
        }
    }
}

impl std::error::Error for ProcessError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ports_allocate_monotonically() {
        let mut t = ProcessTable::new(19901);
        assert_eq!(t.allocate_http_port(), 19901);
        assert_eq!(t.allocate_http_port(), 19902);
    }
}
