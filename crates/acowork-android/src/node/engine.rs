//! How the Node finds a Runtime to spawn (ADR-AND-003 §2.2).
//!
//! The upstream desktop node hard-codes a sibling binary named `acowork-runtime`. That is a
//! packaging accident, not a protocol requirement. Here the engine is a configured command:
//! by default the same executable re-entered as `runtime`, and any other program that accepts
//! the same protocol-shaped arguments is equally valid.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

/// Where the Runtime process comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineSpec {
    /// Executable to spawn. `None` means "this process's own executable" (一体默认).
    pub program: Option<PathBuf>,
    /// Fixed prefix argv inserted **before** the protocol launch arguments.
    ///
    /// For the one-binary layout this is `["runtime"]`. For an external engine that is already
    /// a dedicated binary, it is empty.
    pub prefix_args: Vec<OsString>,
}

impl EngineSpec {
    /// One binary, two roles: node re-executes itself as `runtime …`.
    pub fn integrated() -> EngineSpec {
        EngineSpec {
            program: None,
            prefix_args: vec![OsString::from("runtime")],
        }
    }

    /// An external engine binary. File name is irrelevant (B6).
    pub fn external(program: impl Into<PathBuf>) -> EngineSpec {
        EngineSpec {
            program: Some(program.into()),
            prefix_args: Vec::new(),
        }
    }

    /// Parse `--engine PATH` / `--engine integrated`.
    pub fn parse(raw: &str) -> Result<EngineSpec, EngineError> {
        match raw {
            "integrated" | "self" | "" => Ok(EngineSpec::integrated()),
            path => {
                let p = PathBuf::from(path);
                if path.contains('/') || path.contains('\\') || p.exists() {
                    Ok(EngineSpec::external(p))
                } else {
                    // A bare name with no path separators still counts as external — the OS
                    // resolves it via PATH. Never rewrite it to `acowork-runtime`.
                    Ok(EngineSpec::external(p))
                }
            }
        }
    }

    /// Resolve the program path for a spawn.
    pub fn program_path(&self) -> Result<PathBuf, EngineError> {
        match &self.program {
            Some(p) => Ok(p.clone()),
            None => std::env::current_exe().map_err(|e| EngineError::CurrentExe(e.to_string())),
        }
    }
}

/// Protocol-shaped arguments the Node passes to a Runtime (ADR-AND-003 §2.2).
///
/// Field names mirror the upstream CLI flags so a Gateway-facing wire dump stays comparable;
/// the **binary** that receives them is whatever [`EngineSpec`] says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeLaunch {
    /// Package / agent id.
    pub agent_id: String,
    /// Instance id (ADR-073): MQTT and CONNECT username key off this.
    pub instance_id: String,
    /// Loopback HTTP port the Node's reverse proxy will route to.
    pub http_port: u16,
    /// Gateway host the Runtime should dial (broker / HTTP).
    pub gateway_host: String,
    /// Hosting node id.
    pub node_id: String,
    /// Optional MQTT port.
    pub mqtt_port: Option<u16>,
    /// Optional node token (becomes MQTT password when present).
    pub node_token: Option<String>,
    /// Working directory for the agent.
    pub work_dir: PathBuf,
    /// Optional package install path.
    pub package_path: Option<PathBuf>,
    /// Node reverse-proxy base URL (e.g. `http://192.168.x.x:19900`).
    /// When set, the Runtime publishes `{base}/agents/{instance_id}` as its
    /// retained `http_endpoint` so the Gateway dials the Node, not the
    /// phone's unreachable `127.0.0.1:{port}` (ADR-055 §6.3 / D3).
    pub http_advertise_endpoint: Option<String>,
    /// Own package name for HostProfile fs_roots (APK = `com.acowork.androidhost`).
    pub package: Option<String>,
    /// Session dangerous-mode for this child. Never persisted.
    pub dangerous_mode: bool,
}

impl RuntimeLaunch {
    /// Argv after the engine prefix — never includes the program name.
    pub fn args(&self) -> Vec<OsString> {
        let mut args = vec![
            OsString::from("--agent-id"),
            OsString::from(&self.agent_id),
            OsString::from("--agent-instance-id"),
            OsString::from(&self.instance_id),
            OsString::from("--http-port"),
            OsString::from(self.http_port.to_string()),
            OsString::from("--gateway-host"),
            OsString::from(&self.gateway_host),
            OsString::from("--node-id"),
            OsString::from(&self.node_id),
            OsString::from("--work-dir"),
            self.work_dir.as_os_str().to_owned(),
            // HostConfig prepare() creates snapshots/audit/evidence under --root.
            // Default CLI root is "./host" relative to cwd; on Android the
            // engine binary lives under a read-only app path, so omitting
            // --root makes cold-start die with EROFS before MQTT start-ack
            // usefulness (Gateway 504 HandshakeTimeout / workspace load fail).
            OsString::from("--root"),
            self.work_dir.as_os_str().to_owned(),
        ];
        if let Some(port) = self.mqtt_port {
            args.push(OsString::from("--mqtt-port"));
            args.push(OsString::from(port.to_string()));
        }
        if let Some(token) = &self.node_token {
            args.push(OsString::from("--mqtt-username"));
            args.push(OsString::from(format!("agent:{}", self.instance_id)));
            args.push(OsString::from("--mqtt-password"));
            args.push(OsString::from(token));
        }
        if let Some(pkg) = &self.package_path {
            args.push(OsString::from("--package-path"));
            args.push(pkg.as_os_str().to_owned());
        }
        if let Some(base) = &self.http_advertise_endpoint {
            args.push(OsString::from("--http-advertise-endpoint"));
            args.push(OsString::from(base));
        }
        if let Some(pkg) = &self.package {
            args.push(OsString::from("--package"));
            args.push(OsString::from(pkg));
        }
        if self.dangerous_mode {
            args.push(OsString::from("--dangerous-mode"));
        }
        args
    }
}

/// Build the full argv for logging / tests: `[program, prefix…, launch…]`.
pub fn command_line(
    spec: &EngineSpec,
    launch: &RuntimeLaunch,
) -> Result<Vec<OsString>, EngineError> {
    let mut line = Vec::new();
    line.push(OsString::from(spec.program_path()?));
    line.extend(spec.prefix_args.iter().cloned());
    line.extend(launch.args());
    Ok(line)
}

/// Why an engine specification cannot be used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EngineError {
    /// `current_exe` failed.
    CurrentExe(String),
}

impl std::fmt::Display for EngineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EngineError::CurrentExe(e) => write!(f, "cannot resolve current executable: {e}"),
        }
    }
}

impl std::error::Error for EngineError {}

/// True when a path's file name is the upstream desktop runtime name.
///
/// Used only in tests to prove we do **not** require it. Production code never calls this to
/// accept or reject an engine.
pub fn is_upstream_runtime_name(path: &Path) -> bool {
    path.file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| n == "acowork-runtime" || n == "acowork-runtime.exe")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integrated_default_prefixes_runtime_subcommand() {
        let spec = EngineSpec::integrated();
        assert!(spec.program.is_none());
        assert_eq!(spec.prefix_args, [OsString::from("runtime")]);
    }

    #[test]
    fn external_engine_does_not_care_about_file_name() {
        let odd = EngineSpec::external("/opt/my-android-engine");
        assert!(!is_upstream_runtime_name(odd.program.as_ref().unwrap()));
        let decoy = EngineSpec::external("/opt/acowork-runtime");
        // Allowed! B6: the name is irrelevant; configuration is the authority.
        assert!(is_upstream_runtime_name(decoy.program.as_ref().unwrap()));
    }

    #[test]
    fn launch_args_are_protocol_shaped_not_binary_shaped() {
        let launch = RuntimeLaunch {
            agent_id: "com.example.demo".into(),
            instance_id: "inst-1".into(),
            http_port: 19901,
            gateway_host: "192.168.1.10".into(),
            node_id: "node-1".into(),
            mqtt_port: Some(19875),
            node_token: Some("tok".into()),
            work_dir: PathBuf::from("/tmp/ws"),
            package_path: None,
            http_advertise_endpoint: Some("http://192.168.1.20:19900".into()),
            package: Some("com.acowork.androidhost".into()),
            dangerous_mode: true,
        };
        let args: Vec<String> = launch
            .args()
            .into_iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert!(args.contains(&"--http-advertise-endpoint".into()));
        assert!(args.contains(&"http://192.168.1.20:19900".into()));
        assert!(args.contains(&"--package".into()));
        assert!(args.contains(&"com.acowork.androidhost".into()));
        assert!(args.contains(&"--dangerous-mode".into()));
        // rebuild launch without advertise for the rest of the assertions
        let launch = RuntimeLaunch {
            agent_id: "com.example.demo".into(),
            instance_id: "inst-1".into(),
            http_port: 19901,
            gateway_host: "192.168.1.10".into(),
            node_id: "node-1".into(),
            mqtt_port: Some(19875),
            node_token: Some("tok".into()),
            work_dir: PathBuf::from("/tmp/ws"),
            package_path: None,
            http_advertise_endpoint: None,
            package: None,
            dangerous_mode: false,
        };
        let args: Vec<String> = launch
            .args()
            .into_iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert!(args.contains(&"--agent-id".into()));
        assert!(args.contains(&"com.example.demo".into()));
        assert!(args.contains(&"--root".into()));
        assert!(args.contains(&"/tmp/ws".into()));
        assert!(!args.contains(&"--dangerous-mode".into()));
        assert!(args.contains(&"--http-port".into()));
        assert!(args.contains(&"19901".into()));
        assert!(args.contains(&"agent:inst-1".into()));
        assert!(!args.iter().any(|a| a.contains("acowork-runtime")));
    }
}
