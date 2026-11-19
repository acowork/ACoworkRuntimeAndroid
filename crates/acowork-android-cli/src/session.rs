//! Assemble a probed host + configured chain for one CLI invocation.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use acowork_android::host::{
    ExecutionBackend, HostConfig, HostProfile, LoadSource, Loaded, PreparedHost, ProbeCommand,
    ReversibleBackend, run_probe,
};
use acowork_platform_contract::{
    AttributionVerdict, Gate, GateDecision, HostDescription, LocalReadiness, LockState,
};

use crate::transport::{Transport, TransportKind};

/// Shared flags every subcommand that talks to a device understands.
#[derive(Debug, Clone)]
pub struct CommonArgs {
    pub root: PathBuf,
    pub package: String,
    pub session: String,
    pub transport: TransportKind,
    /// Session-level dangerous-mode switch. Never persisted (ADR-AND-001 §7.3).
    pub dangerous_mode: bool,
}

impl CommonArgs {
    pub fn defaults() -> CommonArgs {
        CommonArgs {
            root: PathBuf::from("./host"),
            package: "com.acowork.host".to_string(),
            session: "acowork-android".to_string(),
            transport: TransportKind::Auto,
            dangerous_mode: false,
        }
    }
}

/// A probed device plus the chain built from the operator's settings document.
pub struct Session {
    pub transport: Transport,
    pub loaded: Loaded,
    pub profile: HostProfile,
    pub prepared: PreparedHost,
    pub chain: Arc<ReversibleBackend>,
    pub inner: Arc<dyn ExecutionBackend>,
    pub dangerous_mode: bool,
}

impl Session {
    pub async fn open(common: &CommonArgs) -> Result<Session, String> {
        let transport = Transport::open(common.transport)?;
        let loaded = HostConfig::load(&common.root).map_err(|e| e.to_string())?;
        let probe = run_probe(
            transport.as_probe(),
            &ProbeCommand::read_only_set(),
            &common.package,
        )
        .await;
        let profile = HostProfile::assemble(&probe, &common.package);
        let prepared = loaded
            .config
            .prepare(&common.root)
            .map_err(|e| e.to_string())?;
        let inner = transport
            .inner_backend(profile.clone(), prepared.default_budget)
            .map_err(|e| e.to_string())?;
        let chain = prepared.chain(Arc::clone(&inner));
        Ok(Session {
            transport,
            loaded,
            profile,
            prepared,
            chain,
            inner,
            dangerous_mode: common.dangerous_mode,
        })
    }

    pub fn settings_source_for(&self, root: &Path) -> String {
        match &self.loaded.source {
            LoadSource::File(path) => path.display().to_string(),
            LoadSource::Defaults => format!(
                "defaults — {} does not exist yet",
                HostConfig::settings_file(root).display()
            ),
        }
    }

    /// Readiness for one request: dangerous-mode from the CLI flag, approval from the token.
    pub fn readiness(&self, approval_presented: bool) -> LocalReadiness {
        LocalReadiness {
            dangerous_session: self.dangerous_mode,
            approval_presented,
            lock: LockState::Available,
        }
    }

    /// Run the contract gate before anything reaches the device.
    ///
    /// Attribution is `None` until MQTT enroll lands. For tiers that need Manage
    /// attribution that fails closed — which is the honest answer, not a bug.
    pub fn decide(&self, request: &acowork_android::host::ExecRequest) -> GateDecision {
        let approval = request.approval_token.is_some();
        Gate::new(&self.profile).decide(
            request,
            Option::<AttributionVerdict>::None,
            self.readiness(approval),
        )
    }

    pub fn print_banner(&self, root: &Path) {
        println!("transport  {}", self.transport.describe());
        println!("settings   {}", self.settings_source_for(root));
        println!(
            "profile    {} · privilege {:?} · shell {:?} · SELinux {:?}",
            self.profile.name.as_str(),
            self.profile.privilege,
            self.profile.shell,
            self.profile.selinux,
        );
        if self.dangerous_mode {
            println!("session    dangerous-mode ON (not persisted; dies with this process)");
        }
        let summary = HostDescription::summary(&self.profile);
        println!(
            "caps       {}",
            if summary.capabilities.is_empty() {
                "(none)".to_string()
            } else {
                summary.capabilities.join(", ")
            }
        );
    }
}
