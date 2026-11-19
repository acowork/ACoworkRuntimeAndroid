//! How the CLI reaches a device: locally (on-device) or over `adb` (from a host).

use std::fmt;
use std::sync::Arc;

use acowork_android::host::{
    AdbTransport, AppSandboxBackend, BackendError, ExecutionBackend, HostProfile, HostProfileName,
    LocalHost, ProbeRunner, ProcessSpawnRunner, RootShellBackend, ShellBackend, SpawnRunner,
};
use acowork_platform_contract::Budget;

/// Which transport the operator asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportKind {
    /// Measure *this* process's shell. The Termux / on-device default.
    Local,
    /// Reach a phone from a development host over `adb`.
    Adb,
    /// Pick local on Android targets, adb everywhere else.
    Auto,
}

impl TransportKind {
    pub fn parse(raw: &str) -> Result<TransportKind, String> {
        match raw {
            "local" => Ok(TransportKind::Local),
            "adb" => Ok(TransportKind::Adb),
            "auto" => Ok(TransportKind::Auto),
            other => Err(format!(
                "unknown --transport `{other}` (expected local|adb|auto)"
            )),
        }
    }

    pub fn resolve(self) -> TransportKind {
        match self {
            TransportKind::Auto => {
                if cfg!(target_os = "android") {
                    TransportKind::Local
                } else {
                    TransportKind::Adb
                }
            }
            other => other,
        }
    }
}

impl fmt::Display for TransportKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            TransportKind::Local => "local",
            TransportKind::Adb => "adb",
            TransportKind::Auto => "auto",
        })
    }
}

/// A probe runner plus the spawn runner the matching backend will use.
///
/// Kept as one enum so a profile probed over adb cannot be handed to a local
/// [`ShellBackend`] by accident — the two runners answer for different machines.
pub enum Transport {
    Local(LocalHost),
    Adb(AdbTransport),
}

impl Transport {
    pub fn open(kind: TransportKind) -> Result<Transport, String> {
        match kind.resolve() {
            TransportKind::Local => LocalHost::new()
                .map(Transport::Local)
                .map_err(|e| e.to_string()),
            TransportKind::Adb => AdbTransport::from_env().map(Transport::Adb).ok_or_else(|| {
                "no adb to talk to: set ACOWORK_ADB to the binary and \
                     ACOWORK_ADB_SERIAL to the device (or connect exactly one device)"
                    .to_string()
            }),
            TransportKind::Auto => unreachable!("resolve() collapsed Auto"),
        }
    }

    pub fn kind(&self) -> TransportKind {
        match self {
            Transport::Local(_) => TransportKind::Local,
            Transport::Adb(_) => TransportKind::Adb,
        }
    }

    pub fn describe(&self) -> String {
        match self {
            Transport::Local(host) => format!("local shell at {}", host.shell().display()),
            Transport::Adb(t) => format!(
                "adb attached to {}",
                t.serial().unwrap_or("the only device connected")
            ),
        }
    }

    pub fn as_probe(&self) -> &dyn ProbeRunner {
        match self {
            Transport::Local(host) => host,
            Transport::Adb(t) => t,
        }
    }

    /// Build the innermost backend for this profile over this transport.
    ///
    /// Tier selection follows the probed [`HostProfileName`]: a rooted profile gets
    /// [`RootShellBackend`], a shell tier gets [`ShellBackend`], and the sandbox gets the
    /// backend whose only honest answer is that there is no shell. The choice is a function of
    /// the probe, never of a CLI flag — a `--root` switch that widened the tier would be a
    /// settings file forging capability claims.
    pub fn inner_backend(
        &self,
        profile: HostProfile,
        budget: Budget,
    ) -> Result<Arc<dyn ExecutionBackend>, BackendError> {
        match self {
            Transport::Local(_) => build_inner(profile, ProcessSpawnRunner::new(), budget),
            Transport::Adb(t) => build_inner(profile, t.clone(), budget),
        }
    }
}

fn build_inner<R: SpawnRunner + 'static>(
    profile: HostProfile,
    runner: R,
    budget: Budget,
) -> Result<Arc<dyn ExecutionBackend>, BackendError> {
    match profile.name {
        HostProfileName::RootShell => Ok(Arc::new(
            RootShellBackend::with_runner(profile, runner)?.with_default_budget(budget),
        )),
        HostProfileName::ApkSandbox => Ok(Arc::new(AppSandboxBackend::new(profile))),
        HostProfileName::Termux | HostProfileName::SystemShell => Ok(Arc::new(
            ShellBackend::with_runner(profile, runner)?.with_default_budget(budget),
        )),
    }
}
