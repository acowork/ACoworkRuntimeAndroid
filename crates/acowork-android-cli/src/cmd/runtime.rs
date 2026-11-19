//! `acowork-android runtime` — one agent instance (ADR-AND-003 §2.3).
//!
//! Spawns the vendored `acowork-runtime` engine after probing the Android host
//! and installing an `ExecutionBackend` so shell tools go through the ADR-AND-001
//! gate (feature `android-host` on the vendored runtime).

use std::path::PathBuf;
use std::sync::Arc;

use acowork_android::host::{HostConfig, HostProfile, ProbeCommand, run_probe};
use acowork_android::node::capability_tags;
use acowork_runtime::cli::Cli;

use crate::session::CommonArgs;
use crate::transport::Transport;

pub struct RuntimeArgs {
    pub common: CommonArgs,
    pub agent_id: String,
    pub instance_id: String,
    pub http_port: u16,
    pub gateway_host: String,
    pub node_id: String,
    pub work_dir: PathBuf,
    pub mqtt_port: Option<u16>,
    pub package_path: Option<PathBuf>,
    pub mqtt_username: Option<String>,
    pub mqtt_password: Option<String>,
    /// Node reverse-proxy base (`http://lan:19900`). Runtime publishes
    /// `{base}/agents/{instance_id}` as retained `http_endpoint`.
    pub http_advertise_endpoint: Option<String>,
}

/// Sync entry: probe host, install backend, then hand off to vendored Runtime.
pub fn run(args: RuntimeArgs) -> Result<(), String> {
    std::fs::create_dir_all(&args.work_dir).map_err(|e| e.to_string())?;

    let package_path = args.package_path.ok_or_else(|| {
        "runtime requires --package-path (Node install path or .agent ZIP/dir)".to_string()
    })?;
    if !package_path.exists() {
        return Err(format!(
            "package path does not exist: {}",
            package_path.display()
        ));
    }

    // Probe + backend on a short-lived runtime, then drop it before Cli::run
    // builds its own multi-thread runtime (nested runtimes panic).
    {
        let probe_rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|e| e.to_string())?;
        let chain = probe_rt.block_on(async {
            let transport = Transport::open(args.common.transport)?;
            let loaded = HostConfig::load(&args.common.root).map_err(|e| e.to_string())?;
            let probe = run_probe(
                transport.as_probe(),
                &ProbeCommand::read_only_set(),
                &args.common.package,
            )
            .await;
            let profile = HostProfile::assemble(&probe, &args.common.package);
            let prepared = loaded
                .config
                .prepare(&args.common.root)
                .map_err(|e| e.to_string())?;
            let inner = transport
                .inner_backend(profile.clone(), prepared.default_budget)
                .map_err(|e| e.to_string())?;
            let tags = capability_tags(&profile);
            eprintln!(
                "acowork-android runtime: agent={} instance={} http=127.0.0.1:{} node={} gateway={} profile={} backend={}",
                args.agent_id,
                args.instance_id,
                args.http_port,
                args.node_id,
                args.gateway_host,
                profile.name.as_str(),
                acowork_android::host::ExecutionBackend::name(inner.as_ref()),
            );
            eprintln!("  caps {}", tags.join(", "));
            eprintln!("  package {}", package_path.display());
            Ok::<_, String>(prepared.chain(Arc::clone(&inner)))
        })?;
        acowork_runtime::android_exec::install(chain);
    }

    let cli = Cli {
        agent_id: args.agent_id,
        agent_instance_id: args.instance_id,
        package_path: package_path.to_string_lossy().replace('\\', "/"),
        work_dir: args.work_dir.to_string_lossy().replace('\\', "/"),
        dev_mode: false,
        debug_port: 19878,
        log_level: std::env::var("ACOWORK_LOG_LEVEL").unwrap_or_else(|_| "info".into()),
        log_file_size_mb: 10,
        log_file_count: 20,
        manifest_path: None,
        config_dir: None,
        mqtt_port: args.mqtt_port,
        http_port: Some(args.http_port),
        gateway_host: Some(args.gateway_host),
        gateway_http_port: None,
        http_advertise_endpoint: args.http_advertise_endpoint,
        node_id: Some(args.node_id),
        mqtt_username: args.mqtt_username,
        mqtt_password: args.mqtt_password,
    };

    cli.run().map_err(|e| e.to_string())
}
