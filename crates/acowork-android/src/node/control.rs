//! Node MQTT control plane — PC `acowork-node` `handle_incoming` shape.
//!
//! ADR-AND-003: independent impl, identical Gateway protocol. Parse the
//! control topic first; reply on agent- or node-scoped events; never invent
//! a reply topic when parse fails.

use std::path::Path;
use std::time::Duration;

use super::engine::{EngineSpec, RuntimeLaunch};
use super::mqtt::{
    IncomingPublish, MqttSession, SharedIdentity, decode_envelope, info_envelope, publish_event,
};
use super::package::PackageInventory;
use super::process::{ProcessTable, RuntimeStatus};
use super::proto::{data_envelope, node_control_command};
use super::proxy::{PortTable, sync_ports};
use super::topics::{
    GATEWAY_MQTT_PORT, node_agent_events_topic, node_events_topic, node_info_topic,
    parse_control_topic,
};

/// Live pieces needed to execute control commands (shared by CLI + FFI).
pub struct ControlCtx<'a> {
    /// MQTT session used to publish NodeEvent replies and retained info.
    pub session: &'a mut MqttSession,
    /// Shared node identity (node_id / node_token).
    pub identity: &'a SharedIdentity,
    /// Running Runtime children.
    pub table: &'a mut ProcessTable,
    /// Reverse-proxy instance_id → loopback port map.
    pub ports: &'a PortTable,
    /// Local `.agent` package inventory.
    pub packages: &'a mut PackageInventory,
    /// Engine binary used to spawn Runtime.
    pub engine: &'a EngineSpec,
    /// Gateway host (no scheme) for Runtime MQTT dial.
    pub gateway_host: &'a str,
    /// Node data home (packages, agents work dirs).
    pub root: &'a Path,
    /// Capability tags already announced on NodeInfo.
    pub tags: &'a [String],
    /// Advertised Node HTTP base (`http://host:port`) for Runtime announce.
    pub http_endpoint: &'a str,
}

/// Handle one inbound MQTT publish that may be a control command.
///
/// Non-control topics (and parse failures) are ignored — same gate as PC
/// `handle_incoming`. Enroll results are the caller's job.
pub async fn handle_control(msg: &IncomingPublish, ctx: &mut ControlCtx<'_>) {
    let node_id = {
        let id = ctx.identity.read().await;
        id.node_id.clone()
    };

    let Some((_, agent_id)) = parse_control_topic(&msg.topic, &node_id) else {
        return;
    };

    let Ok(env) = decode_envelope(&msg.payload) else {
        return;
    };
    let Some(data_envelope::Payload::NodeControlCommand(cmd)) = env.payload else {
        return;
    };

    if cmd.node_id != node_id {
        eprintln!(
            "acowork-android control: command.node_id '{}' != topic node_id '{}' — ignoring",
            cmd.node_id, node_id
        );
        return;
    }
    if cmd.request_id.is_empty() {
        eprintln!("acowork-android control: missing request_id — ignoring");
        return;
    }

    let reply_topic = match &agent_id {
        Some(aid) => node_agent_events_topic(&node_id, aid),
        None => node_events_topic(&node_id),
    };

    let token = ctx.identity.read().await.node_token.clone();
    let request_id = cmd.request_id.clone();

    match cmd.command {
        Some(node_control_command::Command::Ping(_)) => {
            let _ = publish_event(ctx.session, &reply_topic, &node_id, &request_id, "ok", "pong")
                .await;
            let _ = refresh_info(ctx).await;
        }
        Some(node_control_command::Command::Start(start)) => {
            let agent_id = start.agent_id;
            let instance_id = if start.instance_id.is_empty() {
                None
            } else {
                Some(start.instance_id)
            };
            match start_agent(ctx, &agent_id, instance_id.as_deref(), token).await {
                Ok(()) => {
                    let _ = publish_event(
                        ctx.session,
                        &reply_topic,
                        &node_id,
                        &request_id,
                        "ok",
                        &format!("started {agent_id}"),
                    )
                    .await;
                    let _ = refresh_info(ctx).await;
                }
                Err(e) => {
                    let _ = publish_event(
                        ctx.session,
                        &reply_topic,
                        &node_id,
                        &request_id,
                        "error",
                        &e,
                    )
                    .await;
                }
            }
        }
        Some(node_control_command::Command::Stop(stop)) => {
            let instance_id = if stop.instance_id.is_empty() {
                stop.agent_id
            } else {
                stop.instance_id
            };
            match ctx.table.stop(&instance_id).await {
                Ok(()) => {
                    sync_ports_from_table(ctx.ports, ctx.table).await;
                    let _ = publish_event(
                        ctx.session,
                        &reply_topic,
                        &node_id,
                        &request_id,
                        "ok",
                        &format!("stopped {instance_id}"),
                    )
                    .await;
                    let _ = refresh_info(ctx).await;
                }
                Err(e) => {
                    let _ = publish_event(
                        ctx.session,
                        &reply_topic,
                        &node_id,
                        &request_id,
                        "error",
                        &e.to_string(),
                    )
                    .await;
                }
            }
        }
        Some(node_control_command::Command::Install(install)) => {
            handle_install(ctx, &node_id, &request_id, &reply_topic, install).await;
        }
        Some(node_control_command::Command::Uninstall(uninstall)) => {
            handle_uninstall(ctx, &node_id, &request_id, &reply_topic, uninstall).await;
        }
        None => {
            let _ = publish_event(
                ctx.session,
                &reply_topic,
                &node_id,
                &request_id,
                "not_implemented",
                "unknown or unsupported control command",
            )
            .await;
        }
    }
}

async fn handle_install(
    ctx: &mut ControlCtx<'_>,
    node_id: &str,
    request_id: &str,
    reply_topic: &str,
    install: super::proto::NodeInstall,
) {
    let prior_instance = if install.ensure && !install.agent_id.is_empty() {
        ctx.packages
            .agents
            .values()
            .find(|p| p.agent_id == install.agent_id)
            .map(|p| p.instance_id.clone())
    } else {
        None
    };

    let result = if !install.package_url.is_empty() && install.local_path.is_empty() {
        let token = {
            let id = ctx.identity.read().await;
            id.node_token.clone()
        };
        let home = ctx.root.to_path_buf();
        let agent_id = install.agent_id.clone();
        let instance_id = install.instance_id.clone();
        let url = install.package_url.clone();
        let ensure = install.ensure;
        let packages = &mut *ctx.packages;
        tokio::task::block_in_place(|| {
            packages
                .install_from_url(
                    &home,
                    &agent_id,
                    &instance_id,
                    &url,
                    token.as_deref(),
                    ensure,
                )
                .map(|p| p.clone())
        })
    } else {
        ctx.packages
            .install_local(
                ctx.root,
                &install.agent_id,
                &install.instance_id,
                &install.local_path,
                install.ensure,
            )
            .map(|p| p.clone())
    };

    match result {
        Ok(pkg) => {
            if let Some(old) = prior_instance
                && old != pkg.instance_id
            {
                let old_topic = PackageInventory::installed_topic(node_id, &old);
                let _ = ctx.session.clear_retained(&old_topic).await;
            }
            let env = PackageInventory::installed_envelope(&pkg);
            let topic = PackageInventory::installed_topic(node_id, &pkg.instance_id);
            let _ = ctx.session.publish_envelope(&topic, &env, true).await;
            let _ = publish_event(
                ctx.session,
                reply_topic,
                node_id,
                request_id,
                "ok",
                &format!("installed {} @ {}", pkg.agent_id, pkg.instance_id),
            )
            .await;
        }
        Err(e) => {
            let _ = publish_event(
                ctx.session,
                reply_topic,
                node_id,
                request_id,
                "error",
                &e.to_string(),
            )
            .await;
        }
    }
}

async fn handle_uninstall(
    ctx: &mut ControlCtx<'_>,
    node_id: &str,
    request_id: &str,
    reply_topic: &str,
    uninstall: super::proto::NodeUninstall,
) {
    let instance_id = if uninstall.instance_id.is_empty() {
        uninstall.agent_id.clone()
    } else {
        uninstall.instance_id.clone()
    };
    match ctx
        .packages
        .uninstall(ctx.root, &instance_id, &uninstall.agent_id)
    {
        Ok(()) => {
            let topic = PackageInventory::installed_topic(node_id, &instance_id);
            let _ = ctx.session.clear_retained(&topic).await;
            let _ = publish_event(
                ctx.session,
                reply_topic,
                node_id,
                request_id,
                "ok",
                &format!("uninstalled {instance_id}"),
            )
            .await;
        }
        Err(e) => {
            let _ = publish_event(
                ctx.session,
                reply_topic,
                node_id,
                request_id,
                "error",
                &e.to_string(),
            )
            .await;
        }
    }
}

/// Spawn a Runtime via the configured engine (used by control + CLI REPL).
pub async fn start_agent(
    ctx: &mut ControlCtx<'_>,
    agent_id: &str,
    instance_id: Option<&str>,
    node_token: Option<String>,
) -> Result<(), String> {
    let program = ctx.engine.program_path().map_err(|e| e.to_string())?;
    if !program.exists() {
        return Err(format!(
            "engine binary missing: {} (ship libacowork_engine.so in jniLibs)",
            program.display()
        ));
    }
    let http_port = ctx.table.allocate_http_port();
    let instance_id = instance_id.map(str::to_string).unwrap_or_else(|| {
        format!(
            "{}-{}",
            agent_id,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or(Duration::from_secs(0))
                .as_secs()
        )
    });
    let work_dir = ctx.root.join("agents").join(&instance_id);
    std::fs::create_dir_all(&work_dir).map_err(|e| e.to_string())?;
    let package_path = ctx
        .packages
        .agents
        .get(&instance_id)
        .or_else(|| {
            ctx.packages
                .agents
                .values()
                .find(|p| p.agent_id == agent_id)
        })
        .map(|p| std::path::PathBuf::from(&p.install_path));
    if package_path.is_none() {
        eprintln!(
            "acowork-android control: no installed package for agent={agent_id} instance={instance_id}; runtime needs --package-path"
        );
    }
    let node_id = ctx.identity.read().await.node_id.clone();
    let launch = RuntimeLaunch {
        agent_id: agent_id.to_string(),
        instance_id: instance_id.clone(),
        http_port,
        gateway_host: ctx.gateway_host.to_string(),
        node_id,
        mqtt_port: Some(GATEWAY_MQTT_PORT),
        node_token,
        work_dir,
        package_path,
        // ADR-055 §6.3: Node LAN base so Runtime publishes
        // `{base}/agents/{id}` instead of unreachable 127.0.0.1.
        http_advertise_endpoint: Some(ctx.http_endpoint.to_string()),
    };
    let handle = ctx
        .table
        .start(ctx.engine, launch)
        .await
        .map_err(|e| e.to_string())?;
    eprintln!(
        "acowork-android control: started {} instance={} pid={:?} http://127.0.0.1:{}/health",
        handle.agent_id, handle.instance_id, handle.pid, handle.http_port
    );
    // Brief exit check — keep well under Gateway's ~10s control timeout.
    tokio::time::sleep(Duration::from_millis(300)).await;
    if ctx
        .table
        .list()
        .into_iter()
        .find(|(_, id, _, _, _)| id == &instance_id)
        .is_some_and(|(_, _, _, st, _)| st == RuntimeStatus::Exited)
    {
        return Err(format!(
            "runtime exited immediately — see {}/engine.stderr.log",
            ctx.root.join("agents").join(&instance_id).display()
        ));
    }
    sync_ports_from_table(ctx.ports, ctx.table).await;
    Ok(())
}

/// Republish retained NodeInfo after agent count changes.
pub async fn refresh_info(ctx: &mut ControlCtx<'_>) -> Result<(), String> {
    let agent_count = ctx.table.running_count() as u32;
    let id = ctx.identity.read().await.clone();
    ctx.session
        .publish_envelope(
            &node_info_topic(&id.node_id),
            &info_envelope(
                &id,
                ctx.tags.to_vec(),
                ctx.http_endpoint,
                agent_count,
                16,
            ),
            true,
        )
        .await
        .map_err(|e| e.to_string())
}

/// Sync proxy port table from running process rows.
pub async fn sync_ports_from_table(ports: &PortTable, table: &mut ProcessTable) {
    let rows: Vec<(String, u16)> = table
        .list()
        .into_iter()
        .filter(|(_, _, _, st, _)| *st == RuntimeStatus::Running)
        .map(|(_, id, port, _, _)| (id, port))
        .collect();
    sync_ports(ports, &rows).await;
}

/// Point process `HOME` at the node data home so empty-path `/fs/browse`
/// offers that directory as the HOME shortcut.
pub fn set_node_home(home: &Path) {
    // Rust 2024: env mutation is unsafe (process-global).
    unsafe {
        std::env::set_var("HOME", home);
    }
}
