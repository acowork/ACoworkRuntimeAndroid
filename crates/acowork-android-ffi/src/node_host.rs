//! In-process Node host loop for the APK (C1 / C2).
//!
//! Probe → proxy `:19900` → MQTT enroll/announce → handle
//! `ping` / `start` / `stop` / `install` / `uninstall`.
//!
//! Runtime children are spawned via [`EngineSpec`] pointing at the APK-packaged
//! `libacowork_engine.so` (CLI binary renamed for jniLibs), re-entered as `runtime`.

use std::collections::HashMap;
use std::ffi::OsString;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use once_cell::sync::OnceCell;
use serde_json::json;
use tokio::sync::watch;

use acowork_android::host::{HostConfig, HostProfile, LocalHost, ProbeCommand, run_probe};
use acowork_android::node::{
    ControlCtx, EngineSpec, GATEWAY_MQTT_PORT, GatewayReachability, IncomingPublish,
    NODE_PROXY_PORT, NodeIdentity, PackageInventory, PortTable, ProcessTable, ProxyState,
    SharedIdentity, announce, capability_tags, check_gateway_http, decode_enroll_result,
    handle_control, mqtt_connect, proxy_start, set_node_home, shared_identity, sync_ports,
};

#[derive(Clone)]
pub struct StartArgs {
    pub home: PathBuf,
    pub gateway_http: String,
    pub enrollment_token: Option<String>,
    pub node_name: Option<String>,
    /// Host part of NodeInfo.http_endpoint (what Gateway dials back).
    pub advertise_host: String,
    /// Port Gateway should dial. Defaults to [`NODE_PROXY_PORT`].
    /// Use a distinct host port with `adb forward tcp:PORT tcp:19900` so
    /// desktop Node keeps owning local `:19900`.
    pub advertise_port: u16,
    pub package_name: String,
    /// Absolute path to the packaged CLI engine (`libacowork_engine.so`).
    pub engine_path: Option<PathBuf>,
}

struct Lifecycle {
    /// True while a serve task exists. Cleared only by that task on exit,
    /// so `start` cannot spawn a second MQTT client with the same node id.
    running: bool,
    stop_tx: Option<watch::Sender<bool>>,
}

struct HostState {
    lifecycle: Mutex<Lifecycle>,
    status: Mutex<String>,
}

static STATE: OnceCell<HostState> = OnceCell::new();

fn state() -> &'static HostState {
    STATE.get_or_init(|| HostState {
        lifecycle: Mutex::new(Lifecycle {
            running: false,
            stop_tx: None,
        }),
        status: Mutex::new(json!({ "ok": true, "running": false }).to_string()),
    })
}

fn set_status(value: serde_json::Value) {
    if let Ok(mut g) = state().status.lock() {
        *g = value.to_string();
    }
}

pub fn status_json() -> String {
    state()
        .status
        .lock()
        .map(|g| g.clone())
        .unwrap_or_else(|_| err_json("status lock poisoned"))
}

pub fn stop() -> Result<String, String> {
    signal_stop();
    set_status(json!({ "ok": true, "running": false, "stopped": true }));
    Ok(json!({ "ok": true, "running": false }).to_string())
}

fn signal_stop() {
    if let Ok(guard) = state().lifecycle.lock()
        && let Some(tx) = guard.stop_tx.as_ref()
    {
        let _ = tx.send(true);
    }
}

fn mark_stopped() {
    if let Ok(mut guard) = state().lifecycle.lock() {
        guard.running = false;
    }
}

pub fn start(rt: &tokio::runtime::Runtime, args: StartArgs) -> Result<String, String> {
    // A live loop owns the MQTT client id. Stop it and wait until that
    // task has dropped the session before opening another one. Clearing
    // the flag in `stop()` and spawning immediately left two poll tasks
    // kicking each other (broker: Duplicate client_id every 2s).
    if state()
        .lifecycle
        .lock()
        .map(|g| g.running)
        .unwrap_or(false)
    {
        signal_stop();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        while std::time::Instant::now() < deadline {
            let still = state()
                .lifecycle
                .lock()
                .map(|g| g.running)
                .unwrap_or(false);
            if !still {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    }

    let stop_rx = {
        let mut guard = state().lifecycle.lock().map_err(|e| e.to_string())?;
        if guard.running {
            return Ok(json!({ "ok": true, "running": true, "already": true }).to_string());
        }
        let (stop_tx, stop_rx) = watch::channel(false);
        guard.running = true;
        guard.stop_tx = Some(stop_tx);
        stop_rx
    };

    let status_args = args.clone();
    rt.spawn(async move {
        match run_loop(args, stop_rx).await {
            Ok(()) => set_status(json!({ "ok": true, "running": false, "stopped": true })),
            Err(e) => {
                tracing::error!("node host exited: {e}");
                set_status(json!({ "ok": false, "running": false, "error": e }));
            }
        }
        mark_stopped();
    });

    set_status(json!({
        "ok": true,
        "running": true,
        "gateway_http": status_args.gateway_http,
        "home": status_args.home.display().to_string(),
        "engine": status_args
            .engine_path
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "(missing)".into()),
    }));
    Ok(json!({ "ok": true, "running": true }).to_string())
}

fn resolve_engine(path: Option<&PathBuf>) -> Result<EngineSpec, String> {
    let Some(p) = path else {
        return Err("engine_path not set — APK must ship libacowork_engine.so".into());
    };
    if !p.exists() {
        return Err(format!("engine binary missing: {}", p.display()));
    }
    Ok(EngineSpec {
        program: Some(p.clone()),
        prefix_args: vec![OsString::from("runtime")],
    })
}

async fn run_loop(args: StartArgs, mut stop_rx: watch::Receiver<bool>) -> Result<(), String> {
    std::fs::create_dir_all(&args.home).map_err(|e| e.to_string())?;
    // PC Node browses via $HOME; set it to the node data home so /fs/browse
    // root_entries match without Android-only plaster roots.
    set_node_home(&args.home);
    // Previous host sessions can leave Runtime children with PPID=1. They keep
    // MQTT CONNECT alive (Desktop shows the agent "running") while advertising
    // a loopback http port the Gateway cannot reach → workspace 502.
    reap_orphan_engines(&args.home);
    let gateway_host = host_of(&args.gateway_http);
    let gateway_mqtt = format!("{gateway_host}:{GATEWAY_MQTT_PORT}");

    let identity = NodeIdentity::load_or_create(
        &args.home,
        args.node_name.as_deref(),
        Some(&gateway_mqtt),
    )
    .map_err(|e| e.to_string())?;

    let host = LocalHost::new().map_err(|e| e.to_string())?;
    let probe = run_probe(&host, &ProbeCommand::read_only_set(), &args.package_name).await;
    let profile = HostProfile::assemble(&probe, &args.package_name);
    let _ = HostConfig::load(&args.home).map_err(|e| e.to_string())?;
    let tags = capability_tags(&profile);
    // Engine may be absent until libacowork_engine.so is packaged; enroll/ping still work.
    let engine = resolve_engine(args.engine_path.as_ref()).unwrap_or_else(|e| {
        tracing::warn!("{e}");
        EngineSpec {
            program: args.engine_path.clone(),
            prefix_args: vec![OsString::from("runtime")],
        }
    });

    match check_gateway_http(&args.gateway_http).map_err(|e| e.to_string())? {
        GatewayReachability::Reachable { addr } => {
            tracing::info!("gateway HTTP reachable at {addr}");
        }
        GatewayReachability::Unreachable { reason } => {
            tracing::warn!("gateway HTTP unreachable: {reason}");
        }
    }

    let identity_cell: SharedIdentity = shared_identity(identity.clone());
    let ports: PortTable = Arc::new(tokio::sync::Mutex::new(HashMap::new()));
    let proxy_bind = SocketAddr::from(([0, 0, 0, 0], NODE_PROXY_PORT));
    let proxy = proxy_start(
        proxy_bind,
        ProxyState {
            identity: Arc::clone(&identity_cell),
            ports: Arc::clone(&ports),
        },
    )
    .await
    .map_err(|e| e.to_string())?;

    let advertise_port = if args.advertise_port == 0 {
        NODE_PROXY_PORT
    } else {
        args.advertise_port
    };
    let http_endpoint = format!("http://{}:{advertise_port}", args.advertise_host);
    // Prefer persisted node_token. Passing a one-shot enrollment token after
    // enroll already succeeded makes CONNECT NotAuthorized → soft-restart
    // → LWT offline/online flap (Desktop sees the node drop every second).
    let enroll_token = identity
        .node_token
        .clone()
        .or_else(|| args.enrollment_token.clone())
        .unwrap_or_default();

    let mut session = match mqtt_connect(
        &gateway_host,
        GATEWAY_MQTT_PORT,
        &identity.node_id,
        if enroll_token.is_empty() {
            None
        } else {
            Some(enroll_token.clone())
        },
    )
    .await
    {
        Ok(session) => session,
        Err(e) => {
            proxy.stop();
            return Err(e.to_string());
        }
    };

    // Always `session.stop()` — an early `?` used to leave the poll task
    // running, and the next `start` opened a second `node:{id}` client.
    let outcome: Result<(), String> = async {
    let mut packages = PackageInventory::load(&args.home).map_err(|e| e.to_string())?;
    announce(
        &session,
        &identity,
        tags.clone(),
        &http_endpoint,
        0,
        &enroll_token,
    )
    .await
    .map_err(|e| e.to_string())?;

    publish_inventory(&session, &identity.node_id, &packages).await;

    set_status(json!({
        "ok": true,
        "running": true,
        "node_id": identity.node_id,
        "node_name": identity.node_name,
        "profile": profile.name.as_str(),
        "caps": tags,
        "http_endpoint": http_endpoint,
        "packages": packages.agents.len(),
        "engine": engine
            .program
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_default(),
    }));

    let mut table = ProcessTable::new(19901);
    let mut live_token = enroll_token;
    loop {
        tokio::select! {
            _ = stop_rx.changed() => {
                if *stop_rx.borrow() {
                    break;
                }
            }
            _ = session.bootstrap.recv() => {
                if let Some(tok) = identity_cell.read().await.node_token.clone() {
                    live_token = tok;
                }
                let id = identity_cell.read().await.clone();
                let _ = announce(
                    &session,
                    &id,
                    tags.clone(),
                    &http_endpoint,
                    table.running_count() as u32,
                    &live_token,
                ).await;
                // Gateway inventory is rebuilt from retained InstalledAgentInfo.
                // After MQTT flap / Gateway restart the broker may still hold
                // retained messages, but an in-memory Gateway that missed them
                // stays empty until we republish — which is why Desktop showed
                // an empty agent list for already-installed packages.
                publish_inventory(&session, &id.node_id, &packages).await;
            }
            msg = session.incoming.recv() => {
                match msg {
                    Some(pubmsg) => {
                        if pubmsg.topic.ends_with("/enroll_result") {
                            handle_enroll_result(
                                &pubmsg,
                                &mut session,
                                &identity_cell,
                                &args.home,
                                &mut live_token,
                                &tags,
                                &http_endpoint,
                                table.running_count() as u32,
                            ).await;
                            continue;
                        }
                        let mut ctx = ControlCtx {
                            session: &mut session,
                            identity: &identity_cell,
                            table: &mut table,
                            ports: &ports,
                            packages: &mut packages,
                            engine: &engine,
                            gateway_host: &gateway_host,
                            root: &args.home,
                            tags: &tags,
                            http_endpoint: &http_endpoint,
                        };
                        handle_control(&pubmsg, &mut ctx).await;
                        let snap = identity_cell.read().await;
                        set_status(json!({
                            "ok": true,
                            "running": true,
                            "node_id": snap.node_id,
                            "node_name": snap.node_name,
                            "http_endpoint": http_endpoint,
                            "agent_count": table.running_count(),
                            "packages": packages.agents.len(),
                        }));
                    }
                    None => break,
                }
            }
        }
    }

    let _ = stop_all(&mut table, &ports).await;
    session.goodbye().await;
    Ok(())
    }
    .await;
    session.stop();
    proxy.stop();
    outcome
}

async fn handle_enroll_result(
    msg: &IncomingPublish,
    session: &mut acowork_android::node::MqttSession,
    identity: &SharedIdentity,
    home: &std::path::Path,
    live_token: &mut String,
    _tags: &[String],
    http_endpoint: &str,
    agent_count: u32,
) {
    // Mirror desktop Node (ADR-055 §6.12): persist the Gateway-issued
    // token and stop. Do NOT call `announce()` here — that republishes
    // `/enroll`, the Gateway replies again, and we storm the broker
    // (thousands of enroll_result / online updates per minute), which
    // also makes Desktop's node list flap or look empty.
    if let Some(result) = decode_enroll_result(&msg.payload)
        && result.status == "ok"
        && !result.node_token.is_empty()
    {
        let mut id = identity.write().await;
        if id.node_token.as_deref() == Some(result.node_token.as_str()) {
            return; // Same token — nothing to do.
        }
        let gateway_addr = id.gateway_addr.clone().unwrap_or_default();
        id.mark_enrolled(&gateway_addr, Some(result.node_token.clone()));
        let _ = id.save(home);
        *session.credentials.lock().await = Some(result.node_token.clone());
        *live_token = result.node_token.clone();
        let snapshot = id.clone();
        drop(id);
        set_status(json!({
            "ok": true,
            "running": true,
            "enrolled": true,
            "node_id": snapshot.node_id,
            "node_name": snapshot.node_name,
            "http_endpoint": http_endpoint,
            "agent_count": agent_count,
        }));
    }
}

async fn publish_inventory(
    session: &acowork_android::node::MqttSession,
    node_id: &str,
    packages: &PackageInventory,
) {
    for pkg in packages.agents.values() {
        let env = PackageInventory::installed_envelope(pkg);
        let topic = PackageInventory::installed_topic(node_id, &pkg.instance_id);
        let _ = session.publish_envelope(&topic, &env, true).await;
    }
}

/// Kill leftover `libacowork_engine.so runtime …` processes under `home`.
///
/// Only targets orphans (PPID 1) so a live host's own children are left alone
/// when this is called at the start of a fresh serve loop.
fn reap_orphan_engines(home: &Path) {
    let home_s = home.to_string_lossy();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return;
    };
    for ent in entries.flatten() {
        let name = ent.file_name();
        let Some(pid_str) = name.to_str() else {
            continue;
        };
        let Ok(pid) = pid_str.parse::<i32>() else {
            continue;
        };
        let status = std::fs::read_to_string(ent.path().join("status")).unwrap_or_default();
        let ppid = status
            .lines()
            .find_map(|l| l.strip_prefix("PPid:\t").or_else(|| l.strip_prefix("PPid: ")))
            .and_then(|s| s.trim().parse::<i32>().ok())
            .unwrap_or(-1);
        if ppid != 1 {
            continue;
        }
        let cmdline = std::fs::read(ent.path().join("cmdline")).unwrap_or_default();
        let cmd = String::from_utf8_lossy(&cmdline).replace('\0', " ");
        if !(cmd.contains("libacowork_engine") || cmd.contains("acowork-android")) {
            continue;
        }
        if !cmd.contains("runtime") {
            continue;
        }
        if !cmd.contains(home_s.as_ref()) {
            continue;
        }
        tracing::warn!("reaping orphan runtime pid={pid}: {cmd}");
        let _ = std::process::Command::new("kill")
            .args(["-9", &pid.to_string()])
            .status();
    }
}

async fn stop_all(table: &mut ProcessTable, ports: &PortTable) -> Result<(), String> {
    let ids: Vec<String> = table
        .list()
        .into_iter()
        .map(|(_, id, _, _, _)| id)
        .collect();
    for id in ids {
        let _ = table.stop(&id).await;
    }
    sync_ports(ports, &[]).await;
    Ok(())
}

fn host_of(url: &str) -> String {
    let rest = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
        .unwrap_or(url);
    rest.split('/')
        .next()
        .unwrap_or(rest)
        .split(':')
        .next()
        .unwrap_or(rest)
        .to_string()
}

fn err_json(msg: impl AsRef<str>) -> String {
    json!({ "ok": false, "error": msg.as_ref() }).to_string()
}
