//! `acowork-android serve` — Android Node role (ADR-AND-003 / C1 delivery).
//!
//! Probes the host, opens the reverse proxy, connects to the Gateway MQTT
//! broker, publishes enroll + NodeInfo + NodeReady, and runs a local process
//! table that can spawn the configured Runtime engine. Gateway control
//! commands `ping` / `start` / `stop` / `install` / `uninstall` are handled.

use std::collections::HashMap;
use std::io::{BufRead, IsTerminal, Write};
use std::net::SocketAddr;
use std::sync::Arc;

use acowork_android::host::{HostConfig, HostProfile, ProbeCommand, run_probe};
use acowork_android::node::{
    ControlCtx, EngineSpec, GatewayReachability, IncomingPublish, MqttSession, NodeIdentity,
    PackageInventory, PortTable, ProcessTable, ProxyState, SharedIdentity, announce,
    announce_with_enroll, capability_tags, check_gateway_http, decode_enroll_result,
    handle_control, mqtt_connect, proxy_start, refresh_info, set_node_home, shared_identity,
    start_agent, sync_ports, sync_ports_from_table,
};
use tokio::sync::{Mutex, Notify, mpsc};

use crate::session::CommonArgs;
use crate::transport::Transport;

pub struct ServeArgs {
    pub common: CommonArgs,
    pub gateway_http: String,
    pub enrollment_token: Option<String>,
    pub node_name: Option<String>,
    pub engine: EngineSpec,
    pub auto_agent: Option<String>,
    pub mqtt_port: u16,
    pub proxy_port: u16,
    pub advertise_host: String,
}

pub async fn run(args: ServeArgs) -> Result<(), String> {
    let transport = Transport::open(args.common.transport)?;
    println!("transport  {}", transport.describe());
    println!("engine     {:?}", describe_engine(&args.engine)?);

    let home = args.common.root.clone();
    std::fs::create_dir_all(&home).map_err(|e| e.to_string())?;
    set_node_home(&home);

    let gateway_host = host_of(&args.gateway_http);
    let gateway_mqtt = format!("{gateway_host}:{}", args.mqtt_port);
    let identity =
        NodeIdentity::load_or_create(&home, args.node_name.as_deref(), Some(&gateway_mqtt))
            .map_err(|e| e.to_string())?;
    println!(
        "identity   node_id={} name={} enrollment={:?}",
        identity.node_id, identity.node_name, identity.enrollment
    );

    acowork_android::host::set_dangerous_mode(args.common.dangerous_mode);
    let loaded = HostConfig::load(&args.common.root).map_err(|e| e.to_string())?;
    let probe = run_probe(
        transport.as_probe(),
        &ProbeCommand::read_only_set(),
        &args.common.package,
    )
    .await;
    let profile = HostProfile::assemble(&probe, &args.common.package);
    let _prepared = loaded
        .config
        .prepare(&args.common.root)
        .map_err(|e| e.to_string())?;

    let tags = capability_tags(&profile);
    println!(
        "profile    {} · privilege {:?}",
        profile.name.as_str(),
        profile.privilege
    );
    println!("caps       {}", tags.join(", "));

    match check_gateway_http(&args.gateway_http).map_err(|e| e.to_string())? {
        GatewayReachability::Reachable { addr } => {
            println!("gateway    HTTP reachable at {addr}");
        }
        GatewayReachability::Unreachable { reason } => {
            println!(
                "gateway    HTTP UNREACHABLE ({}) — {reason}",
                args.gateway_http
            );
        }
    }

    let identity_cell: SharedIdentity = shared_identity(identity.clone());
    let ports: PortTable = Arc::new(Mutex::new(HashMap::new()));
    let proxy_bind = SocketAddr::from(([0, 0, 0, 0], args.proxy_port));
    let republish = Arc::new(Notify::new());
    let proxy = proxy_start(
        proxy_bind,
        ProxyState {
            identity: Arc::clone(&identity_cell),
            ports: Arc::clone(&ports),
            home: home.clone(),
            republish: Arc::clone(&republish),
        },
    )
    .await
    .map_err(|e| e.to_string())?;
    let http_endpoint = format!("http://{}:{}", args.advertise_host, args.proxy_port);
    println!("proxy      listening on {proxy_bind} (advertise {http_endpoint})");

    // Same rule as the Android host — see [`NodeIdentity::plan_join`]: the
    // CONNECT credential and the `/enroll` payload are separate decisions, and
    // conflating them either flaps the connection or leaves the node ownerless.
    let plan = identity.plan_join(args.enrollment_token.as_deref());
    let fresh_enrollment = plan.presented_fresh;
    let connect_token = plan.connect_token;
    let enroll_token = plan.enroll_token;
    let enroll_now = plan.enroll;

    let mut session = mqtt_connect(
        &gateway_host,
        args.mqtt_port,
        &identity.node_id,
        if connect_token.is_empty() {
            None
        } else {
            Some(connect_token.clone())
        },
    )
    .await
    .map_err(|e| e.to_string())?;
    println!("mqtt       connected to {gateway_host}:{}", args.mqtt_port);

    let mut packages = PackageInventory::load(&home).map_err(|e| e.to_string())?;
    println!("packages   {} installed", packages.agents.len());

    announce_with_enroll(
        &session,
        &identity,
        tags.clone(),
        &http_endpoint,
        0,
        &enroll_token,
        enroll_now,
    )
    .await
    .map_err(|e| e.to_string())?;
    republish_inventory(&session, &identity.node_id, &packages).await?;
    println!("enroll     request published; waiting for enroll_result…");

    let mut table = ProcessTable::new(19901);
    // Live credential string used on reconnect re-announce (starts as
    // enrollment token; swapped to node_token after enroll_result).
    let mut live_token = connect_token;
    if let Some(agent_id) = &args.auto_agent {
        let token = identity_cell.read().await.node_token.clone();
        let mut ctx = ControlCtx {
            session: &mut session,
            identity: &identity_cell,
            table: &mut table,
            ports: &ports,
            packages: &mut packages,
            engine: &args.engine,
            gateway_host: &gateway_host,
            root: &args.common.root,
            tags: &tags,
            http_endpoint: &http_endpoint,
            package: &args.common.package,
            dangerous_mode: args.common.dangerous_mode,
        };
        start_agent(&mut ctx, agent_id, None, token).await?;
        refresh_info(&mut ctx).await?;
    }

    println!();
    println!("node ready. commands: start <agent-id> | stop <instance-id> | list | tags | quit");

    let interactive = std::io::stdin().is_terminal();
    let mut line_rx = if interactive {
        let (tx, rx) = mpsc::unbounded_channel();
        std::thread::spawn(move || {
            let stdin = std::io::stdin();
            for line in stdin.lock().lines() {
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        Some(rx)
    } else {
        println!("(stdin is not a terminal — serving until Ctrl-C)");
        None
    };

    loop {
        if interactive {
            print!("acowork-android> ");
            let _ = std::io::stdout().flush();
        }

        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                println!("shutting down…");
                break;
            }
            _ = session.bootstrap.recv() => {
                // Soft-restart ConnAck: re-subscribe already done in mqtt
                // task; re-announce retained snapshots + inventory.
                println!("mqtt       ConnAck — re-announcing");
                if let Some(tok) = identity_cell.read().await.node_token.clone() {
                    live_token = tok;
                }
                let id = identity_cell.read().await.clone();
                let agent_count = table.running_count() as u32;
                let _ = announce(
                    &session,
                    &id,
                    tags.clone(),
                    &http_endpoint,
                    agent_count,
                    &live_token,
                )
                .await;
                let _ = republish_inventory(&session, &id.node_id, &packages).await;
            }
            _ = republish.notified() => {
                // The proxy persisted a rename — republish the retained
                // `info` so the Gateway registry converges now, without
                // re-enrolling (ownership was settled at enroll time).
                let id = identity_cell.read().await.clone();
                let agent_count = table.running_count() as u32;
                let _ = announce_with_enroll(
                    &session,
                    &id,
                    tags.clone(),
                    &http_endpoint,
                    agent_count,
                    &live_token,
                    false,
                )
                .await;
                println!("rename     re-announced as {}", id.node_name);
            }
            msg = session.incoming.recv() => {
                match msg {
                    Some(pubmsg) => {
                        let mut ctx = ControlCtx {
                            session: &mut session,
                            identity: &identity_cell,
                            table: &mut table,
                            ports: &ports,
                            packages: &mut packages,
                            engine: &args.engine,
                            gateway_host: &gateway_host,
                            root: &args.common.root,
                            tags: &tags,
                            http_endpoint: &http_endpoint,
                            package: &args.common.package,
                            dangerous_mode: args.common.dangerous_mode,
                        };
                        handle_incoming(&pubmsg, &mut ctx, &home, &mut live_token,
                            fresh_enrollment.clone()).await;
                    }
                    None => {
                        println!("mqtt session closed");
                        break;
                    }
                }
            }
            line = recv_line(&mut line_rx), if line_rx.is_some() => {
                let Ok(Some(line)) = line else { break; };
                let line = line.trim().to_string();
                if line.is_empty() {
                    continue;
                }
                let mut ctx = ControlCtx {
                    session: &mut session,
                    identity: &identity_cell,
                    table: &mut table,
                    ports: &ports,
                    packages: &mut packages,
                    engine: &args.engine,
                    gateway_host: &gateway_host,
                    root: &args.common.root,
                    tags: &tags,
                    http_endpoint: &http_endpoint,
                    package: &args.common.package,
                    dangerous_mode: args.common.dangerous_mode,
                };
                if !handle_repl(&line, &mut ctx).await? {
                    break;
                }
            }
        }
    }

    let _ = stop_all(&mut table, &ports).await;
    session.goodbye().await;
    session.stop();
    proxy.stop();
    Ok(())
}

async fn recv_line(
    rx: &mut Option<mpsc::UnboundedReceiver<std::io::Result<String>>>,
) -> Result<Option<String>, String> {
    match rx.as_mut() {
        Some(rx) => match rx.recv().await {
            Some(Ok(l)) => Ok(Some(l)),
            Some(Err(e)) => Err(e.to_string()),
            None => Ok(None),
        },
        None => {
            std::future::pending::<()>().await;
            unreachable!()
        }
    }
}

async fn handle_incoming(
    msg: &IncomingPublish,
    ctx: &mut ControlCtx<'_>,
    home: &std::path::Path,
    live_token: &mut String,
    presented: Option<String>,
) {
    if msg.topic.ends_with("/enroll_result") {
        if let Some(result) = decode_enroll_result(&msg.payload) {
            if result.status == "ok" && !result.node_token.is_empty() {
                let mut id = ctx.identity.write().await;
                let gateway_addr = id.gateway_addr.clone().unwrap_or_default();
                id.mark_enrolled(
                    &gateway_addr,
                    Some(result.node_token.clone()),
                    presented.clone(),
                );
                if let Err(e) = id.save(home) {
                    eprintln!("persist identity: {e}");
                }
                *ctx.session.credentials.lock().await = Some(result.node_token.clone());
                *live_token = result.node_token.clone();
                println!("enroll     OK — node_token persisted ({})", result.message);
            } else {
                println!(
                    "enroll     REJECTED status={} message={}",
                    result.status, result.message
                );
            }
        }
        return;
    }

    handle_control(msg, ctx).await;
}

async fn republish_inventory(
    session: &MqttSession,
    node_id: &str,
    packages: &PackageInventory,
) -> Result<(), String> {
    for pkg in packages.agents.values() {
        let env = PackageInventory::installed_envelope(pkg);
        let topic = PackageInventory::installed_topic(node_id, &pkg.instance_id);
        session
            .publish_envelope(&topic, &env, true)
            .await
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

async fn handle_repl(line: &str, ctx: &mut ControlCtx<'_>) -> Result<bool, String> {
    let mut parts = line.split_whitespace();
    let cmd = parts.next().unwrap_or("");
    match cmd {
        "quit" | "exit" => return Ok(false),
        "list" => {
            for (agent, inst, port, status, pid) in ctx.table.list() {
                println!("  {agent}  instance={inst}  http=:{port}  {status:?}  pid={pid:?}");
            }
            if ctx.table.list().is_empty() {
                println!("  (no runtimes)");
            }
        }
        "tags" => {
            for t in ctx.tags {
                println!("  {t}");
            }
        }
        "start" => {
            let Some(agent_id) = parts.next() else {
                println!("usage: start <agent-id>");
                return Ok(true);
            };
            let token = ctx.identity.read().await.node_token.clone();
            match start_agent(ctx, agent_id, None, token).await {
                Ok(()) => {
                    let _ = refresh_info(ctx).await;
                }
                Err(e) => println!("error: {e}"),
            }
        }
        "stop" => {
            let Some(instance_id) = parts.next() else {
                println!("usage: stop <instance-id>");
                return Ok(true);
            };
            match ctx.table.stop(instance_id).await {
                Ok(()) => {
                    sync_ports_from_table(ctx.ports, ctx.table).await;
                    println!("stopped {instance_id}");
                    let _ = refresh_info(ctx).await;
                }
                Err(e) => println!("error: {e}"),
            }
        }
        "help" => {
            println!("start <agent-id> | stop <instance-id> | list | tags | quit");
        }
        other => println!("unknown command `{other}` (try help)"),
    }
    Ok(true)
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

fn host_of(gateway_http: &str) -> String {
    let trimmed = gateway_http
        .trim()
        .trim_start_matches("http://")
        .trim_start_matches("https://");
    trimmed
        .split('/')
        .next()
        .unwrap_or("127.0.0.1")
        .split(':')
        .next()
        .unwrap_or("127.0.0.1")
        .to_string()
}

fn describe_engine(spec: &EngineSpec) -> Result<String, String> {
    let program = spec
        .program_path()
        .map_err(|e| e.to_string())?
        .display()
        .to_string();
    let prefix: Vec<String> = spec
        .prefix_args
        .iter()
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    Ok(format!("{program} {:?}", prefix))
}
