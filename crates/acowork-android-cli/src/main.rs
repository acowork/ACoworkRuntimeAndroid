//! `acowork-android` — Android Node + Runtime CLI (ADR-AND-003).
//!
//! One binary, two roles: `serve` is the Node, `runtime` is a spawned agent instance.
//! Root-shell remains a probed host mode, not a third product. Independent of upstream
//! `acowork-node` / `acowork-runtime` binaries — only the Gateway protocol is shared.

mod cmd;
mod session;
mod transport;

use std::path::PathBuf;
use std::process::ExitCode;

use acowork_android::node::{EngineSpec, GATEWAY_MQTT_PORT, NODE_PROXY_PORT};

use session::CommonArgs;
use transport::TransportKind;

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(err) => {
            eprintln!("acowork-android: {err}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<ExitCode, String> {
    let mut args = std::env::args().skip(1).peekable();
    let Some(first) = args.next() else {
        print_usage();
        return Ok(ExitCode::FAILURE);
    };

    match first.as_str() {
        "help" | "--help" | "-h" => {
            print_usage();
            Ok(ExitCode::SUCCESS)
        }
        "version" | "--version" | "-V" => {
            cmd::version::run();
            Ok(ExitCode::SUCCESS)
        }
        "probe" => {
            let (common, json) = parse_probe(&mut args)?;
            tokio_run(cmd::probe::run(&common, json))
        }
        "exec" => {
            let exec = parse_exec(&mut args)?;
            tokio_run(cmd::exec::run(exec))
        }
        "settings" => {
            let (common, sub) = parse_settings(&mut args)?;
            cmd::settings::run(&common, sub)?;
            Ok(ExitCode::SUCCESS)
        }
        "evidence" => {
            let evidence = parse_evidence(&mut args)?;
            tokio_run(cmd::evidence::run(evidence))
        }
        "restore" => {
            let common = parse_common_only(&mut args)?;
            tokio_run(cmd::restore::run(&common))
        }
        "serve" => {
            let serve = parse_serve(&mut args)?;
            tokio_run(cmd::serve::run(serve))
        }
        "runtime" => {
            let runtime = parse_runtime(&mut args)?;
            cmd::runtime::run(runtime)?;
            Ok(ExitCode::SUCCESS)
        }
        other => Err(format!("unknown command `{other}`\n\n{}", USAGE.trim_end())),
    }
}

fn tokio_run(
    fut: impl std::future::Future<Output = Result<(), String>>,
) -> Result<ExitCode, String> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    rt.block_on(fut)?;
    Ok(ExitCode::SUCCESS)
}

const USAGE: &str = "\
acowork-android — Android host CLI (Termux / on-device / adb)

Usage:
  acowork-android <command> [options]

Commands:
  probe                 Measure the host; print profile + capability summary
  exec -- <script>      Run one script through the host chain (restores writes)
  settings init|show|catalog
                        Manage the HostConfig document under --root
  evidence <source>     Capture screenshot|bugreport|logcat[:buf]|dumpsys:SVC|file:/PATH
  restore               Undo pending writes on this process's ledger
  serve --gateway-http URL
                        Node role: MQTT enroll, reverse proxy, process table, control ping/start/stop
  runtime               Runtime role: one agent instance (usually spawned by serve)
  version               Print version
  help                  Show this help

Common options:
  --root DIR            Workspace for settings/snapshots/audit (default: ./host)
  --package PKG         Own package name for fs_roots (default: com.acowork.host)
  --session ID          Session id for ledger/audit (default: acowork-android)
  --transport local|adb|auto
                        How to reach the device (default: auto = local on Android, adb elsewhere)
  --dangerous-mode      Session switch for system-tier writes (never persisted)
  --yes                 Approve a write / bugreport without a terminal prompt

serve options:
  --gateway-http URL    Gateway HTTP base (required)
  --enrollment-token T  One-time enroll token (or reuse persisted node_token)
  --name SLUG           Display node_name on first identity create
  --engine PATH|integrated
                        Runtime program (default: integrated = this binary + `runtime`)
  --agent ID            Auto-start one agent instance on boot
  --mqtt-port N         Gateway MQTT port (default: 19875)
  --proxy-port N        Local reverse-proxy port (default: 19900)
  --advertise-host HOST Host embedded in NodeInfo.http_endpoint (default: 127.0.0.1)

Examples:
  ACOWORK_ADB=adb ACOWORK_ADB_SERIAL=SERIAL \\
    acowork-android probe
  acowork-android exec -- \"getprop ro.build.version.release\"
  acowork-android serve --gateway-http http://192.168.1.10:19876 --advertise-host 192.168.1.20
  acowork-android settings init
";

fn print_usage() {
    print!("{USAGE}");
}

fn parse_probe(
    args: &mut std::iter::Peekable<impl Iterator<Item = String>>,
) -> Result<(CommonArgs, bool), String> {
    let mut common = CommonArgs::defaults();
    let mut json = false;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--json" => json = true,
            "--help" | "-h" => {
                return Err("usage: acowork-android probe [--json] [common options]".to_string());
            }
            other => take_common(&mut common, other, args)?,
        }
    }
    Ok((common, json))
}

fn parse_exec(
    args: &mut std::iter::Peekable<impl Iterator<Item = String>>,
) -> Result<cmd::exec::ExecArgs, String> {
    let mut common = CommonArgs::defaults();
    let mut assume_yes = false;
    let mut script = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--" => {
                script = Some(rest_join(args));
                break;
            }
            "--yes" => assume_yes = true,
            "--help" | "-h" => {
                return Err(
                    "usage: acowork-android exec [common options] [--yes] -- <script>".to_string(),
                );
            }
            other if !other.starts_with('-') => {
                // Allow `exec "script"` without `--` for one-shot convenience.
                if script.is_some() {
                    return Err(format!("unexpected extra argument `{other}`"));
                }
                script = Some(other.to_string());
            }
            other => take_common(&mut common, other, args)?,
        }
    }
    Ok(cmd::exec::ExecArgs {
        common,
        script: script.ok_or_else(|| {
            "a script is required (e.g. acowork-android exec -- \"getprop ro.build.version.release\")"
                .to_string()
        })?,
        assume_yes,
    })
}

fn parse_settings(
    args: &mut std::iter::Peekable<impl Iterator<Item = String>>,
) -> Result<(CommonArgs, cmd::settings::SettingsCmd), String> {
    let sub = args
        .next()
        .ok_or_else(|| "usage: acowork-android settings <init|show|catalog>".to_string())?;
    let cmd = match sub.as_str() {
        "init" => cmd::settings::SettingsCmd::Init,
        "show" => cmd::settings::SettingsCmd::Show,
        "catalog" => cmd::settings::SettingsCmd::Catalog,
        "--help" | "-h" => {
            return Err("usage: acowork-android settings <init|show|catalog>".to_string());
        }
        other => {
            return Err(format!(
                "unknown settings subcommand `{other}` (expected init|show|catalog)"
            ));
        }
    };
    let mut common = CommonArgs::defaults();
    while let Some(arg) = args.next() {
        take_common(&mut common, &arg, args)?;
    }
    Ok((common, cmd))
}

fn parse_evidence(
    args: &mut std::iter::Peekable<impl Iterator<Item = String>>,
) -> Result<cmd::evidence::EvidenceArgs, String> {
    let mut common = CommonArgs::defaults();
    let mut assume_yes = false;
    let mut source = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--yes" => assume_yes = true,
            "--help" | "-h" => {
                return Err(
                    "usage: acowork-android evidence <source> [common options] [--yes]".to_string(),
                );
            }
            other if !other.starts_with('-') => {
                if source.is_some() {
                    return Err(format!("unexpected extra argument `{other}`"));
                }
                source = Some(cmd::evidence::parse_source(other)?);
            }
            other => take_common(&mut common, other, args)?,
        }
    }
    Ok(cmd::evidence::EvidenceArgs {
        common,
        source: source.ok_or_else(|| {
            "an evidence source is required \
             (screenshot|bugreport|logcat[:buffer]|dumpsys:SERVICE|file:/ABS/PATH)"
                .to_string()
        })?,
        assume_yes,
    })
}

fn parse_common_only(
    args: &mut std::iter::Peekable<impl Iterator<Item = String>>,
) -> Result<CommonArgs, String> {
    let mut common = CommonArgs::defaults();
    while let Some(arg) = args.next() {
        take_common(&mut common, &arg, args)?;
    }
    Ok(common)
}

fn parse_serve(
    args: &mut std::iter::Peekable<impl Iterator<Item = String>>,
) -> Result<cmd::serve::ServeArgs, String> {
    let mut common = CommonArgs::defaults();
    let mut gateway_http = None;
    let mut enrollment_token = None;
    let mut node_name = None;
    let mut engine = EngineSpec::integrated();
    let mut auto_agent = None;
    let mut mqtt_port = GATEWAY_MQTT_PORT;
    let mut proxy_port = NODE_PROXY_PORT;
    let mut advertise_host = "127.0.0.1".to_string();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--gateway-http" => gateway_http = Some(value(args, "--gateway-http")?),
            "--enrollment-token" => enrollment_token = Some(value(args, "--enrollment-token")?),
            "--name" => node_name = Some(value(args, "--name")?),
            "--engine" => {
                engine = EngineSpec::parse(&value(args, "--engine")?).map_err(|e| e.to_string())?;
            }
            "--agent" => auto_agent = Some(value(args, "--agent")?),
            "--mqtt-port" => {
                mqtt_port = value(args, "--mqtt-port")?
                    .parse()
                    .map_err(|e| format!("--mqtt-port: {e}"))?;
            }
            "--proxy-port" => {
                proxy_port = value(args, "--proxy-port")?
                    .parse()
                    .map_err(|e| format!("--proxy-port: {e}"))?;
            }
            "--advertise-host" => advertise_host = value(args, "--advertise-host")?,
            "--help" | "-h" => {
                return Err(
                    "usage: acowork-android serve --gateway-http URL [--engine integrated|PATH] \
                     [--agent ID] [--name SLUG] [--enrollment-token T] [--mqtt-port N] \
                     [--proxy-port N] [--advertise-host HOST] [common options]"
                        .to_string(),
                );
            }
            other => take_common(&mut common, other, args)?,
        }
    }
    Ok(cmd::serve::ServeArgs {
        common,
        gateway_http: gateway_http.ok_or_else(|| {
            "--gateway-http is required (e.g. --gateway-http http://gateway:19876)".to_string()
        })?,
        enrollment_token,
        node_name,
        engine,
        auto_agent,
        mqtt_port,
        proxy_port,
        advertise_host,
    })
}

fn parse_runtime(
    args: &mut std::iter::Peekable<impl Iterator<Item = String>>,
) -> Result<cmd::runtime::RuntimeArgs, String> {
    let mut common = CommonArgs::defaults();
    let mut agent_id = None;
    let mut instance_id = None;
    let mut http_port = None;
    let mut gateway_host = None;
    let mut node_id = None;
    let mut work_dir = None;
    let mut mqtt_port = None;
    let mut package_path = None;
    let mut mqtt_username = None;
    let mut mqtt_password = None;
    let mut http_advertise_endpoint = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--agent-id" => agent_id = Some(value(args, "--agent-id")?),
            "--agent-instance-id" => instance_id = Some(value(args, "--agent-instance-id")?),
            "--http-port" => {
                http_port = Some(
                    value(args, "--http-port")?
                        .parse()
                        .map_err(|e| format!("--http-port: {e}"))?,
                )
            }
            "--gateway-host" => gateway_host = Some(value(args, "--gateway-host")?),
            "--node-id" => node_id = Some(value(args, "--node-id")?),
            "--work-dir" => work_dir = Some(PathBuf::from(value(args, "--work-dir")?)),
            "--mqtt-port" => {
                mqtt_port = Some(
                    value(args, "--mqtt-port")?
                        .parse()
                        .map_err(|e| format!("--mqtt-port: {e}"))?,
                )
            }
            "--package-path" => package_path = Some(PathBuf::from(value(args, "--package-path")?)),
            "--mqtt-username" => mqtt_username = Some(value(args, "--mqtt-username")?),
            "--mqtt-password" => mqtt_password = Some(value(args, "--mqtt-password")?),
            "--http-advertise-endpoint" => {
                http_advertise_endpoint = Some(value(args, "--http-advertise-endpoint")?)
            }
            "--help" | "-h" => {
                return Err(
                    "usage: acowork-android runtime --agent-id ID --agent-instance-id ID \
                     --http-port N --gateway-host HOST --node-id ID --work-dir DIR \
                     --package-path PATH [--http-advertise-endpoint URL]"
                        .to_string(),
                );
            }
            other => take_common(&mut common, other, args)?,
        }
    }
    Ok(cmd::runtime::RuntimeArgs {
        common,
        agent_id: agent_id.ok_or_else(|| "--agent-id is required".to_string())?,
        instance_id: instance_id.ok_or_else(|| "--agent-instance-id is required".to_string())?,
        http_port: http_port.ok_or_else(|| "--http-port is required".to_string())?,
        gateway_host: gateway_host.ok_or_else(|| "--gateway-host is required".to_string())?,
        node_id: node_id.ok_or_else(|| "--node-id is required".to_string())?,
        work_dir: work_dir.ok_or_else(|| "--work-dir is required".to_string())?,
        mqtt_port,
        package_path,
        mqtt_username,
        mqtt_password,
        http_advertise_endpoint,
    })
}

fn take_common(
    common: &mut CommonArgs,
    arg: &str,
    args: &mut std::iter::Peekable<impl Iterator<Item = String>>,
) -> Result<(), String> {
    match arg {
        "--root" => common.root = value(args, "--root")?.into(),
        "--package" => common.package = value(args, "--package")?,
        "--session" => common.session = value(args, "--session")?,
        "--transport" => {
            common.transport = TransportKind::parse(&value(args, "--transport")?)?;
        }
        "--dangerous-mode" => common.dangerous_mode = true,
        other if other.starts_with('-') => {
            return Err(format!("unknown option `{other}`"));
        }
        other => return Err(format!("unexpected argument `{other}`")),
    }
    Ok(())
}

fn value(args: &mut impl Iterator<Item = String>, name: &str) -> Result<String, String> {
    args.next().ok_or_else(|| format!("`{name}` needs a value"))
}

fn rest_join(args: &mut impl Iterator<Item = String>) -> String {
    args.collect::<Vec<_>>().join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(argv: &[&str]) -> Result<cmd::exec::ExecArgs, String> {
        let mut it = argv.iter().map(|s| (*s).to_string()).peekable();
        parse_exec(&mut it)
    }

    #[test]
    fn exec_accepts_script_after_separator() {
        let args = parse(&["--root", "/tmp/h", "--", "getprop", "ro.build.type"]).unwrap();
        assert_eq!(args.script, "getprop ro.build.type");
        assert_eq!(args.common.root.as_os_str(), "/tmp/h");
    }

    #[test]
    fn exec_accepts_quoted_script_without_separator() {
        let args = parse(&["id -u"]).unwrap();
        assert_eq!(args.script, "id -u");
    }

    #[test]
    fn serve_requires_gateway_http() {
        let mut it = std::iter::empty::<String>().peekable();
        assert!(parse_serve(&mut it).is_err());
    }

    #[test]
    fn serve_accepts_engine_and_agent() {
        let mut it = [
            "--gateway-http",
            "http://127.0.0.1:19876",
            "--engine",
            "integrated",
            "--agent",
            "demo",
        ]
        .iter()
        .map(|s| (*s).to_string())
        .peekable();
        let args = parse_serve(&mut it).unwrap();
        assert_eq!(args.gateway_http, "http://127.0.0.1:19876");
        assert_eq!(args.auto_agent.as_deref(), Some("demo"));
        assert!(args.engine.program.is_none());
    }

    #[test]
    fn runtime_requires_protocol_flags() {
        let mut it = std::iter::empty::<String>().peekable();
        assert!(parse_runtime(&mut it).is_err());
    }

    #[test]
    fn evidence_source_parser_covers_the_documented_shapes() {
        assert!(matches!(
            cmd::evidence::parse_source("screenshot").unwrap(),
            acowork_android::host::EvidenceSource::Screenshot
        ));
        assert!(matches!(
            cmd::evidence::parse_source("dumpsys:battery").unwrap(),
            acowork_android::host::EvidenceSource::Dumpsys { service } if service == "battery"
        ));
        assert!(cmd::evidence::parse_source("dumpsys").is_err());
        assert!(cmd::evidence::parse_source("file:relative").is_err());
    }

    #[test]
    fn transport_auto_resolves_off_android_to_adb() {
        // This crate is built on the development host, not as an Android target, so Auto
        // must pick adb — otherwise every off-device `probe` would try /system/bin/sh.
        assert_eq!(TransportKind::Auto.resolve(), TransportKind::Adb);
    }
}
