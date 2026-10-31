//! Assemble a runtime from a settings document and run one command through it.
//!
//! This is the missing caller. `HostConfig::prepare`, `PreparedHost::chain` and
//! `HostConfig::load` existed as a complete, tested API that nothing outside `config.rs` had
//! ever called — which is how a settings module ends up being a library about a runtime rather
//! than the runtime. Running this binary against a phone exercises the same sequence the APK will
//! run on the device: read the document, probe, build the chain, classify, gate, execute, audit,
//! restore.
//!
//! It is deliberately not a general-purpose CLI. There is one mode, and its job is to answer a
//! question an operator cannot answer from the settings screen: *is the number I set the number
//! that is in force?* Every value it prints is read back out of the assembled host, not out of the
//! crate's constants, so a setting that parses but is never consulted shows up here as a
//! disagreement.
//!
//! ```text
//! # read-only command, the default
//! ACOWORK_ADB=/path/to/adb ACOWORK_ADB_SERIAL=<serial> \
//!   cargo run -q -p acowork-android --bin acowork-host -- --root ./host "getprop ro.build.version.release"
//!
//! # a write, which the gate will ask about before the device is touched
//! cargo run -q -p acowork-android --bin acowork-host -- --root ./host \
//!   "settings put system font_scale 1.1"
//! ```
//!
//! The default command is a read. A script that the classifier says changes state is not run
//! without an approval, and the approval is asked for on the terminal — this binary is the
//! operator, so it is the operator's own yes, not a bypass flag. `--yes` answers it for a scripted
//! run and says so in the output.

use std::error::Error;
use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use acowork_android::host::{
    AdbTransport, ApprovalToken, ExecRequest, ExecutionBackend, HostConfig, HostProfile,
    LoadSource, ProbeCommand, ShellBackend, classify_script, run_probe,
};

/// What the operator asked for.
struct Args {
    /// Where this runtime's own files go. The settings document lives in it as `settings.json`.
    root: PathBuf,
    /// The package whose private directory the port treats as its own.
    package: String,
    /// The session id for the ledger, the lock and the audit trail.
    session: String,
    /// The script to run.
    script: String,
    /// Answer the approval prompt yes, for a scripted run.
    assume_yes: bool,
}

impl Args {
    fn parse(iter: impl Iterator<Item = String>) -> Result<Args, String> {
        let mut root = None;
        let mut package = Some("com.acowork.host".to_string());
        let mut session = None;
        let mut script = None;
        let mut assume_yes = false;
        let mut flags = iter.peekable();
        while let Some(arg) = flags.next() {
            match arg.as_str() {
                "--root" => root = Some(PathBuf::from(value(&mut flags, "--root")?)),
                "--package" => package = Some(value(&mut flags, "--package")?),
                "--session" => session = Some(value(&mut flags, "--session")?),
                "--yes" => assume_yes = true,
                "--help" | "-h" => {
                    return Err(
                        "usage: acowork-host [--root DIR] [--package PKG] [--session ID] [--yes] \
                         <script>"
                            .to_string(),
                    );
                }
                other if other.starts_with("--") => {
                    return Err(format!("unknown option `{other}`"));
                }
                other => {
                    if script.is_some() {
                        return Err(format!("unexpected extra argument `{other}`"));
                    }
                    script = Some(other.to_string());
                }
            }
        }
        Ok(Args {
            // A default root would put snapshots and an audit trail somewhere the operator did
            // not choose, so there is no default: naming it is part of using this binary.
            root: root.ok_or_else(|| {
                "--root is required: it holds settings.json, the snapshot \
                                        store and the audit trail"
                    .to_string()
            })?,
            package: package.expect("defaulted above"),
            session: session.unwrap_or_else(|| "host-cli".to_string()),
            script: script.ok_or_else(|| "a script is required".to_string())?,
            assume_yes,
        })
    }
}

fn value(iter: &mut impl Iterator<Item = String>, name: &str) -> Result<String, String> {
    iter.next().ok_or_else(|| format!("`{name}` needs a value"))
}

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("acowork-host: {err}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), Box<dyn Error>> {
    let args = Args::parse(std::env::args().skip(1)).map_err(|e| {
        let _ = std::io::stderr().write_all(format!("{e}\n").as_bytes());
        e
    })?;

    // ── 1. the document ──────────────────────────────────────────────────────
    //
    // Settings before device, because a phone that is unplugged must not hide the fact that
    // `settings.json` is corrupt: that failure would otherwise surface as "runtime did not start"
    // and be blamed on the cable.
    let loaded = HostConfig::load(&args.root)?;
    let source = match &loaded.source {
        LoadSource::File(path) => format!("{}", path.display()),
        LoadSource::Defaults => format!(
            "defaults — {} does not exist yet",
            HostConfig::settings_file(&args.root).display()
        ),
    };
    println!("settings   {source}");

    // ── 2. the device ────────────────────────────────────────────────────────
    let transport = AdbTransport::from_env().ok_or(
        "no adb to talk to: set ACOWORK_ADB to the binary and ACOWORK_ADB_SERIAL to the device \
         (see README, 「Against a real device」)",
    )?;
    println!(
        "device     adb at {}, attached to {}",
        std::env::var("ACOWORK_ADB").unwrap_or_else(|_| "PATH".to_string()),
        transport.serial().unwrap_or("the only device connected")
    );
    let probe = run_probe(&transport, &ProbeCommand::read_only_set(), &args.package).await;
    let profile = HostProfile::assemble(&probe, &args.package);
    println!(
        "           profile {:?} · API {} · {:?} build · shell {:?} · SELinux {:?}",
        profile.name,
        profile
            .device
            .api_level
            .map(|n| n.to_string())
            .unwrap_or("?".into()),
        profile.device.build_type,
        profile.shell,
        profile.selinux,
    );

    // ── 3. the chain, from the document ──────────────────────────────────────
    let prepared = loaded.config.prepare(&args.root)?;
    let inner: Arc<dyn ExecutionBackend> = Arc::new(
        ShellBackend::with_runner(profile.clone(), transport.clone())?
            .with_default_budget(prepared.default_budget),
    );
    let chain = prepared.chain(Arc::clone(&inner));

    // Everything below is read off what was assembled. If a setting parses but is never consulted,
    // this is where it shows up as a value the operator did not set.
    println!(
        "           snapshots  {} (budget {} bytes, used {})",
        prepared.snapshots.dir().display(),
        prepared.snapshots.budget(),
        prepared.snapshots.used_bytes()
    );
    println!(
        "           audit      {} (cap {} bytes, used {})",
        prepared.audit.path().display(),
        prepared.audit.max_bytes(),
        prepared.audit.used_bytes()
    );
    println!(
        "           limits     timeout {:?}, output cap {} bytes, evidence budget {} bytes, \
         bugreport wait {:?}",
        prepared.default_budget.timeout,
        prepared.default_budget.output_cap,
        prepared.limits.budget,
        prepared.limits.bugreport,
    );

    let claims = loaded.config.claims(&profile)?;
    let granted: Vec<String> = claims
        .iter()
        .map(|c| c.capability.as_str().to_string())
        .collect();
    println!("           claims     {}", granted.join(", "));
    let blocked = loaded.config.blocked_by_settings(&profile);
    if !blocked.is_empty() {
        // The distinction the settings screen has to keep visible: a capability the device cannot
        // do is not the operator's fault, and one they switched off is not the device's.
        println!(
            "           off by settings: {}",
            blocked
                .iter()
                .map(|c| c.id().as_str().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    // ── 4. classify, then ask if it is a write ───────────────────────────────
    let verdict = classify_script(&args.script);
    let effect = verdict.strongest();
    println!("command    {}", args.script);
    println!("           classified as {effect:?}");

    let Some(capability) = effect.capability() else {
        // Opaque and Banned have no capability, so there is nothing to request. Say what the
        // classifier could not bound rather than letting the gate produce a generic refusal.
        let refusal = verdict.refusal_for(None);
        println!(
            "           refused: {}",
            refusal
                .map(|r| r.to_string())
                .unwrap_or_else(|| "no capability authorises it".to_string())
        );
        println!("           (nothing was sent to the device)");
        return Ok(());
    };
    println!("           needs      {}", capability.id().as_str());

    let mut request = ExecRequest::new(capability, args.script.clone(), args.session.clone());
    if !effect.is_read_only() {
        let approved = if args.assume_yes {
            println!("           approved by --yes (a scripted run answering for the operator)");
            true
        } else {
            ask(&args.script, effect)?
        };
        if !approved {
            println!("           not approved — nothing was sent to the device");
            return Ok(());
        }
        request.approval_token = Some(ApprovalToken::new("operator-terminal"));
    }

    // ── 5. execute through the chain ─────────────────────────────────────────
    let record = chain.exec(request).await?;
    println!(
        "           exit {:?} in {} ms, {} bytes{}",
        record.exit_code,
        record.duration_ms,
        record.stdout.len(),
        if record.truncated { " (TRUNCATED)" } else { "" }
    );
    for line in record.stdout.lines().take(5) {
        println!("           | {line}");
    }
    if !record.stderr.trim().is_empty() {
        println!("           stderr: {}", record.stderr.trim());
    }
    if !record.selinux_denials.is_empty() {
        println!(
            "           {} SELinux denial(s): {}",
            record.selinux_denials.len(),
            record
                .selinux_denials
                .iter()
                .map(|d| d.repeat_key())
                .collect::<Vec<_>>()
                .join("; ")
        );
    }

    // ── 6. what the ledger and the audit file recorded ───────────────────────
    let report = chain.restore(&args.session).await;
    println!(
        "restore    {} undone, {} failed, {} left for another session",
        report.restored.len(),
        report.failed.len(),
        report.still_pending_elsewhere
    );
    for target in &report.restored {
        println!("           restored  {target}");
    }
    for (target, why) in &report.failed {
        // A failed restore is the one outcome an operator has to be told about in the terminal,
        // not only in the audit file: the device is now in a state nobody rolled back.
        println!("           FAILED      {target}: {why}");
    }

    let tail = last_audit_line(prepared.audit.path())?;
    println!("audit      last record: {tail}");
    Ok(())
}

/// Ask the operator. Refuses to answer for them when there is no terminal to ask.
fn ask(script: &str, effect: acowork_android::host::Effect) -> Result<bool, Box<dyn Error>> {
    use std::io::IsTerminal;
    if !std::io::stdin().is_terminal() {
        return Err(format!(
            "this command changes state ({effect:?}) and there is no terminal to ask about it; \
             pass --yes only if you have read what it does: {script}"
        )
        .into());
    }
    print!("run `{script}` on the device? it is a {effect:?} — approve [y/N]: ");
    std::io::stdout().flush()?;
    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer)?;
    Ok(matches!(answer.trim(), "y" | "Y" | "yes" | "YES"))
}

/// The final line of the audit file, so the operator can see the run was recorded rather than
/// being told it was.
fn last_audit_line(path: &std::path::Path) -> Result<String, Box<dyn Error>> {
    let text = std::fs::read_to_string(path)
        .map_err(|_| "no audit file was written — the run did not reach the sink")?;
    let Some(line) = text.lines().next_back() else {
        return Ok("<empty>".to_string());
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
        return Ok(line.to_string());
    };
    // One line of JSON is too wide to read in a terminal; show the parts that answer "what did
    // it record about the command I just ran".
    let mut parts = Vec::new();
    // The real record schema: `(session_id, id)` names one command and the attempt/result pair
    // shares it, so a line has to say which of the two it is.
    for key in ["session_id", "id", "capability", "command"] {
        if let Some(field) = value.get(key) {
            let text = field
                .as_str()
                .map(String::from)
                .unwrap_or_else(|| field.to_string());
            parts.push(format!("{key}={text}"));
        }
    }
    if let Some(outcome) = value.get("outcome") {
        let kind = outcome
            .get("outcome")
            .and_then(|o| o.as_str())
            .unwrap_or("?");
        let exit = outcome
            .get("exit_code")
            .map(|c| format!(" exit {c}"))
            .unwrap_or_default();
        parts.push(format!("outcome={kind}{exit}"));
    }
    Ok(parts.join(" "))
}
