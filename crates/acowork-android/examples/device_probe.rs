// Device harness: run the real probe, the real profile assembly and a real execution
// against a physical device, and print what the port actually concluded.
//
//     ACOWORK_ADB=/tmp/platform-tools/adb \
//     ACOWORK_ADB_SERIAL=emulator-5554 \
//         cargo run -p acowork-android --example device_probe -- --out /tmp/probe.json
//
// Three things happen here, in order, and each answers a separate question:
//
//   1. **Probe** — what does the device say about itself, verbatim?
//   2. **Assemble** — what profile and capabilities does the port derive from that, and does
//      the derivation match what is independently known to be true of this device?
//   3. **Execute** — does a command actually run through the real backend, with the identity
//      that ran it correctly extracted from the output?
//
// Step 3 is what justifies the harness existing. Steps 1 and 2 can be checked by reading a
// dump; step 3 is the only place where `script`'s quoting, the identity prologue, the output
// cap, the deadline and the denial parser meet a shell that is not ours.

use std::error::Error;
use std::path::PathBuf;

use acowork_android::host::capability::Capability;
use acowork_android::host::probe::{CommandOutput, ProbeOutput, run_probe};
use acowork_android::host::spawn::{SpawnInvocation, SpawnRunner};
use acowork_android::host::{
    AdbTransport, AuditedBackend, BackendError, ExecRequest, ExecutionBackend, FileAuditSink,
    HostProfile, ProbeCommand, ShellBackend, check_script, shell_tools,
};
use acowork_platform_contract::HostDescription;

/// The package the harness pretends to be, used for the own-package root in probe item 12.
/// Nothing is installed under this name; an absent `/data/data/<pkg>` is simply not reported,
/// which is the honest answer rather than a fabricated one.
const DEFAULT_OWN_PACKAGE: &str = "com.acowork.node";

fn main() -> Result<(), Box<dyn Error>> {
    tokio::runtime::Runtime::new()?.block_on(run())
}

struct Args {
    out: Option<PathBuf>,
    own_package: String,
    skip_exec: bool,
}

fn parse_args() -> Result<Args, Box<dyn Error>> {
    let mut args = Args {
        out: None,
        own_package: DEFAULT_OWN_PACKAGE.to_string(),
        skip_exec: false,
    };
    let mut iter = std::env::args().skip(1);
    while let Some(a) = iter.next() {
        match a.as_str() {
            "--out" => args.out = Some(PathBuf::from(iter.next().ok_or("--out needs a path")?)),
            "--package" => args.own_package = iter.next().ok_or("--package needs a value")?,
            "--skip-exec" => args.skip_exec = true,
            other => return Err(format!("unrecognised argument `{other}`").into()),
        }
    }
    Ok(args)
}

async fn run() -> Result<(), Box<dyn Error>> {
    let args = parse_args()?;

    let bare = AdbTransport::from_env().ok_or(
        "no device configured: set ACOWORK_ADB (path to adb) and optionally \
         ACOWORK_ADB_SERIAL (device serial, see `adb devices`)",
    )?;

    // Fail before the 17-command probe if adb cannot reach anything.
    let hello = SpawnInvocation::new("/system/bin/sh", "echo acowork-harness\n");
    match bare.spawn(hello).await {
        Ok(out) if out.exit_code == Some(0) => {
            let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if text != "acowork-harness" {
                return Err(format!("device echoed {text:?}, expected \"acowork-harness\"").into());
            }
        }
        Ok(out) => {
            return Err(format!(
                "device reachable but the shell did not run the script: exit {:?}, stderr {}",
                out.exit_code,
                String::from_utf8_lossy(&out.stderr).trim()
            )
            .into());
        }
        Err(e) => return Err(format!("cannot reach a device: {e}").into()),
    }

    // `$PREFIX` is read once up front: the trait method is synchronous because on the device
    // it is an environment read, and a remote round trip must not happen inside it.
    let transport = bare
        .clone()
        .with_termux_prefix(bare.read_termux_prefix().await);

    let commands = ProbeCommand::read_only_set();
    let probe = run_probe(&transport, &commands, &args.own_package).await;

    println!(
        "── 1. probe ({} commands) ─────────────────────────────",
        commands.len()
    );
    report_probe(&probe);

    if let Some(out) = &args.out {
        std::fs::write(out, serde_json::to_string_pretty(&probe)?)?;
        println!("\ncaptured fixture -> {}", out.display());
    }

    let profile = HostProfile::assemble(&probe, &args.own_package);
    println!("\n── 2. assembled profile ─────────────────────────────");
    report_profile(&profile);

    if !args.skip_exec {
        println!("\n── 3. execution ───────────────────────────────────");
        report_exec(&profile, &transport).await;
        println!("\n── 4. §4.4 guardrails ──────────────────────────────");
        report_guardrails(&profile, &transport).await;
        println!("\n── 5. §4.5 tool registration ────────────────────────");
        for tool in shell_tools(&profile) {
            println!("  {} -> {}", tool.name, tool.path.display());
            for line in tool.description.lines() {
                println!("      {line}");
            }
        }
        println!("\n── 6. §4.6.1 audit trail ────────────────────────────");
        report_audit(&profile, &transport).await?;
        println!("\n── 7. §4.6 item 6 evidence surface ─────────────────");
        report_evidence(&profile);
        println!("\n── 8. §7.1 projection redaction ───────────────────");
        report_projection(&profile, &transport).await;
    }

    Ok(())
}

/// Print what this uid can actually collect as evidence, per source.
///
/// Printed as measured access rather than as a yes/no availability, because the ADR's list
/// is written yes/no and the device is not: on the BLA-AL00 `/data/anr` lists filenames and
/// refuses contents, which is neither available nor unavailable.
fn report_evidence(profile: &HostProfile) {
    use acowork_android::host::facts::EvidencePath;
    if profile.evidence.is_unknown() {
        println!("  nothing was probed");
        return;
    }
    for path in EvidencePath::ALL {
        let access = profile.evidence.access(path);
        println!(
            "  {:<24} {}{}",
            path.path(),
            access.describe(),
            if access.has_contents() {
                "  <- contents collectable"
            } else {
                ""
            }
        );
    }
    match profile.evidence.dumpsys_services {
        Some(count) => println!("  dumpsys services         {count} listed"),
        None => println!("  dumpsys services         not answered"),
    }
    println!(
        "  readable sources         {:?}",
        profile
            .evidence
            .readable()
            .iter()
            .map(|p| p.path())
            .collect::<Vec<_>>()
    );
}

fn report_probe(probe: &ProbeOutput) {
    let field = |name: &str, slot: &Option<CommandOutput>| match slot {
        None => println!("  {name:<16} not run"),
        Some(o) => println!(
            "  {:<16} {:>5}  exit {:?}{}  {}",
            name,
            match o.duration_ms {
                Some(ms) => format!("{ms}ms"),
                None => "-".to_string(),
            },
            o.exit_code,
            if o.timed_out { " TIMEOUT" } else { "" },
            excerpt(&o.stdout, &o.stderr),
        ),
    };
    field("id -u", &probe.id);
    field("getenforce", &probe.getenforce);
    field("attr/current", &probe.attr_current);
    field("su", &probe.su);
    field("su on PATH", &probe.su_path);
    field("bash", &probe.bash_path);
    // Not "sh --version": that option is an error on Android's mksh, and what runs here is
    // the dialect-variable probe (item 5b). The old label described the command the fixtures
    // claimed, not the one the device was asked.
    field("sh dialect", &probe.system_sh_version);
    field("toybox list", &probe.toybox_list);
    field("busybox list", &probe.busybox_list);
    field("mounts", &probe.mount_table);
    field("build.type", &probe.prop_build_type);
    field("debuggable", &probe.prop_debuggable);
    field("veritymode", &probe.prop_veritymode);
    field("sdk", &probe.prop_sdk);
    field("abi", &probe.prop_abi);
    field("evidence", &probe.evidence_surface);
    field("dumpsys -l", &probe.dumpsys_inventory);
    // The §3 budget is a *total*, and a per-item deadline is not evidence about it: twenty
    // commands at 49 ms each never trip a 500 ms guard and still cost a second. Printed with
    // its scope stated, because this number covers the serial command loop and not the
    // up-front `$PREFIX` read or the `fs_roots` write probes.
    match (probe.total_duration_ms(), probe.slowest_item_ms()) {
        (Some(total), Some(slowest)) => println!(
            "  {:<16} {total}ms total, {slowest}ms slowest  (serial command loop only)",
            "probe cost"
        ),
        _ => println!("  {:<16} not measured", "probe cost"),
    }
    println!("  {:<16} {:?}", "termux $PREFIX", probe.termux_prefix);
    println!("  {:<16} {} reachable", "fs roots", probe.fs_roots.len());
    for r in &probe.fs_roots {
        println!(
            "    {} {}{}",
            if r.writable { "rw" } else { "ro" },
            r.path,
            if r.own_package { " (own package)" } else { "" }
        );
    }
}

/// First 70 printable characters of a probe answer, preferring stdout.
fn excerpt(stdout: &str, stderr: &str) -> String {
    let src = if stdout.trim().is_empty() {
        stderr
    } else {
        stdout
    };
    let cut: String = src.chars().filter(|c| *c != '\0').take(70).collect();
    let flat = cut.replace('\n', " ").trim().to_string();
    if flat.is_empty() { "(empty)" } else { &flat }.to_string()
}

fn report_profile(profile: &HostProfile) {
    println!("  name         : {}", profile.name.as_str());
    println!("  privilege    : {:?}", profile.privilege);
    println!(
        "  selinux      : {:?}  domain {:?}  context {:?}",
        profile.selinux, profile.domain, profile.context
    );
    println!(
        "  shell        : {:?}  all dialects {:?}",
        profile.shell, profile.dialects
    );
    println!("  su           : {:?}", profile.su);
    println!(
        "  applets      : {} (source missing: {})",
        profile.applets.len(),
        profile.applets.list_source_missing
    );
    println!("  paths        : {:?}", profile.paths);
    println!("  device       : {:?}", profile.device);
    println!("  contract lvl : {:?}", HostDescription::privilege(profile));
    println!(
        "  R3 conformant: {}",
        HostDescription::is_r3_conformant(profile)
    );
    println!(
        "  escalation   : {:?}",
        HostDescription::escalation(profile)
    );

    let summary = HostDescription::summary(profile);
    println!(
        "  summary      : {} / {} / {:?} / {:?}",
        summary.platform, summary.profile, summary.privilege, summary.capabilities
    );

    println!("\n  declared:");
    for id in profile.caps.declared_ids() {
        let spec = profile
            .caps
            .spec(&acowork_platform_contract::HostCapability::parse(id).expect("declared id"));
        match spec {
            Some(s) => println!(
                "    {:<22} {:?} / approval {:?} / {:?}",
                id, s.effect, s.approval, s.reversibility
            ),
            None => println!("    {id}  (declared, no spec)"),
        }
    }
    println!("  not declared, and why:");
    for cap in Capability::all() {
        let id = cap.id();
        if profile.caps.is_declared(&id) {
            continue;
        }
        println!("    {:<22} {}", id.as_str(), profile.explain_absence(&id));
    }
}

async fn report_exec(profile: &HostProfile, transport: &AdbTransport) {
    let backend = match ShellBackend::with_runner(profile.clone(), transport.clone()) {
        Ok(b) => b,
        Err(e) => {
            println!("  no shell backend for this profile: {e}");
            return;
        }
    };
    println!(
        "  backend      : {} ({:?})",
        backend.name(),
        backend.dialect()
    );
    println!("  shell        : {}", backend.shell_path().display());
    println!("  base env     : {:?}", backend.base_env());

    let request = ExecRequest::read("echo acowork-harness-ok; id -u; pwd", "harness-session");
    match backend.exec(request).await {
        Ok(record) => {
            println!("  exit         : {:?}", record.exit_code);
            println!(
                "  identity     : uid {:?}  context {:?}",
                record.uid, record.context
            );
            println!(
                "  timed out    : {}   truncated: {}",
                record.timed_out, record.truncated
            );
            println!("  duration     : {}ms", record.duration_ms);
            println!("  stdout       : {}", record.stdout.trim());
            if !record.stderr.trim().is_empty() {
                println!("  stderr       : {}", record.stderr.trim());
            }
            if !record.selinux_denials.is_empty() {
                println!("  denials      : {:?}", record.selinux_denials);
            }
        }
        Err(e) => println!("  failed       : {e}"),
    }
}

/// Check the §7.1 red line on the **output of a real command**, not only on the port's own
/// error strings.
///
/// The rule forbids denial detail crossing the port, and the realistic carrier is not the
/// error stream: an avc record is written by the kernel to the audit log, so it reaches this
/// process as the *stdout* of `logcat -d` — the exact command ADR-AND-001 §4.6 item 6 tells
/// an agent to run for evidence. A redactor wired only to stderr would ship the MLS
/// categories of whatever app tripped the denial inside the log dump the agent asked for.
///
/// Printed rather than asserted, because the device decides whether there is anything to
/// check: a quiet log window means the path was not exercised, and saying so out loud is
/// worth more than a green line that proved nothing.
async fn report_projection(profile: &HostProfile, transport: &AdbTransport) {
    let backend = match ShellBackend::with_runner(profile.clone(), transport.clone()) {
        Ok(b) => b,
        Err(e) => {
            println!("  no shell backend for this profile: {e}");
            return;
        }
    };
    // One command replays the audit log, one is very likely to be refused by policy on a
    // `user` build, so the blocked-but-clean-exit shape is exercised in the same pass.
    for script in [
        "logcat -d -b events -t 400",
        "cat /data/system/packages.xml",
    ] {
        let request = ExecRequest::read(script, "harness-session");
        let record = match backend.exec(request).await {
            Ok(r) => r,
            Err(e) => {
                println!("\n  {script}\n    failed: {e}");
                continue;
            }
        };
        let projected = record.to_contract();
        let out = String::from_utf8_lossy(&projected.stdout.bytes).into_owned();
        let err = String::from_utf8_lossy(&projected.stderr.bytes).into_owned();
        let raw = format!("{}{}", record.stdout, record.stderr);
        let wire = format!("{out}{err}");
        let denials = acowork_android::host::parse_denials(&raw);
        println!("\n  {script}");
        println!(
            "    exit {:?}  {}ms  {} avc record(s) in the raw output",
            record.exit_code,
            record.duration_ms,
            denials.len()
        );
        for token in ["u:r:", "u:object_r:", "s0:c"] {
            println!(
                "    {token:<12} raw {:>4}   projected {:>4}{}",
                raw.matches(token).count(),
                wire.matches(token).count(),
                if wire.contains(token) {
                    "  <- LEAK"
                } else {
                    ""
                }
            );
        }
        println!(
            "    audit records: {} denied in raw, {} avc-shaped lines redacted",
            denials.len(),
            raw.lines().filter(|l| l.contains("avc:")).count()
        );
        if let Some(line) = denials.first().map(|d| d.summary()) {
            println!("    summarised as: {line}");
        }
    }
}

/// §4.4's auto-pass is a claim about the script, not about the label on the request, so the
/// harness shows both halves: what the classifier decides for representative scripts, and
/// whether the read tier actually runs on the device a command that only exists because
/// probe item 6c went and looked for it.
async fn report_guardrails(profile: &HostProfile, transport: &AdbTransport) {
    let backend = match ShellBackend::with_runner(profile.clone(), transport.clone()) {
        Ok(b) => b,
        Err(e) => {
            println!("  no shell backend for this profile: {e}");
            return;
        }
    };

    for (script, claim) in [
        ("getprop ro.build.type", Capability::ShellRead),
        ("logcat -d -t 3", Capability::ShellRead),
        (
            "settings put system airplane_mode_on 1",
            Capability::ShellRead,
        ),
        ("logcat -c", Capability::ShellRead),
        ("toybox rm -rf /data", Capability::ShellWrite),
    ] {
        print!("  {:<42} {:<14}", script, format!("{claim:?}"));
        match check_script(script, Some(claim)) {
            Ok(verdict) => println!("-> {:?}, allowed", verdict.strongest()),
            Err(refusal) => println!("-> refused: {refusal}"),
        }
    }

    // `logcat` is not a toybox applet on this device; the read tier only works because
    // item 6c proved it is there. Run it for real.
    let request = ExecRequest::read("logcat -d -t 3", "harness-session");
    match backend.exec(request).await {
        Ok(record) => println!(
            "  logcat on device: exit {:?} uid {:?} {}ms  {}",
            record.exit_code,
            record.uid,
            record.duration_ms,
            record.stdout.lines().next().unwrap_or("").trim(),
        ),
        Err(e) => println!("  logcat on device: failed {e}"),
    }
}

/// §4.6.1: the audit fields were all being computed and then dropped, so the harness runs
/// three real attempts through the auditing decorator and prints the file that comes out.
///
/// Three attempts, not one, because the log has to separate the outcomes that matter:
/// something ran, something was refused for a fixable reason, and something was refused
/// because it must never run. A trail that records only the first is a traffic counter.
///
/// The sink writes on the **host** here, because this harness runs on the host and drives the
/// device over adb. On a device the same `FileAuditSink` points at the node's own data
/// directory. What is proved is the code path — record, spawn, record — not the partition.
async fn report_audit(
    profile: &HostProfile,
    transport: &AdbTransport,
) -> Result<(), Box<dyn Error>> {
    use std::sync::Arc;

    use acowork_android::host::{AuditSink, DEFAULT_MAX_FILE_BYTES, MemoryAuditSink};

    let shell: Arc<dyn ExecutionBackend> = Arc::new(ShellBackend::with_runner(
        profile.clone(),
        transport.clone(),
    )?);

    let path = std::env::temp_dir().join(format!(
        "acowork-audit-harness-{}.jsonl",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&path);
    let sink = Arc::new(FileAuditSink::new(&path));
    let audited = AuditedBackend::new(shell.clone(), sink.clone());

    for (script, claim) in [
        ("getprop ro.build.type", Capability::ShellRead),
        (
            "settings put system airplane_mode_on 1",
            Capability::ShellRead,
        ),
        ("toybox rm -rf /data", Capability::ShellWrite),
    ] {
        let outcome = audited
            .exec(ExecRequest::new(claim, script, "harness-session"))
            .await;
        print!("  {:<40} ", script);
        match outcome {
            Ok(record) => println!(
                "ran: exit {:?} uid {:?} {}ms",
                record.exit_code, record.uid, record.duration_ms
            ),
            Err(BackendError::Refused { kind, .. }) => println!("refused: {kind:?}"),
            Err(e) => println!("failed: {e}"),
        }
    }

    // The fail-closed half: a sink that cannot accept the opening record stops the command
    // before the device is touched. The backend is never entered, so nothing ran — which is
    // the only reason this is safe to demonstrate against a real phone at all.
    let blocked = AuditedBackend::new(shell, Arc::new(MemoryAuditSink::failing_after(0)));
    match blocked
        .exec(ExecRequest::read(
            "getprop ro.build.type",
            "harness-session",
        ))
        .await
    {
        Err(e) => println!("  sink refuses the record    -> command not run: {e}"),
        Ok(_) => println!("  sink refuses the record    -> RAN ANYWAY (this is a defect)"),
    }

    let text = std::fs::read_to_string(&path)?;
    println!(
        "\n  {} — {} records, {} bytes (cap {DEFAULT_MAX_FILE_BYTES})",
        path.display(),
        text.lines().count(),
        text.len()
    );
    for line in text.lines() {
        let event: serde_json::Value = serde_json::from_str(line)?;
        let outcome = &event["outcome"];
        println!(
            "    id {:<2} {:<9} {:<18} uid {:<6} ctx {:<20} {}",
            event["id"],
            event["backend"].as_str().unwrap_or("?"),
            event["capability"].as_str().unwrap_or("?"),
            event["uid"],
            event["context"].as_str().unwrap_or("-"),
            outcome["outcome"].as_str().unwrap_or("?"),
        );
        if let Some(reason) = outcome.get("reason").and_then(|v| v.as_str()) {
            let one_line: String = reason.split_whitespace().collect::<Vec<_>>().join(" ");
            println!("        {}", one_line.chars().take(140).collect::<String>());
        }
    }
    println!("  sink failures: {}", sink.failures());
    Ok(())
}
