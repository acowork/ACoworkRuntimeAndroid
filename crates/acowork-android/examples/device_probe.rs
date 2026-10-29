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
    HostProfile, MemoryAuditSink, ProbeCommand, ReversibleBackend, ShellBackend, check_script,
    shell_tools,
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
        println!("\n── 9. §4.6.4 rollback planner ─────────────────────");
        report_rollback(&profile, &transport).await;
        println!("\n── 10. §4.6.4 write → restore round trip ──────────");
        report_rollback_roundtrip(&profile, &transport).await?;
        println!("\n── 11. §4.6.4 file snapshot round trip ────────────");
        report_file_snapshot(&profile, &transport).await?;
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
/// Where the harness keeps file snapshots.
///
/// A node would pass its Agent workspace — §4.6.4 names that as where a backup goes. The
/// harness has no workspace, so it prints the path instead of pretending it is somewhere else.
fn snapshot_dir() -> std::path::PathBuf {
    std::env::temp_dir().join("acowork-probe-snapshots")
}

/// A backend chain that can write: the shell tier alone declares reads, and §4.6.4 cannot be
/// demonstrated on a device that refuses every write.
async fn writable_chain(
    profile: &HostProfile,
    transport: &AdbTransport,
    sink: std::sync::Arc<dyn acowork_android::host::AuditSink>,
) -> Result<ReversibleBackend, Box<dyn Error>> {
    let mut granted = profile.clone();
    // Both halves of the write tier: a property write and a file write are different claims, and
    // the gate refuses a `shell:write` label on a redirect — which is the harness being told the
    // truth rather than a bug to route around.
    for capability in [Capability::ShellWrite, Capability::FsOutsideApp] {
        granted
            .caps
            .declare(capability.id())
            .map_err(|e| format!("cannot hand-declare {}: {e}", capability.id()))?;
    }
    use std::sync::Arc;
    let shell: Arc<dyn ExecutionBackend> =
        Arc::new(ShellBackend::with_runner(granted, transport.clone())?);
    let audited: Arc<dyn ExecutionBackend> = Arc::new(AuditedBackend::new(shell, sink));
    Ok(ReversibleBackend::new(audited, snapshot_dir()))
}

/// What §4.6.4 would remember before a write, and what it would run at session end.
///
/// **No write is executed here.** The point of the section is the pre-state capture and the
/// inverse it produces, and both are reachable by running the read half against the device —
/// which is the half that has to be right, since an undo built on a misread value is a second,
/// unapproved change rather than a rollback. Toggling a real property on somebody's handset to
/// watch the restore path work is a demonstration the unit tests already cover with a fake
/// backend that records the request sequence.
async fn report_rollback(profile: &HostProfile, transport: &AdbTransport) {
    let backend = match ShellBackend::with_runner(profile.clone(), transport.clone()) {
        Ok(b) => b,
        Err(e) => {
            println!("  no shell backend for this profile: {e}");
            return;
        }
    };

    for script in [
        "setprop debug.stagefright.ccodec 1",
        "settings put system font_scale 1.6",
        "setenforce 0",
    ] {
        println!("\n  {script}");
        let plan = acowork_android::host::plan_rollback(script);
        for capture in &plan.captures {
            // A file capture is a two-read protocol that ends in a snapshot *file*, so it is
            // demonstrated for real in the round-trip section below rather than half-shown here.
            if matches!(capture.target, acowork_android::host::UndoTarget::File(_)) {
                println!(
                    "    {} would be measured with `{}` and then snapshotted at execution time",
                    capture.target.describe(),
                    capture.read
                );
                continue;
            }
            let request = ExecRequest::read(capture.read.clone(), "harness-session");
            let observed = match backend.exec(request).await {
                Ok(r) if r.succeeded() => Some(r.stdout),
                Ok(r) => {
                    println!(
                        "    capture `{}` -> exit {:?}: {}",
                        capture.read,
                        r.exit_code,
                        r.stderr.trim()
                    );
                    None
                }
                Err(e) => {
                    println!("    capture `{}` -> {e}", capture.read);
                    None
                }
            };
            let claimed = acowork_android::host::classify_script(script)
                .strongest()
                .capability();
            let mut request = ExecRequest::new(
                claimed.unwrap_or(acowork_android::host::Capability::ShellWrite),
                script,
                "harness-session",
            );
            request.approval_token = Some(acowork_android::host::ApprovalToken::new("harness"));
            match acowork_android::host::undo_for(
                capture,
                observed.map(acowork_android::host::PreState::Value),
                &request,
            ) {
                acowork_android::host::UndoResult::Undo(undo) => {
                    println!(
                        "    pre-state {:?}  ->  would restore with `{}`{}",
                        undo.old_value,
                        undo.inverse_script().unwrap_or("<restore from snapshot>"),
                        if undo.faithful {
                            String::new()
                        } else {
                            " (approximate: the key was unset, and Android has no unset)"
                                .to_string()
                        }
                    );
                    println!(
                        "    capability {}  approval reused: {}  persists across reboot: {}",
                        undo.capability,
                        undo.token.is_some(),
                        undo.persists_reboot
                    );
                }
                acowork_android::host::UndoResult::NothingToUndo(why) => {
                    println!("    nothing to undo: {why}");
                }
                acowork_android::host::UndoResult::CannotUndo(why) => {
                    println!("    NO UNDO POSSIBLE: {why}");
                }
            }
        }
    }

    println!("\n  writes this port cannot put back:");
    for script in [
        "am broadcast -a android.intent.action.BOOT_COMPLETED",
        "echo note > /data/local/tmp/note.txt",
        "setprop persist.sys.demo 1 &",
    ] {
        for item in acowork_android::host::plan_rollback(script).unundoable {
            // Two lines rather than a padded column: the unanalysable case's "command" is the
            // whole script, and a fixed width either truncates it or pushes the reason off the
            // edge — and the reason is the part that matters.
            println!("    {}\n      {}", item.command, item.why);
        }
    }
}

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
use acowork_platform_contract::{Gate, GateDecision, LocalReadiness, LockState};

/// §4.6.4 run against the phone instead of against a fake.
///
/// The unit tests prove the ledger's bookkeeping. They cannot prove that the inverse script
/// this port generates actually puts *this device* back: `setprop 'k' ''` is an approximation
/// the module admits to (`faithful: false`), and whether Android's property implementation
/// treats that as "unset" is a fact about the device, not about our parsing. Only a round trip
/// on hardware says which one it is.
///
/// The key is `debug.acowork.probe` — a `debug.*` property nothing on the device reads. That
/// choice is the only thing standing between a demonstration and an incident, because this
/// section really does write to a live phone.
async fn report_rollback_roundtrip(
    profile: &HostProfile,
    transport: &AdbTransport,
) -> Result<(), Box<dyn Error>> {
    use std::sync::Arc;

    use acowork_android::host::ApprovalToken;

    let shell: Arc<dyn ExecutionBackend> = Arc::new(ShellBackend::with_runner(
        profile.clone(),
        transport.clone(),
    )?);
    let sink = Arc::new(MemoryAuditSink::new());
    // Order matters and is the point: the rollback decorator sits *outside* the audit
    // decorator, so its capture reads and its inverse writes are records like any other.
    // Compose it the other way round and the teardown becomes the one part of a write
    // session that leaves no trace.
    let audited: Arc<dyn ExecutionBackend> =
        Arc::new(AuditedBackend::new(shell.clone(), sink.clone()));
    let chain = ReversibleBackend::new(Arc::clone(&audited), snapshot_dir());

    // Observers read through the audit decorator but not through the rollback decorator: an
    // observation must not add ledger entries, and nothing that touches the device should
    // escape the trail — including the harness's own probes. A demo that reads the phone
    // outside the log it prints would be teaching the wrong lesson about §4.6.1.
    async fn read_prop(shell: &Arc<dyn ExecutionBackend>, name: &str) -> String {
        match shell
            .exec(ExecRequest::read(
                format!("getprop {name}"),
                "harness-observer",
            ))
            .await
        {
            Ok(r) => r.stdout.trim().to_string(),
            Err(e) => format!("<unreadable: {e}>"),
        }
    }

    async fn read_file(shell: &Arc<dyn ExecutionBackend>, path: &str) -> String {
        match shell
            .exec(ExecRequest::read(format!("cat {path}"), "harness-observer"))
            .await
        {
            Ok(r) if r.succeeded() => r.stdout.trim().to_string(),
            Ok(r) => format!("<exit {:?}>", r.exit_code),
            Err(e) => format!("<{e}>"),
        }
    }

    let gate = Gate::new(profile);
    let ready = LocalReadiness {
        dangerous_session: false,
        approval_presented: true,
        lock: LockState::Available,
    };

    // ── the floor, on the real profile ────────────────────────────────────────
    let prop = "debug.acowork.probe";
    let session = "harness-roundtrip";
    let mut probe_request = ExecRequest::new(
        Capability::ShellWrite,
        format!("setprop {prop} harness-1"),
        session,
    );
    probe_request.approval_token = Some(ApprovalToken::new("harness"));
    match gate.decide(&probe_request, None, ready) {
        GateDecision::Allow { hold_lock, .. } => {
            println!("  gate allows `android:shell:write` here (hold_lock: {hold_lock})");
        }
        other => println!(
            "  gate refuses `android:shell:write` on this tier: {:?}",
            other.refusal()
        ),
    }
    // The same request, one layer down, with the gate deliberately not consulted. This is the
    // hole the backend check was added for: the harness below found it by *working* — a caller
    // that skipped `decide` used to get a real write out of a device whose profile never
    // demonstrated the tier.
    match chain.exec(probe_request).await {
        Err(BackendError::Refused { reason, kind }) => {
            println!("  backend refuses it too ({kind:?}) without spawning anything:\n    {reason}")
        }
        Ok(r) => println!(
            "  backend RAN it (exit {:?}) — the declaration floor is not holding",
            r.exit_code
        ),
        Err(e) => println!("  backend: {e}"),
    }

    // ── the round trip, on a hand-declared profile ────────────────────────────
    // What this section exists to prove is whether the inverse script puts *this phone* back,
    // and the floor above would refuse the write before it could be tested. Declaring the tier
    // here is a fixture, not a claim about the device — and the phone settles that question on
    // its own terms anyway: uid 2000 under enforcing really can write `debug.*` properties, so
    // the refusal above is policy, not physics. Per-property SELinux types are not something
    // this port probes, and a write tier granted on "some props happen to be writable" would be
    // a tier granted on luck.
    let mut grant_profile = profile.clone();
    grant_profile
        .caps
        .declare(Capability::ShellWrite.id())
        .map_err(|e| format!("cannot hand-declare the write tier: {e}"))?;
    let grant_shell: Arc<dyn ExecutionBackend> =
        Arc::new(ShellBackend::with_runner(grant_profile, transport.clone())?);
    let grant_audited: Arc<dyn ExecutionBackend> =
        Arc::new(AuditedBackend::new(grant_shell, sink.clone()));
    let roundtrip = ReversibleBackend::new(grant_audited, snapshot_dir());

    let before = read_prop(&audited, prop).await;
    println!("  {prop} before  = {before:?}");

    for value in ["harness-1", "harness-2"] {
        let script = format!("setprop {prop} {value}");
        let mut request = ExecRequest::new(Capability::ShellWrite, script.clone(), session);
        request.approval_token = Some(ApprovalToken::new("harness"));
        match roundtrip.exec(request).await {
            Ok(r) if r.succeeded() => {
                let now = read_prop(&audited, prop).await;
                println!("  wrote {value:?} -> device now holds {now:?}");
            }
            Ok(r) => println!(
                "  {script} -> exit {:?} {}",
                r.exit_code,
                r.stderr.trim().chars().take(70).collect::<String>()
            ),
            Err(e) => println!("  {script} -> {e}"),
        }
    }

    let pending = pending_for(&roundtrip, session);
    println!("  ledger holds {pending} undo(es) for this session");
    let report = roundtrip.restore(session).await;
    let after = read_prop(&audited, prop).await;
    println!(
        "  restore: {} run, {} failed -> device now holds {after:?}",
        report.restored.len(),
        report.failed.len()
    );
    for line in &report.restored {
        println!("    restored {line}");
    }
    for (target, why) in &report.failed {
        println!("    FAILED to restore {target}: {why}");
    }
    println!(
        "  {}",
        if after == before {
            format!("MATCH: back to the value it was found with ({before:?})")
        } else {
            format!(
                "MISMATCH: found {before:?}, left {after:?} — the undo does not restore this                  device, and the claim in §4.6.4 is false here"
            )
        }
    );
    println!(
        "  (a FIFO teardown would have left `harness-1`: the second capture recorded the value \
         the first write made, not the value the session found)"
    );

    // A write the device itself refuses. `persist.sys.*` is not writable by uid 2000 under
    // this enforcing policy, so the command exits 1 having changed nothing — and §4.6.4's
    // second step is precisely that the teardown must not invent a write for it. The session's
    // ledger was drained by the restore above, so anything in it now is a phantom undo.
    let doomed = "setprop persist.sys.acowork.probe 1".to_string();
    let mut request = ExecRequest::new(Capability::ShellWrite, doomed.clone(), session);
    request.approval_token = Some(ApprovalToken::new("harness"));
    let outcome = match roundtrip.exec(request).await {
        Ok(r) => format!(
            "exit {:?} {}",
            r.exit_code,
            r.stderr.trim().chars().take(58).collect::<String>()
        ),
        Err(e) => e.to_string(),
    };
    println!(
        "  refused write `{doomed}` -> {outcome}; undos this session holds afterwards: {}",
        pending_for(&roundtrip, session)
    );

    // ── a write this tier *does* allow, and cannot undo ───────────────────────
    let path = "/data/local/tmp/acowork-probe.txt";
    let write = format!("echo harness > {path}");
    let mut request = ExecRequest::new(Capability::FsOutsideApp, write.clone(), session);
    request.approval_token = Some(ApprovalToken::new("harness"));
    match gate.decide(&request, None, ready) {
        GateDecision::Allow { .. } => match chain.exec(request).await {
            Ok(r) if r.succeeded() => println!(
                "\n  gate allows `{write}` (android:fs:outside-app) -> ran, file holds {:?}",
                read_file(&audited, path).await
            ),
            Ok(r) => println!("  `{write}` -> exit {:?}", r.exit_code),
            Err(e) => println!("  `{write}` -> {e}"),
        },
        other => println!("  gate refuses `{write}`: {:?}", other.refusal()),
    }
    println!(
        "  undos the planner offered for it: {}  unundoable it named: {}",
        pending_for(&chain, session),
        chain
            .ledger()
            .lock()
            .map(|l| l.leaving_behind(session).len())
            .unwrap_or(0)
    );
    for item in chain
        .ledger()
        .lock()
        .map(|l| l.leaving_behind(session).to_vec())
        .unwrap_or_default()
    {
        println!("    {} — {}", item.command, item.why);
    }
    // The file half of §4.6.4 is not implemented, so nothing in this port can put the device
    // back. The harness cleans up with a write of its own, through the same chain, and lets it
    // land in the trail: a demo that quietly left no trace would hide the gap it exists to
    // show — and an unaccounted `rm` is exactly what §4.6.1 refuses to run.
    let _ = chain
        .exec(ExecRequest::new(
            Capability::FsOutsideApp,
            format!("rm {path}"),
            session,
        ))
        .await;
    println!(
        "  after cleanup the file reads {:?} — removed by the harness, not by the port",
        read_file(&audited, path).await
    );

    println!("\n  what the audit trail saw ({} records):", sink.len());
    for event in sink.events() {
        let outcome = match event.outcome {
            acowork_android::host::AuditOutcome::Attempted => "attempted".to_string(),
            acowork_android::host::AuditOutcome::Completed { exit_code, .. } => {
                format!("completed exit {exit_code:?}")
            }
            acowork_android::host::AuditOutcome::Refused { .. } => "refused".to_string(),
            other => format!("{other:?}")
                .split('(')
                .next()
                .unwrap_or("?")
                .to_string(),
        };
        println!(
            "    {:<22} {:<26} {}",
            event.capability,
            event.command.chars().take(26).collect::<String>(),
            outcome,
        );
    }
    Ok(())
}

/// §4.6.4's file half, run against the device: write a binary file, overwrite it, put it back.
///
/// Binary content is the point of using `\000` and `\377` rather than a text file. The exec
/// channel decodes stdout as text (`String::from_utf8_lossy`), so a file read through it is
/// *not* the file — which is why the snapshot travels as base64 and why the restore ends with a
/// digest comparison rather than a zero exit code.
async fn report_file_snapshot(
    profile: &HostProfile,
    transport: &AdbTransport,
) -> Result<(), Box<dyn Error>> {
    use std::sync::Arc;

    use acowork_android::host::ApprovalToken;

    let session = "harness-files";
    let path = "/data/local/tmp/acowork-snap.bin";
    let sink = Arc::new(MemoryAuditSink::new());
    let chain = writable_chain(profile, transport, sink.clone()).await?;
    let observer: Arc<dyn ExecutionBackend> = Arc::new(ShellBackend::with_runner(
        profile.clone(),
        transport.clone(),
    )?);

    async fn observe(shell: &Arc<dyn ExecutionBackend>, script: String) -> String {
        match shell
            .exec(ExecRequest::read(script, "harness-observer"))
            .await
        {
            Ok(r) if r.succeeded() => r.stdout.trim().to_string(),
            Ok(r) => format!("<exit {:?}: {}>", r.exit_code, r.stderr.trim()),
            Err(e) => format!("<{e}>"),
        }
    }
    async fn write(chain: &ReversibleBackend, script: &str, session: &str) -> Result<(), String> {
        // Claim what the classifier says the script actually needs, the same way §9 does: a
        // redirect is an `fs:outside-app` write, and mislabelling it is refused, not ignored.
        let claimed = acowork_android::host::classify_script(script)
            .strongest()
            .capability()
            .unwrap_or(Capability::ShellWrite);
        let mut request = ExecRequest::new(claimed, script.to_string(), session);
        request.approval_token = Some(ApprovalToken::new("harness"));
        chain
            .exec(request)
            .await
            .map(|_| ())
            .map_err(|e| format!("{e}"))
    }

    // 1. Create a file that was not there. The observed pre-state is *absence*, so the undo is
    //    a removal, not a restore.
    let create = format!("printf 'A\\000\\377\\033B' > {path}");
    write(&chain, &create, session).await?;
    let created = observe(&observer, format!("wc -c < {path}")).await;
    let created_digest = observe(&observer, format!("sha256sum < {path}")).await;
    println!(
        "  created   {path} = {created} bytes, digest {:?}",
        created_digest.split_whitespace().next().unwrap_or("")
    );
    println!(
        "  ledger after the create: {} undo(s), first is `{}`",
        pending_for(&chain, session),
        chain
            .ledger()
            .lock()
            .map(|l| l
                .pending_for(session)
                .first()
                .and_then(|u| u.inverse_script())
                .unwrap_or("<snapshot>")
                .to_string())
            .unwrap_or_default()
    );

    // 2. Overwrite it. Now the pre-state is the binary content, and the snapshot has to survive
    //    base64, the host filesystem, chunking and the shell's quoting — and be checked.
    let overwrite = format!("echo overwritten > {path}");
    write(&chain, &overwrite, session).await?;
    println!(
        "  overwrote {path} = {} bytes ({:?})",
        observe(&observer, format!("wc -c < {path}")).await,
        observe(&observer, format!("head -c 32 {path} | tr -d '\\n'")).await
    );

    let ledger = chain.ledger();
    let entries = ledger
        .lock()
        .map(|l| {
            l.pending_for(session)
                .iter()
                .map(|u| match &u.action {
                    acowork_android::host::UndoAction::Script(script) => {
                        format!("{} -> script `{script}`", u.target.describe())
                    }
                    acowork_android::host::UndoAction::Snapshot {
                        snapshot,
                        bytes,
                        digest,
                    } => format!(
                        "{} -> snapshot {} ({} device bytes, sha256 {})",
                        u.target.describe(),
                        snapshot.display(),
                        bytes,
                        digest.chars().take(12).collect::<String>()
                    ),
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    drop(ledger);
    for entry in &entries {
        println!("  pending: {entry}");
    }
    let snapshots: Vec<_> = std::fs::read_dir(snapshot_dir())
        .map(|rd| rd.flatten().map(|e| e.path()).collect())
        .unwrap_or_default();
    println!(
        "  workspace copies: {} file(s) under {}",
        snapshots.len(),
        snapshot_dir().display()
    );

    // 3. Tear the session down. LIFO again: the overwrite is undone first (the binary content
    //    comes back), then the create (the file is removed). Restoring in record order would
    //    leave the binary file sitting there after a session that created it.
    let report = chain.restore(session).await;
    println!(
        "  restore: {} applied, {} failed{}",
        report.restored.len(),
        report.failed.len(),
        if report.clean() {
            ""
        } else {
            "  <-- NOT CLEAN"
        }
    );
    for (what, why) in &report.failed {
        println!("    failed {what}: {why}");
    }
    println!(
        "  {path} after teardown: {}",
        observe(
            &observer,
            format!("test -e {path} && echo STILL_THERE || echo absent")
        )
        .await
    );
    println!(
        "  staging leftovers: {}",
        observe(
            &observer,
            "ls /data/local/tmp/.acowork-snap-* 2>/dev/null | wc -l".to_string()
        )
        .await
    );
    println!(
        "  workspace copies after a verified restore: {}",
        std::fs::read_dir(snapshot_dir())
            .map(|rd| rd.flatten().count())
            .unwrap_or(0)
    );

    // 4. More than one chunk. The budget allows a 64 KiB file, whose base64 is ~87 KiB, and the
    //    measured argument ceiling on this device is ~110 KiB — so a real restore of a real file
    //    is *always* chunked, and this is the path that has never run on hardware before.
    let chunked = "/data/local/tmp/acowork-snap-many.bin";
    let big = 60 * 1024;
    write(
        &chain,
        &format!("head -c {big} /dev/urandom > {chunked}"),
        session,
    )
    .await?;
    let big_digest = observe(&observer, format!("sha256sum < {chunked}")).await;
    // Declare the *creation* permanent, so the teardown below has exactly one job: put the
    // content back. Left in the ledger, LIFO would also undo the create and remove the file —
    // correct behaviour that would make this demonstration look like a failure.
    let kept = chain
        .ledger()
        .lock()
        .map(|mut l| {
            l.keep(
                session,
                &acowork_android::host::UndoTarget::File(chunked.to_string()),
            )
        })
        .unwrap_or(false);
    println!("  declared the create permanent (kept: {kept}) — only the content is undoable");
    write(&chain, &format!("echo squashed > {chunked}"), session).await?;
    println!(
        "  wrote a {big}-byte file (digest {:?}), then overwrote it with 9 bytes",
        big_digest.split_whitespace().next().unwrap_or("")
    );
    let report = chain.restore(session).await;
    println!(
        "  restore of the multi-chunk snapshot: {} applied, {} failed{}",
        report.restored.len(),
        report.failed.len(),
        if report.clean() {
            ""
        } else {
            "  <-- NOT CLEAN"
        }
    );
    for (what, why) in &report.failed {
        println!("    failed {what}: {why}");
    }
    let after = observe(&observer, format!("sha256sum < {chunked}")).await;
    println!(
        "  {chunked} is now {} bytes, digest {:?} — the pre-write digest was {:?}. The restore \
         reports success only when those match, so a chunk lost in transit is a failure here, \
         not a quietly short file",
        observe(&observer, format!("wc -c < {chunked}")).await,
        after.split_whitespace().next().unwrap_or("").to_string(),
        big_digest
            .split_whitespace()
            .next()
            .unwrap_or("")
            .to_string()
    );
    write(&chain, &format!("rm -f {chunked}"), session).await?;

    // 5. The refusal path, which is the half that keeps a promise this port cannot make from
    //    being made silently. A file over the snapshot budget is still written — the budget is
    //    about backups, not about permission — but the session ends by naming it.
    let big = "/data/local/tmp/acowork-snap-big.bin";
    let over = acowork_android::host::SNAPSHOT_BUDGET_BYTES + 1;
    write(
        &chain,
        &format!("head -c {over} /dev/urandom > {big}"),
        session,
    )
    .await?;
    let before = chain
        .ledger()
        .lock()
        .map(|l| l.pending_for(session).len())
        .unwrap_or(0);
    write(&chain, &format!("echo too_big > {big}"), session).await?;
    let after = chain
        .ledger()
        .lock()
        .map(|l| l.pending_for(session).len())
        .unwrap_or(0);
    let left = chain
        .ledger()
        .lock()
        .map(|l| {
            l.leaving_behind(session)
                .iter()
                .map(|u| format!("{}: {}", u.command, u.why))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    println!(
        "  a {over}-byte file: undos went {} -> {}, so the write is permanent unless declared",
        before, after
    );
    for why in left {
        println!("    left behind — {why}");
    }
    write(&chain, &format!("rm -f {big}"), session).await?;
    let report = chain.restore(session).await;
    println!(
        "  cleanup: {} applied, {} failed, {} still pending",
        report.restored.len(),
        report.failed.len(),
        report.still_pending_elsewhere
    );
    println!("  audit records for the whole file session: {}", sink.len());
    Ok(())
}

/// How many undos a session has pending, without holding the lock across an await.
fn pending_for(chain: &ReversibleBackend, session: &str) -> usize {
    chain
        .ledger()
        .lock()
        .map(|ledger| ledger.pending_for(session).len())
        .unwrap_or(0)
}
