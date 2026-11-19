//! `acowork-android exec` — run one script through the assembled host chain.

use std::io::{IsTerminal, Write};

use acowork_android::host::{
    ApprovalToken, Effect, ExecRequest, ExecutionBackend, classify_script,
};
use acowork_platform_contract::{GateDecision, Refusal};

use crate::session::{CommonArgs, Session};

pub struct ExecArgs {
    pub common: CommonArgs,
    pub script: String,
    pub assume_yes: bool,
}

pub async fn run(args: ExecArgs) -> Result<(), String> {
    let session = Session::open(&args.common).await?;
    session.print_banner(&args.common.root);

    let verdict = classify_script(&args.script);
    let effect = verdict.strongest();
    println!("command    {}", args.script);
    println!("           classified as {effect:?}");

    let Some(capability) = effect.capability() else {
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

    let mut request =
        ExecRequest::new(capability, args.script.clone(), args.common.session.clone());
    if !effect.is_read_only() {
        let approved = if args.assume_yes {
            println!("           approved by --yes (scripted run answering for the operator)");
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

    match session.decide(&request) {
        GateDecision::Allow { .. } => {}
        GateDecision::Deny { refusal, .. } => {
            println!("           gate refused: {refusal}");
            match &refusal {
                Refusal::DangerousSessionRequired(_) => {
                    println!(
                        "           hint: re-run with --dangerous-mode (session flag; never \
                         persisted)"
                    );
                }
                Refusal::AttributionDenied { .. } => {
                    println!(
                        "           hint: this tier needs Gateway attribution (blocked on engine \
                         enrollment — see `acowork-android serve`)"
                    );
                }
                _ => {}
            }
            println!("           (nothing was sent to the device)");
            return Ok(());
        }
    }

    let record = session
        .chain
        .exec(request)
        .await
        .map_err(|e| e.to_string())?;
    println!(
        "           exit {:?} in {} ms, {} bytes{}",
        record.exit_code,
        record.duration_ms,
        record.stdout.len(),
        if record.truncated { " (TRUNCATED)" } else { "" }
    );
    for line in record.stdout.lines().take(20) {
        println!("           | {line}");
    }
    if !record.stderr.trim().is_empty() {
        for line in record.stderr.lines().take(10) {
            println!("           ! {line}");
        }
    }

    let report = session.chain.restore(&args.common.session).await;
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
        println!("           FAILED      {target}: {why}");
    }
    Ok(())
}

fn ask(script: &str, effect: Effect) -> Result<bool, String> {
    if !std::io::stdin().is_terminal() {
        return Err(format!(
            "this command changes state ({effect:?}) and there is no terminal to ask about it; \
             pass --yes only if you have read what it does: {script}"
        ));
    }
    print!("run `{script}` on the device? it is a {effect:?} — approve [y/N]: ");
    std::io::stdout().flush().map_err(|e| e.to_string())?;
    let mut answer = String::new();
    std::io::stdin()
        .read_line(&mut answer)
        .map_err(|e| e.to_string())?;
    Ok(matches!(answer.trim(), "y" | "Y" | "yes" | "YES"))
}
