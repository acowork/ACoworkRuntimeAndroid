//! `acowork-android probe` — measure the host and print the capability summary.

use acowork_android::host::{HostProfile, shell_tools};
use acowork_platform_contract::HostDescription;

use crate::session::{CommonArgs, Session};

pub async fn run(common: &CommonArgs, json: bool) -> Result<(), String> {
    let session = Session::open(common).await?;
    if json {
        let summary = session.profile.gateway_summary();
        let contract = HostDescription::summary(&session.profile);
        let body = serde_json::json!({
            "transport": session.transport.kind().to_string(),
            "gateway": summary,
            "contract": contract,
            "tools": shell_tools(&session.profile)
                .into_iter()
                .map(|t| serde_json::json!({
                    "name": t.name,
                    "description": t.description,
                }))
                .collect::<Vec<_>>(),
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&body).map_err(|e| e.to_string())?
        );
        return Ok(());
    }

    session.print_banner(&common.root);
    print_human(&session.profile);
    Ok(())
}

fn print_human(profile: &HostProfile) {
    let gw = profile.gateway_summary();
    println!();
    println!("gateway summary (ADR-AND-001 §7.1 — display only, never a gate input)");
    println!("  profile     {}", gw.profile.as_str());
    println!("  privilege   {:?}", gw.privilege);
    println!("  dialect     {}", gw.shell_dialect.unwrap_or("none"));
    println!(
        "  caps        {}",
        if gw.caps.is_empty() {
            "(none)".to_string()
        } else {
            gw.caps.join(", ")
        }
    );

    let tools = shell_tools(profile);
    if tools.is_empty() {
        println!();
        println!("tools       (none registered — apk-sandbox has no shell)");
    } else {
        println!();
        println!("tools");
        for tool in tools {
            println!("  · {} — {}", tool.name, first_line(&tool.description));
        }
    }
}

fn first_line(text: &str) -> &str {
    text.lines().next().unwrap_or(text)
}
