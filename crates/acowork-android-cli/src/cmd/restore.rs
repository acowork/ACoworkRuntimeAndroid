//! `acowork-android restore` — undo writes still on *this process's* session ledger.
//!
//! The rollback ledger is in memory (see `host/rollback.rs`). A fresh CLI process has an empty
//! ledger even when snapshot files remain under the workspace — so this subcommand is meaningful
//! inside a long-lived session (`serve`, once enrollment lands), and otherwise explains that.

use acowork_android::host::HostConfig;

use crate::session::{CommonArgs, Session};

pub async fn run(common: &CommonArgs) -> Result<(), String> {
    let session = Session::open(common).await?;
    session.print_banner(&common.root);

    let pending = session
        .chain
        .ledger()
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .pending_for(&common.session)
        .len();

    if pending == 0 {
        let snapshots = HostConfig::defaults().storage.snapshot_dir(&common.root);
        println!(
            "restore    nothing pending in this process for session `{}`",
            common.session
        );
        println!(
            "           the ledger is process-local: a previous `exec` that already restored \
             (the default), or a different process, leaves this one empty"
        );
        println!(
            "           snapshot files (if any) live under {}",
            snapshots.display()
        );
        return Ok(());
    }

    let report = session.chain.restore(&common.session).await;
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
