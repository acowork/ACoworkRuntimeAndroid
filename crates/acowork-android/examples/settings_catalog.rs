//! Print the settings screen's rows as a markdown table.
//!
//! The settings document is described twice — once as Rust types in
//! [`acowork_android::host::config`], once as prose in `docs/design/zh/android-runtime-settings.md`
//! — and prose written by hand goes stale. This example regenerates the table from
//! [`catalog`](acowork_android::host::catalog::catalog), so the document can be refreshed with one
//! command instead of remembered:
//!
//! ```text
//! cargo run -q -p acowork-android --example settings_catalog
//! ```
//!
//! The row list itself is already pinned to the document by tests in `catalog.rs`; this is the
//! same information for a reader who is not going to run a test.

use acowork_android::host::{SettingKind, catalog};

/// A byte count in the unit a person would actually read.
fn bytes(n: u64) -> String {
    const KIB: u64 = 1024;
    if n >= 1024 * KIB && n % (1024 * KIB) == 0 {
        format!("{} MiB", n / (1024 * KIB))
    } else if n >= KIB && n % KIB == 0 {
        format!("{} KiB", n / KIB)
    } else {
        format!("{n} B")
    }
}

/// The range a control offers, in the same unit as its default.
fn range(kind: &SettingKind) -> String {
    match kind {
        SettingKind::Bytes { min, max } => format!("{} – {}", bytes(*min), bytes(*max)),
        SettingKind::Seconds { min, max } => format!("{min} – {max} s"),
        SettingKind::Lines { max } => format!("0 – {max}"),
        SettingKind::Toggle => "on / off".to_string(),
        SettingKind::Subdirectory => "a directory name".to_string(),
        SettingKind::CapabilityList => "a list of capability ids".to_string(),
    }
}

/// The default, in the unit the range uses.
fn default(kind: &SettingKind, raw: &str) -> String {
    match kind {
        SettingKind::Bytes { .. } => raw
            .parse::<u64>()
            .map(bytes)
            .unwrap_or_else(|_| raw.to_string()),
        _ => raw.to_string(),
    }
}

fn main() {
    println!("| 设置项 | 默认 | 可设范围 | 说明 |");
    println!("|---|---|---|---|");
    let rows = catalog();
    let mut group: Option<acowork_android::host::SettingGroup> = None;
    for row in &rows {
        if Some(row.group) != group {
            group = Some(row.group);
            println!("| **{}** | | | |", section(row.group));
        }
        println!(
            "| `{}` | {} | {} | {} |",
            row.id,
            default(&row.kind, &row.default),
            range(&row.kind),
            row.help.replace('\n', " ")
        );
    }
    println!();
    println!(
        "共 {} 行。本表由 `cargo run -q -p acowork-android --example settings_catalog` 生成，\
         「说明」列是代码里的原文，APK 按 `id` 本地化。行集合与 `HostConfig` 的字段集合由测试钉在\
         一起（`catalog.rs::the_document_and_the_screen_have_the_same_rows`）；默认值是从活的文档里\
         读回来的，可设范围与 `HostConfig::validate` 用的是同一组常量，所以这张表不可能和运行时的\
         实际值不一致。",
        rows.len()
    );
}

fn section(group: acowork_android::host::SettingGroup) -> &'static str {
    use acowork_android::host::SettingGroup;
    match group {
        SettingGroup::Storage => "运行时自己的文件",
        SettingGroup::Budgets => "容量上限",
        SettingGroup::Timing => "时间上限",
        SettingGroup::Evidence => "可执行的证据采集",
        SettingGroup::Capabilities => "允许被请求的能力",
    }
}
