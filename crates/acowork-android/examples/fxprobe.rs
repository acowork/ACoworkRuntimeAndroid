//! Classifier probe: feed script shapes on stdin, print what the gate would answer.
//!
//! Scratch tool for the adversarial sweep of [`acowork_android::host::commands`]. It is not a
//! test: it prints the answer for shapes nobody has decided about yet, which is how a finding
//! gets found. Anything it shows to be wrong belongs in a regression test, not here.
//!
//! ```text
//! cargo run -q -p acowork-android --example fxprobe < shapes.txt
//! ```

use acowork_android::host::commands::{classify, file_writes, words};

fn main() {
    let stdin = std::io::stdin();
    for line in stdin.lines() {
        let Ok(script) = line else { break };
        if script.trim().is_empty() || script.starts_with('#') {
            continue;
        }
        let verdict = classify(&script);
        let effect = verdict.strongest();
        let detail = verdict
            .findings
            .first()
            .map(|f| f.detail.as_str())
            .unwrap_or("");
        let detail = if detail.len() > 96 {
            let cut = detail.floor_char_boundary(96);
            format!("{}…", &detail[..cut])
        } else {
            detail.to_string()
        };
        // The ledger column is what the rollback planner would be handed, read from the same
        // lexer the gate used — not from `split_whitespace`, which would leave the shell's quote
        // characters inside the path and show a target that does not exist.
        let ledger = words(&script)
            .unwrap_or_default()
            .iter()
            .filter_map(|command| file_writes(command))
            .flatten()
            .map(|f| format!("{}:{:?}", f.path, f.change))
            .collect::<Vec<_>>()
            .join(",");
        println!("{script}\n    => {effect:?} | {}", truncate(&ledger, 90));
        println!("       {detail}");
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let cut = s.floor_char_boundary(max);
    format!("{}…", &s[..cut])
}
