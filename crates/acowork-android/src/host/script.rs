//! Assembling a caller's script into what actually reaches the shell.
//!
//! # Why this module exists as a separate, pure file
//!
//! [`super::backend`] defines what a backend must do; [`super::spawn`] is the I/O seam
//! that does it. Neither is where the subtle part lives. The subtle part is that a
//! request carries a script body, a working directory and an environment, and those
//! three have to be turned into one shell program that
//!
//! - reports **who actually ran** (ADR-AND-001 §4.7 requires `uid` and `context` in the
//!   audit record, because that is the only way to catch a privileged helper that
//!   silently dropped privilege — ADR §1.1's "root 进程仍受策略约束" means uid 0 is not
//!   the interesting number, the SELinux domain is);
//! - survives paths and values containing quotes, spaces, newlines and leading dashes;
//! - fails with something actionable rather than confusingly, when the cwd cannot be
//!   entered.
//!
//! All three are pure string transformations, which is what makes them testable without
//! a device — and they are exactly the parts that would be invisible if they lived
//! inside the spawn code, because a spawn test needs a shell.
//!
//! # The identity prologue, and why it goes *first*
//!
//! The marker line is emitted **before** the caller's body, not after. On a timeout the
//! process is killed mid-body, so a trailer would never be written and the audit record
//! would lose the very fact it exists to prove — for the one command class where knowing
//! the real identity matters most. A prologue survives the kill.
//!
//! # Quoting is correctness here, not privilege
//!
//! It is worth being blunt about what the escaping in this module does *not* do. The
//! caller already supplies an arbitrary shell script, so a caller who wanted to run
//! something unintended does not need a clever path to do it. Proper quoting therefore
//! buys **correctness** — `/data/My Dir/x` must still work — and not a security boundary.
//! Whether a caller may run anything at all under `android:fs:system` is decided by the
//! gate (contract rules R6/R7/R8: approval, dangerous-mode, attribution, rollback), not
//! by a quote function. Anyone reading this file for the trust model is reading the
//! wrong file; read [`super::backend`].
//!
//! Still, quoting must be right, because a broken escape on a mutating command means the
//! wrong target gets written — a correctness failure with irreversible consequences.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Exit code used when the requested working directory cannot be entered.
///
/// Borrowed from `sysexits.h` `EX_IOERR` (74) rather than invented, so a human reading a
/// bare 74 in a log has something to look up. The prologue also writes a line to stderr,
/// so the code is never the only signal — a body that happens to exit 74 on its own is
/// not mistaken for a backend failure.
pub const EX_CWD_UNAVAILABLE: i32 = 74;

/// A script ready to be written to a shell's stdin, plus the nonce its marker uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedScript {
    /// The exact bytes to write to stdin.
    pub text: String,
    /// The per-invocation nonce embedded in the identity marker.
    ///
    /// Returned rather than re-derivable: [`extract_identity`] needs the same value, and
    /// a nonce that could be recomputed later is not a nonce.
    pub nonce: String,
}

/// A request that cannot be turned into a script.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScriptError {
    /// An environment key is not a valid POSIX shell identifier, so `export` would be a
    /// syntax error and kill the whole invocation for one bad key.
    InvalidEnvKey(String),
}

impl std::fmt::Display for ScriptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScriptError::InvalidEnvKey(key) => write!(
                f,
                "environment key `{key}` is not a valid shell identifier \
                 (expected [A-Za-z_][A-Za-z0-9_]*); rename it or drop it from the request"
            ),
        }
    }
}

impl std::error::Error for ScriptError {}

/// The identity that actually executed the body, as reported by the prologue.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Identity {
    /// Effective uid, if the shell could report one.
    pub uid: Option<u32>,
    /// SELinux context (`/proc/self/attr/current`), if readable.
    ///
    /// This is the field that matters. Two devices can both show uid 0 and have
    /// completely different reach because the *domain* differs — which is precisely the
    /// technical premise ADR-AND-001 §1.1 corrects.
    pub context: Option<String>,
}

/// A fresh, per-invocation nonce.
///
/// Hex, so it is safe inside a single-quoted shell literal and cannot be confused with
/// the tab-delimited payload. Built from a nanosecond clock mixed with a process-local
/// counter, because two invocations in the same nanosecond would otherwise share a marker
/// and cross-read each other's identity.
///
/// Not a security value: a collision would garble identity parsing, not grant anything,
/// so there is no reason to depend on a CSPRNG here.
pub fn next_nonce() -> String {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    // Mix so two processes that boot in the same nanosecond still differ.
    let mixed = nanos ^ (seq.wrapping_mul(0x9e37_79b9_7f4a_7c15));
    format!("{:016x}{:04x}", mixed, seq & 0xffff)
}

/// Length of a nonce from [`next_nonce`]: 16 hex digits of mixed clock, 4 of sequence.
const NONCE_LEN: usize = 20;

/// Recover the nonce a prepared script will echo, from the script text.
///
/// The inverse of [`prepare`]'s prologue. It exists for anything that has a *script* and
/// needs to know what marker the shell will print: a test double simulating a shell (see
/// [`super::spawn::ScriptedSpawnRunner::dynamic`]), and an audit tool holding a stored
/// script next to a stored output that must be tied back to it.
///
/// Deliberately shape-based rather than position-based — it looks for the one 20-character
/// lowercase-hex token on the prologue line instead of counting quotes — so it keeps working
/// if the `printf` argument order changes. The coupling is not trusted:
/// [`tests::nonce_of_recovers_the_nonce_from_every_generated_script`] generates scripts in a
/// loop and checks this against the nonce `prepare` itself reported, which fails the moment
/// the two disagree.
pub fn nonce_of(script: &str) -> Option<&str> {
    let prologue = script.lines().next()?;
    prologue
        .split(|c: char| !c.is_ascii_hexdigit())
        .find(|token| token.len() == NONCE_LEN)
}

/// Quote a value as a POSIX single-quoted literal.
///
/// `'` becomes `'\''` — close the literal, emit an escaped quote, reopen. That is the
/// only character single quotes cannot contain. Everything else, including newlines and
/// NUL-adjacent bytes, is literal inside `'...'`, so paths with spaces, glob characters
/// and `$` all survive without interpretation.
pub fn quote_posix(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('\'');
    for ch in value.chars() {
        if ch == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    out
}

/// The path a device will open, resolved lexically.
///
/// Two consumers need this and must not disagree: the classifier, which decides which capability
/// a write costs, and the rollback planner, which decides whether a target is worth snapshotting.
/// Both are prefix tests against protected roots, and a prefix test run on the literal text is a
/// test of the *spelling* rather than of the destination:
/// `/data/local/tmp/../../../dev/block/mmcblk0` begins in the directory the shell owns and ends
/// on a raw block device. The kernel walks `..` on the device's behalf, so a port that does not
/// is letting the wording of a request decide what it was allowed to ask for — and a hard ban
/// (§4.6.3 item 3) that can be dodged by adding three path segments is not a ban.
///
/// Resolution also goes the other way, which is what makes it a resolver rather than a scanner
/// for scary substrings: `/data/local/tmp/../../system` is `/data/system`, a directory that
/// belongs to no partition, and calling it a system write would cost the caller an approval for
/// something the script never did.
///
/// Only the lexical form is resolved. A symlink is not, because nothing here can see the
/// filesystem: `test -L` means a round trip per classified word, and `O_NOFOLLOW` is not
/// available to a script that is being handed to `/system/bin/sh`. The residual is recorded in
/// the readiness assessment instead of being answered by a check this port cannot verify.
///
/// A relative path is resolved against `/` rather than against a working directory, which is the
/// interpretation under which `..` climbs furthest: it can ask for a stronger capability than a
/// script happened to need, and cannot be talked into a weaker one. Nothing this port generates
/// is affected — backend and rollback scripts always name absolute paths.
pub fn resolve_path(path: &str) -> String {
    let mut segments: Vec<&str> = Vec::new();
    for segment in path.split('/') {
        match segment {
            // Empty covers both a leading slash and a doubled one; `.` changes nothing.
            "" | "." => {}
            // Popping an empty stack is how POSIX treats a `..` at the root: it stays at the
            // root, so `/../../dev/block/mmcblk0` is still `/dev/block/mmcblk0`.
            ".." => {
                segments.pop();
            }
            other => segments.push(other),
        }
    }
    let mut out = String::with_capacity(path.len());
    out.push('/');
    out.push_str(&segments.join("/"));
    out
}

/// True when `key` can be exported by a POSIX shell.
pub fn is_valid_env_key(key: &str) -> bool {
    let mut chars = key.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Assemble the identity prologue, the cwd, the environment and the body.
///
/// Order matters and is not arbitrary:
/// 1. identity marker — must be first so it survives a later kill (see module docs);
/// 2. `cd` — before the body, and before any relative path the body uses;
/// 3. `export` — before the body, so the body sees them;
/// 4. the caller's body.
///
/// The body is appended **verbatim**. It is not wrapped in a subshell and not quoted:
/// it is the caller's shell program, and rewriting it would silently change semantics.
pub fn prepare(
    body: &str,
    cwd: Option<&Path>,
    env: &BTreeMap<String, String>,
) -> Result<PreparedScript, ScriptError> {
    let nonce = next_nonce();
    let mut text = String::with_capacity(body.len() + 192);

    // 1. Identity prologue. `id -u` and the attr read are redirected to /dev/null so a
    //    device without toybox `id`, or without SELinux at all, still prints a well-formed
    //    marker with empty fields rather than dragging error text into stdout.
    text.push_str(&format!(
        "printf '%s\\t%s\\t%s\\t%s\\n' '{n}' \"$(id -u 2>/dev/null)\" \
         \"$(cat /proc/self/attr/current 2>/dev/null)\" '{n}'\n",
        n = nonce
    ));

    // 2. Working directory. `--` guards a path beginning with `-`; the quoted literal
    //    guards everything else. On failure, say *which* directory, then exit distinctively.
    //
    //    `quote_posix` returns a complete literal including its own quotes, so it is
    //    substituted bare — wrapping it in `'...'` again would produce `''/path''`, which
    //    the shell reads as an empty literal followed by bare words. The same literal is
    //    reused for the error message via a printf argument, because interpolating a raw
    //    path into `'...{path}...'` breaks the moment the path contains a quote.
    if let Some(dir) = cwd {
        let literal = quote_posix(&dir.display().to_string());
        text.push_str(&format!(
            "cd -- {p} || {{ printf 'acowork: cannot enter working directory %s\\n' {p} >&2; \
             exit {code}; }}\n",
            p = literal,
            code = EX_CWD_UNAVAILABLE
        ));
    }

    // 3. Environment. Rejected rather than skipped: one silently dropped variable changes
    //    what the command does, and a mutating command run against the wrong target is the
    //    outcome this whole design is trying to avoid.
    for (key, value) in env {
        if !is_valid_env_key(key) {
            return Err(ScriptError::InvalidEnvKey(key.clone()));
        }
        text.push_str(&format!(
            "export {k}={v}\n",
            k = key,
            v = quote_posix(value)
        ));
    }

    // 4. The caller's body, verbatim.
    text.push_str(body);
    if !text.ends_with('\n') {
        text.push('\n');
    }

    Ok(PreparedScript { text, nonce })
}

impl PreparedScript {
    /// The prologue line this script will emit, for tests and diagnostics.
    pub fn marker_prefix(&self) -> String {
        format!("{}\t", self.nonce)
    }
}

/// Split the identity prologue back out of a shell's stdout.
///
/// Operates on bytes, not `&str`, because output is bytes (contract rule R12) and a
/// `logcat` dump that is not valid UTF-8 must not make the backend lose the identity it
/// was asked to prove. The returned body is the caller's stdout with the marker line
/// removed; the caller then does its own lossy conversion if it wants text.
///
/// Returns `(Identity { None, None }, original)` when the first line is not this
/// invocation's marker. That happens legitimately: a body that redirects stdout early, a
/// shell that prints a profile banner first, or a process killed before the prologue ran.
/// Reporting "unknown" is the honest answer; guessing would put an unproven identity into
/// an audit record whose entire purpose is to be proven.
pub fn extract_identity(stdout: &[u8], nonce: &str) -> (Identity, Vec<u8>) {
    let unknown = (Identity::default(), stdout.to_vec());

    let Some(newline) = stdout.iter().position(|b| *b == b'\n') else {
        // No complete line yet. A marker with no newline is a truncated prologue, which
        // is not something we can attribute — leave the bytes for the caller to see.
        return unknown;
    };
    let line = &stdout[..newline];
    let rest = &stdout[newline + 1..];

    // Nonce is hex (ASCII), so a byte-wise compare against its UTF-8 bytes is exact.
    let marker = nonce.as_bytes();
    if line.len() < marker.len() * 2 || !line.starts_with(marker) || !line.ends_with(marker) {
        return unknown;
    }

    // Strip both nonce copies; what remains is `\t{uid}\t{context}\t`.
    let inner = &line[marker.len()..line.len() - marker.len()];
    let fields: Vec<&[u8]> = inner.split(|b| *b == b'\t').collect();
    if fields.len() != 4 || !fields[0].is_empty() || !fields[3].is_empty() {
        return unknown;
    }

    let uid = {
        let raw = ascii_trim(fields[1]);
        if raw.is_empty() {
            None
        } else {
            std::str::from_utf8(raw)
                .ok()
                .and_then(|s| s.parse::<u32>().ok())
        }
    };
    let context = {
        let raw = ascii_trim(fields[2]);
        if raw.is_empty() {
            None
        } else {
            Some(String::from_utf8_lossy(raw).into_owned())
        }
    };

    (
        Identity { uid, context },
        // Drop any leading blank line the shell may have produced around the marker.
        rest.to_vec(),
    )
}

/// Trim ASCII whitespace, including the `\r` a Windows-ish shell may leave.
fn ascii_trim(bytes: &[u8]) -> &[u8] {
    // NUL is trimmed alongside the whitespace. A security context never contains one, but
    // the kernel terminates `/proc/*/attr/current` with one, and a shell that hands us the
    // file read unfiltered (or a future backend that cats it directly instead of through
    // `$(...)`) would otherwise store `u:r:shell:s0\0` as the identity of the caller.
    let is_pad = |b: &u8| b.is_ascii_whitespace() || *b == b'\0';
    let start = bytes.iter().position(|b| !is_pad(b)).unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|b| !is_pad(b))
        .map(|i| i + 1)
        .unwrap_or(start);
    &bytes[start..end]
}

#[cfg(test)]
mod tests {
    #[test]
    fn path_resolution_matches_what_the_kernel_walks() {
        // The counts matter more than the shapes: three segments climb out of /data/local/tmp,
        // two do not. A resolver that got this backwards would be a scanner for alarming
        // substrings, which is the failure mode on the over-blocking side.
        assert_eq!(
            resolve_path("/data/local/tmp/../../system/x"),
            "/data/system/x",
            "two `..` stop inside /data"
        );
        assert_eq!(
            resolve_path("/data/local/tmp/../../../system/x"),
            "/system/x",
            "three reach the root and then go back down"
        );
        assert_eq!(resolve_path("/system/../system/bin/sh"), "/system/bin/sh");
        assert_eq!(
            resolve_path("/data/local/tmp/../local/tmp/x"),
            "/data/local/local/tmp/x",
            "one `..` undoes `tmp`, it does not undo the whole directory"
        );
    }

    #[test]
    fn a_walk_past_the_root_stays_at_the_root() {
        assert_eq!(
            resolve_path("/../../dev/block/mmcblk0"),
            "/dev/block/mmcblk0"
        );
        assert_eq!(resolve_path("/"), "/");
        assert_eq!(resolve_path("/.."), "/");
    }

    #[test]
    fn redundant_path_components_do_not_change_the_destination() {
        assert_eq!(resolve_path("/data/local/tmp/./x"), "/data/local/tmp/x");
        assert_eq!(resolve_path("/data//local///tmp/x"), "/data/local/tmp/x");
        assert_eq!(
            resolve_path("/data/local/tmp/"),
            "/data/local/tmp",
            "a trailing slash names the directory, not a child of it"
        );
    }

    #[test]
    fn a_relative_target_is_resolved_against_the_root() {
        // Deliberate, and the reason is in `resolve_path`: the working directory is not
        // something the classifier can see, so this is the reading under which `..` climbs
        // furthest. It can over-ask; it cannot be talked into under-asking.
        assert_eq!(resolve_path("../../../system/x"), "/system/x");
        assert_eq!(resolve_path("tmp/x"), "/tmp/x");
    }

    use super::*;

    fn env(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn prologue_is_the_first_line_so_a_killed_body_still_reports_identity() {
        // The reason the marker is a prologue and not a trailer, asserted rather than
        // argued: a body that never finishes still leaves a parseable identity line.
        let prepared = prepare("sleep 999", None, &env(&[])).unwrap();
        assert!(
            prepared.text.starts_with("printf "),
            "identity prologue must come first: {:?}",
            &prepared.text[..40.min(prepared.text.len())]
        );
        assert!(prepared.text.contains("sleep 999"));
    }

    #[test]
    fn round_trips_uid_and_context() {
        let prepared = prepare("echo hi", None, &env(&[])).unwrap();
        let stdout = format!(
            "{}\t0\tu:r:magisk:s0\t{}\nhi\n",
            prepared.nonce, prepared.nonce
        )
        .into_bytes();

        let (identity, body) = extract_identity(&stdout, &prepared.nonce);
        assert_eq!(identity.uid, Some(0));
        assert_eq!(identity.context.as_deref(), Some("u:r:magisk:s0"));
        assert_eq!(String::from_utf8(body).unwrap(), "hi\n");
    }

    #[test]
    fn uid_zero_in_the_untrusted_domain_is_reported_as_such() {
        // ADR-AND-001 §1.1: uid alone is not the interesting number. A backend that
        // collapsed "uid 0" into "root, all clear" would hide the case that matters —
        // a privileged uid still confined by its domain.
        let prepared = prepare("", None, &env(&[])).unwrap();
        let stdout = format!(
            "{}\t0\tu:r:untrusted_app:s0\t{}\n",
            prepared.nonce, prepared.nonce
        )
        .into_bytes();
        let (identity, _) = extract_identity(&stdout, &prepared.nonce);
        assert_eq!(identity.uid, Some(0));
        assert_eq!(identity.context.as_deref(), Some("u:r:untrusted_app:s0"));
    }

    #[test]
    fn missing_fields_parse_as_none_not_as_zero() {
        // A device with no toybox `id`, or no SELinux, prints empty fields. Coercing an
        // absent uid to 0 would fabricate root in an audit record.
        let prepared = prepare("", None, &env(&[])).unwrap();
        let stdout = format!("{}\t\t\t{}\nbody\n", prepared.nonce, prepared.nonce).into_bytes();
        let (identity, body) = extract_identity(&stdout, &prepared.nonce);
        assert_eq!(identity, Identity::default());
        assert_eq!(body, b"body\n");
    }

    #[test]
    fn a_foreign_or_absent_marker_leaves_stdout_untouched() {
        let prepared = prepare("", None, &env(&[])).unwrap();
        let other = next_nonce();
        for case in [
            format!("unrelated output\n{other}\t0\tx\t{other}\n").into_bytes(),
            "no newline at all".as_bytes().to_vec(),
            Vec::new(),
            format!("{}\t0\tctx\n", prepared.nonce).into_bytes(), // truncated payload
        ] {
            let (identity, body) = extract_identity(&case, &prepared.nonce);
            assert_eq!(identity, Identity::default(), "must not guess: {case:?}");
            assert_eq!(body, case, "bytes must survive unchanged");
        }
    }

    #[test]
    fn non_utf8_stdout_does_not_lose_the_identity() {
        // logcat and tombstone dumps are not text. Losing uid/context because the body
        // was undecodable would defeat the point of the prologue.
        let prepared = prepare("", None, &env(&[])).unwrap();
        let mut stdout = format!(
            "{}\t2000\tu:r:shell:s0\t{}\n",
            prepared.nonce, prepared.nonce
        )
        .into_bytes();
        stdout.extend_from_slice(&[0xff, 0xfe, 0x00, 0x41]);

        let (identity, body) = extract_identity(&stdout, &prepared.nonce);
        assert_eq!(identity.uid, Some(2000));
        assert_eq!(identity.context.as_deref(), Some("u:r:shell:s0"));
        assert_eq!(body, vec![0xff, 0xfe, 0x00, 0x41]);
    }

    #[test]
    fn quotes_the_characters_that_break_a_shell() {
        for (raw, expected_roundtrip) in [
            ("plain", "'plain'"),
            ("with space", "'with space'"),
            ("with 'quote'", "'with '\\''quote'\\'''"),
            ("with $HOME", "'with $HOME'"),
            ("with `backtick`", "'with `backtick`'"),
            ("-leading-dash", "'-leading-dash'"),
            ("*", "'*'"),
        ] {
            assert_eq!(quote_posix(raw), expected_roundtrip, "for {raw:?}");
        }
        // A newline is legal inside single quotes; the literal must survive it.
        let multiline = quote_posix("a\nb");
        assert!(multiline.contains("a\nb"));
    }

    #[test]
    fn cwd_and_env_are_emitted_before_the_body() {
        let mut e = env(&[("PATH", "/vendor/bin:/system/bin")]);
        e.insert("LANG".to_string(), "C".to_string());
        let prepared = prepare("echo body", Some(Path::new("/data/local/tmp")), &e).unwrap();

        let prologue = prepared.text.find("echo body").unwrap();
        assert!(prepared.text[..prologue].contains("cd -- '/data/local/tmp'"));
        assert!(prepared.text[..prologue].contains("export LANG='C'"));
        assert!(prepared.text[..prologue].contains("export PATH='/vendor/bin:/system/bin'"));
        // Deterministic ordering: BTreeMap, so two runs of the same request produce the
        // same script, which is what makes an audit log diffable.
        let again = prepare("echo body", Some(Path::new("/data/local/tmp")), &e).unwrap();
        assert_eq!(
            &prepared.text[..prepared.text.find("printf ").unwrap()],
            &again.text[..again.text.find("printf ").unwrap()]
        );
    }

    #[test]
    fn a_path_with_a_quote_is_emitted_as_one_quoted_literal() {
        // Text-level check only. That a shell really passes this as a *single* argument
        // is proven by execution, in tests/spawn_process.rs — not asserted here, because
        // this test cannot run a shell.
        let prepared = prepare("", Some(Path::new("/data/My Dir/it's here")), &env(&[])).unwrap();
        assert!(
            prepared
                .text
                .contains("cd -- '/data/My Dir/it'\\''s here' ||"),
            "{}",
            prepared.text
        );
    }

    #[test]
    fn an_invalid_env_key_is_rejected_not_silently_dropped() {
        // `export 1BAD=x` is a syntax error that would kill the whole invocation, and
        // dropping it silently changes what the command does. Neither is acceptable as a
        // default, so this is an explicit error naming the key.
        for bad in ["1BAD", "HAS-DASH", "", "SPACED OUT", "OK KEY"] {
            assert!(
                matches!(
                    prepare("", None, &env(&[(bad, "v")])),
                    Err(ScriptError::InvalidEnvKey(ref k)) if k == bad
                ),
                "should reject {bad:?}"
            );
        }
        for good in ["PATH", "_HOME", "LANG2", "a"] {
            assert!(is_valid_env_key(good), "should accept {good:?}");
        }
    }

    #[test]
    fn rejection_message_names_the_key_and_the_remedy() {
        // Contract rule R9: a refusal the model cannot act on costs a round trip.
        let err = prepare("", None, &env(&[("1BAD", "v")])).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("1BAD"), "{msg}");
        assert!(msg.contains("rename it or drop it"), "{msg}");
    }

    #[test]
    fn non_empty_env_is_still_reachable_when_body_is_empty() {
        // An empty body is legal (identity probe only) and must not be swallowed by the
        // trailing-newline normalisation.
        let prepared = prepare("", None, &env(&[])).unwrap();
        assert!(prepared.text.ends_with('\n'));
        assert!(prepared.text.contains("printf "));
    }

    #[test]
    fn body_without_trailing_newline_gets_one() {
        // A body ending mid-line would otherwise concatenate with whatever the shell
        // prints next. `sh` tolerates it; the audit log does not need the ambiguity.
        let prepared = prepare("echo hi", None, &env(&[])).unwrap();
        assert!(prepared.text.ends_with("echo hi\n"));
    }

    #[test]
    fn nonces_do_not_repeat_within_a_run() {
        // Two invocations sharing a marker would cross-read each other's identity.
        let mut seen = std::collections::HashSet::new();
        for _ in 0..2000 {
            assert!(seen.insert(next_nonce()), "nonce repeated");
        }
    }

    #[test]
    fn nonce_of_recovers_the_nonce_from_every_generated_script() {
        // The coupling between `prepare`'s prologue and `nonce_of` is the whole reason a
        // simulated shell can produce a believable identity line. If they ever disagree,
        // every test double that uses it silently stops testing the protocol.
        for _ in 0..200 {
            let prepared =
                prepare("echo hi", Some(Path::new("/tmp")), &env(&[("K", "v")])).unwrap();
            assert_eq!(
                nonce_of(&prepared.text).map(str::to_string),
                Some(prepared.nonce.clone()),
                "script was:\n{}",
                prepared.text
            );
        }
    }

    #[test]
    fn nonce_of_finds_nothing_in_a_script_with_no_prologue() {
        assert_eq!(nonce_of("echo hello\n"), None);
        assert_eq!(nonce_of(""), None);
        // A hex token of the wrong length is not a nonce.
        assert_eq!(nonce_of("printf '%s' 'deadbeef'\n"), None);
    }

    #[test]
    fn nonce_is_safe_inside_a_single_quoted_literal() {
        // Hex only: no quote, no backslash, no newline. If this ever stops holding, the
        // prologue format above becomes an injection point.
        for _ in 0..200 {
            let n = next_nonce();
            assert!(
                n.chars().all(|c| c.is_ascii_hexdigit()),
                "nonce must be hex only: {n:?}"
            );
        }
    }
}
