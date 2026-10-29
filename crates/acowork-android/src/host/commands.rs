//! What a script *actually does*, as separate evidence from what it *claims*.
//!
//! # Why this exists
//!
//! ADR-AND-001 §4.4 gives `android:shell:read` the default **"白名单自动放行"** — no approval
//! round trip — precisely because the commands under it cannot change the device. Nothing
//! checked that claim: [`ExecRequest::read`](super::backend::ExecRequest::read) is a
//! self-declaration, so a request labelled `read` that ran `setprop` or
//! `mount -o remount,rw /system` passed the gate with no human ever seeing it. The auto-pass
//! had been implemented as trust in the label rather than as a property of the content — the
//! opposite of what §4.4 decided.
//!
//! This module reads the content. It answers one question — which capability would running
//! this script actually exercise — and the port refuses when that answer and the label
//! disagree.
//!
//! # Fail closed
//!
//! The classifier is a guard, not a shell. Anything it cannot account for is
//! [`Effect::Opaque`], which is refused rather than allowed:
//!
//! - nested execution (`sh -c '…'`, `eval`, `xargs`, `$(…)`) hides a second parse inside the
//!   first, and a guard that re-parses nested text has two surfaces to get wrong;
//! - control flow (`if`, `for`, `case`) can run a command on a path the text never shows;
//! - a command word that is on neither list is unknown, not benign.
//!
//! The cost of this bias is that some harmless scripts get refused and must be split or
//! re-labelled. The cost of the opposite bias is one `rm -rf /data` getting through. Those
//! are not symmetric: the device is a phone someone is using, and the approval round trip
//! §4.4 puts on the write tier is cheap.
//!
//! # One capability per request
//!
//! A script containing both a `setprop` and a file write exercises two capabilities, and
//! [`ExecRecord`](super::backend::ExecRecord) attributes one run to one capability — the
//! audit record §4.6 item 1 asks for. Rather than invent a compound grant, the port refuses
//! and names both. A caller told "this needs `android:fs:system` for the `mount`, which your
//! `android:shell:read` does not cover" has something to act on; a port that silently
//! promoted the request would hide the escalation from the human approving it.
//!
//! Over-claiming is allowed: a request labelled `shell:write` that only reads is refused
//! nowhere, because the dangerous direction is under-claiming. The cost of over-claiming
//! falls on the caller, who spends an approval they did not need.
//!
//! # What this is not
//!
//! It is not a sandbox. A caller holding an approved write capability can still do damage;
//! [`Capability`] and the gate are what bound that. This module's job is narrower: keep the
//! cheap unattended read tier cheap and unattended, and make the tiers that need a human
//! unreachable by choosing a label.

use serde::{Deserialize, Serialize};

use crate::host::capability::Capability;

/// What running one command would do to the device.
///
/// The ordering is by how much damage is possible, and [`Verdict::strongest`] uses it to
/// pick the effect a request must be authorised for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Effect {
    /// Reads state. Covered by `android:shell:read`, auto-passed by §4.4.
    ReadOnly,
    /// Changes device state through a system service: `setprop`, `am`, `pm`, `input`.
    ShellWrite,
    /// Creates or modifies a file outside the app's own directory.
    FileWrite,
    /// Touches a mounted partition or a block device: `mount -o remount`, writes under
    /// `/system`.
    SystemWrite,
    /// Changes the SELinux mode, which the ADR gates separately from either.
    SelinuxChange,
    /// Cannot be analysed: nested execution, control flow, an unknown command word.
    Opaque,
    /// Refused outright by §4.6.3 item 3, regardless of tier or dangerous mode.
    Banned,
}

impl Effect {
    /// The capability that authorises this effect.
    ///
    /// `None` for the two effects no capability authorises: [`Effect::Opaque`], because
    /// nobody can authorise an unknown, and [`Effect::Banned`], because §4.6.3 removes it
    /// from the authorisable set — "a human and a device fingerprint match, even in
    /// dangerous mode" is not something a capability grant expresses.
    pub fn capability(self) -> Option<Capability> {
        match self {
            Effect::ReadOnly => Some(Capability::ShellRead),
            Effect::ShellWrite => Some(Capability::ShellWrite),
            Effect::FileWrite => Some(Capability::FsOutsideApp),
            Effect::SystemWrite => Some(Capability::FsSystem),
            Effect::SelinuxChange => Some(Capability::SelinuxPermissive),
            Effect::Opaque | Effect::Banned => None,
        }
    }

    /// True when nothing is modified. This is the entire content of the auto-pass rule.
    pub fn is_read_only(self) -> bool {
        matches!(self, Effect::ReadOnly)
    }
}

/// One command found in a script, with the reason it got the effect it got.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// The command word, normalised: quotes removed, `/system/bin/logcat` → `logcat`.
    pub command: String,
    /// What it does.
    pub effect: Effect,
    /// Why — `-c clears the log buffer`, `redirected to /data/local/tmp/x`. This reaches
    /// the caller, so contract rule R9 applies: name the condition *and* the next step.
    pub detail: String,
}

impl Finding {
    fn new(command: impl Into<String>, effect: Effect, detail: impl Into<String>) -> Finding {
        Finding {
            command: command.into(),
            effect,
            detail: detail.into(),
        }
    }

    fn opaque(command: impl Into<String>, detail: impl Into<String>) -> Finding {
        Finding::new(command, Effect::Opaque, detail)
    }
}

/// Everything a script was found to contain.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Verdict {
    /// One entry per command word, in the order they appear.
    pub findings: Vec<Finding>,
}

impl Verdict {
    /// The effect the request must be authorised for: the most demanding effect found.
    ///
    /// A script that is only comments, or only variable assignments, has no findings and is
    /// read-only — it does nothing to the device.
    pub fn strongest(&self) -> Effect {
        self.findings
            .iter()
            .map(|f| f.effect)
            .max()
            .unwrap_or(Effect::ReadOnly)
    }

    /// True when every command found is read-only.
    pub fn is_read_only(&self) -> bool {
        self.findings.iter().all(|f| f.effect.is_read_only())
    }

    /// The first finding whose effect is not `expected` — the one to name in a refusal.
    pub fn offending(&self, expected: Effect) -> Option<&Finding> {
        self.findings.iter().find(|f| f.effect != expected)
    }

    /// Why this script is refused, or `None` when the claimed capability covers it.
    ///
    /// `claimed` is `None` when the request names a capability outside this port's
    /// vocabulary; that is the gate's problem under rule R5, not this one's, so no verdict
    /// is offered here rather than a second, different refusal for the same request.
    pub fn refusal_for(&self, claimed: Option<Capability>) -> Option<Refusal> {
        let strongest = self.strongest();
        let named = |effect: Effect| self.findings.iter().find(|f| f.effect == effect);

        match strongest {
            Effect::Banned => named(Effect::Banned).map(|f| Refusal::Banned {
                command: f.command.clone(),
                why: f.detail.clone(),
            }),
            Effect::Opaque => named(Effect::Opaque).map(|f| Refusal::Opaque {
                command: f.command.clone(),
                why: f.detail.clone(),
            }),
            // Nothing is modified. Also covers over-claiming: a write label on a read
            // script spends an approval and harms nobody.
            Effect::ReadOnly => None,
            other => {
                let claim = claimed.and_then(effect_of_capability)?;
                // Coverage is the ordering, not capability equality: a `shell:write` label
                // does authorise the reads that come with it, so comparing capabilities for
                // equality would name `getprop` as the offender in a correctly labelled
                // write request.
                if other <= claim {
                    return None;
                }
                // Name the first command the claim does not cover — that is the one the
                // caller has to move or re-label.
                let offender = self
                    .findings
                    .iter()
                    .find(|f| f.effect > claim)
                    .or_else(|| self.findings.first())?;
                Some(Refusal::Mismatch {
                    command: offender.command.clone(),
                    why: offender.detail.clone(),
                    claimed: claim.capability()?,
                    needed: other.capability()?,
                })
            }
        }
    }
}

/// The effect a capability authorises — the inverse of [`Effect::capability`], and the
/// yardstick [`Verdict::refusal_for`] measures a claim against.
fn effect_of_capability(capability: Capability) -> Option<Effect> {
    match capability {
        Capability::ShellRead => Some(Effect::ReadOnly),
        Capability::ShellWrite => Some(Effect::ShellWrite),
        Capability::FsOutsideApp => Some(Effect::FileWrite),
        Capability::FsSystem => Some(Effect::SystemWrite),
        Capability::SelinuxPermissive => Some(Effect::SelinuxChange),
    }
}

/// A script the port will not run under the capability it was claimed with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// §4.6.3 item 3. Not authorisable by raising a tier.
    Banned {
        /// The command that triggered the ban, as found in the script.
        command: String,
        /// Which §4.6.3 rule it hits, in the caller's terms.
        why: String,
    },
    /// The port cannot tell what the script does.
    Opaque {
        /// The construct that could not be analysed.
        command: String,
        /// Why it is unanalysable, and what to write instead.
        why: String,
    },
    /// The label is weaker than the content.
    Mismatch {
        /// The command that needs more than was claimed.
        command: String,
        /// What that command does.
        why: String,
        /// The capability the request was labelled with.
        claimed: Capability,
        /// The capability the content actually exercises.
        needed: Capability,
    },
}

/// Which rule refused, as a countable value.
///
/// [`Refusal`] itself is a message: its whole design is R9's "say what is missing and what
/// to do next", which is right for a caller reading one refusal and wrong for a log that
/// has to answer "how many people tried to brick this device this week". The audit trail
/// (§4.6.1) needs the *category*, and the categories are not interchangeable:
///
/// - [`RefusalKind::Banned`] is someone reaching for a §4.6.3 hard-banned operation. It is
///   not fixable by re-sending with a higher capability, so it is the one worth alerting on.
/// - [`RefusalKind::Mismatch`] is a mislabel — usually the model guessing the wrong tier,
///   and the expected outcome of a re-send under the capability the refusal names.
/// - [`RefusalKind::Opaque`] is a limitation of the classifier, i.e. ours, not theirs.
///
/// Kept separate from `Refusal` rather than derived from it at read time, because the log
/// outlives any wording change to the messages, and a log entry that has to re-parse English
/// to be counted is not a log entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RefusalKind {
    /// §4.6.3 hard ban: no capability authorises this.
    Banned,
    /// The label is weaker than the script's content.
    Mismatch,
    /// The content could not be analysed, so it was not allowed.
    Opaque,
    /// The capability was never declared on this device (§4.2), so nothing labelled with it
    /// can run here whatever it contains. Not a content verdict — the label may match the
    /// script exactly. It is the device that cannot hold the label, which is why it is counted
    /// separately: a log full of `mismatch` says the model is guessing tiers, a log full of
    /// `undeclared` says something is driving a backend past the gate.
    Undeclared,
}

impl Refusal {
    /// The category of this refusal, for the audit trail.
    pub fn kind(&self) -> RefusalKind {
        match self {
            Refusal::Banned { .. } => RefusalKind::Banned,
            Refusal::Mismatch { .. } => RefusalKind::Mismatch,
            Refusal::Opaque { .. } => RefusalKind::Opaque,
        }
    }
}

impl core::fmt::Display for Refusal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // R9: a refusal names the missing condition and the next step. Each arm below is
        // written so the caller can act without re-reading this module.
        match self {
            Refusal::Banned { command, why } => write!(
                f,
                "`{command}` is not runnable at any tier: {why}. This needs a human \
                 operating the device directly."
            ),
            Refusal::Opaque { command, why } => write!(
                f,
                "`{command}` cannot be classified: {why}. Split the script so each command \
                 is its own request, or use a command the host profile lists."
            ),
            Refusal::Mismatch {
                command,
                why,
                claimed,
                needed,
            } => write!(
                f,
                "this request is labelled `{}` but `{command}` {why}, which needs `{}`. \
                 Re-send it under `{}` (approval required) or drop that command from the \
                 script.",
                claimed.id(),
                needed.id(),
                needed.id()
            ),
        }
    }
}

impl std::error::Error for Refusal {}

/// Classify a script body.
///
/// Never fails and never panics: a script that cannot be analysed yields a verdict whose
/// strongest effect is [`Effect::Opaque`], which the caller turns into a refusal.
pub fn classify(script: &str) -> Verdict {
    Verdict {
        findings: match lex(script).and_then(split) {
            Ok(commands) => commands.iter().map(analyse).collect(),
            Err(opaque) => vec![opaque],
        },
    }
}

/// The script's commands as the argument vectors the shell would pass them.
///
/// `None` means the script could not be split at all — backgrounding, a subshell, a command
/// substitution. That is deliberately not the same as `Some(vec![])`: a caller that wants to
/// reason about *arguments* (the rollback planner, which has to know which prop a `setprop`
/// names) must not read "unanalysable" as "nothing to undo here".
///
/// This exists because the classifier throws the arguments away. `Finding` records the command
/// word and the reason for its effect, which is all a tier decision needs and none of what an
/// inverse needs. Re-implementing the lexer next to it would guarantee the two disagree about
/// what `setprop a 'b c'` is, and the disagreement would surface as a rollback that restores
/// the wrong value.
pub fn words(script: &str) -> Option<Vec<Vec<String>>> {
    Some(
        parsed(script)?
            .into_iter()
            .map(|command| command.words)
            .collect(),
    )
}

/// One command of a script: its words, and the file its output goes to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedCommand {
    /// Every word, in shell order, including the command word and any leading `NAME=value`.
    pub words: Vec<String>,
    /// The file this command redirects output into, when it writes one.
    ///
    /// `/dev/null` and descriptor duplication (`>&1`, `2>&1`) are `None`: neither leaves
    /// anything where a later reader can find it, so neither has a previous state to restore.
    pub redirect: Option<String>,
}

/// The script's commands *and* their redirections.
///
/// [`words`] alone is not enough for a rollback planner: `echo x > /data/local/tmp/hosts`
/// changes a file that appears nowhere in the argument vector, and a planner that cannot see
/// the target cannot snapshot it. The redirection is read from the same `Command` the
/// classifier used, so the tier decision and the rollback decision cannot disagree about
/// which file a script touched.
pub fn parsed(script: &str) -> Option<Vec<ParsedCommand>> {
    let commands = lex(script).and_then(split).ok()?;
    Some(
        commands
            .into_iter()
            .map(|command| ParsedCommand {
                redirect: command.writes().map(str::to_string),
                words: command.words,
            })
            .collect(),
    )
}

/// Classify and check the claim in one step.
pub fn check(script: &str, claimed: Option<Capability>) -> Result<Verdict, Refusal> {
    let verdict = classify(script);
    match verdict.refusal_for(claimed) {
        Some(refusal) => Err(refusal),
        None => Ok(verdict),
    }
}

// ── Lexing ───────────────────────────────────────────────────────────────────

/// A token of script text, already reduced to what matters for classification.
#[derive(Debug, PartialEq, Eq)]
enum Tok {
    Word(String),
    /// `;`, a newline, `|`, `||`, or `&&` — ends the current command.
    Break,
    /// `>` or `>>` with its target attached.
    Out {
        target: String,
    },
}

fn lex(script: &str) -> Result<Vec<Tok>, Finding> {
    let mut toks: Vec<Tok> = Vec::new();
    let mut chars = script.chars().peekable();

    while let Some(c) = chars.peek().copied() {
        match c {
            c if c.is_whitespace() => {
                chars.next();
            }
            ';' | '\n' | '|' => {
                chars.next();
                if chars.peek().copied() == Some('|') {
                    chars.next();
                }
                toks.push(Tok::Break);
            }
            '&' => {
                chars.next();
                if chars.peek().copied() == Some('&') {
                    chars.next();
                    toks.push(Tok::Break);
                } else {
                    return Err(Finding::opaque(
                        "&",
                        "backgrounding (`cmd &`) is not analysable: the command outlives the \
                         invocation that started it, so neither the timeout nor the exit \
                         status describes it",
                    ));
                }
            }
            '<' => {
                chars.next();
                if eat_char(&mut chars, '<') {
                    return Err(Finding::opaque(
                        "<<",
                        "a here-document body is not read by this classifier, so whatever is \
                         fed to the command stays unseen",
                    ));
                }
                // Input redirection reads a file. It changes nothing; the command's own
                // effect is what matters.
                skip_space(&mut chars);
                word(&mut chars)?;
            }
            '>' => {
                chars.next();
                eat_char(&mut chars, '>'); // `>` and `>>` both write
                // `> file` and `>file` are the same redirection; without skipping the space
                // the target reads as empty and every script that logs to a file is refused.
                skip_space(&mut chars);
                // `>&1` and `2>&1` duplicate a descriptor rather than naming a file, and
                // `&` also starts the `&>` form. Read it as part of the target so the
                // caller's `2>&1` is not mistaken for a redirection with no destination.
                let fd = eat_char(&mut chars, '&');
                let mut target = word(&mut chars)?;
                if fd {
                    target.insert(0, '&');
                }
                if target.is_empty() {
                    return Err(Finding::opaque(
                        ">",
                        "a redirection with no target cannot be classified",
                    ));
                }
                toks.push(Tok::Out { target });
            }
            '#' => {
                // A comment runs to the end of the line and cannot execute.
                for next in chars.by_ref() {
                    if next == '\n' {
                        break;
                    }
                }
            }
            '(' | ')' | '{' | '}' => {
                return Err(Finding::opaque(
                    c.to_string(),
                    "subshells and brace groups are not analysed; run the inner command as \
                     its own request so it can be classified",
                ));
            }
            // Anything else starts a word, including `$(` and backquotes, which `word`
            // refuses when it meets them.
            _ => {
                let w = word(&mut chars)?;
                if !w.is_empty() {
                    toks.push(Tok::Word(w));
                }
            }
        }
    }
    Ok(toks)
}

fn skip_space<I: Iterator<Item = char>>(chars: &mut std::iter::Peekable<I>) {
    while chars
        .peek()
        .is_some_and(|c| c.is_whitespace() && *c != '\n')
    {
        chars.next();
    }
}

/// Consume one more `c` if it immediately follows, reporting whether it did (`>=`, `>>`).
fn eat_char<I: Iterator<Item = char>>(chars: &mut std::iter::Peekable<I>, c: char) -> bool {
    if chars.peek().copied() == Some(c) {
        chars.next();
        true
    } else {
        false
    }
}

/// Read one word, honouring quotes inside it. `a'b"c"` is one word: `abc"c`… as POSIX has
/// it — the important property is that a quoted argument containing `;` or a path with a
/// space does not break the segment apart.
fn word<I: Iterator<Item = char>>(chars: &mut std::iter::Peekable<I>) -> Result<String, Finding> {
    let mut out = String::new();
    while let Some(c) = chars.peek().copied() {
        match c {
            '\'' | '"' => {
                chars.next();
                out.push_str(&quoted(chars, c)?);
            }
            c if c.is_whitespace() => break,
            ';' | '|' | '&' | '<' | '>' => break,
            '$' => {
                chars.next();
                if chars.peek().copied() == Some('(') {
                    return Err(Finding::opaque(
                        "$()",
                        "command substitution runs a second command the classifier never \
                         sees; run it as its own request",
                    ));
                }
                if chars.peek().copied() == Some('{') {
                    // `${VAR}` — the value is not known here. Kept as text: a *head* word
                    // containing it is refused by name in `analyse`.
                    out.push_str("${");
                    chars.next();
                } else {
                    out.push('$');
                }
            }
            '\\' => {
                // Outside quotes a backslash escapes the next character. This is not
                // decoration: `quote_posix` emits `'\''` for an apostrophe inside a
                // single-quoted argument, and the classifier has to read the script text
                // the port itself assembles.
                chars.next();
                match chars.next() {
                    Some(escaped) => out.push(escaped),
                    None => out.push('\\'),
                }
            }
            '`' => {
                return Err(Finding::opaque(
                    "`",
                    "backquote substitution runs a second command the classifier never sees",
                ));
            }
            '(' | ')' | '{' | '}' => break,
            c => {
                chars.next();
                out.push(c);
            }
        }
    }
    Ok(out)
}

/// Read to the matching close quote and return the contents.
///
/// Inside double quotes a backslash escapes `"`, `\`, `$` and `` ` ``; inside single quotes
/// there are no escapes, which is exactly why [`quote_posix`](super::script::quote_posix)
/// wraps arguments in them.
fn quoted<I: Iterator<Item = char>>(
    chars: &mut std::iter::Peekable<I>,
    quote: char,
) -> Result<String, Finding> {
    let kind = if quote == '\'' { "single" } else { "double" };
    let mut body = String::new();
    loop {
        let Some(c) = chars.next() else {
            return Err(Finding::opaque(
                "quote",
                format!("unterminated {kind}quote — the classifier will not guess where it ends"),
            ));
        };
        if c == quote {
            return Ok(body);
        }
        if c == '\\' && quote == '"' {
            match chars.next() {
                Some(escaped @ ('"' | '\\' | '$' | '`')) => body.push(escaped),
                Some(other) => {
                    body.push('\\');
                    body.push(other);
                }
                None => {
                    return Err(Finding::opaque(
                        "quote",
                        "a double quote ending after a backslash is not parseable",
                    ));
                }
            }
            continue;
        }
        body.push(c);
    }
}

/// Group tokens into commands.
fn split(toks: Vec<Tok>) -> Result<Vec<Command>, Finding> {
    let mut commands = Vec::new();
    let mut words: Vec<String> = Vec::new();
    let mut output_to: Option<String> = None;

    let mut flush = |words: &mut Vec<String>, output_to: &mut Option<String>| {
        if !words.is_empty() || output_to.is_some() {
            commands.push(Command {
                words: std::mem::take(words),
                output_to: output_to.take(),
            });
        }
    };

    for tok in toks {
        match tok {
            Tok::Break => flush(&mut words, &mut output_to),
            Tok::Word(w) => words.push(w),
            Tok::Out { target } => {
                if output_to.is_some() {
                    return Err(Finding::opaque(
                        ">",
                        "every redirection is applied — `cmd > a > b` truncates `a` and sends \
                         stdout to `b`, so two files change — and the rollback ledger snapshots \
                         one target per command, so the port would be approving a write it \
                         cannot fully put back",
                    ));
                }
                output_to = Some(target);
            }
        }
    }
    flush(&mut words, &mut output_to);
    Ok(commands)
}

/// One command: its words and the file its output goes to, if any.
#[derive(Debug)]
struct Command {
    words: Vec<String>,
    output_to: Option<String>,
}

impl Command {
    /// Index of the command word: the first entry that is not a leading `NAME=value`
    /// assignment, which sets a variable for this command only and is not the thing run.
    fn head_index(&self) -> Option<usize> {
        self.words.iter().position(|w| !is_assignment(w))
    }

    fn head(&self) -> Option<&str> {
        self.head_index().map(|i| self.words[i].as_str())
    }

    /// The arguments — everything *after* the command word, never including it. A slice
    /// that starts at the head turns `mount` into "mount with the argument `mount`", which
    /// reads as a mount operation rather than a listing.
    fn args(&self) -> &[String] {
        match self.head_index() {
            Some(i) if i < self.words.len() => &self.words[i + 1..],
            _ => &[],
        }
    }

    /// Redirection target that actually writes something a reader could find.
    fn writes(&self) -> Option<&str> {
        let target = self.output_to.as_deref()?;
        if target == "/dev/null" || target.starts_with('&') {
            return None;
        }
        Some(target)
    }
}

fn is_assignment(word: &str) -> bool {
    let Some((name, _)) = word.split_once('=') else {
        return false;
    };
    !name.is_empty()
        && !name.starts_with(|c: char| c.is_ascii_digit())
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

// ── Classification ───────────────────────────────────────────────────────────

fn analyse(command: &Command) -> Finding {
    let Some(raw_head) = command.head() else {
        // Nothing but assignments, or a bare redirection.
        return match command.writes() {
            Some(target) => {
                Finding::new("", file_effect(target), format!("redirects to `{target}`"))
            }
            None => Finding::new("", Effect::ReadOnly, "changes no device state"),
        };
    };

    let head = normalise(raw_head);
    if head.contains('$') || head.contains('{') {
        return Finding::opaque(
            head,
            "the command name itself comes from a variable, so nothing is known about it",
        );
    }

    // `toybox` and `busybox` are dispatchers: `toybox rm -rf /data` *is* `rm`. Resolving one
    // level keeps the multiplexer from becoming a bypass.
    if matches!(head.as_str(), "toybox" | "busybox") {
        return match command.args().first().map(|a| normalise(a)) {
            None => Finding::new(
                head,
                Effect::ReadOnly,
                "run with no arguments it prints the applet list",
            ),
            Some(inner) if inner.starts_with('-') || inner.is_empty() => Finding::opaque(
                format!("{head} {inner}"),
                "the effect depends on the flag".to_string(),
            ),
            Some(inner) => {
                let inner_command = Command {
                    words: command.args().to_vec(),
                    output_to: command.output_to.clone(),
                };
                let finding = analyse(&inner_command);
                Finding::new(
                    format!("{head} {inner}"),
                    finding.effect,
                    format!("runs `{inner}` through the multiplexer; {}", finding.detail),
                )
            }
        };
    }

    // A redirection makes the command a file write whatever it was: `logcat -d > /data/x`
    // reads the log *and* writes a file, which is not the capability `logcat` needs.
    //
    // It does not *replace* the command's own effect though, which is what it used to do. A
    // script can write twice from one command — `sed -i 's/a/b/' /system/build.prop >
    // /data/local/tmp/log` rewrites a partition file and drops the noise in tmp — and a tier
    // decision that reports only the redirect approves the smaller half.
    let own = effect_of(&head, command.args());
    match command.writes() {
        Some(target) => {
            let redirect = file_effect(target);
            let detail = if own.effect == Effect::ReadOnly {
                format!("redirects its output to `{target}`")
            } else {
                format!("redirects its output to `{target}`, and {}", own.detail)
            };
            Finding::new(head, redirect.max(own.effect), detail)
        }
        None => own,
    }
}

/// Where a write target actually lands, as far as this port can tell.
enum Destination {
    /// One path, read off the text.
    Known(String),
    /// A pattern, but every file the shell can reach through it sits under this directory.
    Bounded { directory: String },
    /// The device picks the path, after the approval was given.
    Unknown,
}

/// Read a write target as the device will resolve it.
///
/// `$VAR` and `` ` `` expand before the open, a leading `~` becomes the home directory, and a
/// glob is filled in from the filesystem — so a prefix test on that text finds a harmless root
/// and hands out `fs:outside-app` for a write that may land in `/system`. This is the same
/// "spelling decides the approval" hole [`resolve_path`](super::script::resolve_path) closed for
/// `..`, arriving by a different route, and it is closed the same way: say the port cannot tell
/// what the script does, rather than guessing.
///
/// A glob is not automatically unknowable. `rm -fr /data/local/tmp/*` is confined to a directory
/// the shell owns, and refusing it would cost an approval for a bounded operation the port can
/// describe. What makes a glob unbounded is a `..` *after* the metacharacter, because that is
/// resolved after expansion: `/data/*/../../system/x` climbs out of whatever `/data/*` matched.
/// And a pattern with no directory part at all (`*`, `log*.txt`) is relative to a working
/// directory this port never sees, which is unknown for a different reason.
fn destination(target: &str) -> Destination {
    if target.contains(['$', '`']) || target.starts_with('~') {
        return Destination::Unknown;
    }
    // A path that does not start at the root is resolved against a working directory this port
    // never sees, and `resolve_path` cannot help: it reads `./f` as `/f`, which is what the
    // shell would say only from `/`. So `echo x > ./f` is not a write to the root, and not a
    // write to `/data/local/tmp/f` either — it is a write to wherever the device was sitting,
    // which the approval does not describe. Bare `f` and `../../etc/f` go the same way.
    if !target.starts_with('/') {
        return Destination::Unknown;
    }
    let Some(first) = target.find(['*', '?', '[']) else {
        return Destination::Known(target.to_string());
    };
    let (prefix, rest) = target.split_at(first);
    if prefix.is_empty() || rest.split('/').any(|segment| segment == "..") {
        return Destination::Unknown;
    }
    Destination::Bounded {
        directory: prefix.to_string(),
    }
}

/// The tier a write to this path costs, for callers that must compare it against something.
///
/// The rollback planner is that caller: when a command's finding is heavier than its own
/// redirection, the difference is a second write the ledger will not be able to restore, and the
/// session has to be told so at teardown rather than left with an undo list that looks complete.
/// It is exposed as a question to the classifier rather than a rule the planner copies, because a
/// second implementation of "where does this path land" is how the two drift apart — which is the
/// exact defect class `resolve_path` and `written_targets` exist to keep single.
pub fn file_write_effect(target: &str) -> Effect {
    file_effect(target)
}

/// Effect of writing to a path we have already decided the port can see.
fn effect_at(path: &str) -> Effect {
    if is_block_device(path) {
        Effect::Banned
    } else if is_partition_path(path) || is_app_data_path(path) {
        Effect::SystemWrite
    } else {
        Effect::FileWrite
    }
}

/// Paths that hold one application's private files.
///
/// `android:fs:outside-app` is named for exactly the thing these are not: writes outside app
/// data. `/data/local/tmp` is the shell's own scratch and belongs to the light tier; a path under
/// another uid's home does not, and treating it the same way would let a capability whose name
/// promises containment approve reading a bank app's database into the open. There is no app-data
/// tier in this port's vocabulary yet (that is question B2 of the upstream review), so it borrows
/// the heavier one rather than the lighter: the cost is an approval the caller might not need,
/// the alternative is a permission nobody asked for.
fn is_app_data_path(path: &str) -> bool {
    let path = super::script::resolve_path(path);
    const APP_DATA_ROOTS: &[&str] = &["/data/data", "/data/user", "/data/user_de"];
    APP_DATA_ROOTS
        .iter()
        .any(|root| path.starts_with(&format!("{root}/")))
}

/// Effect of writing to a path: partition and device nodes are the heavier tiers, writing a
/// block device outright is banned, and a destination the device picks is refused outright.
fn file_effect(target: &str) -> Effect {
    match destination(target) {
        Destination::Unknown => Effect::Opaque,
        Destination::Known(path) => effect_at(&path),
        // The directory part of a pattern is what bounds it; the glob tail decides nothing about
        // which *tier* the write belongs to.
        Destination::Bounded { directory } => effect_at(&directory),
    }
}

/// Whether a move/copy/link request carries its destination in a flag rather than an operand.
///
/// `-t DIR` and `--target-directory=DIR` are the two spellings, glued or separate. The guard is
/// scoped to `cp`/`mv`/`ln` on purpose: `touch -t 202401010000 file` uses the same letters for a
/// timestamp, and refusing that would be the classifier inventing a rule the command does not
/// have. Whether this toybox implements `-t` at all is a device fact nobody has measured here —
/// the refusal does not wait for the measurement, because the cost of refusing a spelling the
/// device ignores is one clarification, and the cost of blessing one is an approval for a
/// directory nobody read.
fn destination_is_in_a_flag(args: &[String]) -> bool {
    args.iter().any(|a| {
        a == "-t"
            || a == "--target-directory"
            || a.starts_with("--target-directory=")
            || (a.starts_with("-t") && a.len() > 2 && a.as_bytes()[2] == b'/')
    })
}

/// Which operands of a filesystem-mutating command name the files it changes.
///
/// Getting this wrong is not a rounding error: reading the first operand as "the file" describes
/// the *source* of a copy, and the source is only read.
///
/// - `cp` and `ln` write their last operand only.
/// - `mv` writes the last **and** unlinks the others from where they were, so both sides of the
///   rename belong to whatever tier the operation touches.
/// - Everything else in [`FILE_WRITE`] (`touch`, `chmod`, `chown`, `tee`, `truncate`, `rm`, the
///   formatters) acts on every operand it names.
///
/// `None` is the case where no destination can be seen: `cp /data/local/tmp/x` with a single
/// operand puts its result in a working directory this port never observes. Refusing that is the
/// same rule already applied to `sed -i` — a classifier that guesses which file a human approved
/// has approved an operation nobody looked at.
/// Whether an operand could name a file.
///
/// A path is rooted or has a separator in it; a bare word is as likely to be a mode (`755`), a
/// timestamp (`202401010000`) or an user name (`root`). This is not a permission test — it decides
/// which words the classifier reads as destinations, and an operand it does not read is not
/// therefore allowed: a write command whose operands are *all* bare words names no file at all and
/// is refused as opaque.
fn looks_like_path(operand: &str) -> bool {
    operand.starts_with('/') || operand.starts_with('.') || operand.contains('/')
}

fn written_targets<'a>(head: &str, operands: &[&'a str]) -> Option<Vec<&'a str>> {
    match head {
        "cp" | "ln" if operands.len() > 1 => operands.last().copied().map(|t| vec![t]),
        "mv" if operands.len() > 1 => Some(operands.to_vec()),
        "cp" | "ln" | "mv" => None,
        _ if operands.is_empty() => None,
        _ => Some(operands.to_vec()),
    }
}

/// Strip quote leftovers and resolve a command word to its basename.
///
/// `/system/bin/logcat` and `logcat` are the same command; a caller that spells out the
/// path — which the backends do, because the child runs with a cleared environment — must
/// not be classified as unknown.
fn normalise(word: &str) -> String {
    let trimmed = word.trim_matches(|c| c == '"' || c == '\'');
    trimmed
        .rsplit('/')
        .next()
        .filter(|b| !b.is_empty())
        .unwrap_or(trimmed)
        .to_string()
}

fn effect_of(head: &str, args: &[String]) -> Finding {
    let flag = |f: &str| args.iter().any(|a| a.starts_with('-') && a.contains(f));

    // Hard bans first (§4.6.3 item 3): these are refused at every tier.
    if head == "fastboot" || head == "flash" || head == "mkfs" || head == "format" {
        return Finding::new(head, Effect::Banned, BANNED_TEXT);
    }
    if args
        .iter()
        .any(|a| a.contains("wipe-data") || a.contains("wipe_data"))
    {
        return Finding::new(head, Effect::Banned, BANNED_TEXT);
    }
    if head == "dd" {
        // Every `of=` in the script, not the first: a copy can name more than one destination,
        // and returning on the first match is the same reflex that had `cp` classify a source.
        let targets: Vec<&str> = args.iter().filter_map(|a| a.strip_prefix("of=")).collect();
        if !targets.is_empty() {
            let effect = targets
                .iter()
                .map(|t| file_effect(t))
                .max()
                .unwrap_or(Effect::Opaque);
            return Finding::new(head, effect, format!("writes `{}`", targets.join("`, `")));
        }
        return Finding::new(head, Effect::ReadOnly, "copies stdin to stdout");
    }
    if head == "rm" {
        let targets: Vec<&str> = args
            .iter()
            .map(|a| a.as_str())
            .filter(|a| !a.starts_with('-'))
            .collect();
        if targets.iter().any(|t| match destination(t) {
            Destination::Unknown => false,
            Destination::Known(path) => is_destructive_root(&path) || is_partition_path(&path),
            Destination::Bounded { directory } => {
                is_destructive_root(&directory) || is_partition_path(&directory)
            }
        }) {
            return Finding::new(
                head,
                Effect::Banned,
                format!(
                    "`rm {}` removes a partition root or the device root, and {}",
                    targets.join(" "),
                    BANNED_TEXT
                ),
            );
        }
        // A removal the port cannot bound is not a removal it can allow: `$DIR`, a bare `*`
        // relative to a working directory nobody can see, and a pattern with a `..` after it all
        // decide *what* gets deleted after the approval was given.
        if let Some(target) = targets
            .iter()
            .find(|t| matches!(destination(t), Destination::Unknown))
        {
            return Finding::new(
                head,
                Effect::Opaque,
                format!(
                    "`rm` of `{target}` deletes something the device picks: a variable, a home \
                     directory, a pattern relative to an unseen working directory, or a glob \
                     with `..` after it"
                ),
            );
        }
    }

    // SELinux mode is its own tier in §4.4, gated per call and restored at session end.
    if head == "setenforce" {
        return Finding::new(
            head,
            Effect::SelinuxChange,
            "changes the SELinux mode for the whole device",
        );
    }
    if head == "umount" || head == "mount" {
        // `mount` with no arguments, or with only listing flags, is a read. Anything else
        // attaches or remounts a filesystem.
        let listing_only = args.iter().all(|a| MOUNT_READ_FLAGS.contains(&a.as_str()));
        if head == "umount" || !listing_only {
            return Finding::new(
                head,
                Effect::SystemWrite,
                "attaches or remounts a filesystem — the tier that needs dm-verity off",
            );
        }
        return Finding::new(head, Effect::ReadOnly, "lists mounts");
    }

    // The service dispatchers, where the first argument decides: `pm list packages` reads,
    // `pm install` does not.
    if DISPATCHERS.contains(&head) {
        return dispatcher(head, args);
    }

    // `command` and `env` report *or* run, depending on whether a command word follows.
    // They cannot sit on the read list as written: `env rm -rf /data` and `command rm -rf
    // /data` both execute, and the classifier would have called them reads.
    if head == "command" {
        return if matches!(args.first().map(String::as_str), Some("-v") | Some("-V")) {
            Finding::new(head, Effect::ReadOnly, "`command -v` only resolves a name")
        } else {
            Finding::opaque(
                head,
                "`command <name>` runs that name, so its effect is whatever that one is",
            )
        };
    }
    if head == "env" {
        return if args.iter().all(|a| a.starts_with('-') || a.contains('=')) {
            Finding::new(
                head,
                Effect::ReadOnly,
                "prints the environment; assignments here scope to this command only",
            )
        } else {
            Finding::opaque(
                head,
                "`env <cmd>` runs that command — `env -i` is how the backends clear the \
                 environment, and a caller can put anything after it",
            )
        };
    }

    if READ_ONLY.contains(&head) {
        // Commands on the read list with a flag that flips them.
        if head == "logcat" {
            if flag("c") || args.iter().any(|a| a == "--clear") {
                return Finding::new(
                    head,
                    Effect::ShellWrite,
                    "-c clears the log buffer, destroying evidence other readers rely on",
                );
            }
            if flag("r") || flag("f") {
                return Finding::new(
                    head,
                    Effect::FileWrite,
                    "writes the log to a file (-r rotates to a file, -f names it)",
                );
            }
        }
        if head == "sed" && flag("i") {
            // `-i` rewrites the files named *after* the script expression, and the classifier
            // used to stop at "an in-place edit happened" and hand out FileWrite whatever the
            // file was: `sed -i 's/a/b/' /system/build.prop` asked for the lightest write tier
            // there is. Which operand is the script is only decidable when nothing interleaves
            // more expressions with more files, so `-e` and a missing operand are refused rather
            // than guessed — a port that guesses which filename a human approved has approved a
            // different operation than the one on the screen.
            let interleaved = args
                .iter()
                .any(|a| a.starts_with("-e") || a.starts_with("--expression"));
            let operands: Vec<&str> = args
                .iter()
                .filter(|a| !a.starts_with('-'))
                .map(String::as_str)
                .collect();
            if interleaved {
                return Finding::opaque(
                    head,
                    "-e interleaves script expressions with file names, so which operand gets \
                     rewritten cannot be told apart",
                );
            }
            if operands.len() < 2 {
                return Finding::opaque(
                    head,
                    "-i edits a file in place and none was named, so there is nothing to check",
                );
            }
            let effect = operands[1..].iter().map(|f| file_effect(f)).max();
            return Finding::new(
                head,
                effect.unwrap_or(Effect::Opaque),
                format!("rewrites `{}` in place", operands[1..].join("`, `")),
            );
        }
        if head == "screencap" {
            // `screencap` alone writes nothing; with a path it saves a capture there.
            if let Some(target) = args.iter().find(|a| !a.starts_with('-')) {
                return Finding::new(
                    head,
                    file_effect(target),
                    format!("saves a capture to `{target}`"),
                );
            }
        }
        return Finding::new(head, Effect::ReadOnly, "on the read allow-list");
    }

    if NESTED.contains(&head) {
        return Finding::opaque(
            head,
            format!(
                "`{head}` runs a command this classifier cannot see; run the inner command \
                 as its own request"
            ),
        );
    }

    if FILE_WRITE.contains(&head) {
        // Which operands name the files that change. This used to read the *first* argument as
        // "the file", which for `cp`, `mv` and `ln` is the source — so the destination was never
        // classified at all, and `cp /data/local/tmp/x /system/bin/y` cost the lightest write
        // tier available while changing a partition.
        //
        // Only operands that could be paths are read as files. `chmod 755 /system/bin/x` has a
        // mode where a name goes and `touch -t 202401010000 f` has a timestamp; counting those as
        // destinations is what made a tier depend on a word that is not a path at all. Dropping
        // them is safe in the approving direction only because nothing is left when *no* operand
        // looks like a path: the request then has no named file, which is refused below.
        let operands: Vec<&str> = args
            .iter()
            .filter(|a| !a.starts_with('-'))
            .map(String::as_str)
            .filter(|a| looks_like_path(a))
            .collect();
        if matches!(head, "cp" | "mv" | "ln") && destination_is_in_a_flag(args) {
            return Finding::opaque(
                head,
                "-t puts the destination directory in a flag, so the operand list names only what \
                 is being moved — the port would be approving the source and letting the \
                 destination arrive from a flag it never read",
            );
        }
        let Some(targets) = written_targets(head, &operands) else {
            return Finding::opaque(
                head,
                "the file it would change is not named: with one operand the destination is \
                 relative to a working directory this port never sees",
            );
        };
        let effect = targets
            .iter()
            .map(|t| file_effect(t))
            .max()
            .unwrap_or(Effect::Opaque);
        return Finding::new(head, effect, format!("modifies `{}`", targets.join("`, `")));
    }

    if SHELL_WRITE.contains(&head) {
        return Finding::new(head, Effect::ShellWrite, "changes device state");
    }

    Finding::opaque(
        head,
        "on neither the read allow-list nor the write list, so the port has no basis for \
         allowing it unattended",
    )
}

/// `pm`/`am`/`settings`/`cmd`/`wm`/`svc`/`ime`/`content`: the subcommand decides.
fn dispatcher(head: &str, args: &[String]) -> Finding {
    let Some(sub) = args.iter().find(|a| !a.starts_with('-')) else {
        // No subcommand at all: `pm` prints usage. Harmless, and refusing it would punish
        // a caller for asking for help.
        return Finding::new(
            head,
            Effect::ReadOnly,
            "run without a subcommand, prints usage",
        );
    };
    let lower = sub.to_ascii_lowercase();
    let reads = READ_SUBCOMMANDS
        .iter()
        .any(|prefix| lower.starts_with(prefix));
    if reads {
        return Finding::new(
            format!("{head} {sub}"),
            Effect::ReadOnly,
            "read-only subcommand",
        );
    }
    Finding::new(
        format!("{head} {sub}"),
        Effect::ShellWrite,
        "is a mutating subcommand — §4.4 puts these behind approval",
    )
}

/// §4.6.3 item 3: refused regardless of tier. This text is what the caller sees.
const BANNED_TEXT: &str =
    "it is on the hard-ban list (ADR-AND-001 §4.6 item 3), which no capability authorises";

/// Service tools whose first non-flag argument decides whether anything changes.
const DISPATCHERS: &[&str] = &["pm", "am", "settings", "cmd", "wm", "svc", "ime", "content"];

/// Subcommand prefixes that only report state.
const READ_SUBCOMMANDS: &[&str] = &[
    "get", "list", "show", "query", "dump", "status", "which", "path", "help", "print",
];

/// Flags that leave `mount` a listing command. Deliberately tiny: `-a` mounts everything in
/// fstab, `-r` and `-o` accompany a real mount, and `-t` names a filesystem type for one.
const MOUNT_READ_FLAGS: &[&str] = &["-l", "-s", "--"];

/// §4.4's read vocabulary, verbatim: the commands the auto-pass tier claims to cover.
///
/// These are the first seven entries of `READ_ONLY`; everything after them in that table is
/// justified a different way (the probe runs it itself, or it only filters text). A tool
/// description reports on *this* list, because it is the list the ADR commits to — so the
/// two must not drift, which `the_tier_vocabulary_matches_the_classifier` pins.
pub const READ_TIER_COMMANDS: &[&str] = &[
    "getprop",
    "dumpsys",
    "logcat",
    "ps",
    "df",
    "mount",
    "getenforce",
];

/// §4.4's write vocabulary, verbatim: each of these needs approval when the classifier sees
/// it. `am` and `pm` are here as subcommand dispatchers — the classifier decides by the
/// subcommand, and `pm list` is a read.
pub const WRITE_TIER_COMMANDS: &[&str] = &["setprop", "am", "pm", "settings", "input"];

/// Read-only commands.
///
/// The first seven are ADR-AND-001 §4.4's list verbatim. What follows is justified one way
/// or the other: either this crate's own startup probe runs it unattended on every device
/// (`cat`, `id`, `command`, `toybox`), or it is a pure filter over text it is handed
/// (`grep`, `sort`, `awk`…) and changes no device state. `awk` is *not* here: its program
/// text can call `system()` and write files, and reading it would mean parsing another
/// language.
const READ_ONLY: &[&str] = &[
    // §4.4 verbatim.
    "getprop",
    "dumpsys",
    "logcat",
    "ps",
    "df",
    "mount",
    "getenforce",
    // Run by the startup probe itself, so already trusted to be unattended.
    "id",
    "cat",
    "which",
    "toybox",
    "busybox",
    "screencap",
    // Filters and shell builtins: they transform text, not device state.
    "pwd",
    "uname",
    "date",
    "uptime",
    "ls",
    "head",
    "tail",
    "wc",
    "grep",
    "egrep",
    "fgrep",
    "sort",
    "uniq",
    "tr",
    "cut",
    "sed",
    "basename",
    "dirname",
    "readlink",
    "realpath",
    "stat",
    "file",
    "du",
    "lsof",
    "type",
    "expr",
    "seq",
    "od",
    "hexdump",
    "strings",
    "md5sum",
    "sha1sum",
    "sha256sum",
    "base64",
    "echo",
    "printf",
    "true",
    "false",
    "test",
    "[",
    "[[",
];

/// Mutating through a system service — `android:shell:write`.
const SHELL_WRITE: &[&str] = &[
    "setprop",
    "input",
    "monkey",
    "kill",
    "pkill",
    "killall",
    "reboot",
    "stop",
    "start",
    "sync",
    "restorecon",
    "chcon",
    "setcontext",
    "insmod",
    "rmmod",
    "modprobe",
    "swapon",
    "losetup",
    "ioctl",
    "vdc",
    "bugreportz",
    "ifconfig",
    "ip",
    "ndc",
    "svc",
    "settings",
];

/// Mutating through the filesystem — `android:fs:outside-app`, promoted to `fs:system` when
/// the target is a system partition.
const FILE_WRITE: &[&str] = &[
    "rm",
    "mv",
    "cp",
    "touch",
    "mkdir",
    "rmdir",
    "ln",
    "chmod",
    "chown",
    "chgrp",
    "tee",
    "truncate",
    "mkswap",
    "mke2fs",
    "fdisk",
    "sfdisk",
    "parted",
    "mkuserdir",
    "dd",
];

/// Commands whose entire purpose is to run something else. Never looked inside: a guard
/// that re-parses nested script text has two parse surfaces to get wrong.
const NESTED: &[&str] = &[
    "sh", "bash", "ksh", "mksh", "zsh", "dash", "ash", "csh", "source", ".", "eval", "exec",
    "xargs", "su", "run-as", "nohup", "timeout", "nice", "taskset", "strace", "gdb", "env",
];

fn is_block_device(path: &str) -> bool {
    const BLOCK_PREFIXES: &[&str] = &[
        "/dev/block/",
        "/dev/disk/",
        "/dev/mmcblk",
        "/dev/sd",
        "/dev/bootdevice/",
        "/dev/loop",
        "/dev/zram",
    ];
    let path = super::script::resolve_path(path);
    BLOCK_PREFIXES.iter().any(|p| path.starts_with(p))
}

/// Mount points whose contents belong to the system image rather than to a user.
fn is_partition_path(path: &str) -> bool {
    const SYSTEM_ROOTS: &[&str] = &[
        "/system",
        "/vendor",
        "/product",
        "/system_ext",
        "/oem",
        "/odm",
        "/boot",
        "/recovery",
        "/persist",
        "/mnt/vendor",
        "/firmware",
        "/dsp",
        "/dev",
        "/sys",
        "/proc",
    ];
    let path = super::script::resolve_path(path);
    SYSTEM_ROOTS
        .iter()
        .any(|root| path == *root || path.starts_with(&format!("{root}/")))
}

/// The roots `rm` is hard-banned for, §4.6.3 item 3's `rm -rf /data`.
fn is_destructive_root(path: &str) -> bool {
    let path = super::script::resolve_path(path);
    path == "/" || path == "/data" || path == "/sdcard" || path == "/storage"
}

#[cfg(test)]
mod tests {
    use super::*;

    fn effect(script: &str) -> Effect {
        classify(script).strongest()
    }

    fn first_finding(script: &str) -> Finding {
        classify(script)
            .findings
            .into_iter()
            .next()
            .unwrap_or_else(|| panic!("no finding for {script:?}"))
    }

    #[test]
    fn words_recovers_the_arguments_the_classifier_throws_away() {
        // The rollback planner reads prop names and values out of these vectors, so quoting
        // has to survive exactly as the shell would see it.
        assert_eq!(
            words("setprop debug.foo.bar 'a b'"),
            Some(vec![vec![
                "setprop".to_string(),
                "debug.foo.bar".to_string(),
                "a b".to_string()
            ]])
        );
        // Two commands, two vectors — a script that changes two props needs two undos.
        assert_eq!(
            words("setprop a 1; setprop b 2").map(|v| v.len()),
            Some(2),
            "a sequence is not one command"
        );
        // `None`, not an empty list: "I could not read this" must not look like "nothing here
        // needs undoing".
        assert_eq!(words("setprop a b &"), None);
        assert_eq!(words(""), Some(vec![]));
    }

    #[test]
    fn the_tier_vocabulary_matches_the_classifier() {
        // READ_TIER_COMMANDS / WRITE_TIER_COMMANDS are what a tool description tells the
        // model exists. If they drift from the tables the classifier actually consults, the
        // description promises a command the gate will refuse, or hides one it would allow.
        for name in READ_TIER_COMMANDS {
            assert!(
                READ_ONLY.contains(name),
                "`{name}` is advertised as read-tier but the classifier does not treat it as read-only"
            );
        }
        for name in WRITE_TIER_COMMANDS {
            assert!(
                SHELL_WRITE.contains(name) || DISPATCHERS.contains(name),
                "`{name}` is advertised as needing approval but the classifier has no rule for it"
            );
        }
    }

    // ── §4.4: the read allow-list, which is what the auto-pass buys ──────────

    #[test]
    fn every_command_adr_4_4_lists_as_read_is_read_only() {
        // The ADR's list verbatim: getprop / dumpsys / logcat / ps / df / mount / getenforce.
        for script in [
            "getprop",
            "getprop ro.build.type",
            "dumpsys window",
            "logcat -d",
            "logcat -d -b crash",
            "ps -A",
            "df",
            "mount",
            "mount -l",
            "getenforce",
        ] {
            assert_eq!(effect(script), Effect::ReadOnly, "{script}");
            assert!(
                check(script, Some(Capability::ShellRead)).is_ok(),
                "{script} must auto-pass without approval"
            );
        }
    }

    #[test]
    fn read_pipelines_stay_reads_and_one_write_anywhere_ends_the_pass() {
        assert_eq!(effect("getprop | grep ro.build"), Effect::ReadOnly);
        assert_eq!(
            effect("dumpsys battery | grep level && getprop ro.product.cpu.abi"),
            Effect::ReadOnly
        );
        // One write in a pipeline is a write, whichever end of the pipe it sits on.
        assert_eq!(effect("getprop | setprop ro.x 1"), Effect::ShellWrite);
    }

    #[test]
    fn the_command_the_real_device_ran_is_a_read() {
        // `examples/device_probe.rs` runs exactly this on a Huawei BLA-AL00.
        assert_eq!(
            effect("echo acowork-harness-ok; id -u; pwd"),
            Effect::ReadOnly
        );
    }

    // ── The hole this module exists to close ─────────────────────────────────

    #[test]
    fn a_write_labelled_as_read_is_refused_and_names_what_it_needs() {
        let refusal = check("setprop debug.acowork 1", Some(Capability::ShellRead))
            .expect_err("the auto-pass must not trust the label");
        match &refusal {
            Refusal::Mismatch {
                command,
                claimed,
                needed,
                ..
            } => {
                assert_eq!(command, "setprop");
                assert_eq!(*claimed, Capability::ShellRead);
                assert_eq!(*needed, Capability::ShellWrite);
            }
            other => panic!("expected Mismatch, got {other:?}"),
        }
        // R9: the text says what to do next, not just that this failed.
        assert!(
            refusal.to_string().contains("Re-send it under"),
            "{refusal}"
        );
    }

    #[test]
    fn a_remount_labelled_as_read_reaches_the_system_tier() {
        let refusal = check("mount -o remount,rw /system", Some(Capability::ShellRead))
            .expect_err("remount is not a read");
        assert_eq!(
            effect("mount -o remount,rw /system"),
            Effect::SystemWrite,
            "and that is the tier that needs dm-verity off"
        );
        assert!(
            refusal
                .to_string()
                .contains(&Capability::FsSystem.id().to_string()),
            "{refusal}"
        );
    }

    #[test]
    fn over_claiming_is_the_callers_cost_not_a_risk() {
        // A write label on a read command spends an approval nobody needed. Refusing it
        // would punish honesty; the dangerous direction is the other one.
        assert!(check("getprop", Some(Capability::ShellWrite)).is_ok());
    }

    // ── §4.6.3: the hard-ban list ────────────────────────────────────────────

    #[test]
    fn the_hard_banned_forms_are_refused_at_every_tier() {
        let block = "/dev/block/mmcblk0p1";
        for script in [
            format!("dd if=/dev/zero of={block}"),
            "rm -rf /data".to_string(),
            "rm -rf /".to_string(),
            "rm -rf /system/app".to_string(),
            "fastboot flash boot boot.img".to_string(),
            format!("flash {block}"),
            "am wipe-data".to_string(),
        ] {
            assert_eq!(effect(&script), Effect::Banned, "{script}");
            // Even the highest tier does not authorise these.
            for claim in [
                Capability::ShellRead,
                Capability::ShellWrite,
                Capability::FsSystem,
                Capability::SelinuxPermissive,
            ] {
                assert!(
                    matches!(check(&script, Some(claim)), Err(Refusal::Banned { .. })),
                    "{script} must stay banned under {claim:?}"
                );
            }
        }
    }

    #[test]
    fn a_ban_refusal_does_not_offer_a_capability_to_request() {
        // The text must not read like "ask for a higher tier": §4.6.3 removed these from the
        // authorisable set, so pointing at a capability would send the caller in a circle.
        let refusal = check("rm -rf /data", Some(Capability::FsSystem))
            .err()
            .unwrap();
        let text = refusal.to_string();
        assert!(text.contains("human"), "{text}");
        assert!(!text.contains("Re-send it under"), "{text}");
    }

    // ── Bypass attempts ──────────────────────────────────────────────────────

    #[test]
    fn the_multiplexers_do_not_become_bypasses() {
        // `toybox` and `busybox` dispatch to an applet; resolving one level keeps the
        // multiplexer from being the easiest way around this table.
        assert_eq!(effect("toybox rm -rf /data"), Effect::Banned);
        assert_eq!(effect("busybox setprop ro.x 1"), Effect::ShellWrite);
        assert_eq!(effect("toybox"), Effect::ReadOnly);
        assert_eq!(effect("toybox --help"), Effect::Opaque);
    }

    #[test]
    fn an_absolute_path_is_the_same_command_as_its_basename() {
        // The backends spell out `/system/bin/…` because the child runs with a cleared
        // environment; treating the spelled-out form as unknown would refuse the very
        // requests that auto-pass by name.
        assert_eq!(effect("/system/bin/logcat -d"), Effect::ReadOnly);
        assert_eq!(effect("/system/bin/setprop ro.x 1"), Effect::ShellWrite);
    }

    #[test]
    fn runners_of_other_commands_are_never_read_only() {
        // `env` and `command` are on the read list for their reporting forms, so the
        // executing forms have to be caught here or they are a hole with a friendly name.
        assert_eq!(effect("env"), Effect::ReadOnly);
        assert_eq!(effect("env -i"), Effect::ReadOnly);
        assert_eq!(effect("env PATH=/x rm -rf /data"), Effect::Opaque);
        assert_eq!(effect("command -v logcat"), Effect::ReadOnly);
        assert_eq!(effect("command rm -rf /data"), Effect::Opaque);
        for script in [
            "sh -c 'setprop ro.x 1'",
            "bash -c 'rm -rf /data'",
            "su -c id",
            "eval setprop ro.x 1",
            "exec rm -rf /data",
            "xargs rm < files",
            ". /data/local/tmp/script",
        ] {
            assert_eq!(effect(script), Effect::Opaque, "{script}");
        }
    }

    #[test]
    fn nested_text_is_not_reevaluated() {
        // Command substitution and backquotes run something the classifier does not see.
        // Re-parsing the inner text would mean maintaining two parse surfaces.
        assert_eq!(effect("echo $(getprop ro.x)"), Effect::Opaque);
        assert_eq!(effect("echo `id -u`"), Effect::Opaque);
        assert_eq!(effect("echo ${SHELL_VAR}"), Effect::Opaque);
        assert_eq!(effect("$(echo getprop)"), Effect::Opaque);
    }

    #[test]
    fn control_flow_is_not_analysable() {
        for script in [
            "if [ -f /x ]; then setprop ro.y 1; fi",
            "for f in /data/* ; do rm $f ; done",
            "case $x in y) setprop a b ;; esac",
            "(getprop)",
            "{ getprop ; }",
        ] {
            assert_eq!(effect(script), Effect::Opaque, "{script}");
        }
    }

    #[test]
    fn backgrounding_is_refused_because_nothing_about_the_run_describes_it() {
        assert_eq!(effect("sleep 20 &"), Effect::Opaque);
        // `&&` is sequencing, not backgrounding: it ends a command and is analysed.
        assert_eq!(effect("getprop && echo ok"), Effect::ReadOnly);
    }

    // ── Redirection ──────────────────────────────────────────────────────────

    #[test]
    fn writing_a_file_is_a_file_write_whatever_the_command_was() {
        assert_eq!(
            effect("logcat -d > /data/local/tmp/log.txt"),
            Effect::FileWrite
        );
        assert_eq!(effect("getprop > /system/x"), Effect::SystemWrite);
        assert_eq!(effect("getprop >> /dev/block/mmcblk0"), Effect::Banned);
        assert_eq!(effect("echo hi > /dev/null"), Effect::ReadOnly);
        assert_eq!(effect("logcat -d 2>&1"), Effect::ReadOnly);
    }

    // ── Path aliasing ────────────────────────────────────────────────────────

    #[test]
    fn a_write_that_walks_back_into_a_partition_is_a_system_write() {
        // The device opens the path it *resolves*, not the string it was handed. Prefix matching
        // on the literal text therefore asks for the weaker capability for a write that lands in
        // /system, which is the one place a classifier can be talked out of its own decision
        // without the device knowing anything unusual was asked for.
        //
        // Four segments to climb from /data/local/tmp to /: the count is the point, see
        // `a_walk_that_stops_short_of_the_root_is_not_a_system_write`.
        assert_eq!(
            effect("getprop > /data/local/tmp/../../../system/x"),
            Effect::SystemWrite
        );
        assert_eq!(
            effect("echo x > /system/../system/bin/y"),
            Effect::SystemWrite,
            "a `..` that cancels out still names /system"
        );
        assert_eq!(
            effect("getprop > /data/local/../../system/x"),
            Effect::SystemWrite,
            "two segments up from /data/local is /, and `/../system` still names /system"
        );
    }

    #[test]
    fn a_walk_that_stops_short_of_the_root_is_not_a_system_write() {
        // The resolver has to resolve, not spot the word "system". `/data/local/tmp/../../system`
        // is `/data/system` — a real directory, owned by a real app's data, and *not* the system
        // partition. Classifying it as a system write would ask the caller to approve something
        // the script never did.
        assert_eq!(
            effect("getprop > /data/local/tmp/../../system/x"),
            Effect::FileWrite
        );
        assert_eq!(
            effect("rm -fr /data/local/tmp/../../data"),
            Effect::FileWrite
        );
    }

    #[test]
    fn a_block_device_reached_through_dotdot_is_still_banned() {
        assert_eq!(
            effect("getprop > /data/local/tmp/../../../../dev/block/mmcblk0"),
            Effect::Banned
        );
        assert_eq!(
            effect("dd if=/dev/zero of=/data/local/tmp/../../../../dev/block/mmcblk0"),
            Effect::Banned
        );
        // Climbing past the root stops at the root, exactly as the kernel does it.
        assert_eq!(effect("getprop > /../../dev/block/mmcblk0"), Effect::Banned);
    }

    #[test]
    fn a_removal_that_walks_back_to_a_destructive_root_is_banned() {
        // `-fr` and `-rf` are one option cluster: the ban is about the target, never the spelling.
        assert_eq!(
            effect("rm -fr /data/local/tmp/../../../data"),
            Effect::Banned,
            "the target resolves to the destructive root itself"
        );
        assert_eq!(effect("rm -fr /data/local/tmp/../../../"), Effect::Banned);
    }

    #[test]
    fn an_ordinary_dotdot_stays_an_ordinary_path() {
        // Over-blocking is its own defect: this is a normal file in a normal directory, and a
        // classifier that turned it into a system write would cost the caller an approval it
        // should never have been asked for.
        assert_eq!(
            effect("logcat -d > /data/local/tmp/../local/tmp/log.txt"),
            Effect::FileWrite
        );
        assert_eq!(effect("echo hi > /data/local/tmp/./x"), Effect::FileWrite);
        assert_eq!(effect("echo hi > /data/local/tmp/x/.."), Effect::FileWrite);
    }

    #[test]
    fn a_quoted_write_target_is_classified_by_where_it_lands() {
        // Shell authors quote paths; the classifier sees the word after the quotes are gone. If
        // it did not, `> '/system/x'` would be a FileWrite whose target begins with a quote.
        assert_eq!(effect("echo x > '/system/x'"), Effect::SystemWrite);
        assert_eq!(effect("echo x > \"/system/x\""), Effect::SystemWrite);
        assert_eq!(
            effect("echo x > '/data/local/tmp/../../../system/x'"),
            Effect::SystemWrite
        );
    }

    #[test]
    fn a_write_target_whose_destination_is_decided_on_the_device_is_refused() {
        // The classifier may only reason about a destination it can see. These all name a file
        // the *device* picks: `$` and the backtick expand before the open, a glob is filled in
        // from the filesystem, `~` becomes the home directory.
        assert_eq!(
            effect("echo x > $TARGET"),
            Effect::Opaque,
            "the destination is a variable"
        );
        assert_eq!(
            effect("echo x > /data/local/tmp/$SUB"),
            Effect::Opaque,
            "half of it is a variable"
        );
        assert_eq!(
            effect("echo x > `echo /system/x`"),
            Effect::Opaque,
            "half of it is a command"
        );
        assert_eq!(
            effect("echo x > /data/*/../../system/x"),
            Effect::Opaque,
            "the `..` is resolved after the glob, so it climbs out of whatever /data/* matched"
        );
        assert_eq!(
            effect("echo x > ~/../system/x"),
            Effect::Opaque,
            "the home directory is not something this port can see"
        );
    }

    #[test]
    fn a_glob_is_bounded_by_its_directory_not_refused_on_sight() {
        // `rm -fr /data/local/tmp/*` is a normal cleanup of a directory the shell owns. Refusing
        // every pattern would be over-blocking with a straight face; the thing that makes a
        // pattern unknowable is having no directory part, or a `..` after it.
        assert_eq!(
            effect("rm -fr /data/local/tmp/*"),
            Effect::FileWrite,
            "bounded to a directory that belongs to no partition"
        );
        assert_eq!(
            effect("getprop > /data/local/tmp/*.log"),
            Effect::FileWrite,
            "the glob tail decides the name, not the tier"
        );
        assert_eq!(
            effect("getprop > /system/*"),
            Effect::SystemWrite,
            "a pattern inside a partition is still a write to that partition"
        );
        assert_eq!(
            effect("rm -fr /*"),
            Effect::Banned,
            "bounded to the device root, which is the ban"
        );
        assert_eq!(
            effect("rm -fr *"),
            Effect::Opaque,
            "relative to a working directory nobody can see"
        );
    }

    #[test]
    fn a_harmless_looking_variable_still_has_to_be_refused() {
        // The whole point of the ban list is that it does not depend on the caller's intentions.
        // A `dd` whose `of=` is a variable is the same hole as a redirect whose target is one.
        assert_eq!(
            effect("dd if=/dev/zero of=$BLOCK"),
            Effect::Opaque,
            "the block device is chosen after the approval"
        );
        assert_eq!(
            effect("sed -i 's/a/b/' $FILE"),
            Effect::Opaque,
            "in-place editing of an unseeable path"
        );
    }

    #[test]
    fn an_in_place_edit_is_classified_by_the_file_it_rewrites() {
        // `sed -i` was the third instance of the same mistake: the classifier noticed that a
        // file was rewritten and never asked which one, so `/system/build.prop` cost the same
        // approval as a scratch file. The script expression is skipped on purpose — it is not a
        // path, and `s/x$/Y/` would otherwise read as a variable.
        assert_eq!(
            effect("sed -i 's/a/b/' /system/build.prop"),
            Effect::SystemWrite
        );
        assert_eq!(
            effect("sed -i 's/a/b/' /dev/block/mmcblk0"),
            Effect::Banned,
            "rewriting a raw device through a text editor is still writing it"
        );
        assert_eq!(
            effect("sed -i 's/x$/Y/' /data/local/tmp/x"),
            Effect::FileWrite,
            "an end-of-line anchor is not a variable"
        );
        assert_eq!(
            effect("sed -i -e 's/a/b/' /data/local/tmp/x"),
            Effect::Opaque,
            "-e makes the operand list ambiguous"
        );
        assert_eq!(
            effect("sed -i 's/a/b/'"),
            Effect::Opaque,
            "an in-place edit with no file named"
        );
    }

    #[test]
    fn the_destination_of_a_copy_is_what_costs_the_approval() {
        // The classifier took the *first* non-flag argument as the file a command writes. For
        // `cp`, `mv` and `ln` that argument is the source, so the destination — the file that
        // actually changes — was never looked at: `cp /data/local/tmp/x /system/bin/y` cost the
        // same approval as a scratch file, and `mv ... /dev/block/mmcblk0` was not banned.
        assert_eq!(
            effect("cp /data/local/tmp/x /system/bin/y"),
            Effect::SystemWrite
        );
        assert_eq!(
            effect("mv /data/local/tmp/x /dev/block/mmcblk0"),
            Effect::Banned
        );
        assert_eq!(
            effect("ln -s /data/local/tmp/x /system/bin/sh"),
            Effect::SystemWrite,
            "the link name is the file created, not the thing it points at"
        );
        assert_eq!(
            effect("cp /system/app/x.apk /data/local/tmp/y"),
            Effect::FileWrite,
            "reading out of /system is not writing to it"
        );
        assert_eq!(
            effect("mv /system/x /data/local/tmp/y"),
            Effect::SystemWrite,
            "but moving a file out of /system does change /system"
        );
        assert_eq!(
            effect("chmod 755 /system/bin/x"),
            Effect::SystemWrite,
            "the mode is not a path, and the path is not first"
        );
        assert_eq!(effect("truncate -s 0 /data/local/tmp/x"), Effect::FileWrite);
        assert_eq!(
            effect("tee /system/x"),
            Effect::SystemWrite,
            "tee writes every operand it names"
        );
        assert_eq!(
            effect("cp /data/local/tmp/x"),
            Effect::Opaque,
            "one operand means the destination is relative to a working directory nobody sees"
        );
    }

    #[test]
    fn a_destination_hiding_inside_a_flag_is_refused_not_blessed() {
        // `cp -t /system/bin x` names the partition where the operand list never looks: `-t` is
        // a flag, `/system/bin` is a non-flag operand, and "the last operand is the destination"
        // would read this as writing `x`. Whether this toybox implements `-t` is a device fact
        // nobody has measured here, and the refusal does not wait for the measurement.
        assert_eq!(
            effect("cp -t /system/bin /data/local/tmp/x"),
            Effect::Opaque
        );
        assert_eq!(
            effect("mv --target-directory=/system/bin /data/local/tmp/x"),
            Effect::Opaque
        );
        assert_eq!(
            effect("cp -t/system/bin /data/local/tmp/x"),
            Effect::Opaque,
            "the glued spelling is the same request"
        );
    }

    #[test]
    fn a_multiplexer_or_an_absolute_invocation_cannot_change_the_tier() {
        // Two spellings of the same write must cost the same approval: the classifier unpacks
        // `toybox`/`busybox` to the real subcommand and resolves a command word to its basename
        // (backends invoke `/system/bin/cp` because the child runs with a cleared environment).
        assert_eq!(
            effect("toybox cp /data/local/tmp/x /system/bin/y"),
            Effect::SystemWrite
        );
        assert_eq!(
            effect("busybox sed -i 's/a/b/' /system/build.prop"),
            Effect::SystemWrite
        );
        assert_eq!(
            effect("/system/bin/cp /data/local/tmp/x /system/bin/y"),
            Effect::SystemWrite
        );
        assert_eq!(
            effect("toybox dd if=/dev/zero of=/data/local/tmp/../../../dev/block/mmcblk0"),
            Effect::Banned
        );
    }

    #[test]
    fn a_timestamp_flag_is_not_mistaken_for_a_destination() {
        // `touch -t` takes a date. A guard scoped to "any -t anywhere" would be the classifier
        // inventing a rule the command does not have.
        assert_eq!(
            effect("touch -t 202401010000 /data/local/tmp/x"),
            Effect::FileWrite
        );
        assert_eq!(
            effect("touch -t 202401010000 /system/x"),
            Effect::SystemWrite,
            "the timestamp operand is not a path, and the path still decides the tier"
        );
    }

    #[test]
    fn a_command_that_writes_twice_is_costed_for_both_writes() {
        // A redirection used to *replace* the command's own effect: the finding said "redirects
        // its output", and an in-place edit in the same command disappeared from the tier
        // decision. The approval a script needs is the strongest thing it does, not the last
        // thing the classifier noticed.
        assert_eq!(
            effect("sed -i 's/a/b/' /system/build.prop > /data/local/tmp/log"),
            Effect::SystemWrite,
            "the log lands in tmp; the build.prop rewrite does not stop being a partition write"
        );
        assert_eq!(
            effect("sed -i 's/a/b/' /data/local/tmp/x > /data/local/tmp/log"),
            Effect::FileWrite
        );
        assert_eq!(
            effect("cp /data/local/tmp/x /system/bin/y > /data/local/tmp/log"),
            Effect::SystemWrite
        );
        assert_eq!(
            effect("getprop > /data/local/tmp/log"),
            Effect::FileWrite,
            "a pure read with a redirect is still only the file write"
        );
    }

    #[test]
    fn every_output_operand_of_a_copy_counts_not_just_the_first() {
        // `dd` returned on the first `of=` it saw, the same "first match wins" reflex that made
        // `cp` read its source as the destination. Both names are in the script, so the heavier
        // one is the tier the command needs.
        assert_eq!(
            effect("dd if=/dev/zero of=/data/local/tmp/x of=/dev/block/mmcblk0"),
            Effect::Banned
        );
        assert_eq!(
            effect("dd if=/dev/zero of=/data/local/tmp/x"),
            Effect::FileWrite
        );
        assert_eq!(
            effect("dd if=/dev/zero of=/data/local/tmp/x of=/system/y"),
            Effect::SystemWrite
        );
    }

    // ── Flag and subcommand rules ────────────────────────────────────────────

    #[test]
    fn flags_that_flip_a_read_into_a_write() {
        assert_eq!(effect("logcat -c"), Effect::ShellWrite, "clears the buffer");
        assert_eq!(
            effect("logcat -r 1000"),
            Effect::FileWrite,
            "rotates to a file"
        );
        assert_eq!(effect("sed -i 's/a/b/' /x"), Effect::FileWrite);
        assert_eq!(effect("sed 's/a/b/' /x"), Effect::ReadOnly);
        assert_eq!(effect("umount /system"), Effect::SystemWrite);
        assert_eq!(effect("mount /dev/x /y"), Effect::SystemWrite);
    }

    #[test]
    fn the_service_tools_are_decided_by_their_subcommand() {
        assert_eq!(effect("pm list packages"), Effect::ReadOnly);
        assert_eq!(
            effect("pm install /data/local/tmp/x.apk"),
            Effect::ShellWrite
        );
        assert_eq!(effect("pm clear com.example"), Effect::ShellWrite);
        assert_eq!(
            effect("settings get global airplane_mode_on"),
            Effect::ReadOnly
        );
        assert_eq!(
            effect("settings put global airplane_mode_on 1"),
            Effect::ShellWrite
        );
        assert_eq!(effect("am get-current-user"), Effect::ReadOnly);
        assert_eq!(effect("am start -n a/b"), Effect::ShellWrite);
        assert_eq!(
            effect("dumpsys -l"),
            Effect::ReadOnly,
            "dumpsys is not a dispatcher"
        );
    }

    #[test]
    fn selinux_mode_is_its_own_tier() {
        assert_eq!(effect("setenforce 0"), Effect::SelinuxChange);
        assert_eq!(
            effect("setenforce 0").capability(),
            Some(Capability::SelinuxPermissive)
        );
    }

    #[test]
    fn screencap_reads_or_writes_depending_on_the_argument() {
        assert_eq!(effect("screencap"), Effect::ReadOnly);
        assert_eq!(effect("screencap -p"), Effect::ReadOnly);
        assert_eq!(
            effect("screencap /sdcard/screen.png"),
            Effect::FileWrite,
            "§4.6.6's evidence capture writes a file"
        );
    }

    // ── Quoting, where a parser like this usually breaks ─────────────────────

    #[test]
    fn quoted_text_is_data_not_structure() {
        // `echo 'rm -rf /'` prints a string. A classifier that split on `;` before honouring
        // quotes would see a command that is not there.
        assert_eq!(effect("echo 'rm -rf /'"), Effect::ReadOnly);
        assert_eq!(effect("echo \"a;b|c&d\""), Effect::ReadOnly);
        assert_eq!(
            effect("cat '/data/local/tmp/my file.txt'"),
            Effect::ReadOnly
        );
        // The single-quote escape `quote_posix` produces: '\''
        assert_eq!(effect(r"cat '/data/local/tmp/it'\''s'"), Effect::ReadOnly);
    }

    #[test]
    fn a_script_that_cannot_be_read_is_not_guessed_at() {
        assert_eq!(effect("echo 'unterminated"), Effect::Opaque);
        assert_eq!(effect("echo \"unterminated"), Effect::Opaque);
        assert_eq!(
            effect("cat < /x"),
            Effect::ReadOnly,
            "input redirection reads"
        );
        assert_eq!(
            effect("cat << EOF\nsetprop a b\nEOF"),
            Effect::Opaque,
            "a here-document body is not seen"
        );
        assert_eq!(effect(""), Effect::ReadOnly, "does nothing");
        assert_eq!(effect("# only a comment\n"), Effect::ReadOnly);
        assert_eq!(effect("FOO=bar"), Effect::ReadOnly, "sets a shell variable");
    }

    #[test]
    fn an_unrecognised_command_is_opaque_rather_than_read_only() {
        // The default must be refusal. "Not on the list" is not "harmless".
        assert_eq!(effect("somevendortool --do-thing"), Effect::Opaque);
        assert!(
            first_finding("somevendortool --do-thing")
                .detail
                .contains("neither the read allow-list"),
            "the refusal must say why"
        );
    }

    #[test]
    fn findings_are_one_per_command_in_order() {
        let verdict = classify("getprop; setprop a b; logcat -d > /data/x");
        let commands: Vec<&str> = verdict
            .findings
            .iter()
            .map(|f| f.command.as_str())
            .collect();
        assert_eq!(commands, ["getprop", "setprop", "logcat"]);
        assert_eq!(verdict.strongest(), Effect::FileWrite);
        assert_eq!(
            verdict.offending(Effect::ReadOnly).unwrap().command,
            "setprop",
            "the first thing a refusal should name"
        );
    }

    #[test]
    fn a_request_outside_the_port_vocabulary_is_left_to_the_gate() {
        // Rule R5 refuses an unregistered capability. Producing a second, different refusal
        // here would make the same request fail two ways depending on call order.
        assert!(check("setprop a b", None).is_ok());
    }

    #[test]
    fn a_relative_write_target_belongs_to_a_directory_nobody_sees() {
        // `resolve_path` reads `./f` as `/f`, which is only true from `/`. The port does not know
        // where the shell is sitting, so it must not turn that unknown into an approval.
        for script in [
            "echo x > ./f",
            "echo x > f",
            "echo x > sub/f",
            "echo x > ../../system/f",
            "cp a b",
            "chmod 755 f",
            "dd if=./a of=./b",
        ] {
            let v = classify(script);
            assert_eq!(
                v.strongest(),
                Effect::Opaque,
                "`{script}` claims a destination the device picks"
            );
            assert_eq!(v.strongest().capability(), None);
        }
        // A relative *source* does not move the destination: `cp` is classified by what it
        // creates, and a mode word is not a file the command changes.
        assert_eq!(
            classify("cp ./a /data/local/tmp/b").strongest(),
            Effect::FileWrite
        );
        assert_eq!(
            classify("chmod 755 /system/bin/x").strongest(),
            Effect::SystemWrite
        );
        assert_eq!(
            classify("touch -t 202401010000 /data/local/tmp/f").strongest(),
            Effect::FileWrite
        );
        // Absolute spelling is still read normally, and `.` inside an absolute path still means
        // nothing: this is the same path from both sides of the fix.
        assert_eq!(
            classify("echo x > /data/local/tmp/f").strongest(),
            Effect::FileWrite
        );
        assert_eq!(
            classify("echo x > /data/local/tmp/./f").strongest(),
            Effect::FileWrite
        );
    }

    #[test]
    fn the_persistent_image_partitions_are_the_heavier_tier() {
        // /persist holds modem calibration and /odm the vendor overlay: neither is a user's file,
        // and neither was in the list this port grew out of a /system-and-/vendor reading.
        for script in [
            "printf %s x >> /persist/f",
            "echo x > /odm/overlay.apk",
            "echo x > /mnt/vendor/persist/f",
            "echo x > /dsp/firmware.bin",
            "echo x > /system/../persist/f",
        ] {
            assert_eq!(
                classify(script).strongest(),
                Effect::SystemWrite,
                "`{script}` writes a partition root"
            );
        }
        // Deleting them is banned outright, the way /system deletion is.
        assert_eq!(
            classify("rm -rf /persist/modem").strongest(),
            Effect::Banned
        );
        // The shell's own scratch is unaffected.
        assert_eq!(
            classify("rm -f /data/local/tmp/f").strongest(),
            Effect::FileWrite
        );
    }

    #[test]
    fn writing_inside_an_app_private_home_is_not_an_outside_app_write() {
        for script in [
            "echo x > /data/data/com.foo/databases/app.db",
            "echo x > /data/user/0/com.foo/shared_prefs/p.xml",
            "echo x > /data/user_de/0/com.foo/f",
        ] {
            assert_eq!(
                classify(script).strongest(),
                Effect::SystemWrite,
                "`{script}` needs more than the outside-app tier"
            );
        }
        // `/data/local/tmp` is the outside-app area the capability is named for, and a path that
        // merely *starts with* a root's name is not under it.
        assert_eq!(
            classify("echo x > /data/local/tmp/f").strongest(),
            Effect::FileWrite
        );
        assert_eq!(
            classify("echo x > /data/database.txt").strongest(),
            Effect::FileWrite
        );
    }
}
