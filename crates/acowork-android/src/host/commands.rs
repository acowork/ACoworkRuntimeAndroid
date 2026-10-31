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
//! # The refusals are decisions, and here is the list of them
//!
//! A sweep of 290 script shapes puts 86 of them at `Opaque`. That number means nothing unless
//! the 86 are named, because a refusal nobody wrote down is indistinguishable from a command
//! nobody thought about — which is exactly how `find` came to be refused for a whole release.
//! Each class below is a fact about the device or about the text, with the rule that follows
//! from it.
//!
//! | Refused | The fact | The rule |
//! |---|---|---|
//! | `sh -c`, `eval`, `xargs`, `env <cmd>`, `$(…)`, `awk -f`, `find -exec` | a second command runs that this classifier never sees | never look inside a nested interpreter |
//! | `tar -x`, `unzip`, `find -delete`, `rm $GLOB` | the file set is chosen by the device, or is named inside an archive | refuse rather than tier: no approval can name what is written, and the snapshot store cannot restore what it never saw |
//! | `awk` with `>`/`|`/`system()`/`getline` | the program can write files and run programs, and `>` is also its comparison operator | blacklist the letters; `awk '$1 > 5'` is refused with the redirect, and says so |
//! | `sed`/`awk`/`grep` where the script interpolates | `'{print $1}'` and `'{print $1}'$SUF` are the same word once the quotes are off | ask the raw text whether anything expands `has_unquoted_expansion` and withdraw the program-slot exemption if it does |
//! | `sqlite3` | SQL is a second language, and even a `SELECT` can write a `-wal`/`-journal` file next to the database | refused on purpose, not overlooked |
//! | `cd`, `export`, `alias`, `set`, `unset` | they change what the *later* words in the same script mean: `cd /data/data/com.x; cat db` reads a file whose path never appears, `export LD_PRELOAD` changes which binary a classified head is, `alias ls='rm -rf …'` runs something other than what was approved | refused; the read tier is a promise about this text, not about the shell's state |
//! | `ping`, `nslookup`, `getent` | no device state changes, but the script reaches the network, and this vocabulary has no capability for egress | refused until the capability exists — the upstream B2 registry question, not a classifier bug |
//! | `ifconfig wlan0` | measured: `ioctl 8927: Permission denied` at uid 2000 | left at the write tier its name carries; the device is the one refusing, so the classifier has no read shape to exempt |
//! | `zip`, `screenrecord`, `media`, bare `deviceidle`, `sqlite3` | absent from the one device this port has ground truth for (BLA-AL00, Android 10) | not tiered at all. A flag surface guessed from another vendor's build is how a classifier starts lying |
//!
//! The last row is the only one that is work rather than a decision: it needs a device that
//! has those binaries, and then the same procedure as `find`/`tar`/`unzip`/`awk` above —
//! read the usage text off the handset, admit the shapes that read, refuse the shapes that do
//! not, and put the measured line in the comment.
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
    /// Takes the contents of files that belong to another uid out of the app's containment.
    ///
    /// This is not a write, and it is not a free read either, which is why it is its own effect
    /// and not one of the two it sits between. §4.4 auto-passes reads because nothing changes;
    /// on the root tier `cat /data/data/<pkg>/databases/app.db` changes nothing on the device and
    /// still hands somebody else's database to the caller. The ledger has to know the difference:
    /// an undo list for a read is a phantom, and a teardown that reports "a change stays after
    /// the session" for a command that changed nothing teaches the operator to ignore the report.
    ///
    /// It is authorised by `android:fs:system` because this port's vocabulary has no app-data
    /// capability yet — that is question B2 of the upstream review. Borrowing the heaviest
    /// filesystem tier is the conservative direction: the cost is one approval the caller may not
    /// have needed, the alternative is a permission nobody asked for. It also means a disclosure
    /// read takes the device write lock, since the capability that covers it is a mutating one.
    ForeignRead,
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
            // The heaviest filesystem tier the port has, for a read: see the variant. When B2
            // gives this vocabulary an app-data capability, this arm is the one that changes.
            Effect::ForeignRead => Some(Capability::FsSystem),
            Effect::SystemWrite => Some(Capability::FsSystem),
            Effect::SelinuxChange => Some(Capability::SelinuxPermissive),
            Effect::Opaque | Effect::Banned => None,
        }
    }

    /// True when nothing is modified. This is the entire content of the auto-pass rule.
    pub fn is_read_only(self) -> bool {
        matches!(self, Effect::ReadOnly)
    }

    /// True when the device is different afterwards.
    ///
    /// Not the same question as [`is_read_only`](Effect::is_read_only), and the difference is
    /// [`Effect::ForeignRead`]: reading another uid's files leaves the device exactly as it was
    /// and still needs an approval. The rollback ledger asks this one — a command that changes
    /// nothing has no inverse to plan, and filing one anyway would put a phantom in the teardown
    /// report. The gate asks the other: what has to be claimed.
    ///
    /// Stated as [`state_effect`](Effect::state_effect) rather than as its own list of variants,
    /// so the two cannot drift into disagreeing about the same command.
    pub fn changes_state(self) -> bool {
        self.state_effect() != Effect::ReadOnly
    }

    /// This effect with any disclosure taken out of it.
    ///
    /// The rollback ledger compares it against the files it managed to snapshot: when the
    /// approval is heavier than every one of them, something changed that no file name describes,
    /// and the session has to be told. A disclosure is not that.
    /// `cp /data/data/com.foo/db /sdcard/db` was reporting "changes something the file names do
    /// not describe" for a copy whose destination the ledger had just backed up, because the
    /// heavier half of its effect was about *reading* the source.
    ///
    /// Projecting to [`ReadOnly`](Effect::ReadOnly) loses a write that the disclosure outranked —
    /// and that write is exactly the one the ledger already snapshotted, which is why the
    /// comparison it feeds is against captured files rather than against nothing.
    pub fn state_effect(self) -> Effect {
        match self {
            Effect::ReadOnly | Effect::ForeignRead => Effect::ReadOnly,
            other => other,
        }
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
    // Asked of the raw text, once, because the answer is not in the words: see
    // `has_unquoted_expansion`.
    let expandable = has_unquoted_expansion(script);
    Verdict {
        findings: match lex(script).and_then(split) {
            Ok(commands) => commands
                .iter()
                .map(|command| analyse(command, expandable))
                .collect(),
            Err(opaque) => vec![opaque],
        },
    }
}

/// Does this script hold a `$` or a backtick that the shell would expand — one that is not
/// inside single quotes?
///
/// The classifier reads words *after* the lexer has taken their quotes off, so `'{print $1}'` and
/// `'{print $1}'$SUF` are the same word: both contain a `$`. They are not the same fact. In the
/// first the `$` is awk's field marker and nothing expands; in the second the shell substitutes
/// `$SUF` into the program before awk ever sees it, so the program the device runs is not the one
/// anybody read. That is why the read tier may treat a `$` inside a sed script or an awk program
/// as syntax rather than as a path with a hole in it only when this says nothing expands: the
/// exemption is bought with a fact the token itself cannot give.
///
/// A `$` inside double quotes counts as expanding, because it does. `\$` does not, because the
/// backslash is what it says it is.
fn has_unquoted_expansion(script: &str) -> bool {
    let mut single_quoted = false;
    let mut escaped = false;
    for c in script.chars() {
        if escaped {
            escaped = false;
            continue;
        }
        match c {
            '\\' if !single_quoted => escaped = true,
            '\'' => single_quoted = !single_quoted,
            '$' | '`' if !single_quoted => return true,
            _ => {}
        }
    }
    false
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
    pub redirects: Vec<String>,
}

/// The script's commands *and* every file their output goes to.
///
/// [`words`] alone is not enough for a rollback planner: `echo x > /data/local/tmp/hosts`
/// changes a file that appears nowhere in the argument vector, and a planner that cannot see
/// the target cannot snapshot it. The redirections are read from the same `Command` the
/// classifier used, so the tier decision and the rollback decision cannot disagree about
/// which files a script touched — including the `cmd > a > b` case, where it touched two.
pub fn parsed(script: &str) -> Option<Vec<ParsedCommand>> {
    let commands = lex(script).and_then(split).ok()?;
    Some(
        commands
            .into_iter()
            .map(|command| ParsedCommand {
                redirects: command.writes().into_iter().map(str::to_string).collect(),
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
            '(' => {
                return Err(Finding::opaque(
                    c.to_string(),
                    "subshells are not analysed; run the inner command as its own request so it \
                     can be classified",
                ));
            }
            ')' => {
                return Err(Finding::opaque(
                    c.to_string(),
                    "a closing `)` with no subshell open — the script is not one this classifier \
                     can read",
                ));
            }
            // `{` and `}` are reserved words only when they stand alone: POSIX requires the braces
            // to be separate words for `{ cmd; }` to group. As an argument they are literal text,
            // and `find -exec rm {} +` and `xargs -I{}` are the shapes that hit this. Reading
            // them as a group refused the command for the wrong reason — the tier was already the
            // safe one, but the sentence a human reads in the audit log was not.
            '{' | '}' if stands_alone(&chars) => {
                return Err(Finding::opaque(
                    c.to_string(),
                    "a brace group is not analysed; run the inner command as its own request so \
                     it can be classified",
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

/// Whether the character at the front of `chars` is a whole word on its own.
///
/// This is POSIX's reserved-word test, and it is what separates `{ cat x; }` — a brace group —
/// from the `{}` in `find -exec rm {} +`, which is a literal argument the command substitutes.
/// The classifier cannot tell them apart by the character alone, and getting it wrong produced a
/// refusal whose stated reason was false.
fn stands_alone<I: Iterator<Item = char> + Clone>(chars: &std::iter::Peekable<I>) -> bool {
    let mut after = chars.clone();
    after.next();
    matches!(
        after.peek(),
        None | Some(' ') | Some('\t') | Some('\n') | Some(';') | Some('|') | Some('&')
    )
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
            '(' | ')' => break,
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
    let mut outputs: Vec<String> = Vec::new();

    let mut flush = |words: &mut Vec<String>, outputs: &mut Vec<String>| {
        if !words.is_empty() || !outputs.is_empty() {
            commands.push(Command {
                words: std::mem::take(words),
                outputs: std::mem::take(outputs),
            });
        }
    };

    for tok in toks {
        match tok {
            Tok::Break => flush(&mut words, &mut outputs),
            Tok::Word(w) => words.push(w),
            // Every redirection is kept, not the last one seen. `cmd > a > b` truncates `a`
            // and sends stdout to `b`: two files change, and a classifier that read only one
            // would approve a script whose second write it had never mentioned.
            Tok::Out { target } => outputs.push(target),
        }
    }
    flush(&mut words, &mut outputs);
    Ok(commands)
}

/// One command: its words and every file its output goes to.
#[derive(Debug)]
struct Command {
    words: Vec<String>,
    outputs: Vec<String>,
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

    /// Redirection targets that actually write something a reader could find.
    fn writes(&self) -> Vec<&str> {
        self.outputs
            .iter()
            .map(String::as_str)
            .filter(|target| !names_no_file(target) && !target.starts_with('&'))
            .collect()
    }
}

/// True when a write target is a bit bucket rather than a file anybody can read back.
///
/// `/dev/null` discards and `/dev/zero` reads zeroes; neither leaves a state for the ledger to
/// restore or a tier for an approval to name. The redirection reader has always dropped them, and
/// `dd of=` used to keep them — which made `dd of=/dev/null` cost `fs:system` (the whole of `/dev`
/// is a partition root) while `echo x > /dev/null` cost nothing. One rule, both places.
fn names_no_file(target: &str) -> bool {
    target == "/dev/null" || target == "/dev/zero"
}

/// The files a `dd` names as its destination: every `of=` value, minus the bit buckets.
///
/// Every `of=` and not the first: a copy can name more than one destination, and returning on the
/// first match is the same reflex that had `cp` classify a source. Discard destinations are
/// dropped for the reason in [`names_no_file`]. Both the tier decision and the rollback ledger ask
/// this question, and a second implementation of it is how `dd of=/dev/null` came to cost
/// `fs:system` in one and a snapshot of the node in the other.
fn dd_targets(args: &[String]) -> Vec<&str> {
    args.iter()
        .filter_map(|a| a.strip_prefix("of="))
        .filter(|t| !names_no_file(t))
        .collect()
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

fn analyse(command: &Command, expandable: bool) -> Finding {
    let Some(raw_head) = command.head() else {
        // Nothing but assignments, or a bare redirection.
        return match redirect_effect(command) {
            Some((effect, targets)) => Finding::new("", effect, format!("redirects to {targets}")),
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
                    outputs: command.outputs.clone(),
                };
                let finding = analyse(&inner_command, expandable);
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
    let own = effect_of(&head, command.args(), expandable);
    let mut finding = match redirect_effect(command) {
        Some((redirect, targets)) => {
            let detail = if own.effect == Effect::ReadOnly {
                format!("redirects its output to {targets}")
            } else {
                format!("redirects its output to {targets}, and {}", own.detail)
            };
            Finding::new(head, redirect.max(own.effect), detail)
        }
        None => own,
    };

    // Reading a file that belongs to another uid is not a read this port passes unattended. The
    // read tier is auto-approved by design (§4.4), which is only safe while "read" means
    // something the shell is entitled to see: on a root-tier device `cat
    // /data/data/<pkg>/databases/app.db` succeeds, and before this it cost nothing and was
    // logged as an ordinary read. The same rule covers the exfiltration shape — `cp` decides its
    // tier by the destination, so a copy *out* of an app's home was a light write with no word
    // about what it read.
    //
    // The same argument covers a raw block device: writing one is on the §4.6.3 hard-ban list,
    // and reading `/dev/block/mmcblk0` opens every app's home through one argument while the read
    // tier passed it unattended.
    //
    // It is its own effect and not a heavier write, because the two questions the port asks about
    // a command are not the same question: what has to be claimed to run it, and what the ledger
    // has to put back afterwards. This one changes the answer to the first and not the second.
    if !matches!(finding.effect, Effect::Banned | Effect::Opaque) {
        let reached = {
            // A path this command is already tiering as its destination is not also a disclosure
            // read. `cp report.pdf /sdcard/report.pdf` writes into the media tree and takes
            // nothing out of it, and calling that a disclosure would put the commonest automation
            // shape behind the heaviest filesystem tier this vocabulary has. Sources stay in the
            // scan — `cp /sdcard/x /data/local/tmp/y` is the copy that moves a photo where the
            // caller can read it back.
            let destinations: Vec<String> = command
                .writes()
                .into_iter()
                .map(str::to_string)
                .chain(
                    file_writes(&command.words)
                        .unwrap_or_default()
                        .into_iter()
                        .map(|write| write.path),
                )
                .map(|target| super::script::resolve_path(&target))
                .collect();
            command
                .args()
                .iter()
                .filter_map(|a| path_in_token(a))
                .filter(|a| !destinations.contains(&super::script::resolve_path(a)))
                .find_map(|a| disclosure_read(a).map(|why| (a, why)))
        };
        if let Some((path, what)) = reached {
            finding.effect = finding.effect.max(Effect::ForeignRead);
            finding.detail = format!(
                "{}; reads `{path}`, which is not something the read tier was ever entitled to \
                 see — {what}. Nothing on the device changes, so it is a disclosure and not a \
                 write, and this port has no app-data capability to ask for yet, so it costs the \
                 heaviest filesystem tier it has instead of the tier that would have passed it \
                 unattended",
                finding.detail,
            );
        }
    }
    finding
}

/// What a read of this `/proc` entry says about somebody else's process, if it reads one.
///
/// The port cannot ask which uid owns a pid without a device round trip, so the rule is lexical
/// and errs the conservative way: a numbered process directory is somebody's process, and the
/// caller says so to the operator. `/proc/self` and `/proc/thread-self` are the reader's own and
/// stay at the read tier, and `/proc/meminfo` or `/proc/cpuinfo` — the system's own statistics,
/// which is what the evidence surface actually reads — are not under a pid at all.
fn inspectable_path(path: &str) -> Option<&'static str> {
    const SENSITIVE: &[(&str, &str)] = &[
        (
            "environ",
            "the environment of a process the caller does not own, where tokens sit",
        ),
        (
            "mem",
            "the live memory of a process the caller does not own",
        ),
        (
            "smaps",
            "every mapping of a process the caller does not own",
        ),
        (
            "smaps_rollup",
            "every mapping of a process the caller does not own",
        ),
        (
            "pagemap",
            "the page table of a process the caller does not own",
        ),
        (
            "maps",
            "the address layout of a process the caller does not own",
        ),
        (
            "cmdline",
            "the arguments a process was started with, which are often secrets",
        ),
        ("fd", "the open files of a process the caller does not own"),
    ];
    let path = super::script::resolve_path(path);
    let rest = path.strip_prefix("/proc/")?;
    let mut segments = rest.split('/');
    let process = segments.next()?;
    // A numbered process directory is somebody's process; a glob over them is the enumeration of
    // all of them, which is the wider disclosure rather than a reason to pass it.
    let named_process = !process.is_empty() && process.chars().all(|c| c.is_ascii_digit());
    let globbed_process = process.contains(['*', '?', '[']);
    if !(named_process || globbed_process) {
        return None;
    }
    let entry = segments.next()?;
    SENSITIVE
        .iter()
        .find(|(name, _)| *name == entry)
        .map(|(_, why)| *why)
}

/// The tier all of a command's redirections cost, and the sentence naming them.
///
/// `None` when the command redirects nothing a reader could find (`/dev/null`, or `>&2`), which
/// leaves the command's own effect to decide alone.
fn redirect_effect(command: &Command) -> Option<(Effect, String)> {
    let targets = command.writes();
    if targets.is_empty() {
        return None;
    }
    let effect = targets.iter().map(|t| file_effect(t)).max()?;
    let named = targets
        .iter()
        .map(|t| format!("`{t}`"))
        .collect::<Vec<_>>()
        .join(" and ");
    Some((effect, named))
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

/// How a command changes a file it names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileChange {
    /// The bytes in the file are different afterwards. A content snapshot is a real undo.
    Content,
    /// Ownership, mode, timestamp or label — the bytes are the same. A content snapshot would
    /// "restore" a file that was never changed in that way and leave the metadata alone, so the
    /// ledger is told not to offer one.
    Metadata,
    /// The name goes away. Its bytes can be put back, but not its inode, owner or mtime, so the
    /// undo is honest only with `faithful: false` attached.
    Deletion,
}

/// One file a command changes, and what happens to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileWrite {
    /// The path as the script spells it. Resolving it is the caller's job, and the rollback
    /// planner needs the raw spelling to decide whether it can name the file at all.
    pub path: String,
    /// What the command does to it, which decides whether a content snapshot is an honest undo.
    pub change: FileChange,
}

/// Which files a command changes, and how — or `None` when the port cannot say.
///
/// This is the same operand-role reasoning the tier decision uses (`looks_like_path`,
/// `flag_destination`, `written_targets`), not a second reading of the arguments: the rollback
/// planner asks this question instead of re-deriving "which operand is the destination", because
/// a planner that decides that for itself is how a script ends up approved as one file and
/// restored as another. `None` is a real answer and means the command is not one whose operands
/// this port reads as files at all — `echo` with a redirection, an unknown binary, a wrapper.
pub fn file_writes(words: &[String]) -> Option<Vec<FileWrite>> {
    let head_index = words.iter().position(|w| !is_assignment(w))?;
    let head = normalise(&words[head_index]);
    let args: Vec<String> = words[head_index + 1..].to_vec();
    // A multiplexer is its subcommand: `toybox cp a b` changes the same file as `cp a b`.
    if matches!(head.as_str(), "toybox" | "busybox") {
        let inner = args.first()?;
        if inner.starts_with('-') {
            return None;
        }
        let mut inner_words = vec![inner.clone()];
        inner_words.extend(args.iter().skip(1).cloned());
        return file_writes(&inner_words);
    }
    let paths: Vec<&str> = args
        .iter()
        .filter(|a| !a.starts_with('-') && looks_like_path(a))
        .map(String::as_str)
        .collect();
    let flag = |f: &str| args.iter().any(|a| a.starts_with('-') && a.contains(f));
    let operands: Vec<&str> = args
        .iter()
        .filter(|a| !a.starts_with('-'))
        .map(String::as_str)
        .collect();

    let writes: Vec<(String, FileChange)> = match head.as_str() {
        "dd" => dd_targets(&args)
            .into_iter()
            .map(|t| (t.to_string(), FileChange::Content))
            .collect(),
        "sed" if flag("i") => {
            // Same refusal as the tier decision: `-e` interleaves expressions with file names, so
            // which operand gets rewritten cannot be told apart, and the first operand is the
            // script rather than a file.
            if operands.len() < 2
                || args
                    .iter()
                    .any(|a| a.starts_with("-e") || a.starts_with("--expression"))
            {
                return None;
            }
            operands[1..]
                .iter()
                .map(|f| (f.to_string(), FileChange::Content))
                .collect()
        }
        "mv" => {
            let mut v = Vec::new();
            if let Some(dir) = flag_destination(&head, &args) {
                v.push((dir, FileChange::Content));
            }
            for (index, operand) in operands.iter().enumerate() {
                let last_of_two =
                    flag_destination(&head, &args).is_none() && index == operands.len() - 1;
                if last_of_two {
                    v.push((operand.to_string(), FileChange::Content));
                } else {
                    v.push((operand.to_string(), FileChange::Deletion));
                }
            }
            v
        }
        "cp" | "ln" | "install" => {
            let mkdir_style =
                head == "install" && args.iter().any(|a| a == "-d" || a == "--directory");
            if mkdir_style {
                operands
                    .iter()
                    .map(|o| (o.to_string(), FileChange::Metadata))
                    .collect()
            } else if let Some(dir) = flag_destination(&head, &args) {
                vec![(dir, FileChange::Content)]
            } else {
                written_targets(&head, &operands)
                    .unwrap_or_default()
                    .into_iter()
                    .map(|t| (t.to_string(), FileChange::Content))
                    .collect()
            }
        }
        "rm" | "unlink" | "rmdir" => paths
            .iter()
            .map(|p| (p.to_string(), FileChange::Deletion))
            .collect(),
        "chmod" | "chown" | "chgrp" | "chattr" | "touch" | "mkdir" | "chcon" | "restorecon"
        | "setcontext" => paths
            .iter()
            .map(|p| (p.to_string(), FileChange::Metadata))
            .collect(),
        "logcat" => flag_value(&args, &["-f", "--file"])
            .map(|path| vec![(path, FileChange::Content)])
            .unwrap_or_default(),
        // `screencap FILE` — the capture is the file. The tier decision already reads the first
        // non-flag operand as the destination; the ledger has to agree with it, or a capture into
        // the media tree looks like a read of the media tree to the disclosure rule below.
        "screencap" => operands
            .first()
            .map(|o| vec![(o.to_string(), FileChange::Content)])
            .unwrap_or_default(),
        // `tar -c -f ARCHIVE` — the archive is the file it writes, read through the same helper
        // the tier decision uses so the two cannot drift apart. Listing and extracting report
        // nothing: `-t` writes no file, and `-x` is refused by the classifier before the ledger
        // is ever asked, because the names it writes live inside the archive. Reporting the
        // archive as a *destination* for `tar -tf /data/data/x/a.tar` would also have removed it
        // from the disclosure scan below, which reads the operand list for exactly that path.
        "tar" => match tar_operation(&args).0 {
            TarOperation::Create => tar_archive(&args)
                .map(|path| vec![(path, FileChange::Content)])
                .unwrap_or_default(),
            _ => Vec::new(),
        },
        "sort" => flag_value(&args, &["-o", "--output"])
            .map(|path| vec![(path, FileChange::Content)])
            .unwrap_or_default(),
        // `uniq INPUT [OUTPUT]`: the ledger has to know about the output the same way the
        // classifier does, or a deduplicated copy of `/system/build.prop` is approved and then
        // restored as nothing at all.
        "uniq" => match uniq_operands(&args).as_slice() {
            [_, output] => vec![(output.clone(), FileChange::Content)],
            _ => Vec::new(),
        },
        "tee" | "truncate" => paths
            .iter()
            .map(|p| (p.to_string(), FileChange::Content))
            .collect(),
        _ => return None,
    };
    if writes.is_empty() {
        return None;
    }
    Some(
        writes
            .into_iter()
            .map(|(path, change)| FileWrite { path, change })
            .collect(),
    )
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
    } else if is_partition_path(path) || is_private_data_path(path) {
        Effect::SystemWrite
    } else {
        Effect::FileWrite
    }
}

/// The one directory under `/data` that belongs to the calling uid.
///
/// Measured on the BLA-AL00 as uid 2000: `/data/local/tmp` is `drwxrwx--x shell shell` and the
/// harness writes, lists and removes there freely (§11 and §12 of the device probe are built on
/// it). Everything else under `/data` is somebody else's: `/data/anr` is `drwxrwxr-x system`
/// with a root-owned trace file in it that this uid can open (measured: `head -c 24
/// /data/anr/dumptrace_MdvzVC` prints `crash_dump failed to dum`), and `/data/system` lists even
/// though its files are `0660`.
const OWN_DATA: &str = "/data/local/tmp";

/// Paths that belong to a uid other than the caller.
///
/// Two questions use this, and they are the same question: writing into one changes someone
/// else's files, and reading one takes their contents out. The rule is the data root minus the
/// one directory the caller owns, rather than a list of homes, because the list was always going
/// to be one directory short: `/data/anr` and `/data/tombstones` were left out on the assumption
/// that the device refuses them, and on this device it does not — a root-owned ANR trace is
/// readable at the tier that asks for nothing.
///
/// `/data` itself counts: `ls /data` names no single app but enumerates every app's home, which
/// is the same disclosure one level up.
fn is_private_data_path(path: &str) -> bool {
    let path = super::script::resolve_path(path);
    let path = path.trim_end_matches('/');
    path == "/data"
        || (path.starts_with("/data/")
            && path != OWN_DATA
            && !path.starts_with(&format!("{OWN_DATA}/")))
}

/// The device owner's own files, as distinct from another app's or the system's.
///
/// Measured as uid 2000 on the BLA-AL00: `/sdcard` and `/sdcard/DCIM` both list, and what they
/// list is the camera roll and the messaging apps' media. This is the read-side rule only —
/// creating a file under `/sdcard` is exactly what `android:fs:outside-app` was granted for, and
/// the capability's name says so — but *taking those files out* is a disclosure, and the read
/// tier was never asked about it. `/data/media` is the same tree under its bind-mount source, and
/// `/storage` is where the per-user mounts live.
const MEDIA_ROOTS: &[&str] = &["/sdcard", "/storage", "/mnt/sdcard", "/data/media"];

fn is_user_media_path(path: &str) -> bool {
    let path = super::script::resolve_path(path);
    MEDIA_ROOTS
        .iter()
        .any(|root| path == *root || path.starts_with(&format!("{root}/")))
}

/// What a read of this path takes out of the device that the read tier was never entitled to.
///
/// `Some` names the exposure in the sentence the operator reads; `None` means the read tier
/// answers for it. Four families, asked in one place because they are one question — *whose*
/// data is this, not *has it changed* — and because a caller that has to remember three predicates
/// is a caller that adds the fourth path to only two of them.
fn disclosure_read(path: &str) -> Option<&'static str> {
    if let Some(why) = inspectable_path(path) {
        return Some(why);
    }
    if is_block_device(path) {
        return Some(
            "it is the partition itself rather than a file on it: every app's home, every \
             message and every photo is readable through this one argument",
        );
    }
    if is_private_data_path(path) {
        return Some("it belongs to another uid");
    }
    if is_user_media_path(path) {
        return Some(
            "it is the device owner's own files — the camera roll, the downloads, the \
             messaging apps' media",
        );
    }
    None
}

/// True when a directory has one of those homes below it, so a pattern centred there can expand
/// into it: `/data/*/com.foo/db` is confined to `/data`, and `/data` contains every app's home.
/// `/data/local/tmp` and its children are the caller's own and stay confined to nothing.
fn contains_private_data(directory: &str) -> bool {
    let directory = super::script::resolve_path(directory);
    directory == "/"
        || is_private_data_path(&directory)
        || is_private_data_path(&format!("{directory}/anything"))
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

/// The operands `uniq` is pointed at, minus the values its own flags carry separately.
///
/// `-f N` and `-w N` take a number as their next token, and a token of all digits is a field
/// count for this command rather than a file: no path a caller would hand `uniq` is spelled as
/// bare digits. Kept next to the classifier's rule so the tier decision and the ledger's snapshot
/// cannot drift apart on how many operands this command is seen to have.
fn uniq_operands(args: &[String]) -> Vec<String> {
    args.iter()
        .filter(|a| !a.starts_with('-') && !a.chars().all(|c| c.is_ascii_digit()))
        .cloned()
        .collect()
}

/// The destination a move/copy/link/install request carries in a flag, if it carries one.
///
/// `-t DIR` and `--target-directory=DIR`, glued or separate. The guard is scoped to those four
/// commands on purpose: `touch -t 202401010000 file` uses the same letters for a timestamp, and
/// reading that as a directory would be the classifier inventing a rule the command does not have.
///
/// Whether this toybox implements `-t` is a device fact nobody has measured here, and the
/// classification does not wait for it. Reading the flag costs the port nothing it cannot defend:
/// the answer is the *heavier* tier of the directory the flag names, so a caller needs
/// `fs:system` to move files into `/system` either way — and a device that ignores `-t` fails the
/// write instead of performing one nobody was told about. Refusing to read it, the previous
/// behaviour, was safe but told the operator nothing about a destination written in plain text.
fn flag_destination(head: &str, args: &[String]) -> Option<String> {
    if !matches!(head, "cp" | "mv" | "ln" | "install") {
        return None;
    }
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if let Some(dir) = arg.strip_prefix("--target-directory=") {
            return Some(dir.to_string());
        }
        if arg == "-t" || arg == "--target-directory" {
            return iter.next().cloned();
        }
        if arg.starts_with("-t") && arg.len() > 2 && arg.as_bytes()[2] == b'/' {
            return Some(arg[2..].to_string());
        }
    }
    None
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

/// The path a token carries, with any `key=` / `--flag=` / glued-short-flag prefix removed.
///
/// Two operand grammars hide a path behind something that is not a path: `dd
/// if=/dev/block/mmcblk0` and `grep --file=/proc/1/environ`. Each names a file the shell really
/// opens, and neither token starts with a separator, so every predicate that compares the *whole*
/// token against `/data/data/`, `/dev/block/` or a `/proc/<pid>/` prefix misses it. This is not a
/// hypothetical spelling: on the BLA-AL00 `dd if=<file> of=<file>` copies it (`4 bytes (4 B)
/// copied`) and toybox `sort -T <dir>` accepts a directory (exit 0), so a rule that only reads
/// bare operands silently passes the wider read.
///
/// `Some` is a candidate, not a verdict — the caller still decides whether it is a path and what
/// it reaches. The reader is deliberately broad: `--color=/usr/share/x` produces a candidate too.
/// The cost of an extra candidate is one more approval; the cost of a missed one is the whole
/// partition read at the tier that needs no approval.
fn path_in_token(token: &str) -> Option<&str> {
    if let Some((_, value)) = token.split_once('=')
        && (value.starts_with('/') || value.starts_with('.'))
    {
        return Some(value);
    }
    if token.starts_with('/') || token.starts_with('.') {
        return Some(token);
    }
    if let Some(rest) = token.strip_prefix('-') {
        // A short flag with its value glued on: `-T/system/tmp`, `-f/data/data/x`. The flag's own
        // letters are dropped and what follows is the candidate.
        let tail = rest.trim_start_matches(|c: char| c.is_alphabetic() || c == '-');
        if tail.starts_with('/') || tail.starts_with('.') {
            return Some(tail);
        }
    }
    None
}

/// The value a flag carries, in its separate (`-o FILE`), glued (`-oFILE`) or `=` (`--output=FILE`)
/// form.
///
/// All three spellings are accepted because all three work on the shell this port targets, and a
/// classifier that reads only the separate form answers "filter" to `sort -o/system/x`. The first
/// non-empty value wins: a script naming two output files is a script whose last write is the one
/// that matters, and `sort` does not take two — this is not a general multi-flag reader.
fn flag_value(args: &[String], names: &[&str]) -> Option<String> {
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        for name in names {
            if arg == *name {
                // The separate form: `-o FILE`. A flag that carries no value carries no
                // destination either, and the loop simply moves on.
                if let Some(value) = iter.next()
                    && !value.is_empty()
                {
                    return Some(value.clone());
                }
                continue;
            }
            // The `=` form, which `--output` takes and a short flag does not.
            let glued = format!("{name}=");
            if let Some(value) = arg.strip_prefix(glued.as_str())
                && !value.is_empty()
            {
                return Some(value.to_string());
            }
            // Short flags only glue without `=`: `-o/system/x`.
            if !name.starts_with("--") && arg.starts_with(*name) && arg.len() > name.len() {
                let value = &arg[name.len()..];
                if !value.is_empty() {
                    return Some(value.to_string());
                }
            }
        }
    }
    None
}

/// True when a sed program carries a `w FILE` or `r FILE` command — a file named inside the
/// script text rather than in the operand list.
///
/// A program is a `;`- and newline-separated list of commands, and `w`/`r` name a file when they
/// *begin* one (`w /tmp/x`), when they follow the closing delimiter of the command before them
/// (`s/a/b/w /tmp/x`), or when they do that without even the space (`s/a/b/w/tmp/x`). The
/// delimiter count in the last of the three is what keeps `s/a/w/` — a substitution *to* the
/// letter — out of the refused pile: a `w` after the third `/` has nothing left to substitute.
///
/// Approximate in the safe direction on purpose. A program that trips it is refused even when it
/// writes nothing, because the alternative is deciding what a sed program does with something that
/// is not a sed parser, and an approval that names `/data/local/tmp/x` in front of a write to
/// `/system/y` is the failure this module has now been asked to avoid five times.
fn script_names_a_file(program: &str) -> bool {
    program.split(['\n', ';']).any(|command| {
        let trimmed = command.trim_start();
        // A command that *begins* with the letter: `w /tmp/x`, `w/tmp/x`.
        let leading = matches!(trimmed.chars().next(), Some('w' | 'r'))
            && trimmed[1..]
                .chars()
                .next()
                .is_some_and(|next| matches!(next, ' ' | '\t' | '/'));
        // The same command attached to the end of the one before it, with the file after a space:
        // `s/a/b/w /tmp/x`, `/x/w /tmp/x`.
        let attached = ["/w ", "/r ", "/w\t", "/r\t"]
            .iter()
            .any(|needle| trimmed.contains(needle));
        // And attached without the space (`s/a/b/w/tmp/x`), which sed accepts. The two checks
        // above cannot see it, and `s/a/w/` — a substitution *to* the letter — looks identical
        // until the delimiters are counted: a `w` is only a command when it follows the third
        // `/`, because the third one is what closes the substitution.
        let glued = trimmed.match_indices('/').nth(2).is_some_and(|(index, _)| {
            let rest = &trimmed[index + 1..];
            matches!(rest.chars().next(), Some('w' | 'r')) && rest[1..].starts_with('/')
        });
        leading || attached || glued
    })
}
///
/// This is `destination`'s question asked of a read: the same three shapes — expansion (`$F`,
/// `` ` `` , `~`), a path that is not anchored at the root, and a glob whose directory sits above
/// another uid's home — mean the file is chosen by the device after the approval was given.
///
/// Only an operand that *begins* like a path is asked. `contains('/')` would be the obvious test
/// and it is wrong: it reads `sed`'s `s/a/b/` expression, a `content://` URI and a `com.foo/bar`
/// component name as files, and turns ordinary reads into refusals. The cost is that a relative
/// path spelled without its `./` (`cat data/local/tmp/x`) stays a read — see the note in the
/// read-list branch for why the port does not guess at those.
/// The operand that carries a *program* or a *pattern* rather than a file: sed's and awk's
/// script, grep's pattern. This is the slot the "path the device picks" rule has been refusing
/// ever since it was written, and it is not a path — `sed '$d'` is the commonest one-liner in
/// sed, `grep '$'` prints the non-empty lines, and each begins with the very character that
/// means "unbounded" for a file.
///
/// `None` — no exemption — as soon as a flag makes an operand a file after all: `-f FILE` reads
/// the program or the pattern list out of a file, and `-e` interleaves expressions with file
/// names, which is why `sed -i` with `-e` is refused rather than guessed at.
///
/// The caller withdraws this exemption for a script that expands anything: see
/// `has_unquoted_expansion`.
fn program_slot(head: &str, args: &[String]) -> Option<usize> {
    if !matches!(head, "sed" | "awk" | "grep" | "egrep" | "fgrep") {
        return None;
    }
    if args.iter().any(|a| {
        matches!(a.as_str(), "-f" | "--file" | "-e" | "-regexp" | "--regexp")
            || (a.starts_with("-f") || a.starts_with("-e")) && a.len() > 2 && !a.starts_with("--")
    }) {
        return None;
    }
    args.iter().position(|a| !a.starts_with('-'))
}

/// The first operand that is not a flag and not the value of a flag that takes one.
fn first_operand(args: &[String]) -> Option<String> {
    let mut skip_value = false;
    for arg in args {
        if skip_value {
            skip_value = false;
            continue;
        }
        if arg == "-v" || arg == "--assign" {
            skip_value = true;
            continue;
        }
        if arg.starts_with('-') {
            continue;
        }
        return Some(arg.clone());
    }
    None
}

fn unbounded_read_operand(operand: &str) -> bool {
    if operand.starts_with('-') {
        return false;
    }
    // A token that *is* a substitution — `$F`, `` `id` ``, `~root/.ssh/id_rsa` — names a path
    // nobody can read off the text, and that is the fact this rule exists for. A `$` in the
    // *middle* of a word is a different fact: it is awk's field syntax in `{print $1}`, sed's
    // end-of-line anchor in `s/foo$//`, and grep's pattern `'$'`, and all three take their most
    // important operand as a program or a pattern rather than as a file. Treating every `$` as a
    // path hole refused the commonest use of each of them.
    //
    // What is left of the risk is covered twice over: a path that merely *contains* a hole is
    // still caught below, because `destination` cannot bound `/data/$F/x` and returns Unknown;
    // and an awk or sed program that writes or execs is caught by its own branch, which reads
    // the program text rather than guessing at the operand's type.
    if operand.starts_with(['$', '`', '~']) {
        return true;
    }
    let anchored = operand.starts_with('/')
        || operand.starts_with("./")
        || operand.starts_with("../")
        || operand == "."
        || operand == "..";
    if !anchored {
        return false;
    }
    match destination(operand) {
        Destination::Known(_) => false,
        Destination::Bounded { directory } => contains_private_data(&directory),
        Destination::Unknown => true,
    }
}

fn written_targets<'a>(head: &str, operands: &[&'a str]) -> Option<Vec<&'a str>> {
    match head {
        "cp" | "ln" | "install" if operands.len() > 1 => operands.last().copied().map(|t| vec![t]),
        "mv" if operands.len() > 1 => Some(operands.to_vec()),
        "cp" | "ln" | "mv" | "install" => None,
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

/// The five actions this device's `find` accepts that are not a search. Read off its own usage
/// text, measured on the BLA-AL00: `Actions: -print -print0 -exec -execdir -ok -okdir -delete`.
/// Every other option it takes is a match filter or a print, and `find` has no `-fprint`/`-fls`
/// the GNU one has, so this list is complete for the binary that was asked.
const FIND_ACTIONS_THAT_WRITE: &[&str] = &["-delete", "-exec", "-execdir", "-ok", "-okdir"];

/// The letters this device's `tar` accepts in an option cluster, measured from
/// `tar -[cxtjzhmvO] [-X FILE] [-T FILE] [-f TARFILE] [-C DIR]`.
const TAR_CLUSTER_LETTERS: &str = "cxtjzhmvOfFXCT";

/// Which of `tar`'s three operations a call asks for.
enum TarOperation {
    /// `t` — print the archive's index. Reads the archive, writes nothing.
    List,
    /// `c` — build an archive: writes the one file `-f` names, or stdout when there is none.
    Create,
    /// `x` — unpack: writes as many files as the archive holds, under names stored inside it.
    Extract,
    /// The arguments do not spell an operation this port recognises. Refused rather than
    /// defaulted: a command that sits on the read list would otherwise inherit "read" for an
    /// option nobody modelled, which is a hole with a name on it.
    Unclear,
}

/// The operation and whether `-O`/`--to-stdout` redirects whatever it does to the caller.
///
/// The cluster is read with or without its leading dash because this device accepts both —
/// `tar -tf a.tar` and `tar tvf a.tar` listed the same archive when asked.
fn tar_operation(args: &[String]) -> (TarOperation, bool) {
    let mut ops: Vec<char> = Vec::new();
    let mut to_stdout = false;
    for (index, arg) in args.iter().enumerate() {
        let letters = if let Some(long) = arg.strip_prefix("--") {
            match long.split('=').next().unwrap_or("") {
                "list" => "t".to_string(),
                "extract" | "get" => "x".to_string(),
                "create" => "c".to_string(),
                "to-stdout" => {
                    to_stdout = true;
                    String::new()
                }
                _ => return (TarOperation::Unclear, to_stdout),
            }
        } else if let Some(rest) = arg.strip_prefix('-') {
            rest.to_string()
        } else if index == 0
            && !arg.is_empty()
            && arg.chars().all(|c| TAR_CLUSTER_LETTERS.contains(c))
        {
            // Only the first argument can be a dashless cluster. After that a bare word is a
            // file name, and `tar cvf a.tar txt` must not read `txt` as three options.
            arg.clone()
        } else {
            continue;
        };
        for letter in letters.chars() {
            if letter == 'f' {
                // The rest of the cluster is the archive's name, not more options. Measured on
                // the BLA-AL00: `tar -czf/data/local/tmp/a.tar td` creates that file, and a
                // classifier that read the whole tail as option letters would call the call
                // unrecognisable and refuse a write it can name exactly.
                break;
            }
            if matches!(letter, 'c' | 'x' | 't') {
                ops.push(letter);
            } else if letter == 'O' {
                to_stdout = true;
            } else if !TAR_CLUSTER_LETTERS.contains(letter) {
                return (TarOperation::Unclear, to_stdout);
            }
        }
    }
    let mut ops = ops.into_iter();
    let Some(first) = ops.next() else {
        return (TarOperation::Unclear, to_stdout);
    };
    // Two different operations in one call is not a shape with one answer, and picking the
    // lighter of the two is the mistake this module keeps making.
    if ops.any(|other| other != first) {
        return (TarOperation::Unclear, to_stdout);
    }
    let op = match first {
        't' => TarOperation::List,
        'c' => TarOperation::Create,
        _ => TarOperation::Extract,
    };
    (op, to_stdout)
}

/// The archive `tar` was told to write or read, from `-f` — which arrives as its own word
/// (`-f a.tar`), at the end of a cluster with the name next (`-czf a.tar`), or glued inside it
/// (`-czfa.tar`). `-` is stdin/stdout and is not a file this port can name or snapshot.
fn tar_archive(args: &[String]) -> Option<String> {
    for (index, arg) in args.iter().enumerate() {
        if let Some(value) = arg.strip_prefix("--file=") {
            if !value.is_empty() && value != "-" {
                return Some(value.to_string());
            }
            continue;
        }
        let glued = arg.starts_with('-') || index == 0;
        let cluster = arg.strip_prefix('-').unwrap_or(arg);
        if !glued || cluster.is_empty() {
            continue;
        }
        // Only the option letters *before* the `f` are recognised as options; everything after it
        // is the name. A bare word further along is a file being added to the archive, and
        // reading it as `-f` would name the wrong destination.
        let Some((prefix, tail)) = cluster.split_once('f') else {
            continue;
        };
        if !prefix.chars().all(|c| TAR_CLUSTER_LETTERS.contains(c)) {
            continue;
        }
        if !tail.is_empty() {
            return (tail != "-").then(|| tail.to_string());
        }
        let next = args.get(index + 1)?;
        if next != "-" {
            return Some(next.clone());
        }
    }
    None
}

/// What an awk program does besides filter text, as far as a reader that does not parse awk can
/// tell. Measured on the device's awk: `print "x" > "f"` and `print $1 > "f"` both created a
/// file, `BEGIN{system("touch f")}` created one, and `BEGIN{"echo hi" | getline x}` ran a program.
///
/// `>` is also awk's comparison operator, so `awk '$1 > 5'` is refused with the rest of them.
/// The port cannot tell a redirect from a comparison without a second parser, and the two shapes
/// this module has already refused for that reason — `sed`'s `w` command, every `NESTED`
/// interpreter — cost the caller a narrower question than a wrong approval costs anybody.
fn awk_effect(program: &str) -> Option<&'static str> {
    const CONSTRUCTS: &[(&str, &str)] = &[
        (
            ">",
            "a `>`, which is either a redirect to a file or a comparison — this port does not \
             parse awk programs to tell them apart, and a file written from inside the program \
             is one no approval named",
        ),
        (
            "|",
            "a `|`, which in awk is a pipe to a command (awk has no bitwise-or for the same \
             letters to be confused with)",
        ),
        (
            "system(",
            "a `system()` call, which runs whatever string the program holds",
        ),
        (
            "getline",
            "a `getline`, which reads from a file or a pipe the operand list never mentions",
        ),
    ];
    CONSTRUCTS
        .iter()
        .find(|(needle, _)| program.contains(needle))
        .map(|(_, why)| *why)
}

/// The inline program text of an `awk` call: the first operand that is not a flag and not the
/// value of a `-v` assignment. `-f FILE` is handled by the caller — that program is in a file
/// this classifier does not open.
fn awk_program(args: &[String]) -> Option<String> {
    first_operand(args)
}

fn effect_of(head: &str, args: &[String], expandable: bool) -> Finding {
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
        let targets = dd_targets(args);
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

    // `ip` sits in the write vocabulary by name, and most of that is right — `ip link set eth0
    // down` takes the interface away. But its report shapes were measured on the BLA-AL00 at uid
    // 2000 as plain reads: `ip addr show`, `ip route show` and `ip link` each printed state and
    // changed nothing. The word after the object decides which of the two this call is.
    //
    // Only the objects whose every listing form is a read are exempted, and everything else —
    // `ip -4 route add`, `ip neigh replace`, an object this port does not know — keeps the tier
    // the name already carries.
    if head == "ip" {
        const OBJECTS: &[&str] = &[
            "addr", "address", "a", "route", "r", "link", "l", "neigh", "n", "rule",
        ];
        const REPORTS: &[&str] = &["show", "list", "get", "help"];
        let words: Vec<&str> = args
            .iter()
            .map(|a| a.as_str())
            .filter(|a| !a.starts_with('-'))
            .collect();
        if matches!(words.first().copied(), Some(object) if OBJECTS.contains(&object)) {
            match words.get(1).copied() {
                None => {
                    return Finding::new(
                        head,
                        Effect::ReadOnly,
                        "reports addresses, routes, links or neighbours",
                    );
                }
                Some(word) if REPORTS.contains(&word) => {
                    return Finding::new(
                        head,
                        Effect::ReadOnly,
                        "reports addresses, routes, links or neighbours",
                    );
                }
                Some(word) => {
                    return Finding::new(
                        format!("ip {} {word}", words[0]),
                        Effect::ShellWrite,
                        "changes network configuration — §4.4 puts this behind approval",
                    );
                }
            }
        }
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
                // `-f` names the file the log goes to, so it is tiered by that file:
                // `logcat -f /system/build.prop` is not an outside-app write, and hard-coding the
                // answer here is the same mistake `sed -i` made until it was tiered by its file.
                // The glued spelling (`-f/system/log`) is read too, because it works on this
                // shell and a classifier that only sees the separate form calls it a file write
                // into nowhere.
                // `-r` on its own is a rotation *size*, not a path, and is left at the file tier
                // it has always been given.
                if let Some(path) = flag_value(args, &["-f", "--file"]) {
                    let effect = file_effect(&path);
                    return Finding::new(head, effect, format!("writes the log to `{path}`"));
                }
                return Finding::new(
                    head,
                    Effect::FileWrite,
                    "writes the log to a file (-r rotates to a file, -f names it)",
                );
            }
        }
        if head == "sed" {
            // The same fact as awk: a script that expands cannot be read for its `w`/`r`
            // commands, because the text that reaches sed is not the text that was looked at.
            if expandable
                && let Some(script) = first_operand(args)
                && script.contains(['$', '`'])
            {
                return Finding::opaque(
                    head,
                    "the shell expands something inside the script text, so the script sed runs                      is not the one this port read",
                );
            }
            // sed's `w FILE` command writes matching lines to a file named *inside the script*,
            // and `r FILE` reads one in. Neither is in the operand list, so neither was ever
            // tiered: `sed '/x/w /system/y' f` sat on the read allow-list and wrote a partition.
            // The port does not parse sed programs — the same call as refusing to guess which
            // operand `sed -e` rewrites — so a script that carries one of those commands is
            // refused. Guessing the filename is the failure mode this module keeps hitting: an
            // approval that names `/data/local/tmp/x` and a write that lands in `/system`.
            if let Some(script) = args
                .iter()
                .filter(|a| !a.starts_with('-'))
                .find(|a| script_names_a_file(a))
            {
                return Finding::opaque(
                    head,
                    format!(
                        "its script `{script}` carries a `w` or `r` command, which names a file \
                         inside the script text; this port does not parse sed programs, so the \
                         file it writes is not one anybody was shown"
                    ),
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
        if head == "sort" {
            // `-o FILE` is the output file and `-T DIR` is where the temporary files go. `sort`
            // is on the read list because it is a filter, and neither of those is a filter:
            // `sort -o /system/x f` was asking the tier that auto-passes to put a partition file
            // in place, and `sort -T /system/tmp f` writes there for the duration of a sort of
            // anything large enough to need a temp file. Both flags are accepted by this toybox —
            // `-T` measured at exit 0 on the BLA-AL00.
            let output = flag_value(args, &["-o", "--output"]);
            let scratch = flag_value(args, &["-T", "--temporary-directory"]);
            // A program `sort` runs to compress its temp files. The classifier does not run
            // programs named in arguments: `NESTED` only inspects the command word, so this is
            // the one place a program can be smuggled in as a value. Refused rather than
            // reasoned about — this toybox rejects `--compress` outright, so the rule costs
            // nothing on the tier measured and covers the GNU `sort` a Termux host installs.
            if flag_value(args, &["--compress-program", "--compress"]).is_some()
                || args
                    .iter()
                    .any(|a| a == "-Z" || a.starts_with("-Z") && a.len() > 2)
            {
                return Finding::opaque(
                    head,
                    "its `--compress-program` names a program for `sort` to run, and that is a \
                     second command this classifier never sees; run it as its own request",
                );
            }
            match (output, scratch) {
                (Some(out), Some(dir)) => {
                    let effect = file_effect(&out).max(file_effect(&dir));
                    return Finding::new(
                        head,
                        effect,
                        format!(
                            "writes the sorted output to `{out}` and its scratch files to `{dir}`"
                        ),
                    );
                }
                (Some(out), None) => {
                    return Finding::new(
                        head,
                        file_effect(&out),
                        format!("writes the sorted output to `{out}`"),
                    );
                }
                (None, Some(dir)) => {
                    return Finding::new(
                        head,
                        file_effect(&dir),
                        format!("writes its temporary files to `{dir}`"),
                    );
                }
                (None, None) => {}
            }
        }
        if head == "uniq" {
            // `uniq INPUT [OUTPUT]` — the output is a positional operand, not a flag, which is
            // why the read allow-list missed it: every other filter on that list takes at most
            // one file. Two operands mean the second one is created.
            //
            // A bare number is skipped because `-f N` and `-w N` carry theirs as a separate
            // token, and no filename this command is pointed at is spelled as digits alone. A
            // relative output is not a known destination: it lands in a working directory nobody
            // observes, so `file_effect` answers Opaque rather than guessing the tier.
            let operands: Vec<String> = uniq_operands(args);
            match operands.as_slice() {
                [] | [_] => {}
                [_, output] => {
                    return Finding::new(
                        head,
                        file_effect(output),
                        format!("writes the deduplicated output to `{output}`"),
                    );
                }
                [_input, _output, _extra @ ..] => {
                    return Finding::opaque(
                        head,
                        format!(
                            "it names {} files, and `uniq` takes an input and an output; which \
                             one is written is not decided here",
                            operands.len()
                        ),
                    );
                }
            }
        }
        if head == "date" {
            // `date` prints, unless it is being told what the clock should read. `-s`, and the
            // classic positional form (`date 010100002026`), set the system time; `date -u` and
            // `date +FORMAT` only print. The clock is device-global and nothing snapshots it, so
            // this is a write whatever the caller intended.
            if let Some(value) = flag_value(args, &["-s", "--set"]) {
                return Finding::new(
                    head,
                    Effect::ShellWrite,
                    format!("sets the system clock to `{value}`"),
                );
            }
            // A bare operand that is neither a `+FORMAT`, an `@EPOCH` nor a flag is the positional
            // form of the same instruction.
            if let Some(value) = args
                .iter()
                .find(|a| !a.starts_with(['-', '@', '+']) && !a.is_empty())
            {
                return Finding::new(
                    head,
                    Effect::ShellWrite,
                    format!("sets the system clock to `{value}`"),
                );
            }
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
        // A path argument to `dumpsys` is not input. The command takes a service name and flags,
        // and some services accept a file to *write* — `dumpsys SurfaceFlinger --screenshot
        // <file>` being the shape that reaches for a path. On this device the flag is ignored
        // outright (measured on the BLA-AL00: `--screenshot`, `--screen` and `--screenshot=` all
        // leave no file behind), so the rule costs nothing here and answers the question the
        // newer build does. `screencap` is the same shape and was already modelled; leaving this
        // one at the read tier would mean two commands, two answers, one file.
        if head == "dumpsys"
            && let Some(target) = args.iter().find(|a| a.starts_with('/'))
        {
            return Finding::new(
                head,
                file_effect(target),
                format!(
                    "`dumpsys` reads no file argument — `{target}` is somewhere a service was \
                     asked to put something"
                ),
            );
        }
        // `find` is the commonest way to look at a filesystem, and this port refused every use of
        // it: the word was on no list at all, so `find /sdcard -name '*.txt'` — a search that
        // opens nothing for write — cost the caller an approval for a tier it could not be given.
        // What makes `find` unsafe is its actions, and the device's usage text names five; the
        // search itself falls through to the read tier with the rest of them.
        //
        // `-delete` is refused rather than tiered as a file write on purpose. The files it removes
        // are the ones the device matched while running, so no approval could have named them
        // beforehand and the snapshot store cannot put back what it never saw — the same fact that
        // refuses `rm $GLOB`. `-exec` and its three siblings run a program this classifier never
        // looks inside, which is the `NESTED` rule again.
        if head == "find"
            && let Some(action) = args
                .iter()
                .find(|a| FIND_ACTIONS_THAT_WRITE.contains(&a.as_str()))
        {
            return Finding::opaque(
                head,
                format!(
                    "`{action}` is one of the actions this device's `find` has that change the \
                     filesystem or run a program the classifier never sees; the search is a read, \
                     so run what it prints as its own request"
                ),
            );
        }
        if head == "tar" {
            let (operation, to_stdout) = tar_operation(args);
            match operation {
                TarOperation::List => {}
                TarOperation::Create => {
                    // The archive is the file. Without `-f` the archive goes to stdout, which
                    // writes nothing on the device and is bounded by the output cap like any
                    // other read; with it, the tier is the tier of that path.
                    if let Some(archive) = tar_archive(args) {
                        let effect = file_effect(&archive);
                        return Finding::new(
                            head,
                            effect,
                            format!("writes an archive to `{archive}`"),
                        );
                    }
                }
                TarOperation::Extract if to_stdout => {}
                TarOperation::Extract => {
                    return Finding::opaque(
                        head,
                        "unpacking writes one file per archive member, under names stored \
                         inside the archive — the approval cannot list them beforehand and the \
                         snapshot store cannot restore what it never saw. `tar -xO` sends them \
                         to stdout instead, which writes nothing",
                    );
                }
                TarOperation::Unclear => {
                    return Finding::opaque(
                        head,
                        "its operation is not one of the three this port recognises (`t` list, \
                         `c` create, `x` extract), and a command on the read list does not get to \
                         be a read just because nobody modelled the flags it was given",
                    );
                }
            }
        }
        // Measured usage on the BLA-AL00: `unzip [-d DIR] [-lnopqv] ZIP [FILE...] [-x FILE...]`.
        // `-l` and `-v` print the index and `-p` prints one member to stdout — all three read the
        // archive and touch nothing. Everything else, including the default and including `-n`,
        // `-o` and `-d`, which only say *how* to extract, writes the members out under the names
        // stored inside the archive: the `tar -x` problem, with the same answer.
        if head == "unzip" {
            let letters: String = args
                .iter()
                .filter_map(|a| a.strip_prefix('-'))
                .filter(|a| !a.starts_with('-'))
                .flat_map(|a| a.chars())
                .collect();
            if !letters.contains(['l', 'v', 'p']) {
                return Finding::opaque(
                    head,
                    format!(
                        "it extracts (`{letters}` selects no listing flag, and `-n`/`-o`/`-d` \
                         only change how extraction writes), which puts one file per archive \
                         member on the device under names stored inside it. `unzip -l` lists \
                         without writing"
                    ),
                );
            }
        }
        // `awk` is on the read list for the same reason `sed` is: most of the time it is a filter
        // over text. Unlike `sed`, its program can also open files and run programs, and the
        // letters involved are the ones its comparison operators use, so the check is a blacklist
        // that errs by refusing — see `awk_effect` for what was measured and what is over-refused.
        if head == "awk" {
            if args
                .iter()
                .any(|a| a == "-f" || a == "--file" || a.starts_with("-f"))
            {
                return Finding::opaque(
                    head,
                    "its program is in a file this classifier does not open, so what it writes \
                     is whatever that file says",
                );
            }
            if let Some(program) = awk_program(args) {
                // The construct blacklist reads the program text. That is only the text awk will
                // receive if nothing in it expands first, so a script that both interpolates and
                // puts a `$` in the program is refused rather than guessed at.
                if expandable && program.contains(['$', '`']) {
                    return Finding::opaque(
                        head,
                        "the shell expands something inside the program text, so the program                          awk runs is not the one this port read",
                    );
                }
                if let Some(why) = awk_effect(&program) {
                    return Finding::opaque(head, format!("its program carries {why}"));
                }
            }
        }
        if head == "top" {
            // `top` is `ps` refreshed forever: the ADR already auto-passes `ps`, so the process
            // table is not the objection. The objection is a command that never returns — the
            // read tier that passed it would sit on the command timeout for the whole budget.
            let one_cycle = args
                .iter()
                .any(|a| a == "-b" || a.starts_with("-n") || a == "--batch");
            if !one_cycle {
                return Finding::opaque(
                    head,
                    "it refreshes forever unless `-b` or `-n` asks for a fixed number of cycles, \
                     and a read that never returns spends the whole command timeout on nothing; \
                     run `top -n 1`",
                );
            }
        }
        // A read is only free while the port can say *what* is being read. The write side has
        // refused unbounded operands since `destination` was written; the read side is where that
        // asymmetry mattered, because the read tier is the one §4.4 auto-passes. `cat $F` is a
        // read of a path the device picks after the approval, and `cat ./db` is a read relative
        // to a working directory this port never sees — either one is also how the private-data
        // rule in `analyse` gets walked around: `F=/data/data/com.foo/db` costs nothing to set.
        //
        // A bare word, or a relative path spelled without its `./` (`cat data/local/tmp/x`), is
        // deliberately not escalated. It is indistinguishable from the arguments the same
        // commands take that are not files at all — the pattern in `grep secret /data/anr`, the
        // count in `head -n 5 /data/local/tmp/x`, `sed`'s script expression — and guessing at
        // those would refuse the common reads to catch the rare one. It only reaches past the
        // read tier if the working directory is somebody's home, and the working directory comes
        // from the request, not from the script: a caller that pins it into an app's home has
        // already said so in its own call. A script cannot move there on its own — `cd` is not on
        // the read list, and `cd /data/data/com.foo && cat db` is refused as an unknown command.
        let slot = if expandable {
            None
        } else {
            program_slot(head, args)
        };
        if let Some(operand) = args
            .iter()
            .enumerate()
            .filter(|(index, _)| Some(*index) != slot)
            .map(|(_, arg)| arg)
            .find(|a| unbounded_read_operand(a))
        {
            return Finding::opaque(
                head,
                format!(
                    "`{head}` reads `{operand}`, which the port cannot bound: a variable, a home \
                     directory, a path relative to an unseen working directory, or a pattern that \
                     can expand into another uid's files"
                ),
            );
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
        // A destination carried in a flag is read, not refused: `mv -t /system x` writes
        // `/system`, and the operand list alone would describe it as writing `x`.
        let flag_dest = flag_destination(head, args);
        // `install -d` is mkdir with a mode; every operand it names is a directory it creates.
        let mkdir_style = head == "install" && args.iter().any(|a| a == "-d" || a == "--directory");
        let targets = match flag_dest.as_deref() {
            Some(dir) => {
                let mut targets = vec![dir];
                // `mv` also unlinks what it moves, so both sides of every operand belong to the
                // tier the operation touches — the same rule as a positional `mv`.
                if head == "mv" {
                    targets.extend(operands.iter().copied());
                }
                Some(targets)
            }
            None if mkdir_style => {
                if operands.is_empty() {
                    None
                } else {
                    Some(operands.clone())
                }
            }
            None => written_targets(head, &operands),
        };
        let Some(targets) = targets else {
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

    // Relabelling is a metadata write *to a file*, so it is tiered by that file rather than by
    // the verb. `chcon … /system/bin/sh` and `chmod 777 /system/bin/sh` change inodes in the same
    // partition; before this, one of them needed `fs:system` and the other needed only
    // `android:shell:write`, which is a difference in spelling and not in what happens to the
    // device. The security context argument is deliberately not read as a path — it is a label,
    // and counting it would invent a write the command does not perform.
    if matches!(head, "chcon" | "restorecon" | "setcontext") {
        let paths: Vec<&str> = args
            .iter()
            .filter(|a| !a.starts_with('-') && looks_like_path(a))
            .map(String::as_str)
            .collect();
        let Some(effect) = paths.iter().map(|p| file_effect(p)).max() else {
            return Finding::opaque(
                head,
                "the file whose label it changes is not named, so the port cannot say which \
                 partition is being written",
            );
        };
        return Finding::new(
            head,
            effect,
            format!("changes the SELinux label of `{}`", paths.join("`, `")),
        );
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
    if head == "content" {
        return content_provider(args);
    }
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
    // `cmd` is a multiplexer, so the first word is a *service* and the verb belongs to the
    // service: `cmd appops get com.android.shell` asks `get`, and `cmd package list packages`
    // asks `list`. Both printed state on the BLA-AL00 at uid 2000 while the classifier refused
    // them for the service's name — the same over-refusal `find` carried, one level up.
    //
    // Only `cmd` does this. `pm install` and `settings put` name their own verb first, and
    // reading a second word there would let `pm install -f /data/x` be excused by an argument.
    if head == "cmd" {
        let mut rest = args
            .iter()
            .filter(|a| !a.starts_with('-'))
            .skip(1)
            .peekable();
        let Some(verb) = rest.next() else {
            // `cmd package` on its own prints that service's usage, which is what `pm` with no
            // subcommand already answers: harmless, and refusing it punishes a caller for asking
            // for help.
            return Finding::new(
                format!("{head} {sub}"),
                Effect::ReadOnly,
                "names a service and no verb, which prints that service's usage",
            );
        };
        let verb = verb.to_ascii_lowercase();
        if READ_SUBCOMMANDS
            .iter()
            .any(|prefix| verb.starts_with(prefix))
        {
            return Finding::new(
                format!("{head} {sub} {verb}"),
                Effect::ReadOnly,
                "read-only subcommand",
            );
        }
        // A second word that is not a verb either (`cmd appops com.android.shell`) is the
        // service's own argument, and the service was not a read: it stays where it was.
        return Finding::new(
            format!("{head} {sub} {verb}"),
            Effect::ShellWrite,
            "is a mutating subcommand — §4.4 puts these behind approval",
        );
    }
    Finding::new(
        format!("{head} {sub}"),
        Effect::ShellWrite,
        "is a mutating subcommand — §4.4 puts these behind approval",
    )
}

/// The content authorities whose rows are the device's own configuration rather than a person's.
///
/// This is an exception list, not a block-list, and the direction matters: a block-list would have
/// to name every app installed on the handset, and the one provider nobody thinks to name is the
/// one that holds the messages. Measured on the BLA-AL00 as uid 2000 — no root, no dangerous
/// mode — `content query --uri content://sms/` printed real message bodies and
/// `content://contacts/people` printed real contact names, both at the tier §4.4 passes without
/// asking. The path rules cannot see this: the sensitive thing is the URI, not an operand that
/// starts with a separator.
const PUBLIC_AUTHORITIES: &[&str] = &["settings", "deviceinfo"];

/// `content` reads and writes another app's data through its provider.
///
/// Reading a personal provider is the same disclosure as `cat /data/data/<pkg>/databases/app.db`
/// — the row contents leave the containment without anything on the device changing — and writing
/// one is a change inside somebody else's home, which the file rules already put at the heaviest
/// filesystem tier this vocabulary has (question B2 of the upstream review is the app-data
/// capability that would replace both borrowings).
fn content_provider(args: &[String]) -> Finding {
    let Some(sub) = args.iter().find(|a| !a.starts_with('-')) else {
        return Finding::new(
            "content",
            Effect::ReadOnly,
            "run without a subcommand, prints usage",
        );
    };
    let named = format!("content {sub}");
    let reads = READ_SUBCOMMANDS
        .iter()
        .any(|prefix| sub.to_ascii_lowercase().starts_with(prefix));
    let Some(authority) = uri_authority(args) else {
        // No URI, or one this reader cannot take apart (`--uri $PROVIDER`, a variable the device
        // resolves after the approval). Which provider is named is the whole question, so a
        // script that does not say it cannot be passed as a read.
        return Finding::new(
            named,
            Effect::Opaque,
            "names no content URI this classifier can read, so which provider is touched is \
             not known",
        );
    };
    if PUBLIC_AUTHORITIES.iter().any(|p| authority.starts_with(p)) {
        return Finding::new(
            named,
            if reads {
                Effect::ReadOnly
            } else {
                Effect::ShellWrite
            },
            if reads {
                "reads the device's own configuration provider"
            } else {
                "is a mutating subcommand — §4.4 puts these behind approval"
            },
        );
    }
    Finding::new(
        named,
        if reads {
            Effect::ForeignRead
        } else {
            Effect::SystemWrite
        },
        format!(
            "reaches the `{authority}` provider, which is not the caller's own data — the URI, \
             not a path, is what names the person's messages, contacts or files here"
        ),
    )
}

/// The authority a `content` URI names: the segment after `content://`, up to the next `/`.
fn uri_authority(args: &[String]) -> Option<String> {
    let uri = flag_value(args, &["--uri"])?;
    let authority = uri.strip_prefix("content://")?;
    let authority = authority
        .split('/')
        .next()
        .unwrap_or_default()
        .trim_end_matches('/');
    (!authority.is_empty()).then(|| authority.to_string())
}

/// §4.6.3 item 3: refused regardless of tier. This text is what the caller sees.
const BANNED_TEXT: &str =
    "it is on the hard-ban list (ADR-AND-001 §4.6 item 3), which no capability authorises";

/// Service tools whose first non-flag argument decides whether anything changes.
/// The service dispatchers, where the first argument decides: `pm list packages` reads,
/// `pm install` does not.
///
/// `appops` and `deviceidle` are here because both exist as their own binaries on the BLA-AL00
/// (`/system/bin/appops`, and `cmd deviceidle` for the other) and both take a verb: `appops get
/// com.android.shell` printed that uid's modes when asked, and `appops set` would have changed
/// them. Naming the verb is the only difference between them, which is exactly what this list is
/// for.
const DISPATCHERS: &[&str] = &[
    "pm",
    "am",
    "settings",
    "cmd",
    "wm",
    "svc",
    "ime",
    "content",
    "appops",
    "deviceidle",
];

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
    // Measured on the BLA-AL00 as present in `/system/bin`, and tiered by their arguments in
    // `effect_of` rather than by their name alone: each of these has a shape that writes, and the
    // shape is what is refused. They were on no list at all before, which meant a pure search or
    // a pure listing cost the caller an approval for a tier it could not be given.
    "find",
    "tar",
    "unzip",
    "awk",
    "top",
    "sleep",
    "printenv",
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
    "install",
    "unlink",
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
///
/// Exact roots only. `rm -fr /data/data/com.foo` is one app clearing its own home — the same
/// thing `pm clear` does, and approvable. `rm -fr /data/data` is every app's home at once, which
/// is the destruction the ban already covers one level up, reached by a path the ban list did not
/// name. The same argument holds for `/data/system`, where the package list, the users and the
/// account state live: deleting it does not need a partition, it needs the framework's own home.
///
/// The framework homes are therefore every *first-level* directory under `/data` — `/data/anr`,
/// `/data/app`, `/data/tombstones` and the rest of the set the device probe listed (measured on
/// the BLA-AL00: all of them system- or root-owned) — except `local`, which is the shell's own
/// area and where this port keeps its scratch.
fn is_destructive_root(path: &str) -> bool {
    let path = super::script::resolve_path(path);
    if ["/", "/data", "/sdcard", "/storage"]
        .iter()
        .any(|root| path == *root)
    {
        return true;
    }
    let Some(first) = path.strip_prefix("/data/") else {
        return false;
    };
    !first.is_empty() && !first.contains('/') && first != "local"
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

    #[test]
    fn a_read_the_port_cannot_bound_is_not_a_read_it_can_pass_free() {
        // §4.4 auto-passes reads, which is only safe while the port can say what was read. These
        // four shapes are the ones that made the answer "whatever the device picks": an
        // expansion, a path relative to an unseen working directory, a home reference, and a
        // pattern centred on `/data` — the directory every app's home sits in.
        for script in [
            "cat $F",
            "cat `which db`",
            "cat ~/db",
            "cat ./db",
            "cat ../db",
            "cat /data/*/com.foo/db",
            "head -n 5 ./db",
            "sha256sum $HOME/db",
        ] {
            assert_eq!(effect(script), Effect::Opaque, "{script}");
            assert!(
                check(script, None).is_err(),
                "{script} must not auto-pass at the read tier"
            );
        }
        // And the reads the same rule must leave alone. Each of these is a real shape from the
        // port's own scripts and from the harness, and each names a file the port can see.
        // `cat /proc/*/cmdline` left this list when the process-inspection rule landed: a glob
        // over pids reads every process's launch arguments, which is the disclosure that rule is
        // about. `/proc/*/attr/current` stays, because it is what the port's own fact probe runs
        // and it names an SELinux context rather than something anybody keeps secret.
        // `cat /data/anr/*` and `grep -r secret /data/anr` left with the widened data rule: the
        // directory holds another process's stack, so a glob over it is the disclosure and no
        // longer something the read tier passes unattended.
        for script in [
            "cat /data/local/tmp/x",
            "cat '/data/local/tmp/my file.txt'",
            "cat /proc/*/attr/current",
            "head -n 5 /data/local/tmp/x",
            "sed 's/a/b/' /data/local/tmp/x",
            "ls /data/local/tmp",
            "dumpsys window",
            "content query --uri content://settings/system",
        ] {
            assert_eq!(effect(script), Effect::ReadOnly, "{script}");
            assert!(
                check(script, Some(Capability::ShellRead)).is_ok(),
                "{script} must keep auto-passing without approval"
            );
        }
    }

    #[test]
    fn a_content_uri_names_a_person_not_a_path() {
        // The disclosure rules are lexical and read paths. `content` puts the sensitive thing in
        // the URI, so none of them could see this: measured on the BLA-AL00 as uid 2000, with no
        // root and no dangerous mode, `content query --uri content://sms/` printed real message
        // bodies and `content://contacts/people` printed real contact names — at the tier §4.4
        // passes without asking, and logged as a read.
        for script in [
            "content query --uri content://sms/",
            "content query --uri content://sms/inbox --projection body",
            "content query --uri=content://mms",
            "content query --uri content://contacts/people --projection name",
            "content query --uri content://call_log/calls",
            "content query --uri content://com.foo.provider/secrets",
            "content read --uri content://media/external/images/media/12",
        ] {
            assert!(
                matches!(effect(script), Effect::ForeignRead | Effect::SystemWrite),
                "{script} must not be a free read: {:?}",
                effect(script)
            );
            assert!(
                check(script, Some(Capability::ShellRead)).is_err(),
                "{script} must not auto-pass at the read tier"
            );
        }
        // Writing into another app's provider is a change inside somebody else's home, which the
        // file rules already cost the heaviest filesystem tier this vocabulary has.
        assert_eq!(
            effect("content insert --uri content://sms/ --bind body:s:hi"),
            Effect::SystemWrite
        );
        // The device's own configuration provider stays a read: this is the shape the port's
        // evidence surface uses.
        assert_eq!(
            effect("content query --uri content://settings/system"),
            Effect::ReadOnly
        );
        assert!(
            check(
                "content query --uri content://settings/system",
                Some(Capability::ShellRead)
            )
            .is_ok(),
            "and it must keep auto-passing"
        );
        // Which provider is touched is the whole question, so a URI the reader cannot take apart
        // is not a read the port can pass.
        for script in [
            "content query --uri $PROVIDER",
            "content query --uri tel://12345",
            "content query",
        ] {
            assert_eq!(effect(script), Effect::Opaque, "{script}");
        }
    }

    #[test]
    fn reading_another_uids_files_is_not_free() {
        // The write side has needed `fs:system` for an app's home since the partition table was
        // fixed; the read side was still calling the same file a free read, which on the root
        // tier is a copy of somebody's database into the open with no approval and one log line
        // saying "read".
        //
        // It costs `fs:system` because that is the heaviest filesystem tier this vocabulary has
        // (question B2 of the upstream review is the app-data capability that would replace it),
        // and it is a *disclosure* rather than a write because the device is unchanged either way.
        for script in [
            "cat /data/data/com.foo/databases/app.db",
            "ls /data/data",
            "ls /data/system",
            "head -c 100 /data/user/0/com.foo/files/x",
            "grep -r token /data/misc",
            "cat /data/data/com.foo/db > /data/local/tmp/out",
            "cp /data/data/com.foo/db /sdcard/db",
        ] {
            assert_eq!(effect(script), Effect::ForeignRead, "{script}");
            assert!(
                check(script, Some(Capability::FsOutsideApp)).is_err(),
                "{script} must not be covered by the capability whose name says outside app data"
            );
            assert!(
                check(script, Some(Capability::FsSystem)).is_ok(),
                "{script} is covered by the tier that is actually being claimed"
            );
        }
        // Writing into one of those trees is still the heavier thing it always was: the tier
        // answers what has to be put back, and a deletion answers it as a write, not a read.
        assert_eq!(effect("rm -fr /data/data/com.foo"), Effect::SystemWrite);
        assert_eq!(
            effect("cp /sdcard/x /data/data/com.foo/y"),
            Effect::SystemWrite
        );
        // The boundary of the rule is the uid, not the word "data": `/data/local/tmp` is this
        // uid's own (measured: `drwxrwx--x shell shell`, and the device probe writes, lists and
        // removes there in §11 and §12), and a `..` that walks back into it stays an ordinary path.
        for script in [
            "cat /data/local/tmp/x",
            "ls /data/local/tmp",
            "cat /data/misc/../local/tmp/x",
            "cat /data/local/tmp/../tmp/x",
        ] {
            assert_eq!(effect(script), Effect::ReadOnly, "{script}");
        }
        // What the widened rule changed. The old list of homes left `/data/anr` and `/data` out on
        // the assumption that the device refuses them; on this device it does not — `/data/anr`
        // lists (measured: three names) and the root-owned trace in it opens (`head -c 24
        // /data/anr/dumptrace_MdvzVC` printed `crash_dump failed to dum`). An ANR trace is another
        // process's stack, with its arguments and its allocations, which is the disclosure this
        // tier exists to name.
        for script in [
            "cat /data/anr/trace_00",
            "ls /data/anr",
            "cat /data/anr/dumptrace_MdvzVC",
            "ls /data",
            "cat /data/tombstones/x.pb",
            "ls /data/app",
            "cat /data/vendor/wifi/wpa_supplicant.conf",
        ] {
            assert_eq!(effect(script), Effect::ForeignRead, "{script}");
        }
        // The device owner's own files are a different exposure from another app's, and the write
        // side must not borrow it: saving a report where the user can open it is exactly what
        // `android:fs:outside-app` was granted for.
        for script in [
            "cat /sdcard/DCIM/Camera/img.jpg",
            "ls /sdcard",
            "head -c 10 /storage/emulated/0/Download/x.pdf",
        ] {
            assert_eq!(effect(script), Effect::ForeignRead, "{script}");
        }
        for script in [
            "echo x > /sdcard/report.txt",
            "cp /data/local/tmp/a.pdf /sdcard/a.pdf",
            "tee /sdcard/log.txt",
            "rm -rf /sdcard/Download/x",
            "screencap /sdcard/screen.png",
        ] {
            assert_eq!(effect(script), Effect::FileWrite, "{script}");
            assert!(
                check(script, Some(Capability::FsOutsideApp)).is_ok(),
                "{script} is the write the outside-app tier was named for"
            );
        }
    }

    #[test]
    fn a_path_written_behind_a_key_is_still_a_path() {
        // The disclosure rule reads operands, and two grammars hid a path behind a prefix:
        // `dd if=<path>` and `--flag=<path>`. Both were invisible to every root predicate,
        // because the token does not start with a separator. Measured on the BLA-AL00: `dd
        // if=<file> of=<file>` copies it ("4 bytes (4 B) copied"), so this was a working
        // route and not a spelling.
        for script in [
            "dd if=/dev/block/mmcblk0",
            "dd if=/dev/block/mmcblk0 of=/data/local/tmp/out",
            "dd if=/data/data/com.foo/db of=/sdcard/out",
            "dd if=/data/data/com.foo/db > /data/local/tmp/out",
            "grep --file=/proc/1/environ /data/local/tmp/x",
            "wc --files0-from=/data/data/com.foo/list",
            "chmod --reference=/data/data/com.foo/x /data/local/tmp/f",
            "sed -f /data/data/com.foo/s /data/local/tmp/x",
        ] {
            assert_eq!(effect(script), Effect::ForeignRead, "{script}");
            assert!(
                check(script, Some(Capability::FsOutsideApp)).is_err(),
                "{script} must not be covered by the lightest filesystem tier"
            );
        }
        // The same syntax with nothing sensitive behind it stays where it was, so the reader is
        // not simply refusing every `key=value`.
        assert_eq!(
            effect("dd if=/data/local/tmp/a of=/data/local/tmp/b"),
            Effect::FileWrite
        );
        assert_eq!(effect("wc --help"), Effect::ReadOnly);
    }

    #[test]
    fn a_sorts_scratch_directory_is_a_destination_and_a_compression_program_is_a_second_command() {
        // `-T DIR` is accepted by this toybox (measured: exit 0), and sort writes its temporary
        // files there. Naming only `-o` would put an approval in front of a partition write.
        assert_eq!(
            effect("sort -T /system/tmp /data/local/tmp/f"),
            Effect::SystemWrite,
            "the temp directory alone is a destination"
        );
        assert_eq!(
            effect("sort -o /data/local/tmp/x -T /system/tmp /data/local/tmp/f"),
            Effect::SystemWrite,
            "and the heavier of the two wins, so a light output cannot hide the partition"
        );
        assert_eq!(
            effect("sort --temporary-directory=/system/tmp /data/local/tmp/f"),
            Effect::SystemWrite,
            "the `=` spelling is the same write"
        );
        assert_eq!(
            effect("sort -o /data/local/tmp/x /data/local/tmp/f"),
            Effect::FileWrite,
            "a scratch destination stays the light tier"
        );
        // `--compress-program` names a program for sort to run. This toybox rejects the option
        // outright (measured: "Unknown option compress=gzip"), so refusing costs nothing here
        // and covers the GNU sort a Termux host installs.
        for script in [
            "sort --compress-program=gzip /data/local/tmp/f",
            "sort --compress=gzip /data/local/tmp/f",
            "sort -Zgzip /data/local/tmp/f",
        ] {
            assert_eq!(effect(script), Effect::Opaque, "{script}");
        }
        // `uniq --output=` is not an option this uniq has (measured: "Unknown option
        // output=..."), so the token is a flag the command rejects, not a destination — the
        // read answer is correct here and is pinned so a future general `--flag=` rule does not
        // silently start tiering it.
        assert_eq!(
            effect("uniq /data/local/tmp/f --output=/system/x"),
            Effect::ReadOnly
        );
    }

    #[test]
    fn braces_are_only_reserved_when_they_stand_alone() {
        // `find -exec rm {} +` names no group: `{}` is a literal argument. Refusing it as a brace
        // group gave the right tier with a sentence that was wrong, and the audit log is where a
        // human reads that sentence.
        let report = classify("find /data/local/tmp -exec rm {} +");
        assert_eq!(report.strongest(), Effect::Opaque);
        assert!(
            !report.findings[0].detail.contains("brace"),
            "not a brace group: {}",
            report.findings[0].detail
        );
        // A real group is still refused, and still says why.
        let grouped = classify("{ cat /data/local/tmp/x; }");
        assert_eq!(grouped.strongest(), Effect::Opaque);
        assert!(
            grouped.findings[0].detail.contains("brace group"),
            "{}",
            grouped.findings[0].detail
        );
        assert_eq!(
            classify("(cat /data/local/tmp/x)").strongest(),
            Effect::Opaque
        );
        // `xargs -I{}` is the other literal shape.
        assert_eq!(
            classify("echo x | xargs -I{} rm {}").strongest(),
            Effect::Opaque,
            "still refused — xargs runs a command the classifier cannot see"
        );
    }

    #[test]
    fn a_bit_bucket_is_a_bit_bucket_whatever_command_names_it() {
        // The redirection reader has always dropped the bit bucket; `dd of=` did not, so
        // `dd of=/dev/null` cost `fs:system` (all of `/dev` is a partition root) while
        // `echo x > /dev/null` cost nothing. Same file, one answer.
        assert_eq!(
            effect("dd if=/data/local/tmp/a of=/dev/null"),
            Effect::ReadOnly
        );
        assert_eq!(effect("echo hi > /dev/null"), Effect::ReadOnly);
        assert_eq!(
            effect("dd if=/data/local/tmp/a of=/dev/zero"),
            Effect::ReadOnly
        );
        // A real device under the same prefix is still the hard-banned thing.
        assert_eq!(
            effect("dd if=/dev/null of=/dev/block/mmcblk0"),
            Effect::Banned
        );
        // And the ledger asks the same question: a bit bucket has no previous state to put back,
        // so a snapshot of the node would be a phantom in the undo list.
        let words: Vec<String> = "dd if=/data/local/tmp/a of=/dev/null"
            .split_whitespace()
            .map(str::to_string)
            .collect();
        assert!(
            file_writes(&words).is_none(),
            "the planner must not be asked to snapshot `{}`",
            file_writes(&words)
                .map(|w| w[0].path.clone())
                .unwrap_or_default()
        );
    }

    #[test]
    fn reading_another_process_insides_costs_the_disclosure_tier() {
        // The third argument shape in the same family. `/proc/<pid>/environ` is where a process
        // keeps the token it was handed, and `/proc/<pid>/mem` is the decrypted database while it
        // is open — both were answering ReadOnly, the auto-pass tier, on a root device.
        for script in [
            "cat /proc/1234/environ",
            "cat /proc/1/mem",
            "strings /proc/999/maps",
            "ls /proc/42/fd",
            "cat /proc/*/environ",
            "head -c 8 /proc/1234/smaps_rollup",
        ] {
            assert_eq!(effect(script), Effect::ForeignRead, "{script}");
        }
        // The reader's own process and the system's own statistics stay where the evidence
        // surface needs them: this is a rule about *whose* process, not about the word "proc".
        for script in [
            "cat /proc/self/environ",
            "cat /proc/thread-self/status",
            "cat /proc/meminfo",
            "cat /proc/cpuinfo",
            "cat /proc/mounts",
            "ls /proc",
        ] {
            assert_eq!(effect(script), Effect::ReadOnly, "{script}");
        }
    }

    #[test]
    fn reading_a_raw_block_device_costs_the_disclosure_tier_too() {
        // The same asymmetry one level up. §4.6.3 hard-bans *writing* a block device, and the
        // write side honours it, but `cat /dev/block/mmcblk0` was answering ReadOnly — the
        // auto-pass tier — while the device it opens is every app's home, every message and
        // every photo on the handset, in one argument. A read of it changes nothing, so it is
        // the disclosure effect and not a heavier one; it still cannot go unattended.
        for script in [
            "cat /dev/block/mmcblk0",
            "cat /dev/block/mmcblk0p1",
            "od /dev/block/sda",
            "strings /dev/block/by-name/userdata",
            "head -c 4096 /dev/loop0",
            "cat /dev/block/../../dev/block/mmcblk0",
        ] {
            assert_eq!(effect(script), Effect::ForeignRead, "{script}");
            assert!(
                check(script, Some(Capability::FsOutsideApp)).is_err(),
                "{script} must not be covered by a capability that is not being asked for"
            );
        }
        // The devices that are not disks stay at the read tier: `/dev/zero` and `/dev/null` are
        // sources of nothing, and `/dev/kmsg` is not a partition somebody's data lives in.
        for script in ["cat /dev/zero", "cat /dev/null", "cat /proc/self/mem"] {
            assert_eq!(effect(script), Effect::ReadOnly, "{script}");
        }
        // And the write is still the thing that is refused outright, not merely approved.
        assert_eq!(
            effect("dd if=/dev/zero of=/dev/block/mmcblk0"),
            Effect::Banned
        );
    }

    #[test]
    fn removing_a_whole_uid_home_is_banned_and_one_app_home_is_not() {
        // `rm -rf /data` is on the §4.6.3 hard-ban list. `/data/data` is the same destruction
        // one level down — every app's home at once — and was costing the lightest write tier.
        for script in [
            "rm -fr /data/data",
            "rm -fr /data/user",
            "rm -fr /data/user_de",
            "rm -fr /data/system",
            "rm -fr /data/misc",
        ] {
            assert!(
                matches!(
                    check(script, Some(Capability::FsSystem)),
                    Err(Refusal::Banned { .. })
                ),
                "{script} destroys every uid's state and no approval covers it"
            );
        }
        // One app clearing its own home is `pm clear` in another spelling: heavy, and approvable.
        assert_eq!(effect("rm -fr /data/data/com.foo"), Effect::SystemWrite);
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
    fn a_walk_is_resolved_before_it_is_tiered() {
        // The resolver has to resolve, not spot the word "system". Each of these lands somewhere
        // different from what its spelling suggests, and the tier follows the landing.
        assert_eq!(
            effect("getprop > /data/local/tmp/../../local/tmp/x"),
            Effect::FileWrite,
            "`/data/local/tmp/../../local/tmp` is the shell's own scratch"
        );
        assert_eq!(
            effect("getprop > /data/local/tmp/../../system/x"),
            Effect::SystemWrite,
            "`/data/local/tmp/../../system` is /data/system — not the system partition, but the \
             framework uid's home, which is the heavier tier for a different reason"
        );
        assert_eq!(
            effect("rm -fr /data/local/tmp/../../data"),
            Effect::Banned,
            "and `rm` of what that walk reaches — /data/data, every app's home — is the ban that \
             `rm -fr /data/data` already carries"
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
            effect("logcat -d > /data/local/tmp/../tmp/log.txt"),
            Effect::FileWrite,
            "`..` pops a segment, and this one lands back in the shell's own area"
        );
        assert_eq!(
            effect("logcat -d > /data/local/tmp/../local/tmp/log.txt"),
            Effect::SystemWrite,
            "the same spelling one directory deeper is not the shell's area: `/data/local/local` \
             does not exist and creating it needs the data root"
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
    fn a_destination_carried_in_a_flag_is_read_rather_than_refused() {
        // `cp -t /system/bin x` names the partition where the operand list never looks: `-t` is
        // a flag, `/system/bin` is a non-flag operand, and "the last operand is the destination"
        // would read this as writing `x`. The port used to answer Opaque, which was safe and
        // useless — the destination is written in plain text two tokens away.
        assert_eq!(
            effect("cp -t /system/bin /data/local/tmp/x"),
            Effect::SystemWrite
        );
        assert_eq!(
            effect("mv --target-directory=/system/bin /data/local/tmp/x"),
            Effect::SystemWrite,
        );
        assert_eq!(
            effect("cp -t/system/bin /data/local/tmp/x"),
            Effect::SystemWrite,
            "the glued spelling is the same request"
        );
        // A flag whose value the port cannot see is still refused: reading the flag is not
        // guessing at it.
        assert_eq!(effect("cp -t ./system/bin x"), Effect::Opaque);
        assert_eq!(effect("mv -t $DEST x"), Effect::Opaque);
        // `touch -t` is a timestamp. The flag is not consulted for a command that does not
        // carry a destination in it, so the write is still judged by its operand.
        assert_eq!(
            effect("touch -t 202401010000 /data/local/tmp/f"),
            Effect::FileWrite
        );
    }

    #[test]
    fn a_label_change_costs_the_tier_of_the_file_it_labels() {
        // `chcon`/`restorecon` change an inode's security context, which is metadata *of that
        // file* — the same class of change as `chmod`. Classifying them as generic device state
        // let a caller holding `android:shell:write` relabel a partition file, while the
        // identical write via `chmod` needed `fs:system`. The difference was the verb, not the
        // effect.
        assert_eq!(
            effect("chcon u:object_r:system_file:s0 /system/bin/sh"),
            Effect::SystemWrite
        );
        assert_eq!(effect("restorecon /data/local/tmp/f"), Effect::FileWrite);
        assert_eq!(
            effect("chcon -R -v u:object_r:app_data_file:s0 /data/data/com.foo"),
            Effect::SystemWrite,
            "recursion does not change whose file it is"
        );
        // A label change whose file the port cannot name is refused, not blessed as state.
        assert_eq!(effect("chcon -R u:object_r:x:s0 ./f"), Effect::Opaque);
        assert_eq!(effect("restorecon"), Effect::Opaque);
        // And the label argument is not read as a path: it is a context string, and treating it
        // as a destination would invent a second write.
        let finding = first_finding("chcon u:object_r:system_file:s0 /system/bin/sh");
        assert!(
            finding.detail.contains("/system/bin/sh"),
            "{}",
            finding.detail
        );
    }

    #[test]
    fn the_files_a_command_changes_never_outrank_the_approval_it_gets() {
        // The planner asks `file_writes` which files to snapshot; the gate asks the same lexer
        // what to approve. If those two ever disagree in the permissive direction, a script is
        // approved as one file and restored as another — so the relationship is pinned here for a
        // corpus rather than trusted because both read the same helpers.
        let corpus = [
            "sed -i s/a/b/ /data/local/tmp/f",
            "sed -i 's/a/b/' /system/build.prop",
            "cp /data/local/tmp/a /system/b",
            "mv /system/x /data/local/tmp/y",
            "mv -t /system /data/local/tmp/a",
            "install -m 644 /data/local/tmp/a /system/b",
            "install -d /system/x",
            "ln -s /data/local/tmp/x /system/bin/y",
            "rm -r /data/local/tmp/x",
            "unlink /system/x",
            "chmod 777 /data/local/tmp/f",
            "chcon u:object_r:x:s0 /system/bin/sh",
            "tee /system/f",
            "truncate -s 0 /data/local/tmp/f",
            "echo x > /data/local/tmp/f",
            "toybox cp /data/local/tmp/a /system/b",
            "busybox sed -i s/a/b/ /system/build.prop",
            // The two directions through another uid's home. The first is a disclosure whose only
            // write is the light one, the second is a write that the disclosure ladder does not
            // outrank; both have to keep the invariant the corpus exists to pin.
            "cp /data/data/com.foo/db /sdcard/db",
            "cp /sdcard/x /data/data/com.foo/y",
            "rm -fr /data/data/com.foo",
            "cat /data/data/com.foo/db > /data/local/tmp/out",
            // The destination hidden in a flag, on a command the read list used to answer for.
            "sort -o /system/x /data/local/tmp/f",
            "sort -o /data/local/tmp/x /data/local/tmp/f",
            "uniq /data/local/tmp/f /system/out",
            "logcat -f/system/log",
            // The same destination grammar behind a `key=` prefix, which every root predicate
            // used to miss because the token does not start with a separator. `sort -T` is
            // deliberately not here: the scratch directory sets the tier but is not a file the
            // ledger can restore, so the planner is right not to be asked for it.
            "dd if=/dev/block/mmcblk0 of=/data/local/tmp/out",
            "dd if=/data/local/tmp/a of=/system/b",
            "dd if=/data/data/com.foo/db of=/sdcard/out",
        ];
        for script in corpus {
            let verdict = classify(script);
            let effect = verdict.strongest();
            let words: Vec<String> = script.split_whitespace().map(str::to_string).collect();
            let Some(writes) = file_writes(&words) else {
                continue;
            };
            for write in writes {
                let tier = file_effect(&write.path);
                assert!(
                    tier <= effect || matches!(effect, Effect::Opaque | Effect::Banned),
                    "`{script}`: `{}` ({tier:?}) outranks the approval {effect:?}",
                    write.path
                );
            }
        }
    }

    #[test]
    fn the_command_word_and_its_operands_are_told_apart_when_answering() {
        // `echo` changes a file its *arguments* never mention, so the answer here is "cannot say"
        // rather than an empty list: an empty list would read to the planner as "this command
        // writes no file", which is a different claim.
        assert!(file_writes(&["echo".into(), "x".into()]).is_none());
        // A leading assignment is not the command word.
        let writes = file_writes(&[
            "PATH=/system/bin".into(),
            "rm".into(),
            "-f".into(),
            "/data/local/tmp/x".into(),
        ])
        .expect("rm is still rm behind an assignment");
        assert_eq!(writes[0].change, FileChange::Deletion);
        // A multiplexer is its subcommand.
        let writes = file_writes(&[
            "toybox".into(),
            "cp".into(),
            "/data/local/tmp/a".into(),
            "/system/b".into(),
        ])
        .expect("toybox cp is cp");
        assert_eq!(
            writes,
            vec![FileWrite {
                path: "/system/b".into(),
                change: FileChange::Content
            }]
        );
        // A sed whose script and file cannot be told apart answers "cannot say", the same refusal
        // the tier decision makes.
        assert!(
            file_writes(&[
                "sed".into(),
                "-i".into(),
                "-e".into(),
                "s/a/b/".into(),
                "/system/f".into()
            ])
            .is_none()
        );
    }

    #[test]
    fn a_log_written_to_a_partition_is_a_partition_write() {
        // `-f` names a file, and a file under /system is a system write whoever opened it. The
        // answer used to be hard-coded to the light tier for every log path, which is the same
        // mistake `sed -i` made before it was tiered by its file.
        assert_eq!(effect("logcat -f /system/x"), Effect::SystemWrite);
        assert_eq!(
            effect("logcat -f /data/data/com.foo/log"),
            Effect::SystemWrite
        );
        assert_eq!(effect("logcat -d -f /data/local/tmp/x"), Effect::FileWrite);
        assert_eq!(effect("logcat -f ./x"), Effect::Opaque);
        // `-r` is a rotation *size*, not a path, so there is no file to tier and the older answer
        // stands rather than being invented from the number.
        assert_eq!(effect("logcat -r 100"), Effect::FileWrite);
    }

    #[test]
    fn unlink_is_a_removal_of_the_name_it_is_given() {
        assert_eq!(effect("unlink /system/x"), Effect::SystemWrite);
        assert_eq!(effect("unlink /data/local/tmp/x"), Effect::FileWrite);
        assert_eq!(effect("unlink x"), Effect::Opaque, "no root in the name");
    }

    #[test]
    fn install_is_a_copy_wearing_a_mode_flag() {
        // `install SRC DEST` is cp plus chmod; leaving it unmodelled made it Opaque, which is a
        // refusal to say what the command does rather than a safer answer.
        assert_eq!(
            effect("install -m 644 /data/local/tmp/a /system/b"),
            Effect::SystemWrite
        );
        assert_eq!(
            effect("install -m 644 /data/local/tmp/a /data/local/tmp/b"),
            Effect::FileWrite
        );
        // `-d` is mkdir with a mode: every operand is a directory the command creates.
        assert_eq!(effect("install -d /system/x"), Effect::SystemWrite);
        assert_eq!(effect("install -d ./x"), Effect::Opaque);
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
    fn a_command_on_the_read_list_that_writes_is_tiered_by_the_file_it_writes() {
        // Three read-list commands write a file when the argument is right, and all three were
        // answering "filter" while putting one in place.
        assert_eq!(
            effect("sort -o /system/x /data/local/tmp/f"),
            Effect::SystemWrite,
            "`sort -o` is the output file"
        );
        assert_eq!(
            effect("sort -o/system/x /data/local/tmp/f"),
            Effect::SystemWrite,
            "the glued spelling works on this shell and is the same write"
        );
        assert_eq!(
            effect("toybox sort -o /system/x /data/local/tmp/f"),
            Effect::SystemWrite,
            "through the multiplexer it is still `sort`"
        );
        assert_eq!(
            effect("sort -o /data/local/tmp/x /data/local/tmp/f"),
            Effect::FileWrite,
            "and a scratch destination is still the light tier"
        );
        assert_eq!(effect("sort -c /data/local/tmp/f"), Effect::ReadOnly);
        assert_eq!(effect("sort /data/local/tmp/f"), Effect::ReadOnly);

        // `uniq` is the same trap in a different argument position: POSIX and toybox both spell
        // it `uniq INPUT [OUTPUT]`, so the second operand is a file it creates.
        assert_eq!(
            effect("uniq /data/local/tmp/f /system/out"),
            Effect::SystemWrite,
            "the second operand is the output file"
        );
        assert_eq!(
            effect("uniq -f 2 /data/local/tmp/f /data/local/tmp/out"),
            Effect::FileWrite,
            "and a flag's own value is not one of its operands"
        );
        assert_eq!(effect("uniq -c /data/local/tmp/f"), Effect::ReadOnly);
        assert_eq!(effect("uniq /data/local/tmp/f"), Effect::ReadOnly);
        assert_eq!(
            effect("uniq /data/local/tmp/f ./out"),
            Effect::Opaque,
            "a relative output belongs to a working directory nobody observes"
        );
        assert_eq!(
            effect("uniq /data/local/tmp/a /data/local/tmp/b /data/local/tmp/c"),
            Effect::Opaque,
            "three files for a command that takes two does not say which one is written"
        );
        // `-o` on `strings` is a byte offset, not a destination — the shape that would have been
        // over-answered if every `-o` were read as a file.
        assert_eq!(effect("strings -o 5 /data/local/tmp/f"), Effect::ReadOnly);

        // `date` prints, unless it is being told what the clock reads.
        assert_eq!(effect("date"), Effect::ReadOnly);
        assert_eq!(effect("date -u +'%F'"), Effect::ReadOnly);
        assert_eq!(
            effect("date @1700000000"),
            Effect::ReadOnly,
            "an epoch argument is a conversion, not a setting"
        );
        assert_eq!(
            effect("date -s '2026-01-01 00:00'"),
            Effect::ShellWrite,
            "-s sets the clock"
        );
        assert_eq!(
            effect("date 010100002026"),
            Effect::ShellWrite,
            "and so does the positional form, with no flag to spot"
        );

        // sed's `w FILE` writes a file named inside the program, where no operand list can see it.
        for script in [
            "sed '/x/w /system/y' /data/local/tmp/f",
            "sed '/x/r /system/y' /data/local/tmp/f",
            "sed 's/a/b/w /tmp/x' /data/local/tmp/f",
            "sed 's/a/b/w/tmp/x' /data/local/tmp/f",
            "sed -i 's/a/b/w /tmp/x' /data/local/tmp/f",
        ] {
            assert_eq!(effect(script), Effect::Opaque, "{script}");
        }
        // The same test in the other direction: a program that mentions the letters without a
        // file after them is an ordinary read, and refusing these is the false positive that
        // would put every `sed` on the device behind an approval.
        for script in [
            "sed 's/a/w/' /data/local/tmp/f",
            "sed 's/w/x/' /data/local/tmp/f",
            "sed 's/foo/bar/g; s/baz/qux/' /data/local/tmp/f",
            "sed -n '/x/p' /data/local/tmp/f",
            "sed 's/a/b/' /data/local/tmp/f",
        ] {
            assert_eq!(effect(script), Effect::ReadOnly, "{script}");
        }
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
    fn a_path_argument_to_dumpsys_is_a_destination_not_an_input() {
        // Measured on the BLA-AL00: `dumpsys SurfaceFlinger --screenshot /data/local/tmp/ps.png`
        // leaves no file, and neither do `--screen` nor `--screenshot=` — this build's service
        // ignores the flag. The rule stays, because a path handed to `dumpsys` is never something
        // the command reads, and the tier that answers for reads is the one §4.4 passes without
        // asking. `screencap` is the same shape and was already modelled as a write.
        assert_eq!(
            effect("dumpsys SurfaceFlinger --screenshot /data/local/tmp/s.png"),
            Effect::FileWrite
        );
        assert_eq!(
            effect("dumpsys SurfaceFlinger --screenshot /system/s.png"),
            Effect::SystemWrite
        );
        assert_eq!(effect("dumpsys battery"), Effect::ReadOnly);
        assert_eq!(effect("dumpsys -l"), Effect::ReadOnly);
        assert_eq!(effect("dumpsys window"), Effect::ReadOnly);
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
        let verdict = classify("getprop; setprop a b; logcat -d > /data/local/tmp/x");
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
    fn every_redirection_of_a_command_counts_not_just_the_last_one() {
        // POSIX applies each redirection in order: `cmd > a > b` truncates `a` and sends stdout
        // to `b`. Both files change, so the approval has to cost the heavier of the two and name
        // both — reporting only one is the same "first match wins" reflex that had `dd` classify
        // one destination out of several.
        let v = classify("echo x > /data/local/tmp/a > /system/b");
        assert_eq!(v.strongest(), Effect::SystemWrite);
        assert_eq!(v.findings[0].command, "echo");
        let detail = &v.findings[0].detail;
        assert!(
            detail.contains("/data/local/tmp/a") && detail.contains("/system/b"),
            "{detail}"
        );
        // `/dev/null` and a duplicated fd are not files a reader can find, so they add no tier
        // and no second snapshot: the write that matters is the one that remains.
        assert_eq!(
            classify("logcat -d > /dev/null > /data/local/tmp/a").strongest(),
            Effect::FileWrite
        );
        // Two redirections do not cancel the command's own effect either.
        assert_eq!(
            classify(
                "sed -i s/a/b/ /system/build.prop > /data/local/tmp/log1 > /data/local/tmp/log2"
            )
            .strongest(),
            Effect::SystemWrite
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
            classify("echo x > /datapersist/f").strongest(),
            Effect::FileWrite,
            "a name that begins like the data root is not inside it"
        );
        // The rest of `/data` is somebody else's, which is what the widened rule changed: a file
        // in the framework's own home is not an outside-app write either. Measured on the
        // BLA-AL00, `/data` is `drwxrwx--x system system` — this uid may traverse it, not create
        // in it — so a write that lands anywhere else under it is already past the shell's area.
        for script in [
            "echo x > /data/anr/trace.txt",
            "echo x > /data/tombstones/x.pb",
            "echo x > /data/local/x",
            "echo x > /data",
        ] {
            assert_eq!(
                classify(script).strongest(),
                Effect::SystemWrite,
                "`{script}` is not an outside-app write"
            );
        }
    }

    /// The shapes this device's `find` was measured to have: five actions change something or
    /// run a program, everything else is a search. Refusing the whole command because of the
    /// five is what cost callers a `find` they could not ask for.
    #[test]
    fn find_searches_read_and_its_five_actions_do_not() {
        for script in [
            "find /data/local/tmp -type f",
            "find /data/local/tmp -name a -print",
        ] {
            assert_eq!(effect(script), Effect::ReadOnly, "{script}");
        }
        // Searching the media tree is the disclosure the read tier was never entitled to, which
        // is the answer `ls /sdcard` and `wc -l /sdcard/a.txt` already give — `find` is not a new
        // kind of thing, it is the same read of the same files.
        for script in [
            "find /sdcard -name '*.txt'",
            "find /sdcard/Download -maxdepth 1",
            "find /sdcard -size +1M -print",
        ] {
            assert_eq!(effect(script), Effect::ForeignRead, "{script}");
        }
        for script in [
            "find /sdcard -name x -delete",
            "find /data/local/tmp -exec rm {} ;",
            "find /data/local/tmp -execdir cat {} ;",
            "find /sdcard -ok chmod 600 {} ;",
            "find /sdcard -okdir rm {} ;",
        ] {
            assert_eq!(effect(script), Effect::Opaque, "{script}");
        }
        // The start path is a read of whatever is under it, so the disclosure rule still applies.
        assert_eq!(
            effect("find /data/data -name '*.db'"),
            Effect::ForeignRead,
            "a search of somebody else's homes is a disclosure even when it writes nothing"
        );
        // And the reason the refusal is not a file write: the device picks the file set while
        // running, so no approval could have named it.
        let why = first_finding("find /sdcard -name x -delete").detail;
        assert!(
            why.contains("matched") || why.contains("change the filesystem"),
            "{why}"
        );
    }

    #[test]
    fn tar_is_tiered_by_which_of_its_three_operations_it_was_asked_for() {
        for script in [
            "tar -tf /data/local/tmp/a.tar",
            "tar tvf /data/local/tmp/a.tar",
            "tar --list -f /data/local/tmp/a.tar",
            "tar -tf /data/local/tmp/a.tar -C /data/local/tmp",
        ] {
            assert_eq!(effect(script), Effect::ReadOnly, "{script}");
        }
        // `-c` writes exactly one file, the one `-f` names, in all three spellings of `-f`.
        for (script, archive) in [
            (
                "tar -czf /data/local/tmp/a.tar /data/local/tmp",
                "/data/local/tmp/a.tar",
            ),
            ("tar czf /data/local/tmp/a.tar x", "/data/local/tmp/a.tar"),
            ("tar -czf/data/local/tmp/a.tar x", "/data/local/tmp/a.tar"),
        ] {
            let finding = first_finding(script);
            assert_eq!(finding.effect, Effect::FileWrite, "{script}");
            assert!(
                finding.detail.contains(archive.rsplit('/').next().unwrap()),
                "{script} → {}",
                finding.detail
            );
        }
        // An archive named without a leading `/` is a write into a working directory this port
        // never sees, which every write tier in this file already refuses — `tar` is not owed an
        // exception for spelling its destination that way.
        assert_eq!(effect("tar -cf a.tar x"), Effect::Opaque);
        assert_eq!(
            effect("tar -czf /system/a.tar /data/local/tmp"),
            Effect::SystemWrite,
            "an archive written into a partition is not an outside-app write"
        );
        // Unpacking writes one file per member, under names stored inside the archive.
        for script in [
            "tar -xf /data/local/tmp/a.tar",
            "tar -xf /data/local/tmp/a.tar -C /data/local/tmp/out",
            "tar xzf /data/local/tmp/a.tar",
        ] {
            assert_eq!(effect(script), Effect::Opaque, "{script}");
        }
        // `-O` sends the members to stdout, which puts nothing on the device.
        assert_eq!(
            effect("tar -xOf /data/local/tmp/a.tar"),
            Effect::ReadOnly,
            "extracting to stdout writes no file"
        );
        // An option nobody modelled does not inherit the read tier for sitting on the read list.
        assert_eq!(effect("tar --checkpoint=100 -tf a.tar"), Effect::Opaque);
    }

    /// The tier decision and the ledger read `tar` through the same helper, and the rollback
    /// planner is the third reader: an archive written under `/data/anr` has to be named in the
    /// ledger or the session ends with an undo list that looks complete and is not.
    #[test]
    fn the_archive_tar_writes_is_the_file_the_ledger_names() {
        let writes = |script: &str| {
            words(script)
                .unwrap_or_default()
                .iter()
                .filter_map(|command| file_writes(command))
                .flatten()
                .map(|w| (w.path, w.change))
                .collect::<Vec<_>>()
        };
        assert_eq!(
            writes("tar -czf /data/local/tmp/back.tar.gz /data/local/tmp"),
            vec![(
                "/data/local/tmp/back.tar.gz".to_string(),
                FileChange::Content
            )]
        );
        assert!(
            writes("tar -cf - /data/local/tmp").is_empty(),
            "an archive on stdout is not a file anybody can snapshot"
        );
        assert!(
            writes("tar -tf /data/local/tmp/a.tar").is_empty(),
            "listing writes nothing"
        );
        // Listing somebody else's archive is still the disclosure: `-f` must not be read as a
        // *destination* for an operation that only reads it, or the disclosure scan below
        // excludes it and the read goes unreported.
        assert_eq!(
            effect("tar -tf /data/anr/a.tar"),
            Effect::ForeignRead,
            "the archive is a disclosure read while it is being listed"
        );
    }

    #[test]
    fn unzip_lists_and_refuses_to_extract_unnamed_files() {
        // Measured usage: `unzip [-d DIR] [-lnopqv] ZIP [FILE...] [-x FILE...]`.
        for script in [
            "unzip -l /data/local/tmp/a.zip",
            "unzip -v /data/local/tmp/a.zip",
            "unzip -p /data/local/tmp/a.zip readme.txt",
            "unzip -lq /data/local/tmp/a.zip",
        ] {
            assert_eq!(effect(script), Effect::ReadOnly, "{script}");
        }
        for script in [
            "unzip /data/local/tmp/a.zip",
            "unzip -q /data/local/tmp/a.zip",
            "unzip -o /data/local/tmp/a.zip",
            "unzip -d /data/local/tmp/out /data/local/tmp/a.zip",
            "unzip -n /data/local/tmp/a.zip '*.txt'",
        ] {
            assert_eq!(effect(script), Effect::Opaque, "{script}");
        }
        assert_eq!(
            effect("unzip -l /data/data/com.other/a.zip"),
            Effect::ForeignRead
        );
    }

    /// awk's program text is where its file and command effects live, and the letters are the
    /// ones its operators use too. The blacklist is therefore deliberately wider than the risk:
    /// `awk '$1 > 5'` is refused along with `awk '{print > "f"}'`, and says so.
    #[test]
    fn awk_filters_unless_its_program_can_open_a_file_or_run_a_program() {
        for script in [
            "awk '{print $1}' /data/local/tmp/a.txt",
            "awk -F: '{print $2}' /data/local/tmp/passwd",
            "awk '{print $1}' /data/local/tmp/a.txt | wc -l",
            "awk '$1 ~ /error/' /data/local/tmp/log.txt",
        ] {
            assert_eq!(effect(script), Effect::ReadOnly, "{script}");
        }
        for script in [
            "awk '{print $1 > \"/data/local/tmp/out.txt\"}' /data/local/tmp/a.txt",
            "awk 'BEGIN{system(\"rm -rf /data/local/tmp/x\")}'",
            "awk 'BEGIN{\"echo hi\" | getline x}'",
            "awk 'BEGIN{while((getline l < \"/data/anr/t\")>0) print l}'",
            "awk -f /data/local/tmp/prog.awk /data/local/tmp/a.txt",
            "awk $PROG /data/local/tmp/a.txt",
            // The over-refusal, and it is deliberate: `>` is awk's comparison operator too, and
            // telling a comparison from a redirect means parsing awk.
            "awk 'NR>0' /data/local/tmp/a.txt",
            "awk '$1 > 5' /data/local/tmp/a.txt",
            // The hole the program-slot exemption must not open: the shell puts text into the
            // program that nobody read, so the program awk runs is not the one that was tiered.
            "awk '{print $1}'$SUF /data/local/tmp/a.txt",
        ] {
            assert_eq!(effect(script), Effect::Opaque, "{script}");
        }
        // The over-refusal, named rather than hidden.
        let why = first_finding("awk '$1 > 5' /data/local/tmp/a.txt").detail;
        assert!(
            why.contains("comparison"),
            "a `>` in an awk program is refused because the port cannot tell it from a \
             redirect, and the caller is told that: {why}"
        );
    }

    #[test]
    fn top_is_a_read_once_it_is_told_to_stop() {
        for script in ["top -n 1", "top -b -n 1", "top -b", "top -n 1 -m 20"] {
            assert_eq!(effect(script), Effect::ReadOnly, "{script}");
        }
        assert_eq!(
            effect("top"),
            Effect::Opaque,
            "an interactive refresh loop passed by the auto-pass tier spends the whole command \
             timeout on nothing"
        );
    }

    #[test]
    fn a_delay_and_the_environment_are_reads() {
        assert_eq!(effect("sleep 2"), Effect::ReadOnly);
        assert_eq!(effect("printenv PATH"), Effect::ReadOnly);
    }

    /// `cmd` is a multiplexer, so the word after the service is the verb: the classifier used to
    /// read the service's name as if it were one, which refused `cmd package list packages` and
    /// `cmd appops get` — both of which printed state on the BLA-AL00 at uid 2000.
    #[test]
    fn the_dispatchers_are_read_by_the_verb_and_not_by_the_service_name() {
        for script in [
            "cmd appops get com.android.shell",
            "cmd package list packages",
            "cmd deviceidle get light",
            "cmd package",
            "appops get com.android.shell",
            "appops query-wake",
            "deviceidle get light",
        ] {
            assert_eq!(effect(script), Effect::ReadOnly, "{script}");
        }
        for script in [
            "cmd appops set com.android.shell SYSTEM_ALERT_WINDOW allow",
            "cmd package install /data/local/tmp/app.apk",
            "cmd deviceidle whitelist +com.example",
            "appops set com.android.shell BOOT_COMPLETED deny",
            "deviceidle unset +com.example",
            "pm install /data/local/tmp/app.apk",
            "settings put system font_scale 1.1",
        ] {
            assert_eq!(effect(script), Effect::ShellWrite, "{script}");
        }
        // The verb rule is `cmd`'s only, because `cmd` is the one whose first word is a service.
        // `pm install -f /data/x` must not be excused by a second word that is an argument.
        assert_eq!(effect("pm list packages"), Effect::ReadOnly);
        assert_eq!(effect("pm clear com.example"), Effect::ShellWrite);
    }

    /// `ip` is in the write vocabulary by name and mostly deserves it, but its report shapes were
    /// measured as plain reads at uid 2000: `ip addr show`, `ip route show` and `ip link` each
    /// printed state and changed nothing.
    #[test]
    fn ip_reports_state_and_ip_changes_it() {
        for script in [
            "ip addr show",
            "ip -4 addr show",
            "ip addr",
            "ip route show",
            "ip link",
            "ip -s link",
            "ip neigh",
            "ip rule list",
        ] {
            assert_eq!(effect(script), Effect::ReadOnly, "{script}");
        }
        for script in [
            "ip link set eth0 down",
            "ip addr add 10.0.0.1/24 dev eth0",
            "ip route add default via 10.0.0.254",
            "ip addr flush dev lo",
            "ip rule add from 10.0.0.0/8",
            "ip neigh replace 10.0.0.1 lladdr 00:11:22:33:44:55 dev eth0",
            "ip link add br0 type bridge",
        ] {
            assert_eq!(effect(script), Effect::ShellWrite, "{script}");
        }
        // An object this port does not model keeps the tier the name already carries — the
        // exemption is for the four report shapes that were measured, not for `ip` in general.
        assert_eq!(effect("ip xfrm state"), Effect::ShellWrite);
    }

    /// The narrowing that made `awk '{print $1}'` possible at all: a `$` in the middle of a word
    /// is awk's field syntax, sed's anchor and grep's pattern, not a path with a hole in it.
    /// The attack the original rule was written for — a variable standing in for a path — is
    /// still refused, because it is a token that *starts* with the substitution.
    #[test]
    fn a_dollar_in_the_middle_of_a_word_is_not_a_path_hole() {
        for script in [
            "sed 's/foo$//' /data/local/tmp/a.txt",
            "sed '$d' /data/local/tmp/a.txt",
            "grep '$' /data/local/tmp/a.txt",
            "grep '^[a-z]*$' /data/local/tmp/a.txt",
            "awk '{print $1}' /data/local/tmp/a.txt",
            "cut -d: -f1 /data/local/tmp/passwd",
        ] {
            assert_eq!(effect(script), Effect::ReadOnly, "{script}");
        }
        // The exemption is withdrawn where a flag makes an operand a file after all (`grep -f
        // LIST` reads LIST), and where the script interpolates: a `$` the shell fills in is not
        // sed's anchor any more, it is whatever the device put there.
        for script in [
            "grep -f $LIST /data/local/tmp/a.txt",
            "sed -e $SCRIPT /data/local/tmp/a.txt",
            "sed \"s/$V/x/\" /data/local/tmp/a.txt",
            "awk \"{print $V}\" /data/local/tmp/a.txt",
        ] {
            assert_eq!(effect(script), Effect::Opaque, "{script}");
        }
        for script in [
            "cat $F",
            "cat `which cat`",
            "cat ~root/.ssh/id_rsa",
            "cat /data/$F/x",
            "cat ./data/$F/x",
            "F=/data/data/com.foo/db; cat $F",
        ] {
            assert_eq!(effect(script), Effect::Opaque, "{script}");
        }
    }
}
