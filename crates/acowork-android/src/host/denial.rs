//! Structured extraction of `avc: denied` and its conversion into an actionable
//! next step for the model.
//!
//! # Why this module exists
//!
//! android-host-probe.md §4 is the load-bearing rule of the whole probe design:
//! **probe is not a guarantee**. SELinux decides per `(scontext, tcontext,
//! tclass)` at execution time, so a profile that reports "writable" can still
//! collect a denial. When that happens the raw kernel line is useless to a model
//! — it will retry, get denied again, and fill the context window with noise.
//! §4 names this the silent-degradation loop and says the design must block it
//! explicitly.
//!
//! This module is that block. It is the middleware between raw stderr and a
//! sentence the model can act on, which is why it is separate from both the
//! parsers ([`super::facts`], which read probe output) and the backend
//! ([`super::backend`], which runs commands).
//!
//! # What the contract owns versus what this module owns
//!
//! The **remedy vocabulary** and the rule that a remedy must be *admissible on this
//! device* belong to `acowork-platform-contract` ([`Remedy`], [`Diagnostic`],
//! [`DiagnosticLedger`](acowork_platform_contract::DiagnosticLedger)). What is Android's
//! is the classification itself: reading an `avc: denied` record, knowing that
//! `permissive=1` is not a failure, and knowing that a denial in an unprivileged domain
//! is an escalation candidate while a denial in a privileged domain is not.
//!
//! That split is not cosmetic. It is what fixed a real defect: this module used to answer
//! "wrong path, privilege will not help" for an out-of-roots path on *every* host, which
//! is false on a rooted device and steered the model away from the only fix that existed.
//! The guard is now keyed on the host's [`EscalationModel`](acowork_platform_contract::EscalationModel),
//! and the contract independently refuses to forward an `Escalate` remedy to a device
//! that has no escalation — two layers, so the mistake cannot recur silently.
//!
//! # Two rules from ADR-AND-001 §4.6
//!
//! 1. **Denial classification** (item 2): extract `avc: denied` from stderr and
//!    turn it into the next step — "needs the su domain", "needs an explicit
//!    permissive approval", "path is not in `fs_roots`".
//! 2. **Audit** (item 1): every privileged command records capability, actual
//!    uid, SELinux domain, command, exit code, duration and any avc denial. The
//!    [`SelinuxDenial`] type is the denial half of that record.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use acowork_platform_contract::{Diagnostic, HostDescription, Remedy};

use crate::host::facts::SelinuxDomain;
use crate::host::profile::HostProfile;

/// One parsed `avc: denied` record.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct SelinuxDenial {
    /// The permissions inside the braces, e.g. `["read", "open"]`.
    pub permissions: Vec<String>,
    /// Source context — the domain the process was running in.
    pub scontext: Option<String>,
    /// Target context — the label on the object being accessed.
    pub tcontext: Option<String>,
    /// Target class: `file`, `dir`, `process`, `capability`, ...
    pub tclass: Option<String>,
    /// `permissive=1` means the access was **logged but allowed**. Treating that
    /// as a failure would make the model "fix" something that is not broken.
    pub permissive: bool,
    /// The object path, when the kernel included one.
    pub path: Option<String>,
    /// The invoking command name, when included.
    pub comm: Option<String>,
}

impl SelinuxDenial {
    /// The key used for repeat detection: same target label and class means the
    /// same wall, so hitting it twice is not going to work the third time.
    ///
    /// `scontext` is deliberately excluded. A retry from a different domain is a
    /// genuinely different attempt; a retry from the same domain against the same
    /// target is not.
    pub fn repeat_key(&self) -> String {
        format!(
            "{}|{}",
            self.tcontext.as_deref().unwrap_or("?"),
            self.tclass.as_deref().unwrap_or("?")
        )
    }
}

/// Extract every `avc: denied` record from a stderr (or logcat) blob.
///
/// Handles the shapes that actually appear:
/// - `avc: denied { read } for pid=... scontext=... tcontext=... tclass=file permissive=0`
/// - the kernel/dmesg wrapper `type=1400 audit(1234.567:89): avc: denied { ... }`
/// - multiple denials in one blob, which is the common case for a command that
///   touches several objects
///
/// Text that contains no `avc: denied` yields an empty vector. This function
/// never fails: a malformed line is skipped, because guessing at a half-parsed
/// denial would produce a wrong hint, and a wrong hint is worse than no hint.
pub fn parse_denials(blob: &str) -> Vec<SelinuxDenial> {
    let mut out = Vec::new();
    for line in blob.lines() {
        let Some(start) = line.find("avc: denied") else {
            continue;
        };
        if let Some(denial) = parse_one_denial(&line[start..]) {
            out.push(denial);
        }
    }
    out
}

fn parse_one_denial(text: &str) -> Option<SelinuxDenial> {
    // Permissions live in the first `{ ... }` group after "denied".
    let open = text.find('{')?;
    let close = text[open..].find('}')? + open;
    let permissions = text[open + 1..close]
        .split_whitespace()
        .map(str::to_string)
        .collect::<Vec<_>>();
    if permissions.is_empty() {
        return None;
    }

    let rest = &text[close + 1..];
    let fields = parse_key_value_pairs(rest);

    Some(SelinuxDenial {
        permissions,
        scontext: fields.get("scontext").cloned(),
        tcontext: fields.get("tcontext").cloned(),
        tclass: fields.get("tclass").cloned(),
        // Absent `permissive=` means enforcing, which is the safe reading: an
        // unflagged denial is a real block.
        permissive: fields
            .get("permissive")
            .is_some_and(|v| v == "1" || v.eq_ignore_ascii_case("true")),
        path: fields.get("path").or_else(|| fields.get("name")).cloned(),
        comm: fields.get("comm").cloned(),
    })
}

/// Split `key=value` pairs, tolerating quoted values (`comm="cat"`,
/// `path="/data/x y"`).
fn parse_key_value_pairs(text: &str) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        // Find the next `key=`
        let Some(eq) = text[i..].find('=') else { break };
        let key_start = i;
        let key_end = key_start + eq;
        // A key is the trailing token before `=`; it may be preceded by other
        // text (e.g. `audit(1.2:3): scontext=`), so walk back to whitespace.
        let key = text[key_start..key_end]
            .split_whitespace()
            .next_back()
            .unwrap_or("")
            .to_string();
        let mut val_start = key_end + 1;
        let value = if text[val_start..].starts_with('"') {
            val_start += 1;
            match text[val_start..].find('"') {
                Some(end) => {
                    let v = text[val_start..val_start + end].to_string();
                    i = val_start + end + 1;
                    v
                }
                None => {
                    // Unterminated quote: take the rest rather than dropping it.
                    let v = text[val_start..].to_string();
                    i = text.len();
                    v
                }
            }
        } else {
            match text[val_start..].find(char::is_whitespace) {
                Some(end) => {
                    let v = text[val_start..val_start + end].to_string();
                    i = val_start + end;
                    v
                }
                None => {
                    let v = text[val_start..].to_string();
                    i = text.len();
                    v
                }
            }
        };
        if !key.is_empty() {
            map.insert(key, value);
        }
        i = i.max(val_start);
    }
    map
}

/// Whether any of the denied permissions is a write-class access.
///
/// Decides which capability a denial implies, and therefore whether escalating would
/// even be the right next step.
fn is_write_access(permissions: &[String]) -> bool {
    permissions.iter().any(|p| {
        matches!(
            p.as_str(),
            "write" | "append" | "create" | "unlink" | "rename" | "setattr" | "mounton" | "execute"
        )
    })
}

/// The capability a denial implies, from the permissions it lists.
fn implied_capability(denial: &SelinuxDenial) -> crate::host::capability::Capability {
    use crate::host::capability::Capability;
    if is_write_access(&denial.permissions) {
        Capability::ShellWrite
    } else {
        Capability::ShellRead
    }
}

/// Classify one parsed denial against the profile it happened on.
///
/// Pure: the same denial plus the same profile always yields the same diagnostic.
/// Per-target repeat detection lives in [`DenialLedger`], because repeats are a property
/// of the session rather than of the denial.
///
/// # The classification this module used to get wrong
///
/// An out-of-roots path was classified as "wrong path, privilege will not help" on
/// *every* host. That is true on Termux and on an APK sandbox, and **false on a rooted
/// device**, where `fs_roots` records only what the *unprivileged* probe could reach
/// (android-host-probe.md §2 item 12 probes `$PREFIX`, `/sdcard` and the package
/// directory) while the README's capability matrix says root reaches "/data 大范围".
/// Telling a rooted device that escalation cannot help sends the model away from the one
/// action that would have worked.
///
/// The guard below is therefore keyed on whether the host can escalate, and the contract
/// adds a second line of defence: [`acowork_platform_contract::Remedy::is_admissible`]
/// rejects `Escalate` on a host whose [`EscalationModel`] is `None`, so even a
/// mis-classification cannot tell a sandboxed device to do something it cannot do.
pub fn classify(denial: &SelinuxDenial, profile: &HostProfile) -> Option<Diagnostic> {
    use acowork_platform_contract::EscalationModel;

    // `permissive=1` means logged-but-allowed: SELinux is not the cause of the failure.
    // Returning `None` is the honest answer, and the contract turns `None` into "could
    // not determine why — inspect the output", which is right.
    if denial.permissive {
        return None;
    }

    let capability = implied_capability(denial).id();
    let can_escalate = matches!(profile.escalation(), EscalationModel::PerCallHelper);

    let diagnostic = |remedy: Remedy, detail: String| {
        Some(Diagnostic {
            capability,
            remedy,
            detail,
        })
    };

    // ── An out-of-roots path ────────────────────────────────────────────────
    // A wrong-path problem rather than a privilege problem, but *only* on a host that
    // cannot escalate. See the module note above.
    if let Some(path) = denial.path.as_deref()
        && !profile.fs_roots.is_empty()
    {
        let covered = profile
            .fs_roots
            .iter()
            .any(|root| path == root.path || path.starts_with(&format!("{}/", root.path)));
        if !covered {
            return if can_escalate {
                // Root reaches further than the unprivileged probe could see, so the
                // path may well be valid — escalate rather than relocate.
                diagnostic(
                    Remedy::Escalate,
                    format!(
                        "`{path}` is outside every root the unprivileged probe could reach, but \
                         this device can escalate and root's reach is wider"
                    ),
                )
            } else {
                let roots: Vec<&str> = profile.fs_roots.iter().map(|r| r.path.as_str()).collect();
                diagnostic(
                    Remedy::Relocate {
                        to: roots.join(", "),
                    },
                    format!(
                        "`{path}` is outside every filesystem root this host exposes, and this \
                         device cannot escalate, so no retry will reach it"
                    ),
                )
            };
        }
    }

    // ── Which domain did it actually run in? ────────────────────────────────
    let ran_privileged = denial
        .scontext
        .as_deref()
        .map(SelinuxDomain::parse)
        .is_some_and(|d| d.is_privileged());

    if !ran_privileged {
        let from = denial
            .scontext
            .as_deref()
            .map(SelinuxDomain::parse)
            .unwrap_or_else(|| profile.domain.clone());
        return if can_escalate {
            diagnostic(
                Remedy::Escalate,
                format!(
                    "blocked by SELinux in the {from:?} domain; re-issue through the privileged \
                     backend, which needs `{}`",
                    implied_capability(denial)
                ),
            )
        } else {
            // Escalating is not an option here, so say what the real constraint is
            // rather than suggesting a retry that cannot work.
            diagnostic(
                Remedy::AskUser {
                    question: format!(
                        "SELinux blocked this in the {from:?} domain and this device has no \
                         escalation path; is there another way to reach the same result?"
                    ),
                },
                format!("blocked in {from:?} with no `su` available"),
            )
        };
    }

    // ── Already privileged and still refused ────────────────────────────────
    // Only a policy change would help, and that needs its own explicit approval
    // (ADR-AND-001 §8: `setenforce 0` is per-command approved and auto-restored).
    diagnostic(
        Remedy::AskUser {
            question: format!(
                "SELinux refuses this even in the privileged domain. Approve `setenforce 0` for \
                 this command? It needs `{}` and is restored automatically at session end.",
                crate::host::capability::Capability::SelinuxPermissive
            ),
        },
        "refused in a privileged domain; only a policy change would help".to_string(),
    )
}

/// The Android [`DiagnosticClassifier`]: `avc: denied` records in, contract remedies out.
///
/// This is where platform specificity legitimately lives. The contract never sees an
/// SELinux domain, a `tclass` or a `permissive` flag; it sees a [`Remedy`]. A second
/// platform writes its own classifier — an ESP32 would inspect an I2C NACK or a
/// flash-verify mismatch — and nothing above it changes.
pub struct SelinuxClassifier<'p> {
    profile: &'p HostProfile,
}

impl<'p> SelinuxClassifier<'p> {
    /// A classifier against one probed profile.
    pub fn new(profile: &'p HostProfile) -> SelinuxClassifier<'p> {
        SelinuxClassifier { profile }
    }
}

impl acowork_platform_contract::DiagnosticClassifier for SelinuxClassifier<'_> {
    fn classify(
        &self,
        capability: &acowork_platform_contract::HostCapability,
        _stdout: &[u8],
        stderr: &[u8],
    ) -> Option<Diagnostic> {
        // Denials are the informative signal; a failure with none is not something this
        // classifier can explain, and guessing would be worse than saying so.
        let text = String::from_utf8_lossy(stderr);
        let denials = parse_denials(&text);
        // Classify the first *enforced* denial. A command that touches several objects
        // produces several records, and the first enforced one is the wall it hit.
        // `find` skips permissive records: SELinux allowed those, so they are not the
        // cause of the failure. If every record was permissive — or there were none —
        // this returns `None`, and the contract's ledger turns that into "could not
        // determine why", which is the honest answer.
        denials
            .iter()
            .find(|d| !d.permissive)
            .and_then(|d| classify(d, self.profile))
            .map(|mut diag| {
                // Trust the caller's capability over the implied one: the caller knows
                // what it asked for, and the implied capability is only a fallback for
                // direct `classify` calls.
                diag.capability = capability.clone();
                diag
            })
    }
}

/// Session-scoped denial memory.
///
/// android-host-probe.md §4 item 2 requires denials to be accumulated so that a second
/// refusal of the same target produces "do not retry". The key is the SELinux target
/// (`tcontext|tclass`), which is finer-grained than the contract's per-capability
/// counting and is an Android fact: hitting the same *wall* twice is the loop to break,
/// and two different walls under one capability are genuinely different attempts.
///
/// Note the contract gap this exposes, recorded as **B10**: §4 says to accumulate "到
/// HostProfile 的 observed-denials", but §3 declares the profile immutable for the
/// session. Both cannot hold. This ledger is therefore separate, which is also what
/// ADR-AND-001 §7.1 wants — observed-denial detail must never reach the Gateway, and
/// keeping it out of the reported profile makes that structurally impossible rather than
/// a matter of remembering to filter.
#[derive(Debug, Clone, Default)]
pub struct DenialLedger {
    seen: BTreeMap<String, u32>,
}

impl DenialLedger {
    /// An empty ledger.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a denial and return the remedy to give the model.
    ///
    /// The repeat check runs **before** classification, so a second hit on the same wall
    /// always says "stop" regardless of how the first one was explained. That ordering is
    /// the point of the ledger: without it the model gets a fresh, plausible-sounding
    /// instruction every time and keeps going.
    ///
    /// The returned remedy is then subject to the contract's admissibility check when it
    /// passes through [`acowork_platform_contract::DiagnosticLedger::admit`], so a
    /// suggestion this layer makes cannot survive if the device cannot act on it.
    pub fn record(&mut self, denial: &SelinuxDenial, profile: &HostProfile) -> Remedy {
        if denial.permissive {
            // Logged but allowed: nothing to fix, and not a failure to count.
            return Remedy::Retry;
        }
        let key = denial.repeat_key();
        let attempts = {
            let counter = self.seen.entry(key.clone()).or_insert(0);
            *counter += 1;
            *counter
        };
        if attempts >= 2 {
            return Remedy::Abandon {
                reason: format!(
                    "this same SELinux target has already been refused {attempts} times this \
                     session; report the limitation instead of retrying"
                ),
            };
        }
        classify(denial, profile)
            .map(|d| d.remedy)
            // No enforced denial we could classify: the contract's ledger turns `None`
            // into "inspect the output", so hand back the same intent.
            .unwrap_or_else(|| Remedy::AskUser {
                question: format!(
                    "SELinux blocked `{key}` and this device could not determine a next step; \
                     inspect the output before retrying"
                ),
            })
    }

    /// How many distinct targets have been refused this session.
    pub fn distinct_targets(&self) -> usize {
        self.seen.len()
    }

    /// True when this target has already been refused.
    pub fn is_repeat(&self, denial: &SelinuxDenial) -> bool {
        self.seen.get(&denial.repeat_key()).is_some_and(|n| *n >= 1)
    }

    /// Drop the session history. The ledger must not outlive its session: a failure
    /// count that persisted would let one bad run permanently poison a device.
    pub fn clear(&mut self) {
        self.seen.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::facts::{
        AppletSet, BuildType, DeviceFacts, FsRoot, Privilege, SelinuxState, ShellDialect, SuProbe,
        VerityState,
    };
    use crate::host::profile::HostProfileName;
    use acowork_platform_contract::{CapabilityTable, EscalationModel, HostDescription};

    /// An empty table over the Android vocabulary.
    fn empty_table() -> CapabilityTable {
        CapabilityTable::new(
            crate::host::capability::PLATFORM,
            crate::host::capability::android_vocabulary(),
        )
        .unwrap()
    }

    /// Derive a table the same way `HostProfile::assemble` does.
    fn derive_table_from(profile: &HostProfile) -> CapabilityTable {
        let mut table = empty_table();
        let claims = crate::host::capability::derive_claims(profile);
        let _ = acowork_platform_contract::audit_claims(
            &mut table,
            &claims,
            std::time::Duration::from_secs(u64::MAX / 2),
        );
        table
    }

    const REAL_LINE: &str = "avc: denied { read open } for pid=4321 comm=\"cat\" \
path=\"/data/system/packages.xml\" dev=\"dm-1\" ino=1234 \
scontext=u:r:shell:s0 tcontext=u:object_r:system_data_file:s0 tclass=file permissive=0";

    /// The same denial against a path *inside* a probed root.
    ///
    /// The domain tests need this: `REAL_LINE`'s `/data/system/packages.xml` is outside
    /// every root in the fixture, so the out-of-roots branch fires first and the domain
    /// branch is never reached. Testing the domain rule against an out-of-roots path
    /// would be testing the wrong branch and passing for the wrong reason.
    const IN_ROOTS_LINE: &str = "avc: denied { read open } for pid=4321 comm=\"cat\" \
path=\"/data/local/tmp/x\" dev=\"dm-1\" ino=1234 \
scontext=u:r:shell:s0 tcontext=u:object_r:shell_data_file:s0 tclass=file permissive=0";

    fn profile() -> HostProfile {
        let mut profile = HostProfile {
            name: HostProfileName::RootShell,
            privilege: Privilege::AppUid,
            selinux: SelinuxState::Enforcing,
            context: Some("u:r:untrusted_app:s0".to_string()),
            domain: SelinuxDomain::UntrustedApp,
            shell: Some(ShellDialect::MkSh),
            dialects: [ShellDialect::MkSh].into_iter().collect(),
            applets: AppletSet::new(),
            fs_roots: vec![
                FsRoot {
                    path: "/data/local/tmp".to_string(),
                    writable: true,
                    own_package: false,
                },
                FsRoot {
                    path: "/data/data/com.example.agent".to_string(),
                    writable: true,
                    own_package: true,
                },
            ],
            su: SuProbe {
                uid: Some(0),
                context: Some("u:r:magisk:s0".to_string()),
                prompt_denied: false,
                unavailable: false,
            },
            system_remountable: false,
            caps: empty_table(),
            device: DeviceFacts {
                build_type: BuildType::UserDebug,
                debuggable: true,
                secure: false,
                adb_secure: false,
                api_level: Some(34),
                abi: None,
                verity: VerityState::Enforcing,
            },
        };
        // Derive the caps so the fixture is a coherent root-shell host: su works,
        // so ShellWrite is available and the classifier is allowed to suggest
        // escalation. An empty `caps` here would model a device that has su but
        // was granted nothing, which is not the case under test.
        profile.caps = derive_table_from(&profile);
        profile
    }

    /// A host with no escalation path: `su` absent, app uid.
    ///
    /// Modelled by clearing the `su` probe rather than by emptying the capability table,
    /// because [`HostProfile::escalation`] reads the probe — which is the fact that
    /// actually decides whether `Remedy::Escalate` is admissible.
    fn no_escalation() -> HostProfile {
        let mut p = profile();
        p.su = SuProbe {
            uid: None,
            context: None,
            prompt_denied: false,
            unavailable: true,
        };
        p.privilege = Privilege::AppUid;
        p.caps = derive_table_from(&p);
        assert_eq!(
            p.escalation(),
            EscalationModel::None,
            "fixture must model a host that cannot escalate"
        );
        p
    }

    #[test]
    fn parses_a_real_audit_line() {
        let denials = parse_denials(REAL_LINE);
        assert_eq!(denials.len(), 1);
        let d = &denials[0];
        assert_eq!(d.permissions, vec!["read".to_string(), "open".to_string()]);
        assert_eq!(d.scontext.as_deref(), Some("u:r:shell:s0"));
        assert_eq!(
            d.tcontext.as_deref(),
            Some("u:object_r:system_data_file:s0")
        );
        assert_eq!(d.tclass.as_deref(), Some("file"));
        assert!(!d.permissive);
        assert_eq!(d.path.as_deref(), Some("/data/system/packages.xml"));
        assert_eq!(d.comm.as_deref(), Some("cat"));
    }

    #[test]
    fn parses_the_kernel_dmesg_wrapper() {
        let line = "type=1400 audit(1700000000.123:89): avc: denied { write } for \
                    pid=99 comm=\"setprop\" scontext=u:r:magisk:s0 \
                    tcontext=u:object_r:system_prop:s0 tclass=property_service permissive=0";
        let denials = parse_denials(line);
        assert_eq!(denials.len(), 1);
        assert_eq!(denials[0].permissions, vec!["write".to_string()]);
        assert_eq!(denials[0].scontext.as_deref(), Some("u:r:magisk:s0"));
    }

    #[test]
    fn parses_multiple_denials_in_one_blob() {
        let blob = format!("{REAL_LINE}\nsome unrelated stderr noise\n{REAL_LINE}\n");
        assert_eq!(parse_denials(&blob).len(), 2);
    }

    #[test]
    fn no_denial_yields_empty_not_an_error() {
        assert!(parse_denials("cat: /data/x: Permission denied").is_empty());
        assert!(parse_denials("").is_empty());
    }

    #[test]
    fn malformed_denial_is_skipped_rather_than_guessed() {
        // No brace group => unparseable => skipped.
        assert!(parse_denials("avc: denied for pid=1").is_empty());
    }

    #[test]
    fn a_permissive_denial_is_not_a_failure() {
        // `permissive=1` means logged-but-allowed. Classifying it as a block would make
        // the model "fix" something that is not broken.
        let line = REAL_LINE.replace("permissive=0", "permissive=1");
        let d = &parse_denials(&line)[0];
        assert!(d.permissive);
        assert_eq!(classify(d, &profile()), None);
    }

    #[test]
    fn an_absent_permissive_field_means_blocked() {
        let line = REAL_LINE.replace(" permissive=0", "");
        let d = &parse_denials(&line)[0];
        assert!(!d.permissive);
        assert!(classify(d, &profile()).is_some());
    }

    #[test]
    fn an_unprivileged_domain_on_an_escalating_host_is_told_to_escalate() {
        let d = &parse_denials(IN_ROOTS_LINE)[0];
        let diag = classify(d, &profile()).expect("an enforced denial must classify");
        assert_eq!(diag.remedy, Remedy::Escalate);
        // R9: the detail names the domain it ran in and the capability it needs.
        assert!(diag.detail.contains("Shell"), "{}", diag.detail);
        assert!(
            diag.detail.contains("android:shell:read"),
            "{}",
            diag.detail
        );
    }

    #[test]
    fn a_write_access_names_the_write_capability() {
        let line = "avc: denied { write } for comm=\"touch\" path=\"/data/local/tmp/x\" \
                    scontext=u:r:untrusted_app:s0 tcontext=u:object_r:shell_data_file:s0 \
                    tclass=file permissive=0";
        let d = &parse_denials(line)[0];
        let diag = classify(d, &profile()).unwrap();
        assert_eq!(diag.remedy, Remedy::Escalate);
        assert!(
            diag.detail.contains("android:shell:write"),
            "{}",
            diag.detail
        );
    }

    #[test]
    fn an_unprivileged_domain_on_a_sandbox_asks_instead_of_suggesting_escalation() {
        // The contract would reject `Escalate` here anyway; classifying honestly means
        // the model is not sent down a path that cannot work.
        let d = &parse_denials(IN_ROOTS_LINE)[0];
        let diag = classify(d, &no_escalation()).unwrap();
        assert!(
            matches!(diag.remedy, Remedy::AskUser { .. }),
            "a sandbox has no escalation to suggest; got {:?}",
            diag.remedy
        );
        assert!(diag.remedy.is_admissible(&no_escalation()));
    }

    #[test]
    fn a_privileged_domain_still_refused_points_at_permissive_approval() {
        let line = "avc: denied { read } for comm=\"cat\" path=\"/data/local/tmp/x\" \
                    scontext=u:r:magisk:s0 tcontext=u:object_r:system_data_file:s0 \
                    tclass=file permissive=0";
        let d = &parse_denials(line)[0];
        let diag = classify(d, &profile()).unwrap();
        match &diag.remedy {
            Remedy::AskUser { question } => {
                assert!(
                    question.contains("android:selinux:permissive"),
                    "{question}"
                );
                assert!(question.contains("setenforce 0"), "{question}");
            }
            other => panic!("expected a permissive-approval question, got {other:?}"),
        }
    }

    #[test]
    fn an_out_of_roots_path_on_a_sandbox_relocates() {
        let line = "avc: denied { read } for comm=\"cat\" path=\"/mnt/secret/x\" \
                    scontext=u:r:shell:s0 tcontext=u:object_r:mnt_file:s0 \
                    tclass=file permissive=0";
        let d = &parse_denials(line)[0];
        let diag = classify(d, &no_escalation()).unwrap();
        match &diag.remedy {
            Remedy::Relocate { to } => {
                assert!(to.contains("/data/local/tmp"), "{to}");
            }
            other => panic!("expected Relocate on a sandbox, got {other:?}"),
        }
    }

    #[test]
    fn an_out_of_roots_path_on_a_rooted_device_still_offers_escalation() {
        // This is the defect the guard exists for. `fs_roots` records what the
        // *unprivileged* probe could reach, not what root can reach, so on a rooted
        // device "wrong path, privilege will not help" is false — and saying it steers
        // the model away from the one action that would have worked.
        let line = "avc: denied { read } for comm=\"cat\" path=\"/mnt/secret/x\" \
                    scontext=u:r:shell:s0 tcontext=u:object_r:mnt_file:s0 \
                    tclass=file permissive=0";
        let d = &parse_denials(line)[0];
        let diag = classify(d, &profile()).unwrap();
        assert_eq!(
            diag.remedy,
            Remedy::Escalate,
            "a rooted device must not be told escalation cannot help"
        );
        assert!(diag.detail.contains("/mnt/secret/x"), "{}", diag.detail);
    }

    #[test]
    fn every_remedy_this_module_produces_is_admissible_on_its_host() {
        // The invariant the contract enforces and this module must not violate: never
        // suggest an action the device cannot perform.
        let lines = [
            REAL_LINE,
            "avc: denied { write } for comm=\"touch\" path=\"/data/local/tmp/x\" \
             scontext=u:r:untrusted_app:s0 tcontext=u:object_r:shell_data_file:s0 \
             tclass=file permissive=0",
            "avc: denied { read } for comm=\"cat\" path=\"/mnt/secret/x\" \
             scontext=u:r:shell:s0 tcontext=u:object_r:mnt_file:s0 tclass=file permissive=0",
            "avc: denied { read } for comm=\"cat\" path=\"/data/local/tmp/x\" \
             scontext=u:r:magisk:s0 tcontext=u:object_r:system_data_file:s0 \
             tclass=file permissive=0",
        ];
        for (line, host) in lines
            .iter()
            .zip([profile(), profile(), no_escalation(), profile()])
        {
            let d = &parse_denials(line)[0];
            if let Some(diag) = classify(d, &host) {
                assert!(
                    diag.remedy.is_admissible(&host),
                    "{:?} is not admissible on a host whose escalation model is {:?}",
                    diag.remedy,
                    host.escalation()
                );
            }
        }
    }

    #[test]
    fn the_classifier_reads_denials_out_of_stderr() {
        use acowork_platform_contract::DiagnosticClassifier;

        let profile = profile();
        let classifier = SelinuxClassifier::new(&profile);
        let cap = crate::host::capability::Capability::ShellRead.id();
        let stderr = format!("some noise\n{IN_ROOTS_LINE}\n");
        let diag = classifier
            .classify(&cap, b"", stderr.as_bytes())
            .expect("an enforced denial in stderr must classify");
        // The caller's capability wins over the implied one: the caller knows what it
        // asked for.
        assert_eq!(diag.capability, cap);
        assert_eq!(diag.remedy, Remedy::Escalate);
    }

    #[test]
    fn the_classifier_returns_none_when_stderr_has_no_enforced_denial() {
        use acowork_platform_contract::DiagnosticClassifier;

        let profile = profile();
        let classifier = SelinuxClassifier::new(&profile);
        let cap = crate::host::capability::Capability::ShellRead.id();
        // A plain permission error with no SELinux record: this classifier cannot
        // explain it, and guessing would be worse than saying so.
        assert!(
            classifier
                .classify(&cap, b"", b"cat: /x: Permission denied")
                .is_none()
        );
        // Permissive-only denials are not a block either.
        let permissive = REAL_LINE.replace("permissive=0", "permissive=1");
        assert!(
            classifier
                .classify(&cap, b"", permissive.as_bytes())
                .is_none()
        );
    }

    #[test]
    fn repeat_key_ignores_scontext_but_respects_tcontext_and_tclass() {
        let a = parse_denials(REAL_LINE)[0].clone();
        let mut b = a.clone();
        b.scontext = Some("u:r:magisk:s0".to_string());
        assert_eq!(
            a.repeat_key(),
            b.repeat_key(),
            "a retry from another domain hits the same wall"
        );

        let mut c = a.clone();
        c.tcontext = Some("u:object_r:other:s0".to_string());
        assert_ne!(a.repeat_key(), c.repeat_key());
    }

    #[test]
    fn ledger_does_not_count_permissive_logging_as_a_refusal() {
        let mut ledger = DenialLedger::new();
        let line = REAL_LINE.replace("permissive=0", "permissive=1");
        let d = parse_denials(&line)[0].clone();
        let p = profile();
        // A permissive record is not a refusal, so it is not counted at all.
        assert_eq!(ledger.record(&d, &p), Remedy::Retry);
        assert_eq!(ledger.record(&d, &p), Remedy::Retry);
        assert_eq!(ledger.distinct_targets(), 0);
    }

    #[test]
    fn a_second_hit_on_the_same_wall_says_stop() {
        // android-host-probe.md §4 item 2: this is the silent-degradation loop the
        // ledger exists to break. The repeat check runs *before* classification, so the
        // second answer is "stop" no matter how plausible the first one sounded.
        let mut ledger = DenialLedger::new();
        let p = profile();
        let d = parse_denials(IN_ROOTS_LINE)[0].clone();

        let first = ledger.record(&d, &p);
        assert_eq!(
            first,
            Remedy::Escalate,
            "the first hit should suggest the real fix"
        );
        let second = ledger.record(&d, &p);
        match second {
            Remedy::Abandon { reason } => {
                assert!(reason.contains("2 times"), "{reason}");
                assert!(reason.contains("report the limitation"), "{reason}");
            }
            other => panic!("expected Abandon on the second hit, got {other:?}"),
        }
        assert!(ledger.is_repeat(&d));
    }

    #[test]
    fn a_retry_from_a_different_domain_is_the_same_wall() {
        // `repeat_key` excludes scontext on purpose: escalating and hitting the same
        // target again is not a new idea, and counting it as one would let the loop run
        // one more turn.
        let mut ledger = DenialLedger::new();
        let p = profile();
        let a = parse_denials(IN_ROOTS_LINE)[0].clone();
        let mut b = a.clone();
        b.scontext = Some("u:r:magisk:s0".to_string());

        ledger.record(&a, &p);
        assert!(matches!(ledger.record(&b, &p), Remedy::Abandon { .. }));
        assert_eq!(ledger.distinct_targets(), 1);
    }

    #[test]
    fn the_ledger_does_not_outlive_its_session() {
        let mut ledger = DenialLedger::new();
        let p = profile();
        let d = parse_denials(IN_ROOTS_LINE)[0].clone();
        ledger.record(&d, &p);
        assert_eq!(ledger.distinct_targets(), 1);
        ledger.clear();
        assert_eq!(ledger.distinct_targets(), 0);
        assert!(!ledger.is_repeat(&d));
        // After clearing, the same denial is a first hit again.
        assert_eq!(ledger.record(&d, &p), Remedy::Escalate);
    }

    #[test]
    fn ledger_tracks_distinct_targets_separately() {
        let mut ledger = DenialLedger::new();
        let p = profile();
        let a = parse_denials(REAL_LINE)[0].clone();
        let mut b = a.clone();
        b.tcontext = Some("u:object_r:system_prop:s0".to_string());

        ledger.record(&a, &p);
        ledger.record(&b, &p);
        assert_eq!(ledger.distinct_targets(), 2);
        assert!(ledger.is_repeat(&a));
    }
}
