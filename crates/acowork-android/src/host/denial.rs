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

/// What the model should do next, in plain language.
///
/// ADR-AND-001 §4.6 item 2 requires the hint to be *executable* — naming the
/// missing capability rather than restating the denial. Each variant maps to a
/// concrete next action, which is what stops the retry loop.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DenialHint {
    /// The access was logged but granted (`permissive=1`). Not a failure.
    NotBlocked,
    /// The command ran in an unprivileged domain and needs the `su` helper.
    /// Next step: re-issue through the privileged backend.
    NeedsEscalatedDomain {
        /// The domain the command actually ran in.
        from: SelinuxDomain,
        /// The capability the privileged backend would need.
        capability: String,
    },
    /// Even the privileged domain is refused by policy. The only route is
    /// `setenforce 0`, which needs its own explicit approval and is restored at
    /// session end (ADR-AND-001 §8).
    /// Even the privileged domain is refused; only `setenforce 0` would help.
    NeedsPermissiveApproval {
        /// The capability that would have to be approved: `android:selinux:permissive`.
        capability: String,
    },
    /// The target is outside every probed `fs_roots` entry. No amount of
    /// privilege makes this a good idea; the path itself is wrong.
    /// The target is outside every probed root — a wrong path, not a privilege gap.
    PathOutsideRoots {
        /// The offending path, when the kernel reported one.
        path: Option<String>,
    },
    /// This exact target has already been refused in this session. Retrying is
    /// the silent-degradation loop §4 exists to prevent.
    /// This target was already refused in this session. Retrying is the loop §4 blocks.
    DoNotRetry {
        /// How many times this same target has now been refused.
        attempts: u32,
    },
    /// A denial we could not classify. Still reported, because swallowing it
    /// would hide a real block; the raw record travels with it.
    Unclassified,
}

impl DenialHint {
    /// The sentence handed back to the model.
    ///
    /// Written as an instruction rather than a description, because the consumer
    /// is an LLM deciding its next tool call.
    pub fn message(&self) -> String {
        match self {
            DenialHint::NotBlocked => "SELinux logged this access but allowed it (permissive=1). \
                 Nothing to fix — continue."
                .to_string(),
            DenialHint::NeedsEscalatedDomain { from, capability } => {
                format!(
                    "Blocked by SELinux: the command ran in the {from:?} domain. \
                     Re-issue it through the privileged backend, which requires \
                     the `{capability}` capability."
                )
            }
            DenialHint::NeedsPermissiveApproval { capability } => {
                format!(
                    "Blocked by SELinux even in the privileged domain. The only \
                     route is `setenforce 0`, which needs the `{capability}` \
                     capability and explicit per-command approval; it is \
                     restored automatically at session end. Do not retry the \
                     original command unchanged."
                )
            }
            DenialHint::PathOutsideRoots { path } => match path {
                Some(p) => format!(
                    "`{p}` is outside every filesystem root this host exposes. \
                     Privilege will not help — pick a path under a probed root."
                ),
                None => "The target is outside every filesystem root this host \
                         exposes. Privilege will not help."
                    .to_string(),
            },
            DenialHint::DoNotRetry { attempts } => format!(
                "This same target has already been refused {attempts} time(s) in \
                 this session. Do not retry — report the limitation instead."
            ),
            DenialHint::Unclassified => "SELinux refused this access and the reason could not be \
                 classified. Treat it as a hard block; do not retry blindly."
                .to_string(),
        }
    }
}

/// Classify one denial against the profile it happened on.
///
/// Pure function: same denial plus same profile always yields the same hint. The
/// repeat counter is applied separately by [`DenialLedger`], because repeats are
/// a property of the session rather than of the denial.
pub fn classify(denial: &SelinuxDenial, profile: &HostProfile) -> DenialHint {
    if denial.permissive {
        return DenialHint::NotBlocked;
    }

    let can_escalate = profile
        .caps
        .contains(crate::host::capability::Capability::ShellWrite);

    // A path outside every probed root is a wrong-path problem rather than a
    // privilege problem — but **only on a host that cannot escalate anyway**.
    //
    // The guard matters. `fs_roots` records what the *unprivileged* probe could
    // reach (android-host-probe.md §2 item 12 probes `$PREFIX`, `/sdcard` and the
    // package directory); it is not an enumeration of what root can reach, which
    // per the README capability matrix is "/data 大范围". So on a root-shell host
    // an out-of-roots path is still an escalation candidate, and answering "wrong
    // path, privilege will not help" would send the model away from the one thing
    // that would have worked. On Termux/APK there is no escalation, so the same
    // answer is correct and is exactly what stops the retry loop.
    if !can_escalate
        && let Some(path) = denial.path.as_deref()
        && !profile.fs_roots.is_empty()
    {
        let covered = profile
            .fs_roots
            .iter()
            .any(|root| path == root.path || path.starts_with(&format!("{}/", root.path)));
        if !covered {
            return DenialHint::PathOutsideRoots {
                path: Some(path.to_string()),
            };
        }
    }

    let ran_privileged = denial
        .scontext
        .as_deref()
        .map(SelinuxDomain::parse)
        .is_some_and(|d| d.is_privileged());

    if !ran_privileged {
        // The attempt came from an unprivileged domain, so the first thing to try
        // is the privileged backend — provided the host actually has one.
        let from = denial
            .scontext
            .as_deref()
            .map(SelinuxDomain::parse)
            .unwrap_or(profile.domain.clone());
        let capability = if is_write_access(&denial.permissions) {
            crate::host::capability::Capability::ShellWrite
        } else {
            crate::host::capability::Capability::ShellRead
        };
        return DenialHint::NeedsEscalatedDomain {
            from,
            capability: capability.as_str().to_string(),
        };
    }

    // Already privileged and still refused: only a policy change would help.
    DenialHint::NeedsPermissiveApproval {
        capability: crate::host::capability::Capability::SelinuxPermissive
            .as_str()
            .to_string(),
    }
}

/// Whether any of the denied permissions is a write-class access.
fn is_write_access(permissions: &[String]) -> bool {
    permissions.iter().any(|p| {
        matches!(
            p.as_str(),
            "write" | "append" | "create" | "unlink" | "rename" | "setattr" | "mounton" | "execute"
        )
    })
}

/// Session-scoped denial accumulator.
///
/// android-host-probe.md §4 item 2 requires denials to be accumulated so that a
/// second refusal of the same target produces "do not retry". Note the contract
/// gap this exposes, recorded as **B10** in the readiness assessment: §4 says to
/// accumulate "到 HostProfile 的 observed-denials", but §3 declares the profile
/// immutable for the session. Both cannot hold. This ledger is therefore a
/// separate session-scoped structure, which is also what ADR-AND-001 §7.1 wants —
/// observed-denial detail must never reach the Gateway, and keeping it out of the
/// reported profile makes that structurally impossible rather than a matter of
/// remembering to filter.
#[derive(Debug, Clone, Default)]
pub struct DenialLedger {
    seen: BTreeMap<String, u32>,
}

impl DenialLedger {
    /// An empty ledger.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a denial and return the hint to give the model.
    ///
    /// The repeat check runs **before** classification, so a second hit on the
    /// same wall always says "do not retry" regardless of how the first one was
    /// explained. That ordering is the point of the ledger: without it the model
    /// gets a fresh, plausible-sounding instruction every time and keeps going.
    pub fn record(&mut self, denial: &SelinuxDenial, profile: &HostProfile) -> DenialHint {
        if denial.permissive {
            return DenialHint::NotBlocked;
        }
        let key = denial.repeat_key();
        let attempts = {
            let counter = self.seen.entry(key).or_insert(0);
            *counter += 1;
            *counter
        };
        if attempts >= 2 {
            return DenialHint::DoNotRetry { attempts };
        }
        classify(denial, profile)
    }

    /// How many distinct targets have been refused this session.
    pub fn distinct_targets(&self) -> usize {
        self.seen.len()
    }

    /// True when this target has already been refused.
    pub fn is_repeat(&self, denial: &SelinuxDenial) -> bool {
        self.seen.get(&denial.repeat_key()).is_some_and(|n| *n >= 1)
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

    const REAL_LINE: &str = "avc: denied { read open } for pid=4321 comm=\"cat\" \
path=\"/data/system/packages.xml\" dev=\"dm-1\" ino=1234 \
scontext=u:r:shell:s0 tcontext=u:object_r:system_data_file:s0 tclass=file permissive=0";

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
            caps: Default::default(),
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
        profile.caps = crate::host::capability::derive_capabilities(&profile);
        profile
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
    fn permissive_flag_is_honoured() {
        let line = REAL_LINE.replace("permissive=0", "permissive=1");
        let d = &parse_denials(&line)[0];
        assert!(d.permissive);
        assert_eq!(classify(d, &profile()), DenialHint::NotBlocked);
    }

    #[test]
    fn absent_permissive_field_means_blocked() {
        let line = REAL_LINE.replace(" permissive=0", "");
        let d = &parse_denials(&line)[0];
        assert!(!d.permissive);
        assert_ne!(classify(d, &profile()), DenialHint::NotBlocked);
    }

    #[test]
    fn unprivileged_domain_is_told_to_escalate() {
        let d = &parse_denials(REAL_LINE)[0];
        match classify(d, &profile()) {
            DenialHint::NeedsEscalatedDomain { from, capability } => {
                assert_eq!(from, SelinuxDomain::Shell);
                // read/open are not write-class, so the read capability suffices.
                assert_eq!(capability, "android:shell:read");
            }
            other => panic!("expected escalation hint, got {other:?}"),
        }
    }

    #[test]
    fn write_access_from_unprivileged_domain_names_the_write_capability() {
        let line = "avc: denied { write } for comm=\"touch\" path=\"/data/local/tmp/x\" \
                    scontext=u:r:untrusted_app:s0 tcontext=u:object_r:shell_data_file:s0 \
                    tclass=file permissive=0";
        let d = &parse_denials(line)[0];
        match classify(d, &profile()) {
            DenialHint::NeedsEscalatedDomain { capability, .. } => {
                assert_eq!(capability, "android:shell:write")
            }
            other => panic!("expected escalation hint, got {other:?}"),
        }
    }

    #[test]
    fn privileged_domain_still_refused_points_at_permissive_approval() {
        let line = "avc: denied { read } for comm=\"cat\" path=\"/data/local/tmp/x\" \
                    scontext=u:r:magisk:s0 tcontext=u:object_r:system_data_file:s0 \
                    tclass=file permissive=0";
        let d = &parse_denials(line)[0];
        match classify(d, &profile()) {
            DenialHint::NeedsPermissiveApproval { capability } => {
                assert_eq!(capability, "android:selinux:permissive")
            }
            other => panic!("expected permissive hint, got {other:?}"),
        }
    }

    #[test]
    fn path_outside_every_root_is_a_wrong_path_problem_not_a_privilege_one() {
        let line = "avc: denied { read } for comm=\"cat\" path=\"/mnt/secret/x\" \
                    scontext=u:r:shell:s0 tcontext=u:object_r:mnt_file:s0 \
                    tclass=file permissive=0";
        let d = &parse_denials(line)[0];
        // A host that cannot escalate: here "wrong path" is the truthful answer.
        let mut no_escalation = profile();
        no_escalation.caps = Default::default();
        match classify(d, &no_escalation) {
            DenialHint::PathOutsideRoots { path } => {
                assert_eq!(path.as_deref(), Some("/mnt/secret/x"))
            }
            other => panic!("expected outside-roots hint, got {other:?}"),
        }
    }

    #[test]
    fn an_escalatable_host_is_told_to_escalate_even_for_an_out_of_root_path() {
        // The regression this guards: fs_roots is the *unprivileged* reachability
        // probe, not an enumeration of what root can reach. Answering "wrong path"
        // here would send the model away from the fix that would have worked.
        let line = "avc: denied { read } for comm=\"cat\" path=\"/data/system/packages.xml\" \
                    scontext=u:r:shell:s0 tcontext=u:object_r:system_data_file:s0 \
                    tclass=file permissive=0";
        let d = &parse_denials(line)[0];
        assert!(matches!(
            classify(d, &profile()),
            DenialHint::NeedsEscalatedDomain { .. }
        ));
    }

    #[test]
    fn a_path_under_a_probed_root_is_not_reported_as_outside() {
        let line = "avc: denied { read } for comm=\"cat\" path=\"/data/local/tmp/sub/x\" \
                    scontext=u:r:shell:s0 tcontext=u:object_r:shell_data_file:s0 \
                    tclass=file permissive=0";
        let d = &parse_denials(line)[0];
        assert!(matches!(
            classify(d, &profile()),
            DenialHint::NeedsEscalatedDomain { .. }
        ));
    }

    #[test]
    fn every_hint_message_is_actionable_and_names_a_next_step() {
        let hints = [
            DenialHint::NotBlocked,
            DenialHint::NeedsEscalatedDomain {
                from: SelinuxDomain::Shell,
                capability: "android:shell:read".to_string(),
            },
            DenialHint::NeedsPermissiveApproval {
                capability: "android:selinux:permissive".to_string(),
            },
            DenialHint::PathOutsideRoots {
                path: Some("/mnt/x".to_string()),
            },
            DenialHint::DoNotRetry { attempts: 2 },
            DenialHint::Unclassified,
        ];
        for hint in hints {
            let msg = hint.message();
            assert!(msg.len() > 20, "hint too terse to act on: {msg}");
            assert!(
                !msg.contains("avc:") && !msg.contains("scontext="),
                "hint must be translated, not a raw kernel line: {msg}"
            );
        }
    }

    #[test]
    fn ledger_turns_a_second_hit_on_the_same_target_into_do_not_retry() {
        let mut ledger = DenialLedger::new();
        let d = parse_denials(REAL_LINE)[0].clone();
        let p = profile();

        let first = ledger.record(&d, &p);
        assert!(matches!(first, DenialHint::NeedsEscalatedDomain { .. }));
        assert!(!matches!(first, DenialHint::DoNotRetry { .. }));

        let second = ledger.record(&d, &p);
        assert_eq!(second, DenialHint::DoNotRetry { attempts: 2 });

        let third = ledger.record(&d, &p);
        assert_eq!(third, DenialHint::DoNotRetry { attempts: 3 });
        assert_eq!(ledger.distinct_targets(), 1);
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
        assert_eq!(ledger.record(&d, &p), DenialHint::NotBlocked);
        assert_eq!(ledger.record(&d, &p), DenialHint::NotBlocked);
        assert_eq!(ledger.distinct_targets(), 0);
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
