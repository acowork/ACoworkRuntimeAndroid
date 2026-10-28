//! The capability model: namespaced IDs and the four axes every capability must
//! declare.
//!
//! # R5 — the vocabulary belongs to the protocol, the facts belong to the device
//!
//! A capability ID is `<platform>:<name>`, where `<platform>` is the port's
//! registered namespace (`android`, `esp32`, ...) and `<name>` may itself contain
//! colons. IDs are **closed**: [`HostCapability::parse`] rejects a malformed ID
//! and [`CapabilityTable::spec`] returns `None` for an unregistered one. A port
//! declares which capabilities it has; it does not mint new ones at runtime.
//! Silently accepting an unrecognised ID is how a vocabulary change turns into a
//! privilege escalation.
//!
//! # R6 — four axes, composed uniformly
//!
//! The gate in [`crate::gate`] contains no platform-specific branch. Everything it
//! knows about a capability comes from the [`CapabilitySpec`] the port registered.
//! That is what makes the rules uniform rather than merely similar: adding a
//! platform cannot change how authorization works, because authorization only ever
//! reads the table.
//!
//! The corollary is that an open question about a capability belongs in the
//! *table*, not in a gate branch. Android's `shell:write` covers package
//! installation, which upstream ADR-087 D4 reads as a `manage`-tier action, while
//! ADR-AND-001 §7.4 gates only the two system-tier capabilities on ownership. That
//! disagreement is recorded as B11 in the readiness assessment, and it is answered
//! today by declaring `AttributionTier::None` for `android:shell:write` — visible,
//! testable data, changeable in one line, with no gate edit required.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;

use serde::{Deserialize, Serialize};

/// A parsed, validated capability identifier.
///
/// Cheap to clone (one small allocation) and safe to use as a map key.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct HostCapability(String);

/// The two halves of a capability ID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostCapabilityId<'a> {
    /// The port's registered namespace, e.g. `android`.
    pub platform: &'a str,
    /// The capability name inside that namespace, e.g. `shell:read`.
    pub name: &'a str,
}

/// Why an ID was rejected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CapabilityIdError {
    /// No `:` separator, so there is no namespace.
    MissingNamespace,
    /// The namespace is empty or contains a character outside `[a-z0-9_]`.
    BadNamespace(String),
    /// The name is empty.
    EmptyName,
    /// The name contains a character outside `[a-z0-9_:.-]`.
    BadName(String),
}

impl fmt::Display for CapabilityIdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CapabilityIdError::MissingNamespace => write!(
                f,
                "a capability id must be `<platform>:<name>`; no namespace separator found"
            ),
            CapabilityIdError::BadNamespace(ns) => {
                write!(f, "invalid platform namespace `{ns}`: expected [a-z0-9_]+")
            }
            CapabilityIdError::EmptyName => write!(f, "capability name is empty"),
            CapabilityIdError::BadName(name) => {
                write!(
                    f,
                    "invalid capability name `{name}`: expected [a-z0-9_:.-]+"
                )
            }
        }
    }
}

// `core::error::Error`, not `std::error::Error`: the trait has been in `core` since
// 1.81, so a `no_std` port gets the same impl, and on a `std` platform this *is*
// `std::error::Error` (the latter is a re-export). Implementing it is what lets a
// caller write `HostCapability::parse(id)?` into a `Box<dyn Error>` or an `anyhow`
// context instead of hand-mapping the failure.
impl core::error::Error for CapabilityIdError {}

impl HostCapability {
    /// Build an ID from its two halves, validating each.
    pub fn new(platform: &str, name: &str) -> Result<HostCapability, CapabilityIdError> {
        HostCapability::parse(&alloc::format!("{platform}:{name}"))
    }

    /// Parse and validate a `<platform>:<name>` identifier.
    ///
    /// The namespace is the text before the **first** colon, so a name may contain
    /// further colons (`android:shell:read` → platform `android`, name
    /// `shell:read`).
    pub fn parse(id: &str) -> Result<HostCapability, CapabilityIdError> {
        let (platform, name) = id
            .split_once(':')
            .ok_or(CapabilityIdError::MissingNamespace)?;

        if platform.is_empty()
            || !platform
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        {
            return Err(CapabilityIdError::BadNamespace(platform.to_string()));
        }
        if name.is_empty() {
            return Err(CapabilityIdError::EmptyName);
        }
        if !name.chars().all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '_' | ':' | '.' | '-')
        }) {
            return Err(CapabilityIdError::BadName(name.to_string()));
        }
        Ok(HostCapability(id.to_string()))
    }

    /// The whole identifier, e.g. `android:shell:read`.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Split into namespace and name. Infallible: construction validated it.
    pub fn parts(&self) -> HostCapabilityId<'_> {
        let (platform, name) = self.0.split_once(':').expect("validated at construction");
        HostCapabilityId { platform, name }
    }

    /// The port namespace this capability belongs to.
    pub fn platform(&self) -> &str {
        self.parts().platform
    }
}

impl fmt::Display for HostCapability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Whether exercising the capability changes device state.
///
/// Drives the resource lock: a read-only capability never takes it, so read-only
/// diagnostics stay available while another session is mid-write.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Effect {
    /// Observes state only.
    ReadOnly,
    /// Changes device-global state, and therefore has to be serialised.
    Mutating,
}

impl Effect {
    /// True when the capability must hold the device resource lock.
    pub fn needs_lock(&self) -> bool {
        matches!(self, Effect::Mutating)
    }
}

/// What human involvement a capability needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ApprovalRequirement {
    /// Whitelist auto-approved. The read tier on every platform.
    None,
    /// One approval per use.
    PerUse,
    /// One approval per use **and** the session must have been started with the
    /// platform's dangerous-mode switch. Never persisted.
    DangerousSession,
}

impl ApprovalRequirement {
    /// True when a token must be presented.
    pub fn needs_token(&self) -> bool {
        !matches!(self, ApprovalRequirement::None)
    }

    /// True when the session-level dangerous-mode switch must also be on.
    pub fn needs_dangerous_session(&self) -> bool {
        matches!(self, ApprovalRequirement::DangerousSession)
    }
}

/// Which control-plane ownership tier a capability maps to.
///
/// Mirrors upstream ADR-087 D4's three tiers. The gate requires a granted
/// attribution verdict for anything above [`AttributionTier::None`]; it never
/// interprets the tier itself, because *who* satisfies it is the control plane's
/// question (R7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttributionTier {
    /// No ownership check. Auto-approved read paths.
    None,
    /// ADR-087 `use = owner ∨ guest ∨ admin`.
    Use,
    /// ADR-087 `manage = owner ∨ admin`.
    Manage,
}

impl AttributionTier {
    /// True when the gate must see a granted attribution verdict.
    pub fn needs_attribution(&self) -> bool {
        !matches!(self, AttributionTier::None)
    }
}

/// Whether an action can be undone.
///
/// R8: an irreversible capability is refused unless the caller states a rollback
/// path. Irreversibility is a property of the action, not of the platform — Android
/// has raw block-device writes, an ESP32 has an eFuse burn, and both need the same
/// treatment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Reversibility {
    /// Undoable, or harmless enough not to need undoing.
    Reversible,
    /// Needs a stated rollback path before it will run.
    Irreversible,
}

impl Reversibility {
    /// True when a rollback plan must accompany the request.
    pub fn needs_rollback_plan(&self) -> bool {
        matches!(self, Reversibility::Irreversible)
    }
}

/// One registered capability and its four axes.
///
/// This is the whole of what the gate knows about a capability (R6).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilitySpec {
    /// The identifier.
    pub id: HostCapability,
    /// Axis 1 — does it change device state?
    pub effect: Effect,
    /// Axis 2 — what human involvement does it need?
    pub approval: ApprovalRequirement,
    /// Axis 3 — which ownership tier does it map to?
    pub attribution: AttributionTier,
    /// Axis 4 — can it be undone?
    pub reversibility: Reversibility,
}

impl CapabilitySpec {
    /// A read-only, auto-approved, reversible capability — the shape every
    /// platform's observation tier has.
    pub fn read_only(id: HostCapability) -> CapabilitySpec {
        CapabilitySpec {
            id,
            effect: Effect::ReadOnly,
            approval: ApprovalRequirement::None,
            attribution: AttributionTier::None,
            reversibility: Reversibility::Reversible,
        }
    }
}

/// The registered vocabulary for one platform, plus what this device declared.
///
/// Two halves on purpose:
/// - `specs` is the **vocabulary** — what the port says its capabilities mean.
///   Identical on every device of that platform.
/// - `declared` is the **facts** — which of them this device demonstrated.
///   Different per device, and derived by the port's own probe.
///
/// Keeping them apart is what makes R1 checkable: a capability can only be
/// declared if it is in the vocabulary, so a port cannot grant itself something it
/// never registered.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityTable {
    platform: String,
    specs: Vec<CapabilitySpec>,
    declared: Vec<HostCapability>,
}

/// Why a table could not be built or a capability could not be declared.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CapabilityTableError {
    /// A spec belonged to a different platform's namespace.
    ForeignNamespace {
        /// The namespace the table was built for.
        platform: String,
        /// The offending capability.
        found: HostCapability,
    },
    /// Two specs registered the same ID.
    DuplicateSpec(HostCapability),
    /// The device tried to declare an ID outside the vocabulary.
    Unregistered(HostCapability),
}

impl fmt::Display for CapabilityTableError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CapabilityTableError::ForeignNamespace { platform, found } => write!(
                f,
                "capability `{found}` belongs to another platform; this table serves `{platform}`"
            ),
            CapabilityTableError::DuplicateSpec(id) => {
                write!(f, "capability `{id}` is registered twice")
            }
            CapabilityTableError::Unregistered(id) => write!(
                f,
                "capability `{id}` is not in this platform's vocabulary and cannot be declared"
            ),
        }
    }
}

/// See the note on [`CapabilityIdError`]: `core::error::Error` so this works under
/// `no_std` as well, and is `std::error::Error` on a `std` platform.
impl core::error::Error for CapabilityTableError {}

impl CapabilityTable {
    /// Build a table from a platform's vocabulary.
    ///
    /// Every spec must belong to `platform`; a spec from another namespace is a
    /// port bug and is rejected here rather than silently ignored, because
    /// ignoring it would let a device declare a capability the gate cannot find a
    /// spec for.
    pub fn new(
        platform: &str,
        specs: Vec<CapabilitySpec>,
    ) -> Result<CapabilityTable, CapabilityTableError> {
        for spec in &specs {
            if spec.id.platform() != platform {
                return Err(CapabilityTableError::ForeignNamespace {
                    platform: platform.to_string(),
                    found: spec.id.clone(),
                });
            }
        }
        // Reject duplicates: two specs for one ID would make the gate's behaviour
        // depend on ordering, which is exactly the kind of ambiguity R6 exists to
        // remove.
        let mut ids: Vec<&HostCapability> = specs.iter().map(|s| &s.id).collect();
        ids.sort();
        if let Some(pair) = ids.windows(2).find(|w| w[0] == w[1]) {
            return Err(CapabilityTableError::DuplicateSpec(pair[0].clone()));
        }
        Ok(CapabilityTable {
            platform: platform.to_string(),
            specs,
            declared: Vec::new(),
        })
    }

    /// The platform namespace this table serves.
    pub fn platform(&self) -> &str {
        &self.platform
    }

    /// The spec for a capability, if it is in this platform's vocabulary.
    ///
    /// `None` means unregistered — and per R5 an unregistered capability is not
    /// authorizable, whatever the device claims.
    pub fn spec(&self, id: &HostCapability) -> Option<&CapabilitySpec> {
        self.specs.iter().find(|s| &s.id == id)
    }

    /// The whole vocabulary.
    pub fn specs(&self) -> &[CapabilitySpec] {
        &self.specs
    }

    /// Declare a capability this device demonstrated.
    ///
    /// Returns `Err` if the ID is not in the vocabulary: a device may not declare
    /// what its platform never registered (R5).
    pub fn declare(&mut self, id: HostCapability) -> Result<(), CapabilityTableError> {
        if self.spec(&id).is_none() {
            return Err(CapabilityTableError::Unregistered(id));
        }
        if !self.declared.contains(&id) {
            self.declared.push(id);
            self.declared.sort();
        }
        Ok(())
    }

    /// Whether this device declared the capability.
    pub fn is_declared(&self, id: &HostCapability) -> bool {
        self.declared.contains(id)
    }

    /// Everything this device declared, in stable order.
    pub fn declared(&self) -> &[HostCapability] {
        &self.declared
    }

    /// The declared IDs as strings, for the reported summary.
    pub fn declared_ids(&self) -> Vec<&str> {
        self.declared.iter().map(HostCapability::as_str).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn android_vocab() -> Vec<CapabilitySpec> {
        vec![
            CapabilitySpec::read_only(HostCapability::parse("android:shell:read").unwrap()),
            CapabilitySpec {
                id: HostCapability::parse("android:shell:write").unwrap(),
                effect: Effect::Mutating,
                approval: ApprovalRequirement::PerUse,
                // B11: provisional. ADR-AND-001 §7.4 gates only the system tier.
                attribution: AttributionTier::None,
                reversibility: Reversibility::Reversible,
            },
            CapabilitySpec {
                id: HostCapability::parse("android:fs:system").unwrap(),
                effect: Effect::Mutating,
                approval: ApprovalRequirement::DangerousSession,
                attribution: AttributionTier::Manage,
                reversibility: Reversibility::Irreversible,
            },
        ]
    }

    #[test]
    fn errors_interoperate_with_the_std_error_chain() {
        // A compile-time assertion with a runtime witness: both fallible entry points
        // return errors that implement `core::error::Error`, so a caller can use `?`
        // into a `Box<dyn Error>` instead of hand-mapping. On a `std` platform this is
        // `std::error::Error` — same trait, re-exported.
        fn parse_and_register(id: &str) -> Result<(), Box<dyn core::error::Error>> {
            let cap = HostCapability::parse(id)?;
            let mut table = CapabilityTable::new("android", android_vocab())?;
            table.declare(cap)?;
            Ok(())
        }

        assert!(parse_and_register("android:shell:read").is_ok());
        // And the error path carries a message worth surfacing.
        let err = parse_and_register("android:nope").unwrap_err();
        assert!(
            err.to_string()
                .contains("not in this platform's vocabulary")
        );
    }

    #[test]
    fn parses_a_namespaced_id() {
        let cap = HostCapability::parse("android:shell:read").unwrap();
        assert_eq!(cap.platform(), "android");
        assert_eq!(cap.parts().name, "shell:read");
        assert_eq!(cap.as_str(), "android:shell:read");
    }

    #[test]
    fn a_name_may_contain_further_colons() {
        let cap = HostCapability::parse("esp32:bus:i2c:write").unwrap();
        assert_eq!(cap.platform(), "esp32");
        assert_eq!(cap.parts().name, "bus:i2c:write");
    }

    #[test]
    fn a_two_part_id_is_legal_and_its_namespace_is_the_first_segment() {
        let cap = HostCapability::parse("shell:read").unwrap();
        assert_eq!(cap.platform(), "shell");
        assert_eq!(cap.parts().name, "read");
    }

    #[test]
    fn rejects_ids_outside_the_vocabulary_shape() {
        assert!(matches!(
            HostCapability::parse("noseparator"),
            Err(CapabilityIdError::MissingNamespace)
        ));
        assert!(matches!(
            HostCapability::parse(":name"),
            Err(CapabilityIdError::BadNamespace(_))
        ));
        assert!(
            matches!(
                HostCapability::parse("Android:shell"),
                Err(CapabilityIdError::BadNamespace(_))
            ),
            "an uppercase namespace is rejected"
        );
        assert!(matches!(
            HostCapability::parse("android:"),
            Err(CapabilityIdError::EmptyName)
        ));
        assert!(
            matches!(
                HostCapability::parse("android:shell read"),
                Err(CapabilityIdError::BadName(_))
            ),
            "a space in the name is rejected"
        );
        assert!(matches!(
            HostCapability::parse("android:shell/read"),
            Err(CapabilityIdError::BadName(_))
        ));
    }

    #[test]
    fn new_validates_both_halves() {
        assert!(HostCapability::new("android", "shell:read").is_ok());
        assert!(HostCapability::new("android", "").is_err());
        assert!(HostCapability::new("", "shell:read").is_err());
    }

    #[test]
    fn table_rejects_a_spec_from_another_platform() {
        let mut specs = android_vocab();
        specs.push(CapabilitySpec::read_only(
            HostCapability::parse("esp32:gpio:read").unwrap(),
        ));
        let err = CapabilityTable::new("android", specs).unwrap_err();
        assert!(matches!(err, CapabilityTableError::ForeignNamespace { .. }));
    }

    #[test]
    fn table_rejects_a_duplicate_spec() {
        let mut specs = android_vocab();
        specs.push(CapabilitySpec::read_only(
            HostCapability::parse("android:shell:read").unwrap(),
        ));
        assert!(matches!(
            CapabilityTable::new("android", specs).unwrap_err(),
            CapabilityTableError::DuplicateSpec(_)
        ));
    }

    #[test]
    fn a_device_cannot_declare_an_unregistered_capability() {
        // R5: the facts belong to the device, the vocabulary does not.
        let mut table = CapabilityTable::new("android", android_vocab()).unwrap();
        let err = table
            .declare(HostCapability::parse("android:kernel:whatever").unwrap())
            .unwrap_err();
        assert!(matches!(err, CapabilityTableError::Unregistered(_)));
        assert!(table.declared().is_empty());
    }

    #[test]
    fn declaring_is_idempotent_and_stably_ordered() {
        let mut table = CapabilityTable::new("android", android_vocab()).unwrap();
        let write = HostCapability::parse("android:shell:write").unwrap();
        let read = HostCapability::parse("android:shell:read").unwrap();
        table.declare(write.clone()).unwrap();
        table.declare(read.clone()).unwrap();
        table.declare(write.clone()).unwrap();
        assert_eq!(table.declared(), &[read.clone(), write.clone()]);
        assert_eq!(
            table.declared_ids(),
            vec!["android:shell:read", "android:shell:write"]
        );
    }

    #[test]
    fn spec_lookup_drives_the_axes() {
        let mut table = CapabilityTable::new("android", android_vocab()).unwrap();
        let sys = HostCapability::parse("android:fs:system").unwrap();
        table.declare(sys.clone()).unwrap();

        let spec = table.spec(&sys).unwrap();
        assert!(spec.effect.needs_lock());
        assert!(spec.approval.needs_token());
        assert!(spec.approval.needs_dangerous_session());
        assert!(spec.attribution.needs_attribution());
        assert!(spec.reversibility.needs_rollback_plan());

        let read = HostCapability::parse("android:shell:read").unwrap();
        let spec = table.spec(&read).unwrap();
        assert!(!spec.effect.needs_lock());
        assert!(!spec.approval.needs_token());
        assert!(!spec.attribution.needs_attribution());
        assert!(!spec.reversibility.needs_rollback_plan());
    }

    #[test]
    fn an_unregistered_id_has_no_spec_so_the_gate_cannot_authorize_it() {
        let table = CapabilityTable::new("android", android_vocab()).unwrap();
        assert!(
            table
                .spec(&HostCapability::parse("android:kernel:whatever").unwrap())
                .is_none()
        );
    }

    #[test]
    fn read_only_helper_produces_the_observation_tier() {
        let spec = CapabilitySpec::read_only(HostCapability::parse("esp32:sensor:read").unwrap());
        assert_eq!(spec.effect, Effect::ReadOnly);
        assert_eq!(spec.approval, ApprovalRequirement::None);
        assert_eq!(spec.attribution, AttributionTier::None);
        assert_eq!(spec.reversibility, Reversibility::Reversible);
    }

    #[test]
    fn table_serializes_deterministically() {
        let mut a = CapabilityTable::new("android", android_vocab()).unwrap();
        let mut b = CapabilityTable::new("android", android_vocab()).unwrap();
        for cap in ["android:fs:system", "android:shell:read"] {
            a.declare(HostCapability::parse(cap).unwrap()).unwrap();
        }
        for cap in ["android:shell:read", "android:fs:system"] {
            b.declare(HostCapability::parse(cap).unwrap()).unwrap();
        }
        // Declaration order must not change the serialized form: the summary is a
        // regression baseline and a wire payload.
        assert_eq!(
            serde_json::to_string(&a).unwrap(),
            serde_json::to_string(&b).unwrap()
        );
    }

    #[test]
    fn error_display_is_actionable() {
        // R9: the message names the problem, not just that there was one.
        let msg = CapabilityTableError::Unregistered(
            HostCapability::parse("android:kernel:whatever").unwrap(),
        )
        .to_string();
        assert!(msg.contains("android:kernel:whatever"));
        assert!(msg.contains("not in this platform's vocabulary"));
    }
}
