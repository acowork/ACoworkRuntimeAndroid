//! What a port must tell the contract about its device.
//!
//! [`HostDescription`] is the seam between a platform's own facts and the
//! platform-neutral rules. A port implements it once; the gate, the summary and the
//! capability table all read through it, so nothing else in the system needs to
//! know what an SELinux domain or an eFuse bank is.
//!
//! # R3 — the node process itself never holds elevated privilege
//!
//! [`HostDescription::privilege`] reports the privilege the *node process* runs at.
//! Rule R3 requires it to be below [`PrivilegeLevel::Unrestricted`]. Escalation may
//! exist, but only inside a single call behind the narrow
//! [`crate::exec::ExecutionBackend`] interface.
//!
//! The return type is `Option` because privilege separation is not universal. An
//! ESP32 has no MMU and no uid, so it has no privilege axis at all and returns
//! `None` — which is an honest statement, not a missing one. Forcing such a
//! platform to invent a value would make the field meaningless everywhere.
//!
//! # R13 — the summary carries no device identifiers
//!
//! [`HostSummary`] is the shape reported to the control plane. It has deliberately
//! narrow fields: there is nowhere to put a serial number, an IMEI, a mount table or
//! a raw denial record, so a port cannot leak them by accident. The full facts stay
//! on the device and are only ever quoted in a local diagnostic.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;

use serde::{Deserialize, Serialize};

use crate::capability::CapabilityTable;

/// How much authority the node process itself holds.
///
/// Ordered, so R3 can be stated as an inequality rather than a list of platform
/// names. A port maps its own privilege model onto these three levels; the contract
/// never needs to know the mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum PrivilegeLevel {
    /// Confined to the process's own storage. Android's APK sandbox; a firmware
    /// task with no peripheral access.
    Unprivileged,
    /// Can reach shared device storage but not system state. Android's `shell` uid.
    Elevated,
    /// Can change system state directly. Android's root. **R3 forbids the node
    /// process from running here.**
    Unrestricted,
}

impl PrivilegeLevel {
    /// True when this level can change system state without asking anything.
    pub fn is_unrestricted(&self) -> bool {
        matches!(self, PrivilegeLevel::Unrestricted)
    }
}

impl fmt::Display for PrivilegeLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            PrivilegeLevel::Unprivileged => "unprivileged",
            PrivilegeLevel::Elevated => "elevated",
            PrivilegeLevel::Unrestricted => "unrestricted",
        };
        f.write_str(name)
    }
}

/// How a port reaches privilege above its own level, if it can at all.
///
/// Generalises Android's `su` helper. The point of naming it is R3: escalation is a
/// *mechanism with a shape*, not an ambient property, and the shape is what the
/// contract can reason about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EscalationModel {
    /// No way to exceed the node's own privilege. Most embedded targets.
    None,
    /// A separate helper is invoked per call and returns to the caller's privilege
    /// afterwards. Android's `su -c`.
    PerCallHelper,
    /// The node can raise its own privilege and keep it. **Incompatible with R3** —
    /// a port reporting this is non-conformant and the gate treats its mutating
    /// capabilities as unavailable.
    SelfElevating,
}

impl EscalationModel {
    /// True when this model violates R3.
    pub fn violates_r3(&self) -> bool {
        matches!(self, EscalationModel::SelfElevating)
    }
}

/// The device-neutral facts the control plane is allowed to see.
///
/// R13: no field here can hold a device identifier or raw probe output. Compare
/// with what a port knows internally — Android's `DeviceFacts` carries build
/// fingerprints, mount tables and denial records, none of which appear here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostSummary {
    /// The port's registered namespace, e.g. `android`.
    pub platform: String,
    /// The port's own name for this configuration, e.g. `termux`. Opaque to the
    /// contract; useful for humans and for scheduling.
    pub profile: String,
    /// The privilege the node process runs at, or `None` if the platform has no
    /// privilege separation.
    pub privilege: Option<PrivilegeLevel>,
    /// How the port escalates, if it can.
    pub escalation: EscalationModel,
    /// The capability IDs this device declared, in stable order.
    pub capabilities: Vec<String>,
}

/// What a platform port must expose.
///
/// This is the only trait a port is required to implement for the gate and the
/// summary to work. Everything else in this crate is either a data shape the port
/// fills in or a rule the contract enforces on the port's behalf.
pub trait HostDescription {
    /// The registered platform namespace. Must match the namespace of every
    /// capability this port declares.
    fn platform(&self) -> &str;

    /// The port's own name for this device configuration.
    fn profile_name(&self) -> &str;

    /// The privilege the node process runs at (R3), or `None` if the platform has
    /// no privilege separation.
    fn privilege(&self) -> Option<PrivilegeLevel>;

    /// How this port escalates, if at all.
    fn escalation(&self) -> EscalationModel;

    /// The capability table: this platform's vocabulary plus what this device
    /// declared.
    fn capabilities(&self) -> &CapabilityTable;

    /// Why a capability is absent, in terms the model can act on (R9).
    ///
    /// Must name the missing condition, not just the capability. "not permitted" is
    /// a dead end; "the device is not rooted, so system storage cannot be remounted
    /// — use a path under the app's own storage" is a next step.
    fn explain_absence(&self, capability: &crate::capability::HostCapability) -> String;

    /// The device-neutral summary reported to the control plane (R13).
    fn summary(&self) -> HostSummary {
        HostSummary {
            platform: self.platform().to_string(),
            profile: self.profile_name().to_string(),
            privilege: self.privilege(),
            escalation: self.escalation(),
            capabilities: self
                .capabilities()
                .declared_ids()
                .into_iter()
                .map(String::from)
                .collect(),
        }
    }

    /// Whether this port conforms to R3.
    ///
    /// Provided rather than required, because the rule is the same on every
    /// platform and a port should not be able to get it wrong.
    fn is_r3_conformant(&self) -> bool {
        !self.privilege().is_some_and(|p| p.is_unrestricted()) && !self.escalation().violates_r3()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::{CapabilitySpec, HostCapability};

    struct FakeHost {
        table: CapabilityTable,
        privilege: Option<PrivilegeLevel>,
        escalation: EscalationModel,
    }

    impl HostDescription for FakeHost {
        fn platform(&self) -> &str {
            "fake"
        }
        fn profile_name(&self) -> &str {
            "baseline"
        }
        fn privilege(&self) -> Option<PrivilegeLevel> {
            self.privilege
        }
        fn escalation(&self) -> EscalationModel {
            self.escalation
        }
        fn capabilities(&self) -> &CapabilityTable {
            &self.table
        }
        fn explain_absence(&self, capability: &HostCapability) -> String {
            alloc::format!("{capability} was not demonstrated on this device")
        }
    }

    fn host(privilege: Option<PrivilegeLevel>, escalation: EscalationModel) -> FakeHost {
        let mut table = CapabilityTable::new(
            "fake",
            vec![CapabilitySpec::read_only(
                HostCapability::parse("fake:thing:read").unwrap(),
            )],
        )
        .unwrap();
        table
            .declare(HostCapability::parse("fake:thing:read").unwrap())
            .unwrap();
        FakeHost {
            table,
            privilege,
            escalation,
        }
    }

    #[test]
    fn privilege_levels_are_ordered() {
        assert!(PrivilegeLevel::Unprivileged < PrivilegeLevel::Elevated);
        assert!(PrivilegeLevel::Elevated < PrivilegeLevel::Unrestricted);
        assert!(PrivilegeLevel::Unrestricted.is_unrestricted());
        assert!(!PrivilegeLevel::Elevated.is_unrestricted());
    }

    #[test]
    fn a_privilege_less_platform_reports_none_and_still_conforms() {
        // An ESP32 has no MMU and no uid. `None` is the honest answer, and R3 must
        // not fail a platform for lacking an axis it does not have.
        let h = host(None, EscalationModel::None);
        assert_eq!(h.privilege(), None);
        assert!(h.is_r3_conformant());
    }

    #[test]
    fn r3_rejects_a_node_running_unrestricted() {
        let h = host(Some(PrivilegeLevel::Unrestricted), EscalationModel::None);
        assert!(!h.is_r3_conformant());
    }

    #[test]
    fn r3_rejects_self_elevation_even_from_a_low_level() {
        // The node could raise itself and keep the privilege, which is what R3
        // forbids regardless of where it starts.
        let h = host(
            Some(PrivilegeLevel::Unprivileged),
            EscalationModel::SelfElevating,
        );
        assert!(!h.is_r3_conformant());
    }

    #[test]
    fn a_per_call_helper_conforms() {
        let h = host(
            Some(PrivilegeLevel::Elevated),
            EscalationModel::PerCallHelper,
        );
        assert!(h.is_r3_conformant());
    }

    #[test]
    fn summary_carries_no_device_identifiers() {
        let h = host(
            Some(PrivilegeLevel::Elevated),
            EscalationModel::PerCallHelper,
        );
        let json = serde_json::to_string(&h.summary()).unwrap();
        assert_eq!(
            h.summary(),
            HostSummary {
                platform: "fake".into(),
                profile: "baseline".into(),
                privilege: Some(PrivilegeLevel::Elevated),
                escalation: EscalationModel::PerCallHelper,
                capabilities: vec!["fake:thing:read".into()],
            }
        );
        // R13, checked against the actual wire form: the summary has five fields and
        // none of them can hold an identifier or raw probe output.
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        let keys: Vec<&str> = value
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            keys,
            vec![
                "platform",
                "profile",
                "privilege",
                "escalation",
                "capabilities"
            ]
        );
    }

    #[test]
    fn explain_absence_names_the_capability() {
        let h = host(None, EscalationModel::None);
        let cap = HostCapability::parse("fake:thing:write").unwrap();
        assert!(h.explain_absence(&cap).contains("fake:thing:write"));
    }
}
