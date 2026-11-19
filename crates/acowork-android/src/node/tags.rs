//! Capability tags for `NodeInfo.capabilities` / `NodeEnroll.capabilities` (ADR-AND-001 §7.1).
//!
//! Encoding choice: plan D5 option A — controlled string tags, zero proto change. The Gateway
//! treats them as opaque labels for display and filtering; it does not gate on them.

use crate::host::{Capability, HostProfile, HostProfileName, Privilege, ShellDialect};

/// Build the tag set a Node publishes for this device.
///
/// Order is stable. Contents are only profile / privilege / dialect / capability ids — never
/// serials, paths, or SELinux context strings.
pub fn capability_tags(profile: &HostProfile) -> Vec<String> {
    let mut tags = vec![
        "control_plane".to_string(),
        "process".to_string(),
        tag_profile(profile.name),
        tag_privilege(profile.privilege),
    ];
    if let Some(dialect) = profile.shell {
        tags.push(tag_dialect(dialect));
    }
    for cap in Capability::all() {
        if profile.caps.is_declared(&cap.id()) {
            tags.push(tag_cap(cap));
        }
    }
    tags
}

/// `android:host-profile:<name>`
pub fn tag_profile(name: HostProfileName) -> String {
    format!("android:host-profile:{}", name.as_str())
}

/// `android:privilege:<level>`
pub fn tag_privilege(level: Privilege) -> String {
    let word = match level {
        Privilege::AppUid => "app",
        Privilege::ShellUid => "shell",
        Privilege::Root => "root",
    };
    format!("android:privilege:{word}")
}

/// `android:shell-dialect:<dialect>`
pub fn tag_dialect(dialect: ShellDialect) -> String {
    let word = match dialect {
        ShellDialect::Bash => "bash",
        ShellDialect::MkSh => "mksh",
        ShellDialect::BusyBoxSh => "busybox-sh",
    };
    format!("android:shell-dialect:{word}")
}

/// `android:cap:<name>` where `<name>` is the capability's local name (`shell:read`, …).
///
/// Prefixed so Gateway filters can match `android:cap:*` without colliding with the raw
/// capability id namespace that agents also see.
pub fn tag_cap(cap: Capability) -> String {
    format!("android:cap:{}", cap.id().parts().name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::HostProfile;
    use crate::host::probe::{CommandOutput, ProbeOutput};

    fn out(s: &str) -> CommandOutput {
        CommandOutput::ok(s)
    }

    #[test]
    fn tags_never_carry_paths_or_serials() {
        let profile = HostProfile::assemble(
            &ProbeOutput {
                id: Some(out("2000")),
                getenforce: Some(out("Enforcing")),
                attr_current: Some(out("u:r:shell:s0")),
                system_sh_version: Some(out("Mksh")),
                ..ProbeOutput::nothing_ran()
            },
            "com.acowork.host",
        );
        let blob = capability_tags(&profile).join(" ");
        assert!(blob.contains("android:host-profile:"));
        assert!(!blob.contains("/data"));
        assert!(!blob.contains("u:r:"));
        assert!(!blob.contains("serial"));
    }

    #[test]
    fn cap_tag_uses_one_spelling_with_the_local_id() {
        let tag = tag_cap(Capability::ShellRead);
        assert_eq!(tag, "android:cap:shell:read");
        assert!(tag.starts_with("android:cap:"));
    }
}
