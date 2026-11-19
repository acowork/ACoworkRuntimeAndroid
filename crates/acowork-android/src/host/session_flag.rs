//! Session-level switches that must never be persisted (ADR-AND-001 §7.3).
//!
//! `dangerous-mode` is a human-held deadman, not a device fact and not a
//! settings-document field. The APK keeps it in this process; Stop host
//! (or process death) turns it off.

use std::sync::atomic::{AtomicBool, Ordering};

use acowork_platform_contract::{
    AttributionVerdict, Gate, GateDecision, LocalReadiness, LockState,
};

use super::backend::ExecRequest;
use super::profile::HostProfile;

static DANGEROUS: AtomicBool = AtomicBool::new(false);

/// Turn the session switch on or off. Never writes a file.
pub fn set_dangerous_mode(on: bool) {
    DANGEROUS.store(on, Ordering::Relaxed);
}

/// Current session switch. Default off.
pub fn dangerous_mode() -> bool {
    DANGEROUS.load(Ordering::Relaxed)
}

/// Run the contract gate with this process's dangerous-mode bit.
///
/// Attribution is `None` until the Gateway verdict is plumbed through the
/// Runtime tool path; system-tier writes that need Manage then fail closed.
pub fn decide_exec(
    profile: &HostProfile,
    request: &ExecRequest,
    approval_presented: bool,
) -> GateDecision {
    Gate::new(profile).decide(
        request,
        Option::<AttributionVerdict>::None,
        LocalReadiness {
            dangerous_session: dangerous_mode(),
            approval_presented,
            lock: LockState::Available,
        },
    )
}

/// `Ok` when the gate allows the request; `Err` is the refusal text.
pub fn exec_allowed(
    profile: &HostProfile,
    request: &ExecRequest,
    approval_presented: bool,
) -> Result<(), String> {
    match decide_exec(profile, request, approval_presented) {
        GateDecision::Allow { .. } => Ok(()),
        GateDecision::Deny { refusal, .. } => Err(refusal.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dangerous_mode_is_process_local_and_off_by_default() {
        set_dangerous_mode(false);
        assert!(!dangerous_mode());
        set_dangerous_mode(true);
        assert!(dangerous_mode());
        set_dangerous_mode(false);
        assert!(!dangerous_mode());
    }
}
